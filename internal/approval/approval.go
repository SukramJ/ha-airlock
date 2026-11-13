// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

// Package approval holds the tool calls that wait for an administrator's
// decision.
//
// A request is bound to one client, one tool and the exact arguments by a
// hash over all three. An approval lets exactly one call with that hash
// through and is then used up. Nothing here is reachable for the MCP
// client: it cannot list, approve or extend a request, only repeat its call.
//
// Requests live in memory. A restart forgets them, which refuses what was
// waiting or approved and not yet run.
package approval

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/SukramJ/ha-airlock/internal/audit"
)

const (
	// WaitFor is how long a request waits for a decision.
	WaitFor = 5 * time.Minute
	// UseWithin is how long an approval can be used, and how long a denial
	// is remembered, after the decision.
	UseWithin = 2 * time.Minute
	// maxWaitingPerClient bounds what one client can put before the owner
	// at a time.
	maxWaitingPerClient = 5
)

// ErrUnknown reports a decision on a request that does not wait: it never
// existed, expired or was decided already.
var ErrUnknown = errors.New("approval: no such waiting request")

// Status is what the store says about a call.
type Status int

const (
	// Waiting means the call is parked and has not been decided.
	Waiting Status = iota
	// Approved means an administrator approved this call. Resolve reports
	// it once: the approval is used up by being reported.
	Approved
	// Denied means an administrator refused this call.
	Denied
	// TooMany means the client has too many calls waiting already; this one
	// was not parked.
	TooMany
)

// Entity is an entity a request acts on, with the name Home Assistant
// shows for it.
type Entity struct {
	ID   string
	Name string
}

// Request is one call as the owner is shown it. Every field comes from the
// server: the summary from the tool's declaration, the names from Home
// Assistant, the arguments after redaction.
type Request struct {
	// ID names the request on the page. It is not shown to the client.
	ID string
	// Key binds the request to client, tool and arguments; see Key.
	Key       string
	Client    string
	Tool      string
	Summary   string
	Arguments json.RawMessage
	Entities  []Entity
	CreatedAt time.Time
	// Expires is when the request stops waiting.
	Expires time.Time
}

// Appender is the audit log as the store uses it.
type Appender interface {
	Append(ctx context.Context, entry audit.Entry) (audit.Receipt, error)
}

type item struct {
	Request
	status   Status
	approver string
	// expires is when the item is forgotten in its current status.
	expires time.Time
}

// Store holds the requests. It is safe for concurrent use.
type Store struct {
	audit Appender

	mu    sync.Mutex
	items map[string]*item // by Key
	now   func() time.Time
}

// New returns an empty store that records decisions in the audit log.
func New(log Appender) *Store {
	return &Store{audit: log, items: map[string]*item{}, now: time.Now}
}

// Key returns the hash that binds an approval to a client, a tool and
// arguments. Arguments that are the same JSON value give the same key
// whatever the order of their object keys or their spacing; any other
// difference gives another key.
func Key(client, tool string, args json.RawMessage) (string, error) {
	canonical := []byte("null")
	if len(bytes.TrimSpace(args)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(args))
		// Numbers keep their digits: 1 and 1.0 are different arguments.
		dec.UseNumber()
		var value any // any: arbitrary JSON, decoded only to be encoded again
		if err := dec.Decode(&value); err != nil {
			return "", fmt.Errorf("approval: arguments are not JSON: %w", err)
		}
		if dec.More() {
			return "", errors.New("approval: arguments are more than one JSON value")
		}
		// encoding/json writes object keys sorted.
		var err error
		if canonical, err = json.Marshal(value); err != nil {
			return "", fmt.Errorf("approval: encode arguments: %w", err)
		}
	}
	h := sha256.New()
	for _, part := range [][]byte{[]byte(client), []byte(tool), canonical} {
		// Each part is preceded by its length, so that no two different
		// triples give the same bytes.
		h.Write([]byte(strconv.Itoa(len(part)) + ":"))
		h.Write(part)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Resolve says where the call described by req stands, and parks it if it
// is new. req needs Key, Client, Tool, Summary, Arguments and Entities.
//
// An approval is reported once, with the administrator who gave it, and is
// gone afterwards: the caller runs the call now or not at all.
func (s *Store) Resolve(ctx context.Context, req *Request) (status Status, approver string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.prune(ctx, now)

	if it, ok := s.items[req.Key]; ok {
		if it.status == Approved {
			delete(s.items, req.Key)
		}
		return it.status, it.approver, nil
	}
	waiting := 0
	for _, it := range s.items {
		if it.Client == req.Client && it.status == Waiting {
			waiting++
		}
	}
	if waiting >= maxWaitingPerClient {
		return TooMany, "", nil
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return Waiting, "", fmt.Errorf("approval: %w", err)
	}
	parked := *req
	parked.ID = hex.EncodeToString(id)
	parked.CreatedAt = now
	parked.Expires = now.Add(WaitFor)
	s.items[req.Key] = &item{Request: parked, status: Waiting, expires: parked.Expires}
	return Waiting, "", nil
}

// Pending returns the requests that wait for a decision, oldest first.
func (s *Store) Pending() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var out []Request
	for _, it := range s.items {
		if it.status == Waiting && now.Before(it.expires) {
			out = append(out, it.Request)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Decide records an administrator's decision on the waiting request with
// the given ID. The decision takes effect only once it is in the audit log.
func (s *Store) Decide(ctx context.Context, id string, approve bool, by string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.prune(ctx, now)
	var found *item
	for _, it := range s.items {
		if it.ID == id && it.status == Waiting {
			found = it
		}
	}
	if found == nil || id == "" {
		return ErrUnknown
	}
	entry := audit.Entry{
		Event: "action_denied", Client: found.Client, Tool: found.Tool, Arguments: found.Arguments,
		Decision: "denied", Approver: by, Result: found.Summary,
	}
	if approve {
		entry.Event, entry.Decision = "action_approved", "approved"
	}
	if _, err := s.audit.Append(ctx, entry); err != nil {
		return fmt.Errorf("approval: record decision: %w", err)
	}
	found.status, found.approver = Denied, by
	if approve {
		found.status = Approved
	}
	found.expires = now.Add(UseWithin)
	return nil
}

// prune forgets what has expired. A request that expired while waiting, and
// an approval that was never used, are recorded: the owner can see that
// nothing ran. Called with the lock held.
func (s *Store) prune(ctx context.Context, now time.Time) {
	for key, it := range s.items {
		if now.Before(it.expires) {
			continue
		}
		delete(s.items, key)
		if it.status == Denied {
			continue
		}
		result := "expired without a decision; not run"
		if it.status == Approved {
			result = "approved, but the call was not repeated in time; not run"
		}
		// Best effort: the call did not run either way, and the request
		// itself is already on record as a tool call.
		_, _ = s.audit.Append(context.WithoutCancel(ctx), audit.Entry{
			Event: "action_expired", Client: it.Client, Tool: it.Tool, Arguments: it.Arguments,
			Decision: "expired", Approver: it.approver, Result: result,
		})
	}
}
