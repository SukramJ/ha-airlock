// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

// Package changes is the journal of configuration changes: for each one,
// what was there before and what was there after. A change is recorded
// before it is written to Home Assistant, and an undo restores from here,
// so the states are kept as they are, unredacted. The journal knows neither
// tools nor Home Assistant.
package changes

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Keep is how many changes the journal holds. The oldest go first.
const Keep = 200

var (
	// ErrUnknown reports a change the journal does not hold.
	ErrUnknown = errors.New("changes: no such change")
	// ErrUndone reports a change that was undone already.
	ErrUndone = errors.New("changes: the change was undone already")
	// ErrEmpty reports a change with neither a state before nor one after.
	ErrEmpty = errors.New("changes: a change needs a state before or a state after")
)

// Undo says who took a change back, and when.
type Undo struct {
	By   string    `json:"by"`
	Time time.Time `json:"time"`
}

// Change is one configuration change.
type Change struct {
	// ID names the change in the journal. Record sets it.
	ID string `json:"id"`
	// Time is when the change was recorded. Record sets it.
	Time   time.Time `json:"time"`
	Client string    `json:"client"`
	Tool   string    `json:"tool"`
	// Kind is the kind of object, Object its identifier in Home Assistant.
	Kind   string `json:"kind"`
	Object string `json:"object"`
	// Before is the object as it was; absent for a creation. After is the
	// object as the change leaves it; absent for a deletion.
	Before json.RawMessage `json:"before,omitempty"`
	After  json.RawMessage `json:"after,omitempty"`
	// Failed says why the write did not happen, if it did not. The change
	// stays in the journal: it was approved and attempted.
	Failed string `json:"failed,omitempty"`
	// Undone is set once an administrator took the change back.
	Undone *Undo `json:"undone,omitempty"`
}

// Journal holds the changes and keeps them in one file. It is safe for
// concurrent use.
type Journal struct {
	path string
	now  func() time.Time

	mu      sync.Mutex
	changes []Change // oldest first
}

// Open reads the journal at path. A file that does not exist is an empty
// journal.
func Open(path string, now func() time.Time) (*Journal, error) {
	j := &Journal{path: path, now: now}
	data, err := os.ReadFile(path) //nolint:gosec // the path is the operator's configuration, not client input
	if errors.Is(err, os.ErrNotExist) {
		return j, nil
	}
	if err != nil {
		return nil, fmt.Errorf("changes: read the journal: %w", err)
	}
	if err := json.Unmarshal(data, &j.changes); err != nil {
		return nil, fmt.Errorf("changes: read the journal: %w", err)
	}
	return j, nil
}

// Record adds a change and returns it with its ID and time. The change is
// on disk when Record returns; if it cannot be written, the journal is as
// it was and the caller must not make the change.
func (j *Journal) Record(ctx context.Context, c Change) (Change, error) { //nolint:gocritic // a change is passed and returned as a value: the journal's copy is its own
	if err := ctx.Err(); err != nil {
		return Change{}, fmt.Errorf("changes: record: %w", err)
	}
	if len(c.Before) == 0 && len(c.After) == 0 {
		return Change{}, ErrEmpty
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return Change{}, fmt.Errorf("changes: record: %w", err)
	}
	c.ID, c.Time, c.Undone = hex.EncodeToString(id), j.now().UTC(), nil
	c.Before, c.After = bytes.Clone(c.Before), bytes.Clone(c.After)

	j.mu.Lock()
	defer j.mu.Unlock()
	next := append(append([]Change{}, j.changes...), c)
	if len(next) > Keep {
		next = next[len(next)-Keep:]
	}
	if err := j.save(next); err != nil {
		return Change{}, err
	}
	j.changes = next
	return clone(&c), nil
}

// List returns the changes, newest first.
func (j *Journal) List() []Change {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]Change, 0, len(j.changes))
	for i := len(j.changes) - 1; i >= 0; i-- {
		out = append(out, clone(&j.changes[i]))
	}
	return out
}

// Get returns one change.
func (j *Journal) Get(id string) (Change, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i := range j.changes {
		if j.changes[i].ID == id {
			return clone(&j.changes[i]), true
		}
	}
	return Change{}, false
}

// Settle notes how the write of a recorded change ended: the identifier of
// the object, which a creation learns only then, or why it failed.
func (j *Journal) Settle(ctx context.Context, id, object, failed string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("changes: settle: %w", err)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	next := append([]Change{}, j.changes...)
	for i := range next {
		if next[i].ID != id {
			continue
		}
		if object != "" {
			next[i].Object = object
		}
		next[i].Failed = failed
		if err := j.save(next); err != nil {
			return err
		}
		j.changes = next
		return nil
	}
	return ErrUnknown
}

// MarkUndone notes that an administrator took the change back. Like
// Record, it has happened only if it is on disk.
func (j *Journal) MarkUndone(ctx context.Context, id, by string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("changes: mark undone: %w", err)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	next := append([]Change{}, j.changes...)
	for i := range next {
		if next[i].ID != id {
			continue
		}
		if next[i].Undone != nil {
			return ErrUndone
		}
		next[i].Undone = &Undo{By: by, Time: j.now().UTC()}
		if err := j.save(next); err != nil {
			return err
		}
		j.changes = next
		return nil
	}
	return ErrUnknown
}

// save replaces the file with the given changes: written beside it, synced,
// then renamed over it, so that a crash leaves the old journal or the new
// one. Called with the lock held.
func (j *Journal) save(changes []Change) error {
	data, err := json.Marshal(changes)
	if err != nil {
		return fmt.Errorf("changes: write the journal: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(j.path), ".changes-*")
	if err != nil {
		return fmt.Errorf("changes: write the journal: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("changes: write the journal: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("changes: write the journal: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("changes: write the journal: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("changes: write the journal: %w", err)
	}
	if err := os.Rename(tmp.Name(), j.path); err != nil {
		return fmt.Errorf("changes: write the journal: %w", err)
	}
	return nil
}

func clone(c *Change) Change {
	out := *c
	out.Before, out.After = bytes.Clone(c.Before), bytes.Clone(c.After)
	if c.Undone != nil {
		undone := *c.Undone
		out.Undone = &undone
	}
	return out
}

// Absent is the hash of a state that is not there: the state before a
// creation, the state after a deletion.
const Absent = "absent"

// Hash identifies a state. States that are the same JSON value have the
// same hash whatever the order of their object keys or their spacing; any
// other difference gives another hash.
func Hash(state json.RawMessage) (string, error) {
	if len(bytes.TrimSpace(state)) == 0 {
		return Absent, nil
	}
	dec := json.NewDecoder(bytes.NewReader(state))
	// Numbers keep their digits: 1 and 1.0 are different states.
	dec.UseNumber()
	var value any // any: arbitrary JSON, decoded only to be encoded again
	if err := dec.Decode(&value); err != nil {
		return "", fmt.Errorf("changes: the state is not JSON: %w", err)
	}
	if dec.More() {
		return "", errors.New("changes: the state is more than one JSON value")
	}
	// encoding/json writes object keys sorted.
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("changes: encode the state: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}
