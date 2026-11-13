// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package approval_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/SukramJ/ha-airlock/internal/approval"
	"github.com/SukramJ/ha-airlock/internal/audit"
)

// journal is an audit log that keeps its entries, and can be made to fail.
type journal struct {
	mu      sync.Mutex
	entries []audit.Entry
	fail    bool
}

func (j *journal) Append(_ context.Context, e audit.Entry) (audit.Receipt, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.fail {
		return audit.Receipt{}, errors.New("disk full")
	}
	j.entries = append(j.entries, e)
	return audit.Receipt{}, nil
}

func (j *journal) events() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]string, 0, len(j.entries))
	for i := range j.entries {
		out = append(out, j.entries[i].Event)
	}
	return out
}

type fixture struct {
	store *approval.Store
	log   *journal
	now   time.Time
	mu    sync.Mutex
	// notices are what the store told its notify function, in order.
	notices []bool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{log: &journal{}, now: time.Unix(1_800_000_000, 0)}
	f.store = approval.New(f.log, func(_ context.Context, waiting bool) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.notices = append(f.notices, waiting)
	})
	f.store.SetClock(func() time.Time {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.now
	})
	return f
}

func (f *fixture) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

// request is a call of client on tool with the given arguments.
func request(t *testing.T, client, tool, args string) *approval.Request {
	t.Helper()
	key, err := approval.Key(client, tool, json.RawMessage(args))
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	return &approval.Request{Key: key, Client: client, Tool: tool, Summary: "Turn on light.kitchen", Arguments: json.RawMessage(args)}
}

func (f *fixture) resolve(t *testing.T, req *approval.Request) (status approval.Status, approver string) {
	t.Helper()
	status, approver, err := f.store.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	return status, approver
}

func TestKeyIsTheSameForTheSameJSONValueOnly(t *testing.T) {
	t.Parallel()
	key := func(client, tool, args string) string {
		k, err := approval.Key(client, tool, json.RawMessage(args))
		if err != nil {
			t.Fatalf("key of %s: %v", args, err)
		}
		return k
	}
	base := key("c", "t", `{"a":1,"b":"x"}`)
	if key("c", "t", ` { "b" : "x", "a" : 1 } `) != base {
		t.Error("the order of keys or the spacing changed the key")
	}
	for name, other := range map[string]string{
		"another value":         key("c", "t", `{"a":2,"b":"x"}`),
		"another number":        key("c", "t", `{"a":1.0,"b":"x"}`),
		"a string for a number": key("c", "t", `{"a":"1","b":"x"}`),
		"one more key":          key("c", "t", `{"a":1,"b":"x","c":null}`),
		"another client":        key("d", "t", `{"a":1,"b":"x"}`),
		"another tool":          key("c", "u", `{"a":1,"b":"x"}`),
		"shifted boundaries":    key("ct", "", `{"a":1,"b":"x"}`),
		"no arguments":          key("c", "t", ``),
	} {
		if other == base {
			t.Errorf("%s gives the same key", name)
		}
	}
	if key("ab", "c", `1`) == key("a", "bc", `1`) {
		t.Error("client and tool run into each other")
	}
	if key("c", "t", ``) != key("c", "t", `null`) {
		t.Error("no arguments and null differ")
	}
	for _, bad := range []string{`{`, `{} {}`, `x`} {
		if _, err := approval.Key("c", "t", json.RawMessage(bad)); err == nil {
			t.Errorf("arguments %q got a key", bad)
		}
	}
}

func TestApprovedCallIsLetThroughExactlyOnce(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	req := request(t, "client-a", "light_turn_on", `{"entity_id":"light.kitchen"}`)

	if status, _ := f.resolve(t, req); status != approval.Waiting {
		t.Fatalf("first call: status %d, want waiting", status)
	}
	if status, _ := f.resolve(t, req); status != approval.Waiting {
		t.Fatalf("repeated before the decision: status %d, want waiting", status)
	}
	pending := f.store.Pending()
	if len(pending) != 1 || pending[0].Summary != req.Summary || pending[0].ID == "" || !pending[0].Expires.Equal(f.now.Add(approval.WaitFor)) {
		t.Fatalf("pending = %+v", pending)
	}
	if err := f.store.Decide(context.Background(), pending[0].ID, true, "admin-1"); err != nil {
		t.Fatalf("decide: %v", err)
	}
	if len(f.store.Pending()) != 0 {
		t.Fatal("a decided request is still listed as waiting")
	}

	status, approver := f.resolve(t, req)
	if status != approval.Approved || approver != "admin-1" {
		t.Fatalf("after approval: status %d by %q", status, approver)
	}
	if status, _ := f.resolve(t, req); status != approval.Waiting {
		t.Fatalf("the approval was usable twice: status %d", status)
	}
	if got := fmt.Sprint(f.log.events()); got != "[action_approved]" {
		t.Fatalf("audit events = %s", got)
	}
	e := f.log.entries[0]
	if e.Client != "client-a" || e.Tool != "light_turn_on" || e.Approver != "admin-1" || string(e.Arguments) != `{"entity_id":"light.kitchen"}` {
		t.Fatalf("audit entry = %+v", e)
	}
}

func TestApprovalIsForOneClientOneToolAndTheseArguments(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	req := request(t, "client-a", "light_turn_on", `{"entity_id":"light.kitchen"}`)
	f.resolve(t, req)
	if err := f.store.Decide(context.Background(), f.store.Pending()[0].ID, true, "admin-1"); err != nil {
		t.Fatalf("decide: %v", err)
	}

	for name, other := range map[string]*approval.Request{
		"another client":   request(t, "client-b", "light_turn_on", `{"entity_id":"light.kitchen"}`),
		"another tool":     request(t, "client-a", "light_turn_off", `{"entity_id":"light.kitchen"}`),
		"another argument": request(t, "client-a", "light_turn_on", `{"entity_id":"light.hall"}`),
	} {
		if status, _ := f.resolve(t, other); status != approval.Waiting {
			t.Errorf("%s: status %d, want waiting", name, status)
		}
	}
	if status, _ := f.resolve(t, req); status != approval.Approved {
		t.Fatal("the approved call itself is not let through")
	}
}

func TestDeniedCallStaysDeniedAndIsRecorded(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	req := request(t, "client-a", "light_turn_on", `{"entity_id":"light.kitchen"}`)
	f.resolve(t, req)
	if err := f.store.Decide(context.Background(), f.store.Pending()[0].ID, false, "admin-1"); err != nil {
		t.Fatalf("decide: %v", err)
	}
	for range 2 {
		if status, approver := f.resolve(t, req); status != approval.Denied || approver != "admin-1" {
			t.Fatalf("status %d by %q, want denied by admin-1", status, approver)
		}
	}
	if got := fmt.Sprint(f.log.events()); got != "[action_denied]" {
		t.Fatalf("audit events = %s", got)
	}
	// The denial is forgotten after a while; the call may be asked again.
	f.advance(approval.UseWithin)
	if status, _ := f.resolve(t, req); status != approval.Waiting {
		t.Fatalf("after the denial was forgotten: status %d, want waiting", status)
	}
}

func TestDecisionNeedsAWaitingRequest(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	req := request(t, "client-a", "light_turn_on", `{"entity_id":"light.kitchen"}`)
	f.resolve(t, req)
	id := f.store.Pending()[0].ID

	for name, wrong := range map[string]string{"no id": "", "an invented id": "0123456789abcdef", "the key": req.Key} {
		if err := f.store.Decide(context.Background(), wrong, true, "admin-1"); !errors.Is(err, approval.ErrUnknown) {
			t.Errorf("%s: error = %v, want ErrUnknown", name, err)
		}
	}
	if err := f.store.Decide(context.Background(), id, false, "admin-1"); err != nil {
		t.Fatalf("decide: %v", err)
	}
	if err := f.store.Decide(context.Background(), id, true, "admin-2"); !errors.Is(err, approval.ErrUnknown) {
		t.Fatalf("a denial was turned into an approval: %v", err)
	}
	if status, _ := f.resolve(t, req); status != approval.Denied {
		t.Fatalf("status %d, want denied", status)
	}
}

func TestDecisionThatCannotBeRecordedHasNoEffect(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	req := request(t, "client-a", "light_turn_on", `{"entity_id":"light.kitchen"}`)
	f.resolve(t, req)
	f.log.fail = true

	if err := f.store.Decide(context.Background(), f.store.Pending()[0].ID, true, "admin-1"); err == nil {
		t.Fatal("an approval that was not recorded was accepted")
	}
	if status, _ := f.resolve(t, req); status != approval.Waiting {
		t.Fatalf("status %d, want still waiting", status)
	}
}

func TestRequestAndApprovalExpireAndTheExpiryIsRecorded(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	req := request(t, "client-a", "light_turn_on", `{"entity_id":"light.kitchen"}`)

	// Not decided in time.
	f.resolve(t, req)
	id := f.store.Pending()[0].ID
	f.advance(approval.WaitFor)
	if len(f.store.Pending()) != 0 {
		t.Fatal("an expired request is listed as waiting")
	}
	if err := f.store.Decide(context.Background(), id, true, "admin-1"); !errors.Is(err, approval.ErrUnknown) {
		t.Fatalf("an expired request was approved: %v", err)
	}

	// Approved, but not used in time.
	f.resolve(t, req)
	if err := f.store.Decide(context.Background(), f.store.Pending()[0].ID, true, "admin-1"); err != nil {
		t.Fatalf("decide: %v", err)
	}
	f.advance(approval.UseWithin - time.Second)
	other := request(t, "client-a", "light_turn_on", `{"entity_id":"light.hall"}`)
	f.resolve(t, other) // something else happens; the approval is still good
	f.advance(time.Second)
	if status, _ := f.resolve(t, req); status != approval.Waiting {
		t.Fatalf("an approval was used after its time: status %d", status)
	}

	if got := fmt.Sprint(f.log.events()); got != "[action_expired action_approved action_expired]" {
		t.Fatalf("audit events = %s", got)
	}
	if last := f.log.entries[2]; last.Approver != "admin-1" || last.Decision != "expired" {
		t.Fatalf("expiry of the unused approval = %+v", last)
	}
}

func TestOneClientCannotFillThePage(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	for i := range approval.MaxWaitingPerClient {
		if status, _ := f.resolve(t, request(t, "client-a", "light_turn_on", fmt.Sprintf(`{"entity_id":"light.l%d"}`, i))); status != approval.Waiting {
			t.Fatalf("request %d: status %d", i, status)
		}
		f.advance(time.Second)
	}
	if status, _ := f.resolve(t, request(t, "client-a", "light_turn_on", `{"entity_id":"light.one_more"}`)); status != approval.TooMany {
		t.Fatalf("status %d, want too many", status)
	}
	if status, _ := f.resolve(t, request(t, "client-b", "light_turn_on", `{"entity_id":"light.one_more"}`)); status != approval.Waiting {
		t.Fatalf("another client is held back by the first: status %d", status)
	}
	pending := f.store.Pending()
	if len(pending) != approval.MaxWaitingPerClient+1 || string(pending[0].Arguments) != `{"entity_id":"light.l0"}` {
		t.Fatalf("pending = %d requests, first %s; want the oldest first", len(pending), pending[0].Arguments)
	}
	// A request already waiting is still answered when the client is full.
	if status, _ := f.resolve(t, request(t, "client-a", "light_turn_on", `{"entity_id":"light.l0"}`)); status != approval.Waiting {
		t.Fatalf("a waiting request of a full client: status %d", status)
	}
}

func (f *fixture) told() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return fmt.Sprint(f.notices)
}

// The notice follows whether anything waits: told once when the first
// request arrives, once when the last one is decided or has expired.
func TestNotifyIsToldWhenSomethingStartsToWaitAndWhenNothingWaitsAnyMore(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	one := request(t, "client-a", "light_turn_on", `{"entity_id":"light.one"}`)
	two := request(t, "client-a", "light_turn_on", `{"entity_id":"light.two"}`)

	f.resolve(t, one)
	f.resolve(t, one)
	f.resolve(t, two)
	if got := f.told(); got != "[true]" {
		t.Fatalf("after two requests: told %s, want [true]", got)
	}
	pending := f.store.Pending()
	if err := f.store.Decide(context.Background(), pending[0].ID, true, "admin-1"); err != nil {
		t.Fatal(err)
	}
	if got := f.told(); got != "[true]" {
		t.Fatalf("one request still waits: told %s, want [true]", got)
	}
	if err := f.store.Decide(context.Background(), pending[1].ID, false, "admin-1"); err != nil {
		t.Fatal(err)
	}
	if got := f.told(); got != "[true false]" {
		t.Fatalf("after the last decision: told %s, want [true false]", got)
	}
	// Using the approval changes nothing about what waits.
	f.resolve(t, one)
	if got := f.told(); got != "[true false]" {
		t.Fatalf("after the approved call ran: told %s", got)
	}

	// A request that expires is noticed by the sweep alone.
	three := request(t, "client-a", "light_turn_on", `{"entity_id":"light.three"}`)
	f.resolve(t, three)
	f.advance(approval.WaitFor)
	f.store.Sweep(context.Background())
	if got := f.told(); got != "[true false true false]" {
		t.Fatalf("after the expiry: told %s, want [true false true false]", got)
	}
	events := f.log.events()
	if events[len(events)-1] != "action_expired" {
		t.Fatalf("the sweep did not record the expiry: %v", events)
	}
	f.store.Sweep(context.Background())
	if got := f.told(); got != "[true false true false]" {
		t.Fatalf("a sweep with nothing to do told something: %s", got)
	}
}
