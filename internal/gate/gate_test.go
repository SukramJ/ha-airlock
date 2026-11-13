// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package gate_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SukramJ/ha-airlock/internal/approval"
	"github.com/SukramJ/ha-airlock/internal/audit"
	"github.com/SukramJ/ha-airlock/internal/catalog"
	"github.com/SukramJ/ha-airlock/internal/gate"
	"github.com/SukramJ/ha-airlock/internal/policy"
)

const secretInResult = "hunter2pass"

// probeTool is a tool of the given tier that counts how often it ran and
// returns a result with a credential in it.
func probeTool(tier catalog.Tier, runs *atomic.Int32) catalog.Tool {
	tool := catalog.Tool{
		Name: "probe_" + string(tier),
		Tier: tier,
		Handler: func(context.Context, catalog.Core, json.RawMessage) (json.RawMessage, error) {
			runs.Add(1)
			return json.RawMessage(`{"password":"` + secretInResult + `","state":"on"}`), nil
		},
	}
	if tier != catalog.R0 {
		tool.Act = func(json.RawMessage) (catalog.Action, error) {
			return catalog.Action{Summary: "Probe tier " + string(tier)}, nil
		}
	}
	return tool
}

// home is a Home Assistant that knows entities and their labels, and
// records the services called on it.
type home struct {
	mu       sync.Mutex
	labels   map[string][]string
	names    map[string]string
	services []string
}

func (h *home) Call(_ context.Context, command string, params, out any) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	switch command {
	case "config/entity_registry/get":
		var p struct {
			EntityID string `json:"entity_id"`
		}
		_ = json.Unmarshal(raw, &p)
		labels, ok := h.labels[p.EntityID]
		if !ok {
			return errors.New("home assistant command failed: not_found: Entity not found")
		}
		answer, _ := json.Marshal(map[string]any{"labels": labels, "name": nil, "original_name": h.names[p.EntityID]})
		return json.Unmarshal(answer, out)
	case "call_service":
		h.services = append(h.services, string(raw))
		return json.Unmarshal([]byte(`{"context":{"id":"01J"}}`), out)
	default:
		return errors.New("unexpected command " + command)
	}
}

func (h *home) setLabels(entity string, labels ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.labels[entity] = labels
}

func (h *home) called() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.services...)
}

type fixture struct {
	gate      *gate.Gate
	auditPath string
	runs      map[catalog.Tier]*atomic.Int32
	// halted is the kill switch of the test.
	halted    *atomic.Bool
	approvals *approval.Store
	home      *home
}

func newFixture(t *testing.T, pol policy.Policy, extra ...catalog.Tool) fixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.Open(path)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	f := fixture{
		auditPath: path, runs: map[catalog.Tier]*atomic.Int32{}, halted: &atomic.Bool{}, approvals: approval.New(log, nil, time.Now),
		home: &home{
			labels: map[string][]string{"light.kitchen": {"other", "airlock"}, "light.hall": {"airlock"}, "light.cellar": {"other"}},
			names:  map[string]string{"light.kitchen": "Kitchen ceiling"},
		},
	}
	tools := append([]catalog.Tool{}, extra...)
	tools = append(tools, catalog.All()...)
	for _, tier := range catalog.Tiers() {
		f.runs[tier] = &atomic.Int32{}
		tools = append(tools, probeTool(tier, f.runs[tier]))
	}
	f.gate = gate.New(gate.Config{
		Policy: pol, Audit: log, Core: f.home, Tools: tools, Timeout: 5 * time.Second, Halted: f.halted.Load, Approvals: f.approvals,
	})
	return f
}

// records returns the audit log's entries after checking its chain.
func (f fixture) records(t *testing.T) []map[string]any {
	t.Helper()
	if _, err := audit.VerifyFile(f.auditPath); err != nil {
		t.Fatalf("audit log does not verify: %v", err)
	}
	data, err := os.ReadFile(f.auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var l struct {
			Entry map[string]any `json:"entry"`
		}
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			t.Fatalf("audit line: %v", err)
		}
		out = append(out, l.Entry)
	}
	return out
}

func parsePolicy(t *testing.T, text string) policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(text))
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	return p
}

var localClient = &gate.Principal{Client: "client-a", Profile: policy.ProfileLocal}

func TestAllowedCallReturnsRedactedDataWithTheNoticeAndIsRecorded(t *testing.T) {
	t.Parallel()
	f := newFixture(t, policy.Default())

	out, err := f.gate.Call(context.Background(), localClient, "probe_R0", json.RawMessage(`{"api_key":"abcd1234efgh","limit":5}`))
	if err != nil {
		t.Fatalf("call: %v", err)
	}

	if !out.Allowed || f.runs[catalog.R0].Load() != 1 {
		t.Fatalf("allowed = %t, runs = %d", out.Allowed, f.runs[catalog.R0].Load())
	}
	var wrapped struct {
		Notice string         `json:"notice"`
		Data   map[string]any `json:"data"`
	}
	if err := json.Unmarshal(out.Output, &wrapped); err != nil {
		t.Fatalf("output: %v", err)
	}
	if wrapped.Notice != gate.Notice || wrapped.Data["state"] != "on" {
		t.Fatalf("output = %s", out.Output)
	}
	if strings.Contains(string(out.Output), secretInResult) {
		t.Fatalf("the credential left the gate: %s", out.Output)
	}

	records := f.records(t)
	if len(records) != 1 {
		t.Fatalf("%d audit records, want 1", len(records))
	}
	r := records[0]
	if r["client"] != "client-a" || r["tool"] != "probe_R0" || r["decision"] != "allow" {
		t.Fatalf("audit record = %v", r)
	}
	if result, _ := r["result"].(string); !strings.HasPrefix(result, "ok: ") || !strings.Contains(result, "1 redactions") {
		t.Fatalf("audit result = %v", r["result"])
	}
	recorded, _ := json.Marshal(r)
	if strings.Contains(string(recorded), "abcd1234efgh") || strings.Contains(string(recorded), secretInResult) {
		t.Fatalf("the audit record holds a credential: %s", recorded)
	}
	if args, _ := r["arguments"].(map[string]any); args["limit"] != float64(5) {
		t.Fatalf("audit arguments = %v", r["arguments"])
	}
}

// Every tier, under the default policy and for both profiles: only the
// local profile's R0 runs, its R1 waits for an approval; every refusal is
// recorded and runs nothing.
func TestPolicyDecidesEveryTierForEveryProfile(t *testing.T) {
	t.Parallel()
	for _, profile := range []string{policy.ProfileLocal, policy.ProfileRemote, "unknown"} {
		for _, tier := range catalog.Tiers() {
			f := newFixture(t, policy.Default())
			wantRun := profile == policy.ProfileLocal && tier == catalog.R0

			out, err := f.gate.Call(context.Background(), &gate.Principal{Client: "c", Profile: profile}, "probe_"+string(tier), nil)
			if err != nil {
				t.Fatalf("%s/%s: %v", profile, tier, err)
			}

			ran := f.runs[tier].Load() == 1
			if ran != wantRun || out.Allowed != wantRun {
				t.Errorf("%s/%s: ran = %t, allowed = %t, want %t", profile, tier, ran, out.Allowed, wantRun)
			}
			records := f.records(t)
			wantDecision, wantResult := "deny", "refused"
			switch {
			case wantRun:
				wantDecision = "allow"
			case profile == policy.ProfileLocal && tier == catalog.R1:
				wantDecision, wantResult = "approval", "waiting for approval"
			}
			if len(records) != 1 || records[0]["decision"] != wantDecision {
				t.Errorf("%s/%s: audit records = %v", profile, tier, records)
			}
			if !wantRun && (out.Output != nil || records[0]["result"] != wantResult) {
				t.Errorf("%s/%s: a call that did not run produced output or was recorded as %v", profile, tier, records[0]["result"])
			}
			if out.Waiting != (wantDecision == "approval") {
				t.Errorf("%s/%s: waiting = %t", profile, tier, out.Waiting)
			}
		}
	}
}

// A tier the owner opens in the policy runs; this is the allow decision for
// the tiers the default policy denies.
func TestATierOpenedInThePolicyRuns(t *testing.T) {
	t.Parallel()
	for _, tier := range catalog.Tiers() {
		f := newFixture(t, parsePolicy(t, `{"version":1,"profiles":{"remote":{"`+string(tier)+`":"allow"}}}`))

		out, err := f.gate.Call(context.Background(), &gate.Principal{Client: "c", Profile: policy.ProfileRemote}, "probe_"+string(tier), nil)
		if err != nil {
			t.Fatalf("%s: %v", tier, err)
		}
		if !out.Allowed || f.runs[tier].Load() != 1 {
			t.Errorf("%s: allowed = %t, runs = %d", tier, out.Allowed, f.runs[tier].Load())
		}
	}
}

func TestUnknownToolIsRefusedAndRecorded(t *testing.T) {
	t.Parallel()
	f := newFixture(t, policy.Default())

	out, err := f.gate.Call(context.Background(), localClient, "call_any_service", json.RawMessage(`{"password":"x12345"}`))
	if err != nil {
		t.Fatalf("call: %v", err)
	}

	if out.Allowed || out.Output != nil {
		t.Fatalf("outcome = %+v", out)
	}
	records := f.records(t)
	if len(records) != 1 || records[0]["decision"] != "unknown_tool" || records[0]["tool"] != "call_any_service" {
		t.Fatalf("audit records = %v", records)
	}
}

func TestCallerWithoutIdentityIsRefusedAndRecorded(t *testing.T) {
	t.Parallel()
	for name, principal := range map[string]*gate.Principal{"nil": nil, "empty client": {Profile: policy.ProfileLocal}} {
		f := newFixture(t, policy.Default())

		out, err := f.gate.Call(context.Background(), principal, "probe_R0", nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		if out.Allowed || f.runs[catalog.R0].Load() != 0 {
			t.Errorf("%s: the tool ran for a caller without identity", name)
		}
		if records := f.records(t); len(records) != 1 || records[0]["decision"] != "unauthenticated" {
			t.Errorf("%s: audit records = %v", name, records)
		}
	}
}

func TestToolErrorIsRedactedReturnedAndRecorded(t *testing.T) {
	t.Parallel()
	failing := catalog.Tool{
		Name: "failing", Tier: catalog.R0,
		Handler: func(context.Context, catalog.Core, json.RawMessage) (json.RawMessage, error) {
			return nil, errors.New("connect to mqtt://user:" + secretInResult + "@broker failed")
		},
	}
	f := newFixture(t, policy.Default(), failing)

	out, err := f.gate.Call(context.Background(), localClient, "failing", nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}

	if out.Output != nil || !strings.Contains(out.Message, "failed") || strings.Contains(out.Message, secretInResult) {
		t.Fatalf("outcome = %+v", out)
	}
	records := f.records(t)
	recorded, _ := json.Marshal(records)
	if len(records) != 1 || strings.Contains(string(recorded), secretInResult) || !strings.Contains(string(recorded), "error: ") {
		t.Fatalf("audit records = %s", recorded)
	}
}

func TestResultThatCannotBeRedactedIsWithheld(t *testing.T) {
	t.Parallel()
	broken := catalog.Tool{
		Name: "broken", Tier: catalog.R0,
		Handler: func(context.Context, catalog.Core, json.RawMessage) (json.RawMessage, error) {
			return json.RawMessage(`{"password":"` + secretInResult + `"`), nil
		},
	}
	f := newFixture(t, policy.Default(), broken)

	out, err := f.gate.Call(context.Background(), localClient, "broken", nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if out.Output != nil || strings.Contains(out.Message, secretInResult) {
		t.Fatalf("outcome = %+v", out)
	}
}

// failingLog refuses every append.
type failingLog struct{}

func (failingLog) Append(context.Context, audit.Entry) (audit.Receipt, error) {
	return audit.Receipt{}, errors.New("disk full")
}

func TestResultIsWithheldWhenTheCallCannotBeRecorded(t *testing.T) {
	t.Parallel()
	var runs atomic.Int32
	g := gate.New(gate.Config{
		Policy: policy.Default(), Audit: failingLog{}, Tools: []catalog.Tool{probeTool(catalog.R0, &runs)}, Timeout: time.Second,
	})

	out, err := g.Call(context.Background(), localClient, "probe_R0", nil)

	if err == nil {
		t.Fatal("call succeeded although it was not recorded")
	}
	if out.Output != nil || out.Allowed {
		t.Fatalf("an unrecorded call returned something: %+v", out)
	}
}

func TestCallIsRecordedEvenWhenTheCallerHasGone(t *testing.T) {
	t.Parallel()
	f := newFixture(t, policy.Default())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := f.gate.Call(ctx, localClient, "probe_R0", nil); err != nil {
		t.Fatalf("call: %v", err)
	}
	if records := f.records(t); len(records) != 1 {
		t.Fatalf("%d audit records, want 1", len(records))
	}
}

// Every tool of the real catalogue has a tier the policy decides: under the
// default policy the local profile may use the R0 tools, and the R1 tools
// after an approval.
func TestEveryCatalogueToolIsDecidedByThePolicy(t *testing.T) {
	t.Parallel()
	for _, tool := range catalog.All() {
		got := policy.Default().Decide(policy.ProfileLocal, tool.Tier)
		want := policy.Deny
		switch tool.Tier {
		case catalog.R0:
			want = policy.Allow
		case catalog.R1:
			want = policy.Approval
		case catalog.R2, catalog.R3, catalog.R4:
		}
		if got != want {
			t.Errorf("tool %s (tier %s): decision %s, want %s", tool.Name, tool.Tier, got, want)
		}
	}
}

func TestEngagedKillSwitchRefusesEveryCallAndRecordsIt(t *testing.T) {
	t.Parallel()
	f := newFixture(t, parsePolicy(t, `{"version":1,"profiles":{"local":{"R0":"allow","R1":"allow","R2":"allow","R3":"allow","R4":"allow"}}}`))
	f.halted.Store(true)

	for _, tier := range catalog.Tiers() {
		out, err := f.gate.Call(context.Background(), localClient, "probe_"+string(tier), nil)
		if err != nil {
			t.Fatalf("%s: %v", tier, err)
		}
		if out.Allowed || out.Output != nil || f.runs[tier].Load() != 0 {
			t.Errorf("%s ran although the kill switch is engaged", tier)
		}
	}
	records := f.records(t)
	if len(records) != len(catalog.Tiers()) {
		t.Fatalf("%d audit records, want %d", len(records), len(catalog.Tiers()))
	}
	for _, r := range records {
		if r["decision"] != "halted" || r["result"] != "refused" {
			t.Errorf("audit record = %v", r)
		}
	}

	f.halted.Store(false)
	if out, _ := f.gate.Call(context.Background(), localClient, "probe_R0", nil); !out.Allowed {
		t.Fatal("the gate stayed closed after the kill switch was released")
	}
}

func TestClientIsLimitedToItsCallsPerMinuteAndRecovers(t *testing.T) {
	t.Parallel()
	f := newFixture(t, parsePolicy(t, `{"version":1,"profiles":{"local":{"R0":"allow"}},"limits":{"local":{"calls_per_minute":3}}}`))
	now := time.Unix(1_800_000_000, 0)
	f.gate.SetClock(func() time.Time { return now })
	other := &gate.Principal{Client: "client-b", Profile: policy.ProfileLocal}

	for i := range 3 {
		if out, _ := f.gate.Call(context.Background(), localClient, "probe_R0", nil); !out.Allowed {
			t.Fatalf("call %d within the limit was refused", i+1)
		}
	}
	out, err := f.gate.Call(context.Background(), localClient, "probe_R0", nil)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if out.Allowed || f.runs[catalog.R0].Load() != 3 {
		t.Fatalf("the fourth call ran: allowed = %t, runs = %d", out.Allowed, f.runs[catalog.R0].Load())
	}
	records := f.records(t)
	if last := records[len(records)-1]; last["decision"] != "rate_limited" || last["result"] != "refused" {
		t.Fatalf("audit record of the refused call = %v", last)
	}

	// Another client has its own allowance.
	if out, _ := f.gate.Call(context.Background(), other, "probe_R0", nil); !out.Allowed {
		t.Fatal("another client was refused because of the first one's calls")
	}

	// A third of a minute refills one call of three.
	now = now.Add(21 * time.Second)
	if out, _ := f.gate.Call(context.Background(), localClient, "probe_R0", nil); !out.Allowed {
		t.Fatal("the client was still refused after waiting")
	}
	if out, _ := f.gate.Call(context.Background(), localClient, "probe_R0", nil); out.Allowed {
		t.Fatal("the client got more than its refill")
	}
}

// Refused calls count too, so a client cannot fill the audit log faster
// than its limit allows.
func TestRefusedCallsCountAgainstTheLimit(t *testing.T) {
	t.Parallel()
	f := newFixture(t, parsePolicy(t, `{"version":1,"profiles":{"local":{"R0":"allow"}},"limits":{"local":{"calls_per_minute":2}}}`))
	now := time.Unix(1_800_000_000, 0)
	f.gate.SetClock(func() time.Time { return now })

	for range 2 {
		if _, err := f.gate.Call(context.Background(), localClient, "no_such_tool", nil); err != nil {
			t.Fatal(err)
		}
	}
	if out, _ := f.gate.Call(context.Background(), localClient, "probe_R0", nil); out.Allowed {
		t.Fatal("an allowed call ran after the limit was used up by refused ones")
	}
}

const kitchenOn = `{"entity_id":"light.kitchen"}`

func (f fixture) call(t *testing.T, principal *gate.Principal, tool, args string) gate.Outcome {
	t.Helper()
	out, err := f.gate.Call(context.Background(), principal, tool, json.RawMessage(args))
	if err != nil {
		t.Fatalf("call %s: %v", tool, err)
	}
	return out
}

// decide approves or denies the one waiting request as admin-1.
func (f fixture) decide(t *testing.T, approve bool) approval.Request {
	t.Helper()
	pending := f.approvals.Pending()
	if len(pending) != 1 {
		t.Fatalf("%d requests wait, want 1", len(pending))
	}
	if err := f.approvals.Decide(context.Background(), pending[0].ID, approve, "admin-1"); err != nil {
		t.Fatalf("decide: %v", err)
	}
	return pending[0]
}

// The approval decision, end to end on a real control tool: the call waits
// without running, runs once after the approval, and waits again after.
func TestCallThatNeedsApprovalRunsOnceAfterAnAdministratorApprovedIt(t *testing.T) {
	t.Parallel()
	f := newFixture(t, policy.Default())

	first := f.call(t, localClient, "light_turn_on", kitchenOn)
	if !first.Waiting || first.Allowed || first.Output != nil || !strings.HasPrefix(first.Message, "NOT RUN YET") {
		t.Fatalf("first call = %+v, want it to wait", first)
	}
	if len(f.home.called()) != 0 {
		t.Fatal("the service was called before the approval")
	}
	shown := f.decide(t, true)
	if shown.Summary != "Turn on light.kitchen" || shown.Client != "client-a" || shown.Tool != "light_turn_on" ||
		len(shown.Entities) != 1 || shown.Entities[0] != (approval.Entity{ID: "light.kitchen", Name: "Kitchen ceiling"}) ||
		string(shown.Arguments) != kitchenOn {
		t.Fatalf("the owner was shown %+v", shown)
	}

	// The same JSON value, written differently.
	second := f.call(t, localClient, "light_turn_on", ` { "entity_id" : "light.kitchen" } `)
	if !second.Allowed || second.Waiting || !strings.Contains(string(second.Output), `"called":"light.turn_on"`) {
		t.Fatalf("call after the approval = %+v", second)
	}
	want := `{"domain":"light","service":"turn_on","target":{"entity_id":["light.kitchen"]}}`
	if calls := f.home.called(); len(calls) != 1 || calls[0] != want {
		t.Fatalf("services called = %v, want one %s", calls, want)
	}

	third := f.call(t, localClient, "light_turn_on", kitchenOn)
	if !third.Waiting || len(f.home.called()) != 1 {
		t.Fatalf("the approval was used twice: %+v, %d service calls", third, len(f.home.called()))
	}

	records := f.records(t)
	if len(records) != 4 {
		t.Fatalf("%d audit records, want 4: %v", len(records), records)
	}
	if r := records[0]; r["decision"] != "approval" || r["result"] != "waiting for approval" || r["approver"] != nil {
		t.Errorf("record of the waiting call = %v", r)
	}
	if r := records[1]; r["event"] != "action_approved" || r["approver"] != "admin-1" || r["tool"] != "light_turn_on" {
		t.Errorf("record of the approval = %v", r)
	}
	if r := records[2]; r["decision"] != "approval" || r["approver"] != "admin-1" || !strings.HasPrefix(r["result"].(string), "ok: ") {
		t.Errorf("record of the run = %v", r)
	}
}

func TestApprovalDoesNotCarryOverToAnotherClientToolOrEntity(t *testing.T) {
	t.Parallel()
	f := newFixture(t, policy.Default())
	f.call(t, localClient, "light_turn_on", kitchenOn)
	f.decide(t, true)

	otherClient := &gate.Principal{Client: "client-b", Profile: policy.ProfileLocal}
	if out := f.call(t, otherClient, "light_turn_on", kitchenOn); !out.Waiting {
		t.Errorf("another client used the approval: %+v", out)
	}
	if out := f.call(t, localClient, "light_turn_off", kitchenOn); !out.Waiting {
		t.Errorf("another tool used the approval: %+v", out)
	}
	if out := f.call(t, localClient, "light_turn_on", `{"entity_id":"light.hall"}`); !out.Waiting {
		t.Errorf("another entity used the approval: %+v", out)
	}
	if calls := f.home.called(); len(calls) != 0 {
		t.Fatalf("services called without an approval of their own: %v", calls)
	}
	if out := f.call(t, localClient, "light_turn_on", kitchenOn); !out.Allowed {
		t.Fatalf("the approved call itself did not run: %+v", out)
	}
}

func TestDeniedCallDoesNotRunAndIsRecorded(t *testing.T) {
	t.Parallel()
	f := newFixture(t, policy.Default())
	f.call(t, localClient, "light_turn_on", kitchenOn)
	f.decide(t, false)

	out := f.call(t, localClient, "light_turn_on", kitchenOn)

	if out.Allowed || out.Waiting || !strings.Contains(out.Message, "denied") || len(f.home.called()) != 0 {
		t.Fatalf("call after the denial = %+v, %d service calls", out, len(f.home.called()))
	}
	records := f.records(t)
	if r := records[len(records)-1]; r["result"] != "refused: denied by an administrator" || r["approver"] != "admin-1" {
		t.Fatalf("record = %v", r)
	}
}

// An entity is controlled only if the owner released it with the label —
// whether the policy asks for an approval or not. Nothing else is even put
// before the owner.
func TestOnlyEntitiesTheOwnerReleasedAreControlled(t *testing.T) {
	t.Parallel()
	policies := map[string]policy.Policy{
		"approval": policy.Default(),
		"allow":    parsePolicy(t, `{"version":1,"profiles":{"local":{"R1":"allow"}}}`),
	}
	for name, pol := range policies {
		f := newFixture(t, pol)
		for entity, why := range map[string]string{
			"light.cellar":  "carries another label",
			"light.unknown": "does not exist",
		} {
			out := f.call(t, localClient, "light_turn_on", `{"entity_id":"`+entity+`"}`)
			if out.Allowed || out.Waiting || !strings.Contains(out.Message, `"airlock"`) {
				t.Errorf("%s: %s (%s) = %+v, want a refusal", name, entity, why, out)
			}
			if strings.Contains(out.Message, "exist") || strings.Contains(out.Message, "not_found") {
				t.Errorf("%s: the refusal tells the client whether %s exists: %s", name, entity, out.Message)
			}
		}
		if out := f.call(t, localClient, "light_turn_on", `{"entity_id":"lock.front_door"}`); out.Allowed || out.Waiting {
			t.Errorf("%s: an entity of another domain = %+v", name, out)
		}
		if len(f.approvals.Pending()) != 0 || len(f.home.called()) != 0 {
			t.Errorf("%s: %d requests wait, %d services called; want none", name, len(f.approvals.Pending()), len(f.home.called()))
		}
		records := f.records(t)
		for _, i := range []int{0, 1} {
			if records[i]["decision"] != "not_released" || !strings.HasPrefix(records[i]["result"].(string), "refused: light.") {
				t.Errorf("%s: record %d = %v", name, i, records[i])
			}
		}
	}

	f := newFixture(t, policies["allow"])
	if out := f.call(t, localClient, "light_turn_on", kitchenOn); !out.Allowed || len(f.home.called()) != 1 {
		t.Fatalf("a released entity under allow = %+v", out)
	}
}

func TestTheControlLabelIsTheOneThePolicyNames(t *testing.T) {
	t.Parallel()
	f := newFixture(t, parsePolicy(t, `{"version":1,"profiles":{"local":{"R1":"allow"}},"control_label":"other"}`))
	if out := f.call(t, localClient, "light_turn_on", `{"entity_id":"light.cellar"}`); !out.Allowed {
		t.Errorf("the entity with the policy's label = %+v", out)
	}
	if out := f.call(t, localClient, "light_turn_on", `{"entity_id":"light.hall"}`); out.Allowed {
		t.Errorf("an entity with the default label ran under another label: %+v", out)
	}
}

func TestReleaseWithdrawnAfterTheApprovalStopsTheCall(t *testing.T) {
	t.Parallel()
	f := newFixture(t, policy.Default())
	f.call(t, localClient, "light_turn_on", kitchenOn)
	f.decide(t, true)
	f.home.setLabels("light.kitchen")

	out := f.call(t, localClient, "light_turn_on", kitchenOn)

	if out.Allowed || out.Waiting || len(f.home.called()) != 0 {
		t.Fatalf("call = %+v, %d service calls; want a refusal", out, len(f.home.called()))
	}
}

func TestApprovedCallDoesNotRunWhileTheKillSwitchIsEngaged(t *testing.T) {
	t.Parallel()
	f := newFixture(t, policy.Default())
	f.call(t, localClient, "light_turn_on", kitchenOn)
	f.decide(t, true)
	f.halted.Store(true)

	out := f.call(t, localClient, "light_turn_on", kitchenOn)

	if out.Allowed || len(f.home.called()) != 0 || !strings.Contains(out.Message, "halted") {
		t.Fatalf("call = %+v, %d service calls", out, len(f.home.called()))
	}
}

// The approval decision applies to any tier: a read the policy wants
// approved waits like an action.
func TestApprovalWorksForATierWithoutEntities(t *testing.T) {
	t.Parallel()
	f := newFixture(t, parsePolicy(t, `{"version":1,"profiles":{"local":{"R0":"approval","R2":"approval"}}}`))
	for tier, summary := range map[catalog.Tier]string{catalog.R0: "Run probe_R0", catalog.R2: "Probe tier R2"} {
		if out := f.call(t, localClient, "probe_"+string(tier), `{}`); !out.Waiting || f.runs[tier].Load() != 0 {
			t.Fatalf("%s: %+v", tier, out)
		}
		if shown := f.decide(t, true); shown.Summary != summary {
			t.Fatalf("%s: the owner was shown %q, want %q", tier, shown.Summary, summary)
		}
		if out := f.call(t, localClient, "probe_"+string(tier), `{}`); !out.Allowed || f.runs[tier].Load() != 1 {
			t.Fatalf("%s after approval: %+v", tier, out)
		}
	}
}

func TestToolAboveR0ThatDoesNotStateItsActionIsRefused(t *testing.T) {
	t.Parallel()
	var runs atomic.Int32
	silent := probeTool(catalog.R1, &runs)
	silent.Name, silent.Act = "silent", nil
	f := newFixture(t, parsePolicy(t, `{"version":1,"profiles":{"local":{"R1":"allow"}}}`), silent)

	out := f.call(t, localClient, "silent", `{}`)

	if out.Allowed || runs.Load() != 0 {
		t.Fatalf("call = %+v, runs = %d", out, runs.Load())
	}
	if r := f.records(t)[0]; r["decision"] != "undeclared_action" {
		t.Fatalf("record = %v", r)
	}
}

func TestCallThatNeedsApprovalIsRefusedWhereNoneCanBeGiven(t *testing.T) {
	t.Parallel()
	log, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	var runs atomic.Int32
	g := gate.New(gate.Config{Policy: policy.Default(), Audit: log, Tools: []catalog.Tool{probeTool(catalog.R1, &runs)}, Timeout: time.Second})

	out, err := g.Call(context.Background(), localClient, "probe_R1", nil)

	if err != nil || out.Allowed || out.Waiting || runs.Load() != 0 {
		t.Fatalf("call = %+v, %v, runs = %d", out, err, runs.Load())
	}
}

func TestClientWithTooManyWaitingCallsIsToldSo(t *testing.T) {
	t.Parallel()
	f := newFixture(t, parsePolicy(t, `{"version":1,"profiles":{"local":{"R2":"approval"}}}`))
	var last gate.Outcome
	for i := range 6 {
		last = f.call(t, localClient, "probe_R2", `{"n":`+string(rune('0'+i))+`}`)
	}
	if last.Waiting || last.Allowed || !strings.Contains(last.Message, "too many") || len(f.approvals.Pending()) != 5 {
		t.Fatalf("sixth call = %+v, %d waiting", last, len(f.approvals.Pending()))
	}
}
