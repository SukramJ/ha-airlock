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
	"sync/atomic"
	"testing"
	"time"

	"github.com/SukramJ/ha-airlock/internal/audit"
	"github.com/SukramJ/ha-airlock/internal/catalog"
	"github.com/SukramJ/ha-airlock/internal/gate"
	"github.com/SukramJ/ha-airlock/internal/policy"
)

const secretInResult = "hunter2pass"

// probeTool is a tool of the given tier that counts how often it ran and
// returns a result with a credential in it.
func probeTool(tier catalog.Tier, runs *atomic.Int32) catalog.Tool {
	return catalog.Tool{
		Name: "probe_" + string(tier),
		Tier: tier,
		Handler: func(context.Context, catalog.Core, json.RawMessage) (json.RawMessage, error) {
			runs.Add(1)
			return json.RawMessage(`{"password":"` + secretInResult + `","state":"on"}`), nil
		},
	}
}

type fixture struct {
	gate      *gate.Gate
	auditPath string
	runs      map[catalog.Tier]*atomic.Int32
}

func newFixture(t *testing.T, pol policy.Policy, extra ...catalog.Tool) fixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.Open(path)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	f := fixture{auditPath: path, runs: map[catalog.Tier]*atomic.Int32{}}
	tools := extra
	for _, tier := range catalog.Tiers() {
		f.runs[tier] = &atomic.Int32{}
		tools = append(tools, probeTool(tier, f.runs[tier]))
	}
	f.gate = gate.New(pol, log, nil, tools, 5*time.Second)
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
// local profile's R0 runs; every refusal is recorded and runs nothing.
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
			wantDecision := "deny"
			if wantRun {
				wantDecision = "allow"
			}
			if len(records) != 1 || records[0]["decision"] != wantDecision {
				t.Errorf("%s/%s: audit records = %v", profile, tier, records)
			}
			if !wantRun && (out.Output != nil || records[0]["result"] != "refused") {
				t.Errorf("%s/%s: a refused call produced output or was not recorded as refused", profile, tier)
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
	g := gate.New(policy.Default(), failingLog{}, nil, []catalog.Tool{probeTool(catalog.R0, &runs)}, time.Second)

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
// default policy the local profile may use exactly the R0 tools.
func TestEveryCatalogueToolIsDecidedByThePolicy(t *testing.T) {
	t.Parallel()
	for _, tool := range catalog.All() {
		got := policy.Default().Decide(policy.ProfileLocal, tool.Tier)
		want := policy.Deny
		if tool.Tier == catalog.R0 {
			want = policy.Allow
		}
		if got != want {
			t.Errorf("tool %s (tier %s): decision %s, want %s", tool.Name, tool.Tier, got, want)
		}
	}
}
