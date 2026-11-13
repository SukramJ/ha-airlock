// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package gate_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SukramJ/ha-airlock/internal/approval"
	"github.com/SukramJ/ha-airlock/internal/audit"
	"github.com/SukramJ/ha-airlock/internal/catalog"
	"github.com/SukramJ/ha-airlock/internal/changes"
	"github.com/SukramJ/ha-airlock/internal/gate"
)

// helpers is the configuration two test tools change: helper_set replaces
// the helper an entity stands for, helper_new creates one.
type helpers struct {
	mu     sync.Mutex
	states map[string]string
	plans  int
	// journalled is how many changes the journal held when the last write
	// was made.
	journalled int
	fail       error
}

func (h *helpers) state(entity string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.states[entity]
}

func (h *helpers) set(entity, state string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.states[entity] = state
}

func (h *helpers) tools(f *fixture) []catalog.Tool {
	decode := func(args json.RawMessage) (entity, after string, err error) {
		var in struct {
			EntityID string `json:"entity_id"`
			Name     string `json:"name"`
		}
		if err := json.Unmarshal(args, &in); err != nil {
			return "", "", err
		}
		state, err := json.Marshal(map[string]string{"name": in.Name})
		return in.EntityID, string(state), err
	}
	write := func(entity, after string) func(context.Context, catalog.Core) (string, json.RawMessage, error) {
		return func(context.Context, catalog.Core) (string, json.RawMessage, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.journalled = len(f.journal.List())
			if h.fail != nil {
				return "", nil, h.fail
			}
			h.states[entity] = after
			return entity, json.RawMessage(`{"password":"` + secretInResult + `","done":true}`), nil
		}
	}
	return []catalog.Tool{
		{
			Name: "helper_set", Tier: catalog.R2, Kind: catalog.KindHelper,
			Plan: func(_ context.Context, _ catalog.Core, args json.RawMessage) (catalog.Change, error) {
				entity, after, err := decode(args)
				if err != nil {
					return catalog.Change{}, err
				}
				h.mu.Lock()
				defer h.mu.Unlock()
				h.plans++
				before, ok := h.states[entity]
				if !ok {
					return catalog.Change{}, errors.New("there is no such helper")
				}
				return catalog.Change{
					Summary: "Change helper " + entity, Object: entity, Name: "Guests", Entity: entity,
					Before: json.RawMessage(before), After: json.RawMessage(after), Apply: write(entity, after),
				}, nil
			},
		},
		{
			Name: "helper_new", Tier: catalog.R2, Kind: catalog.KindHelper,
			Plan: func(_ context.Context, _ catalog.Core, args json.RawMessage) (catalog.Change, error) {
				_, after, err := decode(args)
				if err != nil {
					return catalog.Change{}, err
				}
				apply := write("input_boolean.new", after)
				return catalog.Change{
					Summary: "Create a helper", After: json.RawMessage(after),
					Apply: func(ctx context.Context, core catalog.Core) (string, json.RawMessage, error) {
						// Home Assistant registers the entity of a new helper.
						f.home.setLabels("input_boolean.new", "kitchen")
						return apply(ctx, core)
					},
				}, nil
			},
		},
	}
}

// changing returns a fixture whose Home Assistant holds one released
// helper, input_boolean.guest, and one that is not, input_boolean.private.
func changing(t *testing.T, policyText string) (*fixture, *helpers) {
	t.Helper()
	h := &helpers{states: map[string]string{
		"input_boolean.guest":   `{"name":"Guests"}`,
		"input_boolean.private": `{"name":"Private"}`,
	}}
	var f fixture
	f = newFixture(t, parsePolicy(t, policyText), h.tools(&f)...)
	f.home.setLabels("input_boolean.guest", "airlock")
	f.home.setLabels("input_boolean.private", "kitchen")
	return &f, h
}

const setGuest = `{"entity_id":"input_boolean.guest","name":"Visitors"}`

func TestChangeWaitsWithItsDifferenceAndIsMadeAfterApproval(t *testing.T) {
	t.Parallel()
	f, h := changing(t, changePolicy)

	if out := f.call(t, localClient, "helper_set", setGuest); !out.Waiting || out.Allowed || h.state("input_boolean.guest") != `{"name":"Guests"}` {
		t.Fatalf("first call = %+v, state %s", out, h.state("input_boolean.guest"))
	}
	pending := f.approvals.Pending()
	if len(pending) != 1 || pending[0].Change == nil {
		t.Fatalf("pending = %+v", pending)
	}
	shown := pending[0].Change
	if shown.Kind != "helper" || shown.Object != "input_boolean.guest" || shown.Name != "Guests" ||
		string(shown.Before) != `{"name":"Guests"}` || string(shown.After) != `{"name":"Visitors"}` || shown.Note != "" ||
		pending[0].Summary != "Change helper input_boolean.guest" {
		t.Fatalf("the owner is shown %+v, %q", shown, pending[0].Summary)
	}
	if len(f.journal.List()) != 0 {
		t.Fatal("a change was journalled before it was approved")
	}
	f.decide(t, true)

	out := f.call(t, localClient, "helper_set", setGuest)
	if !out.Allowed || out.Output == nil || h.state("input_boolean.guest") != `{"name":"Visitors"}` {
		t.Fatalf("call after approval = %+v, state %s", out, h.state("input_boolean.guest"))
	}
	if strings.Contains(string(out.Output), secretInResult) {
		t.Fatalf("the result of a change left unredacted: %s", out.Output)
	}
	if h.journalled != 1 {
		t.Fatalf("the journal held %d changes when the write was made, want 1", h.journalled)
	}
	journal := f.journal.List()
	if len(journal) != 1 || journal[0].Object != "input_boolean.guest" || journal[0].Kind != "helper" || journal[0].Tool != "helper_set" ||
		journal[0].Client != localClient.Client || string(journal[0].Before) != `{"name":"Guests"}` ||
		string(journal[0].After) != `{"name":"Visitors"}` || journal[0].Failed != "" {
		t.Fatalf("journal = %+v", journal)
	}
	before, _ := changes.Hash(journal[0].Before)
	after, _ := changes.Hash(journal[0].After)
	records := f.records(t)
	last, _ := records[len(records)-1]["result"].(string)
	if want := "; change " + journal[0].ID + ", before " + before + ", after " + after; !strings.HasPrefix(last, "ok: ") || !strings.HasSuffix(last, want) {
		t.Fatalf("audit result = %q, want it to end with %q", last, want)
	}
	// An update gets no label: only what ha-airlock created does.
	if got := f.home.labelsOf("input_boolean.guest"); len(got) != 1 || got[0] != "airlock" {
		t.Fatalf("labels after an update = %v", got)
	}
	// The approval was for one call.
	if out := f.call(t, localClient, "helper_set", `{"entity_id":"input_boolean.guest","name":"Guests"}`); !out.Waiting {
		t.Fatalf("a second change ran without an approval: %+v", out)
	}
}

// An approval is for replacing the state the owner was shown. If the object
// is another by the time the call is repeated, the change is not made, and
// the owner is shown the new difference.
func TestApprovalDoesNotApplyOnceTheObjectHasChanged(t *testing.T) {
	t.Parallel()
	f, h := changing(t, changePolicy)
	f.call(t, localClient, "helper_set", setGuest)
	f.decide(t, true)
	h.set("input_boolean.guest", `{"name":"Renamed by hand"}`)

	out := f.call(t, localClient, "helper_set", setGuest)

	if !out.Waiting || out.Allowed || h.state("input_boolean.guest") != `{"name":"Renamed by hand"}` || len(f.journal.List()) != 0 {
		t.Fatalf("call = %+v, state %s, journal %d", out, h.state("input_boolean.guest"), len(f.journal.List()))
	}
	shown := make([]string, 0, 1)
	for _, p := range f.approvals.Pending() {
		shown = append(shown, string(p.Change.Before))
	}
	if len(shown) != 1 || shown[0] != `{"name":"Renamed by hand"}` {
		t.Fatalf("the owner is shown %v as the present state", shown)
	}
}

func TestKindThePolicyDoesNotOpenIsRefusedBeforeHomeAssistantIsRead(t *testing.T) {
	t.Parallel()
	for name, text := range map[string]string{
		"kind not mentioned": `{"version":1,"profiles":{"local":{"R2":"approval"}}}`,
		"kind denied":        `{"version":1,"profiles":{"local":{"R2":"approval"}},"configuration":{"local":{"helper":{"change":"deny"}}}}`,
		"another kind open":  `{"version":1,"profiles":{"local":{"R2":"approval"}},"configuration":{"local":{"scene":{"change":"approval"}}}}`,
	} {
		f, h := changing(t, text)
		out := f.call(t, localClient, "helper_set", setGuest)
		if out.Allowed || out.Waiting || h.plans != 0 || len(f.approvals.Pending()) != 0 {
			t.Errorf("%s: call = %+v, plans = %d", name, out, h.plans)
		}
		if r := f.records(t)[0]; r["decision"] != "kind_denied" || r["result"] != "refused" {
			t.Errorf("%s: record = %v", name, r)
		}
	}
}

func TestObjectWithoutTheLabelIsChangedOnlyIfItsKindIsReleasedAsAWhole(t *testing.T) {
	t.Parallel()
	const setPrivate = `{"entity_id":"input_boolean.private","name":"Open"}`
	f, _ := changing(t, changePolicy)
	out := f.call(t, localClient, "helper_set", setPrivate)
	if out.Allowed || out.Waiting || len(f.approvals.Pending()) != 0 || !strings.Contains(out.Message, "not released") {
		t.Fatalf("call for an object without the label = %+v", out)
	}
	if r := f.records(t)[0]; r["decision"] != "not_released" {
		t.Fatalf("record = %v", r)
	}

	f, h := changing(t, `{"version":1,"profiles":{"local":{"R2":"approval"}},"configuration":{"local":{"helper":{"change":"approval","release":"all"}}}}`)
	if out := f.call(t, localClient, "helper_set", setPrivate); !out.Waiting {
		t.Fatalf("with the kind released as a whole: %+v", out)
	}
	// Released is not approved.
	if h.state("input_boolean.private") != `{"name":"Private"}` {
		t.Fatal("the object was changed without an approval")
	}
}

func TestChangeIsNotMadeWhenTheJournalCannotRecordIt(t *testing.T) {
	t.Parallel()
	f, h := changing(t, changePolicy)
	f.call(t, localClient, "helper_set", setGuest)
	f.decide(t, true)
	if err := os.RemoveAll(f.journalDir); err != nil {
		t.Fatal(err)
	}

	out := f.call(t, localClient, "helper_set", setGuest)

	if out.Allowed || out.Waiting || h.state("input_boolean.guest") != `{"name":"Guests"}` || !strings.Contains(out.Message, "not made") {
		t.Fatalf("call = %+v, state %s", out, h.state("input_boolean.guest"))
	}
	records := f.records(t)
	if last := records[len(records)-1]["result"]; last != "refused: the change could not be recorded in the journal" {
		t.Fatalf("audit result = %v", last)
	}
}

func TestWriteThatFailsIsNotedInTheJournal(t *testing.T) {
	t.Parallel()
	f, h := changing(t, changePolicy)
	h.fail = errors.New("home assistant refused: token abcdefgh12345678abcdefgh12345678 is not valid")
	f.call(t, localClient, "helper_set", setGuest)
	f.decide(t, true)

	out := f.call(t, localClient, "helper_set", setGuest)

	if out.Output != nil || !strings.Contains(out.Message, "home assistant refused") || h.state("input_boolean.guest") != `{"name":"Guests"}` {
		t.Fatalf("call = %+v", out)
	}
	journal := f.journal.List()
	if len(journal) != 1 || !strings.Contains(journal[0].Failed, "home assistant refused") {
		t.Fatalf("journal = %+v", journal)
	}
}

// What ha-airlock created carries the control label afterwards, beside the
// labels Home Assistant gave it, and the owner was told so before approving.
func TestCreatedObjectIsGivenTheControlLabel(t *testing.T) {
	t.Parallel()
	f, h := changing(t, changePolicy)
	const create = `{"name":"Party"}`

	if out := f.call(t, localClient, "helper_new", create); !out.Waiting {
		t.Fatalf("first call = %+v", out)
	}
	shown := f.approvals.Pending()[0].Change
	if len(shown.Before) != 0 || string(shown.After) != `{"name":"Party"}` || shown.Object != "" || !strings.Contains(shown.Note, `the label "airlock"`) {
		t.Fatalf("the owner is shown %+v", shown)
	}
	f.decide(t, true)

	if out := f.call(t, localClient, "helper_new", create); !out.Allowed || h.state("input_boolean.new") != `{"name":"Party"}` {
		t.Fatalf("call after approval = %+v", out)
	}
	if got := f.home.labelsOf("input_boolean.new"); len(got) != 2 || got[0] != "kitchen" || got[1] != "airlock" {
		t.Fatalf("labels of the new object = %v, want kitchen and airlock", got)
	}
	if journal := f.journal.List(); len(journal) != 1 || journal[0].Object != "input_boolean.new" || len(journal[0].Before) != 0 {
		t.Fatalf("journal = %+v", journal)
	}
}

func TestChangeAboveTheBoundIsRefusedNotCut(t *testing.T) {
	t.Parallel()
	f, _ := changing(t, changePolicy)
	args := `{"entity_id":"input_boolean.guest","name":"` + strings.Repeat("x", approval.MaxDifferenceBytes) + `"}`

	out := f.call(t, localClient, "helper_set", args)

	if out.Allowed || out.Waiting || len(f.approvals.Pending()) != 0 {
		t.Fatalf("call = %+v", out)
	}
	if r := f.records(t)[0]; r["decision"] != "too_large" {
		t.Fatalf("record = %v", r)
	}
}

// A tool of tier R2 changes something through its plan only. One without a
// plan, or with another way to run, is refused whatever the policy says.
func TestToolOfR2ThatDoesNotDeclareItsChangeIsRefused(t *testing.T) {
	t.Parallel()
	ran := false
	run := func(context.Context, catalog.Core, json.RawMessage) (json.RawMessage, error) {
		ran = true
		return json.RawMessage(`{}`), nil
	}
	plan := func(context.Context, catalog.Core, json.RawMessage) (catalog.Change, error) {
		return catalog.Change{Summary: "x", After: json.RawMessage(`{}`), Apply: func(context.Context, catalog.Core) (string, json.RawMessage, error) {
			ran = true
			return "", json.RawMessage(`{}`), nil
		}}, nil
	}
	cases := map[string]catalog.Tool{
		"no plan":           {Tier: catalog.R2, Kind: catalog.KindHelper, Handler: run},
		"no kind":           {Tier: catalog.R2, Plan: plan},
		"a handler as well": {Tier: catalog.R2, Kind: catalog.KindHelper, Plan: plan, Handler: run},
		"an action as well": {Tier: catalog.R2, Kind: catalog.KindHelper, Plan: plan, Act: func(json.RawMessage) (catalog.Action, error) { return catalog.Action{}, nil }},
		"a plan that is empty": {Tier: catalog.R2, Kind: catalog.KindHelper, Plan: func(context.Context, catalog.Core, json.RawMessage) (catalog.Change, error) {
			return catalog.Change{Summary: "x"}, nil
		}},
	}
	for name, tool := range cases {
		tool.Name = "odd"
		f := newFixture(t, parsePolicy(t, changePolicy), tool)
		out := f.call(t, localClient, "odd", `{}`)
		if out.Allowed || out.Waiting || ran {
			t.Errorf("%s: call = %+v, ran = %t", name, out, ran)
		}
		if r := f.records(t)[0]; r["decision"] != "undeclared_change" {
			t.Errorf("%s: record = %v", name, r)
		}
	}
}

func TestNoConfigurationIsChangedWithoutAJournal(t *testing.T) {
	t.Parallel()
	f, h := changing(t, changePolicy)
	without := gate.New(gate.Config{
		Policy: parsePolicy(t, changePolicy), Audit: unrecorded{}, Core: f.home, Tools: h.tools(f),
		Timeout: 5 * time.Second, Approvals: f.approvals,
	})

	out, err := without.Call(context.Background(), localClient, "helper_set", json.RawMessage(setGuest))

	if err != nil || out.Allowed || out.Waiting || h.plans != 0 || !strings.Contains(out.Message, "makes none") {
		t.Fatalf("call = %+v, %v, plans = %d", out, err, h.plans)
	}
}

// unrecorded is an audit log that keeps nothing.
type unrecorded struct{}

func (unrecorded) Append(context.Context, audit.Entry) (audit.Receipt, error) {
	return audit.Receipt{}, nil
}
