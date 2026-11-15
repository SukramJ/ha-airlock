// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package gate_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/SukramJ/ha-airlock/internal/audit"
	"github.com/SukramJ/ha-airlock/internal/catalog"
	"github.com/SukramJ/ha-airlock/internal/gate"
)

// registryPolicy opens areas and labels besides helpers.
const registryPolicy = `{"version":1,"profiles":{"local":{"R2":"approval"}},"configuration":{"local":{` +
	`"helper":{"change":"approval"},"area":{"change":"approval"},"label":{"change":"approval"}}}}`

// registryTools are tools of the kinds area and label whose objects live in
// the test's own map, not in Home Assistant: what the gate does around them
// is under test, not the tools.
func registryTools(states map[string]string) []catalog.Tool {
	set := func(kind catalog.Kind, holder bool) func(context.Context, catalog.Core, json.RawMessage) (catalog.Change, error) {
		return func(_ context.Context, _ catalog.Core, args json.RawMessage) (catalog.Change, error) {
			var in struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			}
			if err := json.Unmarshal(args, &in); err != nil {
				return catalog.Change{}, err
			}
			after := `{"name":"` + in.Name + `"}`
			change := catalog.Change{
				Summary: "Change " + string(kind) + " " + in.ID, Object: in.ID, Before: json.RawMessage(states[in.ID]), After: json.RawMessage(after),
				Apply: func(context.Context, catalog.Core) (string, json.RawMessage, error) {
					states[in.ID] = after
					return in.ID, json.RawMessage(`{}`), nil
				},
			}
			if holder {
				change.Holder = in.ID
			}
			return change, nil
		}
	}
	create := func(id string) func(context.Context, catalog.Core, json.RawMessage) (catalog.Change, error) {
		return func(context.Context, catalog.Core, json.RawMessage) (catalog.Change, error) {
			return catalog.Change{
				Summary: "Create " + id, After: json.RawMessage(`{"name":"New"}`),
				Apply: func(context.Context, catalog.Core) (string, json.RawMessage, error) {
					states[id] = `{"name":"New"}`
					return id, json.RawMessage(`{}`), nil
				},
			}, nil
		}
	}
	back := func(_ context.Context, _ catalog.Core, object string, before, _ json.RawMessage) (catalog.Change, error) {
		return catalog.Change{
			Summary: "Take back", Object: object, Before: json.RawMessage(states[object]), After: before,
			Apply: func(context.Context, catalog.Core) (string, json.RawMessage, error) {
				states[object] = string(before)
				return object, json.RawMessage(`{}`), nil
			},
		}, nil
	}
	return []catalog.Tool{
		{Name: "area_set", Tier: catalog.R2, Kind: catalog.KindArea, Plan: set(catalog.KindArea, true), Revert: back},
		{Name: "area_new", Tier: catalog.R2, Kind: catalog.KindArea, Plan: create("garden"), Revert: back},
		{Name: "label_set", Tier: catalog.R2, Kind: catalog.KindLabel, Plan: set(catalog.KindLabel, false), Revert: back},
		{Name: "label_new", Tier: catalog.R2, Kind: catalog.KindLabel, Plan: create("party"), Revert: back},
	}
}

func registries(t *testing.T, policyText string) (f *fixture, states map[string]string) {
	t.Helper()
	states = map[string]string{
		"kitchen": `{"name":"Kitchen"}`, "cellar": `{"name":"Cellar"}`,
		"airlock": `{"name":"airlock"}`, "other": `{"name":"Other"}`,
	}
	built := newFixture(t, parsePolicy(t, policyText), registryTools(states)...)
	return &built, states
}

// An area carries the control label itself, in the area registry: an area
// without it is not changed unless the kind is released as a whole.
func TestAreaIsReleasedByItsOwnLabel(t *testing.T) {
	t.Parallel()
	f, _ := registries(t, registryPolicy)
	if out := f.call(t, localClient, "area_set", `{"id":"kitchen","name":"Cooking"}`); !out.Waiting {
		t.Fatalf("an area with the label: %+v", out)
	}
	out := f.call(t, localClient, "area_set", `{"id":"cellar","name":"Basement"}`)
	if out.Waiting || out.Allowed || !strings.Contains(out.Message, "not released") {
		t.Fatalf("an area without the label: %+v", out)
	}
	if r := lastRecord(t, f); r["decision"] != "not_released" {
		t.Fatalf("record = %v", r)
	}

	f, _ = registries(t, strings.Replace(registryPolicy, `"area":{"change":"approval"}`, `"area":{"change":"approval","release":"all"}`, 1))
	if out := f.call(t, localClient, "area_set", `{"id":"cellar","name":"Basement"}`); !out.Waiting {
		t.Fatalf("with areas released as a whole: %+v", out)
	}
}

// A created area gets the control label on the area, not on an entity.
func TestCreatedAreaIsGivenTheControlLabelOnTheArea(t *testing.T) {
	t.Parallel()
	f, _ := registries(t, registryPolicy)
	f.home.areas["garden"] = []string{"other"}
	f.call(t, localClient, "area_new", `{}`)
	if note := f.approvals.Pending()[0].Change.Note; !strings.Contains(note, `the label "airlock"`) {
		t.Fatalf("the owner was not told about the label: %q", note)
	}
	made(t, f, "area_new", `{}`)
	if got := f.home.areas["garden"]; !slices.Equal(got, []string{"other", "airlock"}) {
		t.Fatalf("labels of the new area = %v", got)
	}
	if len(f.home.updates) != 1 || !strings.HasPrefix(f.home.updates[0], "config/area_registry/update ") {
		t.Fatalf("registry writes = %v", f.home.updates)
	}
}

// Home Assistant drops a label id it does not know and answers success.
// The gate reads the answer, so a label that was not kept is reported.
func TestControlLabelHomeAssistantDidNotKeepIsReported(t *testing.T) {
	t.Parallel()
	for name, tool := range map[string]string{"entity": "helper_new", "area": "area_new"} {
		for _, known := range []bool{true, false} {
			f, h := changing(t, registryPolicy)
			f.gate = gate.New(gate.Config{
				Policy: parsePolicy(t, registryPolicy), Audit: openLog(t, f), Core: f.home, Timeout: 5 * time.Second,
				Approvals: f.approvals, Journal: f.journal, Tools: append(h.tools(f), registryTools(map[string]string{})...),
			})
			f.home.areas["garden"] = []string{}
			f.home.unknown["airlock"] = !known
			f.call(t, localClient, tool, `{"name":"Party"}`)
			f.decide(t, true)
			f.call(t, localClient, tool, `{"name":"Party"}`)
			result, _ := lastRecord(t, f)["result"].(string)
			if reported := strings.Contains(result, "the control label could not be set"); reported == known {
				t.Errorf("%s, label known %t: audit result = %q", name, known, result)
			}
		}
	}
}

// openLog opens a fresh audit log for a gate a test builds by hand; the
// fixture's records then come from it.
func openLog(t *testing.T, f *fixture) *audit.Log {
	t.Helper()
	f.auditPath = filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.Open(f.auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	return log
}

// The control label is changed by no tool, whatever the policy opens.
func TestControlLabelIsNotChanged(t *testing.T) {
	t.Parallel()
	f, states := registries(t, registryPolicy)
	out := f.call(t, localClient, "label_set", `{"id":"airlock","name":"anything"}`)
	if out.Waiting || out.Allowed || len(f.approvals.Pending()) != 0 || states["airlock"] != `{"name":"airlock"}` {
		t.Fatalf("a change of the control label: %+v", out)
	}
	if r := lastRecord(t, f); r["decision"] != "control_label" {
		t.Fatalf("record = %v", r)
	}
	if out := f.call(t, localClient, "label_set", `{"id":"other","name":"Others"}`); !out.Waiting {
		t.Fatalf("a change of another label: %+v", out)
	}
	// A label carries no label: nothing is labelled after the change.
	made(t, f, "label_set", `{"id":"other","name":"Others"}`)
	if len(f.home.updates) != 0 {
		t.Fatalf("registry writes after a label change = %v", f.home.updates)
	}
}

// While the control label does not exist, a new label could be given its
// id; so none is created then.
func TestNoLabelIsCreatedWhileTheControlLabelIsMissing(t *testing.T) {
	t.Parallel()
	f, _ := registries(t, registryPolicy)
	f.home.registry = []string{"other"}
	out := f.call(t, localClient, "label_new", `{}`)
	if out.Waiting || out.Allowed || !strings.Contains(out.Message, "does not exist") {
		t.Fatalf("a creation without the control label: %+v", out)
	}
	if r := lastRecord(t, f); r["decision"] != "control_label" {
		t.Fatalf("record = %v", r)
	}

	f, _ = registries(t, registryPolicy)
	if out := f.call(t, localClient, "label_new", `{}`); !out.Waiting {
		t.Fatalf("a creation with the control label present: %+v", out)
	}
	if note := f.approvals.Pending()[0].Change.Note; note != "" {
		t.Fatalf("the owner is told a label will be put on a label: %q", note)
	}
	made(t, f, "label_new", `{}`)
	if len(f.home.updates) != 0 {
		t.Fatalf("registry writes after a label creation = %v", f.home.updates)
	}
}

// The owner may point the control label at a label ha-airlock changed. An
// undo of that change would then change the control label, so it is
// refused; the control label is read when the undo is asked for.
func TestUndoOfAChangeToWhatIsNowTheControlLabelIsRefused(t *testing.T) {
	t.Parallel()
	f, states := registries(t, registryPolicy)
	change := made(t, f, "label_set", `{"id":"other","name":"Others"}`)

	moved := strings.Replace(registryPolicy, `{"version":1,`, `{"version":1,"control_label":"other",`, 1)
	g := gate.New(gate.Config{
		Policy: parsePolicy(t, moved), Audit: unrecorded{}, Core: f.home, Timeout: 5 * time.Second,
		Journal: f.journal, Tools: registryTools(states),
	})
	if err := g.Undo(context.Background(), change.ID, "admin-1"); !errors.Is(err, gate.ErrControlLabel) || states["other"] != `{"name":"Others"}` {
		t.Fatalf("undo: %v, state %s", err, states["other"])
	}
	if err := f.gate.Undo(context.Background(), change.ID, "admin-1"); err != nil || states["other"] != `{"name":"Other"}` {
		t.Fatalf("undo while the control label is another: %v, state %s", err, states["other"])
	}
}

// A kind says what carries its label. A plan that names no holder where
// the kind has one, or one where it has none, and a kind with no carrier
// declared, are refused before anything is parked.
func TestChangeWhoseHolderDoesNotFitItsKindIsRefused(t *testing.T) {
	t.Parallel()
	plan := func(holder string) func(context.Context, catalog.Core, json.RawMessage) (catalog.Change, error) {
		return func(context.Context, catalog.Core, json.RawMessage) (catalog.Change, error) {
			return catalog.Change{
				Summary: "x", Object: "kitchen", Holder: holder, Before: json.RawMessage(`{"a":1}`), After: json.RawMessage(`{"a":2}`),
				Apply: func(context.Context, catalog.Core) (string, json.RawMessage, error) {
					t.Error("a change was made")
					return "", json.RawMessage(`{}`), nil
				},
			}, nil
		}
	}
	back := func(context.Context, catalog.Core, string, json.RawMessage, json.RawMessage) (catalog.Change, error) {
		return catalog.Change{}, nil
	}
	const open = `{"version":1,"profiles":{"local":{"R2":"approval"}},"configuration":{"local":{` +
		`"area":{"change":"approval","release":"all"},"label":{"change":"approval"},"scene":{"change":"approval","release":"all"}}}}`
	for name, tool := range map[string]catalog.Tool{
		"an area without its holder": {Kind: catalog.KindArea, Plan: plan("")},
		"a label with a holder":      {Kind: catalog.KindLabel, Plan: plan("kitchen")},
		"a kind without a carrier":   {Kind: catalog.KindScene, Plan: plan("scene.x")},
	} {
		tool.Name, tool.Tier, tool.Revert = "odd", catalog.R2, back
		f := newFixture(t, parsePolicy(t, open), tool)
		if out := f.call(t, localClient, "odd", `{}`); out.Waiting || out.Allowed || len(f.approvals.Pending()) != 0 {
			t.Errorf("%s: call = %+v", name, out)
		}
		if r := lastRecord(t, &f); r["decision"] != "undeclared_change" {
			t.Errorf("%s: record = %v", name, r)
		}
	}
}
