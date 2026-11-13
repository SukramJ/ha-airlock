// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package catalog_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/SukramJ/ha-airlock/internal/catalog"
)

// changeCases are the tools of tier R2.
var changeCases = map[string]bool{
	"input_boolean_create": true,
	"input_boolean_update": true,
	"input_boolean_delete": true,
}

func TestChangeToolsAreExactlyTheDeclaredOnesAndChangeHelpers(t *testing.T) {
	t.Parallel()
	found := 0
	for _, tool := range catalog.All() {
		if changeCases[tool.Name] != (tool.Tier == catalog.R2) {
			t.Errorf("tool %s (tier %s): the R2 tools and the cases of this test differ", tool.Name, tool.Tier)
		}
		if tool.Tier == catalog.R2 {
			found++
			if tool.Kind != catalog.KindHelper {
				t.Errorf("tool %s has kind %q", tool.Name, tool.Kind)
			}
		}
	}
	if found != len(changeCases) {
		t.Errorf("%d tools of tier R2, %d cases", found, len(changeCases))
	}
}

// helperHome is a Home Assistant with toggle helpers: stored items, and the
// registry entries of their entities. It records what it was sent.
type helperHome struct {
	items    []map[string]any
	registry []map[string]any
	sent     []string
}

func newHelperHome() *helperHome {
	return &helperHome{
		items: []map[string]any{
			{"id": "guest_mode", "name": "Guest mode", "icon": "mdi:account"},
			{"id": "party", "name": "Party"},
		},
		registry: []map[string]any{
			{"entity_id": "input_boolean.guests", "platform": "input_boolean", "unique_id": "guest_mode", "name": "Guests here", "original_name": "Guest mode"},
			{"entity_id": "input_boolean.party", "platform": "input_boolean", "unique_id": "party", "name": nil, "original_name": "Party"},
			{"entity_id": "input_boolean.from_yaml", "platform": "input_boolean", "unique_id": "", "name": nil, "original_name": "YAML"},
			{"entity_id": "input_boolean.other", "platform": "mqtt", "unique_id": "guest_mode", "name": nil, "original_name": "Other"},
			{"entity_id": "light.desk", "platform": "hue", "unique_id": "1", "name": nil, "original_name": "Desk"},
		},
	}
}

func (h *helperHome) Call(_ context.Context, command string, params, out any) error {
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	h.sent = append(h.sent, command+" "+string(raw))
	answer := func(v any) error {
		if out == nil {
			return nil
		}
		encoded, err := json.Marshal(v)
		if err != nil {
			return err
		}
		return json.Unmarshal(encoded, out)
	}
	switch command {
	case "input_boolean/list":
		return answer(h.items)
	case "config/entity_registry/list":
		return answer(h.registry)
	case "config/entity_registry/get":
		var p struct {
			EntityID string `json:"entity_id"`
		}
		_ = json.Unmarshal(raw, &p)
		for _, entry := range h.registry {
			if entry["entity_id"] == p.EntityID {
				return answer(entry)
			}
		}
		return errors.New("home assistant command failed: not_found: Entity not found")
	case "input_boolean/create":
		h.registry = append(h.registry, map[string]any{"entity_id": "input_boolean.movie_night", "platform": "input_boolean", "unique_id": "movie_night"})
		return answer(map[string]any{"id": "movie_night", "name": "Movie night"})
	case "input_boolean/update", "input_boolean/delete":
		return answer(nil)
	default:
		return errors.New("unexpected command " + command)
	}
}

// writes returns what the home was sent that changes something.
func (h *helperHome) writes() []string {
	var out []string
	for _, s := range h.sent {
		if !strings.HasPrefix(s, "input_boolean/list") && !strings.HasPrefix(s, "config/entity_registry/list") &&
			!strings.HasPrefix(s, "config/entity_registry/get") {
			out = append(out, s)
		}
	}
	return out
}

func plan(t *testing.T, home *helperHome, name, args string) (catalog.Change, error) {
	t.Helper()
	tool, ok := catalog.Lookup(name)
	if !ok {
		t.Fatalf("no tool %s", name)
	}
	return tool.Plan(context.Background(), home, json.RawMessage(args))
}

func TestHelperListGivesEachHelperWithItsEntity(t *testing.T) {
	t.Parallel()
	home := newHelperHome()
	tool, _ := catalog.Lookup("input_boolean_list")

	out, err := tool.Handler(context.Background(), home, nil)

	want := `{"helpers":[{"entity_id":"input_boolean.guests","configuration":{"icon":"mdi:account","name":"Guest mode"}},` +
		`{"entity_id":"input_boolean.party","configuration":{"name":"Party"}}]}`
	if err != nil || string(out) != want {
		t.Fatalf("out = %s, %v\nwant  %s", out, err, want)
	}
	if _, err := tool.Handler(context.Background(), home, json.RawMessage(`{"domain":"timer"}`)); err == nil {
		t.Fatal("an argument was accepted")
	}
}

// A plan reads and writes nothing it does not have to: planning a creation
// touches Home Assistant not at all, and no plan changes anything.
func TestCreationIsPlannedFromTheArgumentsAndWritesOnlyWhenApplied(t *testing.T) {
	t.Parallel()
	home := newHelperHome()

	change, err := plan(t, home, "input_boolean_create", `{"name":"Movie night","initial":false}`)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(change.Before) != 0 || string(change.After) != `{"initial":false,"name":"Movie night"}` || change.Object != "" ||
		change.Entity != "" || change.Name != "" || change.Summary != "Create a toggle helper" || len(home.sent) != 0 {
		t.Fatalf("change = %+v, sent %v", change, home.sent)
	}

	object, result, err := change.Apply(context.Background(), home)
	if err != nil || object != "input_boolean.movie_night" || string(result) != `{"created":"input_boolean.movie_night"}` {
		t.Fatalf("apply = %s, %s, %v", object, result, err)
	}
	if got := home.writes(); len(got) != 1 || got[0] != `input_boolean/create {"initial":false,"name":"Movie night"}` {
		t.Fatalf("writes = %v", got)
	}
}

func TestUpdateIsPlannedAgainstTheStoredItemAndReplacesIt(t *testing.T) {
	t.Parallel()
	home := newHelperHome()

	change, err := plan(t, home, "input_boolean_update", `{"entity_id":"input_boolean.guests","name":"Visitors"}`)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if string(change.Before) != `{"icon":"mdi:account","name":"Guest mode"}` || string(change.After) != `{"name":"Visitors"}` ||
		change.Object != "input_boolean.guests" || change.Entity != "input_boolean.guests" || change.Name != "Guests here" ||
		change.Summary != "Change the toggle helper input_boolean.guests" {
		t.Fatalf("change = %+v", change)
	}
	if got := home.writes(); len(got) != 0 {
		t.Fatalf("the plan wrote %v", got)
	}

	object, result, err := change.Apply(context.Background(), home)
	if err != nil || object != "input_boolean.guests" || string(result) != `{"changed":"input_boolean.guests"}` {
		t.Fatalf("apply = %s, %s, %v", object, result, err)
	}
	// The item is named by the id Home Assistant stores, which the client
	// never gave, and the icon it left out is not sent.
	if got := home.writes(); len(got) != 1 || got[0] != `input_boolean/update {"input_boolean_id":"guest_mode","name":"Visitors"}` {
		t.Fatalf("writes = %v", got)
	}
}

func TestDeletionIsPlannedWithWhatWillBeGone(t *testing.T) {
	t.Parallel()
	home := newHelperHome()

	change, err := plan(t, home, "input_boolean_delete", `{"entity_id":"input_boolean.party"}`)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if string(change.Before) != `{"name":"Party"}` || len(change.After) != 0 || change.Object != "input_boolean.party" ||
		change.Entity != "input_boolean.party" || change.Name != "Party" || change.Summary != "Delete the toggle helper input_boolean.party" {
		t.Fatalf("change = %+v", change)
	}

	if _, _, err := change.Apply(context.Background(), home); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := home.writes(); len(got) != 1 || got[0] != `input_boolean/delete {"input_boolean_id":"party"}` {
		t.Fatalf("writes = %v", got)
	}
}

func TestHelperToolsRefuseWhatTheyDoNotDeclare(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, tool, args string }{
		{"no name", "input_boolean_create", `{"icon":"mdi:account"}`},
		{"empty name", "input_boolean_create", `{"name":"  "}`},
		{"name too long", "input_boolean_create", `{"name":"` + strings.Repeat("x", 101) + `"}`},
		{"name with a line break", "input_boolean_create", `{"name":"a\nb"}`},
		{"name of the wrong type", "input_boolean_create", `{"name":7}`},
		{"icon of the wrong shape", "input_boolean_create", `{"name":"x","icon":"<script>"}`},
		{"initial not a boolean", "input_boolean_create", `{"name":"x","initial":"on"}`},
		{"unknown field", "input_boolean_create", `{"name":"x","labels":["airlock"]}`},
		{"an entity id for a creation", "input_boolean_create", `{"name":"x","entity_id":"input_boolean.x"}`},
		{"the item id chosen by the client", "input_boolean_update", `{"entity_id":"input_boolean.guests","name":"x","input_boolean_id":"party"}`},
		{"update without a name", "input_boolean_update", `{"entity_id":"input_boolean.guests","icon":"mdi:account"}`},
		{"update without an entity", "input_boolean_update", `{"name":"x"}`},
		{"entity of another domain", "input_boolean_update", `{"entity_id":"light.desk","name":"x"}`},
		{"entity that does not exist", "input_boolean_update", `{"entity_id":"input_boolean.nowhere","name":"x"}`},
		{"helper written in YAML", "input_boolean_update", `{"entity_id":"input_boolean.from_yaml","name":"x"}`},
		{"entity of another integration", "input_boolean_update", `{"entity_id":"input_boolean.other","name":"x"}`},
		{"delete with a field", "input_boolean_delete", `{"entity_id":"input_boolean.party","name":"x"}`},
		{"delete of another domain", "input_boolean_delete", `{"entity_id":"light.desk"}`},
		{"not an object", "input_boolean_create", `["name"]`},
	}
	for _, c := range cases {
		home := newHelperHome()
		if change, err := plan(t, home, c.tool, c.args); err == nil {
			t.Errorf("%s: planned %+v", c.name, change)
		}
		if got := home.writes(); len(got) != 0 {
			t.Errorf("%s: wrote %v", c.name, got)
		}
	}
}
