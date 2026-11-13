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
// helperCases gives, for every helper domain, the arguments of a creation
// the domain accepts.
var helperCases = map[string]string{
	"input_boolean":  `{"name":"Movie night"}`,
	"input_button":   `{"name":"Ring"}`,
	"input_number":   `{"name":"Volume","min":0,"max":10}`,
	"input_text":     `{"name":"Note","mode":"text"}`,
	"input_select":   `{"name":"Mode","options":["home","away"]}`,
	"input_datetime": `{"name":"Wake","has_time":true}`,
	"counter":        `{"name":"Visits","maximum":null}`,
	"timer":          `{"name":"Tea","duration":"0:05:00"}`,
}

// changeCases are the tools of tier R2: three for every helper domain.
var changeCases = func() map[string]bool {
	cases := map[string]bool{}
	for domain := range helperCases {
		for _, verb := range []string{"_create", "_update", "_delete"} {
			cases[domain+verb] = true
		}
	}
	return cases
}()

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
	// domain is the helpers' domain; input_boolean if empty.
	domain   string
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
	if h.domain != "" {
		if rest, ok := strings.CutPrefix(command, h.domain+"/"); ok {
			command = "input_boolean/" + rest
		}
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
		domain := "input_boolean"
		if h.domain != "" {
			domain = h.domain
		}
		h.registry = append(h.registry, map[string]any{"entity_id": domain + ".movie_night", "platform": domain, "unique_id": "movie_night"})
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
		if !strings.Contains(strings.SplitN(s, " ", 2)[0], "/list") &&
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
		{"initial null", "input_boolean_create", `{"name":"x","initial":null}`},
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

// Each tool of tier R2 plans the way back from a change it made: what was
// created is deleted, what was changed gets its recorded state again, what
// was deleted is created again.
func TestHelperToolsPlanTheWayBack(t *testing.T) {
	t.Parallel()
	revert := func(home *helperHome, name, object, before, after string) (catalog.Change, error) {
		tool, _ := catalog.Lookup(name)
		return tool.Revert(context.Background(), home, object, json.RawMessage(before), json.RawMessage(after))
	}

	home := newHelperHome()
	change, err := revert(home, "input_boolean_create", "input_boolean.party", "", `{"name":"Party"}`)
	if err != nil || string(change.Before) != `{"name":"Party"}` || len(change.After) != 0 {
		t.Fatalf("back from a creation: %+v, %v", change, err)
	}
	if _, _, err := change.Apply(context.Background(), home); err != nil || len(home.writes()) != 1 || home.writes()[0] != `input_boolean/delete {"input_boolean_id":"party"}` {
		t.Fatalf("writes = %v, %v", home.writes(), err)
	}

	home = newHelperHome()
	change, err = revert(home, "input_boolean_update", "input_boolean.guests", `{"name":"Earlier","initial":true}`, `{"icon":"mdi:account","name":"Guest mode"}`)
	if err != nil || string(change.Before) != `{"icon":"mdi:account","name":"Guest mode"}` || string(change.After) != `{"initial":true,"name":"Earlier"}` {
		t.Fatalf("back from a change: %+v, %v", change, err)
	}
	if _, _, err := change.Apply(context.Background(), home); err != nil || len(home.writes()) != 1 ||
		home.writes()[0] != `input_boolean/update {"initial":true,"input_boolean_id":"guest_mode","name":"Earlier"}` {
		t.Fatalf("writes = %v, %v", home.writes(), err)
	}

	home = newHelperHome()
	change, err = revert(home, "input_boolean_delete", "input_boolean.movie_night", `{"name":"Movie night"}`, "")
	if err != nil || len(change.Before) != 0 || string(change.After) != `{"name":"Movie night"}` {
		t.Fatalf("back from a deletion: %+v, %v", change, err)
	}
	object, _, err := change.Apply(context.Background(), home)
	if err != nil || object != "input_boolean.movie_night" || len(home.writes()) != 1 || home.writes()[0] != `input_boolean/create {"name":"Movie night"}` {
		t.Fatalf("writes = %v, object %s, %v", home.writes(), object, err)
	}

	// Refused: an object that exists again, and a recorded state with a
	// field this server does not write.
	home = newHelperHome()
	if _, err := revert(home, "input_boolean_delete", "input_boolean.party", `{"name":"Party"}`, ""); err == nil {
		t.Error("a deletion is taken back although the object exists")
	}
	if _, err := revert(home, "input_boolean_update", "input_boolean.guests", `{"name":"x","labels":["airlock"]}`, `{}`); err == nil {
		t.Error("a recorded state with an undeclared field is written back")
	}
	if len(home.writes()) != 0 {
		t.Errorf("wrote %v", home.writes())
	}
}

// Every helper domain has the same four tools, and each reaches only its
// own domain's commands: a creation sends the checked fields, a change and
// a deletion name the stored item of the entity.
func TestEveryHelperDomainPlansAndWritesInItsOwnDomain(t *testing.T) {
	t.Parallel()
	for domain, args := range helperCases {
		home := newHelperHome()
		home.domain = domain
		// A stored text helper carries its mode; without it the helper
		// counts as one that holds a secret.
		home.items[0]["mode"] = "text"
		entity := domain + ".guests"
		home.registry = append(home.registry, map[string]any{"entity_id": entity, "platform": domain, "unique_id": "guest_mode", "name": nil, "original_name": "Guest mode"})
		if _, ok := catalog.Lookup(domain + "_list"); !ok {
			t.Errorf("%s: no list tool", domain)
		}

		change, err := plan(t, home, domain+"_create", args)
		if err != nil || len(change.Before) != 0 || change.Left == nil {
			t.Fatalf("%s: creation: %+v, %v", domain, change, err)
		}
		if got := home.writes(); len(got) != 0 {
			t.Fatalf("%s: planning wrote %v", domain, got)
		}
		if _, _, err := change.Apply(context.Background(), home); err != nil {
			t.Fatalf("%s: apply: %v", domain, err)
		}
		if got := home.writes(); len(got) != 1 || !strings.HasPrefix(got[0], domain+"/create {") {
			t.Fatalf("%s: creation wrote %v", domain, got)
		}

		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(args), &fields); err != nil {
			t.Fatal(err)
		}
		fields["entity_id"] = json.RawMessage(`"` + entity + `"`)
		updated, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		home.sent = nil
		change, err = plan(t, home, domain+"_update", string(updated))
		if err != nil || change.Object != entity {
			t.Fatalf("%s: change: %+v, %v", domain, change, err)
		}
		if _, _, err := change.Apply(context.Background(), home); err != nil {
			t.Fatalf("%s: apply: %v", domain, err)
		}
		if got := home.writes(); len(got) != 1 || !strings.HasPrefix(got[0], domain+"/update {") || !strings.Contains(got[0], `"`+domain+`_id":"guest_mode"`) {
			t.Fatalf("%s: change wrote %v", domain, got)
		}

		home.sent = nil
		change, err = plan(t, home, domain+"_delete", `{"entity_id":"`+entity+`"}`)
		if err != nil {
			t.Fatalf("%s: deletion: %v", domain, err)
		}
		if _, _, err := change.Apply(context.Background(), home); err != nil {
			t.Fatalf("%s: apply: %v", domain, err)
		}
		if got := home.writes(); len(got) != 1 || got[0] != domain+`/delete {"`+domain+`_id":"guest_mode"}` {
			t.Fatalf("%s: deletion wrote %v", domain, got)
		}
	}
}

// The input schema names every field the domain requires, so a client
// learns it before the call is refused.
func TestInputSchemaRequiresWhatTheDomainRequires(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]string{
		"input_number_create": `"required": ["name", "min", "max"]`,
		"input_number_update": `"required": ["entity_id", "name", "min", "max"]`,
		"input_select_create": `"required": ["name", "options"]`,
		"timer_create":        `"required": ["name"]`,
	} {
		tool, _ := catalog.Lookup(name)
		if !strings.Contains(string(tool.InputSchema), want) || !json.Valid(tool.InputSchema) {
			t.Errorf("%s: schema lacks %s or is not JSON:\n%s", name, want, tool.InputSchema)
		}
	}
}

// A text helper in the password mode holds a secret: its configuration is
// not returned, and it is neither changed nor deleted.
func TestTextHelperThatHoldsASecretIsWithheldAndNotChanged(t *testing.T) {
	t.Parallel()
	home := newHelperHome()
	home.domain = "input_text"
	home.items = []map[string]any{
		{"id": "door_code", "name": "Door code", "initial": "4711", "mode": "password"},
		{"id": "note", "name": "Note", "initial": "milk", "mode": "text"},
	}
	home.registry = []map[string]any{
		{"entity_id": "input_text.door_code", "platform": "input_text", "unique_id": "door_code", "name": nil, "original_name": "Door code"},
		{"entity_id": "input_text.note", "platform": "input_text", "unique_id": "note", "name": nil, "original_name": "Note"},
	}

	tool, _ := catalog.Lookup("input_text_list")
	out, err := tool.Handler(context.Background(), home, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(out); strings.Contains(got, "4711") || strings.Contains(got, "Door code") ||
		!strings.Contains(got, `{"entity_id":"input_text.door_code","withheld":"the helper holds a secret"}`) || !strings.Contains(got, `"initial":"milk"`) {
		t.Fatalf("list = %s", got)
	}
	for _, call := range [][2]string{
		{"input_text_update", `{"entity_id":"input_text.door_code","name":"Door code","mode":"text"}`},
		{"input_text_delete", `{"entity_id":"input_text.door_code"}`},
	} {
		change, err := plan(t, home, call[0], call[1])
		if err == nil || strings.Contains(err.Error(), "4711") || len(change.Before) != 0 {
			t.Errorf("%s: planned %+v, %v", call[0], change, err)
		}
	}
	if _, err := plan(t, home, "input_text_update", `{"entity_id":"input_text.note","name":"Note","mode":"text"}`); err != nil {
		t.Errorf("a text helper without a secret: %v", err)
	}
	if got := home.writes(); len(got) != 0 {
		t.Errorf("wrote %v", got)
	}
}
