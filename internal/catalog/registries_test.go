// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package catalog_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/SukramJ/ha-airlock/internal/catalog"
)

// registryHome is a Home Assistant with areas, floors, labels, devices and
// entities, answering as Core's registry commands do. It records every
// command with its body.
type registryHome struct {
	areas, floors, labels, devices, entities []map[string]any
	sent                                     []string
}

func newRegistryHome() *registryHome {
	return &registryHome{
		areas: []map[string]any{
			{
				"area_id": "kitchen", "name": "Kitchen", "icon": "mdi:stove", "floor_id": "ground", "aliases": []string{"cook", "galley"},
				"picture": nil, "labels": []string{"airlock"}, "temperature_entity_id": nil, "humidity_entity_id": nil,
				"created_at": 1.0, "modified_at": 2.0,
			},
			{"area_id": "attic", "name": "Attic", "aliases": []string{}, "labels": []string{}, "created_at": 1.0, "modified_at": 1.0},
		},
		floors: []map[string]any{{"floor_id": "ground", "name": "Ground", "level": 0, "icon": nil, "aliases": []string{"b", "a"}}},
		labels: []map[string]any{
			{"label_id": "airlock", "name": "Airlock", "color": "red", "icon": nil, "description": nil, "created_at": 1.0, "modified_at": 1.0},
			{"label_id": "spare", "name": "Spare", "color": nil, "icon": "mdi:tag", "description": "unused", "created_at": 1.0, "modified_at": 1.0},
			{"label_id": "worn", "name": "Worn", "color": nil, "icon": nil, "description": nil, "created_at": 1.0, "modified_at": 1.0},
		},
		devices: []map[string]any{{"id": "d1", "area_id": "kitchen", "labels": []string{}}},
		entities: []map[string]any{
			{"entity_id": "light.desk", "name": nil, "original_name": "Desk", "icon": nil, "area_id": nil, "labels": []string{"worn"}},
			{"entity_id": "sensor.kitchen", "name": "Kitchen air", "original_name": "Air", "icon": "mdi:air", "area_id": "kitchen", "labels": []string{}},
		},
	}
}

func (h *registryHome) Call(_ context.Context, command string, params, out any) error {
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
	var p map[string]any
	_ = json.Unmarshal(raw, &p)
	switch command {
	case "config/area_registry/list":
		return answer(h.areas)
	case "config/floor_registry/list":
		return answer(h.floors)
	case "config/label_registry/list":
		return answer(h.labels)
	case "config/device_registry/list":
		return answer(h.devices)
	case "config/entity_registry/list":
		return answer(h.entities)
	case "config/entity_registry/get":
		for _, e := range h.entities {
			if e["entity_id"] == p["entity_id"] {
				return answer(e)
			}
		}
		return errors.New("home assistant command failed: not_found: Entity not found")
	case "config/area_registry/create":
		return answer(map[string]any{"area_id": "den", "name": p["name"]})
	case "config/label_registry/create":
		return answer(map[string]any{"label_id": "fresh", "name": p["name"]})
	case "config/area_registry/update", "config/label_registry/update", "config/entity_registry/update",
		"config/area_registry/delete", "config/label_registry/delete":
		return answer(nil)
	default:
		return errors.New("unexpected command " + command)
	}
}

// writes returns what the home was sent that changes something.
func (h *registryHome) writes() []string {
	var out []string
	for _, s := range h.sent {
		command := strings.SplitN(s, " ", 2)[0]
		if !strings.HasSuffix(command, "/list") && command != "config/entity_registry/get" {
			out = append(out, s)
		}
	}
	return out
}

func registryPlan(t *testing.T, home *registryHome, name, args string) (catalog.Change, error) {
	t.Helper()
	tool, ok := catalog.Lookup(name)
	if !ok {
		t.Fatalf("no tool %s", name)
	}
	return tool.Plan(context.Background(), home, json.RawMessage(args))
}

func registryRevert(t *testing.T, home *registryHome, name, object, before, after string) (catalog.Change, error) {
	t.Helper()
	tool, ok := catalog.Lookup(name)
	if !ok {
		t.Fatalf("no tool %s", name)
	}
	return tool.Revert(context.Background(), home, object, json.RawMessage(before), json.RawMessage(after))
}

func TestRegistryListsGiveEachEntryWithoutTimestampsAndSetsSorted(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"area_list": `{"areas":[` +
			`{"aliases":[],"area_id":"attic","floor_id":null,"humidity_entity_id":null,"icon":null,"labels":[],"name":"Attic","picture":null,"temperature_entity_id":null},` +
			`{"aliases":["cook","galley"],"area_id":"kitchen","floor_id":"ground","humidity_entity_id":null,"icon":"mdi:stove","labels":["airlock"],"name":"Kitchen","picture":null,"temperature_entity_id":null}]}`,
		"label_list": `{"labels":[` +
			`{"color":"red","description":null,"icon":null,"label_id":"airlock","name":"Airlock"},` +
			`{"color":null,"description":"unused","icon":"mdi:tag","label_id":"spare","name":"Spare"},` +
			`{"color":null,"description":null,"icon":null,"label_id":"worn","name":"Worn"}]}`,
		"floor_list": `{"floors":[{"floor_id":"ground","name":"Ground","level":0,"icon":null,"aliases":["a","b"]}]}`,
	}
	for name, want := range cases {
		tool, _ := catalog.Lookup(name)
		home := newRegistryHome()
		out, err := tool.Handler(context.Background(), home, json.RawMessage(`{}`))
		if err != nil || string(out) != want {
			t.Errorf("%s = %s, %v\nwant %s", name, out, err, want)
		}
		if _, err := tool.Handler(context.Background(), home, json.RawMessage(`{"x":1}`)); err == nil {
			t.Errorf("%s takes an argument", name)
		}
	}
}

// A creation is planned from the checked arguments, sends nothing before it
// is applied, and then sends exactly those arguments.
func TestRegistryCreationIsPlannedFromTheArgumentsAndWritesOnlyWhenApplied(t *testing.T) {
	t.Parallel()
	cases := []struct{ tool, args, after, message, object string }{
		{
			"area_create", `{"name":"Den","floor_id":"ground","aliases":["study","office"],"icon":"mdi:sofa","picture":"/api/image/serve/x/512x512"}`,
			`{"aliases":["office","study"],"floor_id":"ground","icon":"mdi:sofa","name":"Den","picture":"/api/image/serve/x/512x512"}`,
			`config/area_registry/create {"aliases":["office","study"],"floor_id":"ground","icon":"mdi:sofa","name":"Den","picture":"/api/image/serve/x/512x512"}`,
			"den",
		},
		{
			"label_create", `{"name":"Fresh","color":"#00ff00","description":"new"}`,
			`{"color":"#00ff00","description":"new","name":"Fresh"}`,
			`config/label_registry/create {"color":"#00ff00","description":"new","name":"Fresh"}`,
			"fresh",
		},
	}
	for _, c := range cases {
		home := newRegistryHome()
		change, err := registryPlan(t, home, c.tool, c.args)
		if err != nil || string(change.After) != c.after || len(change.Before) != 0 || change.Object != "" || change.Holder != "" {
			t.Errorf("%s: plan = %+v, %v", c.tool, change, err)
			continue
		}
		if len(home.writes()) != 0 {
			t.Errorf("%s wrote while planning: %v", c.tool, home.writes())
		}
		object, _, err := change.Apply(context.Background(), home)
		if err != nil || object != c.object || len(home.writes()) != 1 || home.writes()[0] != c.message {
			t.Errorf("%s: applied %v, object %s, %v", c.tool, home.writes(), object, err)
		}
	}
}

// An update changes only the named fields; the plan shows the whole state
// before and after, with the shown keys bound, and the message holds the
// id and the named fields.
func TestRegistryUpdateIsPlannedAgainstTheStoredEntryAndSendsOnlyTheNamedFields(t *testing.T) {
	t.Parallel()
	cases := []struct{ tool, args, object, holder, before, after, message string }{
		{
			"area_update", `{"area_id":"kitchen","icon":null,"aliases":["z","a"]}`, "kitchen", "kitchen",
			`{"aliases":["cook","galley"],"floor_id":"ground","humidity_entity_id":null,"icon":"mdi:stove","labels":["airlock"],"name":"Kitchen","picture":null,"temperature_entity_id":null}`,
			`{"aliases":["a","z"],"floor_id":"ground","humidity_entity_id":null,"icon":null,"labels":["airlock"],"name":"Kitchen","picture":null,"temperature_entity_id":null}`,
			`config/area_registry/update {"aliases":["a","z"],"area_id":"kitchen","icon":null}`,
		},
		{
			"label_update", `{"label_id":"spare","name":"Reserve","color":null}`, "spare", "",
			`{"color":null,"description":"unused","icon":"mdi:tag","name":"Spare"}`,
			`{"color":null,"description":"unused","icon":"mdi:tag","name":"Reserve"}`,
			`config/label_registry/update {"color":null,"label_id":"spare","name":"Reserve"}`,
		},
		{
			"entity_update", `{"entity_id":"light.desk","name":"Desk lamp","area_id":"kitchen"}`, "light.desk", "light.desk",
			`{"area_id":null,"icon":null,"name":null}`,
			`{"area_id":"kitchen","icon":null,"name":"Desk lamp"}`,
			`config/entity_registry/update {"area_id":"kitchen","entity_id":"light.desk","name":"Desk lamp"}`,
		},
	}
	for _, c := range cases {
		home := newRegistryHome()
		change, err := registryPlan(t, home, c.tool, c.args)
		if err != nil {
			t.Errorf("%s: %v", c.tool, err)
			continue
		}
		if change.Object != c.object || change.Holder != c.holder || string(change.Before) != c.before || string(change.After) != c.after {
			t.Errorf("%s: object %q holder %q\nbefore %s\nafter  %s", c.tool, change.Object, change.Holder, change.Before, change.After)
		}
		if len(home.writes()) != 0 {
			t.Errorf("%s wrote while planning: %v", c.tool, home.writes())
		}
		if _, _, err := change.Apply(context.Background(), home); err != nil || len(home.writes()) != 1 || home.writes()[0] != c.message {
			t.Errorf("%s: applied %v, %v", c.tool, home.writes(), err)
		}
		left, err := change.Left(context.Background(), home, c.object)
		if err != nil || string(left) != c.before {
			t.Errorf("%s: left = %s, %v (the stand-in does not change what it stores)", c.tool, left, err)
		}
	}
	home := newRegistryHome()
	if change, err := registryPlan(t, home, "entity_update", `{"entity_id":"light.desk","icon":"mdi:lamp"}`); err != nil || change.Name != "Desk" {
		t.Errorf("an entity without a name of its own is named by its integration's name: %+v, %v", change, err)
	}
}

func TestRegistryToolsRefuseWhatTheyDoNotDeclare(t *testing.T) {
	t.Parallel()
	refused := map[string][]string{
		"area_create": {
			`{}`, `{"name":""}`, `{"name":"Den","labels":["airlock"]}`, `{"name":"Den","area_id":"den"}`,
			`{"name":"Den","icon":null}`, `{"name":"Den","floor_id":null}`, `{"name":"Den","floor_id":"roof"}`,
			`{"name":"Den","picture":"https://example.com/x.png"}`, `{"name":"Den","picture":"//example.com/x.png"}`,
			`{"name":"Den","picture":"/\\example.com"}`, `{"name":"Den","aliases":["a","a"]}`, `{"name":"Den","aliases":[" a"]}`,
			`{"name":"Den","temperature_entity_id":"sensor.t"}`, `{"name":"Den","icon":"sofa"}`,
		},
		"area_update": {
			`{"area_id":"kitchen"}`, `{"area_id":"cellar","name":"x"}`, `{"area_id":"Kitchen!","name":"x"}`,
			`{"area_id":"kitchen","name":null}`, `{"area_id":"kitchen","aliases":null}`, `{"area_id":"kitchen","labels":[]}`,
			`{"area_id":"kitchen","floor_id":"roof"}`, `{"area_id":"kitchen","humidity_entity_id":null}`,
		},
		"label_create": {`{}`, `{"name":"x","color":"rot"}`, `{"name":"x","color":"#12345"}`, `{"name":"x","label_id":"x"}`, `{"name":"x","color":null}`},
		"label_update": {`{"label_id":"spare"}`, `{"label_id":"nope","name":"x"}`, `{"label_id":"spare","name":null}`, `{"label_id":"spare","labels":[]}`},
		"entity_update": {
			`{"entity_id":"light.desk"}`, `{"entity_id":"light.desk","name":""}`, `{"entity_id":"light.desk","area_id":"cellar"}`,
			`{"entity_id":"light.desk","labels":[]}`, `{"entity_id":"light.desk","new_entity_id":"light.x"}`,
			`{"entity_id":"light.desk","disabled_by":"user"}`, `{"entity_id":"light.desk","hidden_by":"user"}`,
			`{"entity_id":"light.desk","aliases":[]}`, `{"entity_id":"Light Desk","name":"x"}`, `{"entity_id":"light.gone","name":"x"}`,
		},
	}
	for name, cases := range refused {
		for _, args := range cases {
			home := newRegistryHome()
			if change, err := registryPlan(t, home, name, args); err == nil {
				t.Errorf("%s %s: planned %+v", name, args, change)
			}
			if len(home.writes()) != 0 {
				t.Errorf("%s %s wrote %v", name, args, home.writes())
			}
		}
	}
}

// The way back: a creation is undone by deleting what nothing refers to,
// a change by writing the declared fields of the recorded state.
func TestRegistryToolsPlanTheWayBack(t *testing.T) {
	t.Parallel()
	home := newRegistryHome()
	change, err := registryRevert(t, home, "area_create", "attic", "", `{"name":"Attic"}`)
	if err != nil || change.Object != "attic" || change.Holder != "attic" || len(change.Before) == 0 || len(change.After) != 0 {
		t.Fatalf("back from an area's creation: %+v, %v", change, err)
	}
	if _, _, err := change.Apply(context.Background(), home); err != nil || len(home.writes()) != 1 ||
		home.writes()[0] != `config/area_registry/delete {"area_id":"attic"}` {
		t.Fatalf("writes = %v, %v", home.writes(), err)
	}

	home = newRegistryHome()
	change, err = registryRevert(t, home, "label_create", "spare", "", `{"name":"Spare"}`)
	if err != nil || change.Object != "spare" || change.Holder != "" {
		t.Fatalf("back from a label's creation: %+v, %v", change, err)
	}
	if _, _, err := change.Apply(context.Background(), home); err != nil || len(home.writes()) != 1 ||
		home.writes()[0] != `config/label_registry/delete {"label_id":"spare"}` {
		t.Fatalf("writes = %v, %v", home.writes(), err)
	}

	// Refused while something refers to the entry: the kitchen has an
	// entity and a device, worn is on an entity, airlock on an area.
	for _, c := range [][2]string{{"area_create", "kitchen"}, {"label_create", "worn"}, {"label_create", "airlock"}, {"area_create", "gone"}} {
		home := newRegistryHome()
		if _, err := registryRevert(t, home, c[0], c[1], "", `{"name":"x"}`); err == nil {
			t.Errorf("the creation of %s is taken back although it is in use or gone", c[1])
		}
		if len(home.writes()) != 0 {
			t.Errorf("wrote %v", home.writes())
		}
	}
	home = newRegistryHome()
	home.devices = append(home.devices, map[string]any{"id": "d2", "area_id": nil, "labels": []string{"spare"}})
	if _, err := registryRevert(t, home, "label_create", "spare", "", `{"name":"x"}`); err == nil {
		t.Error("the creation of a label a device carries is taken back")
	}

	// A change: the declared fields of the recorded state, nulls included;
	// labels and the sensors are not written back.
	cases := []struct{ tool, object, before, message string }{
		{
			"area_update", "kitchen",
			`{"aliases":["x"],"floor_id":null,"humidity_entity_id":"sensor.h","icon":null,"labels":[],"name":"Cook","picture":null,"temperature_entity_id":null}`,
			`config/area_registry/update {"aliases":["x"],"area_id":"kitchen","floor_id":null,"icon":null,"name":"Cook","picture":null}`,
		},
		{
			"label_update", "spare", `{"color":"red","description":null,"icon":null,"name":"Old"}`,
			`config/label_registry/update {"color":"red","description":null,"icon":null,"label_id":"spare","name":"Old"}`,
		},
		{
			"entity_update", "sensor.kitchen", `{"area_id":null,"icon":null,"name":""}`,
			`config/entity_registry/update {"area_id":null,"entity_id":"sensor.kitchen","icon":null,"name":""}`,
		},
	}
	for _, c := range cases {
		home := newRegistryHome()
		change, err := registryRevert(t, home, c.tool, c.object, c.before, `{}`)
		if err != nil {
			t.Errorf("%s: %v", c.tool, err)
			continue
		}
		if _, _, err := change.Apply(context.Background(), home); err != nil || len(home.writes()) != 1 || home.writes()[0] != c.message {
			t.Errorf("%s: writes = %v, %v", c.tool, home.writes(), err)
		}
	}

	// Refused: a recorded floor or area that is gone since.
	home = newRegistryHome()
	if _, err := registryRevert(t, home, "area_update", "kitchen", `{"name":"Kitchen","floor_id":"roof"}`, `{}`); err == nil {
		t.Error("an area is put back on a floor that is gone")
	}
	if _, err := registryRevert(t, home, "entity_update", "light.desk", `{"area_id":"cellar"}`, `{}`); err == nil {
		t.Error("an entity is put back into an area that is gone")
	}
	if len(home.writes()) != 0 {
		t.Errorf("wrote %v", home.writes())
	}
}

// Home Assistant keeps aliases and labels as sets and sends them in no
// stated order; the state bound to an approval must not depend on it.
func TestRegistryStateDoesNotDependOnTheOrderOfSets(t *testing.T) {
	t.Parallel()
	home := newRegistryHome()
	first, err := registryPlan(t, home, "area_update", `{"area_id":"kitchen","name":"Cook"}`)
	if err != nil {
		t.Fatal(err)
	}
	home.areas[0]["aliases"] = []string{"galley", "cook"}
	home.areas[0]["labels"] = []string{"spare", "airlock"}
	home.areas[0]["modified_at"] = 99.0
	second, err := registryPlan(t, home, "area_update", `{"area_id":"kitchen","name":"Cook"}`)
	if err != nil {
		t.Fatal(err)
	}
	home.areas[0]["labels"] = []string{"airlock", "spare"}
	third, err := registryPlan(t, home, "area_update", `{"area_id":"kitchen","name":"Cook"}`)
	if err != nil {
		t.Fatal(err)
	}
	if string(second.Before) != string(third.Before) {
		t.Errorf("reordered sets give another state:\n%s\n%s", second.Before, third.Before)
	}
	if string(first.Before) == string(second.Before) {
		t.Error("a label more is not part of the state")
	}
}

// No message any registry tool sends carries what releases an object or
// changes an entity beyond name, icon and area, and no tool deletes a label
// except the undo of its creation. Every R2 tool of the registries is
// planned, applied and taken back against the recording stand-in.
func TestRegistryToolsNeverSendLabelsOrTheEntityRegistrysOtherKeys(t *testing.T) {
	t.Parallel()
	calls := []struct{ tool, args, object, before string }{
		{"area_create", `{"name":"Den","aliases":["a"],"floor_id":"ground","icon":"mdi:sofa","picture":"/p"}`, "attic", ""},
		{
			"area_update", `{"area_id":"kitchen","name":"Cook","aliases":["a"],"floor_id":null,"icon":null,"picture":null}`, "kitchen",
			`{"aliases":["x"],"floor_id":"ground","humidity_entity_id":"sensor.h","icon":null,"labels":["airlock","spare"],"name":"K","picture":null,"temperature_entity_id":"sensor.t"}`,
		},
		{"label_create", `{"name":"Fresh","color":"red","icon":"mdi:tag","description":"d"}`, "spare", ""},
		{
			"label_update", `{"label_id":"spare","name":"R","color":null,"icon":null,"description":null}`, "spare",
			`{"color":null,"description":null,"icon":null,"name":"S"}`,
		},
		{
			"entity_update", `{"entity_id":"light.desk","name":"D","icon":"mdi:lamp","area_id":"kitchen"}`, "light.desk",
			`{"area_id":null,"icon":null,"name":null,"labels":["airlock"],"new_entity_id":"light.x","disabled_by":"user","hidden_by":"user"}`,
		},
	}
	forbidden := []string{`"labels"`, `"new_entity_id"`, `"disabled_by"`, `"hidden_by"`, `"temperature_entity_id"`, `"humidity_entity_id"`}
	for _, c := range calls {
		home := newRegistryHome()
		change, err := registryPlan(t, home, c.tool, c.args)
		if err != nil {
			t.Fatalf("%s: %v", c.tool, err)
		}
		if _, _, err := change.Apply(context.Background(), home); err != nil {
			t.Fatalf("%s: %v", c.tool, err)
		}
		back, err := registryRevert(t, home, c.tool, c.object, c.before, `{}`)
		if err != nil {
			t.Fatalf("%s back: %v", c.tool, err)
		}
		if _, _, err := back.Apply(context.Background(), home); err != nil {
			t.Fatalf("%s back: %v", c.tool, err)
		}
		writes := home.writes()
		for i, w := range writes {
			command, body, _ := strings.Cut(w, " ")
			for _, key := range forbidden {
				if strings.Contains(body, key) {
					t.Errorf("%s sends %s: %s", c.tool, key, w)
				}
			}
			if command == "config/label_registry/delete" && (c.tool != "label_create" || i == 0) {
				t.Errorf("%s deletes a label: %s", c.tool, w)
			}
		}
		if !slices.ContainsFunc(writes, func(w string) bool { return strings.Contains(w, "/delete ") }) && strings.HasSuffix(c.tool, "_create") {
			t.Errorf("%s: the undo of a creation deleted nothing: %v", c.tool, writes)
		}
	}
}
