// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package catalog_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const registry = `[
 {"entity_id":"light.kitchen","name":"Kitchen ceiling","original_name":"Ceiling","area_id":"kitchen","labels":["airlock","evening"],"platform":"hue","disabled_by":null,"hidden_by":null,"unique_id":"secret-unique","device_id":"dev1","options":{"x":1}},
 {"entity_id":"light.hall","name":null,"original_name":"Hall","area_id":null,"labels":[],"platform":"hue","disabled_by":"user","hidden_by":null},
 {"entity_id":"lightning.sensor","name":null,"original_name":null,"area_id":null,"labels":["airlock"],"platform":"demo","disabled_by":null,"hidden_by":"integration"},
 {"entity_id":"switch.pump","name":"","original_name":"Pump","area_id":"cellar","labels":["airlock"],"platform":"shelly","disabled_by":null,"hidden_by":null}
]`

type listed struct {
	Entities []struct {
		EntityID string   `json:"entity_id"`
		Name     string   `json:"name"`
		AreaID   string   `json:"area_id"`
		Labels   []string `json:"labels"`
		Platform string   `json:"platform"`
		Disabled bool     `json:"disabled"`
		Hidden   bool     `json:"hidden"`
	} `json:"entities"`
	Truncated bool `json:"truncated"`
}

func list(t *testing.T, args string) (got listed, raw string) {
	t.Helper()
	out, core, err := runTool(t, "entities_list", args, registry)
	if err != nil {
		t.Fatalf("%s: %v", args, err)
	}
	if len(core.commands) != 1 || core.commands[0] != "config/entity_registry/list" || core.params[0] != "null" {
		t.Fatalf("%s: sent %v %v", args, core.commands, core.params)
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%s: %v", args, err)
	}
	return got, out
}

func ids(l listed) string {
	out := make([]string, 0, len(l.Entities))
	for _, e := range l.Entities {
		out = append(out, e.EntityID)
	}
	return strings.Join(out, ",")
}

func TestEntitiesListReturnsTheChosenFieldsOfTheChosenEntities(t *testing.T) {
	t.Parallel()
	all, raw := list(t, `{}`)
	if ids(all) != "light.kitchen,light.hall,lightning.sensor,switch.pump" || all.Truncated {
		t.Fatalf("all = %s, truncated %t", ids(all), all.Truncated)
	}
	k := all.Entities[0]
	if k.Name != "Kitchen ceiling" || k.AreaID != "kitchen" || fmt.Sprint(k.Labels) != "[airlock evening]" || k.Platform != "hue" || k.Disabled || k.Hidden {
		t.Errorf("kitchen = %+v", k)
	}
	if h := all.Entities[1]; h.Name != "Hall" || !h.Disabled || h.Labels == nil {
		t.Errorf("hall = %+v, want the original name, disabled, and an empty list of labels", h)
	}
	if !all.Entities[2].Hidden || all.Entities[3].Name != "Pump" {
		t.Errorf("hidden or the fallback for an empty name is wrong: %+v", all.Entities[2:])
	}
	for _, internal := range []string{"secret-unique", "dev1", "options", "unique_id"} {
		if strings.Contains(raw, internal) {
			t.Errorf("the result carries %q, which the tool does not declare", internal)
		}
	}

	for args, want := range map[string]string{
		`{"domain":"light"}`:                   "light.kitchen,light.hall",
		`{"label":"airlock"}`:                  "light.kitchen,lightning.sensor,switch.pump",
		`{"domain":"light","label":"airlock"}`: "light.kitchen",
		`{"label":"nobody"}`:                   "",
	} {
		if got, _ := list(t, args); ids(got) != want || got.Truncated {
			t.Errorf("%s = %q, want %q", args, ids(got), want)
		}
	}
	if got, raw := list(t, `{"label":"nobody"}`); got.Entities == nil || !strings.Contains(raw, `"entities":[]`) {
		t.Errorf("no match must be an empty list, not null: %s", raw)
	}
}

func TestEntitiesListLimitsWhatItReturnsAndSaysSo(t *testing.T) {
	t.Parallel()
	if got, _ := list(t, `{"limit":2}`); ids(got) != "light.kitchen,light.hall" || !got.Truncated {
		t.Errorf("limit 2 = %s, truncated %t", ids(got), got.Truncated)
	}
	if got, _ := list(t, `{"limit":4}`); len(got.Entities) != 4 || got.Truncated {
		t.Errorf("limit 4 = %d entities, truncated %t", len(got.Entities), got.Truncated)
	}
	if got, _ := list(t, `{"domain":"light","limit":2}`); got.Truncated {
		t.Error("a limit that was exactly met is reported as truncated")
	}
}

func TestEntityToolsRefuseArgumentsOutsideTheirShape(t *testing.T) {
	t.Parallel()
	cases := map[string][]string{
		"entities_list": {
			`{"domain":"Light"}`, `{"domain":"light.kitchen"}`, `{"label":"my label"}`, `{"label":""}`,
			`{"limit":0}`, `{"limit":1001}`, `{"area":"kitchen"}`,
		},
		"states_get": {
			``, `{}`, `{"entity_ids":[]}`, `{"entity_ids":["all"]}`, `{"entity_ids":["light.Kitchen"]}`,
			`{"entity_ids":"light.kitchen"}`, `{"entity_ids":["light.a"],"domain":"light"}`,
			`{"entity_ids":[` + strings.TrimSuffix(strings.Repeat(`"light.a",`, 51), ",") + `]}`,
		},
	}
	for name, bad := range cases {
		for _, args := range bad {
			if _, core, err := runTool(t, name, args, `[]`); err == nil || len(core.commands) != 0 {
				t.Errorf("%s %s: error = %v, commands = %v; want a refusal and no command", name, args, err, core.commands)
			}
		}
	}
}

func TestStatesGetReturnsTheNamedEntitiesWithoutTheirContext(t *testing.T) {
	t.Parallel()
	states := `[
 {"entity_id":"light.kitchen","state":"on","attributes":{"brightness":200},"last_changed":"2026-11-13T04:00:00+00:00","last_reported":"x","last_updated":"2026-11-13T04:00:01+00:00","context":{"id":"01J","parent_id":null,"user_id":"the-user-id"}},
 {"entity_id":"light.hall","state":"off","attributes":{},"last_changed":"a","last_updated":"b","context":{"id":"02J","user_id":null}},
 {"entity_id":"sensor.other","state":"7","attributes":{},"last_changed":"a","last_updated":"b","context":{"id":"03J"}}
]`
	out, core, err := runTool(t, "states_get", `{"entity_ids":["light.hall","light.gone","light.kitchen","light.hall"]}`, states)
	if err != nil {
		t.Fatalf("states_get: %v", err)
	}
	if len(core.commands) != 1 || core.commands[0] != "get_states" || core.params[0] != "null" {
		t.Fatalf("sent %v %v", core.commands, core.params)
	}
	want := `{"states":[` +
		`{"entity_id":"light.kitchen","state":"on","attributes":{"brightness":200},"last_changed":"2026-11-13T04:00:00+00:00","last_updated":"2026-11-13T04:00:01+00:00"},` +
		`{"entity_id":"light.hall","state":"off","attributes":{},"last_changed":"a","last_updated":"b"}],` +
		`"missing":["light.gone"]}`
	if out != want {
		t.Fatalf("result =\n%s\nwant\n%s", out, want)
	}

	out, _, err = runTool(t, "states_get", `{"entity_ids":["light.kitchen"]}`, states)
	if err != nil || !strings.Contains(out, `"missing":[]`) {
		t.Fatalf("nothing missing must be an empty list: %s, %v", out, err)
	}
}

func TestEntityToolsReportAFailureOfCore(t *testing.T) {
	t.Parallel()
	for name, args := range map[string]string{"entities_list": `{}`, "states_get": `{"entity_ids":["light.a"]}`} {
		if _, _, err := runTool(t, name, args, `not json`); err == nil {
			t.Errorf("%s: no error for a failing command", name)
		}
	}
}
