// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package catalog_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/SukramJ/ha-airlock/internal/catalog"
)

// controlCases are the R1 tools and the one service each may call.
var controlCases = map[string][2]string{
	"light_turn_on":          {"light", "turn_on"},
	"light_turn_off":         {"light", "turn_off"},
	"switch_turn_on":         {"switch", "turn_on"},
	"switch_turn_off":        {"switch", "turn_off"},
	"input_boolean_turn_on":  {"input_boolean", "turn_on"},
	"input_boolean_turn_off": {"input_boolean", "turn_off"},
}

func TestControlToolsAreExactlyTheDeclaredServices(t *testing.T) {
	t.Parallel()
	for _, tool := range catalog.All() {
		if _, ok := controlCases[tool.Name]; ok != (tool.Tier == catalog.R1) {
			t.Errorf("tool %s (tier %s): the R1 tools and the cases of this test differ", tool.Name, tool.Tier)
		}
		if tool.Tier != catalog.R0 && tool.Tier != catalog.R1 {
			t.Errorf("tool %s has tier %s, for which no test exists", tool.Name, tool.Tier)
		}
	}
}

func TestControlToolsCallTheirOneServiceOnTheOneEntity(t *testing.T) {
	t.Parallel()
	for name, c := range controlCases {
		domain, service := c[0], c[1]
		entity := domain + ".kitchen_1"
		out, core, err := runTool(t, name, `{"entity_id":"`+entity+`"}`, `{"context":{"id":"01J","user_id":"someone"}}`)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		want := `{"domain":"` + domain + `","service":"` + service + `","target":{"entity_id":["` + entity + `"]}}`
		if len(core.commands) != 1 || core.commands[0] != "call_service" || core.params[0] != want {
			t.Errorf("%s sent %v %v, want one call_service %s", name, core.commands, core.params, want)
		}
		if out != `{"called":"`+domain+"."+service+`","entity_id":"`+entity+`"}` {
			t.Errorf("%s returned %s", name, out)
		}

		tool, _ := catalog.Lookup(name)
		action, err := tool.Act(json.RawMessage(`{"entity_id":"` + entity + `"}`))
		if err != nil || len(action.Entities) != 1 || action.Entities[0] != entity || !strings.HasSuffix(action.Summary, " "+entity) {
			t.Errorf("%s: action = %+v, %v", name, action, err)
		}
		if !strings.Contains(tool.Endpoints[0], domain+"."+service) {
			t.Errorf("%s declares %v, not its service", name, tool.Endpoints)
		}
	}
}

func TestControlToolsRefuseEverythingButOneEntityOfTheirDomain(t *testing.T) {
	t.Parallel()
	bad := map[string]string{
		"no arguments":         ``,
		"no entity":            `{}`,
		"another domain":       `{"entity_id":"lock.front_door"}`,
		"a domain as prefix":   `{"entity_id":"lightx.kitchen"}`,
		"several entities":     `{"entity_id":"light.a,light.b"}`,
		"a list":               `{"entity_id":["light.a"]}`,
		"all":                  `{"entity_id":"all"}`,
		"upper case":           `{"entity_id":"light.Kitchen"}`,
		"service data":         `{"entity_id":"light.kitchen","brightness":255}`,
		"a service of its own": `{"entity_id":"light.kitchen","service":"toggle"}`,
		"a target":             `{"entity_id":"light.kitchen","target":{"area_id":"house"}}`,
	}
	tool, _ := catalog.Lookup("light_turn_on")
	for name, args := range bad {
		_, core, err := runTool(t, "light_turn_on", args, `{}`)
		if err == nil || len(core.commands) != 0 {
			t.Errorf("%s: handler error = %v, commands = %v; want a refusal and no command", name, err, core.commands)
		}
		if _, err := tool.Act(json.RawMessage(args)); err == nil {
			t.Errorf("%s: the action was stated for arguments the tool refuses", name)
		}
	}
}

func TestControlToolReportsAFailureOfCore(t *testing.T) {
	t.Parallel()
	// A result that is not JSON makes the stand-in's Call fail.
	if _, _, err := runTool(t, "switch_turn_off", `{"entity_id":"switch.pump"}`, `not json`); err == nil || !strings.Contains(err.Error(), "call_service switch.turn_off") {
		t.Fatalf("error = %v, want one that names the call", err)
	}
}
