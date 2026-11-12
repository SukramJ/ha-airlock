// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package catalog_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/SukramJ/ha-airlock/internal/catalog"
)

// recordingCore records the one command it is sent and answers it with a
// canned result.
type recordingCore struct {
	result   string
	commands []string
	params   []string
}

func (r *recordingCore) Call(_ context.Context, command string, params, out any) error {
	r.commands = append(r.commands, command)
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	r.params = append(r.params, string(raw))
	return json.Unmarshal([]byte(r.result), out)
}

func runTool(t *testing.T, name, args, result string) (out string, core *recordingCore, err error) {
	t.Helper()
	tool, ok := catalog.Lookup(name)
	if !ok {
		t.Fatalf("tool %s is not in the catalogue", name)
	}
	core = &recordingCore{result: result}
	raw, err := tool.Handler(context.Background(), core, json.RawMessage(args))
	return string(raw), core, err
}

// Each tool sends exactly one command, the one it declares, with exactly
// the parameters its arguments describe.
func TestDiagnosticToolsSendTheCommandTheyDeclare(t *testing.T) {
	t.Parallel()
	cases := []struct {
		tool, args, command, params string
	}{
		{"repairs_list_issues", ``, "repairs/list_issues", `null`},
		{"repairs_list_issues", `{}`, "repairs/list_issues", `null`},
		{"config_entries_list", `{}`, "config_entries/get", `null`},
		{"config_entries_list", `{"domain":"mqtt"}`, "config_entries/get", `{"domain":"mqtt"}`},
		{"trace_list", `{"domain":"automation"}`, "trace/list", `{"domain":"automation"}`},
		{"trace_list", `{"domain":"script","item_id":"morning_routine"}`, "trace/list", `{"domain":"script","item_id":"morning_routine"}`},
		{"logbook_events", `{"start_time":"2026-11-12T08:00:00+01:00"}`, "logbook/get_events", `{"start_time":"2026-11-12T08:00:00+01:00"}`},
		{
			"logbook_events", `{"start_time":"2026-11-12T08:00:00Z","end_time":"2026-11-12T09:00:00Z","entity_ids":["light.kitchen"]}`,
			"logbook/get_events", `{"end_time":"2026-11-12T09:00:00Z","entity_ids":["light.kitchen"],"start_time":"2026-11-12T08:00:00Z"}`,
		},
	}
	for _, tc := range cases {
		result := `{"issues":[]}`
		if tc.tool == "logbook_events" {
			result = `[]`
		}
		_, core, err := runTool(t, tc.tool, tc.args, result)
		if err != nil {
			t.Errorf("%s %s: %v", tc.tool, tc.args, err)
			continue
		}
		if len(core.commands) != 1 || core.commands[0] != tc.command || core.params[0] != tc.params {
			t.Errorf("%s %s: sent %v with %v, want %s with %s", tc.tool, tc.args, core.commands, core.params, tc.command, tc.params)
		}
		tool, _ := catalog.Lookup(tc.tool)
		if len(tool.Endpoints) != 1 || tool.Endpoints[0] != "websocket: "+tc.command {
			t.Errorf("%s declares %v but sends %s", tc.tool, tool.Endpoints, tc.command)
		}
	}
}

func TestDiagnosticToolsRefuseArgumentsOutsideTheirShape(t *testing.T) {
	t.Parallel()
	cases := map[string][]string{
		"repairs_list_issues": {`{"issue_id":"x"}`, `[]`},
		"config_entries_list": {`{"domain":"MQTT"}`, `{"domain":"mqtt; drop"}`, `{"domain":""}`, `{"domain":5}`, `{"type_filter":["hub"]}`},
		"trace_list": {
			`{}`, `{"domain":"scene"}`, `{"domain":"automation","item_id":"a/b"}`, `{"domain":"automation","item_id":""}`,
			`{"domain":"automation","run_id":"1"}`,
		},
		"logbook_events": {
			`{}`, `{"start_time":"yesterday"}`, `{"start_time":"2026-11-12T08:00:00Z","end_time":"2026-11-12T07:00:00Z"}`,
			`{"start_time":"2026-11-12T08:00:00Z","end_time":"soon"}`,
			`{"start_time":"2026-11-12T08:00:00Z","entity_ids":["Light.Kitchen"]}`,
			`{"start_time":"2026-11-12T08:00:00Z","entity_ids":["kitchen"]}`,
			`{"start_time":"2026-11-12T08:00:00Z","limit":0}`, `{"start_time":"2026-11-12T08:00:00Z","limit":501}`,
			`{"start_time":"2026-11-12T08:00:00Z","device_ids":["abc"]}`,
			`{"start_time":"2026-11-12T08:00:00Z","entity_ids":[` + strings.TrimSuffix(strings.Repeat(`"light.a",`, 21), ",") + `]}`,
		},
	}
	for tool, argsList := range cases {
		for _, args := range argsList {
			_, core, err := runTool(t, tool, args, `[]`)
			if err == nil {
				t.Errorf("%s accepted %s", tool, args)
			}
			if len(core.commands) != 0 {
				t.Errorf("%s reached Home Assistant with %s", tool, args)
			}
		}
	}
}

func TestPassThroughToolsReturnWhatCoreReturned(t *testing.T) {
	t.Parallel()
	const result = `{"issues":[{"domain":"mqtt","severity":"warning","is_fixable":false}]}`
	out, _, err := runTool(t, "repairs_list_issues", `{}`, result)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if out != result {
		t.Fatalf("result = %s, want %s", out, result)
	}
}

func TestLogbookEventsLimitsWhatItReturnsAndSaysSo(t *testing.T) {
	t.Parallel()
	many := "[" + strings.TrimSuffix(strings.Repeat(`{"name":"x"},`, 150), ",") + "]"
	cases := []struct {
		args      string
		want      int
		truncated bool
	}{
		{`{"start_time":"2026-11-12T08:00:00Z"}`, 100, true},
		{`{"start_time":"2026-11-12T08:00:00Z","limit":10}`, 10, true},
		{`{"start_time":"2026-11-12T08:00:00Z","limit":500}`, 150, false},
	}
	for _, tc := range cases {
		out, _, err := runTool(t, "logbook_events", tc.args, many)
		if err != nil {
			t.Fatalf("%s: %v", tc.args, err)
		}
		var got struct {
			Events    []json.RawMessage `json:"events"`
			Truncated bool              `json:"truncated"`
		}
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("%s: %v", tc.args, err)
		}
		if len(got.Events) != tc.want || got.Truncated != tc.truncated {
			t.Errorf("%s: %d events, truncated %t; want %d, %t", tc.args, len(got.Events), got.Truncated, tc.want, tc.truncated)
		}
	}
}
