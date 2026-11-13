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

// fakeCore answers system_log/list with n entries and records what it was
// asked.
type fakeCore struct {
	entries  int
	commands []string
	err      error
}

func (f *fakeCore) Call(_ context.Context, command string, _, out any) error {
	f.commands = append(f.commands, command)
	if f.err != nil {
		return f.err
	}
	items := make([]map[string]any, f.entries)
	for i := range items {
		items[i] = map[string]any{"name": "logger", "level": "ERROR", "count": i + 1}
	}
	raw, err := json.Marshal(items)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func TestEveryToolIsFullyDeclared(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, tool := range catalog.All() {
		if tool.Name == "" || tool.Title == "" || tool.Description == "" {
			t.Errorf("tool %q lacks a name, a title or a description", tool.Name)
		}
		if seen[tool.Name] {
			t.Errorf("tool name %q is declared twice", tool.Name)
		}
		seen[tool.Name] = true
		if !slices.Contains(catalog.Tiers(), tool.Tier) {
			t.Errorf("tool %q has tier %q, which is not a tier", tool.Name, tool.Tier)
		}
		if len(tool.Endpoints) == 0 {
			t.Errorf("tool %q declares no Home Assistant endpoint", tool.Name)
		}
		// A tool that changes configuration works through its plan and
		// has nothing else to run; every other tool has a handler, and
		// states its action exactly when it is above R0.
		changes := tool.Tier == catalog.R2
		if (tool.Plan != nil) != changes || (tool.Revert != nil) != changes || (tool.Kind != "") != changes || (tool.Handler == nil) != changes {
			t.Errorf("tool %q (tier %s): a plan, a way back and a kind, and no handler, exactly for a tool of R2", tool.Name, tool.Tier)
		}
		if tool.Kind != "" && !slices.Contains(catalog.Kinds(), tool.Kind) {
			t.Errorf("tool %q has kind %q, which is not a kind", tool.Name, tool.Kind)
		}
		if (tool.Act != nil) != (tool.Tier != catalog.R0 && !changes) {
			t.Errorf("tool %q (tier %s): a tool states its action exactly when it is above R0 and has no plan", tool.Name, tool.Tier)
		}
		var schema struct {
			Type                 string `json:"type"`
			AdditionalProperties *bool  `json:"additionalProperties"`
		}
		if err := json.Unmarshal(tool.InputSchema, &schema); err != nil {
			t.Errorf("tool %q: input schema is not JSON: %v", tool.Name, err)
			continue
		}
		if schema.Type != "object" || schema.AdditionalProperties == nil || *schema.AdditionalProperties {
			t.Errorf("tool %q: input schema must be an object that forbids additional properties", tool.Name)
		}
	}
}

func TestLookupFindsDeclaredToolsOnly(t *testing.T) {
	t.Parallel()
	if _, ok := catalog.Lookup("system_log_list"); !ok {
		t.Fatal("system_log_list is not in the catalogue")
	}
	if _, ok := catalog.Lookup("call_any_service"); ok {
		t.Fatal("an undeclared tool was found")
	}
}

func runSystemLog(t *testing.T, core *fakeCore, args string) (int, error) {
	t.Helper()
	tool, _ := catalog.Lookup("system_log_list")
	raw, err := tool.Handler(context.Background(), core, json.RawMessage(args))
	if err != nil {
		return 0, err
	}
	var out struct {
		Entries []json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("result is not the expected JSON: %v", err)
	}
	return len(out.Entries), nil
}

func TestSystemLogListLimitsWhatItReturns(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		args string
		have int
		want int
	}{
		{"default limit", ``, 120, 50},
		{"empty object", `{}`, 120, 50},
		{"explicit limit", `{"limit": 5}`, 120, 5},
		{"fewer than the limit", `{"limit": 200}`, 7, 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			core := &fakeCore{entries: tc.have}
			got, err := runSystemLog(t, core, tc.args)
			if err != nil {
				t.Fatalf("handler: %v", err)
			}
			if got != tc.want {
				t.Fatalf("entries = %d, want %d", got, tc.want)
			}
			if len(core.commands) != 1 || core.commands[0] != "system_log/list" {
				t.Fatalf("commands sent: %v", core.commands)
			}
		})
	}
}

func TestSystemLogListRejectsArgumentsItDoesNotDeclare(t *testing.T) {
	t.Parallel()
	for _, args := range []string{`{"limit": 0}`, `{"limit": 201}`, `{"limit": "5"}`, `{"command": "config/auth/list"}`, `[1]`, `{} {}`} {
		core := &fakeCore{entries: 3}
		if _, err := runSystemLog(t, core, args); err == nil {
			t.Errorf("arguments %s were accepted", args)
		}
		if len(core.commands) != 0 {
			t.Errorf("arguments %s reached Home Assistant", args)
		}
	}
}

func TestSystemLogListReportsAFailureOfCore(t *testing.T) {
	t.Parallel()
	core := &fakeCore{err: errors.New("unauthorized")}
	_, err := runSystemLog(t, core, `{}`)
	if err == nil || !strings.Contains(err.Error(), "system_log/list") {
		t.Fatalf("error = %v, want one naming the command", err)
	}
}
