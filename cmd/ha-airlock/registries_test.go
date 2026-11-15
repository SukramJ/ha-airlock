// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package main

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// startRegistryServer starts the server as main builds it, with a policy
// file that opens the given kinds of configuration for profile local, and
// a Home Assistant that answers with the given results.
func startRegistryServer(t *testing.T, kinds string, results map[string]string, then map[string]map[string]string) *running {
	t.Helper()
	r := startServerIn(t, `{"public_url":"`+publicURL+`"}`, func(env *environment) {
		policyFile := `{"version":1,"profiles":{"local":{"R0":"allow","R2":"approval"}},"configuration":{"local":` + kinds + `}}`
		if err := os.WriteFile(filepath.Join(env.configDir, "policy.json"), []byte(policyFile), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	r.home.Mu.Lock()
	for command, result := range results {
		r.home.CoreResults[command] = result
	}
	r.home.CoreThen = then
	r.home.Mu.Unlock()
	return r
}

// sentCore returns the messages Core received of the given command type.
func (r *running) sentCore(command string) []string {
	r.home.Mu.Lock()
	defer r.home.Mu.Unlock()
	var out []string
	for _, m := range r.home.CoreMessages {
		if strings.HasPrefix(m, command+" ") {
			out = append(out, m)
		}
	}
	return out
}

const (
	kitchenArea = `{"area_id":"kitchen","name":"Kitchen","icon":null,"floor_id":null,"aliases":[],"picture":null,` +
		`"labels":["airlock"],"temperature_entity_id":null,"humidity_entity_id":null,"created_at":1,"modified_at":1}`
	kitchenRenamed = `{"area_id":"kitchen","name":"Cook","icon":null,"floor_id":null,"aliases":[],"picture":null,` +
		`"labels":["airlock"],"temperature_entity_id":null,"humidity_entity_id":null,"created_at":1,"modified_at":2}`
	bareKitchen = `{"area_id":"kitchen","name":"Kitchen","aliases":[],"labels":[],"created_at":1,"modified_at":1}`
	denArea     = `{"area_id":"den","name":"Den","icon":null,"floor_id":null,"aliases":[],"picture":null,` +
		`"labels":[],"temperature_entity_id":null,"humidity_entity_id":null,"created_at":3,"modified_at":3}`
	denLabelled = `{"area_id":"den","name":"Den","icon":null,"floor_id":null,"aliases":[],"picture":null,` +
		`"labels":["airlock"],"temperature_entity_id":null,"humidity_entity_id":null,"created_at":3,"modified_at":4}`
	labels       = `[{"label_id":"airlock","name":"Airlock","color":null,"icon":null,"description":null},{"label_id":"spare","name":"Spare","color":null,"icon":null,"description":null}]`
	labelsAfter  = `[{"label_id":"airlock","name":"Airlock","color":null,"icon":null,"description":null},{"label_id":"spare","name":"Reserve","color":null,"icon":null,"description":null}]`
	desk         = `{"entity_id":"light.desk","labels":["airlock"],"name":null,"original_name":"Desk","icon":null,"area_id":null,"platform":"hue"}`
	deskRenamed  = `{"entity_id":"light.desk","labels":["airlock"],"name":"Desk lamp","original_name":"Desk","icon":null,"area_id":null,"platform":"hue"}`
	deskUnmarked = `{"entity_id":"light.desk","labels":[],"name":null,"original_name":"Desk","icon":null,"area_id":null,"platform":"hue"}`
)

// Areas, labels and entities are changed through the server as main
// builds it: the policy file opens the kind, the call waits with its
// difference on the sidebar page, after the approval exactly the client's
// fields go to Home Assistant, the change is journalled, and an
// administrator takes it back on the sidebar page.
func TestRegistryObjectsAreChangedOnlyAfterApprovalAndAreJournalledAndUndone(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, kinds, tool string
		args              map[string]string
		results           map[string]string
		then              map[string]map[string]string
		// shown is on the sidebar page while the call waits.
		shown string
		// write is the command of the change; message what it carries.
		write   string
		message []string
		object  string
		// undo is the command and what it carries when the change is
		// taken back.
		undo        string
		undoMessage []string
	}{
		{
			name: "area", kinds: `{"area":{"change":"approval"}}`, tool: "area_update",
			args: map[string]string{"area_id": "kitchen", "name": "Cook"},
			results: map[string]string{
				"config/area_registry/list": "[" + kitchenArea + "]", "config/floor_registry/list": `[]`,
				"config/area_registry/update": kitchenRenamed,
			},
			then:  map[string]map[string]string{"config/area_registry/update": {"config/area_registry/list": "[" + kitchenRenamed + "]"}},
			shown: "Change an area kitchen", write: "config/area_registry/update",
			message: []string{`"area_id":"kitchen"`, `"name":"Cook"`}, object: "kitchen",
			undo: "config/area_registry/update", undoMessage: []string{`"area_id":"kitchen"`, `"name":"Kitchen"`},
		},
		{
			name: "area created", kinds: `{"area":{"change":"approval"}}`, tool: "area_create",
			args: map[string]string{"name": "Den"},
			results: map[string]string{
				"config/area_registry/list": "[" + kitchenArea + "]", "config/floor_registry/list": `[]`,
				"config/area_registry/create": denArea, "config/area_registry/update": denLabelled,
				"config/area_registry/delete": `"success"`, "config/entity_registry/list": `[]`, "config/device_registry/list": `[]`,
			},
			then: map[string]map[string]string{
				"config/area_registry/create": {"config/area_registry/list": "[" + kitchenArea + "," + denArea + "]"},
				"config/area_registry/update": {"config/area_registry/list": "[" + kitchenArea + "," + denLabelled + "]"},
			},
			shown: "Create an area", write: "config/area_registry/create",
			message: []string{`"name":"Den"`}, object: "den",
			undo: "config/area_registry/delete", undoMessage: []string{`"area_id":"den"`},
		},
		{
			name: "label", kinds: `{"label":{"change":"approval"}}`, tool: "label_update",
			args: map[string]string{"label_id": "spare", "name": "Reserve"},
			results: map[string]string{
				"config/label_registry/list": labels, "config/label_registry/update": `{"label_id":"spare","name":"Reserve"}`,
			},
			then:  map[string]map[string]string{"config/label_registry/update": {"config/label_registry/list": labelsAfter}},
			shown: "Change a label spare", write: "config/label_registry/update",
			message: []string{`"label_id":"spare"`, `"name":"Reserve"`}, object: "spare",
			undo: "config/label_registry/update", undoMessage: []string{`"label_id":"spare"`, `"name":"Spare"`},
		},
		{
			name: "entity", kinds: `{"entity":{"change":"approval"}}`, tool: "entity_update",
			args: map[string]string{"entity_id": "light.desk", "name": "Desk lamp"},
			results: map[string]string{
				"config/entity_registry/get": desk, "config/entity_registry/update": `{"entity_entry":` + deskRenamed + `}`,
				"get_states": `[{"entity_id":"light.desk","state":"off"}]`,
			},
			then:  map[string]map[string]string{"config/entity_registry/update": {"config/entity_registry/get": deskRenamed}},
			shown: "Change the entity light.desk", write: "config/entity_registry/update",
			message: []string{`"entity_id":"light.desk"`, `"name":"Desk lamp"`}, object: "light.desk",
			undo: "config/entity_registry/update", undoMessage: []string{`"entity_id":"light.desk"`, `"name":null`},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			r := startRegistryServer(t, c.kinds, c.results, c.then)
			accessToken := r.authorize(t, "local")

			text, isError := r.callToolWith(t, accessToken, c.tool, c.args)
			if isError || !strings.HasPrefix(text, "NOT RUN YET") || len(r.sentCore(c.write)) != 0 {
				t.Fatalf("call before the approval: isError = %t, sent %v, %s", isError, r.sentCore(c.write), text)
			}
			shown := r.asAdmin(t, http.MethodGet, "/", nil).body
			id, token := actionIDRE.FindStringSubmatch(shown), formTokenRE.FindStringSubmatch(shown)
			if !strings.Contains(shown, c.shown) || id == nil || token == nil {
				t.Fatalf("the sidebar page does not show %q with a form:\n%s", c.shown, shown)
			}
			if got := r.asAdmin(t, http.MethodPost, "/action", url.Values{"csrf": {token[1]}, "id": {id[1]}, "action": {"approve"}}); got.status != http.StatusOK {
				t.Fatalf("approve: status %d", got.status)
			}

			text, isError = r.callToolWith(t, accessToken, c.tool, c.args)
			written := r.sentCore(c.write)
			if isError || len(written) != 1 {
				t.Fatalf("call after the approval: isError = %t, sent %v, %s", isError, written, text)
			}
			for _, want := range c.message {
				if !strings.Contains(written[0], want) {
					t.Errorf("the change lacks %s: %s", want, written[0])
				}
			}
			if strings.Contains(written[0], `"labels"`) {
				t.Errorf("the change carries labels: %s", written[0])
			}
			if c.tool == "area_create" {
				// The gate labels the new area, and only that message
				// carries labels.
				labelled := r.sentCore("config/area_registry/update")
				if len(labelled) != 1 || !strings.Contains(labelled[0], `"area_id":"den"`) || !strings.Contains(labelled[0], `"labels":["airlock"]`) {
					t.Errorf("the new area was not labelled: %v", labelled)
				}
			}
			journal, err := os.ReadFile(filepath.Join(r.dataDir, "changes.json")) //nolint:gosec // test file below t.TempDir
			if err != nil || !strings.Contains(string(journal), `"object":"`+c.object+`"`) || !strings.Contains(string(journal), `"left":`) {
				t.Fatalf("the journal of changes does not hold the change: %v\n%s", err, journal)
			}

			before := len(r.sentCore(c.undo))
			shown = r.asAdmin(t, http.MethodGet, "/", nil).body
			undoID, token := undoIDRE.FindStringSubmatch(shown), formTokenRE.FindStringSubmatch(shown)
			if undoID == nil || token == nil {
				t.Fatalf("the sidebar page offers no undo:\n%s", shown)
			}
			got := r.asAdmin(t, http.MethodPost, "/undo", url.Values{"csrf": {token[1]}, "id": {undoID[1]}})
			undone := r.sentCore(c.undo)
			if got.status != http.StatusOK || !strings.Contains(got.body, "Undone.") || len(undone) != before+1 {
				t.Fatalf("undo: status %d, sent %v:\n%s", got.status, undone, got.body)
			}
			for _, want := range c.undoMessage {
				if !strings.Contains(undone[before], want) {
					t.Errorf("the undo lacks %s: %s", want, undone[before])
				}
			}
			if c.undo != "config/area_registry/delete" && strings.Contains(undone[before], `"labels"`) {
				t.Errorf("the undo carries labels: %s", undone[before])
			}
			if audited := r.auditText(t); !strings.Contains(audited, `"event":"change_undone"`) {
				t.Errorf("the audit log does not record the undo:\n%s", audited)
			}
		})
	}
}

// What the policy or the release rules refuse is refused by the running
// server before anything is parked or written.
func TestRegistryChangesTheServerRefuses(t *testing.T) {
	t.Parallel()
	base := map[string]string{
		"config/area_registry/list": "[" + bareKitchen + "]", "config/floor_registry/list": `[]`,
		"config/label_registry/list": labels, "config/entity_registry/get": deskUnmarked,
		"get_states": `[{"entity_id":"light.desk","state":"off"}]`,
	}
	cases := []struct {
		name, kinds, tool string
		args              map[string]string
		results           map[string]string
		// refusal is in the answer, decision in the audit record.
		refusal, decision string
	}{
		{"area not opened", `{"helper":{"change":"approval"}}`, "area_update", map[string]string{"area_id": "kitchen", "name": "Cook"}, nil, `of the kind "area"`, `"decision":"kind_denied"`},
		{"label not opened", `{"helper":{"change":"approval"}}`, "label_update", map[string]string{"label_id": "spare", "name": "R"}, nil, `of the kind "label"`, `"decision":"kind_denied"`},
		{"entity not opened", `{"helper":{"change":"approval"}}`, "entity_update", map[string]string{"entity_id": "light.desk", "name": "D"}, nil, `of the kind "entity"`, `"decision":"kind_denied"`},
		{"area without the label", `{"area":{"change":"approval","release":"label"}}`, "area_update", map[string]string{"area_id": "kitchen", "name": "Cook"}, nil, "not released for change", ""},
		{"entity without the label", `{"entity":{"change":"approval"}}`, "entity_update", map[string]string{"entity_id": "light.desk", "name": "D"}, nil, "not released for change", ""},
		{"the control label", `{"label":{"change":"approval"}}`, "label_update", map[string]string{"label_id": "airlock", "name": "Open"}, nil, "control label", ""},
		{
			"a label while the control label is missing", `{"label":{"change":"approval"}}`, "label_create",
			map[string]string{"name": "Airlock"},
			map[string]string{"config/label_registry/list": `[{"label_id":"spare","name":"Spare"}]`},
			"does not exist", "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			results := map[string]string{}
			for k, v := range base {
				results[k] = v
			}
			for k, v := range c.results {
				results[k] = v
			}
			r := startRegistryServer(t, c.kinds, results, nil)
			accessToken := r.authorize(t, "local")
			text, _ := r.callToolWith(t, accessToken, c.tool, c.args)
			if strings.HasPrefix(text, "NOT RUN YET") || !strings.Contains(text, c.refusal) {
				t.Errorf("answer %q, want a refusal with %q", text, c.refusal)
			}
			if c.decision != "" && !strings.Contains(r.auditText(t), c.decision) {
				t.Errorf("the audit log lacks %s:\n%s", c.decision, r.auditText(t))
			}
			if actionIDRE.MatchString(r.asAdmin(t, http.MethodGet, "/", nil).body) {
				t.Error("the refused call waits on the sidebar page")
			}
			r.home.Mu.Lock()
			defer r.home.Mu.Unlock()
			for _, m := range r.home.CoreMessages {
				if command := strings.SplitN(m, " ", 2)[0]; strings.HasSuffix(command, "/update") || strings.HasSuffix(command, "/create") || strings.HasSuffix(command, "/delete") {
					t.Errorf("sent %s", m)
				}
			}
		})
	}
}

// With release: all the owner opens every area, labelled or not.
func TestAreaReleasedForAllWaitsForApprovalWithoutTheLabel(t *testing.T) {
	t.Parallel()
	r := startRegistryServer(t, `{"area":{"change":"approval","release":"all"}}`,
		map[string]string{"config/area_registry/list": "[" + bareKitchen + "]", "config/floor_registry/list": `[]`}, nil)
	accessToken := r.authorize(t, "local")
	if text, isError := r.callToolWith(t, accessToken, "area_update", map[string]string{"area_id": "kitchen", "name": "Cook"}); isError || !strings.HasPrefix(text, "NOT RUN YET") {
		t.Fatalf("the call was not parked: isError = %t, %s", isError, text)
	}
}
