// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// A helper is an item of a storage collection in Home Assistant, and an
// entity stands for it: the entity's registry entry has the helper's domain
// as platform and the item's id as unique id
// (homeassistant/helpers/collection.py:479-491, Core 3f8160ce7ff). The
// tools name a helper by that entity, because the entity is what the owner
// sees and labels; the item id is looked up.

// helperField is one field of a helper's stored configuration.
type helperField struct {
	name string
	// schema is the field's JSON Schema, for the tool's input schema.
	schema string
	// check refuses a value Home Assistant would refuse, or that this
	// server does not pass on.
	check func(value json.RawMessage) error
}

// helperDomain declares the tools for the helpers of one domain. The fields
// are those of the domain's storage schema; a name is required by all.
type helperDomain struct {
	domain string
	// noun is what the helper is called in a sentence.
	noun   string
	fields []helperField
}

var iconShape = regexp.MustCompile(`^[a-z0-9-]{1,32}:[a-z0-9-]{1,64}$`)

func checkName(value json.RawMessage) error {
	var name string
	if err := json.Unmarshal(value, &name); err != nil {
		return errors.New("name must be a string")
	}
	if n := len([]rune(name)); n < 1 || n > 100 || strings.TrimSpace(name) == "" {
		return errors.New("name must have between 1 and 100 characters")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return errors.New("name must not contain control characters")
		}
	}
	return nil
}

func checkIcon(value json.RawMessage) error {
	var icon string
	if err := json.Unmarshal(value, &icon); err != nil || !iconShape.MatchString(icon) {
		return errors.New("icon must have the form prefix:name, such as mdi:account")
	}
	return nil
}

func checkBool(name string) func(json.RawMessage) error {
	return func(value json.RawMessage) error {
		var b bool
		if err := json.Unmarshal(value, &b); err != nil {
			return fmt.Errorf("%s must be true or false", name)
		}
		return nil
	}
}

var nameField = helperField{
	name: "name", check: checkName,
	schema: `{"type": "string", "minLength": 1, "maxLength": 100, "description": "The helper's name."}`,
}

var iconField = helperField{
	name: "icon", check: checkIcon,
	schema: `{"type": "string", "pattern": "^[a-z0-9-]{1,32}:[a-z0-9-]{1,64}$", "description": "An icon, for example mdi:account."}`,
}

// inputBoolean has the fields of
// homeassistant/components/input_boolean/__init__.py:31-35 (Core
// 3f8160ce7ff).
var inputBoolean = helperDomain{
	domain: "input_boolean", noun: "toggle helper",
	fields: []helperField{
		nameField, iconField,
		{
			name: "initial", check: checkBool("initial"),
			schema: `{"type": "boolean", "description": "The state the helper has when Home Assistant starts. If left out, the last state is restored."}`,
		},
	},
}

// helperTools returns the tools for every declared helper domain.
func helperTools() []Tool {
	domains := []helperDomain{inputBoolean}
	tools := make([]Tool, 0, 4*len(domains))
	for _, d := range domains {
		tools = append(tools, d.list(), d.create(), d.update(), d.remove())
	}
	return tools
}

// properties renders the fields as JSON Schema properties.
func (d helperDomain) properties() string {
	parts := make([]string, 0, len(d.fields))
	for _, f := range d.fields {
		parts = append(parts, fmt.Sprintf("    %q: %s", f.name, f.schema))
	}
	return strings.Join(parts, ",\n")
}

func (d helperDomain) entitySchema() string {
	return fmt.Sprintf(`"entity_id": {"type": "string", "pattern": "^%s\\.[a-z0-9_]{1,128}$", "description": "The helper's entity, for example %s.example."}`,
		d.domain, d.domain)
}

// state reads the fields a client gave into the state a write would leave:
// the declared fields, each checked, and nothing else. skip names keys that
// are not fields of the helper.
func (d helperDomain) state(given map[string]json.RawMessage, skip string) (map[string]json.RawMessage, error) {
	state := map[string]json.RawMessage{}
	for key, value := range given {
		if key == skip {
			continue
		}
		known := false
		for _, f := range d.fields {
			if f.name != key {
				continue
			}
			known = true
			if err := f.check(value); err != nil {
				return nil, err
			}
			state[key] = value
		}
		if !known {
			return nil, fmt.Errorf("invalid arguments: unknown field %q", key)
		}
	}
	if _, ok := state["name"]; !ok {
		return nil, errors.New("name is required")
	}
	return state, nil
}

// entity checks the entity id a client gave.
func (d helperDomain) entity(given map[string]json.RawMessage) (string, error) {
	var id string
	if err := json.Unmarshal(given["entity_id"], &id); err != nil || !entityIDShape.MatchString(id) || !strings.HasPrefix(id, d.domain+".") {
		return "", fmt.Errorf("entity_id must be an entity of the domain %s, such as %s.example", d.domain, d.domain)
	}
	return id, nil
}

// helperItem is a helper as Home Assistant stores it.
type helperItem struct {
	id     string
	fields map[string]json.RawMessage
}

// items reads the domain's helpers.
func (d helperDomain) items(ctx context.Context, core Core) ([]helperItem, error) {
	var raw []map[string]json.RawMessage
	if err := core.Call(ctx, d.domain+"/list", nil, &raw); err != nil {
		return nil, fmt.Errorf("%s/list: %w", d.domain, err)
	}
	items := make([]helperItem, 0, len(raw))
	for _, fields := range raw {
		var id string
		if err := json.Unmarshal(fields["id"], &id); err != nil || id == "" {
			return nil, fmt.Errorf("%s/list: an item has no id", d.domain)
		}
		delete(fields, "id")
		items = append(items, helperItem{id: id, fields: fields})
	}
	return items, nil
}

// find returns the helper an entity stands for, and the entity's name.
func (d helperDomain) find(ctx context.Context, core Core, entity string) (item helperItem, name string, err error) {
	var reg struct {
		Platform     string  `json:"platform"`
		UniqueID     string  `json:"unique_id"`
		Name         *string `json:"name"`
		OriginalName *string `json:"original_name"`
	}
	if err := core.Call(ctx, "config/entity_registry/get", map[string]string{"entity_id": entity}, &reg); err != nil {
		return helperItem{}, "", fmt.Errorf("config/entity_registry/get: %w", err)
	}
	if reg.Platform != d.domain || reg.UniqueID == "" {
		return helperItem{}, "", fmt.Errorf("%s is not a %s created in Home Assistant's user interface", entity, d.noun)
	}
	items, err := d.items(ctx, core)
	if err != nil {
		return helperItem{}, "", err
	}
	switch {
	case reg.Name != nil && *reg.Name != "":
		name = *reg.Name
	case reg.OriginalName != nil:
		name = *reg.OriginalName
	}
	for _, it := range items {
		if it.id == reg.UniqueID {
			return it, name, nil
		}
	}
	return helperItem{}, "", fmt.Errorf("%s has no stored configuration", entity)
}

// entityOf returns the entity that stands for the item with the given id.
// Home Assistant registers it when the item is created; the registry is
// asked a few times, in case that has not happened yet.
func (d helperDomain) entityOf(ctx context.Context, core Core, id string) (string, error) {
	for attempt := 0; ; attempt++ {
		var entries []struct {
			EntityID string `json:"entity_id"`
			Platform string `json:"platform"`
			UniqueID string `json:"unique_id"`
		}
		if err := core.Call(ctx, "config/entity_registry/list", nil, &entries); err != nil {
			return "", fmt.Errorf("config/entity_registry/list: %w", err)
		}
		for i := range entries {
			if entries[i].Platform == d.domain && entries[i].UniqueID == id {
				return entries[i].EntityID, nil
			}
		}
		if attempt == 4 {
			return "", fmt.Errorf("the new %s has no entity yet", d.noun)
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("look for the new entity: %w", ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func decodeFields(args json.RawMessage) (map[string]json.RawMessage, error) {
	given := map[string]json.RawMessage{}
	if err := decodeArgs(args, &given); err != nil {
		return nil, err
	}
	return given, nil
}

func (d helperDomain) list() Tool {
	return Tool{
		Name:  d.domain + "_list",
		Title: "List " + d.noun + "s",
		Description: fmt.Sprintf("Returns the %ss created in Home Assistant's user interface, each with its entity and "+
			"its stored configuration.", d.noun),
		Tier:        R0,
		Endpoints:   []string{"websocket: " + d.domain + "/list", "websocket: config/entity_registry/list"},
		InputSchema: json.RawMessage("{\n  \"type\": \"object\",\n  \"properties\": {},\n  \"additionalProperties\": false\n}"),
		Handler: func(ctx context.Context, core Core, args json.RawMessage) (json.RawMessage, error) {
			if given, err := decodeFields(args); err != nil || len(given) != 0 {
				return nil, errors.New("invalid arguments: this tool takes none")
			}
			items, err := d.items(ctx, core)
			if err != nil {
				return nil, err
			}
			var entries []struct {
				EntityID string `json:"entity_id"`
				Platform string `json:"platform"`
				UniqueID string `json:"unique_id"`
			}
			if err := core.Call(ctx, "config/entity_registry/list", nil, &entries); err != nil {
				return nil, fmt.Errorf("config/entity_registry/list: %w", err)
			}
			entityOf := map[string]string{}
			for i := range entries {
				if entries[i].Platform == d.domain {
					entityOf[entries[i].UniqueID] = entries[i].EntityID
				}
			}
			type helper struct {
				EntityID      string                     `json:"entity_id"`
				Configuration map[string]json.RawMessage `json:"configuration"`
			}
			out := make([]helper, 0, len(items))
			for _, it := range items {
				out = append(out, helper{EntityID: entityOf[it.id], Configuration: it.fields})
			}
			encoded, err := json.Marshal(struct {
				Helpers []helper `json:"helpers"`
			}{out})
			if err != nil {
				return nil, fmt.Errorf("encode result: %w", err)
			}
			return encoded, nil
		},
	}
}

const changeNote = " The call waits for the owner's approval: it returns without having run, and runs when it is " +
	"repeated with the same arguments after the approval. The owner is shown the present configuration beside the " +
	"requested one."

func (d helperDomain) create() Tool {
	return Tool{
		Name:        d.domain + "_create",
		Title:       "Create a " + d.noun,
		Description: fmt.Sprintf("Creates a %s. ha-airlock releases what it created for later changes.", d.noun) + changeNote,
		Tier:        R2,
		Kind:        KindHelper,
		Endpoints: []string{
			"websocket: " + d.domain + "/create", "websocket: config/entity_registry/list",
			"websocket: config/entity_registry/get", "websocket: config/entity_registry/update (labels of the new entity)",
		},
		InputSchema: json.RawMessage(fmt.Sprintf("{\n  \"type\": \"object\",\n  \"properties\": {\n%s\n  },\n"+
			"  \"required\": [\"name\"],\n  \"additionalProperties\": false\n}", d.properties())),
		Plan: func(_ context.Context, _ Core, args json.RawMessage) (Change, error) {
			given, err := decodeFields(args)
			if err != nil {
				return Change{}, err
			}
			state, err := d.state(given, "")
			if err != nil {
				return Change{}, err
			}
			return d.planCreate(state)
		},
		// What was created is taken back by deleting it.
		Revert: func(ctx context.Context, core Core, object string, _, _ json.RawMessage) (Change, error) {
			return d.planDelete(ctx, core, object)
		},
	}
}

// recorded reads a state the journal holds into the fields of a helper,
// through the same checks a client's fields pass.
func (d helperDomain) recorded(state json.RawMessage) (map[string]json.RawMessage, error) {
	given := map[string]json.RawMessage{}
	if err := json.Unmarshal(state, &given); err != nil {
		return nil, fmt.Errorf("the recorded state is not an object: %w", err)
	}
	return d.state(given, "")
}

// planUpdate plans replacing the stored configuration of the helper an
// entity stands for by the given state.
func (d helperDomain) planUpdate(ctx context.Context, core Core, entity string, state map[string]json.RawMessage) (Change, error) {
	item, name, err := d.find(ctx, core, entity)
	if err != nil {
		return Change{}, err
	}
	before, err := json.Marshal(item.fields)
	if err != nil {
		return Change{}, fmt.Errorf("encode the present state: %w", err)
	}
	after, err := json.Marshal(state)
	if err != nil {
		return Change{}, fmt.Errorf("encode the requested state: %w", err)
	}
	return Change{
		Summary: fmt.Sprintf("Change the %s %s", d.noun, entity),
		Object:  entity, Name: name, Entity: entity, Before: before, After: after, Left: d.left,
		Apply: func(ctx context.Context, core Core) (string, json.RawMessage, error) {
			message := map[string]json.RawMessage{}
			for key, value := range state {
				message[key] = value
			}
			id, err := json.Marshal(item.id)
			if err != nil {
				return "", nil, fmt.Errorf("encode the helper's id: %w", err)
			}
			message[d.domain+"_id"] = id
			if err := core.Call(ctx, d.domain+"/update", message, nil); err != nil {
				return "", nil, fmt.Errorf("%s/update: %w", d.domain, err)
			}
			return entity, json.RawMessage(fmt.Sprintf(`{"changed":%q}`, entity)), nil
		},
	}, nil
}

// left reads the stored configuration of the helper an entity stands for,
// as a change's state after the write.
func (d helperDomain) left(ctx context.Context, core Core, entity string) (json.RawMessage, error) {
	item, _, err := d.find(ctx, core, entity)
	if err != nil {
		return nil, err
	}
	held, err := json.Marshal(item.fields)
	if err != nil {
		return nil, fmt.Errorf("encode the state after the change: %w", err)
	}
	return held, nil
}

// planDelete plans deleting the helper an entity stands for.
func (d helperDomain) planDelete(ctx context.Context, core Core, entity string) (Change, error) {
	item, name, err := d.find(ctx, core, entity)
	if err != nil {
		return Change{}, err
	}
	before, err := json.Marshal(item.fields)
	if err != nil {
		return Change{}, fmt.Errorf("encode the present state: %w", err)
	}
	return Change{
		Summary: fmt.Sprintf("Delete the %s %s", d.noun, entity),
		Object:  entity, Name: name, Entity: entity, Before: before,
		Apply: func(ctx context.Context, core Core) (string, json.RawMessage, error) {
			if err := core.Call(ctx, d.domain+"/delete", map[string]string{d.domain + "_id": item.id}, nil); err != nil {
				return "", nil, fmt.Errorf("%s/delete: %w", d.domain, err)
			}
			return entity, json.RawMessage(fmt.Sprintf(`{"deleted":%q}`, entity)), nil
		},
	}, nil
}

// planCreate plans creating a helper with the given state.
func (d helperDomain) planCreate(state map[string]json.RawMessage) (Change, error) {
	after, err := json.Marshal(state)
	if err != nil {
		return Change{}, fmt.Errorf("encode the requested state: %w", err)
	}
	return Change{
		Summary: "Create a " + d.noun,
		After:   after, Left: d.left,
		Apply: func(ctx context.Context, core Core) (string, json.RawMessage, error) {
			var created struct {
				ID string `json:"id"`
			}
			if err := core.Call(ctx, d.domain+"/create", state, &created); err != nil {
				return "", nil, fmt.Errorf("%s/create: %w", d.domain, err)
			}
			entity, err := d.entityOf(ctx, core, created.ID)
			if err != nil {
				return "", nil, err
			}
			return entity, json.RawMessage(fmt.Sprintf(`{"created":%q}`, entity)), nil
		},
	}, nil
}

func (d helperDomain) update() Tool {
	return Tool{
		Name:  d.domain + "_update",
		Title: "Change a " + d.noun,
		Description: fmt.Sprintf("Replaces the stored configuration of one %s: every field that is left out is removed. "+
			"The helper must be released by the owner.", d.noun) + changeNote,
		Tier:      R2,
		Kind:      KindHelper,
		Endpoints: []string{"websocket: config/entity_registry/get", "websocket: " + d.domain + "/list", "websocket: " + d.domain + "/update"},
		InputSchema: json.RawMessage(fmt.Sprintf("{\n  \"type\": \"object\",\n  \"properties\": {\n    %s,\n%s\n  },\n"+
			"  \"required\": [\"entity_id\", \"name\"],\n  \"additionalProperties\": false\n}", d.entitySchema(), d.properties())),
		Plan: func(ctx context.Context, core Core, args json.RawMessage) (Change, error) {
			given, err := decodeFields(args)
			if err != nil {
				return Change{}, err
			}
			entity, err := d.entity(given)
			if err != nil {
				return Change{}, err
			}
			state, err := d.state(given, "entity_id")
			if err != nil {
				return Change{}, err
			}
			return d.planUpdate(ctx, core, entity, state)
		},
		// A change is taken back by writing the recorded state again.
		Revert: func(ctx context.Context, core Core, object string, before, _ json.RawMessage) (Change, error) {
			state, err := d.recorded(before)
			if err != nil {
				return Change{}, err
			}
			return d.planUpdate(ctx, core, object, state)
		},
	}
}

func (d helperDomain) remove() Tool {
	return Tool{
		Name:  d.domain + "_delete",
		Title: "Delete a " + d.noun,
		Description: fmt.Sprintf("Deletes one %s and its entity. The helper must be released by the owner.", d.noun) +
			changeNote,
		Tier:      R2,
		Kind:      KindHelper,
		Endpoints: []string{"websocket: config/entity_registry/get", "websocket: " + d.domain + "/list", "websocket: " + d.domain + "/delete"},
		InputSchema: json.RawMessage(fmt.Sprintf("{\n  \"type\": \"object\",\n  \"properties\": {\n    %s\n  },\n"+
			"  \"required\": [\"entity_id\"],\n  \"additionalProperties\": false\n}", d.entitySchema())),
		Plan: func(ctx context.Context, core Core, args json.RawMessage) (Change, error) {
			given, err := decodeFields(args)
			if err != nil {
				return Change{}, err
			}
			entity, err := d.entity(given)
			if err != nil {
				return Change{}, err
			}
			if len(given) != 1 {
				return Change{}, errors.New("invalid arguments: only entity_id is taken")
			}
			return d.planDelete(ctx, core, entity)
		},
		// A deletion is taken back by creating the helper again. The
		// entity it gets is Home Assistant's choice.
		Revert: func(ctx context.Context, core Core, object string, before, _ json.RawMessage) (Change, error) {
			state, err := d.recorded(before)
			if err != nil {
				return Change{}, err
			}
			var entries []struct {
				EntityID string `json:"entity_id"`
			}
			if err := core.Call(ctx, "config/entity_registry/list", nil, &entries); err != nil {
				return Change{}, fmt.Errorf("config/entity_registry/list: %w", err)
			}
			for i := range entries {
				if entries[i].EntityID == object {
					return Change{}, fmt.Errorf("%s exists again", object)
				}
			}
			return d.planCreate(state)
		},
	}
}
