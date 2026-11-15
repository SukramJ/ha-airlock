// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// Areas, labels and the entity registry are registries of Home Assistant
// Core, changed through config/<registry>/create and /update
// (homeassistant/components/config/area_registry.py:42-152,
// label_registry.py:72-152, entity_registry.py:153-293, Core 3f8160ce7ff).
// Their update commands change only the keys a message holds
// (helpers/area_registry.py:381-430, helpers/label_registry.py:187-208,
// components/config/entity_registry.py:219-229), so the tools here change
// the fields a client names and leave the others as they are. A message
// holds the object's id and the client's checked fields, nothing else: never
// labels, which release objects for change.

// registryIDShape is the form Home Assistant gives the id of an area, a
// floor or a label: the slug of its name (helpers/area_registry.py:271-273,
// helpers/normalized_name_base_registry.py:70-77). An id of another form is
// refused, not passed on.
var registryIDShape = regexp.MustCompile(`^[a-z0-9_]{1,128}$`)

// picturePath is a path on the Home Assistant the owner uses, never another
// address: every browser that shows the area would load it. A second slash
// or a backslash after the first would make it another host's address.
var picturePath = regexp.MustCompile(`^/[A-Za-z0-9._~%-][A-Za-z0-9._~%/-]{0,254}$`)

// colorShape is color_hex of homeassistant/helpers/config_validation.py:461-471.
var colorShape = regexp.MustCompile(`^#[0-9A-Fa-f]{6}$`)

// themeColors are the named colours a label may have
// (homeassistant/components/config/label_registry.py:13-40).
var themeColors = []string{
	"primary", "accent", "disabled", "red", "pink", "purple", "deep-purple", "indigo", "blue", "light-blue", "cyan",
	"teal", "green", "light-green", "lime", "yellow", "amber", "orange", "deep-orange", "brown", "light-grey", "grey",
	"dark-grey", "blue-grey", "black", "white",
}

// registryField is one field of a registry entry a client may set.
type registryField struct {
	name   string
	schema string
	check  func(value json.RawMessage) error
	// nullable says that an update may clear the field with null. A
	// creation never sends null: Core's create schemas refuse it for some
	// fields, and a field left out is empty anyway.
	nullable bool
}

// registry declares the tools for the entries of one of Core's registries.
type registry struct {
	kind Kind
	// noun is what an entry is called in a sentence, article included.
	noun, plural string
	// command is the prefix of the registry's WebSocket commands, and
	// idKey the key that names an entry.
	command, idKey string
	fields         []registryField
	// shown are keys that are read, shown and bound, and never sent.
	shown []string
	// sets are keys whose value Home Assistant keeps as a set and sends in
	// no stated order (helpers/area_registry.py:88-104). They are sorted
	// before anything is shown or hashed.
	sets []string
	// references checks that what fields name exists.
	references func(ctx context.Context, core Core, fields map[string]json.RawMessage) error
	// unused checks that nothing refers to an entry before an undo of its
	// creation deletes it.
	unused func(ctx context.Context, core Core, id string) error
}

func registryTools() []Tool {
	return []Tool{
		areaRegistry.list(), areaRegistry.create(), areaRegistry.update(),
		floorList(),
		labelRegistry.list(), labelRegistry.create(), labelRegistry.update(),
		entityUpdate(),
	}
}

// areaRegistry has the fields of the area create and update schemas
// (components/config/area_registry.py:43-50, :112-120). Labels and the
// sensors of an area are shown and never changed here.
var areaRegistry = registry{
	kind: KindArea, noun: "an area", plural: "areas", command: "config/area_registry", idKey: "area_id",
	fields: []registryField{
		{name: "name", check: checkName, schema: `{"type": "string", "minLength": 1, "maxLength": 100, "description": "The area's name."}`},
		{name: "icon", check: checkIcon, nullable: true, schema: `{"type": ["string", "null"], "pattern": "^[a-z0-9-]{1,32}:[a-z0-9-]{1,64}$", "description": "An icon, for example mdi:sofa; null clears it."}`},
		{
			name: "floor_id", check: checkMatch("floor_id", registryIDShape, "of a floor id, such as ground_floor"), nullable: true,
			schema: `{"type": ["string", "null"], "pattern": "^[a-z0-9_]{1,128}$", "description": "The floor the area is on, as floor_list names it; null takes it off its floor."}`,
		},
		{name: "aliases", check: checkAliases, schema: `{"type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 100}, "maxItems": 20, "uniqueItems": true, "description": "Other names of the area, for voice assistants. Replaces the present ones."}`},
		{name: "picture", check: checkPicture, nullable: true, schema: `{"type": ["string", "null"], "pattern": "^/[A-Za-z0-9._~%-][A-Za-z0-9._~%/-]{0,254}$", "description": "A path on this Home Assistant, such as /api/image/serve/<id>/512x512; null clears it. Other addresses are refused."}`},
	},
	shown: []string{"labels", "temperature_entity_id", "humidity_entity_id"},
	sets:  []string{"aliases", "labels"},
	references: func(ctx context.Context, core Core, fields map[string]json.RawMessage) error {
		value, ok := fields["floor_id"]
		if !ok || isJSONNull(value) {
			return nil
		}
		var floor string
		_ = json.Unmarshal(value, &floor)
		// Core stores any floor id it is given
		// (helpers/area_registry.py:302-312, :398-410), so it is checked here.
		var floors []struct {
			ID string `json:"floor_id"`
		}
		if err := core.Call(ctx, "config/floor_registry/list", nil, &floors); err != nil {
			return fmt.Errorf("config/floor_registry/list: %w", err)
		}
		for _, f := range floors {
			if f.ID == floor {
				return nil
			}
		}
		return fmt.Errorf("there is no floor %s", floor)
	},
	unused: func(ctx context.Context, core Core, id string) error {
		return unassigned(ctx, core, "area_id", id)
	},
}

// labelRegistry has the fields of the label create and update schemas
// (components/config/label_registry.py:73-78, :126-132). A label carries no
// label; the gate keeps the control label out of reach.
var labelRegistry = registry{
	kind: KindLabel, noun: "a label", plural: "labels", command: "config/label_registry", idKey: "label_id",
	fields: []registryField{
		{name: "name", check: checkName, schema: `{"type": "string", "minLength": 1, "maxLength": 100, "description": "The label's name."}`},
		{name: "color", check: checkColor, nullable: true, schema: `{"type": ["string", "null"], "description": "A colour, as #RRGGBB or one of the theme colours such as red, indigo, light-grey; null clears it."}`},
		{name: "icon", check: checkIcon, nullable: true, schema: `{"type": ["string", "null"], "pattern": "^[a-z0-9-]{1,32}:[a-z0-9-]{1,64}$", "description": "An icon, for example mdi:tag; null clears it."}`},
		{name: "description", check: checkText("description"), nullable: true, schema: `{"type": ["string", "null"], "maxLength": 255, "description": "What the label is for; null clears it."}`},
	},
	unused: func(ctx context.Context, core Core, id string) error {
		if err := unassigned(ctx, core, "labels", id); err != nil {
			return err
		}
		var areas []struct {
			ID     string   `json:"area_id"`
			Labels []string `json:"labels"`
		}
		if err := core.Call(ctx, "config/area_registry/list", nil, &areas); err != nil {
			return fmt.Errorf("config/area_registry/list: %w", err)
		}
		for _, a := range areas {
			if slices.Contains(a.Labels, id) {
				return fmt.Errorf("the area %s carries the label %s", a.ID, id)
			}
		}
		return nil
	},
}

func checkAliases(value json.RawMessage) error {
	var aliases []json.RawMessage
	if jsonKind(value) != '[' || json.Unmarshal(value, &aliases) != nil || len(aliases) > 20 {
		return errors.New("aliases must be a list of at most 20 names")
	}
	seen := map[string]bool{}
	for _, raw := range aliases {
		if err := checkName(raw); err != nil {
			return fmt.Errorf("an alias: %w", err)
		}
		var alias string
		_ = json.Unmarshal(raw, &alias)
		// Core strips aliases and keeps them as a set
		// (components/config/area_registry.py:67-71): what it would keep
		// is what is asked for.
		if alias != strings.TrimSpace(alias) || seen[alias] {
			return errors.New("aliases must be distinct, without leading or trailing spaces")
		}
		seen[alias] = true
	}
	return nil
}

func checkPicture(value json.RawMessage) error {
	var path string
	if jsonKind(value) != '"' || json.Unmarshal(value, &path) != nil || !picturePath.MatchString(path) {
		return errors.New("picture must be a path on this Home Assistant, beginning with a single /")
	}
	return nil
}

func checkColor(value json.RawMessage) error {
	var color string
	if jsonKind(value) == '"' && json.Unmarshal(value, &color) == nil && (colorShape.MatchString(color) || slices.Contains(themeColors, color)) {
		return nil
	}
	return errors.New("color must be #RRGGBB or one of " + strings.Join(themeColors, ", "))
}

// unassigned checks that no entity and no device names id under key: an
// area as area_id, a label in labels. The deleted entities and devices Home
// Assistant keeps are not in these lists (helpers/area_registry.py:329-334).
func unassigned(ctx context.Context, core Core, key, id string) error {
	for _, list := range []struct{ command, noun string }{
		{"config/entity_registry/list", "entity"},
		{"config/device_registry/list", "entry of the device registry"},
	} {
		var entries []map[string]json.RawMessage
		if err := core.Call(ctx, list.command, nil, &entries); err != nil {
			return fmt.Errorf("%s: %w", list.command, err)
		}
		for _, entry := range entries {
			var area string
			var labels []string
			switch {
			case key == "labels" && json.Unmarshal(entry["labels"], &labels) == nil && slices.Contains(labels, id),
				key == "area_id" && json.Unmarshal(entry["area_id"], &area) == nil && area == id:
				return fmt.Errorf("an %s still refers to %s", list.noun, id)
			}
		}
	}
	return nil
}

// entries reads the registry, each entry as a state the journal can hold.
func (r registry) entries(ctx context.Context, core Core) (map[string]map[string]json.RawMessage, error) {
	var raw []map[string]json.RawMessage
	if err := core.Call(ctx, r.command+"/list", nil, &raw); err != nil {
		return nil, fmt.Errorf("%s/list: %w", r.command, err)
	}
	out := make(map[string]map[string]json.RawMessage, len(raw))
	for _, entry := range raw {
		var id string
		if err := json.Unmarshal(entry[r.idKey], &id); err != nil || id == "" {
			return nil, fmt.Errorf("%s/list: an entry has no %s", r.command, r.idKey)
		}
		state, err := r.state(entry)
		if err != nil {
			return nil, err
		}
		out[id] = state
	}
	return out, nil
}

// state is an entry as it is shown, bound and hashed: the declared fields
// and the shown keys, sets sorted, a missing key as null. The id and the
// timestamps are not part of it; modified_at moves with every write.
func (r registry) state(entry map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	state := map[string]json.RawMessage{}
	keys := slices.Clone(r.shown)
	for _, f := range r.fields {
		keys = append(keys, f.name)
	}
	for _, key := range keys {
		value, ok := entry[key]
		if !ok {
			value = json.RawMessage("null")
		}
		if slices.Contains(r.sets, key) {
			sorted, err := sortedSet(value)
			if err != nil {
				return nil, fmt.Errorf("%s of an entry: %w", key, err)
			}
			value = sorted
		}
		state[key] = value
	}
	return state, nil
}

// sortedSet sorts a list of strings; null stays null.
func sortedSet(value json.RawMessage) (json.RawMessage, error) {
	if isJSONNull(value) {
		return value, nil
	}
	var items []string
	if err := json.Unmarshal(value, &items); err != nil {
		return nil, errors.New("not a list of strings")
	}
	slices.Sort(items)
	return json.Marshal(items)
}

// read returns one entry's state and its name.
func (r registry) read(ctx context.Context, core Core, id string) (state map[string]json.RawMessage, name string, err error) {
	all, err := r.entries(ctx, core)
	if err != nil {
		return nil, "", err
	}
	state, ok := all[id]
	if !ok {
		return nil, "", fmt.Errorf("there is no %s %s", strings.TrimPrefix(strings.TrimPrefix(r.noun, "an "), "a "), id)
	}
	_ = json.Unmarshal(state["name"], &name)
	return state, name, nil
}

// left reads an entry as a change's state after the write.
func (r registry) left(ctx context.Context, core Core, id string) (json.RawMessage, error) {
	state, _, err := r.read(ctx, core, id)
	if err != nil {
		return nil, err
	}
	return json.Marshal(state)
}

// given checks the fields a client named: declared, each checked, null only
// where an update may clear the field.
func (r registry) given(args map[string]json.RawMessage, creation bool) (map[string]json.RawMessage, error) {
	fields := map[string]json.RawMessage{}
	for key, value := range args {
		if key == r.idKey && !creation {
			continue
		}
		i := slices.IndexFunc(r.fields, func(f registryField) bool { return f.name == key })
		if i < 0 {
			return nil, fmt.Errorf("invalid arguments: unknown field %q", key)
		}
		f := r.fields[i]
		switch {
		case isJSONNull(value) && (creation || !f.nullable):
			return nil, fmt.Errorf("%s cannot be null here", key)
		case isJSONNull(value):
		default:
			if err := f.check(value); err != nil {
				return nil, err
			}
			if slices.Contains(r.sets, key) {
				sorted, err := sortedSet(value)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", key, err)
				}
				value = sorted
			}
		}
		fields[key] = value
	}
	if _, ok := fields["name"]; creation && !ok {
		return nil, errors.New("name is required")
	}
	if len(fields) == 0 {
		return nil, errors.New("invalid arguments: name at least one field to change")
	}
	return fields, nil
}

// holder is what carries the label that releases an entry: the area
// itself, or nothing for a label.
func (r registry) holder(id string) string {
	if r.kind.Carrier() == CarrierArea {
		return id
	}
	return ""
}

func (r registry) properties() string {
	parts := make([]string, 0, len(r.fields))
	for _, f := range r.fields {
		parts = append(parts, fmt.Sprintf("    %q: %s", f.name, f.schema))
	}
	return strings.Join(parts, ",\n")
}

func (r registry) idSchema() string {
	return fmt.Sprintf(`%q: {"type": "string", "pattern": "^[a-z0-9_]{1,128}$", "description": "The %s's id, as %s_list names it."}`,
		r.idKey, strings.TrimSuffix(r.idKey, "_id"), strings.TrimSuffix(r.idKey, "_id"))
}

func (r registry) list() Tool {
	return Tool{
		Name:        strings.TrimSuffix(r.idKey, "_id") + "_list",
		Title:       "List " + r.plural,
		Description: fmt.Sprintf("Returns the %s of Home Assistant, each with its id and what is stored for it.", r.plural),
		Tier:        R0,
		Endpoints:   []string{"websocket: " + r.command + "/list"},
		InputSchema: json.RawMessage("{\n  \"type\": \"object\",\n  \"properties\": {},\n  \"additionalProperties\": false\n}"),
		Handler: func(ctx context.Context, core Core, args json.RawMessage) (json.RawMessage, error) {
			if given, err := decodeFields(args); err != nil || len(given) != 0 {
				return nil, errors.New("invalid arguments: this tool takes none")
			}
			all, err := r.entries(ctx, core)
			if err != nil {
				return nil, err
			}
			out := make([]map[string]json.RawMessage, 0, len(all))
			for _, id := range slices.Sorted(maps.Keys(all)) {
				entry := maps.Clone(all[id])
				entry[r.idKey], _ = json.Marshal(id)
				out = append(out, entry)
			}
			encoded, err := json.Marshal(map[string]any{r.plural: out})
			if err != nil {
				return nil, fmt.Errorf("encode result: %w", err)
			}
			return encoded, nil
		},
	}
}

func (r registry) create() Tool {
	name := strings.TrimSuffix(r.idKey, "_id")
	endpoints := []string{"websocket: " + r.command + "/create", "websocket: " + r.command + "/list"}
	note := " ha-airlock releases what it created for later changes."
	switch r.kind.Carrier() {
	case CarrierArea:
		endpoints = append(endpoints, "websocket: config/floor_registry/list", "websocket: config/area_registry/update (labels of the new area)")
	case CarrierNone:
		note = " Home Assistant gives the label its id from the name."
	}
	if r.unused != nil {
		endpoints = append(endpoints, "websocket: "+r.command+"/delete (undo only)",
			"websocket: config/entity_registry/list (undo only)", "websocket: config/device_registry/list (undo only)")
	}
	return Tool{
		Name:        name + "_create",
		Title:       "Create " + r.noun,
		Description: "Creates " + r.noun + "." + note + changeNote,
		Tier:        R2,
		Kind:        r.kind,
		Endpoints:   endpoints,
		InputSchema: json.RawMessage(fmt.Sprintf("{\n  \"type\": \"object\",\n  \"properties\": {\n%s\n  },\n"+
			"  \"required\": [\"name\"],\n  \"additionalProperties\": false\n}", r.properties())),
		Plan: func(ctx context.Context, core Core, args json.RawMessage) (Change, error) {
			given, err := decodeFields(args)
			if err != nil {
				return Change{}, err
			}
			fields, err := r.given(given, true)
			if err != nil {
				return Change{}, err
			}
			if r.references != nil {
				if err := r.references(ctx, core, fields); err != nil {
					return Change{}, err
				}
			}
			after, err := json.Marshal(fields)
			if err != nil {
				return Change{}, fmt.Errorf("encode the requested state: %w", err)
			}
			return Change{
				Summary: "Create " + r.noun, After: after, Left: r.left,
				Apply: func(ctx context.Context, core Core) (string, json.RawMessage, error) {
					var created map[string]json.RawMessage
					if err := core.Call(ctx, r.command+"/create", fields, &created); err != nil {
						return "", nil, fmt.Errorf("%s/create: %w", r.command, err)
					}
					var id string
					if err := json.Unmarshal(created[r.idKey], &id); err != nil || id == "" {
						return "", nil, fmt.Errorf("%s/create: the answer names no %s", r.command, r.idKey)
					}
					return id, json.RawMessage(fmt.Sprintf(`{"created":%q}`, id)), nil
				},
			}, nil
		},
		// What was created is taken back by deleting it, and only while
		// nothing refers to it: a deletion takes every assignment with it.
		Revert: func(ctx context.Context, core Core, object string, _, _ json.RawMessage) (Change, error) {
			if r.unused == nil {
				return Change{}, errors.New("a creation of " + r.noun + " is not undone")
			}
			present, name, err := r.read(ctx, core, object)
			if err != nil {
				return Change{}, err
			}
			if err := r.unused(ctx, core, object); err != nil {
				return Change{}, err
			}
			before, err := json.Marshal(present)
			if err != nil {
				return Change{}, fmt.Errorf("encode the present state: %w", err)
			}
			return Change{
				Summary: "Delete " + r.noun + " " + object, Object: object, Name: name, Holder: r.holder(object), Before: before,
				Apply: func(ctx context.Context, core Core) (string, json.RawMessage, error) {
					if err := core.Call(ctx, r.command+"/delete", map[string]string{r.idKey: object}, nil); err != nil {
						return "", nil, fmt.Errorf("%s/delete: %w", r.command, err)
					}
					return object, json.RawMessage(fmt.Sprintf(`{"deleted":%q}`, object)), nil
				},
			}, nil
		},
	}
}

func (r registry) update() Tool {
	name := strings.TrimSuffix(r.idKey, "_id")
	endpoints := []string{"websocket: " + r.command + "/list", "websocket: " + r.command + "/update"}
	release := " The " + name + " must be released by the owner."
	switch r.kind.Carrier() {
	case CarrierArea:
		endpoints = append(endpoints, "websocket: config/floor_registry/list")
	case CarrierNone:
		release = " The label that releases objects for ha-airlock is not changed."
	}
	return Tool{
		Name:  name + "_update",
		Title: "Change " + r.noun,
		Description: "Changes the fields of one " + name + " that are named; the others stay as they are." + release +
			changeNote,
		Tier:      R2,
		Kind:      r.kind,
		Endpoints: endpoints,
		InputSchema: json.RawMessage(fmt.Sprintf("{\n  \"type\": \"object\",\n  \"properties\": {\n    %s,\n%s\n  },\n"+
			"  \"required\": [%q],\n  \"additionalProperties\": false\n}", r.idSchema(), r.properties(), r.idKey)),
		Plan: func(ctx context.Context, core Core, args json.RawMessage) (Change, error) {
			given, err := decodeFields(args)
			if err != nil {
				return Change{}, err
			}
			var id string
			if err := json.Unmarshal(given[r.idKey], &id); err != nil || !registryIDShape.MatchString(id) {
				return Change{}, fmt.Errorf("%s must be an id such as living_room", r.idKey)
			}
			fields, err := r.given(given, false)
			if err != nil {
				return Change{}, err
			}
			if r.references != nil {
				if err := r.references(ctx, core, fields); err != nil {
					return Change{}, err
				}
			}
			return r.planUpdate(ctx, core, id, fields)
		},
		// A change is taken back by writing the fields as they were. They
		// were read from Home Assistant, so they pass unchecked.
		Revert: func(ctx context.Context, core Core, object string, before, _ json.RawMessage) (Change, error) {
			var recorded map[string]json.RawMessage
			if err := json.Unmarshal(before, &recorded); err != nil {
				return Change{}, fmt.Errorf("the recorded state is not an object: %w", err)
			}
			fields := map[string]json.RawMessage{}
			for _, f := range r.fields {
				if value, ok := recorded[f.name]; ok {
					fields[f.name] = value
				}
			}
			return r.planUpdate(ctx, core, object, fields)
		},
	}
}

// planUpdate plans writing the given fields of one entry.
func (r registry) planUpdate(ctx context.Context, core Core, id string, fields map[string]json.RawMessage) (Change, error) {
	present, name, err := r.read(ctx, core, id)
	if err != nil {
		return Change{}, err
	}
	requested := maps.Clone(present)
	maps.Copy(requested, fields)
	before, err := json.Marshal(present)
	if err != nil {
		return Change{}, fmt.Errorf("encode the present state: %w", err)
	}
	after, err := json.Marshal(requested)
	if err != nil {
		return Change{}, fmt.Errorf("encode the requested state: %w", err)
	}
	return Change{
		Summary: "Change " + r.noun + " " + id, Object: id, Name: name, Holder: r.holder(id),
		Before: before, After: after, Left: r.left,
		Apply: func(ctx context.Context, core Core) (string, json.RawMessage, error) {
			message := maps.Clone(fields)
			message[r.idKey], _ = json.Marshal(id)
			if err := core.Call(ctx, r.command+"/update", message, nil); err != nil {
				return "", nil, fmt.Errorf("%s/update: %w", r.command, err)
			}
			return id, json.RawMessage(fmt.Sprintf(`{"changed":%q}`, id)), nil
		},
	}, nil
}

// floorList names the floors, so that an area can be put on one.
func floorList() Tool {
	return Tool{
		Name:        "floor_list",
		Title:       "List floors",
		Description: "Returns the floors of Home Assistant, each with its id, name, level, icon and aliases.",
		Tier:        R0,
		Endpoints:   []string{"websocket: config/floor_registry/list"},
		InputSchema: json.RawMessage("{\n  \"type\": \"object\",\n  \"properties\": {},\n  \"additionalProperties\": false\n}"),
		Handler: func(ctx context.Context, core Core, args json.RawMessage) (json.RawMessage, error) {
			if given, err := decodeFields(args); err != nil || len(given) != 0 {
				return nil, errors.New("invalid arguments: this tool takes none")
			}
			// The fields of homeassistant/components/config/floor_registry.py:158-168.
			var floors []struct {
				ID      string   `json:"floor_id"`
				Name    string   `json:"name"`
				Level   *int     `json:"level"`
				Icon    *string  `json:"icon"`
				Aliases []string `json:"aliases"`
			}
			if err := core.Call(ctx, "config/floor_registry/list", nil, &floors); err != nil {
				return nil, fmt.Errorf("config/floor_registry/list: %w", err)
			}
			for i := range floors {
				slices.Sort(floors[i].Aliases)
			}
			encoded, err := json.Marshal(map[string]any{"floors": floors})
			if err != nil {
				return nil, fmt.Errorf("encode result: %w", err)
			}
			return encoded, nil
		},
	}
}

// entityFields are what entity_update changes of an entity's registry
// entry: name, icon and area, nothing else (ADR 0006). The update command
// takes more (components/config/entity_registry.py:156-196); this server
// sends none of it.
var entityFields = []registryField{
	{name: "name", check: checkName, nullable: true, schema: `{"type": ["string", "null"], "minLength": 1, "maxLength": 100, "description": "The entity's name; null gives it back the name its integration gives it."}`},
	{name: "icon", check: checkIcon, nullable: true, schema: `{"type": ["string", "null"], "pattern": "^[a-z0-9-]{1,32}:[a-z0-9-]{1,64}$", "description": "An icon, for example mdi:lamp; null gives it back its own."}`},
	{name: "area_id", check: checkMatch("area_id", registryIDShape, "of an area id, such as living_room"), nullable: true, schema: `{"type": ["string", "null"], "pattern": "^[a-z0-9_]{1,128}$", "description": "The area, as area_list names it; null makes the entity follow its device's area."}`},
}

// entityState reads the fields entity_update changes from an entity's
// registry entry, and the name Home Assistant shows for it.
func entityState(ctx context.Context, core Core, entity string) (state map[string]json.RawMessage, name string, err error) {
	var entry map[string]json.RawMessage
	if err := core.Call(ctx, "config/entity_registry/get", map[string]string{"entity_id": entity}, &entry); err != nil {
		return nil, "", fmt.Errorf("config/entity_registry/get: %w", err)
	}
	state = map[string]json.RawMessage{}
	for _, f := range entityFields {
		value, ok := entry[f.name]
		if !ok {
			value = json.RawMessage("null")
		}
		state[f.name] = value
	}
	var own, original *string
	_ = json.Unmarshal(entry["name"], &own)
	_ = json.Unmarshal(entry["original_name"], &original)
	switch {
	case own != nil && *own != "":
		name = *own
	case original != nil:
		name = *original
	}
	return state, name, nil
}

func entityUpdate() Tool {
	properties := make([]string, 0, len(entityFields))
	for _, f := range entityFields {
		properties = append(properties, fmt.Sprintf("    %q: %s", f.name, f.schema))
	}
	return Tool{
		Name:  "entity_update",
		Title: "Change an entity's name, icon or area",
		Description: "Changes the name, the icon or the area of one entity in Home Assistant's entity registry; fields " +
			"left out stay as they are. The entity must be released by the owner." + changeNote,
		Tier: R2,
		Kind: KindEntity,
		Endpoints: []string{
			"websocket: config/entity_registry/get", "websocket: config/area_registry/list", "websocket: config/entity_registry/update",
		},
		InputSchema: json.RawMessage(fmt.Sprintf("{\n  \"type\": \"object\",\n  \"properties\": {\n    "+
			`"entity_id": {"type": "string", "pattern": "^[a-z0-9_]{1,64}\\.[a-z0-9_]{1,128}$", "description": "The entity, for example light.kitchen."}`+
			",\n%s\n  },\n  \"required\": [\"entity_id\"],\n  \"additionalProperties\": false\n}", strings.Join(properties, ",\n"))),
		Plan: func(ctx context.Context, core Core, args json.RawMessage) (Change, error) {
			given, err := decodeFields(args)
			if err != nil {
				return Change{}, err
			}
			var entity string
			if err := json.Unmarshal(given["entity_id"], &entity); err != nil || !entityIDShape.MatchString(entity) {
				return Change{}, errors.New("entity_id must be an entity id such as light.kitchen")
			}
			delete(given, "entity_id")
			fields := map[string]json.RawMessage{}
			for key, value := range given {
				i := slices.IndexFunc(entityFields, func(f registryField) bool { return f.name == key })
				if i < 0 {
					return Change{}, fmt.Errorf("invalid arguments: unknown field %q", key)
				}
				// An empty name is a value of its own in Home Assistant
				// (helpers/entity_registry.py:330-336); a client clears
				// the name with null.
				if !isJSONNull(value) {
					if err := entityFields[i].check(value); err != nil {
						return Change{}, err
					}
				}
				fields[key] = value
			}
			if len(fields) == 0 {
				return Change{}, errors.New("invalid arguments: name at least one field to change")
			}
			if err := areaExists(ctx, core, fields["area_id"]); err != nil {
				return Change{}, err
			}
			return planEntityUpdate(ctx, core, entity, fields)
		},
		// A change is taken back by writing the three fields as they were.
		Revert: func(ctx context.Context, core Core, object string, before, _ json.RawMessage) (Change, error) {
			var recorded map[string]json.RawMessage
			if err := json.Unmarshal(before, &recorded); err != nil {
				return Change{}, fmt.Errorf("the recorded state is not an object: %w", err)
			}
			fields := map[string]json.RawMessage{}
			for _, f := range entityFields {
				if value, ok := recorded[f.name]; ok {
					fields[f.name] = value
				}
			}
			return planEntityUpdate(ctx, core, object, fields)
		},
	}
}

// areaExists checks an area id a client gave: Core stores any it is given
// (helpers/entity_registry.py:2085-2132).
func areaExists(ctx context.Context, core Core, value json.RawMessage) error {
	if len(value) == 0 || isJSONNull(value) {
		return nil
	}
	var id string
	_ = json.Unmarshal(value, &id)
	if _, _, err := areaRegistry.read(ctx, core, id); err != nil {
		return err
	}
	return nil
}

func planEntityUpdate(ctx context.Context, core Core, entity string, fields map[string]json.RawMessage) (Change, error) {
	present, name, err := entityState(ctx, core, entity)
	if err != nil {
		return Change{}, err
	}
	requested := maps.Clone(present)
	maps.Copy(requested, fields)
	before, err := json.Marshal(present)
	if err != nil {
		return Change{}, fmt.Errorf("encode the present state: %w", err)
	}
	after, err := json.Marshal(requested)
	if err != nil {
		return Change{}, fmt.Errorf("encode the requested state: %w", err)
	}
	return Change{
		Summary: "Change the entity " + entity, Object: entity, Name: name, Holder: entity, Before: before, After: after,
		Left: func(ctx context.Context, core Core, entity string) (json.RawMessage, error) {
			state, _, err := entityState(ctx, core, entity)
			if err != nil {
				return nil, err
			}
			return json.Marshal(state)
		},
		Apply: func(ctx context.Context, core Core) (string, json.RawMessage, error) {
			message := maps.Clone(fields)
			message["entity_id"], _ = json.Marshal(entity)
			if err := core.Call(ctx, "config/entity_registry/update", message, nil); err != nil {
				return "", nil, fmt.Errorf("config/entity_registry/update: %w", err)
			}
			return entity, json.RawMessage(fmt.Sprintf(`{"changed":%q}`, entity)), nil
		},
	}, nil
}
