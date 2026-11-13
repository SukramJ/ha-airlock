// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Bounds of the entity tools. Home Assistant answers both commands with
// everything it has; the tools return a part the client asked for.
const (
	entitiesDefaultLimit = 200
	entitiesMaxLimit     = 1000
	statesMaxEntities    = 50
)

// labelIDShape is the shape of a label id.
var labelIDShape = domainShape

// entitiesList reads which entities exist, and which labels they carry.
func entitiesList() Tool {
	return Tool{
		Name:  "entities_list",
		Title: "List entities",
		Description: "Returns entities from Home Assistant's entity registry: id, name, area, labels, integration, and " +
			"whether the entity is disabled or hidden. Optionally only one domain, or only entities carrying one label. " +
			"The owner releases an entity for control with a label; the labels show which entities that are.",
		Tier:      R0,
		Endpoints: []string{"websocket: config/entity_registry/list"},
		InputSchema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "domain": {"type": "string", "pattern": "^[a-z0-9_]{1,64}$", "description": "Entity domain, for example light. All domains if left out."},
    "label": {"type": "string", "pattern": "^[a-z0-9_]{1,64}$", "description": "Label id. Only entities carrying this label."},
    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "description": "Most entities to return. 200 if left out."}
  },
  "additionalProperties": false
}`),
		Handler: runEntitiesList,
	}
}

func runEntitiesList(ctx context.Context, core Core, args json.RawMessage) (json.RawMessage, error) {
	in := struct {
		Domain *string `json:"domain"`
		Label  *string `json:"label"`
		Limit  *int    `json:"limit"`
	}{}
	if err := decodeArgs(args, &in); err != nil {
		return nil, err
	}
	if in.Domain != nil && !domainShape.MatchString(*in.Domain) {
		return nil, errors.New("domain must be an entity domain such as light")
	}
	if in.Label != nil && !labelIDShape.MatchString(*in.Label) {
		return nil, errors.New("label must be a label id of lower-case letters, digits and underscores")
	}
	limit := entitiesDefaultLimit
	if in.Limit != nil {
		limit = *in.Limit
	}
	if limit < 1 || limit > entitiesMaxLimit {
		return nil, fmt.Errorf("limit must be between 1 and %d", entitiesMaxLimit)
	}

	var registry []struct {
		EntityID     string   `json:"entity_id"`
		Name         *string  `json:"name"`
		OriginalName *string  `json:"original_name"`
		AreaID       *string  `json:"area_id"`
		Labels       []string `json:"labels"`
		Platform     string   `json:"platform"`
		DisabledBy   *string  `json:"disabled_by"`
		HiddenBy     *string  `json:"hidden_by"`
	}
	if err := core.Call(ctx, "config/entity_registry/list", nil, &registry); err != nil {
		return nil, fmt.Errorf("config/entity_registry/list: %w", err)
	}
	type entity struct {
		EntityID string   `json:"entity_id"`
		Name     string   `json:"name,omitempty"`
		AreaID   string   `json:"area_id,omitempty"`
		Labels   []string `json:"labels"`
		Platform string   `json:"platform,omitempty"`
		Disabled bool     `json:"disabled,omitempty"`
		Hidden   bool     `json:"hidden,omitempty"`
	}
	entities := []entity{}
	truncated := false
	for i := range registry {
		r := &registry[i]
		if in.Domain != nil && !strings.HasPrefix(r.EntityID, *in.Domain+".") {
			continue
		}
		if in.Label != nil && !contains(r.Labels, *in.Label) {
			continue
		}
		if len(entities) == limit {
			truncated = true
			break
		}
		e := entity{EntityID: r.EntityID, Labels: r.Labels, Platform: r.Platform, Disabled: r.DisabledBy != nil, Hidden: r.HiddenBy != nil}
		if e.Labels == nil {
			e.Labels = []string{}
		}
		switch {
		case r.Name != nil && *r.Name != "":
			e.Name = *r.Name
		case r.OriginalName != nil:
			e.Name = *r.OriginalName
		}
		if r.AreaID != nil {
			e.AreaID = *r.AreaID
		}
		entities = append(entities, e)
	}
	out, err := json.Marshal(struct {
		Entities  []entity `json:"entities"`
		Truncated bool     `json:"truncated"`
	}{Entities: entities, Truncated: truncated})
	if err != nil {
		return nil, fmt.Errorf("encode result: %w", err)
	}
	return out, nil
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// statesGet reads the current state of named entities.
func statesGet() Tool {
	return Tool{
		Name:  "states_get",
		Title: "Read entity states",
		Description: "Returns the current state and attributes of up to 50 named entities, with the time of the last " +
			"change. Entities that have no state are listed as missing.",
		Tier:      R0,
		Endpoints: []string{"websocket: get_states"},
		InputSchema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "entity_ids": {"type": "array", "minItems": 1, "maxItems": 50, "items": {"type": "string", "pattern": "^[a-z0-9_]{1,64}\\.[a-z0-9_]{1,128}$"}, "description": "The entities, for example [\"light.kitchen\"]."}
  },
  "required": ["entity_ids"],
  "additionalProperties": false
}`),
		Handler: runStatesGet,
	}
}

func runStatesGet(ctx context.Context, core Core, args json.RawMessage) (json.RawMessage, error) {
	in := struct {
		EntityIDs []string `json:"entity_ids"`
	}{}
	if err := decodeArgs(args, &in); err != nil {
		return nil, err
	}
	if len(in.EntityIDs) < 1 || len(in.EntityIDs) > statesMaxEntities {
		return nil, fmt.Errorf("entity_ids must name between 1 and %d entities", statesMaxEntities)
	}
	wanted := make(map[string]bool, len(in.EntityIDs))
	for _, id := range in.EntityIDs {
		if !entityIDShape.MatchString(id) {
			return nil, errors.New("entity_ids must be entity ids such as light.kitchen")
		}
		wanted[id] = true
	}

	// Home Assistant has no command for the state of one entity over this
	// connection; it sends all states, and the tool keeps the ones asked
	// for. What identifies who caused a state — its context — is left out.
	type state struct {
		EntityID    string          `json:"entity_id"`
		State       string          `json:"state"`
		Attributes  json.RawMessage `json:"attributes"`
		LastChanged string          `json:"last_changed"`
		LastUpdated string          `json:"last_updated"`
	}
	var all []state
	if err := core.Call(ctx, "get_states", nil, &all); err != nil {
		return nil, fmt.Errorf("get_states: %w", err)
	}
	found := []state{}
	for i := range all {
		if wanted[all[i].EntityID] {
			found = append(found, all[i])
			delete(wanted, all[i].EntityID)
		}
	}
	missing := []string{}
	for _, id := range in.EntityIDs {
		if wanted[id] {
			missing = append(missing, id)
			delete(wanted, id)
		}
	}
	out, err := json.Marshal(struct {
		States  []state  `json:"states"`
		Missing []string `json:"missing"`
	}{States: found, Missing: missing})
	if err != nil {
		return nil, fmt.Errorf("encode result: %w", err)
	}
	return out, nil
}
