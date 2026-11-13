// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package catalog

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Action is what one call of a tool above R0 would do, stated by the server
// from the checked arguments. It is what the owner is shown when a call
// waits for approval; nothing in it is text the client chose freely.
type Action struct {
	// Summary is one sentence built from the tool's own words and from
	// identifiers of a checked shape.
	Summary string
	// Entities are the entities the call acts on. The gate lets the call
	// through only if the owner released every one of them.
	Entities []string
}

// entityService declares one tool that calls one fixed service of one fixed
// domain on one entity of that domain. Domain and service are constants of
// the declaration: the client chooses the entity and nothing else.
func entityService(domain, service, title, verb string) Tool {
	check := func(args json.RawMessage) (string, error) {
		in := struct {
			EntityID string `json:"entity_id"`
		}{}
		if err := decodeArgs(args, &in); err != nil {
			return "", err
		}
		if !entityIDShape.MatchString(in.EntityID) || !strings.HasPrefix(in.EntityID, domain+".") {
			return "", fmt.Errorf("entity_id must be an entity of the domain %s, such as %s.example", domain, domain)
		}
		return in.EntityID, nil
	}
	return Tool{
		Name:  domain + "_" + service,
		Title: title,
		Description: fmt.Sprintf("Calls the service %s.%s on one entity of the domain %s. The entity must be released "+
			"for control by the owner. Depending on the policy the call waits for the owner's approval: it then "+
			"returns without having run, and runs when it is repeated with the same arguments after the approval.",
			domain, service, domain),
		Tier:      R1,
		Endpoints: []string{fmt.Sprintf("websocket: call_service (%s.%s)", domain, service)},
		InputSchema: json.RawMessage(fmt.Sprintf(`{
  "type": "object",
  "properties": {
    "entity_id": {"type": "string", "pattern": "^%s\\.[a-z0-9_]{1,128}$", "description": "The entity, for example %s.example."}
  },
  "required": ["entity_id"],
  "additionalProperties": false
}`, domain, domain)),
		Act: func(args json.RawMessage) (Action, error) {
			entity, err := check(args)
			if err != nil {
				return Action{}, err
			}
			return Action{Summary: verb + " " + entity, Entities: []string{entity}}, nil
		},
		Handler: func(ctx context.Context, core Core, args json.RawMessage) (json.RawMessage, error) {
			entity, err := check(args)
			if err != nil {
				return nil, err
			}
			params := struct {
				Domain  string              `json:"domain"`
				Service string              `json:"service"`
				Target  map[string][]string `json:"target"`
			}{Domain: domain, Service: service, Target: map[string][]string{"entity_id": {entity}}}
			var answer json.RawMessage
			if err := core.Call(ctx, "call_service", params, &answer); err != nil {
				return nil, fmt.Errorf("call_service %s.%s: %w", domain, service, err)
			}
			return json.Marshal(struct {
				Called   string `json:"called"`
				EntityID string `json:"entity_id"`
			}{Called: domain + "." + service, EntityID: entity})
		},
	}
}

// controlTools are the tools of tier R1. Lock, alarm and cover are not
// among them.
func controlTools() []Tool {
	return []Tool{
		entityService("light", "turn_on", "Turn a light on", "Turn on"),
		entityService("light", "turn_off", "Turn a light off", "Turn off"),
		entityService("switch", "turn_on", "Turn a switch on", "Turn on"),
		entityService("switch", "turn_off", "Turn a switch off", "Turn off"),
		entityService("input_boolean", "turn_on", "Turn a toggle helper on", "Turn on"),
		entityService("input_boolean", "turn_off", "Turn a toggle helper off", "Turn off"),
	}
}
