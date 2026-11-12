// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Shapes of the identifiers tools accept. An argument is checked against
// its shape before it is put into a command: a tool passes on values of a
// known kind, never text of the client's choosing.
var (
	domainShape   = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	itemIDShape   = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)
	entityIDShape = regexp.MustCompile(`^[a-z0-9_]{1,64}\.[a-z0-9_]{1,128}$`)
)

// repairsListIssues reads what Home Assistant asks the owner to repair.
func repairsListIssues() Tool {
	return Tool{
		Name:  "repairs_list_issues",
		Title: "List repair issues",
		Description: "Returns the issues Home Assistant's Repairs dashboard lists: the integration, severity, " +
			"whether the issue is fixable or ignored, and the version in which it breaks.",
		Tier:        R0,
		Endpoints:   []string{"websocket: repairs/list_issues"},
		InputSchema: json.RawMessage(`{"type": "object", "properties": {}, "additionalProperties": false}`),
		Handler: func(ctx context.Context, core Core, args json.RawMessage) (json.RawMessage, error) {
			if err := decodeArgs(args, &struct{}{}); err != nil {
				return nil, err
			}
			return passThrough(ctx, core, "repairs/list_issues", nil)
		},
	}
}

// configEntriesList reads which integrations are set up and in what state.
func configEntriesList() Tool {
	return Tool{
		Name:  "config_entries_list",
		Title: "List integrations",
		Description: "Returns the configured integrations (config entries) with their state, for example loaded, " +
			"setup_error or setup_retry, and the reason of a failure. Optionally for one integration domain.",
		Tier:      R0,
		Endpoints: []string{"websocket: config_entries/get"},
		InputSchema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "domain": {"type": "string", "pattern": "^[a-z0-9_]{1,64}$", "description": "Integration domain, for example mqtt. All integrations if left out."}
  },
  "additionalProperties": false
}`),
		Handler: func(ctx context.Context, core Core, args json.RawMessage) (json.RawMessage, error) {
			in := struct {
				Domain *string `json:"domain"`
			}{}
			if err := decodeArgs(args, &in); err != nil {
				return nil, err
			}
			var params map[string]string
			if in.Domain != nil {
				if !domainShape.MatchString(*in.Domain) {
					return nil, errors.New("domain must be an integration domain such as mqtt")
				}
				params = map[string]string{"domain": *in.Domain}
			}
			return passThrough(ctx, core, "config_entries/get", params)
		},
	}
}

// traceList reads the summaries of automation or script runs.
func traceList() Tool {
	return Tool{
		Name:  "trace_list",
		Title: "List automation and script traces",
		Description: "Returns summaries of the stored runs of automations or scripts: when a run started and " +
			"finished, how it ended, and its error if it failed. Optionally for one automation or script.",
		Tier:      R0,
		Endpoints: []string{"websocket: trace/list"},
		InputSchema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "domain": {"type": "string", "enum": ["automation", "script"]},
    "item_id": {"type": "string", "pattern": "^[A-Za-z0-9_]{1,128}$", "description": "The id of one automation or script. All of the domain if left out."}
  },
  "required": ["domain"],
  "additionalProperties": false
}`),
		Handler: func(ctx context.Context, core Core, args json.RawMessage) (json.RawMessage, error) {
			in := struct {
				Domain string  `json:"domain"`
				ItemID *string `json:"item_id"`
			}{}
			if err := decodeArgs(args, &in); err != nil {
				return nil, err
			}
			if in.Domain != "automation" && in.Domain != "script" {
				return nil, errors.New("domain must be automation or script")
			}
			params := map[string]string{"domain": in.Domain}
			if in.ItemID != nil {
				if !itemIDShape.MatchString(*in.ItemID) {
					return nil, errors.New("item_id must be the id of an automation or script")
				}
				params["item_id"] = *in.ItemID
			}
			return passThrough(ctx, core, "trace/list", params)
		},
	}
}

const (
	logbookDefaultLimit = 100
	logbookMaxLimit     = 500
	logbookMaxEntities  = 20
)

// logbookEvents reads what happened in a period of time.
func logbookEvents() Tool {
	return Tool{
		Name:  "logbook_events",
		Title: "Read the logbook",
		Description: "Returns logbook entries of a period of time, oldest first: state changes, automation runs " +
			"and service calls, with the entity, the time and what caused them. Optionally for certain entities.",
		Tier:      R0,
		Endpoints: []string{"websocket: logbook/get_events"},
		InputSchema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "start_time": {"type": "string", "format": "date-time", "description": "Start of the period, RFC 3339, for example 2026-11-12T08:00:00Z."},
    "end_time": {"type": "string", "format": "date-time", "description": "End of the period. Now if left out."},
    "entity_ids": {"type": "array", "items": {"type": "string"}, "maxItems": 20},
    "limit": {"type": "integer", "minimum": 1, "maximum": 500, "description": "How many entries to return. Default 100."}
  },
  "required": ["start_time"],
  "additionalProperties": false
}`),
		Handler: runLogbookEvents,
	}
}

func runLogbookEvents(ctx context.Context, core Core, args json.RawMessage) (json.RawMessage, error) {
	in := struct {
		StartTime string   `json:"start_time"`
		EndTime   *string  `json:"end_time"`
		EntityIDs []string `json:"entity_ids"`
		Limit     *int     `json:"limit"`
	}{}
	if err := decodeArgs(args, &in); err != nil {
		return nil, err
	}
	start, err := time.Parse(time.RFC3339, in.StartTime)
	if err != nil {
		return nil, errors.New("start_time must be a time such as 2026-11-12T08:00:00Z")
	}
	// params holds strings and one list of strings: a JSON object of mixed
	// values, which is what any is for here.
	params := map[string]any{"start_time": start.Format(time.RFC3339)}
	if in.EndTime != nil {
		end, err := time.Parse(time.RFC3339, *in.EndTime)
		if err != nil || !end.After(start) {
			return nil, errors.New("end_time must be a time after start_time")
		}
		params["end_time"] = end.Format(time.RFC3339)
	}
	if len(in.EntityIDs) > logbookMaxEntities {
		return nil, fmt.Errorf("at most %d entity_ids", logbookMaxEntities)
	}
	for _, id := range in.EntityIDs {
		if !entityIDShape.MatchString(id) {
			return nil, errors.New("entity_ids must be entity ids such as light.kitchen")
		}
	}
	if len(in.EntityIDs) > 0 {
		params["entity_ids"] = in.EntityIDs
	}
	limit := logbookDefaultLimit
	if in.Limit != nil {
		limit = *in.Limit
	}
	if limit < 1 || limit > logbookMaxLimit {
		return nil, fmt.Errorf("limit must be between 1 and %d", logbookMaxLimit)
	}

	var events []json.RawMessage
	if err := core.Call(ctx, "logbook/get_events", params, &events); err != nil {
		return nil, fmt.Errorf("logbook/get_events: %w", err)
	}
	truncated := len(events) > limit
	if truncated {
		events = events[:limit]
	}
	out, err := json.Marshal(struct {
		Events    []json.RawMessage `json:"events"`
		Truncated bool              `json:"truncated"`
	}{Events: events, Truncated: truncated})
	if err != nil {
		return nil, fmt.Errorf("encode result: %w", err)
	}
	return out, nil
}

// passThrough sends one fixed command and returns Core's result as it is.
func passThrough(ctx context.Context, core Core, command string, params any) (json.RawMessage, error) { //nolint:revive // params is the command's JSON object: any is the encoding/json contract
	var result json.RawMessage
	if err := core.Call(ctx, command, params, &result); err != nil {
		return nil, fmt.Errorf("%s: %w", command, err)
	}
	if len(result) == 0 {
		return json.RawMessage(`null`), nil
	}
	return result, nil
}
