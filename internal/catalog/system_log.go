// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package catalog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	systemLogDefaultLimit = 50
	systemLogMaxLimit     = 200
)

// systemLogList reads the errors and warnings Core has collected.
func systemLogList() Tool {
	return Tool{
		Name:  "system_log_list",
		Title: "List system log entries",
		Description: "Returns the errors and warnings Home Assistant Core has collected since it started, " +
			"newest first: logger name, message, level, source, count and timestamps.",
		Tier:      R0,
		Endpoints: []string{"websocket: system_log/list"},
		InputSchema: json.RawMessage(`{
  "type": "object",
  "properties": {
    "limit": {"type": "integer", "minimum": 1, "maximum": 200, "description": "How many entries to return. Default 50."}
  },
  "additionalProperties": false
}`),
		Handler: runSystemLogList,
	}
}

func runSystemLogList(ctx context.Context, core Core, args json.RawMessage) (json.RawMessage, error) {
	params := struct {
		Limit *int `json:"limit"`
	}{}
	if err := decodeArgs(args, &params); err != nil {
		return nil, err
	}
	limit := systemLogDefaultLimit
	if params.Limit != nil {
		limit = *params.Limit
	}
	if limit < 1 || limit > systemLogMaxLimit {
		return nil, fmt.Errorf("limit must be between 1 and %d", systemLogMaxLimit)
	}

	var entries []json.RawMessage
	if err := core.Call(ctx, "system_log/list", nil, &entries); err != nil {
		return nil, fmt.Errorf("system_log/list: %w", err)
	}
	if len(entries) > limit {
		entries = entries[:limit]
	}
	out, err := json.Marshal(struct {
		Entries []json.RawMessage `json:"entries"`
	}{Entries: entries})
	if err != nil {
		return nil, fmt.Errorf("encode result: %w", err)
	}
	return out, nil
}

// decodeArgs decodes a tool's arguments strictly: an unknown field is an
// error, not something to ignore. Absent arguments are an empty object.
func decodeArgs(args json.RawMessage, into any) error { //nolint:revive // into is the tool's own argument struct: any is the encoding/json contract
	if len(bytes.TrimSpace(args)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(args))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("invalid arguments: %w", err)
	}
	if dec.More() {
		return errors.New("invalid arguments: more than one JSON value")
	}
	return nil
}
