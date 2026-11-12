// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

// Package hacoretest provides a stand-in for Home Assistant Core's
// WebSocket API for the tests of packages that use hacore.
package hacoretest

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/websocket"
)

// Handler returns a WebSocket endpoint that performs Core's auth handshake,
// accepting token only, and then answers each command with the canned JSON
// result stored under its type. A command without a canned result gets
// Core's unknown_command error.
func Handler(token string, results map[string]string) http.Handler {
	upgrader := websocket.Upgrader{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = ws.Close() }()
		serve(ws, token, results)
	})
}

func serve(ws *websocket.Conn, token string, results map[string]string) {
	if err := ws.WriteJSON(map[string]string{"type": "auth_required", "ha_version": "test"}); err != nil {
		return
	}
	var auth struct {
		Type        string `json:"type"`
		AccessToken string `json:"access_token"`
	}
	if err := ws.ReadJSON(&auth); err != nil {
		return
	}
	if auth.Type != "auth" || auth.AccessToken != token {
		_ = ws.WriteJSON(map[string]string{"type": "auth_invalid", "message": "Invalid access token or password"})
		return
	}
	if err := ws.WriteJSON(map[string]string{"type": "auth_ok", "ha_version": "test"}); err != nil {
		return
	}
	for {
		var cmd struct {
			ID   uint64 `json:"id"`
			Type string `json:"type"`
		}
		if err := ws.ReadJSON(&cmd); err != nil {
			return
		}
		reply := answer{ID: cmd.ID, Type: "result"}
		if result, ok := results[cmd.Type]; ok {
			reply.Success = true
			reply.Result = json.RawMessage(result)
		} else {
			reply.Error = &answerError{Code: "unknown_command", Message: "Unknown command."}
		}
		if err := ws.WriteJSON(reply); err != nil {
			return
		}
	}
}

// answer is Core's reply to a command.
type answer struct {
	ID      uint64          `json:"id"`
	Type    string          `json:"type"`
	Success bool            `json:"success"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *answerError    `json:"error,omitempty"`
}

type answerError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
