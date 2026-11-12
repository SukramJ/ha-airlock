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

// Responder answers one command. raw is the whole command message. It
// returns the JSON result, or an error code to make the command fail.
type Responder func(commandType string, raw json.RawMessage) (result, errorCode string)

// Handler returns a WebSocket endpoint that performs Core's auth handshake,
// accepting token only, and then answers each command with the canned JSON
// result stored under its type. A command without a canned result gets
// Core's unknown_command error.
func Handler(token string, results map[string]string) http.Handler {
	return HandlerFunc(token, func(commandType string, _ json.RawMessage) (string, string) {
		if result, ok := results[commandType]; ok {
			return result, ""
		}
		return "", "unknown_command"
	})
}

// HandlerFunc is Handler with the answers computed by respond.
func HandlerFunc(token string, respond Responder) http.Handler {
	upgrader := websocket.Upgrader{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = ws.Close() }()
		serve(ws, token, respond)
	})
}

func serve(ws *websocket.Conn, token string, respond Responder) {
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
		_, raw, err := ws.ReadMessage()
		if err != nil {
			return
		}
		var cmd struct {
			ID   uint64 `json:"id"`
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &cmd); err != nil {
			return
		}
		reply := answer{ID: cmd.ID, Type: "result"}
		if result, code := respond(cmd.Type, raw); code == "" {
			reply.Success = true
			reply.Result = json.RawMessage(result)
		} else {
			reply.Error = &answerError{Code: code, Message: code}
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
