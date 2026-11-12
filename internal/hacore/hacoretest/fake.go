// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

// Package hacoretest provides a stand-in for Home Assistant Core's
// WebSocket API for the tests of packages that use hacore.
package hacoretest

import (
	"encoding/json"
	"fmt"
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
		id, err := json.Marshal(cmd.ID)
		if err != nil {
			return
		}
		reply := fmt.Sprintf(`{"id":%s,"type":"result","success":false,"error":{"code":"unknown_command","message":"Unknown command."}}`, id)
		if result, ok := results[cmd.Type]; ok {
			reply = fmt.Sprintf(`{"id":%s,"type":"result","success":true,"result":%s}`, id, result)
		}
		if err := ws.WriteMessage(websocket.TextMessage, []byte(reply)); err != nil {
			return
		}
	}
}
