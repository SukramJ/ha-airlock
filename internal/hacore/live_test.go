// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package hacore_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/SukramJ/ha-airlock/internal/hacore"
)

// TestLiveCurrentUser runs the client against a real Home Assistant. It only
// reads. It is skipped unless HA_AIRLOCK_LIVE_URL names the WebSocket URL
// (ws://host:port/api/websocket) and HA_AIRLOCK_LIVE_TOKEN_FILE a file
// holding a token.
func TestLiveCurrentUser(t *testing.T) {
	url, tokenFile := os.Getenv("HA_AIRLOCK_LIVE_URL"), os.Getenv("HA_AIRLOCK_LIVE_TOKEN_FILE")
	if url == "" || tokenFile == "" {
		t.Skip("HA_AIRLOCK_LIVE_URL and HA_AIRLOCK_LIVE_TOKEN_FILE are not set")
	}
	token, err := os.ReadFile(tokenFile) //nolint:gosec // the path is the developer's own setting
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := hacore.Dial(ctx, url, strings.TrimSpace(string(token)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	var user struct {
		Name    string `json:"name"`
		IsAdmin bool   `json:"is_admin"`
	}
	if err := conn.Call(ctx, "auth/current_user", nil, &user); err != nil {
		t.Fatalf("auth/current_user: %v", err)
	}
	if user.Name == "" {
		t.Fatal("Core returned a user without a name")
	}
	t.Logf("connected as %q, admin %t", user.Name, user.IsAdmin)

	// A second command on the same connection, with a large answer.
	var states []struct {
		EntityID string `json:"entity_id"`
	}
	if err := conn.Call(ctx, "get_states", nil, &states); err != nil {
		t.Fatalf("get_states: %v", err)
	}
	t.Logf("get_states returned %d states", len(states))

	// Core's own error path: a command that does not exist.
	if err := conn.Call(ctx, "ha_airlock/no_such_command", nil, nil); err == nil {
		t.Fatal("an unknown command was answered with success")
	} else {
		t.Logf("unknown command: %v", err)
	}
}
