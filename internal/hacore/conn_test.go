// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package hacore_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/SukramJ/ha-airlock/internal/hacore"
)

const goodToken = "token-for-test"

// command is what the fake Core received after the handshake.
type command struct {
	ID   uint64 `json:"id"`
	Type string `json:"type"`
	Name string `json:"name"`
}

// fakeCore speaks Core's handshake and then hands every command to answer.
type fakeCore struct {
	server *httptest.Server
	mu     sync.Mutex
	seen   []command
	header http.Header
}

// newFakeCore starts a server. answer writes the reply to one command and
// returns false to stop serving the connection.
func newFakeCore(t *testing.T, answer func(ws *websocket.Conn, cmd command) bool) *fakeCore {
	t.Helper()
	f := &fakeCore{}
	upgrader := websocket.Upgrader{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.header = r.Header.Clone()
		f.mu.Unlock()
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = ws.Close() }()
		_ = ws.WriteJSON(map[string]string{"type": "auth_required", "ha_version": "test"})
		var auth struct {
			Type        string `json:"type"`
			AccessToken string `json:"access_token"`
		}
		if err := ws.ReadJSON(&auth); err != nil {
			return
		}
		if auth.Type != "auth" || auth.AccessToken != goodToken {
			_ = ws.WriteJSON(map[string]string{"type": "auth_invalid", "message": "Invalid access token or password"})
			return
		}
		_ = ws.WriteJSON(map[string]string{"type": "auth_ok", "ha_version": "test"})
		for {
			var cmd command
			if err := ws.ReadJSON(&cmd); err != nil {
				return
			}
			f.mu.Lock()
			f.seen = append(f.seen, cmd)
			f.mu.Unlock()
			if !answer(ws, cmd) {
				return
			}
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeCore) url() string {
	return "ws" + strings.TrimPrefix(f.server.URL, "http")
}

func result(ws *websocket.Conn, id uint64, value string) {
	_ = ws.WriteMessage(websocket.TextMessage,
		[]byte(`{"id":`+jsonNumber(id)+`,"type":"result","success":true,"result":`+value+`}`))
}

func jsonNumber(n uint64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func dial(t *testing.T, f *fakeCore, token string) (*hacore.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	conn, err := hacore.Dial(ctx, f.url(), token)
	if err == nil {
		t.Cleanup(func() { _ = conn.Close() })
	}
	return conn, err
}

func TestCallReturnsTheResultOfItsCommand(t *testing.T) {
	t.Parallel()
	f := newFakeCore(t, func(ws *websocket.Conn, cmd command) bool {
		result(ws, cmd.ID, `{"name":"`+cmd.Name+`","is_admin":true}`)
		return true
	})
	conn, err := dial(t, f, goodToken)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	var got struct {
		Name    string `json:"name"`
		IsAdmin bool   `json:"is_admin"`
	}
	err = conn.Call(context.Background(), "auth/current_user", map[string]string{"name": "echo"}, &got)
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if got.Name != "echo" || !got.IsAdmin {
		t.Fatalf("result = %+v", got)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.seen) != 1 || f.seen[0].Type != "auth/current_user" {
		t.Fatalf("fake core saw %+v", f.seen)
	}
}

func TestDialSendsTheTokenInTheAuthMessageOnly(t *testing.T) {
	t.Parallel()
	f := newFakeCore(t, func(*websocket.Conn, command) bool { return true })
	if _, err := dial(t, f, goodToken); err != nil {
		t.Fatalf("dial: %v", err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	for name, values := range f.header {
		for _, v := range values {
			if strings.Contains(v, goodToken) {
				t.Fatalf("header %s carries the token", name)
			}
		}
	}
}

func TestDialReportsARefusedCredentialWithoutRepeatingIt(t *testing.T) {
	t.Parallel()
	f := newFakeCore(t, func(*websocket.Conn, command) bool { return true })
	const wrong = "wrong-token-value"

	_, err := dial(t, f, wrong)

	if !errors.Is(err, hacore.ErrAuthInvalid) {
		t.Fatalf("dial error = %v, want ErrAuthInvalid", err)
	}
	if strings.Contains(err.Error(), wrong) {
		t.Fatal("the error repeats the credential")
	}
}

// Core sends events and results of other commands on the same connection.
func TestCallSkipsMessagesThatAreNotItsResult(t *testing.T) {
	t.Parallel()
	f := newFakeCore(t, func(ws *websocket.Conn, cmd command) bool {
		_ = ws.WriteMessage(websocket.TextMessage, []byte(`{"id":`+jsonNumber(cmd.ID)+`,"type":"event","event":{"x":1}}`))
		result(ws, cmd.ID+1000, `"result of another command"`)
		result(ws, cmd.ID, `"mine"`)
		return true
	})
	conn, err := dial(t, f, goodToken)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	var got string
	if err := conn.Call(context.Background(), "ping", nil, &got); err != nil {
		t.Fatalf("call: %v", err)
	}
	if got != "mine" {
		t.Fatalf("result = %q, want %q", got, "mine")
	}
}

func TestCallReturnsTheErrorCoreGave(t *testing.T) {
	t.Parallel()
	f := newFakeCore(t, func(ws *websocket.Conn, cmd command) bool {
		_ = ws.WriteMessage(websocket.TextMessage, []byte(`{"id":`+jsonNumber(cmd.ID)+
			`,"type":"result","success":false,"error":{"code":"unauthorized","message":"Unauthorized"}}`))
		return true
	})
	conn, err := dial(t, f, goodToken)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	err = conn.Call(context.Background(), "config/auth/list", nil, nil)

	var cmdErr *hacore.CommandError
	if !errors.As(err, &cmdErr) {
		t.Fatalf("call error = %v, want a CommandError", err)
	}
	if cmdErr.Code != "unauthorized" {
		t.Fatalf("code = %q, want %q", cmdErr.Code, "unauthorized")
	}
}

func TestCallUsesIncreasingIdentifiers(t *testing.T) {
	t.Parallel()
	f := newFakeCore(t, func(ws *websocket.Conn, cmd command) bool {
		result(ws, cmd.ID, `null`)
		return true
	})
	conn, err := dial(t, f, goodToken)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	for range 3 {
		if err := conn.Call(context.Background(), "ping", nil, nil); err != nil {
			t.Fatalf("call: %v", err)
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.seen) != 3 || f.seen[0].ID != 1 || f.seen[1].ID != 2 || f.seen[2].ID != 3 {
		t.Fatalf("identifiers seen: %+v", f.seen)
	}
}

func TestCallEndsWhenItsContextEnds(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f := newFakeCore(t, func(*websocket.Conn, command) bool {
		<-release // never answers while the test runs
		return false
	})
	conn, err := dial(t, f, goodToken)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)

	done := make(chan error, 1)
	go func() { done <- conn.Call(ctx, "ping", nil, nil) }()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("call error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("call did not return after its context was cancelled")
	}
}

func TestCallRejectsParametersThatAreNotAnObject(t *testing.T) {
	t.Parallel()
	f := newFakeCore(t, func(*websocket.Conn, command) bool { return true })
	conn, err := dial(t, f, goodToken)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	if err := conn.Call(context.Background(), "ping", []int{1, 2}, nil); err == nil {
		t.Fatal("call accepted parameters that are not a JSON object")
	}
}
