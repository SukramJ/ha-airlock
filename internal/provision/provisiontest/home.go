// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

// Package provisiontest provides a stand-in for the Home Assistant that
// provisioning talks to, for the tests of provisioning and of its wiring.
package provisiontest

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/SukramJ/ha-airlock/internal/hacore/hacoretest"
)

// The values the stand-in accepts and issues.
const (
	SupervisorToken = "supervisor-token-for-test"
	RefreshToken    = "refresh-token-for-test"
	AccessToken     = "access-token-for-test"
	NewUserID       = "user-id-created-by-test"
)

// Home is a stand-in for one Home Assistant: the Supervisor, with its Core
// info and its proxy to Core, and Core's own auth endpoints and WebSocket,
// sharing one set of users.
type Home struct {
	// Supervisor serves /core/info and the proxy's /core/websocket.
	Supervisor *httptest.Server
	Core       *httptest.Server

	Mu            sync.Mutex
	ExistingUsers []string // usernames present before provisioning
	Passwords     map[string]string
	Created       []string
	Deleted       []string
	ProxyCommands []string
	Services      []string
	LoginFails    bool
	RefreshStatus int
}

// NewHome starts the stand-in; it stops with the test.
func NewHome(t *testing.T) *Home {
	t.Helper()
	h := &Home{Passwords: map[string]string{}, RefreshStatus: http.StatusOK}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/login_flow", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"type":"form","flow_id":"flow-1","step_id":"init"}`)
	})
	mux.HandleFunc("POST /auth/login_flow/flow-1", h.submitLogin)
	mux.HandleFunc("POST /auth/token", h.token)
	mux.Handle("/api/websocket", hacoretest.HandlerFunc(AccessToken, h.coreCommand))
	h.Core = httptest.NewServer(mux)
	t.Cleanup(h.Core.Close)

	_, corePort, err := net.SplitHostPort(h.Core.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split core address: %v", err)
	}
	sup := http.NewServeMux()
	sup.HandleFunc("GET /core/info", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+SupervisorToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"result":"ok","data":{"port":`+corePort+`,"ssl":false}}`)
	})
	sup.Handle("/core/websocket", hacoretest.HandlerFunc(SupervisorToken, h.proxyCommand))
	h.Supervisor = httptest.NewServer(sup)
	t.Cleanup(h.Supervisor.Close)
	return h
}

func (h *Home) proxyCommand(commandType string, raw json.RawMessage) (result, errorCode string) {
	h.Mu.Lock()
	defer h.Mu.Unlock()
	h.ProxyCommands = append(h.ProxyCommands, commandType)
	var cmd struct {
		UserID   string `json:"user_id"`
		Username string `json:"username"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}
	_ = json.Unmarshal(raw, &cmd)
	switch commandType {
	case "config/auth/list":
		users := make([]map[string]string, 0, 1+len(h.ExistingUsers))
		users = append(users, map[string]string{"username": "someone-else"})
		for _, name := range h.ExistingUsers {
			users = append(users, map[string]string{"username": name})
		}
		out, _ := json.Marshal(users)
		return string(out), ""
	case "config/auth/create":
		h.Created = append(h.Created, cmd.Name)
		return `{"user":{"id":"` + NewUserID + `"}}`, ""
	case "config/auth_provider/homeassistant/create":
		h.Passwords[cmd.Username] = cmd.Password
		return `null`, ""
	case "config/auth/delete":
		h.Deleted = append(h.Deleted, cmd.UserID)
		return `null`, ""
	default:
		return "", "unknown_command"
	}
}

func (h *Home) submitLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	h.Mu.Lock()
	want, known := h.Passwords[body.Username]
	fails := h.LoginFails
	h.Mu.Unlock()
	if fails || !known || want != body.Password {
		_, _ = io.WriteString(w, `{"type":"form","flow_id":"flow-1","errors":{"base":"invalid_auth"}}`)
		return
	}
	_, _ = io.WriteString(w, `{"type":"create_entry","flow_id":"flow-1","result":"code-1"}`)
}

func (h *Home) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	h.Mu.Lock()
	refreshStatus := h.RefreshStatus
	h.Mu.Unlock()
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		if r.PostForm.Get("code") != "code-1" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, `{"access_token":"`+AccessToken+`","refresh_token":"`+RefreshToken+`"}`)
	case "refresh_token":
		if refreshStatus != http.StatusOK || r.PostForm.Get("refresh_token") != RefreshToken {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, `{"access_token":"`+AccessToken+`"}`)
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (h *Home) coreCommand(commandType string, raw json.RawMessage) (result, errorCode string) {
	if commandType != "call_service" {
		return "", "unknown_command"
	}
	var cmd struct {
		Domain  string `json:"domain"`
		Service string `json:"service"`
	}
	_ = json.Unmarshal(raw, &cmd)
	h.Mu.Lock()
	h.Services = append(h.Services, cmd.Domain+"."+cmd.Service)
	h.Mu.Unlock()
	return `null`, ""
}

// ProxyURL is the WebSocket URL of the stand-in's proxy to Core.
func (h *Home) ProxyURL() string {
	return "ws" + strings.TrimPrefix(h.Supervisor.URL, "http") + "/core/websocket"
}
