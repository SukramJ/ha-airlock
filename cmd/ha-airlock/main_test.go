// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunWithoutArgumentsPrintsTheVersion(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer

	code := run(context.Background(), nil, environment{}, &out)

	if code != exitOK {
		t.Fatalf("exit code = %d, want %d", code, exitOK)
	}
	if !strings.HasPrefix(out.String(), "ha-airlock ") {
		t.Fatalf("output = %q, want the version line", out.String())
	}
}

func TestRunRejectsAnUnknownCommand(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer

	if code := run(context.Background(), []string{"nonsense"}, environment{}, &out); code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}
}

func TestProbeRefusesToRunWithoutASupervisorToken(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer

	if code := run(context.Background(), []string{"probe"}, environment{}, &out); code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}
}

// The probe command, built the way main builds it, reaches a Supervisor and
// a Core and reports success, and its log never contains the token.
func TestProbeCommandRunsEveryCheckAndKeepsTheTokenOutOfTheLog(t *testing.T) {
	t.Parallel()
	const token = "token-that-must-not-be-logged"

	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(core.Close)
	_, corePort, err := net.SplitHostPort(core.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split core address: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/core/info", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"result":"ok","data":{"port":`+corePort+`,"ssl":false}}`)
	})
	mux.HandleFunc("/core/api/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	})
	supervisor := httptest.NewServer(mux)
	t.Cleanup(supervisor.Close)

	var out bytes.Buffer
	env := environment{supervisorURL: supervisor.URL, supervisorToken: token, coreHost: "127.0.0.1"}

	code := run(context.Background(), []string{"probe"}, env, &out)

	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; log:\n%s", code, exitOK, out.String())
	}
	if got := strings.Count(out.String(), "outcome=ok"); got != 3 {
		t.Fatalf("log has %d ok outcomes, want 3:\n%s", got, out.String())
	}
	if strings.Contains(out.String(), token) {
		t.Fatal("the log contains the Supervisor token")
	}
}
