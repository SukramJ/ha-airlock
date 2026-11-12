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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SukramJ/ha-airlock/internal/audit"
	"github.com/SukramJ/ha-airlock/internal/hacore/hacoretest"
	"github.com/SukramJ/ha-airlock/internal/provision"
	"github.com/SukramJ/ha-airlock/internal/provision/provisiontest"
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
	mux.Handle("/core/websocket", hacoretest.Handler(token, map[string]string{
		"auth/current_user": `{"id":"abc","name":"Supervisor","is_admin":true,"is_owner":false}`,
	}))
	supervisor := httptest.NewServer(mux)
	t.Cleanup(supervisor.Close)

	var out bytes.Buffer
	env := environment{supervisorURL: supervisor.URL, supervisorToken: token, coreHost: "127.0.0.1"}

	code := run(context.Background(), []string{"probe"}, env, &out)

	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; log:\n%s", code, exitOK, out.String())
	}
	if got := strings.Count(out.String(), "outcome=ok"); got != 4 {
		t.Fatalf("log has %d ok outcomes, want 4:\n%s", got, out.String())
	}
	if strings.Contains(out.String(), token) {
		t.Fatal("the log contains the Supervisor token")
	}
}

func writeAuditLog(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.Open(path)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	for range 2 {
		if _, err := log.Append(context.Background(), audit.Entry{Event: "tool_call", Decision: "allow"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatalf("close audit log: %v", err)
	}
	return path
}

func TestAuditVerifyCommandAcceptsAnUntouchedLog(t *testing.T) {
	t.Parallel()
	path := writeAuditLog(t)
	var out bytes.Buffer

	code := run(context.Background(), []string{"audit", "verify", path}, environment{}, &out)

	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; output:\n%s", code, exitOK, out.String())
	}
	if !strings.HasPrefix(out.String(), "ok: 2 records, head ") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestAuditVerifyCommandFailsOnAChangedLog(t *testing.T) {
	t.Parallel()
	path := writeAuditLog(t)
	data, err := os.ReadFile(path) //nolint:gosec // test file below t.TempDir
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	changed := strings.Replace(string(data), `"decision":"allow"`, `"decision":"deny"`, 1)
	if err := os.WriteFile(path, []byte(changed), 0o600); err != nil {
		t.Fatalf("write audit log: %v", err)
	}
	var out bytes.Buffer

	code := run(context.Background(), []string{"audit", "verify", path}, environment{}, &out)

	if code != exitFailed {
		t.Fatalf("exit code = %d, want %d; output:\n%s", code, exitFailed, out.String())
	}
	if !strings.Contains(out.String(), "line 1: hash does not match the entry") {
		t.Fatalf("output does not name the break:\n%s", out.String())
	}
}

func TestAuditCommandRejectsAWrongInvocation(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer

	if code := run(context.Background(), []string{"audit", "verify"}, environment{}, &out); code != exitUsage {
		t.Fatalf("exit code = %d, want %d", code, exitUsage)
	}
}

// The provision command, built the way main builds it, creates the user,
// keeps a credential in the data directory and leaves an audit log that
// verifies and starts with the provisioning.
func TestProvisionCommandCreatesTheUserAndRecordsIt(t *testing.T) {
	t.Parallel()
	home := provisiontest.NewHome(t)
	dataDir := t.TempDir()
	env := environment{
		supervisorURL:   home.Supervisor.URL,
		supervisorToken: provisiontest.SupervisorToken,
		coreHost:        "127.0.0.1",
		dataDir:         dataDir,
	}
	var out bytes.Buffer

	code := run(context.Background(), []string{"provision"}, env, &out)

	if code != exitOK {
		t.Fatalf("exit code = %d, want %d; log:\n%s", code, exitOK, out.String())
	}
	if !strings.Contains(out.String(), "created=true") {
		t.Fatalf("log does not report the creation:\n%s", out.String())
	}
	if _, err := os.Stat(filepath.Join(dataDir, "core-credential.json")); err != nil {
		t.Fatalf("credential file: %v", err)
	}
	summary, err := audit.VerifyFile(filepath.Join(dataDir, "audit.jsonl"))
	if err != nil || summary.Records != 1 {
		t.Fatalf("audit log: %+v, %v", summary, err)
	}
	for _, secret := range []string{provisiontest.SupervisorToken, provisiontest.RefreshToken, provisiontest.AccessToken} {
		if strings.Contains(out.String(), secret) {
			t.Fatal("the log contains a token")
		}
	}

	// A second run finds the credential and creates nothing.
	out.Reset()
	if code := run(context.Background(), []string{"provision"}, env, &out); code != exitOK {
		t.Fatalf("second run: exit code = %d; log:\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "created=false") {
		t.Fatalf("second run does not report reuse:\n%s", out.String())
	}
	home.Mu.Lock()
	defer home.Mu.Unlock()
	if len(home.Created) != 1 {
		t.Fatalf("users created: %v", home.Created)
	}
}

func TestProvisionCommandStopsAtAUserItDidNotCreate(t *testing.T) {
	t.Parallel()
	home := provisiontest.NewHome(t)
	home.ExistingUsers = []string{provision.Username}
	env := environment{
		supervisorURL:   home.Supervisor.URL,
		supervisorToken: provisiontest.SupervisorToken,
		coreHost:        "127.0.0.1",
		dataDir:         t.TempDir(),
	}
	var out bytes.Buffer

	code := run(context.Background(), []string{"provision"}, env, &out)

	if code != exitFailed {
		t.Fatalf("exit code = %d, want %d; log:\n%s", code, exitFailed, out.String())
	}
	home.Mu.Lock()
	defer home.Mu.Unlock()
	if len(home.Created) != 0 {
		t.Fatalf("users created: %v", home.Created)
	}
}
