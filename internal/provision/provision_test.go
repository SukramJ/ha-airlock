// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package provision_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SukramJ/ha-airlock/internal/audit"
	"github.com/SukramJ/ha-airlock/internal/provision"
	"github.com/SukramJ/ha-airlock/internal/provision/provisiontest"
)

const (
	supervisorToken = provisiontest.SupervisorToken
	refreshToken    = provisiontest.RefreshToken
	accessToken     = provisiontest.AccessToken
	newUserID       = provisiontest.NewUserID
)

// setup is everything one Ensure call needs, and what it leaves behind.
type setup struct {
	cfg       provision.Config
	auditPath string
	log       *bytes.Buffer
}

func newSetup(t *testing.T, h *provisiontest.Home) setup {
	t.Helper()
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	auditLog, err := audit.Open(auditPath)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })
	var logBuf bytes.Buffer
	return setup{
		auditPath: auditPath,
		log:       &logBuf,
		cfg: provision.Config{
			ProxyURL:        h.ProxyURL(),
			SupervisorToken: supervisorToken,
			CoreURL:         h.Core.URL,
			CredentialPath:  filepath.Join(dir, "core-credential.json"),
			Audit:           auditLog,
			Logger:          slog.New(slog.NewTextHandler(&logBuf, nil)),
		},
	}
}

func ensure(t *testing.T, cfg provision.Config) (provision.Credential, bool, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return provision.Ensure(ctx, cfg)
}

func auditText(t *testing.T, s setup) string {
	t.Helper()
	if _, err := audit.VerifyFile(s.auditPath); err != nil {
		t.Fatalf("audit log does not verify: %v", err)
	}
	data, err := os.ReadFile(s.auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	return string(data)
}

func TestEnsureCreatesTheUserOnTheFirstStart(t *testing.T) {
	t.Parallel()
	h := provisiontest.NewHome(t)
	s := newSetup(t, h)

	cred, created, err := ensure(t, s.cfg)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}

	if !created {
		t.Fatal("created = false on the first start")
	}
	if cred.UserID != newUserID || cred.RefreshToken != refreshToken || cred.ClientID != h.Core.URL+"/" {
		t.Fatalf("credential = %+v", cred)
	}
	h.Mu.Lock()
	defer h.Mu.Unlock()
	if len(h.Created) != 1 || h.Created[0] != "ha-airlock" {
		t.Fatalf("users created: %v", h.Created)
	}
	if len(h.Deleted) != 0 {
		t.Fatalf("users deleted: %v", h.Deleted)
	}
	if got := strings.Join(h.Services, ","); got != "logbook.log,persistent_notification.create" {
		t.Fatalf("announcements = %q", got)
	}
}

func TestEnsureStoresTheCredentialForItsOwnerOnlyAndNeverThePassword(t *testing.T) {
	t.Parallel()
	h := provisiontest.NewHome(t)
	s := newSetup(t, h)
	if _, _, err := ensure(t, s.cfg); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	info, err := os.Stat(s.cfg.CredentialPath)
	if err != nil {
		t.Fatalf("stat credential: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("credential mode = %o, want 600", perm)
	}
	stored, err := os.ReadFile(s.cfg.CredentialPath)
	if err != nil {
		t.Fatalf("read credential: %v", err)
	}
	h.Mu.Lock()
	password := h.Passwords[provision.Username]
	h.Mu.Unlock()
	if len(password) < 40 {
		t.Fatalf("password has %d characters, want a long random one", len(password))
	}
	audited := auditText(t, s)
	for name, text := range map[string]string{"credential file": string(stored), "log": s.log.String(), "audit log": audited} {
		if strings.Contains(text, password) {
			t.Fatalf("the %s contains the password", name)
		}
	}
	for name, text := range map[string]string{"log": s.log.String(), "audit log": audited} {
		if strings.Contains(text, refreshToken) || strings.Contains(text, accessToken) || strings.Contains(text, supervisorToken) {
			t.Fatalf("the %s contains a token", name)
		}
	}
}

func TestEnsureRecordsTheCreationInTheAuditLog(t *testing.T) {
	t.Parallel()
	h := provisiontest.NewHome(t)
	s := newSetup(t, h)
	if _, _, err := ensure(t, s.cfg); err != nil {
		t.Fatalf("ensure: %v", err)
	}

	audited := auditText(t, s)
	if !strings.Contains(audited, `"event":"provisioning"`) || !strings.Contains(audited, "created home assistant user "+newUserID) {
		t.Fatalf("audit log:\n%s", audited)
	}
	if !strings.Contains(audited, `"seq":1,`) {
		t.Fatalf("provisioning is not the first record:\n%s", audited)
	}
}

func TestEnsureUsesTheStoredCredentialOnALaterStart(t *testing.T) {
	t.Parallel()
	h := provisiontest.NewHome(t)
	s := newSetup(t, h)
	first, _, err := ensure(t, s.cfg)
	if err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	h.Mu.Lock()
	commandsAfterFirst := len(h.ProxyCommands)
	h.Mu.Unlock()

	second, created, err := ensure(t, s.cfg)
	if err != nil {
		t.Fatalf("second ensure: %v", err)
	}

	if created {
		t.Fatal("created = true on a later start")
	}
	if second != first {
		t.Fatalf("credential changed: %+v != %+v", second, first)
	}
	h.Mu.Lock()
	defer h.Mu.Unlock()
	if len(h.ProxyCommands) != commandsAfterFirst {
		t.Fatalf("the proxy was used again on a later start: %v", h.ProxyCommands[commandsAfterFirst:])
	}
	if len(h.Created) != 1 {
		t.Fatalf("users created: %v", h.Created)
	}
}

func TestEnsureRefusesAUserItDidNotCreate(t *testing.T) {
	t.Parallel()
	h := provisiontest.NewHome(t)
	h.ExistingUsers = []string{provision.Username}
	s := newSetup(t, h)

	_, _, err := ensure(t, s.cfg)

	if !errors.Is(err, provision.ErrUserExists) {
		t.Fatalf("ensure error = %v, want ErrUserExists", err)
	}
	h.Mu.Lock()
	defer h.Mu.Unlock()
	if got := strings.Join(h.ProxyCommands, ","); got != "config/auth/list" {
		t.Fatalf("commands sent through the proxy = %q, want the list only", got)
	}
	if _, err := os.Stat(s.cfg.CredentialPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a credential file exists: %v", err)
	}
}

func TestEnsureRemovesTheUserItCreatedWhenTheLoginFails(t *testing.T) {
	t.Parallel()
	h := provisiontest.NewHome(t)
	h.LoginFails = true
	s := newSetup(t, h)

	_, _, err := ensure(t, s.cfg)
	if err == nil {
		t.Fatal("ensure succeeded although the login failed")
	}

	h.Mu.Lock()
	deleted := strings.Join(h.Deleted, ",")
	h.Mu.Unlock()
	if deleted != newUserID {
		t.Fatalf("users deleted = %q, want %q", deleted, newUserID)
	}
	if _, statErr := os.Stat(s.cfg.CredentialPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("a credential file exists: %v", statErr)
	}
	if audited := auditText(t, s); !strings.Contains(audited, `"result":"failed: `) {
		t.Fatalf("the failure is not in the audit log:\n%s", audited)
	}
}

func TestEnsureDoesNotCreateASecondUserWhenCoreRefusesTheStoredCredential(t *testing.T) {
	t.Parallel()
	h := provisiontest.NewHome(t)
	s := newSetup(t, h)
	if _, _, err := ensure(t, s.cfg); err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	h.Mu.Lock()
	h.RefreshStatus = http.StatusBadRequest
	h.Mu.Unlock()

	_, _, err := ensure(t, s.cfg)

	if !errors.Is(err, provision.ErrCredentialRefused) {
		t.Fatalf("ensure error = %v, want ErrCredentialRefused", err)
	}
	h.Mu.Lock()
	defer h.Mu.Unlock()
	if len(h.Created) != 1 {
		t.Fatalf("users created: %v", h.Created)
	}
}
