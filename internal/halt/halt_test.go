// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package halt_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SukramJ/ha-airlock/internal/audit"
	"github.com/SukramJ/ha-airlock/internal/halt"
)

func open(t *testing.T) (sw *halt.Switch, path, auditPath string, log *audit.Log) {
	t.Helper()
	dir := t.TempDir()
	auditPath = filepath.Join(dir, "audit.jsonl")
	log, err := audit.Open(auditPath)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	path = filepath.Join(dir, "halted")
	sw, err = halt.Open(path, log)
	if err != nil {
		t.Fatalf("open switch: %v", err)
	}
	return sw, path, auditPath, log
}

func TestSwitchIsReleasedUntilSomeoneEngagesIt(t *testing.T) {
	t.Parallel()
	sw, _, auditPath, _ := open(t)
	if sw.Engaged() {
		t.Fatal("a new switch is engaged")
	}

	if err := sw.Set(context.Background(), true, "admin"); err != nil {
		t.Fatalf("engage: %v", err)
	}
	if !sw.Engaged() {
		t.Fatal("the switch is not engaged")
	}
	if err := sw.Set(context.Background(), false, "admin"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if sw.Engaged() {
		t.Fatal("the switch is still engaged")
	}

	data, err := os.ReadFile(auditPath) //nolint:gosec // test file below t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"decision":"engaged"`) || !strings.Contains(string(data), `"decision":"released"`) ||
		strings.Count(string(data), `"approver":"admin"`) != 2 {
		t.Fatalf("audit log:\n%s", data)
	}
}

func TestEngagedSwitchSurvivesARestart(t *testing.T) {
	t.Parallel()
	sw, path, _, log := open(t)
	if err := sw.Set(context.Background(), true, "admin"); err != nil {
		t.Fatalf("engage: %v", err)
	}

	again, err := halt.Open(path, log)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if !again.Engaged() {
		t.Fatal("the switch came back released")
	}
}

func TestChangeNeedsTheUserWhoMadeIt(t *testing.T) {
	t.Parallel()
	sw, _, _, _ := open(t)
	if err := sw.Set(context.Background(), true, ""); err == nil {
		t.Fatal("a change without a user was accepted")
	}
	if sw.Engaged() {
		t.Fatal("the switch changed")
	}
}

// failingLog refuses every append.
type failingLog struct{}

func (failingLog) Append(context.Context, audit.Entry) (audit.Receipt, error) {
	return audit.Receipt{}, errors.New("disk full")
}

func TestEngagingWorksWithoutTheAuditLogAndReleasingDoesNot(t *testing.T) {
	t.Parallel()
	sw, err := halt.Open(filepath.Join(t.TempDir(), "halted"), failingLog{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if err := sw.Set(context.Background(), true, "admin"); err == nil {
		t.Fatal("the failure to record was not reported")
	}
	if !sw.Engaged() {
		t.Fatal("engaging did not take effect although it must not depend on the audit log")
	}

	if err := sw.Set(context.Background(), false, "admin"); err == nil {
		t.Fatal("a release that could not be recorded was accepted")
	}
	if !sw.Engaged() {
		t.Fatal("the switch was released without a record")
	}
}
