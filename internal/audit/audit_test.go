// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/SukramJ/ha-airlock/internal/audit"
)

// writeLog appends n entries of client-a to a new log and returns its path.
func writeLog(t *testing.T, n int) string {
	t.Helper()
	return writeLogFor(t, n, "client-a")
}

func writeLogFor(t *testing.T, n int, client string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := range n {
		entry := audit.Entry{
			Event:     "tool_call",
			Client:    client,
			Tool:      fmt.Sprintf("tool_%d", i),
			Arguments: json.RawMessage(`{"entity":"light.<kitchen> &   ü"}`),
			Decision:  "allow",
		}
		if _, err := log.Append(context.Background(), entry); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := log.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return path
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test file below t.TempDir
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	data := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
}

func wantBroken(t *testing.T, path, wantInMessage string) {
	t.Helper()
	_, err := audit.VerifyFile(path)
	if !errors.Is(err, audit.ErrBroken) {
		t.Fatalf("verify error = %v, want ErrBroken", err)
	}
	if !strings.Contains(err.Error(), wantInMessage) {
		t.Fatalf("verify error = %q, want it to contain %q", err, wantInMessage)
	}
}

func TestVerifyAcceptsAnUntouchedLog(t *testing.T) {
	t.Parallel()
	path := writeLog(t, 3)

	summary, err := audit.VerifyFile(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if summary.Records != 3 {
		t.Fatalf("records = %d, want 3", summary.Records)
	}
	if len(summary.Head) != 64 {
		t.Fatalf("head = %q, want a SHA-256 in hex", summary.Head)
	}
}

func TestVerifyDetectsAChangedEntry(t *testing.T) {
	t.Parallel()
	path := writeLog(t, 3)
	lines := readLines(t, path)
	lines[1] = strings.Replace(lines[1], `"decision":"allow"`, `"decision":"deny"`, 1)
	writeLines(t, path, lines)

	wantBroken(t, path, "line 2: hash does not match the entry")
}

func TestVerifyDetectsARemovedLine(t *testing.T) {
	t.Parallel()
	path := writeLog(t, 3)
	lines := readLines(t, path)
	writeLines(t, path, []string{lines[0], lines[2]})

	wantBroken(t, path, "line 2: sequence number is 3")
}

func TestVerifyDetectsSwappedLines(t *testing.T) {
	t.Parallel()
	path := writeLog(t, 3)
	lines := readLines(t, path)
	writeLines(t, path, []string{lines[1], lines[0], lines[2]})

	wantBroken(t, path, "line 1: sequence number is 2")
}

// A line taken from another log has a fitting sequence number and a valid
// hash of its own; only the link to the line before gives it away.
func TestVerifyDetectsALineFromAnotherLog(t *testing.T) {
	t.Parallel()
	path := writeLog(t, 3)
	other := writeLogFor(t, 2, "client-b")
	lines, otherLines := readLines(t, path), readLines(t, other)
	writeLines(t, path, []string{lines[0], otherLines[1], lines[2]})

	wantBroken(t, path, "line 2: previous hash does not match the line before")
}

func TestVerifyDetectsAnIncompleteLastLine(t *testing.T) {
	t.Parallel()
	path := writeLog(t, 2)
	data, err := os.ReadFile(path) //nolint:gosec // test file below t.TempDir
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if err := os.WriteFile(path, data[:len(data)-10], 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}

	wantBroken(t, path, "line 2: last line is incomplete")
}

// The limit of a hash chain, stated as a test so that nobody assumes more:
// whole lines cut off the end leave a shorter log whose chain still holds.
func TestVerifyDoesNotDetectLinesCutOffTheEnd(t *testing.T) {
	t.Parallel()
	path := writeLog(t, 3)
	lines := readLines(t, path)
	writeLines(t, path, lines[:2])

	summary, err := audit.VerifyFile(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if summary.Records != 2 {
		t.Fatalf("records = %d, want 2", summary.Records)
	}
}

func TestOpenContinuesTheChainOfAnExistingLog(t *testing.T) {
	t.Parallel()
	path := writeLog(t, 2)
	before, err := audit.VerifyFile(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	log, err := audit.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	receipt, err := log.Append(context.Background(), audit.Entry{Event: "tool_call"})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if receipt.Seq != 3 {
		t.Fatalf("sequence = %d, want 3", receipt.Seq)
	}
	after, err := audit.VerifyFile(path)
	if err != nil {
		t.Fatalf("verify after reopen: %v", err)
	}
	if after.Records != 3 || after.Head != receipt.Hash || after.Head == before.Head {
		t.Fatalf("summary after reopen = %+v, receipt = %+v", after, receipt)
	}
}

func TestOpenRefusesABrokenLog(t *testing.T) {
	t.Parallel()
	path := writeLog(t, 3)
	lines := readLines(t, path)
	lines[1] = strings.Replace(lines[1], `"client":"client-a"`, `"client":"client-b"`, 1)
	writeLines(t, path, lines)

	if _, err := audit.Open(path); !errors.Is(err, audit.ErrBroken) {
		t.Fatalf("open error = %v, want ErrBroken", err)
	}
}

func TestOpenCreatesTheLogReadableByItsOwnerOnly(t *testing.T) {
	t.Parallel()
	path := writeLog(t, 1)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %o, want 600", perm)
	}
}

func TestAppendRejectsArgumentsThatAreNotJSON(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	_, err = log.Append(context.Background(), audit.Entry{Event: "tool_call", Arguments: json.RawMessage(`{broken`)})
	if err == nil {
		t.Fatal("append accepted arguments that are not JSON")
	}
	if summary, verr := audit.VerifyFile(path); verr != nil || summary.Records != 0 {
		t.Fatalf("log after rejected append: %+v, %v", summary, verr)
	}
}

func TestAppendHonoursACancelledContext(t *testing.T) {
	t.Parallel()
	log, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := log.Append(ctx, audit.Entry{Event: "tool_call"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("append error = %v, want context.Canceled", err)
	}
}

func TestConcurrentAppendsFormOneChain(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	const writers, each = 8, 25
	var wg sync.WaitGroup
	for range writers {
		wg.Go(func() {
			for range each {
				if _, err := log.Append(context.Background(), audit.Entry{Event: "tool_call"}); err != nil {
					t.Errorf("append: %v", err)
				}
			}
		})
	}
	wg.Wait()
	if err := log.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	summary, err := audit.VerifyFile(path)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if summary.Records != writers*each {
		t.Fatalf("records = %d, want %d", summary.Records, writers*each)
	}
}

func TestVerifyOfAnEmptyLogReportsNoRecords(t *testing.T) {
	t.Parallel()
	summary, err := audit.Verify(bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if summary.Records != 0 {
		t.Fatalf("records = %d, want 0", summary.Records)
	}
}
