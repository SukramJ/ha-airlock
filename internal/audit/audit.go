// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

// Package audit is the audit log: one JSON line per event, each line chained
// to the one before it by a SHA-256 hash.
//
// A line is {"hash":H,"entry":E}. E carries the sequence number, the hash of
// the previous line and the event; H is the SHA-256 of the bytes of E exactly
// as written. Changing, removing, inserting or reordering a line therefore
// breaks the chain at that line.
//
// The chain does not show that lines were cut off its end, and it does not
// stop someone who can write the file from rewriting all of it. Both need an
// anchor outside the file.
package audit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// genesis is the previous-hash of the first line.
const genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// maxLine bounds one line of the log when reading it back.
const maxLine = 4 << 20

// maxEntry bounds an encoded entry when appending, so that every line the
// log writes is one it can read back: the hash, the keys and the newline
// around the entry stay well below the difference to maxLine.
const maxEntry = maxLine - 1024

// ErrTooLarge reports an entry that would not fit a line of the log.
var ErrTooLarge = errors.New("audit entry is too large")

// ErrBroken is wrapped by every error that reports a log whose chain does
// not hold.
var ErrBroken = errors.New("audit log is broken")

// Entry is one event as the caller describes it. Callers redact before they
// append: the log stores what it is given.
type Entry struct {
	// Event names what happened.
	Event string `json:"event"`
	// Client is the identity of the MCP client the event belongs to.
	Client string `json:"client,omitempty"`
	Tool   string `json:"tool,omitempty"`
	// Arguments are the tool's arguments as JSON.
	Arguments json.RawMessage `json:"arguments,omitempty"`
	// Decision is what the policy decided.
	Decision string `json:"decision,omitempty"`
	// Approver is the Home Assistant user who approved, if anyone had to.
	Approver   string `json:"approver,omitempty"`
	Diff       string `json:"diff,omitempty"`
	Result     string `json:"result,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
}

// stored is an Entry as it stands in the file.
type stored struct {
	Seq  uint64    `json:"seq"`
	Prev string    `json:"prev"`
	Time time.Time `json:"time"`
	Entry
}

// line is one line of the file. Entry keeps the exact bytes that were
// hashed, so verification never depends on re-encoding.
type line struct {
	Hash  string          `json:"hash"`
	Entry json.RawMessage `json:"entry"`
}

// Receipt identifies an appended line.
type Receipt struct {
	Seq  uint64
	Hash string
}

// Summary is what Verify found in a log whose chain holds.
type Summary struct {
	// Records is the number of lines.
	Records uint64
	// Head is the hash of the last line, or the genesis value for an empty
	// log.
	Head string
}

// Log appends to one audit file. It is safe for concurrent use.
type Log struct {
	mu   sync.Mutex
	file *os.File
	seq  uint64
	head string
	now  func() time.Time
}

// Open verifies the log at path and opens it for appending, creating it if
// it does not exist. A log whose chain does not hold is not opened: appending
// to it would bury the break under valid lines.
func Open(path string) (*Log, error) {
	summary, err := VerifyFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if errors.Is(err, os.ErrNotExist) {
		summary = Summary{Head: genesis}
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // the path is the operator's configuration, not client input
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return &Log{file: file, seq: summary.Records, head: summary.Head, now: time.Now}, nil
}

// Append writes one entry and returns once it is on stable storage.
func (l *Log) Append(ctx context.Context, entry Entry) (Receipt, error) {
	if err := ctx.Err(); err != nil {
		return Receipt{}, fmt.Errorf("append audit entry: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	body, err := json.Marshal(stored{
		Seq:   l.seq + 1,
		Prev:  l.head,
		Time:  l.now().UTC(),
		Entry: entry,
	})
	if err != nil {
		return Receipt{}, fmt.Errorf("encode audit entry: %w", err)
	}
	if len(body) > maxEntry {
		return Receipt{}, fmt.Errorf("%w: %d bytes encoded", ErrTooLarge, len(body))
	}
	hash := hashOf(body)
	// The line is assembled by hand so that the entry's bytes reach the file
	// exactly as they were hashed.
	var out bytes.Buffer
	out.WriteString(`{"hash":"`)
	out.WriteString(hash)
	out.WriteString(`","entry":`)
	out.Write(body)
	out.WriteString("}\n")
	if _, err := l.file.Write(out.Bytes()); err != nil {
		return Receipt{}, fmt.Errorf("write audit line: %w", err)
	}
	if err := l.file.Sync(); err != nil {
		return Receipt{}, fmt.Errorf("sync audit log: %w", err)
	}
	l.seq++
	l.head = hash
	return Receipt{Seq: l.seq, Hash: hash}, nil
}

// Close closes the file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.file.Close(); err != nil {
		return fmt.Errorf("close audit log: %w", err)
	}
	return nil
}

// VerifyFile verifies the log at path.
func VerifyFile(path string) (Summary, error) {
	file, err := os.Open(path) //nolint:gosec // the path is the operator's configuration, not client input
	if err != nil {
		return Summary{}, fmt.Errorf("open audit log: %w", err)
	}
	defer func() { _ = file.Close() }()
	return Verify(file)
}

// Verify reads a log and checks every line against the chain. It returns
// the first break it finds, wrapped around ErrBroken.
func Verify(r io.Reader) (Summary, error) {
	summary := Summary{Head: genesis}
	reader := bufio.NewReader(r)
	for {
		raw, err := readLine(reader)
		if errors.Is(err, io.EOF) {
			return summary, nil
		}
		number := summary.Records + 1
		if err != nil {
			return summary, fmt.Errorf("%w: line %d: %w", ErrBroken, number, err)
		}
		hash, err := checkLine(raw, number, summary.Head)
		if err != nil {
			return summary, fmt.Errorf("%w: line %d: %w", ErrBroken, number, err)
		}
		summary.Records = number
		summary.Head = hash
	}
}

// readLine returns the next line without its newline. A last line that does
// not end in a newline was not written completely and is an error.
func readLine(reader *bufio.Reader) ([]byte, error) {
	var raw []byte
	for {
		part, err := reader.ReadSlice('\n')
		raw = append(raw, part...)
		if len(raw) > maxLine {
			return nil, errors.New("line is longer than the limit")
		}
		switch {
		case err == nil:
			return bytes.TrimSuffix(raw, []byte{'\n'}), nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(raw) == 0:
			return nil, io.EOF
		case errors.Is(err, io.EOF):
			return nil, errors.New("last line is incomplete")
		default:
			return nil, fmt.Errorf("read: %w", err)
		}
	}
}

// checkLine verifies one line against its position and the hash before it,
// and returns the line's hash.
func checkLine(raw []byte, number uint64, prev string) (string, error) {
	var l line
	if err := json.Unmarshal(raw, &l); err != nil {
		return "", fmt.Errorf("not a JSON line: %w", err)
	}
	if hashOf(l.Entry) != l.Hash {
		return "", errors.New("hash does not match the entry")
	}
	var s stored
	if err := json.Unmarshal(l.Entry, &s); err != nil {
		return "", fmt.Errorf("entry is not valid: %w", err)
	}
	if s.Seq != number {
		return "", fmt.Errorf("sequence number is %d", s.Seq)
	}
	if s.Prev != prev {
		return "", errors.New("previous hash does not match the line before")
	}
	return l.Hash, nil
}

func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
