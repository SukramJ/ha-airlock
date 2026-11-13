// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

// Package halt is the kill switch: one persistent flag that, while set,
// makes the gate refuse every tool call. It survives a restart, so that a
// server stopped in an emergency does not come back open.
package halt

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/SukramJ/ha-airlock/internal/audit"
)

// Appender is the audit log as the switch uses it.
type Appender interface {
	Append(ctx context.Context, entry audit.Entry) (audit.Receipt, error)
}

// Switch is the kill switch. The flag is the existence of a file.
type Switch struct {
	mu      sync.RWMutex
	path    string
	audit   Appender
	engaged bool
}

// Open returns the switch whose state is kept at path.
func Open(path string, log Appender) (*Switch, error) {
	s := &Switch{path: path, audit: log}
	_, err := os.Stat(path)
	switch {
	case err == nil:
		s.engaged = true
	case !errors.Is(err, os.ErrNotExist):
		// A state that cannot be read is treated as an error, not as "off".
		return nil, fmt.Errorf("kill switch: %w", err)
	}
	return s, nil
}

// Engaged reports whether tool calls are halted.
func (s *Switch) Engaged() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.engaged
}

// Set engages or releases the switch. by is the Home Assistant user who
// did it.
//
// Engaging takes effect even if it cannot be recorded or stored: stopping
// must not depend on a working disk. Releasing takes effect only once it is
// in the audit log and the stored flag is gone.
func (s *Switch) Set(ctx context.Context, engage bool, by string) error {
	if by == "" {
		return errors.New("kill switch: a change needs the user who made it")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if engage {
		s.engaged = true
		_, auditErr := s.audit.Append(ctx, audit.Entry{Event: "kill_switch", Decision: "engaged", Approver: by})
		fileErr := os.WriteFile(s.path, []byte("engaged\n"), 0o600)
		if err := errors.Join(auditErr, fileErr); err != nil {
			return fmt.Errorf("kill switch is engaged, but that could not be recorded or stored: %w", err)
		}
		return nil
	}
	if _, err := s.audit.Append(ctx, audit.Entry{Event: "kill_switch", Decision: "released", Approver: by}); err != nil {
		return fmt.Errorf("kill switch stays engaged, the release could not be recorded: %w", err)
	}
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("kill switch stays engaged, the stored flag could not be removed: %w", err)
	}
	s.engaged = false
	return nil
}
