// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package oauth

import "time"

// SetClock replaces the store's clock in tests.
func (s *Store) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// Lifetimes, for tests that move the clock past them.
const (
	PendingLifetime = pendingLifetime
	CodeLifetime    = codeLifetime
	AccessLifetime  = accessLifetime
	RefreshIdle     = refreshIdle
	MaxPending      = maxPending
)
