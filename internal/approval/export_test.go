// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package approval

import "time"

// SetClock replaces the store's clock in tests.
func (s *Store) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = now
}

// MaxWaitingPerClient is the bound a test fills.
const MaxWaitingPerClient = maxWaitingPerClient
