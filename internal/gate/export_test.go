// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package gate

import "time"

// SetClock replaces the gate's clock in tests.
func (g *Gate) SetClock(now func() time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.now = now
}
