// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package oauth

import (
	"crypto/x509"
	"net/netip"
	"time"
)

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

// NewTestFetcher returns a fetcher that trusts roots and connects to any
// address, for tests that serve a metadata document on loopback.
func NewTestFetcher(roots *x509.CertPool) *Fetcher {
	return newFetcher(func(netip.Addr) bool { return true }, roots)
}

// IsPublicAddress exposes the address classification.
var IsPublicAddress = isPublicAddress
