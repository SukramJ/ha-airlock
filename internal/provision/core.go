// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package provision

import (
	"context"
	"fmt"

	"github.com/SukramJ/ha-airlock/internal/hacore"
)

// Core is ha-airlock's access to Home Assistant Core as its own user: the
// connection every tool works through.
//
// Each call obtains a fresh access token and its own connection. That costs
// a round trip per call and keeps no state that could go stale.
type Core struct {
	auth *coreAuth
	cred Credential
}

// NewCore returns the access to Core at coreURL for the given credential.
func NewCore(coreURL string, cred Credential) *Core {
	return &Core{auth: newCoreAuth(coreURL), cred: cred}
}

// Call sends one WebSocket command to Core and decodes its result into out.
func (c *Core) Call(ctx context.Context, command string, params, out any) error { //nolint:revive // command-specific JSON: any is the encoding/json contract
	token, err := c.auth.accessToken(ctx, c.cred)
	if err != nil {
		return err
	}
	conn, err := hacore.Dial(ctx, c.auth.webSocketURL(), token)
	if err != nil {
		return fmt.Errorf("connect to core: %w", err)
	}
	defer func() { _ = conn.Close() }()
	return conn.Call(ctx, command, params, out)
}
