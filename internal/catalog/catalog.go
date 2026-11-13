// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

// Package catalog is the static tool catalogue: every tool ha-airlock offers
// is declared here, at compile time, with its risk tier and the Home
// Assistant endpoints it touches. Nothing adds a tool at run time, and no
// tool passes an arbitrary command or path through to Home Assistant.
package catalog

import (
	"context"
	"encoding/json"
)

// Tier is the risk tier of a tool.
type Tier string

// The tiers, from reading to writing files. A tool belongs to exactly one.
const (
	// R0 reads and diagnoses.
	R0 Tier = "R0"
	// R1 controls devices.
	R1 Tier = "R1"
	// R2 changes configuration.
	R2 Tier = "R2"
	// R3 acts on the system and on Apps.
	R3 Tier = "R3"
	// R4 reads and writes files.
	R4 Tier = "R4"
)

// Tiers returns every tier.
func Tiers() []Tier { return []Tier{R0, R1, R2, R3, R4} }

// Core is the connection to Home Assistant Core a tool works with.
type Core interface {
	// Call sends one WebSocket command and decodes its result into out.
	Call(ctx context.Context, command string, params, out any) error //nolint:revive // command-specific JSON: any is the encoding/json contract
}

// Handler runs a tool. args is the JSON object the client sent; the result
// is JSON that has not been redacted yet.
type Handler func(ctx context.Context, core Core, args json.RawMessage) (json.RawMessage, error)

// Tool is one declared tool.
type Tool struct {
	Name        string
	Title       string
	Description string
	Tier        Tier
	// Endpoints names what the tool touches in Home Assistant, for the
	// owner to read: WebSocket command types and REST paths.
	Endpoints []string
	// InputSchema is the JSON Schema of the arguments.
	InputSchema json.RawMessage
	Handler     Handler
	// Act states what a call would do. Every tool above R0 has it, and no
	// tool of R0: a tool that changes something says what, to the gate and
	// to the owner.
	Act func(args json.RawMessage) (Action, error)
}

// All returns the catalogue. The slice is new on every call; the catalogue
// itself cannot be changed.
func All() []Tool {
	return append([]Tool{
		systemLogList(),
		repairsListIssues(),
		configEntriesList(),
		traceList(),
		logbookEvents(),
	}, controlTools()...)
}

// Lookup returns the tool with the given name.
func Lookup(name string) (Tool, bool) {
	tools := All()
	for i := range tools {
		if tools[i].Name == name {
			return tools[i], true
		}
	}
	return Tool{}, false
}
