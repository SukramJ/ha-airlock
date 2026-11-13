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

// Kind is a kind of configuration a tool of tier R2 changes. The policy
// switches each kind on its own.
type Kind string

// The kinds of configuration.
const (
	KindHelper     Kind = "helper"
	KindArea       Kind = "area"
	KindLabel      Kind = "label"
	KindEntity     Kind = "entity"
	KindScene      Kind = "scene"
	KindScript     Kind = "script"
	KindAutomation Kind = "automation"
	KindDashboard  Kind = "dashboard"
)

// Kinds returns every kind of configuration.
func Kinds() []Kind {
	return []Kind{KindHelper, KindArea, KindLabel, KindEntity, KindScene, KindScript, KindAutomation, KindDashboard}
}

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
	// Kind is the kind of configuration a tool of tier R2 changes, and
	// Plan what one call would change. Every tool of R2 has both and
	// neither Act nor Handler: it changes something only through its plan.
	Kind Kind
	Plan func(ctx context.Context, core Core, args json.RawMessage) (Change, error)
}

// Change is what one call of a tool of tier R2 would change, stated by the
// server: from the checked arguments, and from what it read in Home
// Assistant just now. It is what the owner is shown, what the approval is
// bound to, and what is written.
type Change struct {
	// Summary is one sentence built from the tool's own words and from
	// identifiers of a checked shape. It never holds a name.
	Summary string
	// Object identifies what is changed, and Name is what Home Assistant
	// calls it now. Both are empty for a creation.
	Object string
	Name   string
	// Entity is the entity whose label releases the object for change.
	// Empty for a creation, which has nothing to release.
	Entity string
	// Before is the object as Home Assistant holds it; absent for a
	// creation. After is the object as the call would leave it; absent for
	// a deletion.
	Before json.RawMessage
	After  json.RawMessage
	// Apply makes exactly this change. For a creation it returns the
	// entity that now stands for the new object.
	Apply func(ctx context.Context, core Core) (object string, result json.RawMessage, err error)
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
		entitiesList(),
		statesGet(),
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
