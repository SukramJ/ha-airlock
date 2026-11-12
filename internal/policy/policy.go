// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

// Package policy decides whether a profile may use a tier. What is not
// allowed in so many words is denied.
//
// The policy only narrows or opens tiers of tools that exist in the
// catalogue. It cannot add a tool, so nothing on the Never list of
// CONCEPT.md can be enabled by it.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/SukramJ/ha-airlock/internal/catalog"
)

// Decision is what the policy says about one call.
type Decision string

const (
	// Allow lets the call run.
	Allow Decision = "allow"
	// Deny refuses it.
	Deny Decision = "deny"
)

// The profiles a client can be given.
const (
	ProfileLocal  = "local"
	ProfileRemote = "remote"
)

// version is the only file format this build reads.
const version = 1

// Policy maps each profile to its decision per tier.
type Policy struct {
	profiles map[string]map[catalog.Tier]Decision
}

// Default is the policy in force when the owner has written none: the local
// profile may read and diagnose, and nothing else is allowed. The remote
// profile is denied everything until its stricter redaction exists.
func Default() Policy {
	return Policy{profiles: map[string]map[catalog.Tier]Decision{
		ProfileLocal:  {catalog.R0: Allow},
		ProfileRemote: {},
	}}
}

// file is the policy as the owner writes it.
type file struct {
	Version  int                          `json:"version"`
	Profiles map[string]map[string]string `json:"profiles"`
}

// Parse reads a policy file. It rejects what it does not know — a key, a
// profile, a tier or a decision — because a misspelt rule that is silently
// ignored reads as a rule that is in force.
func Parse(data []byte) (Policy, error) {
	var f file
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return Policy{}, fmt.Errorf("policy: %w", err)
	}
	if dec.More() {
		return Policy{}, errors.New("policy: more than one JSON value")
	}
	if f.Version != version {
		return Policy{}, fmt.Errorf("policy: version is %d, this build reads version %d", f.Version, version)
	}

	known := map[catalog.Tier]bool{}
	for _, tier := range catalog.Tiers() {
		known[tier] = true
	}
	p := Policy{profiles: map[string]map[catalog.Tier]Decision{}}
	for profile, tiers := range f.Profiles {
		if profile != ProfileLocal && profile != ProfileRemote {
			return Policy{}, fmt.Errorf("policy: unknown profile %q", profile)
		}
		p.profiles[profile] = map[catalog.Tier]Decision{}
		for tier, decision := range tiers {
			if !known[catalog.Tier(tier)] {
				return Policy{}, fmt.Errorf("policy: profile %q: unknown tier %q", profile, tier)
			}
			switch Decision(decision) {
			case Allow, Deny:
				p.profiles[profile][catalog.Tier(tier)] = Decision(decision)
			default:
				return Policy{}, fmt.Errorf("policy: profile %q, tier %s: unknown decision %q", profile, tier, decision)
			}
		}
	}
	return p, nil
}

// Decide returns the decision for a profile and a tier. A profile or a tier
// the policy does not mention is denied.
func (p Policy) Decide(profile string, tier catalog.Tier) Decision {
	if p.profiles[profile][tier] == Allow {
		return Allow
	}
	return Deny
}
