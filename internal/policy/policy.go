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
	"regexp"

	"github.com/SukramJ/ha-airlock/internal/catalog"
)

// Decision is what the policy says about one call.
type Decision string

const (
	// Allow lets the call run.
	Allow Decision = "allow"
	// Deny refuses it.
	Deny Decision = "deny"
	// Approval lets the call run once an administrator approved exactly
	// this call in the sidebar page.
	Approval Decision = "approval"
)

// Release says which existing objects of a kind of configuration a tool
// may change.
type Release string

const (
	// ReleaseLabel releases the objects the owner marked: those carrying
	// the control label, or, for dashboards, those the policy names.
	ReleaseLabel Release = "label"
	// ReleaseAll releases every object of the kind.
	ReleaseAll Release = "all"
)

// Kind is what the policy says about one kind of configuration.
type Kind struct {
	// Change is Approval or Deny. Configuration is never changed without
	// an approval.
	Change Decision
	// Release says which existing objects can be changed.
	Release Release
	// Objects are the released dashboards, by URL path. Empty for every
	// other kind.
	Objects []string
}

// dashboardShape is the shape of a dashboard's URL path.
var dashboardShape = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

// defaultControlLabel is the Home Assistant label that releases an entity
// for control when the policy file names none.
const defaultControlLabel = "airlock"

// labelShape is the shape of a label id as Home Assistant generates it.
var labelShape = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// The profiles a client can be given.
const (
	ProfileLocal  = "local"
	ProfileRemote = "remote"
)

// version is the only file format this build reads.
const version = 1

// Limits on how many tool calls a client of a profile may make per minute,
// used when the policy file sets none, and the bounds a file may set.
const (
	defaultLocalCallsPerMinute  = 60
	defaultRemoteCallsPerMinute = 30
	maxCallsPerMinute           = 6000
)

// Policy maps each profile to its decision per tier and to its call limit.
type Policy struct {
	profiles map[string]map[catalog.Tier]Decision
	kinds    map[string]map[catalog.Kind]Kind
	limits   map[string]int
	label    string
}

func defaultLimits() map[string]int {
	return map[string]int{ProfileLocal: defaultLocalCallsPerMinute, ProfileRemote: defaultRemoteCallsPerMinute}
}

// Default is the policy in force when the owner has written none: the local
// profile may read and diagnose, and may control released entities after an
// approval for each call. Nothing else is allowed: no configuration is
// changed until the owner's file says which kinds. The remote profile is
// denied everything until its stricter redaction exists.
func Default() Policy {
	return Policy{
		profiles: map[string]map[catalog.Tier]Decision{
			ProfileLocal:  {catalog.R0: Allow, catalog.R1: Approval},
			ProfileRemote: {},
		},
		limits: defaultLimits(),
		label:  defaultControlLabel,
	}
}

// file is the policy as the owner writes it.
type file struct {
	Version  int                          `json:"version"`
	Profiles map[string]map[string]string `json:"profiles"`
	Limits   map[string]limit             `json:"limits"`
	// Configuration says, per profile and kind of configuration, whether
	// and which objects of the kind can be changed.
	Configuration map[string]map[string]kind `json:"configuration"`
	// ControlLabel is the id of the Home Assistant label that releases an
	// entity for control.
	ControlLabel *string `json:"control_label"`
}

// kind is what the file may say about one kind of configuration.
type kind struct {
	Change  string   `json:"change"`
	Release *string  `json:"release"`
	Objects []string `json:"objects"`
}

// limit is what the file may say about one profile's quantity limits.
type limit struct {
	CallsPerMinute int `json:"calls_per_minute"`
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
	p := Policy{
		profiles: map[string]map[catalog.Tier]Decision{}, kinds: map[string]map[catalog.Kind]Kind{},
		limits: defaultLimits(), label: defaultControlLabel,
	}
	if f.ControlLabel != nil {
		if !labelShape.MatchString(*f.ControlLabel) {
			return Policy{}, errors.New("policy: control_label must be a label id of lower-case letters, digits and underscores")
		}
		p.label = *f.ControlLabel
	}
	for profile, l := range f.Limits {
		if profile != ProfileLocal && profile != ProfileRemote {
			return Policy{}, fmt.Errorf("policy: limits: unknown profile %q", profile)
		}
		if l.CallsPerMinute < 1 || l.CallsPerMinute > maxCallsPerMinute {
			return Policy{}, fmt.Errorf("policy: limits: profile %q: calls_per_minute must be between 1 and %d", profile, maxCallsPerMinute)
		}
		p.limits[profile] = l.CallsPerMinute
	}
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
			case Allow, Deny, Approval:
				p.profiles[profile][catalog.Tier(tier)] = Decision(decision)
			default:
				return Policy{}, fmt.Errorf("policy: profile %q, tier %s: unknown decision %q", profile, tier, decision)
			}
			// Configuration is not changed without the owner seeing the
			// difference; no file can say otherwise.
			if catalog.Tier(tier) == catalog.R2 && Decision(decision) == Allow {
				return Policy{}, fmt.Errorf("policy: profile %q: tier R2 cannot be allowed without approval; use %q or %q", profile, Approval, Deny)
			}
		}
	}
	for profile, kinds := range f.Configuration {
		if profile != ProfileLocal && profile != ProfileRemote {
			return Policy{}, fmt.Errorf("policy: configuration: unknown profile %q", profile)
		}
		p.kinds[profile] = map[catalog.Kind]Kind{}
		for name, k := range kinds {
			parsed, err := parseKind(catalog.Kind(name), k)
			if err != nil {
				return Policy{}, fmt.Errorf("policy: configuration: profile %q, kind %q: %w", profile, name, err)
			}
			p.kinds[profile][catalog.Kind(name)] = parsed
		}
	}
	return p, nil
}

// parseKind checks what the file says about one kind of configuration.
func parseKind(name catalog.Kind, k kind) (Kind, error) {
	known := false
	for _, other := range catalog.Kinds() {
		known = known || other == name
	}
	if !known {
		return Kind{}, errors.New("there is no such kind")
	}
	out := Kind{Release: ReleaseLabel}
	switch Decision(k.Change) {
	case Approval, Deny:
		out.Change = Decision(k.Change)
	default:
		return Kind{}, fmt.Errorf("change must be %q or %q", Approval, Deny)
	}
	switch name {
	case catalog.KindEntity:
		// The objects of this kind are the entities themselves, and an
		// entity is released by the control label only.
		if k.Release != nil && Release(*k.Release) != ReleaseLabel {
			return Kind{}, fmt.Errorf("release can only be %q: entities are released one by one", ReleaseLabel)
		}
	case catalog.KindLabel:
		// A label carries no label. Every label but the control label is
		// of this kind, and the file has nothing to choose.
		if k.Release != nil {
			return Kind{}, errors.New("release cannot be set: a label cannot carry a label")
		}
		out.Release = ReleaseAll
	default:
		if k.Release != nil {
			switch Release(*k.Release) {
			case ReleaseLabel, ReleaseAll:
				out.Release = Release(*k.Release)
			default:
				return Kind{}, fmt.Errorf("release must be %q or %q", ReleaseLabel, ReleaseAll)
			}
		}
	}
	if len(k.Objects) > 0 {
		if name != catalog.KindDashboard {
			return Kind{}, errors.New("objects can only be named for dashboards; other kinds are released by the control label")
		}
		for _, object := range k.Objects {
			if !dashboardShape.MatchString(object) {
				return Kind{}, fmt.Errorf("objects: %q is not a dashboard's URL path", object)
			}
		}
		out.Objects = append([]string{}, k.Objects...)
	}
	return out, nil
}

// Configuration returns what the policy says about a kind of configuration
// for a profile. It is denied unless the profile's tier R2 asks for
// approval and the kind does too.
func (p Policy) Configuration(profile string, name catalog.Kind) Kind {
	k, ok := p.kinds[profile][name]
	if !ok || k.Change != Approval || p.Decide(profile, catalog.R2) != Approval {
		return Kind{Change: Deny, Release: ReleaseLabel}
	}
	k.Objects = append([]string{}, k.Objects...)
	return k
}

// Decide returns the decision for a profile and a tier. A profile or a tier
// the policy does not mention is denied.
func (p Policy) Decide(profile string, tier catalog.Tier) Decision {
	switch d := p.profiles[profile][tier]; d {
	case Allow, Approval:
		return d
	default:
		return Deny
	}
}

// ControlLabel returns the id of the Home Assistant label an entity must
// carry for a tool to act on it.
func (p Policy) ControlLabel() string { return p.label }

// CallsPerMinute returns how many tool calls a client of the profile may
// make per minute. A profile the policy does not know gets the stricter of
// the defaults; it is denied every tier anyway.
func (p Policy) CallsPerMinute(profile string) int {
	if n, ok := p.limits[profile]; ok {
		return n
	}
	return defaultRemoteCallsPerMinute
}
