// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package policy_test

import (
	"strings"
	"testing"

	"github.com/SukramJ/ha-airlock/internal/catalog"
	"github.com/SukramJ/ha-airlock/internal/policy"
)

func TestDefaultLetsTheLocalProfileReadAndControlAfterApprovalAndNothingElse(t *testing.T) {
	t.Parallel()
	p := policy.Default()
	if p.ControlLabel() != "airlock" {
		t.Errorf("control label = %q, want airlock", p.ControlLabel())
	}
	for _, tier := range catalog.Tiers() {
		want := policy.Deny
		switch tier {
		case catalog.R0:
			want = policy.Allow
		case catalog.R1:
			want = policy.Approval
		case catalog.R2, catalog.R3, catalog.R4:
		}
		if got := p.Decide(policy.ProfileLocal, tier); got != want {
			t.Errorf("local, %s = %s, want %s", tier, got, want)
		}
		if got := p.Decide(policy.ProfileRemote, tier); got != policy.Deny {
			t.Errorf("remote, %s = %s, want deny", tier, got)
		}
		if got := p.Decide("", tier); got != policy.Deny {
			t.Errorf("no profile, %s = %s, want deny", tier, got)
		}
		if got := p.Decide("admin", tier); got != policy.Deny {
			t.Errorf("unknown profile, %s = %s, want deny", tier, got)
		}
	}
}

// Every tier can be set to every decision, for every profile, and a tier
// the file leaves out is denied. The one exception is its own test:
// configuration is never allowed outright.
func TestParseAppliesEachDecisionToEachTier(t *testing.T) {
	t.Parallel()
	for _, profile := range []string{policy.ProfileLocal, policy.ProfileRemote} {
		for _, tier := range catalog.Tiers() {
			for _, decision := range []policy.Decision{policy.Allow, policy.Deny} {
				if tier == catalog.R2 && decision == policy.Allow {
					continue
				}
				text := `{"version":1,"profiles":{"` + profile + `":{"` + string(tier) + `":"` + string(decision) + `"}}}`
				p, err := policy.Parse([]byte(text))
				if err != nil {
					t.Fatalf("parse %s: %v", text, err)
				}
				if got := p.Decide(profile, tier); got != decision {
					t.Errorf("%s: %s, %s = %s", text, profile, tier, got)
				}
				for _, other := range catalog.Tiers() {
					if other != tier && p.Decide(profile, other) != policy.Deny {
						t.Errorf("%s: tier %s, not mentioned, is not denied", text, other)
					}
				}
			}
		}
	}
}

func TestParseRejectsWhatItDoesNotKnow(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"unknown key":                 `{"version":1,"profiles":{},"never":[]}`,
		"unknown profile":             `{"version":1,"profiles":{"admin":{"R0":"allow"}}}`,
		"unknown tier":                `{"version":1,"profiles":{"local":{"R9":"allow"}}}`,
		"misspelt tier":               `{"version":1,"profiles":{"local":{"r0":"allow"}}}`,
		"unknown decision":            `{"version":1,"profiles":{"local":{"R1":"ask"}}}`,
		"empty control label":         `{"version":1,"profiles":{},"control_label":""}`,
		"control label with a space":  `{"version":1,"profiles":{},"control_label":"my label"}`,
		"control label of wrong type": `{"version":1,"profiles":{},"control_label":7}`,
		"misspelt decision":           `{"version":1,"profiles":{"local":{"R0":"Allow"}}}`,
		"missing version":             `{"profiles":{"local":{"R0":"allow"}}}`,
		"other version":               `{"version":2,"profiles":{}}`,
		"not JSON":                    `version: 1`,
		"two values":                  `{"version":1,"profiles":{}} {"version":1,"profiles":{}}`,
		"decision of the wrong type":  `{"version":1,"profiles":{"local":{"R0":true}}}`,
	}
	for name, text := range cases {
		if _, err := policy.Parse([]byte(text)); err == nil {
			t.Errorf("%s: accepted %s", name, text)
		} else if !strings.HasPrefix(err.Error(), "policy: ") {
			t.Errorf("%s: error %q does not name the policy", name, err)
		}
	}
}

func TestCallLimitsHaveDefaultsAndCanBeSet(t *testing.T) {
	t.Parallel()
	d := policy.Default()
	if d.CallsPerMinute(policy.ProfileLocal) != 60 || d.CallsPerMinute(policy.ProfileRemote) != 30 || d.CallsPerMinute("unknown") != 30 {
		t.Fatalf("default limits: local %d, remote %d, unknown %d",
			d.CallsPerMinute(policy.ProfileLocal), d.CallsPerMinute(policy.ProfileRemote), d.CallsPerMinute("unknown"))
	}

	p, err := policy.Parse([]byte(`{"version":1,"profiles":{},"limits":{"remote":{"calls_per_minute":5}}}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.CallsPerMinute(policy.ProfileRemote) != 5 || p.CallsPerMinute(policy.ProfileLocal) != 60 {
		t.Fatalf("limits: remote %d, local %d", p.CallsPerMinute(policy.ProfileRemote), p.CallsPerMinute(policy.ProfileLocal))
	}

	for name, text := range map[string]string{
		"unknown profile": `{"version":1,"profiles":{},"limits":{"admin":{"calls_per_minute":5}}}`,
		"zero":            `{"version":1,"profiles":{},"limits":{"local":{"calls_per_minute":0}}}`,
		"negative":        `{"version":1,"profiles":{},"limits":{"local":{"calls_per_minute":-1}}}`,
		"too large":       `{"version":1,"profiles":{},"limits":{"local":{"calls_per_minute":100000}}}`,
		"unknown key":     `{"version":1,"profiles":{},"limits":{"local":{"calls_per_hour":5}}}`,
		"missing value":   `{"version":1,"profiles":{},"limits":{"local":{}}}`,
	} {
		if _, err := policy.Parse([]byte(text)); err == nil {
			t.Errorf("%s: accepted %s", name, text)
		}
	}
}

func TestParseReadsTheApprovalDecisionAndTheControlLabel(t *testing.T) {
	t.Parallel()
	p, err := policy.Parse([]byte(`{"version":1,"profiles":{"local":{"R0":"approval","R1":"allow"},"remote":{"R1":"approval"}},"control_label":"ai_may_switch"}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Decide(policy.ProfileLocal, catalog.R0) != policy.Approval || p.Decide(policy.ProfileLocal, catalog.R1) != policy.Allow ||
		p.Decide(policy.ProfileRemote, catalog.R1) != policy.Approval || p.Decide(policy.ProfileRemote, catalog.R0) != policy.Deny {
		t.Fatal("the decisions are not the ones the file names")
	}
	if p.ControlLabel() != "ai_may_switch" {
		t.Fatalf("control label = %q", p.ControlLabel())
	}

	plain, err := policy.Parse([]byte(`{"version":1,"profiles":{}}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if plain.ControlLabel() != "airlock" {
		t.Fatalf("control label of a file that names none = %q, want airlock", plain.ControlLabel())
	}
}

// No policy file lets configuration be changed without an approval.
func TestConfigurationCannotBeAllowedWithoutApproval(t *testing.T) {
	t.Parallel()
	for _, profile := range []string{policy.ProfileLocal, policy.ProfileRemote} {
		text := `{"version":1,"profiles":{"` + profile + `":{"R2":"allow"}}}`
		if _, err := policy.Parse([]byte(text)); err == nil || !strings.Contains(err.Error(), "R2 cannot be allowed without approval") {
			t.Errorf("%s: err = %v", text, err)
		}
		text = `{"version":1,"profiles":{"` + profile + `":{"R2":"approval"}}}`
		p, err := policy.Parse([]byte(text))
		if err != nil || p.Decide(profile, catalog.R2) != policy.Approval {
			t.Errorf("%s: %v", text, err)
		}
	}
}

// A kind of configuration can be changed only if the profile's tier R2 and
// the kind itself both ask for approval. Every other combination, a kind
// the file leaves out and the default policy are a denial.
func TestKindIsDeniedUnlessTierAndKindBothAskForApproval(t *testing.T) {
	t.Parallel()
	for _, profile := range []string{policy.ProfileLocal, policy.ProfileRemote} {
		for _, kind := range catalog.Kinds() {
			if got := policy.Default().Configuration(profile, kind); got.Change != policy.Deny {
				t.Errorf("default policy: %s, %s = %s", profile, kind, got.Change)
			}
			for _, tier := range []string{`"R2":"approval"`, `"R2":"deny"`, `"R0":"allow"`} {
				for _, change := range []policy.Decision{policy.Approval, policy.Deny} {
					text := `{"version":1,"profiles":{"` + profile + `":{` + tier + `}},"configuration":{"` + profile +
						`":{"` + string(kind) + `":{"change":"` + string(change) + `"}}}}`
					p, err := policy.Parse([]byte(text))
					if err != nil {
						t.Fatalf("parse %s: %v", text, err)
					}
					want := policy.Deny
					if tier == `"R2":"approval"` && change == policy.Approval {
						want = policy.Approval
					}
					if got := p.Configuration(profile, kind).Change; got != want {
						t.Errorf("%s: %s = %s, want %s", text, kind, got, want)
					}
					for _, other := range catalog.Kinds() {
						if other != kind && p.Configuration(profile, other).Change != policy.Deny {
							t.Errorf("%s: kind %s, not mentioned, is not denied", text, other)
						}
					}
					otherProfile := policy.ProfileRemote
					if profile == policy.ProfileRemote {
						otherProfile = policy.ProfileLocal
					}
					if p.Configuration(otherProfile, kind).Change != policy.Deny {
						t.Errorf("%s: the other profile is not denied", text)
					}
				}
			}
		}
	}
}

func parseKinds(t *testing.T, kinds string) (policy.Policy, error) {
	t.Helper()
	return policy.Parse([]byte(`{"version":1,"profiles":{"local":{"R2":"approval"}},"configuration":{"local":{` + kinds + `}}}`))
}

// Objects of a kind are released by the control label unless the file says
// all. Entities are released one by one whatever the file says, a label
// carries no label, and only dashboards are named.
func TestReleaseOfAKindIsByLabelUnlessTheFileSaysAll(t *testing.T) {
	t.Parallel()
	for _, kind := range catalog.Kinds() {
		p, err := parseKinds(t, `"`+string(kind)+`":{"change":"approval"}`)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		want := policy.ReleaseLabel
		if kind == catalog.KindLabel {
			want = policy.ReleaseAll
		}
		if got := p.Configuration("local", kind).Release; got != want {
			t.Errorf("%s without release = %s, want %s", kind, got, want)
		}

		p, err = parseKinds(t, `"`+string(kind)+`":{"change":"approval","release":"all"}`)
		switch kind {
		case catalog.KindEntity, catalog.KindLabel:
			if err == nil {
				t.Errorf("%s: release all was accepted", kind)
			}
		default:
			if err != nil || p.Configuration("local", kind).Release != policy.ReleaseAll {
				t.Errorf("%s: release all: %v", kind, err)
			}
		}

		_, err = parseKinds(t, `"`+string(kind)+`":{"change":"approval","objects":["lovelace-test"]}`)
		if (kind == catalog.KindDashboard) != (err == nil) {
			t.Errorf("%s: objects named: err = %v", kind, err)
		}
	}

	p, err := parseKinds(t, `"dashboard":{"change":"approval","objects":["lovelace-test","energy_2"]}`)
	if err != nil {
		t.Fatal(err)
	}
	got := p.Configuration("local", catalog.KindDashboard)
	if got.Release != policy.ReleaseLabel || len(got.Objects) != 2 || got.Objects[0] != "lovelace-test" || got.Objects[1] != "energy_2" {
		t.Fatalf("dashboards = %+v", got)
	}
	// What the policy hands out is a copy.
	got.Objects[0] = "changed"
	if p.Configuration("local", catalog.KindDashboard).Objects[0] != "lovelace-test" {
		t.Fatal("the policy's list of dashboards was changed from outside")
	}
	// A denied kind names nothing.
	if denied := policy.Default().Configuration("local", catalog.KindDashboard); len(denied.Objects) != 0 || denied.Release != policy.ReleaseLabel {
		t.Fatalf("denied kind = %+v", denied)
	}
}

func TestParseRejectsWhatItDoesNotKnowAboutConfiguration(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"unknown kind":             `"blueprint":{"change":"approval"}`,
		"plural kind":              `"helpers":{"change":"approval"}`,
		"change allowed outright":  `"helper":{"change":"allow"}`,
		"change missing":           `"helper":{"release":"all"}`,
		"unknown change":           `"helper":{"change":"ask"}`,
		"unknown release":          `"helper":{"change":"approval","release":"some"}`,
		"unknown key":              `"helper":{"change":"approval","labels":["x"]}`,
		"entity released as a lot": `"entity":{"change":"approval","release":"all"}`,
		"label with a release":     `"label":{"change":"approval","release":"label"}`,
		"objects for a helper":     `"helper":{"change":"approval","objects":["input_boolean.x"]}`,
		"dashboard path with a /":  `"dashboard":{"change":"approval","objects":["a/b"]}`,
		"empty dashboard path":     `"dashboard":{"change":"approval","objects":[""]}`,
		"kind of the wrong type":   `"helper":"approval"`,
	}
	for name, kinds := range cases {
		if _, err := parseKinds(t, kinds); err == nil {
			t.Errorf("%s: accepted %s", name, kinds)
		} else if !strings.HasPrefix(err.Error(), "policy: ") {
			t.Errorf("%s: error %q does not name the policy", name, err)
		}
	}
	if _, err := policy.Parse([]byte(`{"version":1,"profiles":{},"configuration":{"admin":{}}}`)); err == nil {
		t.Error("an unknown profile under configuration was accepted")
	}
}
