// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package policy_test

import (
	"strings"
	"testing"

	"github.com/SukramJ/ha-airlock/internal/catalog"
	"github.com/SukramJ/ha-airlock/internal/policy"
)

func TestDefaultAllowsTheLocalProfileToReadAndNothingElse(t *testing.T) {
	t.Parallel()
	p := policy.Default()
	for _, tier := range catalog.Tiers() {
		want := policy.Deny
		if tier == catalog.R0 {
			want = policy.Allow
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
// the file leaves out is denied.
func TestParseAppliesEachDecisionToEachTier(t *testing.T) {
	t.Parallel()
	for _, profile := range []string{policy.ProfileLocal, policy.ProfileRemote} {
		for _, tier := range catalog.Tiers() {
			for _, decision := range []policy.Decision{policy.Allow, policy.Deny} {
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
		"unknown key":                `{"version":1,"profiles":{},"never":[]}`,
		"unknown profile":            `{"version":1,"profiles":{"admin":{"R0":"allow"}}}`,
		"unknown tier":               `{"version":1,"profiles":{"local":{"R9":"allow"}}}`,
		"misspelt tier":              `{"version":1,"profiles":{"local":{"r0":"allow"}}}`,
		"unknown decision":           `{"version":1,"profiles":{"local":{"R1":"approval"}}}`,
		"misspelt decision":          `{"version":1,"profiles":{"local":{"R0":"Allow"}}}`,
		"missing version":            `{"profiles":{"local":{"R0":"allow"}}}`,
		"other version":              `{"version":2,"profiles":{}}`,
		"not JSON":                   `version: 1`,
		"two values":                 `{"version":1,"profiles":{}} {"version":1,"profiles":{}}`,
		"decision of the wrong type": `{"version":1,"profiles":{"local":{"R0":true}}}`,
	}
	for name, text := range cases {
		if _, err := policy.Parse([]byte(text)); err == nil {
			t.Errorf("%s: accepted %s", name, text)
		} else if !strings.HasPrefix(err.Error(), "policy: ") {
			t.Errorf("%s: error %q does not name the policy", name, err)
		}
	}
}
