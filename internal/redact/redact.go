// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

// Package redact removes credentials and locations from data before it
// leaves ha-airlock. It is applied to every tool result and to everything
// the audit log stores about a call.
//
// It works on what data looks like, not on where it came from: a value is
// removed because of the name of its key, or because a string has the shape
// of a credential. That catches what Home Assistant's own diagnostics and
// logs are known to contain; it is not a proof that nothing sensitive is
// left.
package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Mark replaces a removed value.
const Mark = "[redacted]"

// sensitiveKeys are substrings of key names whose values are removed
// whatever they contain. Compared in lower case.
var sensitiveKeys = []string{
	"password", "passwd", "secret", "token", "api_key", "apikey", "access_key",
	"private_key", "authorization", "credential", "webhook_id", "cloudhook",
	"latitude", "longitude",
}

// patterns are shapes of credentials inside strings: log lines and
// messages carry them where no key name gives them away.
var patterns = []*regexp.Regexp{
	// JSON Web Tokens, the form of Home Assistant's access tokens.
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
	// A bearer or basic credential in a header rendered into text.
	regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`),
	// The user and password of a URL.
	regexp.MustCompile(`://[^/\s:@]+:[^/\s@]+@`),
	// key=value and key: value pairs whose key names a credential.
	regexp.MustCompile(`(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key)["']?\s*[=:]\s*["']?[^\s"',;&]{4,}`),
}

// JSON returns raw with sensitive values replaced, and how many were.
func JSON(raw json.RawMessage) (clean json.RawMessage, redactions int, err error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Numbers stay as written; decoding them to float64 would change them.
	dec.UseNumber()
	var value any // wire-decoded JSON before type-dispatch
	if err := dec.Decode(&value); err != nil {
		return nil, 0, fmt.Errorf("redact: %w", err)
	}
	count := 0
	value = walk(value, &count)
	out, err := json.Marshal(value)
	if err != nil {
		return nil, 0, fmt.Errorf("redact: %w", err)
	}
	return out, count, nil
}

// String returns s with credential-shaped parts replaced, and how many were.
func String(s string) (clean string, redactions int) {
	count := 0
	for _, pattern := range patterns {
		s = pattern.ReplaceAllStringFunc(s, func(string) string {
			count++
			return Mark
		})
	}
	return s, count
}

// walk redacts one decoded JSON value. any is the shape encoding/json gives
// a value whose structure is not known in advance.
func walk(value any, count *int) any {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			if isSensitiveKey(key) && child != nil {
				v[key] = Mark
				*count++
				continue
			}
			v[key] = walk(child, count)
		}
		return v
	case []any:
		for i, child := range v {
			v[i] = walk(child, count)
		}
		return v
	case string:
		out, n := String(v)
		*count += n
		return out
	default:
		return v
	}
}

func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, part := range sensitiveKeys {
		if strings.Contains(lower, part) {
			return true
		}
	}
	return false
}
