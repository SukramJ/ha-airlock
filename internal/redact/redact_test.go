// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package redact_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/SukramJ/ha-airlock/internal/redact"
)

func TestJSONRemovesValuesOfSensitiveKeys(t *testing.T) {
	t.Parallel()
	const secret = "s3cr3t-value-123"
	for _, key := range []string{
		"password", "Password", "db_password", "client_secret", "access_token", "refresh_token",
		"api_key", "apiKey", "private_key", "Authorization", "credentials", "webhook_id",
		"cloudhook_url", "latitude", "longitude",
	} {
		raw := `{"outer":[{"` + key + `":"` + secret + `","name":"kept"}]}`
		out, count, err := redact.JSON(json.RawMessage(raw))
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		if strings.Contains(string(out), secret) {
			t.Errorf("key %q: the value survived: %s", key, out)
		}
		if count != 1 {
			t.Errorf("key %q: %d redactions, want 1", key, count)
		}
		if !strings.Contains(string(out), `"name":"kept"`) {
			t.Errorf("key %q: a harmless value was lost: %s", key, out)
		}
	}
}

func TestJSONRemovesNonStringValuesOfSensitiveKeys(t *testing.T) {
	t.Parallel()
	out, count, err := redact.JSON(json.RawMessage(`{"latitude":52.5200,"token":{"a":"b"},"password":null}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "52.52") || strings.Contains(string(out), `"a"`) {
		t.Fatalf("a value survived: %s", out)
	}
	if count != 2 {
		t.Fatalf("%d redactions, want 2 (null is not a value to remove)", count)
	}
}

func TestStringRemovesCredentialShapes(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"jwt":            "token eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJhYmMifQ.c2lnbmF0dXJlLXZhbHVl rejected",
		"bearer header":  "Authorization: Bearer abcdefghijklmnop123456",
		"basic header":   "sent basic dXNlcjpwYXNzd29yZA== to host",
		"url userinfo":   "connecting to mqtt://homeassistant:hunter2pass@192.168.1.5:1883",
		"key equals":     "login failed for password=hunter2pass on host",
		"key colon json": `config was {"api_key": "abcd1234efgh"}`,
	}
	secrets := []string{"c2lnbmF0dXJlLXZhbHVl", "abcdefghijklmnop123456", "dXNlcjpwYXNzd29yZA==", "hunter2pass", "abcd1234efgh"}
	for name, text := range cases {
		out, count := redact.String(text)
		if count == 0 {
			t.Errorf("%s: nothing redacted in %q", name, text)
		}
		for _, secret := range secrets {
			if strings.Contains(out, secret) {
				t.Errorf("%s: %q survived in %q", name, secret, out)
			}
		}
	}
}

func TestJSONRedactsCredentialShapesInsideStrings(t *testing.T) {
	t.Parallel()
	raw := `{"entries":[{"message":["Error connecting to http://admin:hunter2pass@cam.local/stream"],"level":"ERROR"}]}`
	out, count, err := redact.JSON(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "hunter2pass") || count != 1 {
		t.Fatalf("out = %s, redactions = %d", out, count)
	}
	if !strings.Contains(string(out), `"level":"ERROR"`) {
		t.Fatalf("a harmless value was lost: %s", out)
	}
}

func TestJSONLeavesHarmlessDataAndNumbersAsTheyWere(t *testing.T) {
	t.Parallel()
	raw := `{"count":3,"big":12345678901234567890,"ratio":0.10,"name":"sensor.kitchen_temperature","ok":true,"none":null}`
	out, count, err := redact.JSON(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("%d redactions in harmless data: %s", count, out)
	}
	for _, want := range []string{`"big":12345678901234567890`, `"ratio":0.10`, `"name":"sensor.kitchen_temperature"`} {
		if !strings.Contains(string(out), want) {
			t.Errorf("%s is missing from %s", want, out)
		}
	}
}

func TestJSONRejectsWhatIsNotJSON(t *testing.T) {
	t.Parallel()
	if _, _, err := redact.JSON(json.RawMessage(`{"password": "x"`)); err == nil {
		t.Fatal("invalid JSON was accepted")
	}
}
