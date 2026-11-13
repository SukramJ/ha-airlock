// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 SukramJ.

package catalog

import (
	"encoding/json"
	"strings"
	"testing"
)

var declaredHelperDomains = []helperDomain{
	inputBoolean, inputNumber, inputText, inputSelect, inputDatetime, inputButton, counterHelper, timerHelper,
}

func decodeState(t *testing.T, text string) map[string]json.RawMessage {
	t.Helper()
	given := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(text), &given); err != nil {
		t.Fatalf("test state %s: %v", text, err)
	}
	return given
}

func TestEveryHelperFieldSchemaIsValidJSON(t *testing.T) {
	for _, d := range declaredHelperDomains {
		for _, f := range d.fields {
			var schema map[string]json.RawMessage
			if err := json.Unmarshal([]byte(f.schema), &schema); err != nil {
				t.Errorf("%s.%s: schema is not a JSON object: %v", d.domain, f.name, err)
				continue
			}
			if _, ok := schema["type"]; !ok {
				t.Errorf("%s.%s: schema has no type", d.domain, f.name)
			}
			var description string
			if err := json.Unmarshal(schema["description"], &description); err != nil || description == "" {
				t.Errorf("%s.%s: schema has no description", d.domain, f.name)
			}
		}
	}
}

func TestHelperDomainsAcceptWhatHomeAssistantStores(t *testing.T) {
	cases := []struct {
		domain helperDomain
		state  string
	}{
		{inputNumber, `{"name":"Volume","min":0.0,"max":100.0,"step":1.0,"mode":"slider"}`},
		{inputNumber, `{"name":"Volume","min":0,"max":100,"initial":5,"step":0.5,"mode":"box","icon":"mdi:volume-high","unit_of_measurement":"%","device_class":"sound_pressure"}`},
		{inputText, `{"name":"Note","min":0,"max":100,"initial":"","mode":"text"}`},
		{inputText, `{"name":"Note","min":0,"max":255,"pattern":"^[a-z]*$","unit_of_measurement":"","icon":"mdi:note"}`},
		{inputSelect, `{"name":"Mode","options":["home","away"]}`},
		{inputSelect, `{"name":"Mode","options":["home"],"initial":"home","icon":"mdi:home"}`},
		{inputDatetime, `{"name":"Wake","has_date":false,"has_time":true}`},
		{inputDatetime, `{"name":"Wake","has_date":true,"has_time":true,"initial":"2026-01-01 07:00:00","icon":"mdi:alarm"}`},
		{inputButton, `{"name":"Ring"}`},
		{inputButton, `{"name":"Ring","icon":"mdi:bell"}`},
		{counterHelper, `{"name":"Visits","initial":0,"maximum":null,"minimum":null,"restore":true,"step":1}`},
		{counterHelper, `{"name":"Visits","initial":-3,"maximum":10,"minimum":-10,"restore":false,"step":2,"icon":"mdi:counter"}`},
		{timerHelper, `{"name":"Tea","duration":"0:05:00","restore":false}`},
		{timerHelper, `{"name":"Tea","duration":"1234:59:59","icon":"mdi:timer"}`},
	}
	for _, c := range cases {
		if _, err := c.domain.state(decodeState(t, c.state), ""); err != nil {
			t.Errorf("%s %s: refused: %v", c.domain.domain, c.state, err)
		}
	}
}

func TestHelperDomainsRefuseWhatTheyDoNotDeclare(t *testing.T) {
	long := `"` + strings.Repeat("a", 256) + `"`
	cases := []struct {
		domain helperDomain
		state  string
		want   string
	}{
		// Required fields.
		{inputNumber, `{"min":0,"max":1}`, "name is required"},
		{inputNumber, `{"name":"N","max":1}`, "min is required"},
		{inputNumber, `{"name":"N","min":0}`, "max is required"},
		{inputSelect, `{"name":"S"}`, "options is required"},
		{inputButton, `{}`, "name is required"},

		// input_number.
		{inputNumber, `{"name":"N","min":"0","max":1}`, "min must be a number"},
		{inputNumber, `{"name":"N","min":null,"max":1}`, "min must be a number"},
		{inputNumber, `{"name":"N","min":0,"max":true}`, "max must be a number"},
		{inputNumber, `{"name":"N","min":0,"max":1,"initial":"1"}`, "initial must be a number"},
		{inputNumber, `{"name":"N","min":0,"max":1,"step":0}`, "step must be a number greater than 0"},
		{inputNumber, `{"name":"N","min":0,"max":1,"step":-1}`, "step must be a number greater than 0"},
		{inputNumber, `{"name":"N","min":0,"max":1,"step":"1"}`, "step must be a number greater than 0"},
		{inputNumber, `{"name":"N","min":0,"max":1,"icon":"volume"}`, "icon must have the form"},
		{inputNumber, `{"name":"N","min":0,"max":1,"unit_of_measurement":5}`, "unit_of_measurement must be a string"},
		{inputNumber, `{"name":"N","min":0,"max":1,"unit_of_measurement":"a\u0007b"}`, "unit_of_measurement must not contain control characters"},
		{inputNumber, `{"name":"N","min":0,"max":1,"unit_of_measurement":` + long + `}`, "unit_of_measurement must have at most 255 characters"},
		{inputNumber, `{"name":"N","min":0,"max":1,"device_class":"Sound Pressure"}`, "device_class must have the form"},
		{inputNumber, `{"name":"N","min":0,"max":1,"device_class":1}`, "device_class must have the form"},
		{inputNumber, `{"name":"N","min":0,"max":1,"mode":"dial"}`, "mode must be one of box, slider"},
		{inputNumber, `{"name":"N","min":0,"max":1,"mode":1}`, "mode must be one of box, slider"},
		{inputNumber, `{"name":"N","min":0,"max":1,"options":[]}`, `unknown field "options"`},

		// input_text.
		{inputText, `{"name":"T","min":5.0}`, "min must be an integer between 0 and 255"},
		{inputText, `{"name":"T","min":-1}`, "min must be an integer between 0 and 255"},
		{inputText, `{"name":"T","min":"0"}`, "min must be an integer between 0 and 255"},
		{inputText, `{"name":"T","max":0}`, "max must be an integer between 1 and 255"},
		{inputText, `{"name":"T","max":256}`, "max must be an integer between 1 and 255"},
		{inputText, `{"name":"T","max":1e2}`, "max must be an integer between 1 and 255"},
		{inputText, `{"name":"T","initial":5}`, "initial must be a string"},
		{inputText, `{"name":"T","initial":null}`, "initial must be a string"},
		{inputText, `{"name":"T","initial":` + long + `}`, "initial must have at most 255 characters"},
		{inputText, `{"name":"T","icon":1}`, "icon must have the form"},
		{inputText, `{"name":"T","unit_of_measurement":[]}`, "unit_of_measurement must be a string"},
		{inputText, `{"name":"T","pattern":true}`, "pattern must be a string"},
		{inputText, `{"name":"T","mode":"password"}`, `mode "password" is not offered: the helper would hold a secret`},
		{inputText, `{"name":"T","mode":"box"}`, "mode must be text"},
		{inputText, `{"name":"T","mode":1}`, "mode must be text"},
		{inputText, `{"name":"T","options":["a"]}`, `unknown field "options"`},

		// input_select.
		{inputSelect, `{"name":"S","options":"a"}`, "options must be an array of strings"},
		{inputSelect, `{"name":"S","options":null}`, "options must be an array of strings"},
		{inputSelect, `{"name":"S","options":[]}`, "options must have between 1 and 100 entries"},
		{inputSelect, `{"name":"S","options":["a","a"]}`, `options must not contain "a" twice`},
		{inputSelect, `{"name":"S","options":["a",""]}`, "options must not contain an empty entry"},
		{inputSelect, `{"name":"S","options":["a","  "]}`, "options must not contain an empty entry"},
		{inputSelect, `{"name":"S","options":["a",1]}`, "each entry of options must be a string"},
		{inputSelect, `{"name":"S","options":["a",` + long + `]}`, "each entry of options must have at most 255 characters"},
		{inputSelect, `{"name":"S","options":["a"],"initial":1}`, "initial must be a string"},
		{inputSelect, `{"name":"S","options":["a"],"icon":"a"}`, "icon must have the form"},
		{inputSelect, `{"name":"S","options":["a"],"mode":"box"}`, `unknown field "mode"`},

		// input_datetime.
		{inputDatetime, `{"name":"D","has_date":"yes"}`, "has_date must be true or false"},
		{inputDatetime, `{"name":"D","has_time":1}`, "has_time must be true or false"},
		{inputDatetime, `{"name":"D","icon":"x"}`, "icon must have the form"},
		{inputDatetime, `{"name":"D","initial":7}`, "initial must be a string"},
		{inputDatetime, `{"name":"D","duration":"0:00:01"}`, `unknown field "duration"`},

		// input_button.
		{inputButton, `{"name":"B","icon":true}`, "icon must have the form"},
		{inputButton, `{"name":"B","initial":true}`, `unknown field "initial"`},

		// counter.
		{counterHelper, `{"name":"C","icon":"c"}`, "icon must have the form"},
		{counterHelper, `{"name":"C","initial":5.0}`, "initial must be an integer"},
		{counterHelper, `{"name":"C","initial":null}`, "initial must be an integer"},
		{counterHelper, `{"name":"C","initial":"5"}`, "initial must be an integer"},
		{counterHelper, `{"name":"C","maximum":5.5}`, "maximum must be an integer or null"},
		{counterHelper, `{"name":"C","maximum":"5"}`, "maximum must be an integer or null"},
		{counterHelper, `{"name":"C","minimum":false}`, "minimum must be an integer or null"},
		{counterHelper, `{"name":"C","restore":"true"}`, "restore must be true or false"},
		{counterHelper, `{"name":"C","step":0}`, "step must be an integer of at least 1"},
		{counterHelper, `{"name":"C","step":-1}`, "step must be an integer of at least 1"},
		{counterHelper, `{"name":"C","step":1.0}`, "step must be an integer of at least 1"},
		{counterHelper, `{"name":"C","step":99999999999999999999}`, "step must be an integer of at least 1"},
		{counterHelper, `{"name":"C","mode":"box"}`, `unknown field "mode"`},

		// timer.
		{timerHelper, `{"name":"T","icon":"t"}`, "icon must have the form"},
		{timerHelper, `{"name":"T","duration":"5 minutes"}`, "duration must have the form hours:minutes:seconds"},
		{timerHelper, `{"name":"T","duration":"0:61:00"}`, "duration must have the form hours:minutes:seconds"},
		{timerHelper, `{"name":"T","duration":"0:00:60"}`, "duration must have the form hours:minutes:seconds"},
		{timerHelper, `{"name":"T","duration":300}`, "duration must have the form hours:minutes:seconds"},
		{timerHelper, `{"name":"T","restore":"no"}`, "restore must be true or false"},
		{timerHelper, `{"name":"T","initial":"0:00:01"}`, `unknown field "initial"`},
	}
	for _, c := range cases {
		_, err := c.domain.state(decodeState(t, c.state), "")
		if err == nil {
			t.Errorf("%s %s: accepted, want %q", c.domain.domain, c.state, c.want)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %s: refused with %q, want %q", c.domain.domain, c.state, err, c.want)
		}
	}
}
