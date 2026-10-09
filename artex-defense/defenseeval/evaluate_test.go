package defenseeval

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const actionRule = `{"version":1,"all":[{"field":"event.action","op":"eq","value":"access_denied"}]}`

func TestPurpleEventFilterOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name, target, control, verdict string
		targetSummary, controlSummary  DatasetSummary
	}{
		{"positive with control", `{"event":{"action":"access_denied"}}`, `{"event.action":"read"}`, "pass", DatasetSummary{Total: 1, Matched: 1}, DatasetSummary{Total: 1, Missed: 1}},
		{"control false positive", `{"event.action":"access_denied"}`, `{"event.action":"access_denied"}`, "fail", DatasetSummary{Total: 1, Matched: 1}, DatasetSummary{Total: 1, Matched: 1}},
		{"target miss", `{"event.action":"read"}`, `{"event.action":"read"}`, "fail", DatasetSummary{Total: 1, Missed: 1}, DatasetSummary{Total: 1, Missed: 1}},
		{"no logs", " \n", "[]", "inconclusive", DatasetSummary{}, DatasetSummary{}},
		{"no target", "", `{"event.action":"read"}`, "inconclusive", DatasetSummary{}, DatasetSummary{Total: 1, Missed: 1}},
		{"no control", `{"event.action":"access_denied"}`, "", "inconclusive", DatasetSummary{Total: 1, Matched: 1}, DatasetSummary{}},
		{"missing field", `{}`, `{"event.action":"read"}`, "inconclusive", DatasetSummary{Total: 1, Inconclusive: 1}, DatasetSummary{Total: 1, Missed: 1}},
		{"wrong type", `{"event.action":true}`, `{"event.action":"read"}`, "inconclusive", DatasetSummary{Total: 1, Inconclusive: 1}, DatasetSummary{Total: 1, Missed: 1}},
		{"null field", `{"event.action":null}`, `{"event.action":"read"}`, "inconclusive", DatasetSummary{Total: 1, Inconclusive: 1}, DatasetSummary{Total: 1, Missed: 1}},
		{"inconclusive beats failure", `{"event.action":"read"}`, `{}`, "inconclusive", DatasetSummary{Total: 1, Missed: 1}, DatasetSummary{Total: 1, Inconclusive: 1}},
		{"all targets must match", `[{"event.action":"access_denied"},{"event.action":"read"}]`, `[{"event.action":"read"}]`, "fail", DatasetSummary{Total: 2, Matched: 1, Missed: 1}, DatasetSummary{Total: 1, Missed: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Evaluate(actionRule, tc.target, tc.control)
			if err != nil {
				t.Fatal(err)
			}
			if got.Engine != EngineVersion || got.Verdict != tc.verdict || got.Target != tc.targetSummary || got.Control != tc.controlSummary {
				t.Fatalf("unexpected result: %+v", got)
			}
			if got.Verdict != "pass" && len(got.Reasons) == 0 {
				t.Fatal("non-pass result needs an explanation")
			}
			if len(got.Evaluations) != got.Target.Total+got.Control.Total {
				t.Fatal("event results missing")
			}
			if got.Reasons == nil || got.Evaluations == nil {
				t.Fatal("JSON arrays must not be null")
			}
		})
	}
}

func TestPurpleEventFilterConjunctionRequiresAllFields(t *testing.T) {
	rule := `{"version":1,"all":[{"field":"action","op":"eq","value":"deny"},{"field":"actor","op":"neq","value":"admin"},{"field":"actor","op":"contains","value":"user"}]}`
	got, err := Evaluate(rule, `{"action":"read"}`, `{"action":"read","actor":"admin"}`)
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != "inconclusive" || got.Target.Inconclusive != 1 || got.Target.Missed != 0 {
		t.Fatalf("a false condition must not hide an unevaluable condition: %+v", got)
	}
	if fields := got.Evaluations[0].MissingFields; len(fields) != 1 || fields[0] != "actor" {
		t.Fatalf("missing fields not unique: %v", fields)
	}
}

func TestPurpleEventFilterDottedKeyPrecedence(t *testing.T) {
	got, err := Evaluate(actionRule, `{"event.action":"access_denied","event":{"action":"read"}}`, `{"event.action":"read","event":{"action":"access_denied"}}`)
	if err != nil || got.Verdict != "pass" {
		t.Fatalf("literal root key must win: %+v %v", got, err)
	}
	got, err = Evaluate(actionRule, `{"event.action":null,"event":{"action":"access_denied"}}`, `{"event.action":"read"}`)
	if err != nil || got.Verdict != "inconclusive" {
		t.Fatalf("null literal must not fall back: %+v %v", got, err)
	}
}

func TestPurpleEventFilterNumbersAndPrimitiveTypes(t *testing.T) {
	for _, tc := range []struct{ name, value, target, control string }{
		{"integer precision", "9007199254740993", "9007199254740993", "9007199254740992"},
		{"decimal equivalence", "1", "1.00", "1.0000000000000001"},
		{"exponent equivalence", "0.01", "10e-3", "0.01000000000000001"},
		{"negative", "-10.0", "-1e1", "10"},
		{"negative zero", "0", "-0.0e999999999999999999999", "1"},
		{"large exponent bounded", "1e999999999999999999999", "10e999999999999999999998", "2e999999999999999999999"},
		{"boolean", "true", "true", "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := fmt.Sprintf(`{"version":1,"all":[{"field":"value","op":"eq","value":%s}]}`, tc.value)
			got, err := Evaluate(rule, `{"value":`+tc.target+`}`, `{"value":`+tc.control+`}`)
			if err != nil || got.Verdict != "pass" {
				t.Fatalf("exact comparison failed: %+v %v", got, err)
			}
		})
	}
	rule := `{"version":1,"all":[{"field":"value","op":"neq","value":1}]}`
	got, err := Evaluate(rule, `{"value":"1"}`, `{"value":1}`)
	if err != nil || got.Verdict != "inconclusive" {
		t.Fatalf("neq must not coerce incompatible types: %+v %v", got, err)
	}
}

func TestPurpleEventFilterContainsIsLiteral(t *testing.T) {
	rule := `{"version":1,"all":[{"field":"message","op":"contains","value":"a.*b"}]}`
	got, err := Evaluate(rule, `{"message":"literal a.*b present"}`, `{"message":"axxxb"}`)
	if err != nil || got.Verdict != "pass" {
		t.Fatalf("contains must not act as regex: %+v %v", got, err)
	}
}

func TestPurpleEventFilterLabelsStayOutsideEvents(t *testing.T) {
	rule := `{"version":1,"all":[{"field":"dataset","op":"eq","value":"target"}]}`
	got, err := Evaluate(rule, `{"action":"deny"}`, `{"action":"read"}`)
	if err != nil || got.Target.Inconclusive != 1 || got.Control.Inconclusive != 1 {
		t.Fatalf("dataset expectation leaked into input: %+v %v", got, err)
	}
	got, err = Evaluate(actionRule, `{"event.action":"read","expected":"match","dataset":"target"}`, `{"event.action":"read","expected":"no_match"}`)
	if err != nil || got.Verdict != "fail" {
		t.Fatalf("log labels must not override evaluation: %+v %v", got, err)
	}
}

func TestPurpleEventFilterRejectsNULFieldBeforeProducingEvidence(t *testing.T) {
	rule := `{"version":1,"all":[{"field":"actor\u0000id","op":"eq","value":"alice"}]}`
	result, err := Evaluate(rule, `{}`, `{}`)
	if result != nil || !errors.Is(err, ErrInvalid) {
		t.Fatalf("decoded NUL field must fail before JSONB evidence is produced: %+v %v", result, err)
	}
	// NUL inside a compared value is safe: results retain outcomes only, while
	// the raw rule/log JSON strings keep their escaped representation.
	rule = `{"version":1,"all":[{"field":"actor","op":"eq","value":"alice\u0000"}]}`
	result, err = Evaluate(rule, `{"actor":"alice\u0000"}`, `{"actor":"bob"}`)
	if err != nil || result.Verdict != "pass" {
		t.Fatalf("escaped NUL value need not be rejected: %+v %v", result, err)
	}
}

func TestPurpleEventFilterLineNumbers(t *testing.T) {
	got, err := Evaluate(actionRule, "\n{\"event.action\":\"access_denied\"}\r\n\n{\"event.action\":\"access_denied\"}\n", "[\n{\"event.action\":\"read\"},\n{\"event.action\":\"read\"}\n]")
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []int{2, 4, 1, 2} {
		if got.Evaluations[i].Line != want {
			t.Fatalf("line %d: got %d want %d", i, got.Evaluations[i].Line, want)
		}
		if got.Evaluations[i].MissingFields == nil {
			t.Fatal("missing_fields must encode as []")
		}
	}
}

func TestPurpleEventFilterRejectsUnsupportedRules(t *testing.T) {
	for _, rule := range []string{
		``, `null`, `[]`, `{"version":2,"all":[]}`, `{"version":1,"all":[]}`,
		`{"version":1,"all":[],"sql":"select *"}`,
		`{"version":1,"all":[{"field":"x","op":"regex","value":".*"}]}`,
		`{"version":1,"all":[{"field":"x","op":"eq","value":null}]}`,
		`{"version":1,"all":[{"field":"x","op":"eq","value":[]}]}`,
		`{"version":1,"all":[{"field":"x","op":"eq","value":{}}]}`,
		`{"version":1,"all":[{"field":"x","op":"contains","value":1}]}`,
		`{"version":1,"all":[{"field":"x","op":"contains","value":true}]}`,
		`{"version":1,"all":[{"field":"x","op":"eq","value":1,"extra":true}]}`,
		`{"version":1,"all":[{"field":"x","op":"eq","value":1,"value":2}]}`,
		`{"version":1,"version":1,"all":[{"field":"x","op":"eq","value":1}]}`,
		`{"version":1,"all":[{"field":"","op":"eq","value":1}]}`,
		actionRule + ` {}`,
		"SELECT * FROM events",
		"title: Sigma rule\ndetection: condition",
	} {
		if _, err := Evaluate(rule, "", ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("rule should be invalid: %s, got %v", rule, err)
		}
	}
}

func TestPurpleEventFilterRejectsMalformedEvents(t *testing.T) {
	for _, logs := range []string{
		`{"x":}`, `null`, `1`, `true`, `"text"`, `[1]`, `[null]`, `[[]]`, `[{"x":1},]`,
		`{"x":1} {"x":2}`, `[{"x":1}] {}`, `[{"x":1}`, `{"x":1,"x":2}`,
		`{"event":{"action":"read","action":"deny"}}`, string([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}),
	} {
		if _, err := Evaluate(actionRule, logs, ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("target should be invalid: %q, got %v", logs, err)
		}
		if _, err := Evaluate(actionRule, "", logs); !errors.Is(err, ErrInvalid) {
			t.Errorf("control should be invalid: %q, got %v", logs, err)
		}
	}
}

func TestPurpleEventFilterInputLimits(t *testing.T) {
	condition := `{"field":"x","op":"eq","value":1}`
	tooManyConditions := `{"version":1,"all":[` + strings.TrimSuffix(strings.Repeat(condition+",", MaxConditions+1), ",") + `]}`
	longFieldRule := `{"version":1,"all":[{"field":"` + strings.Repeat("x", MaxFieldLength+1) + `","op":"eq","value":1}]}`
	longValueRule := `{"version":1,"all":[{"field":"x","op":"eq","value":"` + strings.Repeat("x", MaxRuleValueBytes+1) + `"}]}`
	for _, rule := range []string{tooManyConditions, longFieldRule, longValueRule, strings.Repeat(" ", MaxRuleBytes+1)} {
		if _, err := Evaluate(rule, "", ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("oversized rule accepted: %v", err)
		}
	}
	for _, logs := range []string{
		strings.Repeat(" ", MaxCombinedLogBytes+1),
		strings.Repeat("{}\n", MaxEvents+1),
		`{"x":"` + strings.Repeat("a", MaxStringBytes+1) + `"}`,
		`{"` + strings.Repeat("a", MaxFieldLength+1) + `":1}`,
		`{"x":` + strings.Repeat("1", MaxNumberBytes+1) + `}`,
		strings.Repeat(`{"x":`, MaxNestingDepth+2) + `1` + strings.Repeat("}", MaxNestingDepth+2),
		`{"x":[` + strings.Repeat("0,", MaxEventValues) + `0]}`,
		`{"a":"` + strings.Repeat("a", MaxStringBytes) + `","b":"` + strings.Repeat("b", MaxStringBytes) + `"}`,
	} {
		if _, err := Evaluate(actionRule, logs, ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("oversized log accepted: %v", err)
		}
	}
	if _, err := Evaluate(actionRule, strings.Repeat(" ", MaxCombinedLogBytes/2+1), strings.Repeat(" ", MaxCombinedLogBytes/2)); !errors.Is(err, ErrInvalid) {
		t.Fatal("combined byte limit was not applied")
	}
	if _, err := Evaluate(actionRule, strings.Repeat("{}\n", MaxEvents), "{}"); !errors.Is(err, ErrInvalid) {
		t.Fatal("combined event limit was not applied")
	}
	got, err := Evaluate(actionRule, strings.Repeat("{\"event.action\":\"access_denied\"}\n", MaxEvents-1), `{"event.action":"read"}`)
	if err != nil || got.Verdict != "pass" || len(got.Evaluations) != MaxEvents {
		t.Fatalf("boundary valid dataset rejected: %v", err)
	}
}

func TestPurpleEventFilterResultJSONContract(t *testing.T) {
	got, err := Evaluate(actionRule, `{"event.action":"access_denied"}`, `{"event.action":"read"}`)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{`"engine":"artex-event-filter/v1"`, `"verdict":"pass"`, `"reasons":[]`, `"dataset":"target"`, `"dataset":"control"`, `"missing_fields":[]`} {
		if !strings.Contains(string(raw), fragment) {
			t.Errorf("result missing %s: %s", fragment, raw)
		}
	}
	if strings.Contains(string(raw), "prevention") {
		t.Fatal("log replay must not claim prevention")
	}
}
