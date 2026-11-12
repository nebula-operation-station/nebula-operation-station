// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

func TestToolRegistryIsExactlyTheFixedSet(t *testing.T) {
	want := []string{ToolCVEDetails, ToolAdvisoryText, ToolPackageHistory, ToolBackportCheck, ToolExposure, ToolKEVEPSS, ToolSubmitAssessment}
	defs := ToolDefinitions()
	if len(defs) != len(want) {
		t.Fatalf("registry has %d tools, want %d", len(defs), len(want))
	}
	for i, d := range defs {
		if d.Name != want[i] {
			t.Errorf("tool %d = %q, want %q", i, d.Name, want[i])
		}
		var schema map[string]any
		if err := json.Unmarshal(d.Parameters, &schema); err != nil {
			t.Errorf("%s schema: %v", d.Name, err)
		}
		if schema["additionalProperties"] != false {
			t.Errorf("%s schema allows additional properties", d.Name)
		}
	}
	// A copy cannot change the registry.
	defs[0].Name = "shell_exec"
	if ToolDefinitions()[0].Name != ToolCVEDetails {
		t.Fatal("ToolDefinitions returned the registry itself")
	}
}

func TestLookupRejectsUnknownToolsAndInvalidArguments(t *testing.T) {
	tl := tools{snap: newFakeSnapshot(), view: newFakeSnapshot()}
	cases := []struct {
		name, tool, args string
		want             error
	}{
		{"unknown tool", "shell_exec", `{"cmd":"id"}`, ErrUnknownTool},
		{"submit is not a lookup", ToolSubmitAssessment, `{}`, ErrUnknownTool},
		{"case variant", "CVE_DETAILS", `{"vuln_id":"CVE-2026-0001"}`, ErrUnknownTool},
		{"unknown field", ToolCVEDetails, `{"vuln_id":"CVE-2026-0001","url":"http://x"}`, ErrInvalidArguments},
		{"case-folded field", ToolCVEDetails, `{"VULN_ID":"CVE-2026-0001"}`, ErrInvalidArguments},
		{"duplicate field", ToolCVEDetails, `{"vuln_id":"CVE-2026-0001","vuln_id":"CVE-2026-0002"}`, ErrInvalidArguments},
		{"missing field", ToolCVEDetails, `{}`, ErrInvalidArguments},
		{"null", ToolCVEDetails, `{"vuln_id":null}`, ErrInvalidArguments},
		{"number", ToolKEVEPSS, `{"vuln_id":5}`, ErrInvalidArguments},
		{"trailing data", ToolKEVEPSS, `{"vuln_id":"CVE-2026-0001"} {}`, ErrInvalidArguments},
		{"not an object", ToolKEVEPSS, `["CVE-2026-0001"]`, ErrInvalidArguments},
		{"bad pattern", ToolCVEDetails, `{"vuln_id":"../../etc/passwd"}`, ErrInvalidArguments},
		{"unknown source", ToolCVEDetails, `{"vuln_id":"CVE-2026-0001","source":"evil"}`, ErrInvalidArguments},
		{"bad finding key", ToolBackportCheck, `{"finding_key":"AAAA"}`, ErrInvalidArguments},
		{"bad ecosystem", ToolPackageHistory, `{"ecosystem":"Debian Bookworm","source_package":"openssl"}`, ErrInvalidArguments},
		{"not found", ToolKEVEPSS, `{"vuln_id":"CVE-2026-9999"}`, ErrNotFound},
		{"exposure unknown key", ToolExposure, `{"finding_key":"` + keyB + `"}`, ErrNotFound},
		{"invalid utf8", ToolKEVEPSS, "{\"vuln_id\":\"\xff\"}", ErrInvalidArguments},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := tl.execLookup(c.tool, c.args); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestLookupResultsCarryOneRecordText(t *testing.T) {
	tl := tools{snap: newFakeSnapshot(), view: newFakeSnapshot()}
	r, err := tl.execLookup(ToolCVEDetails, `{"vuln_id":"CVE-2026-0001"}`)
	if err != nil {
		t.Fatal(err)
	}
	// Source order puts debian-tracker before nvd.
	if r.record == nil || *r.record != (RecordRef{"debian-tracker", 3}) {
		t.Fatalf("record = %+v", r.record)
	}
	b, _ := json.Marshal(r.data)
	if strings.Contains(string(b), "NVD description") || !strings.Contains(string(b), "Tracker text") || !strings.Contains(string(b), "CVSS:3.1") {
		t.Fatalf("default result = %s", b)
	}
	r, err = tl.execLookup(ToolCVEDetails, `{"vuln_id":"CVE-2026-0001","source":"nvd"}`)
	if err != nil || r.record == nil || r.record.SourceID != "nvd" {
		t.Fatalf("named source: %+v %v", r.record, err)
	}
	for _, tc := range []struct{ tool, args string }{
		{ToolPackageHistory, `{"ecosystem":"debian:bookworm","source_package":"openssl"}`},
		{ToolExposure, `{"finding_key":"` + keyA + `"}`},
		{ToolKEVEPSS, `{"vuln_id":"CVE-2026-0001"}`},
	} {
		r, err := tl.execLookup(tc.tool, tc.args)
		if err != nil || r.record != nil {
			t.Errorf("%s: record %+v err %v, want untagged result", tc.tool, r.record, err)
		}
	}
	r, err = tl.execLookup(ToolBackportCheck, `{"finding_key":"`+keyA+`"}`)
	if err != nil || r.record == nil || r.record.SourceID != "debian-tracker" {
		t.Fatalf("backport: %+v %v", r.record, err)
	}
	b, _ = json.Marshal(r.data)
	if !strings.Contains(string(b), `"verdict":"affected"`) {
		t.Fatalf("backport verdict changed: %s", b)
	}
}

func TestToolResultIsCutToLimitAndStaysDelimited(t *testing.T) {
	tl := tools{snap: newFakeSnapshot(), view: newFakeSnapshot()}
	r, err := tl.execLookup(ToolAdvisoryText, `{"advisory_id":"DSA-6000-1"}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{DefaultMaxToolResultBytes, 1000, 300} {
		s, err := toolResultContent(ToolAdvisoryText, r, limit)
		if err != nil {
			t.Fatal(err)
		}
		if len(s) > limit {
			t.Fatalf("limit %d: result %d bytes", limit, len(s))
		}
		var env struct {
			Envelope string         `json:"envelope"`
			Data     map[string]any `json:"data"`
		}
		if err := json.Unmarshal([]byte(s), &env); err != nil || env.Envelope != envelopeUntrusted {
			t.Fatalf("limit %d: not a valid envelope: %v %q", limit, err, s)
		}
		if env.Data["cut"] != truncatedMarker || env.Data["record"] == nil {
			t.Fatalf("limit %d: no marker or record tag: %v", limit, env.Data)
		}
	}
}

func TestSubmitAssessmentSchema(t *testing.T) {
	ok := `{"text":"Fix via backport.\nUpdate openssl.","backport_checked":true,"likely_false_positive":false,"exploit_public":true,"rationale":"KEV listed"}`
	a, err := parseSubmit(ok)
	if err != nil || !a.BackportChecked || a.LikelyFalsePositive || !a.ExploitPublic || a.Rationale != "KEV listed" {
		t.Fatalf("valid payload: %+v %v", a, err)
	}
	if _, err := parseSubmit(`{"text":"` + strings.Repeat("x", MaxTextBytes) + `","backport_checked":true,"likely_false_positive":false,"exploit_public":true,"rationale":"` + strings.Repeat("y", MaxRationaleBytes) + `"}`); err != nil {
		t.Fatalf("payload at the limits rejected: %v", err)
	}
	bad := map[string]string{
		"text too long":     `{"text":"` + strings.Repeat("x", MaxTextBytes+1) + `","backport_checked":true,"likely_false_positive":false,"exploit_public":true,"rationale":""}`,
		"rationale long":    `{"text":"t","backport_checked":true,"likely_false_positive":false,"exploit_public":true,"rationale":"` + strings.Repeat("y", MaxRationaleBytes+1) + `"}`,
		"control char":      `{"text":"a\u0007b","backport_checked":true,"likely_false_positive":false,"exploit_public":true,"rationale":""}`,
		"escape sequence":   `{"text":"\u001b[31mred","backport_checked":true,"likely_false_positive":false,"exploit_public":true,"rationale":""}`,
		"bidi override":     `{"text":"a` + string(rune(0x202e)) + `b","backport_checked":true,"likely_false_positive":false,"exploit_public":true,"rationale":""}`,
		"lone surrogate":    `{"text":"a\ud800b","backport_checked":true,"likely_false_positive":false,"exploit_public":true,"rationale":""}`,
		"unknown field":     `{"text":"t","backport_checked":true,"likely_false_positive":false,"exploit_public":true,"rationale":"","state":"fixed"}`,
		"missing flag":      `{"text":"t","backport_checked":true,"likely_false_positive":false,"rationale":""}`,
		"string flag":       `{"text":"t","backport_checked":"true","likely_false_positive":false,"exploit_public":true,"rationale":""}`,
		"null text":         `{"text":null,"backport_checked":true,"likely_false_positive":false,"exploit_public":true,"rationale":""}`,
		"duplicate text":    `{"text":"a","text":"b","backport_checked":true,"likely_false_positive":false,"exploit_public":true,"rationale":""}`,
		"case-folded field": `{"Text":"t","backport_checked":true,"likely_false_positive":false,"exploit_public":true,"rationale":""}`,
		"trailing":          ok + `x`,
		"not json":          `PWNED`,
		"oversized raw":     padded(ok, MaxSubmitArgumentsBytes+1),
	}
	// The padded payload differs from ok only in whitespace: at the raw
	// limit it is accepted, so its rejection one byte over is the size check.
	if a, err := parseSubmit(padded(ok, MaxSubmitArgumentsBytes)); err != nil || a.Rationale != "KEV listed" {
		t.Fatalf("payload padded to the raw limit rejected: %v", err)
	}
	for name, p := range bad {
		if _, err := parseSubmit(p); !errors.Is(err, ErrInvalidArguments) {
			t.Errorf("%s: err = %v, want ErrInvalidArguments", name, err)
		}
	}
}

// padded inserts JSON whitespace after the opening brace of obj so the
// result is exactly n bytes long.
func padded(obj string, n int) string {
	return "{" + strings.Repeat(" ", n-len(obj)) + obj[1:]
}

func TestTextLimitsMatchFindingRecord(t *testing.T) {
	if MaxTextBytes != vulnfinding.MaxAssessmentBytes {
		t.Fatalf("MaxTextBytes %d != vulnfinding.MaxAssessmentBytes %d", MaxTextBytes, vulnfinding.MaxAssessmentBytes)
	}
	if MaxOperatorInstructionsBytes != vulnstore.MaxAgentOperatorText {
		t.Fatalf("operator limit %d != vulnstore %d", MaxOperatorInstructionsBytes, vulnstore.MaxAgentOperatorText)
	}
}
