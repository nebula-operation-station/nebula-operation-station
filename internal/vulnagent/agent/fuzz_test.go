// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"unicode/utf8"
)

// The fuzz targets below check the parsing of model-chosen tool arguments
// and the encoding of tool results (ADR 0011 A1.4). Model arguments are
// untrusted input: no input may panic, a success must satisfy the schema,
// and a failure must be one of the package's fixed sentinels whose text
// carries no part of the input. Only the seed corpus runs under go test;
// local fuzzing is `go test -run '^$' -fuzz '^FuzzParseSubmit$' -fuzztime 60s`
// (and likewise for the other two targets).

// fuzzRequired and fuzzOptional are the fixed name sets FuzzDecodeArgs
// decodes against.
var (
	fuzzRequired = []string{"vuln_id", "finding_key"}
	fuzzOptional = []string{"source"}
)

// jsonObjectNames returns the decoded member names of the single top-level
// JSON object in s, in order, and fails if s is not exactly one object
// followed by end of input. It is an independent reference for the
// strictness rules decodeObject enforces.
func jsonObjectNames(s string) ([]string, error) {
	dec := json.NewDecoder(strings.NewReader(s))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errors.New("not an object")
	}
	var names []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, ok := tok.(string)
		if !ok {
			return nil, errors.New("member name is not a string")
		}
		names = append(names, name)
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, errors.New("unterminated object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after object")
	}
	return names, nil
}

// submitSeeds are valid and invalid submit_assessment payloads, taken from
// the cases of TestSubmitAssessmentSchema and TestLookupRejectsUnknownToolsAndInvalidArguments.
var submitSeeds = []string{
	`{"text":"Fix via backport.\nUpdate openssl.","backport_checked":true,"likely_false_positive":false,"exploit_public":true,"rationale":"KEV listed"}`,
	`{"text":"","backport_checked":false,"likely_false_positive":true,"exploit_public":false,"rationale":""}`,
	`{"text":"x","backport_checked":true,"likely_false_positive":false,"exploit_public":true}`,
	`{"text":"x","backport_checked":true,"likely_false_positive":false,"exploit_public":true,"rationale":"y","extra":1}`,
	`{"text":"x","text":"y","backport_checked":true,"likely_false_positive":false,"exploit_public":true,"rationale":"z"}`,
	`{"text":null,"backport_checked":true,"likely_false_positive":false,"exploit_public":true,"rationale":"z"}`,
	`{"text":"x","backport_checked":1,"likely_false_positive":false,"exploit_public":true,"rationale":"z"}`,
	`{"text":"x","backport_checked":"true","likely_false_positive":false,"exploit_public":true,"rationale":"z"}`,
	`{"text":"x\u0007","backport_checked":true,"likely_false_positive":false,"exploit_public":true,"rationale":"z"}`,
	`{"text":"x","backport_checked":true,"likely_false_positive":false,"exploit_public":true,"rationale":"z"} {}`,
	`["text"]`,
	`{"text":"\xff","backport_checked":true,"likely_false_positive":false,"exploit_public":true,"rationale":"z"}`,
	"{\"text\":\"\xff\",\"backport_checked\":true,\"likely_false_positive\":false,\"exploit_public\":true,\"rationale\":\"z\"}",
	`{"text":"x","backport_checked":true,"likely_false_positive":false,"exploit_public":true,"rationale":"` + strings.Repeat("y", MaxRationaleBytes) + `"}`,
	`{"text":"` + strings.Repeat("x", MaxTextBytes+1) + `","backport_checked":true,"likely_false_positive":false,"exploit_public":true,"rationale":"z"}`,
	`{}`,
	``,
}

// FuzzParseSubmit checks that parseSubmit never panics, that an accepted
// payload is within its size limits and valid UTF-8, and that a rejected
// one returns exactly ErrInvalidArguments, whose text names no input.
func FuzzParseSubmit(f *testing.F) {
	for _, s := range submitSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, args string) {
		a, err := parseSubmit(args)
		if err != nil {
			// The sentinel itself is the error: its text is fixed and
			// carries no part of the input.
			if err != ErrInvalidArguments {
				t.Fatalf("error %v, want the sentinel ErrInvalidArguments", err)
			}
			return
		}
		if len(args) > MaxSubmitArgumentsBytes {
			t.Fatalf("accepted %d argument bytes, limit %d", len(args), MaxSubmitArgumentsBytes)
		}
		if len(a.Text) > MaxTextBytes || !utf8.ValidString(a.Text) {
			t.Fatalf("accepted text of %d bytes (valid UTF-8: %v), limit %d", len(a.Text), utf8.ValidString(a.Text), MaxTextBytes)
		}
		if len(a.Rationale) > MaxRationaleBytes || !utf8.ValidString(a.Rationale) {
			t.Fatalf("accepted rationale of %d bytes (valid UTF-8: %v), limit %d", len(a.Rationale), utf8.ValidString(a.Rationale), MaxRationaleBytes)
		}
	})
}

// FuzzDecodeArgs checks that decodeArgs never panics and that a success has
// every required name, no name outside the schema, no duplicate name, and
// no data after the object. Every value of a success is a string.
func FuzzDecodeArgs(f *testing.F) {
	seeds := []string{
		`{"vuln_id":"CVE-2026-0001"}`,
		`{"vuln_id":"CVE-2026-0001","source":"nvd"}`,
		`{"vuln_id":"CVE-2026-0001","finding_key":"AAAA"}`,
		`{"vuln_id":"CVE-2026-0001","finding_key":"AAAA","source":""}`,
		`{"vuln_id":"CVE-2026-0001","url":"http://x","finding_key":"AAAA"}`,
		`{"VULN_ID":"CVE-2026-0001","finding_key":"AAAA"}`,
		`{"vuln_id":"CVE-2026-0001","vuln_id":"CVE-2026-0002","finding_key":"AAAA"}`,
		`{"vuln_id":"CVE-2026-0001"}`,
		`{}`,
		`{"vuln_id":null,"finding_key":"AAAA"}`,
		`{"vuln_id":5,"finding_key":"AAAA"}`,
		`{"vuln_id":"CVE-2026-0001","finding_key":"AAAA"} {}`,
		`{"vuln_id":"CVE-2026-0001","finding_key":"AAAA"}x`,
		`["CVE-2026-0001"]`,
		`{"vuln_id":"CVE-2026-0001","finding_key":"AAAA","source":{"a":"b"}}`,
		`{"vuln_id":"CVE","finding_key":"AAAA"}`,
		"{\"vuln_id\":\"\xff\",\"finding_key\":\"AAAA\"}",
		"{\"vuln_id\":\"CVE\",\"finding_key\":\"\xff\"}",
		``,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, args string) {
		out, err := decodeArgs(args, fuzzRequired, fuzzOptional)
		if err != nil {
			if err != ErrInvalidArguments {
				t.Fatalf("error %v, want the sentinel ErrInvalidArguments", err)
			}
			return
		}
		allowed := map[string]bool{}
		for _, n := range append(append([]string{}, fuzzRequired...), fuzzOptional...) {
			allowed[n] = true
		}
		for _, n := range fuzzRequired {
			if _, ok := out[n]; !ok {
				t.Fatalf("accepted %q without required %q", args, n)
			}
		}
		for n := range out {
			if !allowed[n] {
				t.Fatalf("accepted unknown name %q", n)
			}
		}
		names, err := jsonObjectNames(args)
		if err != nil {
			t.Fatalf("accepted input the reference rejects (%v): %q", err, args)
		}
		seen := map[string]bool{}
		for _, n := range names {
			if seen[n] {
				t.Fatalf("accepted duplicate name %q in %q", n, args)
			}
			seen[n] = true
		}
	})
}

// toolResultSeeds are the data shapes used by TestToolResultIsCutToLimitAndStaysDelimited
// and TestLookupResultsCarryOneRecordText, as JSON values.
var toolResultSeeds = []string{
	`{"advisory_id":"DSA-6000-1","text":"Tracker text","affected":["1.0"],"fixed":"1.1"}`,
	`{"text":"` + strings.Repeat("A", 2000) + `"}`,
	`{"text":"` + strings.Repeat("ä", 1500) + `"}`,
	`{"text":"<script>\"\\\n </script>"}`,
	`{"envelope":"untrusted_data","kind":"x","data":{}}`,
	`null`,
	`[]`,
	`"plain string"`,
	"\xff\xfe invalid utf-8 data",
}

// FuzzToolResultContent checks, for any data and any limit from
// MinToolResultBytes up, that the encoded result is valid JSON of at most
// the limit, that it is an untrusted_data envelope with exactly the keys
// envelope, kind and data, and that a cut keeps everything inside data.
func FuzzToolResultContent(f *testing.F) {
	for i, s := range toolResultSeeds {
		f.Add([]byte(s), uint16(i*997), uint8(i%2), int64(i))
	}
	f.Add([]byte(`{}`), uint16(0), uint8(0), int64(0))
	f.Fuzz(func(t *testing.T, data []byte, limitSeed uint16, withRecord uint8, pos int64) {
		limit := MinToolResultBytes + int(limitSeed)%(HardMaxToolResultBytes-MinToolResultBytes+1)
		var v any
		if err := json.Unmarshal(data, &v); err != nil {
			v = string(data)
		}
		r := lookupResult{data: v}
		if withRecord%2 == 1 {
			ref := RecordRef{SourceID: "debian-tracker", Position: pos}
			r.record = &ref
		}
		const tool = ToolAdvisoryText
		s, err := toolResultContent(tool, r, limit)
		if err != nil {
			t.Fatalf("limit %d: %v", limit, err)
		}
		if len(s) > limit {
			t.Fatalf("limit %d: result is %d bytes", limit, len(s))
		}
		var env map[string]json.RawMessage
		if err := json.Unmarshal([]byte(s), &env); err != nil {
			t.Fatalf("result is not a JSON object: %v: %q", err, s)
		}
		if len(env) != 3 {
			t.Fatalf("envelope has keys %v, want envelope, kind and data", keysOf(env))
		}
		for _, k := range []string{"envelope", "kind", "data"} {
			if _, ok := env[k]; !ok {
				t.Fatalf("envelope lacks key %q: %q", k, s)
			}
		}
		var fixed, kind string
		if err := json.Unmarshal(env["envelope"], &fixed); err != nil || fixed != envelopeUntrusted {
			t.Fatalf("envelope marker = %q (%v), want %q", fixed, err, envelopeUntrusted)
		}
		if err := json.Unmarshal(env["kind"], &kind); err != nil || kind != "tool_result:"+tool {
			t.Fatalf("kind = %q (%v), want %q", kind, err, "tool_result:"+tool)
		}
		// Whether the result fits decides the form: a result that fits
		// is the full envelope, anything else must be the cut form.
		// Data text never leaves the data field in either form.
		full, err := json.Marshal(struct {
			Envelope string `json:"envelope"`
			Kind     string `json:"kind"`
			Data     any    `json:"data"`
		}{envelopeUntrusted, "tool_result:" + tool, v})
		if err != nil {
			t.Fatalf("encode fuzz data: %v", err)
		}
		if len(full) <= limit {
			if string(full) != s {
				t.Fatalf("result fits limit %d but differs from the full envelope: %q", limit, s)
			}
			return
		}
		enc, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("encode fuzz data: %v", err)
		}
		var cut struct {
			Cut     *string         `json:"cut"`
			Partial *string         `json:"partial"`
			Record  json.RawMessage `json:"record"`
		}
		if err := json.Unmarshal(env["data"], &cut); err != nil || cut.Cut == nil || cut.Partial == nil {
			t.Fatalf("oversized result is not a cut object: %s", env["data"])
		}
		if *cut.Cut != truncatedMarker {
			t.Fatalf("cut marker = %q", *cut.Cut)
		}
		if !bytes.HasPrefix(enc, []byte(*cut.Partial)) {
			t.Fatalf("partial is not a prefix of the encoded data")
		}
		if r.record != nil && len(cut.Record) == 0 {
			t.Fatalf("cut lost the record tag")
		}
	})
}

// keysOf lists the keys of m for error messages.
func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
