// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnnotify

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// fuzzSeeds are the hand-picked inputs of export_test.go, used as seeds.
// Unicode spaces and bidi controls are built from code points so that the
// source stays free of invisible characters.
var fuzzSeeds = []string{
	"=HYPERLINK(\"http://evil\")", "+1+1", "-2+3", "@SUM(A1)", "\tcmd", "\rcmd",
	" =1+1", "  +cmd", string(rune(0x00a0)) + "=HYPERLINK(\"x\")", string(rune(0x3000)) + "@SUM(A1)", " \t-2+3",
	"GHSA-x\n" + string(rune(0x202e)) + "y", "a\x00b\xff", "<script>alert(1)</script>", " openssl",
	"CVE-2026-0001", strings.Repeat("A", 300), string(rune(0x2028)) + "=x", string(rune(0x202e)) + "=x", "",
}

// fuzzFinding builds an exported finding from fuzzed feed fields.
func fuzzFinding(id, pkg, fixed string, aliases []string) vulnstore.Finding {
	f := exportFinding()
	f.Record.Vuln.ID = id
	f.Record.Vuln.Aliases = aliases
	f.Record.Component = vulnfinding.Component{SourcePackage: pkg, SourceVersion: fixed}
	f.Record.Fix = vulnfinding.Fix{State: vulnfinding.FixFixed, Version: fixed}
	return f
}

// badRune reports a control, format (bidi) or otherwise non-printable rune.
func badRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || !unicode.IsPrint(r)
}

// formulaStart reports whether s begins, after Unicode whitespace, with a
// spreadsheet formula trigger: '=', '+', '-', '@', tab or CR.
func formulaStart(s string) bool {
	t := strings.TrimLeftFunc(s, unicode.IsSpace)
	return t != "" && strings.ContainsRune("=+-@\t\r", rune(t[0]))
}

func FuzzExportCSV(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s, s, s, s, s)
	}
	f.Fuzz(func(t *testing.T, id, pkg, fixed, alias1, alias2 string) {
		fs := []vulnstore.Finding{fuzzFinding(id, pkg, fixed, []string{alias1, alias2})}
		var buf bytes.Buffer
		if err := Export(context.Background(), &audit{}, &buf, ExportRequest{Format: FormatCSV, Actor: "admin", Findings: fs}); err != nil {
			t.Fatal(err)
		}
		if !utf8.Valid(buf.Bytes()) {
			t.Fatalf("csv export is not valid UTF-8: %q", buf.String())
		}
		r := csv.NewReader(&buf)
		r.FieldsPerRecord = len(csvHeader)
		recs, err := r.ReadAll()
		if err != nil {
			t.Fatalf("csv export does not read back: %v", err)
		}
		if len(recs) != 2 {
			t.Fatalf("got %d records, want header and one row", len(recs))
		}
		for i, cell := range recs[1] {
			col := csvHeader[i]
			if formulaStart(cell) {
				t.Errorf("column %s starts with a formula trigger after whitespace: %q (inputs %q %q %q %q %q)", col, cell, id, pkg, fixed, alias1, alias2)
			}
			if n := utf8.RuneCountInString(cell); n > maxCell+2 {
				t.Errorf("column %s has %d runes, limit %d (prefix and ellipsis included)", col, n, maxCell+2)
			}
			for _, r := range cell {
				if badRune(r) {
					t.Errorf("column %s contains control or bidi rune %U: %q", col, r, cell)
					break
				}
			}
		}
	})
}

// exportRowFields returns the JSON field names of ExportRow.
func exportRowFields() map[string]bool {
	names := map[string]bool{}
	rt := reflect.TypeOf(ExportRow{})
	for i := 0; i < rt.NumField(); i++ {
		names[strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]] = true
	}
	return names
}

// checkJSONStrings fails on any string in v that is not clean text.
func checkJSONStrings(t *testing.T, v any) {
	t.Helper()
	switch x := v.(type) {
	case string:
		if !utf8.ValidString(x) {
			t.Errorf("string is not valid UTF-8: %q", x)
		}
		for _, r := range x {
			if badRune(r) {
				t.Errorf("string contains control or bidi rune %U: %q", r, x)
				return
			}
		}
	case []any:
		for _, e := range x {
			checkJSONStrings(t, e)
		}
	case map[string]any:
		for _, e := range x {
			checkJSONStrings(t, e)
		}
	}
}

func FuzzExportJSON(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s, s, s, s, s)
	}
	fields := exportRowFields()
	f.Fuzz(func(t *testing.T, id, pkg, fixed, alias1, alias2 string) {
		fs := []vulnstore.Finding{fuzzFinding(id, pkg, fixed, []string{alias1, alias2})}
		var buf bytes.Buffer
		if err := Export(context.Background(), &audit{}, &buf, ExportRequest{Format: FormatJSON, Actor: "admin", Findings: fs}); err != nil {
			t.Fatal(err)
		}
		if !utf8.Valid(buf.Bytes()) || !json.Valid(buf.Bytes()) {
			t.Fatalf("json export is not valid JSON/UTF-8: %q", buf.String())
		}
		var doc struct {
			Format   string           `json:"format"`
			Findings []map[string]any `json:"findings"`
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		if doc.Format != "nos-vuln-findings-v1" || len(doc.Findings) != 1 {
			t.Fatalf("doc format %q with %d findings", doc.Format, len(doc.Findings))
		}
		for key, v := range doc.Findings[0] {
			if !fields[key] {
				t.Errorf("unexpected field %q (not an ExportRow field; assessment or admin data?)", key)
			}
			checkJSONStrings(t, v)
		}
	})
}

func FuzzPlain(f *testing.F) {
	for i, s := range fuzzSeeds {
		f.Add(s, i%8)
	}
	f.Fuzz(func(t *testing.T, s string, limit int) {
		limit %= 1024
		if limit < 0 {
			limit = -limit
		}
		out := plain(s, limit)
		if !utf8.ValidString(out) {
			t.Fatalf("plain(%q, %d) is not valid UTF-8: %q", s, limit, out)
		}
		if n := utf8.RuneCountInString(out); n > limit+1 {
			t.Fatalf("plain(%q, %d) has %d runes, limit %d plus ellipsis", s, limit, n, limit)
		}
		for _, r := range out {
			if badRune(r) {
				t.Fatalf("plain(%q, %d) keeps control or bidi rune %U: %q", s, limit, r, out)
			}
		}
		if again := plain(out, limit); again != out {
			t.Fatalf("plain is not idempotent: %q -> %q -> %q", s, out, again)
		}
	})
}
