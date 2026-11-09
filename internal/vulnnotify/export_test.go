// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnnotify

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

type audit struct {
	kinds []string
	attrs []map[string]string
	err   error
}

func (a *audit) Append(_ context.Context, kind string, attrs map[string]string) error {
	if a.err != nil {
		return a.err
	}
	a.kinds = append(a.kinds, kind)
	a.attrs = append(a.attrs, attrs)
	return nil
}

func exportFinding() vulnstore.Finding {
	f := finding(7, 1, vulnstore.TierCritical, true)
	f.Record.Ecosystem = "debian:bookworm"
	f.Record.Component = vulnfinding.Component{SourcePackage: "openssl", SourceVersion: "3.0.11-1~deb12u1"}
	f.Record.Fix = vulnfinding.Fix{State: vulnfinding.FixFixed, Version: "3.0.11-1~deb12u2"}
	f.Record.Scores.CVSS = &vulnfinding.CVSS{BaseScore: 9.8, Vector: "CVSS:3.1/AV:N", Version: "3.1"}
	f.Record.Assessment.Text = "SECRET-LLM-TEXT"
	f.Record.Evidence.BasisSources = []vulnfinding.BasisSource{{SourceID: "osv", SnapshotID: "SNAPSHOT-SECRET"}}
	f.Human = &vulnstore.HumanState{By: "alice", Reason: "SECRET-ADMIN-REASON"}
	f.ClosedReason = "SECRET-CLOSE-REASON"
	f.ClosedAdmin = "bob"
	return f
}

func TestExportCSVFieldsAndNoSecrets(t *testing.T) {
	var buf bytes.Buffer
	a := &audit{}
	f := exportFinding()
	if err := Export(context.Background(), a, &buf, ExportRequest{Format: FormatCSV, Actor: "admin", Findings: []vulnstore.Finding{f}}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, secret := range []string{"SECRET", "alice", "bob", "CVSS:3.1"} {
		if strings.Contains(out, secret) {
			t.Fatalf("export contains %q:\n%s", secret, out)
		}
	}
	recs, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || strings.Join(recs[0], ",") != strings.Join(csvHeader, ",") {
		t.Fatalf("records %v", recs)
	}
	got := map[string]string{}
	for i, h := range recs[0] {
		got[h] = recs[1][i]
	}
	want := map[string]string{"subject_kind": "host", "subject_id": "web1", "state": "open", "vuln_id": "CVE-2026-0001",
		"component": "openssl", "fixed_version": "3.0.11-1~deb12u2", "tier": "critical", "kev": "true", "cvss_score": "9.8",
		"fix_flow": "os_update", "advisory_link": "https://osv.dev/vulnerability/CVE-2026-0001", "finding_key": f.Key.String()}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if len(a.kinds) != 1 || a.kinds[0] != AuditKindExport || a.attrs[0]["user"] != "admin" || a.attrs[0]["findings"] != "1" {
		t.Fatalf("audit %v %v", a.kinds, a.attrs)
	}
}

func TestExportCSVInjectionPrefix(t *testing.T) {
	for _, bad := range []string{"=HYPERLINK(\"http://evil\")", "+1+1", "-2+3", "@SUM(A1)", "\tcmd", "\rcmd"} {
		f := exportFinding()
		f.Record.Vuln.ID = bad
		f.Record.Component.SourcePackage = bad
		var buf bytes.Buffer
		if err := Export(context.Background(), &audit{}, &buf, ExportRequest{Format: FormatCSV, Actor: "admin", Findings: []vulnstore.Finding{f}}); err != nil {
			t.Fatal(err)
		}
		recs, err := csv.NewReader(&buf).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		for i, cell := range recs[1] {
			if cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
				t.Fatalf("%q: column %s starts with a formula char: %q", bad, recs[0][i], cell)
			}
		}
		if !strings.HasPrefix(recs[1][7], "'") || recs[1][20] != "" {
			t.Fatalf("%q: vuln_id %q advisory_link %q", bad, recs[1][7], recs[1][20])
		}
	}
}

func TestExportStripsControlAndBidi(t *testing.T) {
	f := exportFinding()
	f.Record.Vuln.Aliases = []string{"GHSA-x\n\u202ey", "a\x00b\xff"}
	row := Row(f)
	for _, a := range row.Aliases {
		if strings.ContainsAny(a, "\n\x00\u202e") || !strings.Contains(a, "?") {
			t.Fatalf("alias %q", a)
		}
	}
}

func TestExportJSONNoAssessmentAndUnconfirmedLabel(t *testing.T) {
	f := exportFinding()
	f.State = vulnstore.StateFixed
	f.ClosedBy = vulnstore.ClosedByHermesUnconfirmed
	f.Record.Vuln.ID = "<script>alert(1)</script>"
	var buf bytes.Buffer
	if err := Export(context.Background(), &audit{}, &buf, ExportRequest{Format: FormatJSON, Actor: "admin", Findings: []vulnstore.Finding{f}}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "SECRET") || strings.Contains(buf.String(), "<script>") {
		t.Fatalf("json export: %s", buf.String())
	}
	var doc struct {
		Format   string      `json:"format"`
		Findings []ExportRow `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	r := doc.Findings[0]
	if doc.Format != "nos-vuln-findings-v1" || r.StateLabel != "closed by Hermes, not confirmed by NOS" || r.VulnID != "<script>alert(1)</script>" || r.AdvisoryLink != "" {
		t.Fatalf("row %+v", r)
	}
}

func TestExportRefusals(t *testing.T) {
	ctx := context.Background()
	fs := []vulnstore.Finding{exportFinding()}
	auditErr := errors.New("disk full")
	cases := []struct {
		name string
		a    Auditor
		req  ExportRequest
	}{
		{"bad format", &audit{}, ExportRequest{Format: "xlsx", Actor: "admin", Findings: fs}},
		{"no actor", &audit{}, ExportRequest{Format: FormatCSV, Actor: " ", Findings: fs}},
		{"no auditor", nil, ExportRequest{Format: FormatCSV, Actor: "admin", Findings: fs}},
		{"too many", &audit{}, ExportRequest{Format: FormatJSON, Actor: "admin", Findings: make([]vulnstore.Finding, MaxExportFindings+1)}},
		{"audit fails", &audit{err: auditErr}, ExportRequest{Format: FormatCSV, Actor: "admin", Findings: fs}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := Export(ctx, c.a, &buf, c.req); err == nil {
				t.Fatal("export succeeded")
			}
			if buf.Len() != 0 {
				t.Fatalf("refused export wrote %d bytes", buf.Len())
			}
		})
	}
}

func TestFixFlowPerSubjectKind(t *testing.T) {
	for kind, want := range map[vulnfinding.SubjectKind]string{vulnfinding.SubjectHost: "os_update",
		vulnfinding.SubjectImage: "container_update", vulnfinding.SubjectDevice: "vendor_advisory"} {
		f := exportFinding()
		f.Subject.Kind = kind
		if got := Row(f).FixFlow; got != want {
			t.Errorf("%s: %q, want %q", kind, got, want)
		}
		f.Record.Fix = vulnfinding.Fix{State: vulnfinding.FixNoFixYet}
		if got := Row(f).FixFlow; got != "" {
			t.Errorf("%s without fix: %q", kind, got)
		}
	}
}

// TestExportCSVInjectionPrefixAfterWhitespace: whitespace (ASCII, NBSP,
// ideographic space) before a formula character does not bypass the guard.
func TestExportCSVInjectionPrefixAfterWhitespace(t *testing.T) {
	nbsp, ideo := string(rune(0x00a0)), string(rune(0x3000))
	for _, bad := range []string{" =1+1", "  +cmd", nbsp + "=HYPERLINK(\"x\")", ideo + "@SUM(A1)", " \t-2+3"} {
		f := exportFinding()
		f.Record.Vuln.ID = bad
		f.Record.Component.SourcePackage = bad
		var buf bytes.Buffer
		if err := Export(context.Background(), &audit{}, &buf, ExportRequest{Format: FormatCSV, Actor: "admin", Findings: []vulnstore.Finding{f}}); err != nil {
			t.Fatal(err)
		}
		recs, err := csv.NewReader(&buf).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		for _, col := range []int{7, 10} {
			if cell := recs[1][col]; !strings.HasPrefix(cell, "'") {
				t.Fatalf("%q: column %s not prefixed: %q", bad, recs[0][col], cell)
			}
		}
	}
	// Plain text with leading space keeps no prefix.
	f := exportFinding()
	f.Record.Component.SourcePackage = " openssl"
	var buf bytes.Buffer
	if err := Export(context.Background(), &audit{}, &buf, ExportRequest{Format: FormatCSV, Actor: "admin", Findings: []vulnstore.Finding{f}}); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if recs[1][10] != " openssl" {
		t.Fatalf("component %q", recs[1][10])
	}
}

// writeRecorder records the size of every Write.
type writeRecorder struct {
	buf     bytes.Buffer
	writes  int
	largest int
}

func (w *writeRecorder) Write(p []byte) (int, error) {
	w.writes++
	w.largest = max(w.largest, len(p))
	return w.buf.Write(p)
}

// TestExportJSONStreamsRows: the JSON export is written row by row (no
// write holds more than one row) and stays one valid document.
func TestExportJSONStreamsRows(t *testing.T) {
	const rows = 50
	fs := make([]vulnstore.Finding, 0, rows)
	for i := 0; i < rows; i++ {
		f := exportFinding()
		f.Key[1] = byte(i)
		f.Record.Vuln.Aliases = []string{strings.Repeat("A", 300), "GHSA-1"}
		fs = append(fs, f)
	}
	var w writeRecorder
	if err := Export(context.Background(), &audit{}, &w, ExportRequest{Format: FormatJSON, Actor: "admin", Findings: fs}); err != nil {
		t.Fatal(err)
	}
	one, err := json.Marshal(Row(fs[0]))
	if err != nil {
		t.Fatal(err)
	}
	if w.writes < rows || w.largest > len(one)+16 {
		t.Fatalf("not streamed: %d writes, largest %d bytes (row %d)", w.writes, w.largest, len(one))
	}
	var doc struct {
		Format   string      `json:"format"`
		Findings []ExportRow `json:"findings"`
	}
	if err := json.Unmarshal(w.buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if doc.Format != "nos-vuln-findings-v1" || len(doc.Findings) != rows || doc.Findings[rows-1].FindingKey != fs[rows-1].Key.String() {
		t.Fatalf("doc %s with %d rows", doc.Format, len(doc.Findings))
	}
}

// TestExportJSONEmpty: an export without findings is a document with an
// empty list.
func TestExportJSONEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := Export(context.Background(), &audit{}, &buf, ExportRequest{Format: FormatJSON, Actor: "admin"}); err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid json %q: %v", buf.String(), err)
	}
	if string(doc["findings"]) != "[]" {
		t.Fatalf("findings %s", doc["findings"])
	}
}
