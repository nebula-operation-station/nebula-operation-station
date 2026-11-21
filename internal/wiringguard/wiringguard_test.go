// SPDX-License-Identifier: AGPL-3.0-or-later

package wiringguard

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// checkFixture runs Check on testdata/<name> with the allowlist text allowText.
func checkFixture(t *testing.T, name, allowText string) Result {
	t.Helper()
	allow, err := ParseAllowlist(strings.NewReader(allowText))
	if err != nil {
		t.Fatalf("parse allowlist for %s: %v", name, err)
	}
	res, err := Check(filepath.Join("testdata", name), allow)
	if err != nil {
		t.Fatalf("check fixture %s: %v", name, err)
	}
	return res
}

func TestWiringRulesOnFixtures(t *testing.T) {
	tests := []struct {
		name      string
		fixture   string
		allow     string
		unwired   []string
		allowed   []string
		nowWired  []string
		stale     []string
		wantCheck int
	}{
		{
			name:      "unreachable package without entry is a finding",
			fixture:   "unreachable",
			unwired:   []string{"internal/b"},
			wantCheck: 2,
		},
		{
			name:      "package imported only by a test file is a finding",
			fixture:   "testonly",
			unwired:   []string{"internal/t"},
			wantCheck: 2,
		},
		{
			name:      "entry with reason and ticket allows an unreachable package",
			fixture:   "unreachable",
			allow:     "internal/b | test helper, not wired yet | uf07\n",
			allowed:   []string{"internal/b"},
			wantCheck: 2,
		},
		{
			name:    "reachable package with entry is reported as now wired",
			fixture: "unreachable",
			allow: "# comment line\n\ninternal/a | was planned | uf07\n" +
				"internal/b | not wired yet | uf07\n",
			allowed:   []string{"internal/b"},
			nowWired:  []string{"internal/a"},
			wantCheck: 2,
		},
		{
			name:      "entry naming no checked package is stale",
			fixture:   "unreachable",
			allow:     "internal/zz | removed package | uf07\n",
			unwired:   []string{"internal/b"},
			stale:     []string{"internal/zz"},
			wantCheck: 2,
		},
		{
			name:      "package reachable only through an unreachable package is a finding for both",
			fixture:   "chain",
			unwired:   []string{"internal/c", "internal/x"},
			wantCheck: 3,
		},
		{
			name:      "generated-only package is not checked but its imports still count",
			fixture:   "generated",
			unwired:   []string{"tools/gen"},
			wantCheck: 2,
		},
		{
			name:      "package main outside cmd is a checked package",
			fixture:   "generated",
			allow:     "tools/gen | one-off generator, run by hand | uf07\n",
			allowed:   []string{"tools/gen"},
			wantCheck: 2,
		},
		{
			name:      "subdirectory with its own go.mod is another module and is not scanned",
			fixture:   "nestedmod",
			wantCheck: 1,
		},
		{
			name:      "import from a build-constrained file counts toward reachability",
			fixture:   "buildtags",
			wantCheck: 2,
		},
		{
			name:      "vendor, underscore and dot directories are not scanned, so their imports do not count",
			fixture:   "skipdirs",
			unwired:   []string{"internal/b", "internal/c", "internal/d"},
			wantCheck: 4,
		},
		{
			name:      "generated marker after the package clause does not make a package generated",
			fixture:   "latemarker",
			unwired:   []string{"internal/g"},
			wantCheck: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := checkFixture(t, tc.fixture, tc.allow)
			if !reflect.DeepEqual(res.Unwired, tc.unwired) {
				t.Errorf("Unwired = %v, want %v", res.Unwired, tc.unwired)
			}
			if !reflect.DeepEqual(res.Allowed, tc.allowed) {
				t.Errorf("Allowed = %v, want %v", res.Allowed, tc.allowed)
			}
			if !reflect.DeepEqual(res.NowWired, tc.nowWired) {
				t.Errorf("NowWired = %v, want %v", res.NowWired, tc.nowWired)
			}
			if !reflect.DeepEqual(res.Stale, tc.stale) {
				t.Errorf("Stale = %v, want %v", res.Stale, tc.stale)
			}
			if res.Checked != tc.wantCheck {
				t.Errorf("Checked = %d, want %d", res.Checked, tc.wantCheck)
			}
		})
	}
}

func TestParseAllowlistRejectsIncompleteEntries(t *testing.T) {
	tests := []struct {
		name string
		text string
	}{
		{"missing reason", "internal/b |  | uf07\n"},
		{"missing ticket", "internal/b | not wired yet |\n"},
		{"missing both", "internal/b\n"},
		{"two fields only", "internal/b | not wired yet\n"},
		{"too many fields", "internal/b | a | b | c\n"},
		{"duplicate path", "internal/b | a | uf07\ninternal/b | b | uf07\n"},
		{"path escapes module", "../x | a | uf07\n"},
		{"absolute path", "/internal/b | a | uf07\n"},
		{"unclean path", "internal//b | a | uf07\n"},
		{"empty path", " | a | uf07\n"},
		{"too large", strings.Repeat("#", maxAllowlistBytes+1) + "\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseAllowlist(strings.NewReader(tc.text)); err == nil {
				t.Fatalf("ParseAllowlist(%q) succeeded, want error", tc.text)
			}
		})
	}
}

func TestParseAllowlistReadsEntries(t *testing.T) {
	allow, err := ParseAllowlist(strings.NewReader("# header\n\ninternal/web/enroll | EN-09 not mounted | uf07\n"))
	if err != nil {
		t.Fatalf("ParseAllowlist: %v", err)
	}
	want := Allowlist{"internal/web/enroll": {Reason: "EN-09 not mounted", Ticket: "uf07"}}
	if !reflect.DeepEqual(allow, want) {
		t.Fatalf("ParseAllowlist = %v, want %v", allow, want)
	}
}

func TestBrokenGoFileFailsTheCheck(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/broken\n\ngo 1.26.0\n")
	write("cmd/app/main.go", "package main\n\nimport (\n")
	if _, err := Check(root, Allowlist{}); err == nil {
		t.Fatal("Check on a file with a syntax error succeeded, want error")
	}
}

func TestRealTreeIsWired(t *testing.T) {
	root, err := FindModuleRoot(".")
	if err != nil {
		t.Fatalf("find module root: %v", err)
	}
	allow, err := LoadAllowlist("allowlist.txt")
	if err != nil {
		t.Fatalf("load allowlist: %v", err)
	}
	res, err := Check(root, allow)
	if err != nil {
		t.Fatalf("check module tree: %v", err)
	}
	if res.Checked == 0 {
		t.Fatal("no packages were checked; the scan found nothing under internal/")
	}
	for _, pkg := range res.Unwired {
		t.Errorf("%s: production package with no importer reachable from cmd/: wire it or record why in internal/wiringguard/allowlist.txt", pkg)
	}
	for _, pkg := range res.Stale {
		t.Errorf("allowlist entry %s names no checked package; remove the entry", pkg)
	}
	for _, pkg := range res.NowWired {
		t.Logf("allowlist entry %s is reachable now; the entry can be removed", pkg)
	}
}
