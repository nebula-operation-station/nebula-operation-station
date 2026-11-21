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

// writeTree creates the files of a temporary module tree; keys are slash
// separated paths relative to the tree root.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
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
			allow:     "internal/b | planned: test helper, not wired yet | WG-01\n",
			allowed:   []string{"internal/b"},
			wantCheck: 2,
		},
		{
			name:    "reachable package with entry is reported as now wired",
			fixture: "unreachable",
			allow: "# comment line\n\ninternal/a | planned: was planned | WG-01\n" +
				"internal/b | planned: not wired yet | WG-01\n",
			allowed:   []string{"internal/b"},
			nowWired:  []string{"internal/a"},
			wantCheck: 2,
		},
		{
			name:      "entry naming no checked package is stale",
			fixture:   "unreachable",
			allow:     "internal/zz | planned: removed package | WG-01\n",
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
			allow:     "tools/gen | developer tool: one-off generator, run by hand | WG-01\n",
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
		{"missing reason", "internal/b |  | WG-01\n"},
		{"missing ticket", "internal/b | planned: not wired yet |\n"},
		{"missing both", "internal/b\n"},
		{"two fields only", "internal/b | planned: not wired yet\n"},
		{"too many fields", "internal/b | planned: a | WG-01 | c\n"},
		{"duplicate path", "internal/b | planned: a | WG-01\ninternal/b | planned: b | WG-01\n"},
		{"path escapes module", "../x | planned: a | WG-01\n"},
		{"absolute path", "/internal/b | planned: a | WG-01\n"},
		{"unclean path", "internal//b | planned: a | WG-01\n"},
		{"empty path", " | planned: a | WG-01\n"},
		{"reason without category", "internal/b | not wired yet | WG-01\n"},
		{"reason with unknown category", "internal/b | later: not wired yet | WG-01\n"},
		{"ticket with a space", "internal/b | planned: a | G 41\n"},
		{"ticket with a slash", "internal/b | planned: a | WG-01/02\n"},
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

func TestParseAllowlistAcceptsEveryCategory(t *testing.T) {
	text := "internal/web/enroll | planned: enrollment route merged but not mounted | EN-09\n" +
		"internal/hostrun/hostruntest | test helper - never wired: in-process SSH server | M4-1\n" +
		"internal/wiringguard | developer tool: run by its own test | WG-01\n"
	allow, err := ParseAllowlist(strings.NewReader(text))
	if err != nil {
		t.Fatalf("ParseAllowlist: %v", err)
	}
	want := Allowlist{
		"internal/web/enroll":          {Reason: "planned: enrollment route merged but not mounted", Ticket: "EN-09"},
		"internal/hostrun/hostruntest": {Reason: "test helper - never wired: in-process SSH server", Ticket: "M4-1"},
		"internal/wiringguard":         {Reason: "developer tool: run by its own test", Ticket: "WG-01"},
	}
	if !reflect.DeepEqual(allow, want) {
		t.Fatalf("ParseAllowlist = %v, want %v", allow, want)
	}
}

func TestUnknownTicketIsReported(t *testing.T) {
	root := writeTree(t, map[string]string{
		"docs/implementation/plan.md": "# Plan\n\n| AS-09 | open | the assistant |\nIG-05 is the parser.\n",
		"internal/wiringguard/tickets.txt": "WG-01 | wiring guard\n" +
			"# comment\n",
	})
	allow := Allowlist{
		"internal/a": {Reason: "planned: parser", Ticket: "IG-05"},
		"internal/b": {Reason: "planned: never defined", Ticket: "G41"},
		"internal/c": {Reason: "planned: prefix only", Ticket: "IG-0"},
		"internal/d": {Reason: "developer tool: guard", Ticket: "WG-01"},
		"internal/e": {Reason: "planned: in the register title only", Ticket: "wiring"},
		"internal/f": {Reason: "planned: table row", Ticket: "AS-09"},
	}
	got, err := UnknownTickets(root, allow)
	if err != nil {
		t.Fatalf("UnknownTickets: %v", err)
	}
	want := []string{"internal/b", "internal/c", "internal/e"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UnknownTickets = %v, want %v", got, want)
	}
}

func TestUnknownTicketsFailsWithoutPlanningDocs(t *testing.T) {
	root := writeTree(t, map[string]string{"go.mod": "module example.com/x\n"})
	if _, err := UnknownTickets(root, Allowlist{}); err == nil {
		t.Fatal("UnknownTickets without docs/ succeeded, want error")
	}
}

func TestParseAllowlistReadsEntries(t *testing.T) {
	allow, err := ParseAllowlist(strings.NewReader("# header\n\ninternal/web/enroll | planned: EN-09 not mounted | EN-09\n"))
	if err != nil {
		t.Fatalf("ParseAllowlist: %v", err)
	}
	want := Allowlist{"internal/web/enroll": {Reason: "planned: EN-09 not mounted", Ticket: "EN-09"}}
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

func TestRealTreeTicketsExist(t *testing.T) {
	root, err := FindModuleRoot(".")
	if err != nil {
		t.Fatalf("find module root: %v", err)
	}
	allow, err := LoadAllowlist("allowlist.txt")
	if err != nil {
		t.Fatalf("load allowlist: %v", err)
	}
	unknown, err := UnknownTickets(root, allow)
	if err != nil {
		t.Fatalf("check tickets: %v", err)
	}
	for _, pkg := range unknown {
		t.Errorf("%s: ticket %q is not defined in docs/ or internal/wiringguard/tickets.txt", pkg, allow[pkg].Ticket)
	}
}
