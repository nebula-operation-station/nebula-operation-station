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
		{"reason is only planned category", "internal/b | planned: | WG-01\n"},
		{"reason is only developer tool category", "internal/b | developer tool: | WG-01\n"},
		{"reason is only test helper category", "internal/b | test helper - never wired:   | WG-01\n"},
		{"category without colon", "internal/b | planned | WG-01\n"},
		{"ticket is a placeholder", "internal/b | planned: not wired yet | TODO\n"},
		{"ticket has no digits", "internal/b | planned: not wired yet | wiring\n"},
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

// ticketPlan is a planning document that defines some tickets and mentions or
// fakes others.
const ticketPlan = "# Plan\n\n" +
	"| AS-09 | open | the assistant |\n" +
	"IG-05 is the parser, mentioned in running text only.\n" +
	"| TODO | placeholder | x |\n" +
	"| none | nothing | x |\n" +
	"| **VU-23** | open | bold label |\n" +
	"| EN-16h: SSH step | later | label with a colon |\n" +
	"| Attached runs (M4-1) | done | ticket in parentheses |\n" +
	"## WG-07: wiring rules\n" +
	"## later\n" +
	"## planned\n"

func TestUnknownTicketIsReported(t *testing.T) {
	root := writeTree(t, map[string]string{
		"docs/implementation/plan.md":      ticketPlan,
		"internal/wiringguard/tickets.txt": "WG-02 | wiring guard | docs/implementation/plan.md\n",
	})
	allow := Allowlist{
		"internal/a": {Reason: "planned: parser", Ticket: "IG-05"},
		"internal/b": {Reason: "planned: never defined", Ticket: "G41"},
		"internal/c": {Reason: "planned: placeholder", Ticket: "TODO"},
		"internal/d": {Reason: "planned: placeholder", Ticket: "none"},
		"internal/e": {Reason: "planned: placeholder", Ticket: "later"},
		"internal/f": {Reason: "planned: placeholder", Ticket: "planned"},
		"internal/g": {Reason: "planned: a label word", Ticket: "wiring"},
		"internal/h": {Reason: "planned: table row", Ticket: "AS-09"},
		"internal/i": {Reason: "planned: bold label", Ticket: "VU-23"},
		"internal/j": {Reason: "planned: label with colon", Ticket: "EN-16h"},
		"internal/k": {Reason: "planned: ticket in parentheses", Ticket: "M4-1"},
		"internal/l": {Reason: "planned: heading", Ticket: "WG-07"},
		"internal/m": {Reason: "developer tool: guard", Ticket: "WG-02"},
	}
	got, err := UnknownTickets(root, allow)
	if err != nil {
		t.Fatalf("UnknownTickets: %v", err)
	}
	want := []string{"internal/a", "internal/b", "internal/c", "internal/d", "internal/e", "internal/f", "internal/g"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("UnknownTickets = %v, want %v", got, want)
	}
}

func TestPlaceholderTicketsAreNotAccepted(t *testing.T) {
	for _, id := range []string{"TODO", "none", "later", "planned", "tbd"} {
		t.Run(id, func(t *testing.T) {
			text := "internal/b | planned: not wired yet | " + id + "\n"
			if _, err := ParseAllowlist(strings.NewReader(text)); err == nil {
				t.Fatalf("ParseAllowlist accepted placeholder ticket %q", id)
			}
		})
	}
}

func TestRegisterMustNameTrackingDocument(t *testing.T) {
	tests := []struct {
		name     string
		register string
	}{
		{"two fields only", "WG-02 | wiring guard\n"},
		{"four fields", "WG-02 | wiring guard | docs/implementation/plan.md | extra\n"},
		{"placeholder id", "TODO | wiring guard | docs/implementation/plan.md\n"},
		{"tracking document missing", "WG-02 | wiring guard | docs/implementation/missing.md\n"},
		{"tracking document outside docs", "WG-02 | wiring guard | internal/wiringguard/tickets.txt\n"},
		{"tracking path escapes docs", "WG-02 | wiring guard | docs/../go.mod\n"},
		{"tracking document not markdown", "WG-02 | wiring guard | docs/implementation/plan.txt\n"},
		{"duplicate id", "WG-02 | a | docs/implementation/plan.md\nWG-02 | b | docs/implementation/plan.md\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := writeTree(t, map[string]string{
				"docs/implementation/plan.md":      ticketPlan,
				"docs/implementation/plan.txt":     ticketPlan,
				"internal/wiringguard/tickets.txt": tc.register,
			})
			allow := Allowlist{"internal/a": {Reason: "developer tool: guard", Ticket: "WG-02"}}
			if _, err := UnknownTickets(root, allow); err == nil {
				t.Fatalf("UnknownTickets with register %q succeeded, want error", tc.register)
			}
		})
	}
}

func TestMissingRegisterIsEmpty(t *testing.T) {
	root := writeTree(t, map[string]string{"docs/implementation/plan.md": ticketPlan})
	allow := Allowlist{
		"internal/a": {Reason: "planned: table row", Ticket: "AS-09"},
		"internal/b": {Reason: "developer tool: guard", Ticket: "WG-02"},
	}
	got, err := UnknownTickets(root, allow)
	if err != nil {
		t.Fatalf("UnknownTickets without register: %v", err)
	}
	if want := []string{"internal/b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("UnknownTickets = %v, want %v", got, want)
	}
}

func TestPlanningDocumentSizeLimit(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{"at the limit", maxTicketSourceBytes, false},
		{"one byte over the limit", maxTicketSourceBytes + 1, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			big := ticketPlan + strings.Repeat("x", tc.size-len(ticketPlan))
			root := writeTree(t, map[string]string{"docs/implementation/big.md": big})
			_, err := UnknownTickets(root, Allowlist{"internal/a": {Reason: "planned: a", Ticket: "AS-09"}})
			if tc.wantErr && err == nil {
				t.Fatal("UnknownTickets accepted an oversized planning document")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("UnknownTickets on a document at the limit: %v", err)
			}
		})
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
		t.Errorf("%s: ticket %q is not defined in a docs/ table row or heading, nor registered in internal/wiringguard/tickets.txt", pkg, allow[pkg].Ticket)
	}
}

func TestModulePathAcceptsTrailingComment(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":          "module example.com/tc // the module\n\ngo 1.26.0\n",
		"cmd/app/main.go": "package main\n\nimport _ \"example.com/tc/internal/b\"\n\nfunc main() {}\n",
		"internal/b/b.go": "package b\n",
	})
	res, err := Check(root, Allowlist{})
	if err != nil {
		t.Fatalf("Check with a commented module line: %v", err)
	}
	if res.Checked != 1 || len(res.Unwired) != 0 {
		t.Fatalf("Check = %+v, want one checked package that is wired", res)
	}
}

func TestModuleBoundaryDoesNotMatchPrefix(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod": "module example.com/wg\n\ngo 1.26.0\n",
		"cmd/app/main.go": "package main\n\nimport (\n" +
			"\t_ \"example.com/wg2/internal/b\"\n" +
			"\t_ \"example.com/wg/internal/c\"\n" +
			")\n\nfunc main() {}\n",
		"internal/b/b.go": "package b\n",
		"internal/c/c.go": "package c\n",
	})
	res, err := Check(root, Allowlist{})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if want := []string{"internal/b"}; !reflect.DeepEqual(res.Unwired, want) {
		t.Fatalf("Unwired = %v, want %v: an import of example.com/wg2 must not count for module example.com/wg", res.Unwired, want)
	}
}

func TestModuleDirMapsOnlyOwnModule(t *testing.T) {
	tests := []struct {
		importPath string
		wantDir    string
		wantOK     bool
	}{
		{"example.com/wg", ".", true},
		{"example.com/wg/internal/b", "internal/b", true},
		{"example.com/wg2", "", false},
		{"example.com/wg2/internal/b", "", false},
		{"example.com/wgx/internal/b", "", false},
		{"example.com/other/internal/b", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.importPath, func(t *testing.T) {
			dir, ok := moduleDir(tc.importPath, "example.com/wg")
			if ok != tc.wantOK || dir != tc.wantDir {
				t.Fatalf("moduleDir(%q) = (%q, %v), want (%q, %v)", tc.importPath, dir, ok, tc.wantDir, tc.wantOK)
			}
		})
	}
}

func TestIgnoredGoFileDoesNotMakeMainPackage(t *testing.T) {
	const generator = "//go:build ignore\n\npackage main\n\nfunc main() {}\n"
	root := writeTree(t, map[string]string{
		"go.mod":            "module example.com/g\n\ngo 1.26.0\n",
		"tools/gen/gen.go":  generator,
		"internal/h/gen.go": generator,
		"internal/g/gen.go": generator,
		"internal/g/lib.go": "package g\n",
	})
	res, err := Check(root, Allowlist{})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if res.Checked != 1 {
		t.Errorf("Checked = %d, want 1: a directory whose only main file is ignored by build constraints is not a candidate", res.Checked)
	}
	if want := []string{"internal/g"}; !reflect.DeepEqual(res.Unwired, want) {
		t.Errorf("Unwired = %v, want %v", res.Unwired, want)
	}
}
