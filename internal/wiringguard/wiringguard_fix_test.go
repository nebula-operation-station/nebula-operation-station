// SPDX-License-Identifier: AGPL-3.0-or-later

package wiringguard

import (
	"go/parser"
	"go/token"
	"reflect"
	"sort"
	"testing"
)

// TestRegisterMustDefineIDInTrackingDocument checks the register rule: a
// registered ticket is known only when the document it names defines it as a
// table row or heading. A definition in some other document under docs/ does
// not count. Each case asserts whether the allowlisted package is reported
// unknown, so the register decides the outcome; the cases where the ID is
// defined elsewhere fail if the register is ignored.
func TestRegisterMustDefineIDInTrackingDocument(t *testing.T) {
	const named = "docs/implementation/plan.md"
	const other = "docs/implementation/other.md"
	tests := []struct {
		name  string
		doc   string // the named tracking document
		other string // another document under docs/, "" for none
		known bool
	}{
		{"id not mentioned", "# Plan\n\n| AS-09 | open | x |\n", "", false},
		{"id in running text only", "# Plan\n\nWG-02 is planned here.\n", "", false},
		{"id only in fenced code", "# Plan\n\n```\n## WG-02: wiring guard\n```\n", "", false},
		{"id defined only in another document", "# Plan\n\n| AS-09 | open | x |\n", "## WG-02: wiring guard\n", false},
		{"id defined in named and another document", "# Plan\n\n## WG-02: wiring guard\n", "| WG-02 | open | x |\n", true},
		{"id as heading", "# Plan\n\n## WG-02: wiring guard\n", "", true},
		{"id as table row", "# Plan\n\n| WG-02 | open | wiring guard |\n", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{
				named:                              tc.doc,
				"internal/wiringguard/tickets.txt": "WG-02 | wiring guard | " + named + "\n",
			}
			if tc.other != "" {
				files[other] = tc.other
			}
			root := writeTree(t, files)
			allow := Allowlist{"internal/a": {Reason: "developer tool: guard", Ticket: "WG-02"}}
			unknown, err := UnknownTickets(root, allow)
			if err != nil {
				t.Fatalf("UnknownTickets: %v", err)
			}
			gotKnown := len(unknown) == 0
			if gotKnown != tc.known {
				t.Fatalf("UnknownTickets = %v, want known=%v for WG-02 registered to %s", unknown, tc.known, named)
			}
		})
	}
}

func TestDefinedTicketsIgnoresDecisionLabelsAndCode(t *testing.T) {
	tests := []struct {
		name string
		text string
		want []string
	}{
		{"design decision table labels", "| D7 | rule |\n| I2 | rule |\n", nil},
		{"design decision heading", "## D7: decision\n", nil},
		{"hash lines in fenced code", "```\n# WG-03 in code\n```\n", nil},
		{"table rows in tilde fence", "~~~\n| WG-04 | x |\n~~~\n", nil},
		{"ticket after a closed fence", "```\n# x\n```\n## WG-05: heading\n", []string{"WG-05"}},
		{"ticket beside a decision label", "| WG-06 | ok |\n| D7 | no |\n", []string{"WG-06"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for id := range definedTickets(tc.text) {
				got = append(got, id)
			}
			sort.Strings(got)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("definedTickets = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIgnoreConstraintIsRecognisedInEveryForm(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{"go:build ignore", "//go:build ignore\n", true},
		{"go:build ignore and tag", "//go:build ignore && linux\n", true},
		{"go:build tag and ignore", "//go:build linux && ignore\n", true},
		{"legacy +build ignore", "// +build ignore\n", true},
		{"legacy ignore with comma tag", "// +build ignore,linux\n", true},
		{"go:build linux overrides legacy ignore", "//go:build linux\n// +build ignore\n", false},
		{"go:build ignore overrides legacy tag", "//go:build ignore\n// +build linux\n", true},
		{"legacy lines without go:build are conjoined", "// +build linux\n// +build ignore\n", true},
		{"go:build linux alone with legacy linux", "//go:build linux\n// +build linux\n", false},
		{"ignore or tag can build", "//go:build ignore || linux\n", false},
		{"negated ignore builds", "//go:build !ignore\n", false},
		{"other constraint", "//go:build linux\n", false},
		{"no constraint", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := tc.header + "\npackage x\n"
			f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, parser.ImportsOnly|parser.ParseComments)
			if err != nil {
				t.Fatalf("parse %q: %v", src, err)
			}
			if got := isIgnored(f); got != tc.want {
				t.Fatalf("isIgnored(%q) = %v, want %v", src, got, tc.want)
			}
		})
	}
}

func TestTestdataDirectoriesAreNotScanned(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":                         "module example.com/td\n\ngo 1.26.0\n",
		"cmd/app/main.go":                "package main\n\nimport _ \"example.com/td/internal/a\"\n\nfunc main() {}\n",
		"internal/a/a.go":                "package a\n",
		"internal/b/b.go":                "package b\n",
		"internal/c/c.go":                "package c\n",
		"internal/testdata/gen/main.go":  "package main\n\nimport _ \"example.com/td/internal/b\"\n\nfunc main() {}\n",
		"internal/b/testdata/fx/main.go": "package main\n\nimport _ \"example.com/td/internal/c\"\n\nfunc main() {}\n",
	})
	res, err := Check(root, Allowlist{})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if res.Checked != 3 {
		t.Errorf("Checked = %d, want 3: a package main under internal/testdata is not a candidate", res.Checked)
	}
	if want := []string{"internal/b", "internal/c"}; !reflect.DeepEqual(res.Unwired, want) {
		t.Errorf("Unwired = %v, want %v: imports from testdata directories must not count", res.Unwired, want)
	}
}

func TestPackagePrefixBoundaries(t *testing.T) {
	root := writeTree(t, map[string]string{
		"go.mod":              "module example.com/pb\n\ngo 1.26.0\n",
		"cmd/app/main.go":     "package main\n\nimport _ \"example.com/pb/internal/a\"\n\nfunc main() {}\n",
		"internal/a/a.go":     "package a\n",
		"internal/b/b.go":     "package b\n",
		"internalx/y/y.go":    "package y\n",
		"cmdtool/app/main.go": "package main\n\nfunc main() {}\n",
	})
	res, err := Check(root, Allowlist{})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if res.Checked != 3 {
		t.Errorf("Checked = %d, want 3: internalx/ is not under internal/ and cmdtool/ is not under cmd/", res.Checked)
	}
	if want := []string{"cmdtool/app", "internal/b"}; !reflect.DeepEqual(res.Unwired, want) {
		t.Errorf("Unwired = %v, want %v", res.Unwired, want)
	}
}

func TestIsUnderMatchesWholePathElements(t *testing.T) {
	tests := []struct {
		dir, parent string
		want        bool
	}{
		{"cmd", "cmd", true},
		{"cmd/app", "cmd", true},
		{"cmdtool", "cmd", false},
		{"cmdtool/app", "cmd", false},
		{"internal", "internal", true},
		{"internal/b", "internal", true},
		{"internalx/y", "internal", false},
	}
	for _, tc := range tests {
		if got := isUnder(tc.dir, tc.parent); got != tc.want {
			t.Errorf("isUnder(%q, %q) = %v, want %v", tc.dir, tc.parent, got, tc.want)
		}
	}
}
