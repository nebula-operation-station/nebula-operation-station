// SPDX-License-Identifier: AGPL-3.0-or-later

package exportconform

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// tablesByName maps each shared table to the name used in failure messages.
// Both the server and the client mirror run exactly these slices, so a table
// that contradicts itself would make the two sides disagree.
//
// TestConformanceTableListIsComplete makes sure this map lists every []Case
// variable declared in exportconform.go, so a table added later cannot skip the
// consistency checks.
var tablesByName = map[string][]Case{
	"Vendor":   Vendor,
	"Model":    Model,
	"Firmware": Firmware,
}

// sourceFile is the file the table lives in. Go runs tests in the package
// directory, so the name is relative to it.
const sourceFile = "exportconform.go"

// caseTypeName is the element type of a conformance table.
const caseTypeName = "Case"

// invalidEncodingMarker is the text a case name must contain when its value is
// deliberately not valid UTF-8. No such case exists today; the rule is kept so
// that one cannot be added silently.
const invalidEncodingMarker = "invalid UTF-8"

// The check helpers below return one finding per problem, as text. They do not
// touch testing.T, so the negative tests can feed them contradictory tables and
// see exactly what they report.

// nameFindings reports empty names, names that t.Run cannot render as they are
// written, and names that collide once rendered. Both consumers pass Case.Name
// to t.Run, which turns spaces into underscores and treats "/" as a subtest
// separator, so "palo alto" and "palo_alto" would clash in the output.
func nameFindings(cases []Case) []string {
	var out []string
	seen := make(map[string]int, len(cases))
	for i, c := range cases {
		if strings.TrimSpace(c.Name) == "" {
			out = append(out, fmt.Sprintf("case %d has an empty name (value %q)", i, c.Value))
			continue
		}
		renderable := true
		for _, r := range c.Name {
			switch {
			case r == '/':
				out = append(out, fmt.Sprintf("case %d name %q contains '/', which t.Run treats as a subtest separator", i, c.Name))
				renderable = false
			case !isTestingSpace(r) && !strconv.IsPrint(r):
				out = append(out, fmt.Sprintf("case %d name %q contains %U, which t.Run does not print", i, c.Name, r))
				renderable = false
			}
		}
		if !renderable {
			continue
		}
		key := renderSubtestName(c.Name)
		if j, dup := seen[key]; dup {
			out = append(out, fmt.Sprintf("case %d name %q and case %d name %q render as the same subtest name %q",
				j, cases[j].Name, i, c.Name, key))
			continue
		}
		seen[key] = i
	}
	return out
}

// valueFindings reports each value that occurs more than once in a table. A
// value listed twice with different verdicts would make the table contradict
// itself; the same verdict twice would hide a copy error.
func valueFindings(cases []Case) []string {
	var out []string
	seen := make(map[string]string, len(cases))
	for _, c := range cases {
		if prev, dup := seen[c.Value]; dup {
			out = append(out, fmt.Sprintf("value %q appears twice: cases %q and %q", c.Value, prev, c.Name))
			continue
		}
		seen[c.Value] = c.Name
	}
	return out
}

// verdictFindings reports a table that is empty or that lacks an accepted or a
// refused case. A table with only one verdict would pass a consumer that
// accepts everything, or one that refuses everything.
func verdictFindings(cases []Case) []string {
	if len(cases) == 0 {
		return []string{"table is empty"}
	}
	var accepted, refused int
	for _, c := range cases {
		if c.OK {
			accepted++
		} else {
			refused++
		}
	}
	var out []string
	if accepted == 0 {
		out = append(out, "table has no accepted case")
	}
	if refused == 0 {
		out = append(out, "table has no refused case")
	}
	return out
}

// unnamedInvalidFindings reports a value that is not valid UTF-8 whose name does
// not carry invalidEncodingMarker. Values are printed with %q so raw bytes never
// reach the test output.
func unnamedInvalidFindings(cases []Case) []string {
	var out []string
	for _, c := range cases {
		if !utf8.ValidString(c.Value) && !strings.Contains(c.Name, invalidEncodingMarker) {
			out = append(out, fmt.Sprintf("case %q has value %q, which is not valid UTF-8, and its name does not say %q",
				c.Name, c.Value, invalidEncodingMarker))
		}
	}
	return out
}

// markedValidFindings reports a case whose name carries invalidEncodingMarker
// while its value is valid, so the marker cannot label ordinary text.
func markedValidFindings(cases []Case) []string {
	var out []string
	for _, c := range cases {
		if utf8.ValidString(c.Value) && strings.Contains(c.Name, invalidEncodingMarker) {
			out = append(out, fmt.Sprintf("case %q is named as invalid UTF-8 but its value %q is valid", c.Name, c.Value))
		}
	}
	return out
}

// encodingFindings runs both UTF-8 rules: the unnamed invalid value and the
// marker on a valid value.
func encodingFindings(cases []Case) []string {
	return append(unnamedInvalidFindings(cases), markedValidFindings(cases)...)
}

// checkTable runs every consistency check on one table.
func checkTable(cases []Case) []string {
	var out []string
	out = append(out, nameFindings(cases)...)
	out = append(out, valueFindings(cases)...)
	out = append(out, verdictFindings(cases)...)
	out = append(out, encodingFindings(cases)...)
	return out
}

// renderSubtestName returns the name testing shows for t.Run(name): every
// space-like rune becomes '_' and a rune that is not printable is written as
// its escape. It mirrors rewrite in the standard library's testing package.
func renderSubtestName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case isTestingSpace(r):
			b.WriteByte('_')
		case !strconv.IsPrint(r):
			q := strconv.QuoteRune(r)
			b.WriteString(q[1 : len(q)-1])
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// isTestingSpace reports the runes that testing renders as '_'. It mirrors
// isSpace in the standard library's testing package, which is not the Unicode
// White_Space set.
func isTestingSpace(r rune) bool {
	if r < 0x2000 {
		switch r {
		case '\t', '\n', '\v', '\f', '\r', ' ', 0x85, 0xA0, 0x1680:
			return true
		}
		return false
	}
	if r <= 0x200a {
		return true
	}
	switch r {
	case 0x2028, 0x2029, 0x202f, 0x205f, 0x3000:
		return true
	}
	return false
}

// declaredCaseTables returns the sorted names of the top-level variables in src
// whose type is []Case, either declared or taken from a composite literal.
func declaredCaseTables(src []byte) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), sourceFile, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", sourceFile, err)
	}
	var names []string
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, ident := range vs.Names {
				if isCaseSlice(vs.Type) || (len(vs.Values) == len(vs.Names) && isCaseSliceLiteral(vs.Values[i])) {
					names = append(names, ident.Name)
				}
			}
		}
	}
	sort.Strings(names)
	return names, nil
}

// isCaseSlice reports whether expr is the type []Case.
func isCaseSlice(expr ast.Expr) bool {
	arr, ok := expr.(*ast.ArrayType)
	if !ok || arr.Len != nil {
		return false
	}
	id, ok := arr.Elt.(*ast.Ident)
	return ok && id.Name == caseTypeName
}

// isCaseSliceLiteral reports whether expr is a composite literal of type []Case.
func isCaseSliceLiteral(expr ast.Expr) bool {
	lit, ok := expr.(*ast.CompositeLit)
	return ok && lit.Type != nil && isCaseSlice(lit.Type)
}

// sortedTableNames returns the keys of tablesByName in order, so failures
// come out in the same order on every run.
func sortedTableNames() []string {
	names := make([]string, 0, len(tablesByName))
	for name := range tablesByName {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// TestConformanceTableListIsComplete checks that tablesByName lists exactly the
// []Case variables that exportconform.go declares. A table missing from the map
// would get none of the consistency checks.
func TestConformanceTableListIsComplete(t *testing.T) {
	src, err := os.ReadFile(sourceFile)
	if err != nil {
		t.Fatalf("read %s: %v", sourceFile, err)
	}
	declared, err := declaredCaseTables(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range declared {
		if _, ok := tablesByName[name]; !ok {
			t.Errorf("%s declares table %s, which is not in tablesByName; add it so the consistency checks run on it", sourceFile, name)
		}
	}
	for _, name := range sortedTableNames() {
		if !slices.Contains(declared, name) {
			t.Errorf("tablesByName lists %s, which %s does not declare as a []%s", name, sourceFile, caseTypeName)
		}
	}
	if len(declared) == 0 {
		t.Errorf("%s declares no []%s table; the consistency checks would run on nothing", sourceFile, caseTypeName)
	}
}

// TestDeclaredCaseTablesFindsEveryCaseSlice checks the discovery that the list
// test depends on, against source that uses each form of declaration.
func TestDeclaredCaseTablesFindsEveryCaseSlice(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{
			name: "literal and declared types, grouped and single",
			src: `package exportconform
type Case struct{ Name, Value string; OK bool }
var Alpha = []Case{{"a", "b", true}}
var Beta []Case
var (
	Gamma = []Case{}
	Delta = []string{"x"}
)
var Zeta = map[string]Case{}
const K = 1
`,
			want: []string{"Alpha", "Beta", "Gamma"},
		},
		{
			name: "several names on one line with literals",
			src: `package exportconform
type Case struct{ Name, Value string; OK bool }
var One, Two = []Case{}, []Case{}
`,
			want: []string{"One", "Two"},
		},
		{
			name: "no case slice at all",
			src: `package exportconform
type Case struct{ Name, Value string; OK bool }
var Count = 3
`,
			want: nil,
		},
		{
			name: "array of case is not a slice",
			src: `package exportconform
type Case struct{ Name, Value string; OK bool }
var Fixed = [2]Case{}
`,
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := declaredCaseTables([]byte(tt.src))
			if err != nil {
				t.Fatalf("declaredCaseTables: %v", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("declaredCaseTables = %q, want %q", got, tt.want)
			}
		})
	}
	if _, err := declaredCaseTables([]byte("package exportconform\nvar = ")); err == nil {
		t.Error("declaredCaseTables accepted unparseable source; want an error")
	}
}

// TestConformanceTableNamesAreUniqueAndNonEmpty checks that every case in a
// table has a name, and that no two cases in a table share a name once t.Run
// renders them, so a failure in a consumer test names exactly one row.
func TestConformanceTableNamesAreUniqueAndNonEmpty(t *testing.T) {
	for _, name := range sortedTableNames() {
		t.Run(name, func(t *testing.T) {
			for _, f := range nameFindings(tablesByName[name]) {
				t.Error(f)
			}
		})
	}
}

// TestConformanceTableValuesAppearOnce checks that each value occurs at most
// once per table.
func TestConformanceTableValuesAppearOnce(t *testing.T) {
	for _, name := range sortedTableNames() {
		t.Run(name, func(t *testing.T) {
			for _, f := range valueFindings(tablesByName[name]) {
				t.Error(f)
			}
		})
	}
}

// TestConformanceTableHasAcceptedAndRefusedCases checks that each table is not
// empty and contains at least one case that must be accepted and one that must
// be refused.
func TestConformanceTableHasAcceptedAndRefusedCases(t *testing.T) {
	for _, name := range sortedTableNames() {
		t.Run(name, func(t *testing.T) {
			for _, f := range verdictFindings(tablesByName[name]) {
				t.Error(f)
			}
		})
	}
}

// TestConformanceTableValuesAreUTF8 checks that every value is valid UTF-8, or
// that its name says the value is invalid on purpose.
func TestConformanceTableValuesAreUTF8(t *testing.T) {
	for _, name := range sortedTableNames() {
		t.Run(name, func(t *testing.T) {
			for _, f := range unnamedInvalidFindings(tablesByName[name]) {
				t.Error(f)
			}
		})
	}
}

// TestConformanceTableInvalidEncodingIsNamed checks the reverse direction: a
// case whose name claims invalid UTF-8 must really carry such a value.
func TestConformanceTableInvalidEncodingIsNamed(t *testing.T) {
	for _, name := range sortedTableNames() {
		t.Run(name, func(t *testing.T) {
			for _, f := range markedValidFindings(tablesByName[name]) {
				t.Error(f)
			}
		})
	}
}

// TestConsistencyChecksFireOnContradictoryTables feeds each check a table that
// breaks exactly one rule and expects that check to report exactly one finding,
// naming the offending row. A check with a wrong key or an inverted condition
// would stay silent here and fail the test.
func TestConsistencyChecksFireOnContradictoryTables(t *testing.T) {
	tests := []struct {
		name  string
		cases []Case
		check func([]Case) []string
		want  string // substring of the one finding, naming the offending row
	}{
		{
			name:  "duplicate name",
			cases: []Case{{"cisco", "cisco", true}, {"cisco", "ciscox", false}},
			check: nameFindings,
			want:  `case 0 name "cisco" and case 1 name "cisco"`,
		},
		{
			name:  "names that t.Run renders alike",
			cases: []Case{{"palo alto", "paloalto", true}, {"palo_alto", "paloalto-x", false}},
			check: nameFindings,
			want:  `case 0 name "palo alto" and case 1 name "palo_alto"`,
		},
		{
			name:  "name with a slash",
			cases: []Case{{"core/sw", "core", false}},
			check: nameFindings,
			want:  `name "core/sw" contains '/'`,
		},
		{
			name:  "empty name",
			cases: []Case{{"", "v", true}},
			check: nameFindings,
			want:  "case 0 has an empty name",
		},
		{
			name:  "name with a control character",
			cases: []Case{{"a\x07b", "v", true}},
			check: nameFindings,
			want:  `case 0 name "a\ab" contains U+0007`,
		},
		{
			name:  "duplicate value",
			cases: []Case{{"first", "same", true}, {"second", "same", false}},
			check: valueFindings,
			want:  `cases "first" and "second"`,
		},
		{
			name:  "no refused case",
			cases: []Case{{"a", "1", true}, {"b", "2", true}},
			check: verdictFindings,
			want:  "table has no refused case",
		},
		{
			name:  "no accepted case",
			cases: []Case{{"a", "1", false}},
			check: verdictFindings,
			want:  "table has no accepted case",
		},
		{
			name:  "empty table",
			cases: nil,
			check: verdictFindings,
			want:  "table is empty",
		},
		{
			name:  "invalid UTF-8 without the marker",
			cases: []Case{{"bad bytes", "\xff", true}},
			check: encodingFindings,
			want:  `case "bad bytes" has value "\xff"`,
		},
		{
			name:  "marker on a valid value",
			cases: []Case{{"invalid UTF-8 sample", "ok", true}},
			check: encodingFindings,
			want:  `case "invalid UTF-8 sample" is named as invalid UTF-8`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.check(tt.cases)
			if len(got) != 1 {
				t.Fatalf("got %d findings %q, want exactly 1 naming the row", len(got), got)
			}
			if !strings.Contains(got[0], tt.want) {
				t.Errorf("finding %q does not contain %q", got[0], tt.want)
			}
		})
	}
}

// TestConsistencyChecksAcceptCleanTables is the control for the test above: a
// table that obeys every rule gets no findings from any check, so the checks do
// not fire on everything.
func TestConsistencyChecksAcceptCleanTables(t *testing.T) {
	tests := []struct {
		name  string
		cases []Case
	}{
		{
			name:  "clean two-verdict table",
			cases: []Case{{"cisco", "cisco", true}, {"palo alto", "paloalto", false}},
		},
		{
			name:  "named invalid UTF-8 value is allowed",
			cases: []Case{{"invalid UTF-8 sample", "\xff", false}, {"plain", "ok", true}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkTable(tt.cases); len(got) != 0 {
				t.Errorf("clean table reported findings: %q", got)
			}
		})
	}
}

// TestRenderSubtestNameMatchesTesting checks the local copy of the rendering
// rule against the names it must produce.
func TestRenderSubtestNameMatchesTesting(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"palo alto", "palo_alto"},
		{"a\tb", "a_b"},
		{"a b", "a_b"},
		{"a　b", "a_b"},
		{"a\x07b", `a\a` + "b"},
	}
	for _, tt := range tests {
		if got := renderSubtestName(tt.in); got != tt.want {
			t.Errorf("renderSubtestName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
