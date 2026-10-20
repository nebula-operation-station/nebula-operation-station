// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The security test index (docs/implementation/security-tests.md) names
// only tests that exist, so a renamed or deleted test cannot leave a
// criterion silently uncovered.
func TestSecurityIndexNamesExistingTests(t *testing.T) {
	root := filepath.Join("..", "..")
	doc, err := os.ReadFile(filepath.Join(root, "docs", "implementation", "security-tests.md"))
	if err != nil {
		t.Fatal(err)
	}
	defined := map[string]bool{}
	fn := regexp.MustCompile(`(?m)^func ((?:Test|Fuzz)[A-Za-z0-9_]+)\(`)
	err = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if strings.HasSuffix(p, "_test.go") {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for _, m := range fn.FindAllSubmatch(b, -1) {
				defined[string(m[1])] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	named := regexp.MustCompile("`((?:Test|Fuzz)[A-Za-z0-9_]+)`").FindAllStringSubmatch(string(doc), -1)
	if len(named) < 50 {
		t.Fatalf("only %d tests named", len(named))
	}
	for _, m := range named {
		if !defined[m[1]] {
			t.Errorf("the index names %s, which does not exist", m[1])
		}
	}
	// A wildcard row (`TestH03_*`) must still match at least one test
	// (review m103, finding 6).
	for _, m := range regexp.MustCompile("`((?:Test|Fuzz)[A-Za-z0-9_]+)\\*`").FindAllStringSubmatch(string(doc), -1) {
		n := 0
		for name := range defined {
			if strings.HasPrefix(name, m[1]) {
				n++
			}
		}
		if n == 0 {
			t.Errorf("the index names %s*, which matches no test", m[1])
		}
	}
}
