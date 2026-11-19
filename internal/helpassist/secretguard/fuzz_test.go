// SPDX-License-Identifier: AGPL-3.0-or-later

package secretguard

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// asciiFoldContains reports whether s contains lowerPat, comparing ASCII
// letters case-insensitively. It is the test's own reference and does not
// share code with the implementation.
func asciiFoldContains(s, lowerPat string) bool {
	n := len(lowerPat)
	for i := 0; i+n <= len(s); i++ {
		ok := true
		for j := 0; j < n; j++ {
			c := s[i+j]
			if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != lowerPat[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// hasNOSTokenShape reports whether s holds "nos_" followed by at least 43
// URL-safe base64 characters.
func hasNOSTokenShape(s string) bool {
	for i := 0; i+4 <= len(s); i++ {
		if s[i:i+4] != "nos_" {
			continue
		}
		run := 0
		for j := i + 4; j < len(s); j++ {
			c := s[j]
			isB64 := ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') || c == '-' || c == '_'
			if !isB64 {
				break
			}
			run++
		}
		if run >= 43 {
			return true
		}
	}
	return false
}

// containsFixedPattern reports whether q contains one of the guard's fixed
// patterns, using the reference matchers above.
func containsFixedPattern(q string) bool {
	return asciiFoldContains(q, "-----begin") ||
		asciiFoldContains(q, "age-secret-key-") ||
		asciiFoldContains(q, "otpauth://") ||
		hasNOSTokenShape(q)
}

// FuzzCheck checks the guard's properties on arbitrary input: no panic; an
// accepted question is valid UTF-8 within the limit; a rejected question
// carries one of the fixed error texts; a question containing a fixed
// pattern is never accepted.
func FuzzCheck(f *testing.F) {
	seeds := []string{
		"",
		"How do I add a host?",
		fakePrivateKey,
		fakeAgeKey,
		fakeNOSToken,
		fakeOTPAuth,
		"-----beGIN",
		"AGE-secret-KEY-",
		"OTPAUTH://",
		"nos_",
		"\xff\xfe",
		strings.Repeat("a", MaxQuestionBytes),
		strings.Repeat("a", MaxQuestionBytes+1),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	fixed := map[string]bool{
		ErrTooLong.Error():         true,
		ErrInvalidText.Error():     true,
		ErrLooksLikeSecret.Error(): true,
	}
	f.Fuzz(func(t *testing.T, q string) {
		err := Check(q)
		if err == nil {
			if !utf8.ValidString(q) {
				t.Fatalf("accepted invalid UTF-8: %q", q)
			}
			if len(q) > MaxQuestionBytes {
				t.Fatalf("accepted question of %d bytes", len(q))
			}
		} else {
			if !fixed[err.Error()] {
				t.Fatalf("error text %q is not one of the fixed texts", err.Error())
			}
		}
		if containsFixedPattern(q) && err == nil {
			t.Fatalf("accepted a question that contains a fixed secret pattern: %q", q)
		}
	})
}

// TestSecretGuardImportsOnlyStdlib enforces that the guard imports no
// module outside the standard library: every import path's first element
// must have no dot.
func TestSecretGuardImportsOnlyStdlib(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no Go files found")
	}
	fset := token.NewFileSet()
	for _, name := range files {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			first, _, _ := strings.Cut(path, "/")
			if strings.Contains(first, ".") {
				t.Errorf("%s imports non-stdlib package %q", name, path)
			}
		}
	}
}
