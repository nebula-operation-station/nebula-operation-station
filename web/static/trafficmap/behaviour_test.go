// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficmap_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
)

// minJSTestFiles guards against a glob that silently matches too little.
const minJSTestFiles = 4

// nodeTimeout bounds the whole node test run.
const nodeTimeout = 2 * time.Minute

// nodeBinary finds Node.js. It fails rather than skips: the behavioural
// tests are part of make check and CI (the CI workflow sets up Node.js),
// and a missing interpreter must not turn them silently green.
func nodeBinary(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"node", "nodejs"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Fatalf("Node.js (node) is not on PATH (CI=%q); it is needed to run the traffic map behaviour tests (*.test.mjs)", os.Getenv("CI"))
	return ""
}

var tapCountRE = regexp.MustCompile(`(?m)^# (tests|pass|fail) (\d+)$`)

// TestJavaScriptBehaviour runs the renderer's behavioural tests
// (*.test.mjs: validator, layout, scene, bridge, backend fallback and the
// frame loop) under node --test, so a wrong implementation fails the build
// and not only a changed source string. Each file runs in its own node
// process and must declare at least one test: node counts a file that
// declares no tests as one passing test (the file itself), so a summary
// over all files would stay green when a test file is emptied.
func TestJavaScriptBehaviour(t *testing.T) {
	node := nodeBinary(t)
	files, err := filepath.Glob("*.test.mjs")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	if len(files) < minJSTestFiles {
		t.Fatalf("found %d *.test.mjs files, want at least %d", len(files), minJSTestFiles)
	}
	ctx, cancel := context.WithTimeout(context.Background(), nodeTimeout)
	defer cancel()
	for _, f := range files {
		t.Run(f, func(t *testing.T) {
			// The file is passed as an absolute path so that node names the
			// file entry (emitted for a file that declares no tests) the same
			// way on every supported node version.
			abs, err := filepath.Abs(f)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(ctx, node, "--test", "--test-reporter=tap", abs)
			cmd.Env = []string{"PATH=/usr/bin:/bin", "NODE_OPTIONS=", "NO_COLOR=1"}
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := cmd.Run(); err != nil {
				t.Fatalf("node --test %s failed: %v\n%s", f, err, out.String())
			}
			counts := tapCounts(t, out.String())
			tests := counts["tests"]
			if jsFileEntry(out.String(), f) {
				// Node lists a file that declares no tests as one passing
				// test named after the file; that is not a declared test.
				tests--
			}
			if tests < 1 {
				t.Fatalf("%s declares no tests\n%s", f, out.String())
			}
			if counts["pass"] != tests || counts["fail"] != 0 {
				t.Fatalf("node --test %s summary tests=%d pass=%d fail=%d; want all passing\n%s",
					f, tests, counts["pass"], counts["fail"], out.String())
			}
		})
	}
}

// tapCounts parses the "# tests / # pass / # fail" summary lines of
// `node --test --test-reporter=tap`.
func tapCounts(t *testing.T, tap string) map[string]int {
	t.Helper()
	counts := map[string]int{}
	for _, m := range tapCountRE.FindAllStringSubmatch(tap, -1) {
		n, err := strconv.Atoi(m[2])
		if err != nil {
			t.Fatal(err)
		}
		counts[m[1]] = n
	}
	return counts
}

// jsFileEntry reports whether the TAP output contains the entry node emits
// for a file that declares no tests: an ok line named after the file's
// absolute path.
func jsFileEntry(tap, file string) bool {
	abs, err := filepath.Abs(file)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(tap, "\n") {
		if !strings.HasPrefix(line, "ok ") {
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(line, "ok "))
		if i := strings.Index(name, " - "); i >= 0 {
			name = name[i+len(" - "):]
		}
		if name == abs {
			return true
		}
	}
	return false
}

// TestRendererSourcesAreASCII rejects non-ASCII characters in the renderer
// sources and tests. Invisible characters such as U+2028 are line
// terminators in JavaScript and once broke a regular expression literal in
// model.js; such characters must be written as \u escapes.
func TestRendererSourcesAreASCII(t *testing.T) {
	var files []string
	for _, pat := range []string{"*.js", "*.mjs"} {
		m, err := filepath.Glob(pat)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	for _, f := range files {
		for i, r := range string(readFile(t, f)) {
			if r > unicode.MaxASCII {
				t.Errorf("%s: non-ASCII character %U at byte %d; use a \\u escape", f, r, i)
				break
			}
		}
	}
}
