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
// and not only a changed source string.
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
	args := append([]string{"--test", "--test-reporter=tap"}, files...)
	cmd := exec.CommandContext(ctx, node, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "NODE_OPTIONS=", "NO_COLOR=1"}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("node --test failed: %v\n%s", err, out.String())
	}
	counts := map[string]int{}
	for _, m := range tapCountRE.FindAllStringSubmatch(out.String(), -1) {
		n, err := strconv.Atoi(m[2])
		if err != nil {
			t.Fatal(err)
		}
		counts[m[1]] = n
	}
	if counts["tests"] == 0 || counts["pass"] != counts["tests"] || counts["fail"] != 0 {
		t.Fatalf("node --test summary tests=%d pass=%d fail=%d; want all passing and at least one\n%s",
			counts["tests"], counts["pass"], counts["fail"], out.String())
	}
	t.Logf("node --test: %d JavaScript tests passed in %d files", counts["pass"], len(files))
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
