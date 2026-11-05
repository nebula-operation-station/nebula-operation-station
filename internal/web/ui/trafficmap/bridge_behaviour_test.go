// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficmap

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// minBridgeJSTests guards against a test file that silently declares too
// few tests (node counts an empty file as one passing test).
const minBridgeJSTests = 15

// bridgeNodeTimeout bounds the node test run.
const bridgeNodeTimeout = 2 * time.Minute

var bridgeTapRE = regexp.MustCompile(`(?m)^# (tests|pass|fail) (\d+)$`)

// TestBridgeJavaScriptBehaviour runs bridge.test.mjs (the parent bridge
// web/static/trafficmap-bridge.js against the renderer's validator) under
// node --test. It fails rather than skips without Node.js: CI sets it up,
// and a missing interpreter must not turn the tests silently green.
func TestBridgeJavaScriptBehaviour(t *testing.T) {
	var node string
	for _, name := range []string{"node", "nodejs"} {
		if p, err := exec.LookPath(name); err == nil {
			node = p
			break
		}
	}
	if node == "" {
		t.Fatalf("Node.js (node) is not on PATH (CI=%q); it is needed for bridge.test.mjs", os.Getenv("CI"))
	}
	abs, err := filepath.Abs("bridge.test.mjs")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), bridgeNodeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "--test", "--test-reporter=tap", abs)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "NODE_OPTIONS=", "NO_COLOR=1"}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("node --test bridge.test.mjs failed: %v\n%s", err, out.String())
	}
	counts := map[string]int{}
	for _, m := range bridgeTapRE.FindAllStringSubmatch(out.String(), -1) {
		n, _ := strconv.Atoi(m[2])
		counts[m[1]] = n
	}
	if counts["fail"] != 0 || counts["tests"] < minBridgeJSTests || counts["pass"] != counts["tests"] {
		t.Fatalf("node test counts %v, want >= %d tests, all passing\n%s", counts, minBridgeJSTests, out.String())
	}
}

// TestBridgeSourceHasNoHTMLSinksOrForeignTargets scans the parent bridge
// for APIs that would let host data become markup, code or a foreign URL.
func TestBridgeSourceHasNoHTMLSinksOrForeignTargets(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "web", "static", bridgeScript))
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if !strings.HasPrefix(src, "// SPDX-License-Identifier: AGPL-3.0-or-later\n") {
		t.Error("bridge lacks the SPDX header")
	}
	// Invisible and bidi characters must be written as \u escapes, so the
	// reviewed source is what runs (no "Trojan Source").
	if i := strings.IndexFunc(src, func(r rune) bool {
		return r == 0x2028 || r == 0x2029 || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) ||
			(r >= 0x200b && r <= 0x200f) || r == 0xfeff || (r < 0x20 && r != '\n')
	}); i >= 0 {
		t.Errorf("bridge contains an invisible or control character at byte %d", i)
	}
	code := regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(src, "")
	code = regexp.MustCompile(`(?m)(^|[^:"'])//.*$`).ReplaceAllString(code, "$1")
	for _, pat := range []string{
		`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document\.write`, `createContextualFragment`, `DOMParser`,
		`\beval\s*\(`, `new\s+Function`, `\.src\s*=`, `\.href\s*=`, `location\.href`, `window\.open`,
		`https?://`, `XMLHttpRequest`, `WebSocket`, `localStorage`, `sessionStorage`, `document\.cookie`,
		`allow-same-origin`,
	} {
		if loc := regexp.MustCompile(pat).FindStringIndex(code); loc != nil {
			t.Errorf("bridge uses forbidden API %q", code[loc[0]:loc[1]])
		}
	}
	// "*" as target origin only for the sandboxed iframe's window.
	posts := regexp.MustCompile(`postMessage\(([^)]*)\)`).FindAllStringSubmatch(code, -1)
	if len(posts) != 1 || posts[0][1] != `msg, "*"` || !strings.Contains(code, `frame.contentWindow.postMessage(msg, "*")`) {
		t.Errorf("postMessage calls %q, want exactly frame.contentWindow.postMessage(msg, \"*\")", posts)
	}
	if !strings.Contains(code, `ev.source !== frameWin || ev.origin !== "null"`) {
		t.Error("incoming messages are not checked for the iframe source and opaque origin")
	}
}
