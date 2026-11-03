// SPDX-License-Identifier: AGPL-3.0-or-later

package live

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// nodeBinary returns the Node.js binary that runs the client harness.
// The client logic is JavaScript; without Node.js it cannot be checked,
// so a missing binary fails the test instead of passing silently.
func nodeBinary(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"node", "nodejs"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Fatal("Node.js (node) is not on PATH; it is needed to run the live client harness")
	return ""
}

// The live block of inventory.js runs against a fake DOM, stream, fetch
// and clock (testdata/live_client.js): a wrong drop or stale rule fails
// here, not only a changed string.
func TestLiveClientBehaviour(t *testing.T) {
	node := nodeBinary(t)
	harness, err := filepath.Abs(filepath.Join("testdata", "live_client.js"))
	if err != nil {
		t.Fatal(err)
	}
	block := liveClientBlock(t) + "\n})();\n"
	for _, scenario := range []string{
		"boxes",  // node, guest and host boxes are requested; values render
		"drop",   // a box not granted loses its live line
		"stale",  // no value for 15 s shows the age without any event
		"hidden", // a hidden page releases every box
	} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, node, harness, scenario)
			cmd.Dir = t.TempDir()
			cmd.Env = []string{"PATH=/usr/bin:/bin", "NODE_OPTIONS="}
			cmd.Stdin = strings.NewReader(block)
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := cmd.Run(); err != nil {
				t.Fatalf("harness %s: %v\n%s", scenario, err, out.String())
			}
			if got := strings.TrimSpace(out.String()); got != "ok "+scenario {
				t.Fatalf("harness %s output = %q, want %q", scenario, got, "ok "+scenario)
			}
		})
	}
}
