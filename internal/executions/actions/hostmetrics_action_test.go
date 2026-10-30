// SPDX-License-Identifier: AGPL-3.0-or-later
package actions

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/hostmetrics"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// P1-22: host.metrics and filesystem.list are read-only LOW telemetry
// actions. They must be registered, declared read-only and LOW (so they can
// be scheduled and retried), and carry distinct non-empty scripts.
func TestHostTelemetryActionsAreLowReadOnly(t *testing.T) {
	for _, id := range []string{"host.metrics", "filesystem.list"} {
		t.Run(id, func(t *testing.T) {
			a, ok := Lookup(id)
			if !ok {
				t.Fatalf("%s is not registered", id)
			}
			if a.Risk != pb.RiskClass_RISK_CLASS_LOW {
				t.Errorf("%s risk = %v, want LOW", id, a.Risk)
			}
			if !a.ReadOnly {
				t.Errorf("%s is not marked read-only", id)
			}
			if len(a.Script) == 0 {
				t.Errorf("%s has an empty script", id)
			}
			if a.Durable {
				t.Errorf("%s is a read-only action, not durable", id)
			}
		})
	}
	// The two scripts must be distinct.
	m, _ := Lookup("host.metrics")
	f, _ := Lookup("filesystem.list")
	if m.SHA256() == f.SHA256() {
		t.Fatal("host.metrics and filesystem.list share the same script")
	}
}

// runTelemetryScript runs a read-only telemetry script on this host and
// returns its single JSON line. The scripts only read /proc and run df, so
// this is safe and hermetic with respect to the rest of the system.
func runTelemetryScript(t *testing.T, script []byte) []byte {
	t.Helper()
	p := filepath.Join(t.TempDir(), "action.sh")
	if err := os.WriteFile(p, script, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("/bin/sh", p).CombinedOutput()
	if err != nil {
		t.Fatalf("run %s: %v\n%s", p, err, out)
	}
	return out
}

// The scripts' output must be accepted by the hostmetrics parser and report
// phase=done, locking the script->parser format contract (host-metrics-v1 /
// fs-list-v1) end to end.
func TestHostTelemetryScriptsRoundTrip(t *testing.T) {
	m, ok := Lookup("host.metrics")
	if !ok {
		t.Fatal("host.metrics not registered")
	}
	out := runTelemetryScript(t, m.Script)
	parsed, err := hostmetrics.ParseMetrics(out)
	if err != nil {
		t.Fatalf("ParseMetrics(%q): %v", out, err)
	}
	if parsed.Phase != "done" {
		t.Fatalf("host.metrics phase = %q, want done", parsed.Phase)
	}

	f, ok := Lookup("filesystem.list")
	if !ok {
		t.Fatal("filesystem.list not registered")
	}
	out = runTelemetryScript(t, f.Script)
	fs, err := hostmetrics.ParseFilesystems(out)
	if err != nil {
		t.Fatalf("ParseFilesystems(%q): %v", out, err)
	}
	if fs.Phase != "done" {
		t.Fatalf("filesystem.list phase = %q, want done", fs.Phase)
	}
}
