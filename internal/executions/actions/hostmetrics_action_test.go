// SPDX-License-Identifier: AGPL-3.0-or-later
package actions

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// runFixtureTelemetry substitutes only telemetry inputs and uses a real awk.
func runFixtureTelemetry(t *testing.T, id, meminfo, dfBody, awkCommand string) map[string]any {
	t.Helper()
	dir := t.TempDir()
	f := &fakeHost{dir: dir, bin: filepath.Join(dir, "bin")}
	if err := os.Mkdir(f.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	memPath := filepath.Join(dir, "meminfo")
	if err := os.WriteFile(memPath, []byte(meminfo), 0o600); err != nil {
		t.Fatal(err)
	}
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
	f.write(t, "awk", `if [ "${2-}" = /proc/meminfo ]; then set -- "$1" `+quote(memPath)+`; fi
exec `+awkCommand+` "$@"`)
	f.write(t, "df", dfBody)
	f.write(t, "sleep", "exit 0")
	a, ok := Lookup(id)
	if !ok {
		t.Fatalf("%s not registered", id)
	}
	code, doc := f.run(t, a.Script)
	if code != 0 {
		t.Fatalf("%s exit = %d: %v", id, code, doc)
	}
	return doc
}

func TestHostMetricsScriptMemoryAndDiskCounters(t *testing.T) {
	awkPath, err := exec.LookPath("awk")
	if err != nil {
		t.Fatal(err)
	}
	awkers := map[string]string{"system": awkPath}
	if busybox, err := exec.LookPath("busybox"); err == nil {
		awkers["busybox"] = busybox + " awk"
	}
	for name, awkCommand := range awkers {
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct{ name, meminfo, want string }{
				{"large counters", "MemTotal: 16777216 kB\nMemAvailable: 4194304 kB\n", "12884901888 17179869184"},
				{"zero available with free", "MemTotal: 16777216 kB\nMemAvailable: 0 kB\nMemFree: 1024 kB\n", "17179869184 17179869184"},
				{"zero available without free", "MemTotal: 16777216 kB\nMemAvailable: 0 kB\n", "17179869184 17179869184"},
				{"absent available", "MemTotal: 16777216 kB\nMemFree: 1048576 kB\nBuffers: 1048576 kB\nCached: 2097152 kB\n", "12884901888 17179869184"},
				{"invalid available", "MemTotal: 1000 kB\nMemAvailable: 1001 kB\nMemFree: 100 kB\n", ""},
			} {
				t.Run(tc.name, func(t *testing.T) {
					doc := runFixtureTelemetry(t, "host.metrics", tc.meminfo, `printf '%s\n' 'Filesystem Type 1B-blocks Used Available Capacity Mounted on' '/dev/a ext4 1099511627776 644245094400 455266533376 59% /data'`, awkCommand)
					if got := b64(t, doc, "mem"); got != tc.want {
						t.Errorf("mem = %q, want %q", got, tc.want)
					}
					if got := b64(t, doc, "disk"); got != "/data\t644245094400\t1099511627776" {
						t.Errorf("disk = %q, want exact large counters", got)
					}
				})
			}
		})
	}
}

func TestHostMetricsScriptSelectsEmptyFilesystem(t *testing.T) {
	awkPath, err := exec.LookPath("awk")
	if err != nil {
		t.Fatal(err)
	}
	doc := runFixtureTelemetry(t, "host.metrics", "", `printf '%s\n' 'Filesystem Type 1B-blocks Used Available Capacity Mounted on' 'tmpfs tmpfs 1000 500 500 50% /run' '/dev/a ext4 1099511627776 0 1099511627776 0% /empty' '/dev/b xfs 1000 0 1000 0% /also-empty'`, awkPath)
	if got := b64(t, doc, "disk"); got != "/empty\t0\t1099511627776" {
		t.Errorf("disk = %q, want first real empty filesystem", got)
	}
}

func TestFilesystemScriptEnumeratesDuplicateAndBindMounts(t *testing.T) {
	awkPath, err := exec.LookPath("awk")
	if err != nil {
		t.Fatal(err)
	}
	doc := runFixtureTelemetry(t, "filesystem.list", "", `printf '%s\n' 'Filesystem Type 1B-blocks Used Available Capacity Mounted on' '/dev/a ext4 1000 10 990 1% /'
for arg do
  if [ "$arg" = -a ] || [ "$arg" = --all ]; then
    printf '%s\n' '/dev/a ext4 1000 10 990 1% /duplicate' '/dev/a ext4 1000 10 990 1% /bind mount' 'proc proc 0 0 0 - /proc' 'tmpfs tmpfs 1000 100 900 10% /run'
  fi
done`, awkPath)
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := hostmetrics.ParseFilesystems(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !fs.Available || len(fs.Mounts) != 3 {
		t.Fatalf("filesystems = %+v, want three real mounts", fs)
	}
	for i, mount := range []string{"/", "/duplicate", "/bind mount"} {
		if fs.Mounts[i].Mount != mount || fs.Mounts[i].FSType != "ext4" || fs.Mounts[i].SizeBytes != 1000 || fs.Mounts[i].UsedBytes != 10 {
			t.Errorf("mount[%d] = %+v, want %s with original counters", i, fs.Mounts[i], mount)
		}
	}
}
