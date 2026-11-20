// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions/netfacts"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
)

// These tests run net.facts and package.list_updates through the same
// path the executor uses: hostrun.Attached over SSH against the in-process
// test server. The result is classified by hostrun's own rules (one bounded
// JSON document, exit status, 1 MiB limit), and only then decoded by the
// consumer (netfacts.Decode for the traffic map, osdebian.ParseUpdates for
// the update lists). Both scripts budget against hostrun.MaxResult
// themselves; these tests check that the budget holds on the real path.

const netHostrunExecutionID = "7c1d9e52-4a3b-4f8e-9b26-0d5e8f1a2c33"

// attachedRun runs the named built-in action's script through
// hostrun.Attached with PATH set to path in front of the unchanged script.
func attachedRun(t *testing.T, action, id, path string) hostrun.Result {
	t.Helper()
	a, ok := Lookup(action)
	if !ok {
		t.Fatalf("%s is not registered", action)
	}
	script := "PATH='" + path + "'; export PATH\n" + string(a.Script)
	r, err := hostrun.Attached(context.Background(), hostrunClient(t), id, []byte(`{}`), []byte(script), a.Timeout)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// netPattern is n bytes that cover every byte value, so the cut sections
// carry bytes above 0x7e, control characters and NUL.
func netPattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*131 + i/255)
	}
	return b
}

// decodeNetDoc returns the raw JSON sections of a net.facts result, with the
// base64 data already decoded.
func decodeNetDoc(t *testing.T, out []byte) map[string]netSection {
	t.Helper()
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("result is not a JSON object: %v", err)
	}
	sections := map[string]netSection{}
	for _, c := range netFactsCommands {
		s, _ := section(t, doc, c.section)
		sections[c.section] = s
	}
	return sections
}

// Every net.facts section is at its limit on a host where every tool prints
// more than 256 KiB. The script keeps 256 KiB of addr, link and route, the
// rest of the 720 KiB total budget goes to the part of route, and the other
// sections are skipped. Each cut or skipped section says so, the result is a
// success for hostrun, and netfacts (the traffic map's reader) accepts it as
// an incomplete result.
func TestNetFactsAtLimitThroughHostrun(t *testing.T) {
	h := newNetHost(t)
	allNetTools(t, h)
	data := netPattern(netfacts.MaxSection + 44<<10)
	for _, c := range netFactsCommands {
		h.output(t, c.cmd, data)
	}
	r := attachedRun(t, "net.facts", netHostrunExecutionID, h.bin)
	if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
		t.Fatalf("class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
	}
	if len(r.Result) == 0 || len(r.Result) > hostrun.MaxResult {
		t.Fatalf("result %d bytes, want 1..%d", len(r.Result), hostrun.MaxResult)
	}
	t.Logf("worst case: result %d bytes (limit %d)", len(r.Result), hostrun.MaxResult)

	sections := decodeNetDoc(t, r.Result)
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(r.Result, &doc); err != nil {
		t.Fatal(err)
	}
	// The cut is byte-exact: section by section, the budget left after the
	// earlier sections, and the first bytes of the command's output.
	left := netfacts.MaxTotal
	for _, c := range netFactsCommands {
		s, b := section(t, doc, c.section)
		if !s.Truncated {
			t.Errorf("%s: not reported as cut: %+v", c.section, s)
		}
		if left == 0 {
			if s.Status != "skipped" || len(b) != 0 {
				t.Errorf("%s: %+v, want skipped", c.section, s)
			}
			continue
		}
		want := min(netfacts.MaxSection, left)
		if s.Status != "ok" || len(b) != want || !bytes.Equal(b, data[:want]) {
			t.Errorf("%s: status %s, %d bytes, want ok with the first %d bytes of the output", c.section, s.Status, len(b), want)
		}
		left -= len(b)
	}
	if left != 0 {
		t.Fatalf("%d bytes of the total budget unused", left)
	}

	facts, err := netfacts.Decode(r.Result)
	if err != nil {
		t.Fatalf("netfacts refuses the result: %v", err)
	}
	if !facts.Incomplete() {
		t.Fatal("netfacts reports a cut result as complete")
	}
	if got := len(sections); got != len(netFactsCommands) {
		t.Fatalf("%d sections, want %d", got, len(netFactsCommands))
	}
}

// Optional tools that are not installed are absent, an IPv6 command refused
// with "Address family not supported" is unavailable, and a command that
// exits non-zero is failed. The run is still a success, and netfacts accepts
// it as incomplete (the failed ss table), not as an error.
func TestNetFactsAbsentAndFailedThroughHostrun(t *testing.T) {
	h := newNetHost(t)
	h.tool(t, "ip", `case "$*" in *-6*) echo "RTNETLINK answers: Address family not supported by protocol" >&2; exit 2 ;; esac`)
	h.tool(t, "bridge", "")
	h.tool(t, "ss", `echo "ss: cannot open netlink socket" >&2; exit 1`)
	// lldpcli and conntrack are not installed: they are not in h.bin.
	h.output(t, "ip -j addr", []byte("[]\n"))
	r := attachedRun(t, "net.facts", netHostrunExecutionID, h.bin)
	if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
		t.Fatalf("class %s (%s), exit %d", r.Class, r.Detail, r.ExitCode)
	}
	sections := decodeNetDoc(t, r.Result)
	want := map[string]string{
		"addr": "ok", "link": "ok", "route": "ok", "route6": "unavailable",
		"neigh": "ok", "neigh6": "unavailable", "bridge_vlan": "ok",
		"lldp": "absent", "sockets": "failed", "conntrack": "absent",
	}
	for name, status := range want {
		if got := sections[name].Status; got != status {
			t.Errorf("%s: status %q, want %q", name, got, status)
		}
	}
	facts, err := netfacts.Decode(r.Result)
	if err != nil {
		t.Fatalf("netfacts refuses the result: %v", err)
	}
	if !facts.IPv6Unavailable() {
		t.Error("IPv6 disabled on the host is not reported as unavailable")
	}
	if !facts.Incomplete() {
		t.Error("a failed sockets table is reported as complete")
	}
	if s := facts.Sections["sockets"]; s.Status != netfacts.StatusFailed {
		t.Errorf("sockets: %+v", s)
	}
}

// simulationLine is one Inst line of an apt-get -s upgrade on a host with
// long package names, epochs, security and other sources and kernels.
func simulationLine(i int) string {
	name := fmt.Sprintf("libexample-long-package-name-component-%05d-runtime-x", i)
	old := fmt.Sprintf("1:2.%d.%d-%d+deb12u%d", i%9, i%31, i%5+1, i%4+1)
	newv := fmt.Sprintf("1:2.%d.%d-%d+deb12u%d", i%9, i%31+1, i%5+1, i%4+2)
	archive := "Debian:12/stable"
	if i%3 == 0 {
		archive = "Debian-Security:12/stable-security"
	}
	if i%500 == 0 {
		name = fmt.Sprintf("linux-image-6.1.0-%d-amd64", 20+i/500)
		old, newv, archive = "6.1.112-1", "6.1.115-1", "Debian-Security:12/stable-security"
	}
	return fmt.Sprintf("Inst %s [%s] (%s %s [amd64])", name, old, newv, archive)
}

// listUpdatesSimulationHost is a fake host whose apt-get prints the
// simulation lines of n packages and whose apt-cache prints copies stanzas
// per requested candidate: more candidate bytes than fit next to the
// simulation in hostrun.MaxResult.
func listUpdatesSimulationHost(t *testing.T, n, copies int) *fakeHost {
	t.Helper()
	d := t.TempDir()
	f := &fakeHost{dir: d, bin: filepath.Join(d, "bin"), calls: filepath.Join(d, "calls")}
	if err := os.Mkdir(f.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	var sim strings.Builder
	sim.WriteString("Reading package lists...\n")
	for i := 1; i <= n; i++ {
		sim.WriteString(simulationLine(i) + "\n")
	}
	if err := os.WriteFile(filepath.Join(d, "sim.txt"), []byte(sim.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	f.write(t, "apt-get", `cat "`+filepath.Join(d, "sim.txt")+`"`)
	f.write(t, "apt-cache", `for a in "$@"; do [ "$a" = show ] || echo "$a"; done | awk -F= -v c=`+fmt.Sprint(copies)+` '{ for (j = 0; j < c; j++) printf "Package: %s\nVersion: %s\nSource: example-src-%s (%s)\n\n", $1, $2, substr($1, length($1) - 4), $2 }'`)
	return f
}

// A 4000-package upgrade with long names, epochs, security and other
// sources and kernels: hostrun classes it as a success, the result is within
// hostrun.MaxResult, the simulation is complete, and the candidate section
// is cut and marked as cut. osdebian reads the same counts as the script.
func TestListUpdatesAt4000PackagesThroughHostrun(t *testing.T) {
	const n = 4000
	f := listUpdatesSimulationHost(t, n, 3)
	r := attachedRun(t, "package.list_updates", netHostrunExecutionID, f.bin+":/usr/bin:/bin")
	if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
		t.Fatalf("class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
	}
	if len(r.Result) == 0 || len(r.Result) > hostrun.MaxResult {
		t.Fatalf("result %d bytes, want 1..%d", len(r.Result), hostrun.MaxResult)
	}
	t.Logf("4000 packages: result %d bytes (limit %d)", len(r.Result), hostrun.MaxResult)

	var doc map[string]any
	if err := json.Unmarshal(r.Result, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["candidates_truncated"] != true {
		t.Fatalf("candidates_truncated = %v, want true", doc["candidates_truncated"])
	}
	// The simulation the script printed has every Inst line of the fake.
	sim, err := base64.StdEncoding.DecodeString(doc["simulate"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(sim), "Inst "); got != n {
		t.Fatalf("simulation has %d Inst lines, want %d", got, n)
	}

	u, err := osdebian.ParseUpdates(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	wantSecurity := 0
	wantKernel := 0
	for i := 1; i <= n; i++ {
		if i%3 == 0 || i%500 == 0 {
			wantSecurity++
		}
		if i%500 == 0 {
			wantKernel++
		}
	}
	if len(u.Packages) != n || u.Security != wantSecurity || u.Kernel != wantKernel || !u.CandidatesTruncated {
		t.Fatalf("%d packages (want %d), security %d (want %d), kernel %d (want %d), truncated %v",
			len(u.Packages), n, u.Security, wantSecurity, u.Kernel, wantKernel, u.CandidatesTruncated)
	}
	known := 0
	for _, p := range u.Packages {
		if p.SourceVersion == "" {
			continue
		}
		known++
		if p.SourceName == "" {
			t.Fatalf("%s: source version without name", p.Name)
		}
	}
	if known == 0 || known == n {
		t.Fatalf("%d of %d sources known, want a cut part", known, n)
	}
}

// The simulation fails (apt-get exits non-zero, e.g. broken packages).
// The script must not turn that into a successful, empty update list; the
// run ends with a failure class and no result.
func TestListUpdatesSimulationFailureThroughHostrun(t *testing.T) {
	d := t.TempDir()
	f := &fakeHost{dir: d, bin: filepath.Join(d, "bin"), calls: filepath.Join(d, "calls")}
	if err := os.Mkdir(f.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	f.write(t, "apt-get", `echo "Inst libfoo1 [1.2-3] (1.2-4 Debian:12/stable [amd64])"; echo "E: Broken packages" >&2; exit 100`)
	r := attachedRun(t, "package.list_updates", netHostrunExecutionID, f.bin+":/usr/bin:/bin")
	if r.Class == hostrun.ClassSuccess {
		t.Fatalf("failed simulation classed as success: %s", r.Result)
	}
	if r.Class != hostrun.ClassScriptFailed || r.ExitCode == 0 || len(r.Result) != 0 {
		t.Fatalf("class %s, exit %d, result %q", r.Class, r.ExitCode, r.Result)
	}
}

// A host without apt-get is not a Debian host: the script fails with its
// message on stderr, prints no document, and hostrun reports the failure.
func TestListUpdatesWithoutAptGetThroughHostrun(t *testing.T) {
	d := t.TempDir()
	bin := filepath.Join(d, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	r := attachedRun(t, "package.list_updates", netHostrunExecutionID, bin)
	if r.Class != hostrun.ClassScriptFailed || r.ExitCode != 3 || len(r.Result) != 0 {
		t.Fatalf("class %s, exit %d, result %q", r.Class, r.ExitCode, r.Result)
	}
	if !bytes.Contains(r.Log, []byte("not a Debian or Ubuntu host")) {
		t.Errorf("log %q lacks the reason", r.Log)
	}
}
