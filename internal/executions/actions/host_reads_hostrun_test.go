// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/hostmetrics"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
)

// readExecutionID is a fixed run ID for the read-only builtins below.
const readExecutionID = "3f1c9d52-7a0e-4b8d-9c61-2e5a8f704d19"

// The tests in this file run core.facts, host.metrics and filesystem.list
// the way the executor does: as an attached run over SSH, classified by
// hostrun.Attached. Nothing runs the script with /bin/sh directly. The only
// text placed in front of the unchanged script is PATH, which puts the fake
// commands in front of the real ones.

// runReadThroughHostrun runs builtin id over hostrunClient's SSH channel
// with fakes from f first on PATH.
func runReadThroughHostrun(t *testing.T, id string, f *fakeHost) hostrun.Result {
	t.Helper()
	a, ok := Lookup(id)
	if !ok {
		t.Fatalf("%s is not registered", id)
	}
	script := "PATH='" + f.bin + ":/usr/bin:/bin'; export PATH\n" + string(a.Script)
	r, err := hostrun.Attached(context.Background(), hostrunClient(t), readExecutionID, []byte(`{}`), []byte(script), a.Timeout)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// requireAcceptedResult checks what the executor checks before it parses:
// class success with the expected exit code, a result within the limit that
// is one JSON document, and only printable ASCII (the scripts' output is
// JSON with base64 values, so nothing else may reach the parser).
func requireAcceptedResult(t *testing.T, r hostrun.Result, wantExit int) {
	t.Helper()
	if r.Class != hostrun.ClassSuccess || r.ExitCode != wantExit {
		t.Fatalf("class %s (%s), exit %d, want success with exit %d; log %q", r.Class, r.Detail, r.ExitCode, wantExit, r.Log)
	}
	if len(r.Result) == 0 || len(r.Result) > hostrun.MaxResult {
		t.Fatalf("result %d bytes, want 1..%d", len(r.Result), hostrun.MaxResult)
	}
	for i, b := range r.Result {
		if (b < 0x20 && b != '\n') || b > 0x7e {
			t.Fatalf("result byte %d is raw %#x:\n%s", i, b, r.Result)
		}
	}
	var doc map[string]any
	if err := json.Unmarshal(r.Result, &doc); err != nil {
		t.Fatalf("result is not one JSON object: %v\n%s", err, r.Result)
	}
}

// newReadFake returns a fake host whose bin directory holds the fakes.
func newReadFake(t *testing.T) *fakeHost {
	t.Helper()
	d := t.TempDir()
	f := &fakeHost{dir: d, bin: filepath.Join(d, "bin")}
	if err := os.Mkdir(f.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	return f
}

// serveRaw makes the fake name print data, raw bytes included, on stdout.
func serveRaw(t *testing.T, f *fakeHost, name string, data []byte) {
	t.Helper()
	p := filepath.Join(f.dir, name+".out")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	f.write(t, name, `cat "`+p+`"`)
}

// redirectAwk installs an awk fake that runs the real awk with the /proc
// paths in files replaced by fixtures. Other arguments are untouched.
func redirectAwk(t *testing.T, f *fakeHost, files map[string]string) {
	t.Helper()
	awk, err := exec.LookPath("awk")
	if err != nil {
		t.Fatal(err)
	}
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
	var cases strings.Builder
	for _, p := range []string{"/proc/stat", "/proc/loadavg", "/proc/meminfo"} {
		fmt.Fprintf(&cases, "    %s) a=%s;;\n", p, quote(files[p]))
	}
	f.write(t, "awk", `n=$#; i=0
while [ "$i" -lt "$n" ]; do
  a=$1; shift
  case $a in
`+cases.String()+`  esac
  set -- "$@" "$a"
  i=$((i+1))
done
exec `+quote(awk)+` "$@"`)
}

// Raw bytes from the host, as they would arrive in a command's output. The
// filesystem list and the metrics both read a df table; the header line is
// skipped by the scripts.
const dfHeader = "Filesystem Type 1B-blocks Used Available Capacity Mounted on\n"

// coreFactsDoc is the core.facts document the parser reads: base64 values
// and a boolean, nothing else.
type coreFactsDoc struct {
	OSRelease string `json:"os_release"`
	Uname     string `json:"uname"`
	Hostname  string `json:"hostname"`
	Uptime    string `json:"uptime"`
	Proxmox   bool   `json:"proxmox"`
}

// decodeCoreFacts decodes the document strictly: no unknown members, and
// each base64 value decodes.
func decodeCoreFacts(t *testing.T, result []byte) (coreFactsDoc, map[string][]byte) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(result))
	dec.DisallowUnknownFields()
	var doc coreFactsDoc
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("core.facts document: %v\n%s", err, result)
	}
	values := map[string][]byte{}
	for name, s := range map[string]string{"os_release": doc.OSRelease, "uname": doc.Uname, "hostname": doc.Hostname, "uptime": doc.Uptime} {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("core.facts %s is not base64: %v", name, err)
		}
		values[name] = b
	}
	return doc, values
}

func TestCoreFactsThroughHostrunReportsHostValues(t *testing.T) {
	f := newReadFake(t)
	f.write(t, "uname", `echo "Linux 6.1.0-test x86_64"`)
	f.write(t, "hostname", `echo "test-host"`)
	r := runReadThroughHostrun(t, "core.facts", f)
	requireAcceptedResult(t, r, 0)
	doc, values := decodeCoreFacts(t, r.Result)
	if got := string(values["uname"]); got != "Linux 6.1.0-test x86_64\n" {
		t.Errorf("uname = %q", got)
	}
	if got := string(values["hostname"]); got != "test-host\n" {
		t.Errorf("hostname = %q", got)
	}
	if _, err := base64.StdEncoding.DecodeString(doc.Uptime); err != nil {
		t.Errorf("uptime not base64: %v", err)
	}
}

// The fakes exit 1. The script's pipelines end in base64, whose status is
// zero, so the run is still a success with empty values, never a missing result.
func TestCoreFactsThroughHostrunFailingToolsGiveEmptyValues(t *testing.T) {
	f := newReadFake(t)
	f.write(t, "uname", `exit 1`)
	f.write(t, "hostname", `exit 1`)
	r := runReadThroughHostrun(t, "core.facts", f)
	requireAcceptedResult(t, r, 0)
	_, values := decodeCoreFacts(t, r.Result)
	if len(values["uname"]) != 0 || len(values["hostname"]) != 0 {
		t.Errorf("uname %q, hostname %q, want empty", values["uname"], values["hostname"])
	}
}

// Hostname and kernel strings with quotes, backslashes, tabs, control
// bytes and invalid UTF-8 reach the document as base64 and decode to the
// exact bytes the host sent.
func TestCoreFactsThroughHostrunHostileValues(t *testing.T) {
	uname := []byte("Linux \"k\"\\ \t\x01\xff\n")
	hostname := []byte("h\"o\\s\t\x1b\xc3(\n")
	f := newReadFake(t)
	serveRaw(t, f, "uname", uname)
	serveRaw(t, f, "hostname", hostname)
	r := runReadThroughHostrun(t, "core.facts", f)
	requireAcceptedResult(t, r, 0)
	_, values := decodeCoreFacts(t, r.Result)
	if !bytes.Equal(values["uname"], uname) || !bytes.Equal(values["hostname"], hostname) {
		t.Errorf("uname %q, hostname %q, want %q and %q", values["uname"], values["hostname"], uname, hostname)
	}
}

// metricsFake returns a fake host for host.metrics whose /proc inputs are
// fixtures. The first /proc/stat reading is stat, and the fake sleep between
// the two CPU samples replaces it with stat2, so the CPU percentage is
// deterministic: busy 300 of 400 ticks = 75.0.
func metricsFake(t *testing.T) (*fakeHost, map[string]string) {
	t.Helper()
	f := newReadFake(t)
	files := map[string]string{
		"/proc/stat":    filepath.Join(f.dir, "stat"),
		"/proc/loadavg": filepath.Join(f.dir, "loadavg"),
		"/proc/meminfo": filepath.Join(f.dir, "meminfo"),
	}
	fixtures := map[string]string{
		files["/proc/stat"]:           "cpu  1000 0 0 1000 0 0 0 0 0 0\n",
		filepath.Join(f.dir, "stat2"): "cpu  1300 0 0 1100 0 0 0 0 0 0\n",
		files["/proc/loadavg"]:        "0.50 0.40 0.30 1/200 1234\n",
		files["/proc/meminfo"]:        "MemTotal: 16777216 kB\nMemAvailable: 4194304 kB\n",
	}
	for p, body := range fixtures {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	redirectAwk(t, f, files)
	f.write(t, "sleep", `cp "`+filepath.Join(f.dir, "stat2")+`" "`+files["/proc/stat"]+`"`)
	return f, files
}

// dfTable is a df -P -T table with the header line first.
func dfTable(rows ...string) []byte {
	return []byte(dfHeader + strings.Join(rows, "\n") + "\n")
}

func TestHostMetricsThroughHostrunReportsHostValues(t *testing.T) {
	f, _ := metricsFake(t)
	serveRaw(t, f, "df", dfTable("/dev/a ext4 1099511627776 644245094400 455266533376 59% /data"))
	r := runReadThroughHostrun(t, "host.metrics", f)
	requireAcceptedResult(t, r, 0)
	m, err := hostmetrics.ParseMetrics(r.Result)
	if err != nil {
		t.Fatalf("ParseMetrics: %v", err)
	}
	if m.Phase != "done" {
		t.Fatalf("phase %q", m.Phase)
	}
	if !m.CPU.Available || m.CPU.Percent != 75 {
		t.Errorf("cpu = %+v, want 75.0", m.CPU)
	}
	if !m.Load.Available || m.Load.Min1 != 0.5 || m.Load.Min5 != 0.4 || m.Load.Min15 != 0.3 {
		t.Errorf("load = %+v", m.Load)
	}
	if !m.Mem.Available || m.Mem.UsedBytes != 12884901888 || m.Mem.TotalBytes != 17179869184 {
		t.Errorf("mem = %+v", m.Mem)
	}
	if !m.Disk.Available || m.Disk.Mount != "/data" || m.Disk.UsedBytes != 644245094400 || m.Disk.TotalBytes != 1099511627776 {
		t.Errorf("disk = %+v", m.Disk)
	}
}

// A failing df and a failing awk leave every value empty, which the parser
// reads as unavailable (never a zero). The run is still a success.
func TestHostMetricsThroughHostrunFailedReadsAreUnavailable(t *testing.T) {
	f, _ := metricsFake(t)
	f.write(t, "df", `exit 1`)
	f.write(t, "awk", `exit 1`)
	r := runReadThroughHostrun(t, "host.metrics", f)
	requireAcceptedResult(t, r, 0)
	m, err := hostmetrics.ParseMetrics(r.Result)
	if err != nil {
		t.Fatalf("ParseMetrics: %v", err)
	}
	if m.CPU.Available || m.Load.Available || m.Mem.Available || m.Disk.Available {
		t.Errorf("metrics available although every reading failed: %+v", m)
	}
}

// Host text in the fullest mount reaches the document as base64. A mount the
// parser can take (quotes, backslashes) comes through exactly. A tab splits
// the mount in df's output, and the scripts join the parts with a single
// space. This is a known limitation: a tab or a run of spaces in a mount
// point is not preserved (the script splits df's whitespace-separated
// columns), but it is never injected into the document. A control byte makes
// the disk reading unavailable; it never falls back to a neighbouring row.
func TestHostMetricsThroughHostrunHostileMounts(t *testing.T) {
	neighbour := "/dev/y ext4 1000 100 900 10% /neighbour"
	for _, tc := range []struct {
		name, row, wantMount string
		wantAvailable        bool
	}{
		{"quote and backslash", `/dev/x ext4 1000 950 50 95% /a"b\c`, `/a"b\c`, true},
		{"tab", "/dev/x ext4 1000 950 50 95% /t\tx", "/t x", true},
		{"control byte", "/dev/x ext4 1000 950 50 95% /c\x01x", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, _ := metricsFake(t)
			serveRaw(t, f, "df", dfTable(neighbour, tc.row))
			r := runReadThroughHostrun(t, "host.metrics", f)
			requireAcceptedResult(t, r, 0)
			m, err := hostmetrics.ParseMetrics(r.Result)
			if err != nil {
				t.Fatalf("ParseMetrics: %v", err)
			}
			if m.Disk.Available != tc.wantAvailable {
				t.Fatalf("disk available = %v, want %v: %+v", m.Disk.Available, tc.wantAvailable, m.Disk)
			}
			if !tc.wantAvailable {
				return
			}
			if m.Disk.Mount != tc.wantMount || m.Disk.UsedBytes != 950 || m.Disk.TotalBytes != 1000 {
				t.Errorf("disk = %+v, want mount %q with the row's own counters 950/1000", m.Disk, tc.wantMount)
			}
		})
	}
}

// Fixed table: the virtual filesystems are excluded by the parser, and each
// real mount keeps its own counters.
func TestFilesystemListThroughHostrunReportsMounts(t *testing.T) {
	f := newReadFake(t)
	serveRaw(t, f, "df", dfTable(
		"/dev/a ext4 1000 10 990 1% /",
		"/dev/b xfs 2000 500 1500 25% /data",
		"proc proc 0 0 0 - /proc",
		"tmpfs tmpfs 1000 100 900 10% /run",
	))
	r := runReadThroughHostrun(t, "filesystem.list", f)
	requireAcceptedResult(t, r, 0)
	fs, err := hostmetrics.ParseFilesystems(r.Result)
	if err != nil {
		t.Fatalf("ParseFilesystems: %v", err)
	}
	if !fs.Available || fs.Phase != "done" {
		t.Fatalf("available %v, phase %q", fs.Available, fs.Phase)
	}
	want := []hostmetrics.Mount{
		{FSType: "ext4", Mount: "/", SizeBytes: 1000, UsedBytes: 10},
		{FSType: "xfs", Mount: "/data", SizeBytes: 2000, UsedBytes: 500},
	}
	if len(fs.Mounts) != len(want) {
		t.Fatalf("mounts = %+v, want %+v", fs.Mounts, want)
	}
	for i, w := range want {
		g := fs.Mounts[i]
		if g.FSType != w.FSType || g.Mount != w.Mount || g.SizeBytes != w.SizeBytes || g.UsedBytes != w.UsedBytes {
			t.Errorf("mount[%d] = %+v, want %+v", i, g, w)
		}
	}
}

// A failing df gives no rows: a success with an unavailable listing.
func TestFilesystemListThroughHostrunFailedReadIsUnavailable(t *testing.T) {
	f := newReadFake(t)
	f.write(t, "df", `exit 1`)
	r := runReadThroughHostrun(t, "filesystem.list", f)
	requireAcceptedResult(t, r, 0)
	fs, err := hostmetrics.ParseFilesystems(r.Result)
	if err != nil {
		t.Fatalf("ParseFilesystems: %v", err)
	}
	if fs.Available || len(fs.Mounts) != 0 {
		t.Errorf("listing available with no df output: %+v", fs)
	}
}

// Hostile mount points: quotes, backslashes, a tab (which df's output
// splits) and a control byte. A row with a control byte is rejected by the
// parser, which makes the listing incomplete. The good rows around it keep
// their own counters.
func TestFilesystemListThroughHostrunHostileMounts(t *testing.T) {
	f := newReadFake(t)
	serveRaw(t, f, "df", dfTable(
		`/dev/a ext4 1000 10 990 1% /"q"`,
		`/dev/b ext4 1000 20 980 2% /back\slash`,
		"/dev/c ext4 1000 30 970 3% /ctl\x01x",
		"/dev/e ext4 1000 50 950 5% /tab\tx",
		"/dev/f ext4 1000 60 940 6% /after",
	))
	r := runReadThroughHostrun(t, "filesystem.list", f)
	requireAcceptedResult(t, r, 0)
	fs, err := hostmetrics.ParseFilesystems(r.Result)
	if err != nil {
		t.Fatalf("ParseFilesystems: %v", err)
	}
	if fs.Available {
		t.Errorf("listing with rejected rows is marked complete: %+v", fs.Mounts)
	}
	want := map[string]uint64{`/"q"`: 10, `/back\slash`: 20, "/tab x": 50, "/after": 60}
	if len(fs.Mounts) != len(want) {
		t.Fatalf("mounts = %+v, want exactly the four valid rows", fs.Mounts)
	}
	for _, m := range fs.Mounts {
		used, ok := want[m.Mount]
		if !ok || m.UsedBytes != used || m.SizeBytes != 1000 || m.FSType != "ext4" {
			t.Errorf("mount %+v does not match its own row (want used %d)", m, used)
		}
	}
}

// Invalid UTF-8 in a mount is rejected by the parser for the whole document
// (fail closed), not made into a value. The run itself is still a success.
func TestHostMetricsThroughHostrunInvalidUTF8RejectsDocument(t *testing.T) {
	f, _ := metricsFake(t)
	serveRaw(t, f, "df", dfTable("/dev/x ext4 1000 950 50 95% /u\xff"))
	r := runReadThroughHostrun(t, "host.metrics", f)
	requireAcceptedResult(t, r, 0)
	if m, err := hostmetrics.ParseMetrics(r.Result); err == nil {
		t.Fatalf("ParseMetrics accepted invalid UTF-8 in the mount: %+v", m.Disk)
	}
}

func TestFilesystemListThroughHostrunInvalidUTF8RejectsDocument(t *testing.T) {
	f := newReadFake(t)
	serveRaw(t, f, "df", dfTable("/dev/d xfs 1000 40 960 4% /bad\xff\xfe", "/dev/f ext4 1000 60 940 6% /after"))
	r := runReadThroughHostrun(t, "filesystem.list", f)
	requireAcceptedResult(t, r, 0)
	if fs, err := hostmetrics.ParseFilesystems(r.Result); err == nil {
		t.Fatalf("ParseFilesystems accepted invalid UTF-8 in a mount: %+v", fs.Mounts)
	}
}
