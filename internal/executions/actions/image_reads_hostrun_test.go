// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
)

// image.packages and image.vulnerabilities run over SSH as attached runs
// (script -> hostrun classifier -> parser), like package.list_installed.
// Every run gets its own imageHost: a PATH with only the tools the script
// may use, fake docker and trivy, a TMPDIR of its own, and stand-ins that
// record and refuse anything a read must never run. Nothing here runs the
// script with /bin/sh directly.

// imageHostrunExec is the execution ID of every run in this file.
const imageHostrunExec = "5d1c7a2e-9b3f-4e8a-a6c1-0f2b7d9e4c31"

// imageUID is what the fake id -u prints; the vulnerability script names its
// work directory after it.
const imageUID = "1000"

// imageNameMax is the longest repository name the image parameter accepts:
// 255 characters before "@sha256:".
var imageNameMax = "n" + strings.Repeat("b/", 127)

// imageTools are the commands the image scripts use besides their fakes.
// Each is a symlink to the real binary, so nothing else is on PATH.
var imageTools = []string{"sed", "python3", "cat", "base64", "tr", "stat", "date",
	"sha256sum", "head", "grep", "awk", "wc", "mkdir", "chmod", "rm", "find", "cut", "sort"}

// forbiddenTools are stand-ins that record the call and fail: an image read
// never fetches, installs or escalates.
var forbiddenTools = []string{"sudo", "curl", "wget", "apt-get", "apk", "dnf", "yum"}

// imageHostFiles are the only entries a run may leave in the host directory.
var imageHostFiles = map[string]bool{"bin": true, "calls": true, "tmp": true, "tcache": true, "trivy-out": true}

// imageHost is a fake Docker host for one attached image read. PATH is bin
// only. TMPDIR is tmp, a directory of this test alone, so the script's work
// directory and its cache are never shared with another run (the hostrun
// bootstrap reads TMPDIR from the test process, so t.Setenv sets it for
// both).
type imageHost struct {
	dir, bin, tmp, calls string
}

// newImageHost prepares a host for one test.
func newImageHost(t *testing.T) *imageHost {
	t.Helper()
	d := t.TempDir()
	// The vulnerability script refuses a TMPDIR whose components are
	// group- or world-writable, so the test directory is private whatever
	// the runner's umask.
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	h := &imageHost{dir: d, bin: filepath.Join(d, "bin"), tmp: filepath.Join(d, "tmp"), calls: filepath.Join(d, "calls")}
	if err := os.Mkdir(h.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(h.tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tool := range imageTools {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("%s missing on this machine", tool)
		}
		if err := os.Symlink(p, filepath.Join(h.bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	h.stub(t, "id", `echo `+imageUID)
	for _, c := range forbiddenTools {
		h.stub(t, c, `echo "forbidden $0 $*" >> "`+h.calls+`"; exit 1`)
	}
	t.Setenv("TMPDIR", h.tmp)
	return h
}

// stub writes an executable fake named name into the host's bin directory.
func (h *imageHost) stub(t *testing.T, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(h.bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// packagesDocker is a fake docker for image.packages: the daemon answers,
// and an image inspect succeeds only for a local image.
func (h *imageHost) packagesDocker(t *testing.T, local bool) {
	t.Helper()
	h.stub(t, "docker", `echo "docker $*" >> "`+h.calls+`"
case "$1" in
  version) echo "27.3.1" ;;
  image) [ "`+localFlag(local)+`" = 1 ] || exit 1; echo "sha256:`+pkgsOtherHex+`" ;;
  *) exit 64 ;;
esac`)
}

// vulnsDocker is a fake docker for image.vulnerabilities: the daemon answers,
// and an image inspect prints the platform only for a local image.
func (h *imageHost) vulnsDocker(t *testing.T, local bool) {
	t.Helper()
	h.stub(t, "docker", `echo "docker $*" >> "`+h.calls+`"
case "$1" in
  version) echo "27.3.1" ;;
  image) [ "`+localFlag(local)+`" = 1 ] || exit 1
    echo "linux/amd64" ;;
  *) exit 64 ;;
esac`)
}

func localFlag(local bool) string {
	if local {
		return "1"
	}
	return "0"
}

// trivy installs a fake Trivy. It records every call as "trivy <args>" and,
// for an image scan, prints out and exits rc. The output is written into the
// host directory first; no real Trivy runs.
func (h *imageHost) trivy(t *testing.T, out []byte, rc int) {
	t.Helper()
	file := filepath.Join(h.dir, "trivy-out")
	if err := os.WriteFile(file, out, 0o600); err != nil {
		t.Fatal(err)
	}
	h.stub(t, "trivy", `echo "trivy $*" >> "`+h.calls+`"
case "$1" in
  --version) echo "Version: 0.57.1" ;;
  image) cat "`+file+`"; exit `+strconv.Itoa(rc)+` ;;
  *) exit 64 ;;
esac`)
}

// vulnDB puts a fresh, operator-managed Trivy database where the script
// reads it (TRIVY_CACHE_DIR).
func (h *imageHost) vulnDB(t *testing.T) {
	t.Helper()
	db := filepath.Join(h.dir, "tcache", "db")
	if err := os.MkdirAll(db, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(db, "trivy.db"), []byte("operator-managed database"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	meta := fmt.Sprintf(`{"Version":2,"UpdatedAt":%q,"NextUpdate":%q,"DownloadedAt":%q}`,
		now.Format(time.RFC3339Nano), now.Add(6*time.Hour).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err := os.WriteFile(filepath.Join(db, "metadata.json"), []byte(meta), 0o600); err != nil {
		t.Fatal(err)
	}
}

// readCalls returns the fake tools' call log.
func (h *imageHost) readCalls(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(h.calls)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

// assertNoLeftovers checks what a run left on the host. The hostrun
// bootstrap removes its own run directory, so the only things a read may
// leave are the vulnerability script's work directory in TMPDIR (its lock
// file and cached summaries) and the database the test put in place.
func (h *imageHost) assertNoLeftovers(t *testing.T, id string) {
	t.Helper()
	home, err := os.ReadDir(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range home {
		if !imageHostFiles[e.Name()] {
			t.Fatalf("%s left %s in the host directory", id, e.Name())
		}
	}
	top, err := os.ReadDir(h.tmp)
	if err != nil {
		t.Fatal(err)
	}
	if id != "image.vulnerabilities" {
		if len(top) != 0 {
			t.Fatalf("%s left %s in TMPDIR", id, top[0].Name())
		}
		return
	}
	for _, e := range top {
		if e.Name() != "nebula-image-vulns."+imageUID {
			t.Fatalf("%s left %s in TMPDIR", id, e.Name())
		}
		inner, err := os.ReadDir(filepath.Join(h.tmp, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range inner {
			if f.Name() != "scan.lock" && !strings.HasPrefix(f.Name(), "c-") {
				t.Fatalf("the scan work directory holds %s", f.Name())
			}
		}
	}
}

// shQuote quotes s for a POSIX shell.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// runImageHostrun runs the action's script for image as an attached run over
// SSH: the hostrun bootstrap, the classifier and the unchanged script, with
// h's PATH in front of the body. It fails the test if a forbidden command
// was called or the run left files behind.
func runImageHostrun(t *testing.T, id string, h *imageHost, image string) hostrun.Result {
	t.Helper()
	a, ok := Lookup(id)
	if !ok {
		t.Fatalf("%s is not registered", id)
	}
	params := map[string]string{"image": image}
	if err := a.ValidParams(params); err != nil {
		t.Fatalf("%s params: %v", id, err)
	}
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	prefix := "PATH=" + shQuote(h.bin) + "; HOME=" + shQuote(h.dir) +
		"; TRIVY_CACHE_DIR=" + shQuote(filepath.Join(h.dir, "tcache")) + "; export PATH HOME TRIVY_CACHE_DIR\n"
	r, err := hostrun.Attached(context.Background(), hostrunClient(t), imageHostrunExec, raw, []byte(prefix+string(a.Script)), a.Timeout)
	if err != nil {
		t.Fatal(err)
	}
	if calls := h.readCalls(t); strings.Contains(calls, "forbidden") {
		t.Fatalf("script ran a forbidden command: %s", calls)
	}
	h.assertNoLeftovers(t, id)
	return r
}

// assertImageRun checks what the executor requires of any image read: a
// success class, exit 0, one result document within hostrun.MaxResult with
// only printable ASCII (the scripts emit ASCII-escaped JSON), and a log
// within hostrun.MaxLog plus its truncation marker.
func assertImageRun(t *testing.T, r hostrun.Result) {
	t.Helper()
	if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
		t.Fatalf("class %s (%s), exit %d, log %q, result %q", r.Class, r.Detail, r.ExitCode, r.Log, r.Result)
	}
	if len(r.Result) > hostrun.MaxResult {
		t.Fatalf("result %d bytes, limit %d", len(r.Result), hostrun.MaxResult)
	}
	if len(r.Log) > hostrun.MaxLog+len(hostrun.TruncationMarker) {
		t.Fatalf("log %d bytes, limit %d", len(r.Log), hostrun.MaxLog)
	}
	for _, b := range bytes.TrimSuffix(r.Result, []byte("\n")) {
		if b < 0x20 || b > 0x7e {
			t.Fatalf("result has raw byte %#x:\n%s", b, r.Result)
		}
	}
}

// resultField returns a top-level field of a script result: a string, a
// bool, or nil when absent. The script result is always one JSON object.
func resultField(t *testing.T, result []byte, key string) any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(result, &doc); err != nil {
		t.Fatalf("result is not one JSON object: %v\n%s", err, result)
	}
	return doc[key]
}

// ---------------------------------------------------------------- packages

// pkgsEntry is one Trivy package entry; values are JSON-encoded, so any
// quote, backslash, control byte or non-ASCII value reaches the script
// exactly as the raw report carries it.
func pkgsEntry(name, version string, epoch int, release string) string {
	b, err := json.Marshal(map[string]any{"Name": name, "Version": version, "Epoch": epoch,
		"Release": release, "SrcName": "src-" + name, "SrcVersion": version, "SrcRelease": release})
	if err != nil {
		panic(err) // only strings and ints: cannot fail
	}
	return string(b)
}

// nearLimitEntry is a package at the parser's field limits: a 256-character
// name, and versions whose composed [epoch:]version[-release] is 128
// characters, the longest the parser keeps.
func nearLimitEntry(i int) string {
	pad := func(s string, n int) string { return s + strings.Repeat("x", n-len(s)) }
	b, err := json.Marshal(map[string]any{"Name": pad(fmt.Sprintf("long-%06d", i), 256),
		"Version": pad(fmt.Sprintf("2.%d", i), 96), "Epoch": 0, "Release": pad("1", 31),
		"SrcName": pad(fmt.Sprintf("src-%06d", i), 64), "SrcVersion": pad("2", 96), "SrcRelease": pad("1", 31)})
	if err != nil {
		panic(err) // only strings and ints: cannot fail
	}
	return string(b)
}

// bigDebianDoc is a Trivy report of a Debian image with n packages from
// two ecosystems: dpkg (os-pkgs, type debian, two thirds) and npm
// (lang-pkgs, one third). dpkg versions carry epochs, "~" and "+"; every
// 750th dpkg name is non-ASCII. It returns the report and the number of
// dpkg entries with non-ASCII names.
//
// The parser keeps OS packages only for the image's detected OS family,
// and an Alpine apk result in a Debian image is dropped (see
// bigAlpineDoc for apk), so the two ecosystems of a Debian image are dpkg
// and a language ecosystem.
func bigDebianDoc(n int) (string, int) {
	var dpkg, npm []string
	bad := 0
	for i := 0; i < n; i++ {
		if i%3 == 2 {
			npm = append(npm, fmt.Sprintf(`{"Name":"npm-pkg-%04d","Version":"%d.%d.%d"}`, i, i%5, i%11, i%7))
			continue
		}
		name := fmt.Sprintf("lib-pkg-%04d", i)
		if i%750 == 0 {
			name = fmt.Sprintf("lib-ü-%04d", i)
			bad++
		}
		ver := fmt.Sprintf("%d.%d~rc%d+git%d", i%40, i%13, i%7, i%997)
		dpkg = append(dpkg, pkgsEntry(name, ver, i%3, fmt.Sprintf("%d+deb12u%d", i%9+1, i%4)))
	}
	doc := `{
  "SchemaVersion": 2,
  "ArtifactName": "nginx@sha256:` + pkgsHex + `",
  "Metadata": {
    "OS": {"Family": "debian", "Name": "12.8"},
    "RepoDigests": ["nginx@sha256:` + pkgsHex + `"],
    "ImageConfig": {"config": {"Env": ["` + pkgsSecret + `"]}}
  },
  "Results": [
    {"Target": "nginx (debian 12.8)", "Class": "os-pkgs", "Type": "debian", "Packages": [` + strings.Join(dpkg, ",") + `]},
    {"Target": "usr/lib/node_modules/app", "Class": "lang-pkgs", "Type": "node-pkg", "Packages": [` + strings.Join(npm, ",") + `]}
  ]
}`
	return doc, bad
}

// bigAlpineDoc is a Trivy report of an Alpine image with n apk packages:
// versions with "_p" and "-r" release, no epochs.
func bigAlpineDoc(n int) string {
	var apk []string
	for i := 0; i < n; i++ {
		apk = append(apk, pkgsEntry(fmt.Sprintf("apk-pkg-%04d", i), fmt.Sprintf("%d.%d_p%d", i%40, i%13, i%7), 0, fmt.Sprintf("r%d", i%9)))
	}
	return `{
  "SchemaVersion": 2,
  "ArtifactName": "nginx@sha256:` + pkgsHex + `",
  "Metadata": {
    "OS": {"Family": "alpine", "Name": "3.20.3"},
    "RepoDigests": ["nginx@sha256:` + pkgsHex + `"]
  },
  "Results": [
    {"Target": "nginx (alpine 3.20.3)", "Class": "os-pkgs", "Type": "alpine", "Packages": [` + strings.Join(apk, ",") + `]}
  ]
}`
}

// pkgsTrivyStderrFlood is a fake trivy that exits 1 after writing 2 MiB to stderr.
const pkgsTrivyStderrFlood = `python3 -c "import sys; sys.stderr.write('x' * 2097152)"; exit 1`

// packagesOutput is the reduction's own verdict in the result: ok, truncated,
// toolarge or unparseable. The parser folds the last three into one reason,
// so the tests check this field to tell them apart.
func packagesOutput(t *testing.T, result []byte) string {
	t.Helper()
	s, _ := resultField(t, result, "output").(string)
	return s
}

// TestImagePackagesThroughHostrunLargeReport: 3000 packages of a Debian
// image from two ecosystems (dpkg and npm). The result is a success, below
// the limit, the parser gives every package, and the reduction changes
// nothing the parser judges.
func TestImagePackagesThroughHostrunLargeReport(t *testing.T) {
	h := newImageHost(t)
	h.packagesDocker(t, true)
	raw, bad := bigDebianDoc(3000)
	h.trivy(t, []byte(raw), 0)
	r := runImageHostrun(t, "image.packages", h, pkgsImage)
	assertImageRun(t, r)
	t.Logf("3000 packages: result %d bytes (limit %d), %d non-ASCII dpkg names", len(r.Result), hostrun.MaxResult, bad)
	if got := packagesOutput(t, r.Result); got != "ok" {
		t.Fatalf("output %q, want ok", got)
	}
	p := parsePkgs(t, r.Result)
	sameAsRaw(t, raw, p)
	if !p.Known || !p.Complete || p.Reason != "" {
		t.Fatalf("known=%v complete=%v reason=%q, want a complete read", p.Known, p.Complete, p.Reason)
	}
	eco := map[string]int{}
	for _, pkg := range p.Packages {
		eco[pkg.Ecosystem]++
	}
	if len(p.Packages) != 3000 {
		t.Fatalf("%d packages %v, want all 3000", len(p.Packages), eco)
	}
	if eco["debian"] != 2000 || eco["node-pkg"] != 1000 {
		t.Fatalf("ecosystems %v, want debian 2000 and node-pkg 1000", eco)
	}
	// Non-ASCII names are valid for the parser: they arrive unchanged.
	kept := 0
	for _, pkg := range p.Packages {
		if strings.HasPrefix(pkg.Name, "lib-ü-") {
			kept++
		}
	}
	if kept != bad {
		t.Fatalf("%d non-ASCII names kept, want %d", kept, bad)
	}
	if strings.Contains(string(r.Result), pkgsSecret) {
		t.Fatal("image config leaked into the result")
	}
}

// TestImagePackagesThroughHostrunLargeApkReport: 3000 apk packages of an
// Alpine image, the second OS family the parser accepts. Nothing is cut
// and the result stays below the limit.
func TestImagePackagesThroughHostrunLargeApkReport(t *testing.T) {
	h := newImageHost(t)
	h.packagesDocker(t, true)
	raw := bigAlpineDoc(3000)
	h.trivy(t, []byte(raw), 0)
	r := runImageHostrun(t, "image.packages", h, pkgsImage)
	assertImageRun(t, r)
	t.Logf("3000 apk packages: result %d bytes (limit %d)", len(r.Result), hostrun.MaxResult)
	p := parsePkgs(t, r.Result)
	sameAsRaw(t, raw, p)
	if !p.Known || !p.Complete || len(p.Packages) != 3000 {
		t.Fatalf("known=%v complete=%v reason=%q packages=%d", p.Known, p.Complete, p.Reason, len(p.Packages))
	}
	if p.OS.Family != "alpine" {
		t.Fatalf("OS %+v", p.OS)
	}
}

// TestImagePackagesThroughHostrunNearLimitReport: the reduced report sits
// just below its 1,040,000-byte limit and the image reference is the longest
// the parameter takes. The run is a success, the whole result stays under
// hostrun.MaxResult, and the parser gets every package.
func TestImagePackagesThroughHostrunNearLimitReport(t *testing.T) {
	const n = 1430 // about 700 bytes each: just under the 1,040,000-byte limit
	var extra []string
	for i := 0; i < n; i++ {
		extra = append(extra, nearLimitEntry(i))
	}
	image := imageNameMax + "@sha256:" + pkgsHex
	h := newImageHost(t)
	h.packagesDocker(t, true)
	h.trivy(t, []byte(pkgsTrivyDoc(pkgsHex, extra...)), 0)
	r := runImageHostrun(t, "image.packages", h, image)
	assertImageRun(t, r)
	t.Logf("near-limit packages: result %d bytes (limit %d)", len(r.Result), hostrun.MaxResult)
	if got := packagesOutput(t, r.Result); got != "ok" {
		t.Fatalf("output %q, want ok", got)
	}
	if len(r.Result) < 900_000 {
		t.Fatalf("result %d bytes: the test no longer reaches the report limit", len(r.Result))
	}
	p, err := ParseImagePackagesResult(image, r.Result)
	if err != nil {
		t.Fatal(err)
	}
	// pkgsTrivyDoc adds two OS packages and one Go module to the n entries.
	if want := n + 3; !p.Complete || len(p.Packages) != want {
		t.Fatalf("complete=%v reason=%q packages=%d, want %d", p.Complete, p.Reason, len(p.Packages), want)
	}
}

// TestImagePackagesThroughHostrunToolargeReport: a reduced report over the
// 1,040,000-byte limit is reported as toolarge: a success, with no packages
// and a small result.
func TestImagePackagesThroughHostrunToolargeReport(t *testing.T) {
	var extra []string
	for i := range 4000 {
		extra = append(extra, fmt.Sprintf(`{"Name":"pkg-%04d-%s","Version":"1.0","Release":"1","SrcName":"src-%04d-%s","SrcVersion":"1.0","SrcRelease":"1"}`,
			i, strings.Repeat("n", 100), i, strings.Repeat("s", 100)))
	}
	h := newImageHost(t)
	h.packagesDocker(t, true)
	h.trivy(t, []byte(pkgsTrivyDoc(pkgsHex, extra...)), 0)
	r := runImageHostrun(t, "image.packages", h, pkgsImage)
	assertImageRun(t, r)
	if got := packagesOutput(t, r.Result); got != "toolarge" {
		t.Fatalf("output %q, want toolarge (result %d bytes)", got, len(r.Result))
	}
	p := parsePkgs(t, r.Result)
	if p.Known || p.Complete || p.Reason != dockerhost.ReasonUnparseable {
		t.Fatalf("known=%v complete=%v reason=%q", p.Known, p.Complete, p.Reason)
	}
}

// TestImagePackagesThroughHostrunRawOutputTruncated: Trivy's raw output
// above the 32 MiB stdout limit is cut while it is read: the result says
// truncated, the run is a success and nothing is parsed.
func TestImagePackagesThroughHostrunRawOutputTruncated(t *testing.T) {
	pad := strings.Repeat("x", dockerhost.MaxImagePackagesOutput)
	raw := strings.Replace(pkgsTrivyDoc(pkgsHex), `"CreatedAt"`, `"Pad":"`+pad+`","CreatedAt"`, 1)
	h := newImageHost(t)
	h.packagesDocker(t, true)
	h.trivy(t, []byte(raw), 0)
	r := runImageHostrun(t, "image.packages", h, pkgsImage)
	assertImageRun(t, r)
	if got := packagesOutput(t, r.Result); got != "truncated" {
		t.Fatalf("output %q, want truncated (result %d bytes)", got, len(r.Result))
	}
	p := parsePkgs(t, r.Result)
	if p.Known || p.Complete || p.Reason != dockerhost.ReasonUnparseable {
		t.Fatalf("known=%v complete=%v reason=%q", p.Known, p.Complete, p.Reason)
	}
}

// TestImagePackagesThroughHostrunAbsentTrivy: no trivy on PATH gives an
// unknown read with trivy_absent, and nothing is scanned.
func TestImagePackagesThroughHostrunAbsentTrivy(t *testing.T) {
	h := newImageHost(t)
	h.packagesDocker(t, true)
	r := runImageHostrun(t, "image.packages", h, pkgsImage)
	assertImageRun(t, r)
	p := parsePkgs(t, r.Result)
	if p.Known || p.Complete || p.Reason != dockerhost.ReasonTrivyAbsent {
		t.Fatalf("known=%v complete=%v reason=%q", p.Known, p.Complete, p.Reason)
	}
}

// TestImagePackagesThroughHostrunNotLocal: a non-local image is never
// scanned and gives image_not_local.
func TestImagePackagesThroughHostrunNotLocal(t *testing.T) {
	h := newImageHost(t)
	h.packagesDocker(t, false)
	raw, _ := bigDebianDoc(10)
	h.trivy(t, []byte(raw), 0)
	r := runImageHostrun(t, "image.packages", h, pkgsImage)
	assertImageRun(t, r)
	p := parsePkgs(t, r.Result)
	if p.Known || p.Complete || p.Reason != ReasonImageNotLocal {
		t.Fatalf("known=%v complete=%v reason=%q", p.Known, p.Complete, p.Reason)
	}
	if calls := h.readCalls(t); strings.Contains(calls, "trivy image") {
		t.Fatalf("a non-local image was scanned: %s", calls)
	}
}

// TestImagePackagesThroughHostrunTrivyStderrFlood: trivy fails and writes
// 2 MiB to stderr. The stream is cut at its 64 KiB limit: the result says
// truncated (not a parse failure), the read is unknown, and the host log
// stays small because trivy's stderr is read by the script and never logged.
func TestImagePackagesThroughHostrunTrivyStderrFlood(t *testing.T) {
	h := newImageHost(t)
	h.packagesDocker(t, true)
	h.stub(t, "trivy", pkgsTrivyStderrFlood)
	r := runImageHostrun(t, "image.packages", h, pkgsImage)
	assertImageRun(t, r)
	if got := packagesOutput(t, r.Result); got != "truncated" {
		t.Fatalf("output %q, want truncated", got)
	}
	if len(r.Log) > 4096 {
		t.Fatalf("host log %d bytes after a 2 MiB stderr flood", len(r.Log))
	}
	p := parsePkgs(t, r.Result)
	if p.Known || p.Complete || p.Reason != dockerhost.ReasonUnparseable {
		t.Fatalf("known=%v complete=%v reason=%q", p.Known, p.Complete, p.Reason)
	}
}

// TestImagePackagesThroughHostrunEscaping: quote, backslash, newline and
// tab in package names and versions. The run stays a success, no raw
// control byte is emitted, values stay in their own fields, and the
// reduced report parses exactly like the raw one.
func TestImagePackagesThroughHostrunEscaping(t *testing.T) {
	entries := []string{
		pkgsEntry(`ev"il`, "1.0", 0, "1"),
		pkgsEntry(`back\slash`, "1.0", 0, "1"),
		pkgsEntry("new\nline", "1.0", 0, "1"),
		pkgsEntry("tab\tname", "1.0", 0, "1"),
		pkgsEntry("good-pkg", `1.0"},"x":"`, 0, "1"),
		pkgsEntry("good-two", "2.0", 0, "2"),
	}
	raw := strings.Replace(pkgsTrivyDoc(pkgsHex), `"Packages": [`, `"Packages": [`+strings.Join(entries, ",")+",", 1)
	h := newImageHost(t)
	h.packagesDocker(t, true)
	h.trivy(t, []byte(raw), 0)
	r := runImageHostrun(t, "image.packages", h, pkgsImage)
	assertImageRun(t, r)
	p := parsePkgs(t, r.Result)
	sameAsRaw(t, raw, p)
	if !strings.Contains(p.Reason, dockerhost.ReasonEntryDropped) {
		t.Fatalf("reason %q: the escaped entries must be marked dropped", p.Reason)
	}
	// The parser accepts printable ASCII, quotes and backslashes included;
	// what must never survive is a control byte, and every kept value must
	// be the raw one (sameAsRaw above already checks that).
	for _, pkg := range p.Packages {
		if strings.ContainsAny(pkg.Name+pkg.Version+pkg.SrcName+pkg.SrcVersion, "\n\t\x01\x7f") {
			t.Fatalf("a value with a control character was kept: %+v", pkg)
		}
	}
	t.Logf("escaping: %d packages kept, reason %q", len(p.Packages), p.Reason)
}

// TestImagePackagesThroughHostrunInvalidUTF8: a report with invalid UTF-8
// is not decoded by the script at all: the output is unparseable, the run
// stays a success class, and no raw byte reaches the result.
func TestImagePackagesThroughHostrunInvalidUTF8(t *testing.T) {
	h := newImageHost(t)
	h.packagesDocker(t, true)
	raw := strings.Replace(pkgsTrivyDoc(pkgsHex), `"libssl3"`, "\"lib\xffssl3\"", 1)
	h.trivy(t, []byte(raw), 0)
	r := runImageHostrun(t, "image.packages", h, pkgsImage)
	assertImageRun(t, r)
	if got := packagesOutput(t, r.Result); got != "unparseable" {
		t.Fatalf("output %q, want unparseable", got)
	}
	p := parsePkgs(t, r.Result)
	if p.Known || p.Complete || p.Reason != dockerhost.ReasonUnparseable {
		t.Fatalf("known=%v complete=%v reason=%q", p.Known, p.Complete, p.Reason)
	}
}

// ----------------------------------------------------------- vulnerabilities

// vulnsRow is one Trivy finding for the vulnerability tests.
type vulnsRow struct {
	id, sev, pkg, version, fixed string
}

var vulnsSeverities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

// vulnsDescription is the long free text real findings carry: quotes,
// backslashes, a newline and non-ASCII letters. The reducer never reads it.
var vulnsDescription = strings.Repeat("A heap overflow in \"parser\" lets a crafted \\ input corrupt memory; ünïcode ✓.\n", 8)

// bigVulnsRows returns n findings over 1700 CVE IDs, so IDs repeat, with
// every severity; the same ID may come with different severities and fixed
// versions, the script keeps the highest severity and the first fixed version.
func bigVulnsRows(n int) []vulnsRow {
	rows := make([]vulnsRow, 0, n)
	for i := 0; i < n; i++ {
		fixed := fmt.Sprintf("1.%d-%d", i%50, i%9)
		if i%4 == 0 {
			fixed = ""
		}
		rows = append(rows, vulnsRow{
			id:      fmt.Sprintf("CVE-2024-%05d", i%1700),
			sev:     vulnsSeverities[(i/3)%5],
			pkg:     fmt.Sprintf("pkg-%03d", i%311),
			version: fmt.Sprintf("%d.%d", i%7, i%23),
			fixed:   fixed,
		})
	}
	return rows
}

// vulnsDocument renders rows as a Trivy JSON v2 report for vulnsDigest. With
// rich set, every finding also carries the fields real Trivy output has
// beyond the reducer's: title, description, references, CVSS per source,
// data source and dates.
func vulnsDocument(rows []vulnsRow, rich bool) []byte {
	findings := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		f := map[string]any{"VulnerabilityID": r.id, "PkgName": r.pkg, "InstalledVersion": r.version,
			"FixedVersion": r.fixed, "Severity": r.sev}
		if rich {
			f["Title"] = "Title of " + r.id
			f["Description"] = vulnsDescription
			f["References"] = []string{"https://nvd.nist.gov/vuln/detail/" + r.id,
				"https://access.redhat.com/security/cve/" + r.id,
				"https://security-tracker.debian.org/tracker/" + r.id,
				"https://github.com/advisories?query=" + r.id,
				"https://osv.dev/vulnerability/" + r.id}
			f["CVSS"] = map[string]any{
				"nvd":    map[string]any{"V2Score": 7.5, "V3Score": 9.8, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
				"redhat": map[string]any{"V3Score": 8.1, "V3Vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"},
			}
			f["DataSource"] = map[string]string{"ID": "nvd", "URL": "https://nvd.nist.gov/"}
			f["PrimaryURL"] = "https://avd.aquasec.com/nvd/" + strings.ToLower(r.id)
			f["PublishedDate"] = "2024-01-02T03:04:05Z"
			f["LastModifiedDate"] = "2024-02-03T04:05:06Z"
		}
		findings = append(findings, f)
	}
	doc := map[string]any{"SchemaVersion": 2, "ArtifactName": "nginx@" + vulnsDigest,
		"Results": []any{map[string]any{"Target": "nginx", "Class": "os-pkgs", "Vulnerabilities": findings}}}
	b, err := json.Marshal(doc)
	if err != nil {
		panic(err) // maps of strings and numbers cannot fail
	}
	return b
}

// expectedVulns computes the summary the script must report for rows: one
// count per unique ID at its highest severity, the first non-empty fixed
// version, and the top 25 by severity then ID.
func expectedVulns(rows []vulnsRow) (map[string]int, int, []dockerhost.ImageVuln) {
	rank := map[string]int{}
	for i, s := range vulnsSeverities {
		rank[s] = i
	}
	type agg struct {
		sev   string
		fixed string
	}
	seen := map[string]*agg{}
	for _, r := range rows {
		a, ok := seen[r.id]
		if !ok {
			seen[r.id] = &agg{sev: r.sev, fixed: r.fixed}
			continue
		}
		if rank[r.sev] < rank[a.sev] {
			a.sev = r.sev
		}
		if a.fixed == "" {
			a.fixed = r.fixed
		}
	}
	counts := map[string]int{}
	ids := make([]string, 0, len(seen))
	for id, a := range seen {
		counts[a.sev]++
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		ri, rj := rank[seen[ids[i]].sev], rank[seen[ids[j]].sev]
		if ri != rj {
			return ri < rj
		}
		return ids[i] < ids[j]
	})
	var top []dockerhost.ImageVuln
	for _, id := range ids[:min(25, len(ids))] {
		top = append(top, dockerhost.ImageVuln{ID: id, Severity: seen[id].sev, Fixed: seen[id].fixed})
	}
	return counts, len(seen), top
}

// vulnsRef is the image reference the vulnerability tests scan.
func vulnsRef() string {
	return "nginx@" + vulnsDigest
}

// checkVulnsSummary compares a parsed summary with expectedVulns for rows.
func checkVulnsSummary(t *testing.T, got dockerhost.ImageVulns, rows []vulnsRow) {
	t.Helper()
	counts, total, top := expectedVulns(rows)
	if got.Status != "ok" || got.Phase != "done" {
		t.Fatalf("status %q phase %q", got.Status, got.Phase)
	}
	if got.Total != total {
		t.Fatalf("total %d, want %d", got.Total, total)
	}
	for _, s := range vulnsSeverities {
		if got.Severity[s] != counts[s] {
			t.Errorf("severity %s: %d, want %d", s, got.Severity[s], counts[s])
		}
	}
	if len(got.Top) != len(top) {
		t.Fatalf("%d top entries, want %d", len(got.Top), len(top))
	}
	for i := range top {
		if got.Top[i] != top[i] {
			t.Fatalf("top[%d] = %+v, want %+v", i, got.Top[i], top[i])
		}
	}
	if got.Targets != 1 {
		t.Errorf("targets %d, want 1", got.Targets)
	}
}

// TestImageVulnsThroughHostrunLargeReport: 5000 findings over 1700 CVE IDs
// of every severity. The counts per severity, the total and the top 25
// match the fake report.
func TestImageVulnsThroughHostrunLargeReport(t *testing.T) {
	h := newImageHost(t)
	h.vulnsDocker(t, true)
	rows := bigVulnsRows(5000)
	h.trivy(t, vulnsDocument(rows, false), 0)
	h.vulnDB(t)
	r := runImageHostrun(t, "image.vulnerabilities", h, vulnsRef())
	assertImageRun(t, r)
	t.Logf("5000 findings: result %d bytes (limit %d)", len(r.Result), hostrun.MaxResult)
	got, err := dockerhost.ParseImageVulns(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	checkVulnsSummary(t, got, rows)
}

// TestImageVulnsThroughHostrunRealisticLargeReport: 5000 findings carrying
// the description, references, CVSS and dates real Trivy output has, about
// 7 MB of report. The reduction must read the same summary and keep none of
// that text: the result stays small and printable.
func TestImageVulnsThroughHostrunRealisticLargeReport(t *testing.T) {
	h := newImageHost(t)
	h.vulnsDocker(t, true)
	rows := bigVulnsRows(5000)
	raw := vulnsDocument(rows, true)
	h.trivy(t, raw, 0)
	h.vulnDB(t)
	r := runImageHostrun(t, "image.vulnerabilities", h, vulnsRef())
	assertImageRun(t, r)
	t.Logf("realistic 5000 findings: report %d bytes, result %d bytes", len(raw), len(r.Result))
	if len(raw) > 16<<20 {
		t.Fatalf("test report %d bytes is above the script's stdout limit", len(raw))
	}
	if strings.Contains(string(r.Result), "heap overflow") || strings.Contains(string(r.Result), "nvd.nist.gov") {
		t.Fatal("description or references leaked into the result")
	}
	got, err := dockerhost.ParseImageVulns(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	checkVulnsSummary(t, got, rows)
}

// TestImageVulnsThroughHostrunNearLimitNames: the longest image reference
// the parameter takes (255 characters before the digest), 60 CVEs with the
// longest IDs the reducer keeps (64 characters) and the longest fixed
// versions it keeps (200 characters). The result is ok and its top list is
// exact. The summary is bounded by the top 25, so this is the largest
// result a valid scan can produce.
func TestImageVulnsThroughHostrunNearLimitNames(t *testing.T) {
	var rows []vulnsRow
	for i := 0; i < 60; i++ {
		rows = append(rows, vulnsRow{
			id:      "CVE-2025-" + fmt.Sprintf("%055d", i),
			sev:     vulnsSeverities[i%5],
			pkg:     "p",
			version: "1",
			fixed:   strings.Repeat("1.", 100),
		})
	}
	h := newImageHost(t)
	h.vulnsDocker(t, true)
	h.trivy(t, vulnsDocument(rows, false), 0)
	h.vulnDB(t)
	r := runImageHostrun(t, "image.vulnerabilities", h, imageNameMax+"@"+vulnsDigest)
	assertImageRun(t, r)
	t.Logf("longest names: result %d bytes (limit %d)", len(r.Result), hostrun.MaxResult)
	got, err := dockerhost.ParseImageVulns(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	checkVulnsSummary(t, got, rows)
	if len(got.Top) != 25 || len(got.Top[0].ID) != 64 || len(got.Top[0].Fixed) != 200 {
		t.Fatalf("top list %+v: want 25 entries with 64-character IDs and 200-character fixed versions", got.Top[:1])
	}
}

// TestImageVulnsThroughHostrunRawOutputTruncated: Trivy's raw output above
// the 16 MiB stdout limit is cut while it is read: status truncated, no
// findings, a success run.
func TestImageVulnsThroughHostrunRawOutputTruncated(t *testing.T) {
	pad := strings.Repeat("x", 16<<20)
	raw := `{"SchemaVersion":2,"ArtifactName":"nginx@` + vulnsDigest + `","Pad":"` + pad + `","Results":[]}`
	h := newImageHost(t)
	h.vulnsDocker(t, true)
	h.trivy(t, []byte(raw), 0)
	h.vulnDB(t)
	r := runImageHostrun(t, "image.vulnerabilities", h, vulnsRef())
	assertImageRun(t, r)
	got, err := dockerhost.ParseImageVulns(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "truncated" || len(got.Top) != 0 || got.Total != 0 {
		t.Fatalf("raw output over the limit gave %+v", got)
	}
}

// TestImageVulnsThroughHostrunAbsentTrivy: no trivy gives status absent and
// no findings.
func TestImageVulnsThroughHostrunAbsentTrivy(t *testing.T) {
	h := newImageHost(t)
	h.vulnsDocker(t, true)
	h.vulnDB(t)
	r := runImageHostrun(t, "image.vulnerabilities", h, vulnsRef())
	assertImageRun(t, r)
	got, err := dockerhost.ParseImageVulns(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "absent" || got.Present || len(got.Top) != 0 || got.Total != 0 {
		t.Fatalf("absent trivy gave %+v", got)
	}
}

// TestImageVulnsThroughHostrunNotLocal: a non-local image is never scanned:
// the recorded calls hold no image scan.
func TestImageVulnsThroughHostrunNotLocal(t *testing.T) {
	h := newImageHost(t)
	h.vulnsDocker(t, false)
	h.trivy(t, vulnsDocument(bigVulnsRows(50), false), 0)
	h.vulnDB(t)
	r := runImageHostrun(t, "image.vulnerabilities", h, vulnsRef())
	assertImageRun(t, r)
	got, err := dockerhost.ParseImageVulns(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "notlocal" || len(got.Top) != 0 {
		t.Fatalf("not local gave %+v", got)
	}
	if calls := h.readCalls(t); strings.Contains(calls, "trivy image") {
		t.Fatalf("a non-local image was scanned: %s", calls)
	}
}

// TestImageVulnsThroughHostrunTrivyStderrFlood: trivy fails and writes
// 2 MiB to stderr. The scan is cut at the stderr limit: status truncated,
// no findings, bounded log.
func TestImageVulnsThroughHostrunTrivyStderrFlood(t *testing.T) {
	h := newImageHost(t)
	h.vulnsDocker(t, true)
	h.stub(t, "trivy", pkgsTrivyStderrFlood)
	h.vulnDB(t)
	r := runImageHostrun(t, "image.vulnerabilities", h, vulnsRef())
	assertImageRun(t, r)
	got, err := dockerhost.ParseImageVulns(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "truncated" || len(got.Top) != 0 || got.Total != 0 {
		t.Fatalf("stderr flood gave %+v", got)
	}
	if len(r.Log) > 4096 {
		t.Fatalf("host log %d bytes after a 2 MiB stderr flood", len(r.Log))
	}
}

// TestImageVulnsThroughHostrunEscaping: quote, backslash, newline, tab and
// other control bytes in the CVE IDs and in the fixed versions of kept
// findings. Findings whose ID does not match the ID pattern are dropped
// without marking the scan partial, so those four IDs never appear. The
// kept findings keep their printable fixed-version bytes and lose the
// control bytes; the run stays a success and no raw control byte is emitted.
func TestImageVulnsThroughHostrunEscaping(t *testing.T) {
	rows := []vulnsRow{
		{id: `CVE-2024-"quote`, sev: "HIGH", pkg: `p"q`, version: "1", fixed: "1.1"},
		{id: `CVE-2024-back\slash`, sev: "CRITICAL", pkg: `p\s`, version: "1", fixed: "1.1"},
		{id: "CVE-2024-new\nline", sev: "LOW", pkg: "p", version: "1", fixed: "1.1"},
		{id: "CVE-2024-tab\there", sev: "MEDIUM", pkg: "p", version: "1", fixed: "1.1"},
		{id: "CVE-2024-00001", sev: "HIGH", pkg: "p", version: "1", fixed: `1.0"},"x":"\`},
		{id: "CVE-2024-00002", sev: "CRITICAL", pkg: "p", version: "1", fixed: "1.0\n2\t3\x01\x7f4"},
		{id: "CVE-2024-00003", sev: "LOW", pkg: "p", version: "1", fixed: "1.0 \\ \"ok\""},
		{id: "CVE-2024-00004", sev: "MEDIUM", pkg: "p", version: "1", fixed: "\n\t"},
	}
	want := []dockerhost.ImageVuln{
		{ID: "CVE-2024-00002", Severity: "CRITICAL", Fixed: "1.0234"},
		{ID: "CVE-2024-00001", Severity: "HIGH", Fixed: `1.0"},"x":"\`},
		{ID: "CVE-2024-00004", Severity: "MEDIUM", Fixed: ""},
		{ID: "CVE-2024-00003", Severity: "LOW", Fixed: `1.0 \ "ok"`},
	}
	h := newImageHost(t)
	h.vulnsDocker(t, true)
	h.trivy(t, vulnsDocument(rows, false), 0)
	h.vulnDB(t)
	r := runImageHostrun(t, "image.vulnerabilities", h, vulnsRef())
	assertImageRun(t, r)
	got, err := dockerhost.ParseImageVulns(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "ok" {
		t.Fatalf("status %q, want ok: the escaped values are valid JSON", got.Status)
	}
	if got.Total != len(want) || len(got.Top) != len(want) {
		t.Fatalf("total %d, %d top entries; want %d kept findings: %+v", got.Total, len(got.Top), len(want), got.Top)
	}
	for i := range want {
		if got.Top[i] != want[i] {
			t.Fatalf("top[%d] = %q, want %q", i, got.Top[i], want[i])
		}
	}
}

// TestImageVulnsThroughHostrunInvalidUTF8: an invalid UTF-8 byte in the
// report is not decoded by the script: the scan is unsupported exactly, the
// run stays a success, and no raw byte reaches the result.
func TestImageVulnsThroughHostrunInvalidUTF8(t *testing.T) {
	h := newImageHost(t)
	h.vulnsDocker(t, true)
	raw := strings.Replace(string(vulnsDocument([]vulnsRow{{id: "CVE-2024-00001", sev: "HIGH", pkg: "p", version: "1", fixed: "1.1"}}, false)),
		"CVE-2024-00001", "CVE-2024-\xff0001", 1)
	h.trivy(t, []byte(raw), 0)
	h.vulnDB(t)
	r := runImageHostrun(t, "image.vulnerabilities", h, vulnsRef())
	assertImageRun(t, r)
	got, err := dockerhost.ParseImageVulns(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "unsupported" || len(got.Top) != 0 || got.Total != 0 {
		t.Fatalf("invalid UTF-8 report gave %+v, want status unsupported", got)
	}
}

// TestImageVulnsThroughHostrunSecondRunUsesCache: the same scan twice on one
// host. The second run is answered from the cache the first run left in its
// work directory, with the same summary, and trivy ran once.
func TestImageVulnsThroughHostrunSecondRunUsesCache(t *testing.T) {
	h := newImageHost(t)
	h.vulnsDocker(t, true)
	rows := bigVulnsRows(200)
	h.trivy(t, vulnsDocument(rows, false), 0)
	h.vulnDB(t)
	first := runImageHostrun(t, "image.vulnerabilities", h, vulnsRef())
	second := runImageHostrun(t, "image.vulnerabilities", h, vulnsRef())
	assertImageRun(t, first)
	assertImageRun(t, second)
	if resultField(t, first.Result, "cached") != nil {
		t.Fatal("the first run claims a cached summary")
	}
	if resultField(t, second.Result, "cached") != true {
		t.Fatalf("the second run did not use the cache: %s", second.Result)
	}
	a, err := dockerhost.ParseImageVulns(first.Result)
	if err != nil {
		t.Fatal(err)
	}
	b, err := dockerhost.ParseImageVulns(second.Result)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a.Top, b.Top) || a.Total != b.Total || !reflect.DeepEqual(a.Severity, b.Severity) {
		t.Fatalf("cached summary differs:\n first %+v\nsecond %+v", a, b)
	}
	if n := strings.Count(h.readCalls(t), "trivy image"); n != 1 {
		t.Fatalf("trivy scanned %d times, want 1", n)
	}
}
