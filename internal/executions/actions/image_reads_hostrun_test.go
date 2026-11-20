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
	"sort"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
)

// image.packages and image.vulnerabilities run over SSH as attached runs
// (script -> hostrun classifier -> parser), like package.list_installed.
// The fake docker and trivy sit in front of the unchanged script; nothing
// here runs the script with /bin/sh directly.

// imageHostrunExec is the execution ID of every run in this file.
const imageHostrunExec = "5d1c7a2e-9b3f-4e8a-a6c1-0f2b7d9e4c31"

// shQuote quotes s for a POSIX shell.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// runImageHostrun runs the action's script for image as an attached run.
// prefix sets the environment in front of the script body.
func runImageHostrun(t *testing.T, id, prefix, image string) hostrun.Result {
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
	r, err := hostrun.Attached(context.Background(), hostrunClient(t), imageHostrunExec, raw, []byte(prefix+string(a.Script)), a.Timeout)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// assertImageRun checks what the executor requires of any image read: a
// success class, exit 0, one result document within hostrun.MaxResult with
// only printable ASCII (the scripts emit ASCII-escaped JSON), and a log
// within hostrun.MaxLog plus its truncation marker.
func assertImageRun(t *testing.T, r hostrun.Result) {
	t.Helper()
	if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
		t.Fatalf("class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
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

// ---------------------------------------------------------------- packages

// pkgsPrefix puts the fake tools directory first on PATH, nothing else.
func pkgsPrefix(h *pkgsHost) string {
	return "PATH=" + shQuote(h.bin) + "; export PATH\n"
}

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

// TestImagePackagesThroughHostrunLargeReport: 3000 packages of a Debian
// image from two ecosystems (dpkg and npm). The result is a success, below
// the limit, the parser gives every package, and the reduction changes
// nothing the parser judges.
func TestImagePackagesThroughHostrunLargeReport(t *testing.T) {
	h := newPkgsHost(t, true)
	raw, bad := bigDebianDoc(3000)
	h.trivy(t, raw, 0)
	r := runImageHostrun(t, "image.packages", pkgsPrefix(h), pkgsImage)
	assertImageRun(t, r)
	t.Logf("3000 packages: result %d bytes (limit %d), %d non-ASCII dpkg names", len(r.Result), hostrun.MaxResult, bad)
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
	h := newPkgsHost(t, true)
	raw := bigAlpineDoc(3000)
	h.trivy(t, raw, 0)
	r := runImageHostrun(t, "image.packages", pkgsPrefix(h), pkgsImage)
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

// TestImagePackagesThroughHostrunAbsentTrivy: no trivy on PATH gives an
// unknown read with trivy_absent, and nothing is scanned.
func TestImagePackagesThroughHostrunAbsentTrivy(t *testing.T) {
	h := newPkgsHost(t, true)
	r := runImageHostrun(t, "image.packages", pkgsPrefix(h), pkgsImage)
	assertImageRun(t, r)
	p := parsePkgs(t, r.Result)
	if p.Known || p.Complete || p.Reason != dockerhost.ReasonTrivyAbsent {
		t.Fatalf("known=%v complete=%v reason=%q", p.Known, p.Complete, p.Reason)
	}
}

// TestImagePackagesThroughHostrunNotLocal: a non-local image is never
// scanned and gives image_not_local.
func TestImagePackagesThroughHostrunNotLocal(t *testing.T) {
	h := newPkgsHost(t, false)
	raw, _ := bigDebianDoc(10)
	h.trivy(t, raw, 0)
	r := runImageHostrun(t, "image.packages", pkgsPrefix(h), pkgsImage)
	assertImageRun(t, r)
	p := parsePkgs(t, r.Result)
	if p.Known || p.Complete || p.Reason != ReasonImageNotLocal {
		t.Fatalf("known=%v complete=%v reason=%q", p.Known, p.Complete, p.Reason)
	}
	if strings.Contains(h.readCalls(t), "trivy") {
		t.Fatalf("a non-local image was scanned: %s", h.readCalls(t))
	}
}

// TestImagePackagesThroughHostrunTrivyStderrFlood: trivy fails and writes
// 2 MiB to stderr. The stream is cut at its limit, the log stays bounded
// and the read is unknown, never complete.
func TestImagePackagesThroughHostrunTrivyStderrFlood(t *testing.T) {
	h := newPkgsHost(t, true)
	h.cmd(t, "trivy", pkgsTrivyStderrFlood)
	r := runImageHostrun(t, "image.packages", pkgsPrefix(h), pkgsImage)
	assertImageRun(t, r)
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
	h := newPkgsHost(t, true)
	h.trivy(t, raw, 0)
	r := runImageHostrun(t, "image.packages", pkgsPrefix(h), pkgsImage)
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
// is not decoded by the script at all: unknown, unparseable, still a
// success class and no raw byte in the result.
func TestImagePackagesThroughHostrunInvalidUTF8(t *testing.T) {
	h := newPkgsHost(t, true)
	raw := strings.Replace(pkgsTrivyDoc(pkgsHex), `"libssl3"`, "\"lib\xffssl3\"", 1)
	h.trivy(t, raw, 0)
	r := runImageHostrun(t, "image.packages", pkgsPrefix(h), pkgsImage)
	assertImageRun(t, r)
	p := parsePkgs(t, r.Result)
	if p.Known || p.Complete || p.Reason != dockerhost.ReasonUnparseable {
		t.Fatalf("known=%v complete=%v reason=%q", p.Known, p.Complete, p.Reason)
	}
}

// ----------------------------------------------------------- vulnerabilities

// vulnsRow is one Trivy finding for the large vulnerability test.
type vulnsRow struct {
	id, sev, pkg, version, fixed string
}

var vulnsSeverities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

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

// vulnsReport renders rows as a Trivy JSON v2 report for vulnsDigest.
func vulnsReport(rows []vulnsRow) string {
	var b strings.Builder
	b.WriteString(`{"SchemaVersion": 2, "ArtifactName": "nginx@` + vulnsDigest + `", "Results": [{"Target": "nginx", "Class": "os-pkgs", "Vulnerabilities": [`)
	for i, r := range rows {
		if i > 0 {
			b.WriteString(",")
		}
		v, _ := json.Marshal(map[string]string{"VulnerabilityID": r.id, "PkgName": r.pkg,
			"InstalledVersion": r.version, "FixedVersion": r.fixed, "Severity": r.sev})
		b.Write(v)
	}
	b.WriteString(`]}]}`)
	return b.String()
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

// vulnsPrefix puts PATH and the Trivy cache in front of the script.
func vulnsPrefix(f *fakeHost, path string) string {
	return "PATH=" + shQuote(path) + "; TRIVY_CACHE_DIR=" + shQuote(filepath.Join(f.dir, "tcache")) + "; export PATH TRIVY_CACHE_DIR\n"
}

// vulnsAbsentPath is a PATH with the fake docker but no trivy: the
// vulnerability tools only, plus python3.
func vulnsAbsentPath(t *testing.T, f *fakeHost) string {
	t.Helper()
	bin := vulnsBin(t, f)
	p, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(p, filepath.Join(bin, "python3")); err != nil {
		t.Fatal(err)
	}
	return f.bin + ":" + bin
}

// TestImageVulnsThroughHostrunLargeReport: 5000 findings over 1700 CVE IDs
// of every severity. The counts per severity, the total and the top 25
// match the fake report.
func TestImageVulnsThroughHostrunLargeReport(t *testing.T) {
	f := newFakeHost(t, "1")
	vulnsDocker(t, f, true)
	rows := bigVulnsRows(5000)
	if err := os.WriteFile(filepath.Join(f.dir, "trivy-big.json"), []byte(vulnsReport(rows)), 0o600); err != nil {
		t.Fatal(err)
	}
	vulnsTrivy(t, f, "trivy-big.json", "0")
	vulnsDB(t, f)
	r := runImageHostrun(t, "image.vulnerabilities", vulnsPrefix(f, f.bin+":/usr/bin:/bin"), vulnsDigestRef())
	assertImageRun(t, r)
	t.Logf("5000 findings: result %d bytes (limit %d)", len(r.Result), hostrun.MaxResult)
	got, err := dockerhost.ParseImageVulns(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "ok" || got.Phase != "done" {
		t.Fatalf("status %q phase %q", got.Status, got.Phase)
	}
	counts, total, top := expectedVulns(rows)
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

// vulnsDigestRef is the image reference the vulnerability tests scan.
func vulnsDigestRef() string {
	return "nginx@" + vulnsDigest
}

// TestImageVulnsThroughHostrunAbsentTrivy: no trivy gives status absent and
// no findings.
func TestImageVulnsThroughHostrunAbsentTrivy(t *testing.T) {
	f := newFakeHost(t, "1")
	vulnsDocker(t, f, true)
	r := runImageHostrun(t, "image.vulnerabilities", vulnsPrefix(f, vulnsAbsentPath(t, f)), vulnsDigestRef())
	assertImageRun(t, r)
	got, err := dockerhost.ParseImageVulns(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "absent" || got.Present || len(got.Top) != 0 || got.Total != 0 {
		t.Fatalf("absent trivy gave %+v", got)
	}
}

// TestImageVulnsThroughHostrunNotLocal: a non-local image is never scanned.
func TestImageVulnsThroughHostrunNotLocal(t *testing.T) {
	f := newFakeHost(t, "1")
	vulnsDocker(t, f, false)
	vulnsTrivy(t, f, "trivy-big.json", "0")
	vulnsDB(t, f)
	r := runImageHostrun(t, "image.vulnerabilities", vulnsPrefix(f, f.bin+":/usr/bin:/bin"), vulnsDigestRef())
	assertImageRun(t, r)
	got, err := dockerhost.ParseImageVulns(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "notlocal" || len(got.Top) != 0 {
		t.Fatalf("not local gave %+v", got)
	}
	if strings.Contains(f.readCalls(t), "trivy image") {
		t.Fatal("a non-local image was scanned")
	}
}

// TestImageVulnsThroughHostrunTrivyStderrFlood: trivy fails and writes
// 2 MiB to stderr. The scan is cut at the stderr limit: status truncated,
// no findings, bounded log.
func TestImageVulnsThroughHostrunTrivyStderrFlood(t *testing.T) {
	f := newFakeHost(t, "1")
	vulnsDocker(t, f, true)
	f.write(t, "trivy", pkgsTrivyStderrFlood)
	vulnsDB(t, f)
	r := runImageHostrun(t, "image.vulnerabilities", vulnsPrefix(f, f.bin+":/usr/bin:/bin"), vulnsDigestRef())
	assertImageRun(t, r)
	got, err := dockerhost.ParseImageVulns(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "truncated" || len(got.Top) != 0 || got.Total != 0 {
		t.Fatalf("stderr flood gave %+v", got)
	}
}

// TestImageVulnsThroughHostrunEscaping: quote, backslash, newline and a
// tab in CVE IDs and fixed versions. The run stays a success and no raw
// control byte is emitted. The script drops findings whose ID does not
// match its ID pattern without marking the scan partial (a finding for the
// report, not decided here), so this test checks only the clean finding.
func TestImageVulnsThroughHostrunEscaping(t *testing.T) {
	rows := []vulnsRow{
		{id: `CVE-2024-"quote`, sev: "HIGH", pkg: `p"q`, version: "1", fixed: `1.0"},"x":"`},
		{id: `CVE-2024-back\slash`, sev: "CRITICAL", pkg: `p\s`, version: "1", fixed: `1.0\`},
		{id: "CVE-2024-new\nline", sev: "LOW", pkg: "p", version: "1", fixed: "1.0\n2"},
		{id: "CVE-2024-tab\there", sev: "MEDIUM", pkg: "p", version: "1", fixed: "1.0\t"},
		{id: "CVE-2024-00001", sev: "MEDIUM", pkg: "p", version: "1", fixed: "1.1"},
	}
	f := newFakeHost(t, "1")
	vulnsDocker(t, f, true)
	if err := os.WriteFile(filepath.Join(f.dir, "trivy-esc.json"), []byte(vulnsReport(rows)), 0o600); err != nil {
		t.Fatal(err)
	}
	vulnsTrivy(t, f, "trivy-esc.json", "0")
	vulnsDB(t, f)
	r := runImageHostrun(t, "image.vulnerabilities", vulnsPrefix(f, f.bin+":/usr/bin:/bin"), vulnsDigestRef())
	assertImageRun(t, r)
	got, err := dockerhost.ParseImageVulns(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("escaping: status %q, top %+v", got.Status, got.Top)
	if got.Status != "ok" {
		t.Fatalf("status %q, want ok: the escaped values are valid JSON", got.Status)
	}
	for _, v := range got.Top {
		if strings.ContainsAny(v.ID+v.Fixed, "\n\t\x01\x7f") {
			t.Fatalf("a value with a control character was kept: %+v", v)
		}
	}
	// The clean row keeps its own severity and fixed version.
	found := false
	for _, v := range got.Top {
		if v.ID == "CVE-2024-00001" && v.Severity == "MEDIUM" && v.Fixed == "1.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("clean finding lost or changed: %+v", got.Top)
	}
}

// TestImageVulnsThroughHostrunInvalidUTF8: an invalid UTF-8 byte in the
// report is not decoded by the script: the scan is unsupported, the run
// stays a success, and no raw byte reaches the result.
func TestImageVulnsThroughHostrunInvalidUTF8(t *testing.T) {
	f := newFakeHost(t, "1")
	vulnsDocker(t, f, true)
	raw := strings.Replace(vulnsReport([]vulnsRow{{id: "CVE-2024-00001", sev: "HIGH", pkg: "p", version: "1", fixed: "1.1"}}), "CVE-2024-00001", "CVE-2024-\xff0001", 1)
	if err := os.WriteFile(filepath.Join(f.dir, "trivy-bad.json"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	vulnsTrivy(t, f, "trivy-bad.json", "0")
	vulnsDB(t, f)
	r := runImageHostrun(t, "image.vulnerabilities", vulnsPrefix(f, f.bin+":/usr/bin:/bin"), vulnsDigestRef())
	assertImageRun(t, r)
	got, err := dockerhost.ParseImageVulns(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status == "ok" {
		t.Fatalf("invalid UTF-8 report was accepted: %+v", got)
	}
}
