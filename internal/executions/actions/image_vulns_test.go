// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
)

var vulnsDigest = "sha256:" + strings.Repeat("a", 64)

// trivyOut is a pretty-printed Trivy JSON result: two unique CVEs, one of
// them reported twice with different severities (the highest must win),
// one unfixed.
var trivyOut = `{
  "SchemaVersion": 2,
  "ArtifactName": "nginx@sha256:` + vulnsDigest + `",
  "Results": [
    {
      "Target": "nginx@sha256:` + vulnsDigest + `",
      "Class": "os-pkgs",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-0001",
          "PkgName": "openssl",
          "InstalledVersion": "1.1.1",
          "FixedVersion": "1.1.2",
          "Severity": "HIGH"
        },
        {
          "VulnerabilityID": "CVE-2023-0002",
          "PkgName": "zlib",
          "InstalledVersion": "1.2",
          "FixedVersion": "",
          "Severity": "CRITICAL"
        },
        {
          "VulnerabilityID": "CVE-2023-0001",
          "PkgName": "openssl",
          "InstalledVersion": "1.1.1",
          "FixedVersion": "1.1.3",
          "Severity": "MEDIUM"
        }
      ]
    }
  ]
}`

// runVulns runs the image.vulnerabilities script against a fake host.
// NEBULA_PARAMS is a one-line params file; TMPDIR and TRIVY_CACHE_DIR live
// inside the host directory so the scan work and cache are inspectable.
func (f *fakeHost) runVulns(t *testing.T, path, params string) (int, []byte, map[string]any) {
	t.Helper()
	p := filepath.Join(f.dir, "params.json")
	if err := os.WriteFile(p, []byte(params), 0o600); err != nil {
		t.Fatal(err)
	}
	a, ok := Lookup("image.vulnerabilities")
	if !ok {
		t.Fatal("image.vulnerabilities is not registered")
	}
	s := filepath.Join(f.dir, "iv.sh")
	if err := os.WriteFile(s, a.Script, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", s)
	cmd.Dir = f.dir
	cmd.Env = []string{
		"PATH=" + path,
		"NEBULA_PARAMS=" + p,
		"TMPDIR=" + filepath.Join(f.dir, "tmp"),
		"TRIVY_CACHE_DIR=" + filepath.Join(f.dir, "tcache"),
		"HOME=" + f.dir,
	}
	out, err := cmd.Output()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("result %q: %v", out, err)
	}
	return code, out, doc
}

// vulnsDocker is a fake docker: version works, image inspect returns the
// platform unless inspectOK is false (image not local).
func vulnsDocker(t *testing.T, f *fakeHost, inspectOK bool) {
	t.Helper()
	ok := "0"
	if inspectOK {
		ok = "1"
	}
	f.write(t, "docker", `echo "$@" >> "`+f.calls+`"
case "$1" in
  version) echo "27.3.1" ;;
  image) [ "`+ok+`" = 1 ] || exit 1
    echo "linux/amd64" ;;
esac`)
}

// vulnsTrivy is a fake trivy: --version and an image scan that prints the
// file named out and exits rc.
func vulnsTrivy(t *testing.T, f *fakeHost, out, rc string) {
	t.Helper()
	f.write(t, "trivy", `echo "$@" >> "`+f.calls+`"
case "$1" in
  --version) echo "Version: 0.52.0" ;;
  image) cat "`+f.dir+`/`+out+`"; exit `+rc+` ;;
esac`)
}

// vulnsDB puts a fresh vulnerability database file into TRIVY_CACHE_DIR.
func vulnsDB(t *testing.T, f *fakeHost) {
	t.Helper()
	db := filepath.Join(f.dir, "tcache", "db")
	if err := os.MkdirAll(db, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(db, "vuln-list.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// vulnsBin returns a PATH with only the tools the script needs (plus the
// fake id), so a real docker or trivy on this machine stays out of reach.
func vulnsBin(t *testing.T, f *fakeHost) string {
	t.Helper()
	bin := filepath.Join(f.dir, "vbin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	tools := []string{"sed", "base64", "tr", "stat", "date", "sha256sum",
		"head", "grep", "awk", "wc", "mkdir", "chmod", "rm", "find", "cut", "sort"}
	for _, tool := range tools {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("%s missing on this machine", tool)
		}
		if err := os.Symlink(p, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "id"), []byte("#!/bin/sh\necho 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func vulnsParams() string {
	return `{"image":"nginx@` + vulnsDigest + `"}`
}

// TestImageVulnsAction checks the registration: LOW, read-only, one
// digest-pinned parameter, and a local-only scan profile in the script.
func TestImageVulnsAction(t *testing.T) {
	a, ok := Lookup("image.vulnerabilities")
	if !ok || !a.ReadOnly || a.Risk.String() != "RISK_CLASS_LOW" || a.Retry != RetrySafe ||
		len(a.Params) != 1 || a.Params[0].Name != "image" {
		t.Fatalf("image.vulnerabilities %+v", a)
	}
	if err := a.ValidParams(map[string]string{"image": "nginx@" + vulnsDigest}); err != nil {
		t.Fatalf("digest-pinned reference rejected: %v", err)
	}
	for _, bad := range []string{
		"nginx:latest",
		"nginx@" + strings.Repeat("a", 63),
		"nginx@" + "sha256:" + strings.Repeat("A", 64),
		"@sha256:" + strings.Repeat("a", 64),
	} {
		if err := a.ValidParams(map[string]string{"image": bad}); err == nil {
			t.Errorf("parameter %q accepted", bad)
		}
	}
	s := string(a.Script)
	for _, want := range []string{"--offline-scan", "--skip-db-update", "--scanners vuln"} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks the local-only scan flag %s", want)
		}
	}
	for _, banned := range []string{"trivy db update", "download-db-only", "docker pull", "apt-get", "dnf ", "yum ", "curl ", "wget "} {
		if strings.Contains(s, banned) {
			t.Errorf("script may not install, pull or refresh: %s", banned)
		}
	}
}

func TestImageVulnsScriptOK(t *testing.T) {
	f := newFakeHost(t, "1")
	vulnsDocker(t, f, true)
	vulnsTrivy(t, f, "trivy-out.json", "0")
	if err := os.WriteFile(filepath.Join(f.dir, "trivy-out.json"), []byte(trivyOut), 0o600); err != nil {
		t.Fatal(err)
	}
	vulnsDB(t, f)
	code, raw, doc := f.runVulns(t, f.bin+":/usr/bin:/bin", vulnsParams())
	if code != 0 || doc["phase"] != "done" || doc["status"] != "ok" || doc["present"] != true {
		t.Fatalf("%d %v", code, doc)
	}
	if b64(t, doc, "platform") != "linux/amd64" || doc["image"] != "nginx@"+vulnsDigest {
		t.Fatalf("%v", doc)
	}
	if doc["dbage"].(float64) != 0 {
		t.Fatalf("fresh database, age %v", doc["dbage"])
	}
	var sum struct {
		Severity map[string]int `json:"severity"`
		Total    int            `json:"total"`
		Targets  int            `json:"targets"`
		Top      []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Fixed    string `json:"fixed"`
		} `json:"top"`
	}
	if err := json.Unmarshal([]byte(b64(t, doc, "summary")), &sum); err != nil {
		t.Fatal(err)
	}
	if sum.Total != 2 || sum.Targets != 1 ||
		sum.Severity["CRITICAL"] != 1 || sum.Severity["HIGH"] != 1 ||
		sum.Severity["MEDIUM"] != 0 || len(sum.Top) != 2 ||
		sum.Top[0].ID != "CVE-2023-0002" || sum.Top[0].Severity != "CRITICAL" || sum.Top[0].Fixed != "" ||
		sum.Top[1].ID != "CVE-2023-0001" || sum.Top[1].Severity != "HIGH" || sum.Top[1].Fixed != "1.1.2" {
		t.Fatalf("summary %+v", sum)
	}
	calls := f.readCalls(t)
	if !strings.Contains(calls, "image --offline-scan --skip-db-update --scanners vuln --quiet --format json") ||
		!strings.Contains(calls, "image inspect") {
		t.Fatalf("calls %q", calls)
	}
	// The result must round-trip through the server-side parser.
	v, err := dockerhost.ParseImageVulns(raw)
	if err != nil {
		t.Fatalf("ParseImageVulns: %v", err)
	}
	if v.Status != dockerhost.VulnsOK || v.Total != 2 || v.Targets != 1 ||
		v.Severity["CRITICAL"] != 1 || v.Severity["HIGH"] != 1 || v.Platform != "linux/amd64" || v.Cached {
		t.Fatalf("%+v", v)
	}
}

// TestImageVulnsScriptCached runs the scan twice: the second run must be
// served from the 24 h cache without invoking the scanner again.
func TestImageVulnsScriptCached(t *testing.T) {
	f := newFakeHost(t, "1")
	vulnsDocker(t, f, true)
	vulnsTrivy(t, f, "trivy-out.json", "0")
	if err := os.WriteFile(filepath.Join(f.dir, "trivy-out.json"), []byte(trivyOut), 0o600); err != nil {
		t.Fatal(err)
	}
	vulnsDB(t, f)
	if code, _, doc := f.runVulns(t, f.bin+":/usr/bin:/bin", vulnsParams()); code != 0 || doc["cached"] == true {
		t.Fatalf("first run %d %v", code, doc)
	}
	code, _, doc := f.runVulns(t, f.bin+":/usr/bin:/bin", vulnsParams())
	if code != 0 || doc["status"] != "ok" || doc["cached"] != true {
		t.Fatalf("second run %d %v", code, doc)
	}
	scans := strings.Count(f.readCalls(t), "--offline-scan")
	if scans != 1 {
		t.Fatalf("the scanner ran %d times, want 1", scans)
	}
}

func TestImageVulnsScriptAbsent(t *testing.T) {
	f := newFakeHost(t, "1")
	bin := vulnsBin(t, f)
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\necho 27.3.1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	code, _, doc := f.runVulns(t, bin, vulnsParams())
	if code != 0 || doc["phase"] != "done" || doc["status"] != "absent" || doc["present"] != false {
		t.Fatalf("%d %v", code, doc)
	}
	if _, ok := doc["summary"]; ok {
		t.Fatal("an absent scan must not carry findings")
	}
}

func TestImageVulnsScriptNoDocker(t *testing.T) {
	f := newFakeHost(t, "1")
	code, _, doc := f.runVulns(t, vulnsBin(t, f), vulnsParams())
	if code != 10 || doc["phase"] != "precheck" || !strings.Contains(doc["reason"].(string), "Docker is not installed") {
		t.Fatalf("%d %v", code, doc)
	}
}

func TestImageVulnsScriptNotLocal(t *testing.T) {
	f := newFakeHost(t, "1")
	vulnsDocker(t, f, false)
	vulnsTrivy(t, f, "trivy-out.json", "0")
	vulnsDB(t, f)
	code, _, doc := f.runVulns(t, f.bin+":/usr/bin:/bin", vulnsParams())
	if code != 0 || doc["status"] != "notlocal" {
		t.Fatalf("%d %v", code, doc)
	}
	if strings.Contains(f.readCalls(t), "trivy image") {
		t.Fatal("a non-local image must not be scanned (never pulled)")
	}
}

func TestImageVulnsScriptStale(t *testing.T) {
	t.Run("no database", func(t *testing.T) {
		f := newFakeHost(t, "1")
		vulnsDocker(t, f, true)
		vulnsTrivy(t, f, "trivy-out.json", "0")
		code, _, doc := f.runVulns(t, f.bin+":/usr/bin:/bin", vulnsParams())
		if code != 0 || doc["status"] != "stale" {
			t.Fatalf("%d %v", code, doc)
		}
	})
	t.Run("database older than 24 h", func(t *testing.T) {
		f := newFakeHost(t, "1")
		vulnsDocker(t, f, true)
		vulnsTrivy(t, f, "trivy-out.json", "0")
		vulnsDB(t, f)
		old := time.Now().Add(-48 * time.Hour)
		if err := os.Chtimes(filepath.Join(f.dir, "tcache", "db", "vuln-list.json"), old, old); err != nil {
			t.Fatal(err)
		}
		code, _, doc := f.runVulns(t, f.bin+":/usr/bin:/bin", vulnsParams())
		if code != 0 || doc["status"] != "stale" {
			t.Fatalf("%d %v", code, doc)
		}
		if h := doc["dbage"].(float64); h < 48 || h > 49 {
			t.Fatalf("database age %v h, want ~48", h)
		}
	})
}

// TestImageVulnsScriptBusy: another scan holds the per-host lock.
func TestImageVulnsScriptBusy(t *testing.T) {
	f := newFakeHost(t, "1")
	vulnsDocker(t, f, true)
	vulnsTrivy(t, f, "trivy-out.json", "0")
	vulnsDB(t, f)
	w := filepath.Join(f.dir, "tmp", "nebula-image-vulns.0")
	if err := os.MkdirAll(w, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("flock missing on this machine")
	}
	lock := exec.Command("flock", filepath.Join(w, "scan.lock"), "-c", "sleep 3")
	if err := lock.Start(); err != nil {
		t.Fatal(err)
	}
	defer lock.Process.Kill()
	time.Sleep(200 * time.Millisecond)
	code, _, doc := f.runVulns(t, f.bin+":/usr/bin:/bin", vulnsParams())
	if code != 0 || doc["status"] != "busy" {
		t.Fatalf("%d %v", code, doc)
	}
}

func TestImageVulnsScriptFailed(t *testing.T) {
	f := newFakeHost(t, "1")
	vulnsDocker(t, f, true)
	vulnsTrivy(t, f, "trivy-out.json", "1")
	if err := os.WriteFile(filepath.Join(f.dir, "trivy-out.json"), []byte(trivyOut), 0o600); err != nil {
		t.Fatal(err)
	}
	vulnsDB(t, f)
	code, _, doc := f.runVulns(t, f.bin+":/usr/bin:/bin", vulnsParams())
	if code != 0 || doc["status"] != "failed" {
		t.Fatalf("%d %v", code, doc)
	}
}

func TestImageVulnsScriptTruncated(t *testing.T) {
	f := newFakeHost(t, "1")
	vulnsDocker(t, f, true)
	vulnsTrivy(t, f, "trivy-out.json", "0")
	if err := os.WriteFile(filepath.Join(f.dir, "trivy-out.json"), bytes.Repeat([]byte("x\n"), 17000000), 0o600); err != nil {
		t.Fatal(err)
	}
	vulnsDB(t, f)
	code, _, doc := f.runVulns(t, f.bin+":/usr/bin:/bin", vulnsParams())
	if code != 0 || doc["status"] != "truncated" {
		t.Fatalf("%d %v", code, doc)
	}
}

func TestImageVulnsScriptUnsupported(t *testing.T) {
	f := newFakeHost(t, "1")
	vulnsDocker(t, f, true)
	vulnsTrivy(t, f, "trivy-out.json", "0")
	if err := os.WriteFile(filepath.Join(f.dir, "trivy-out.json"), []byte("this is not a scan result"), 0o600); err != nil {
		t.Fatal(err)
	}
	vulnsDB(t, f)
	code, _, doc := f.runVulns(t, f.bin+":/usr/bin:/bin", vulnsParams())
	if code != 0 || doc["status"] != "unsupported" {
		t.Fatalf("%d %v", code, doc)
	}
}

func TestImageVulnsScriptPrecheck(t *testing.T) {
	for _, params := range []string{
		`{}`,
		`{"image":"nginx:latest"}`,
		`{"image":"nginx@` + strings.Repeat("a", 63) + `"}`,
		`{"image":"nginx@` + vulnsDigest + `","extra":"1"}`,
	} {
		f := newFakeHost(t, "1")
		vulnsDocker(t, f, true)
		code, _, doc := f.runVulns(t, f.bin+":/usr/bin:/bin", params)
		if code != 10 || doc["phase"] != "precheck" {
			t.Fatalf("%s: %d %v", params, code, doc)
		}
	}
}

// TestImageVulnsScriptSudo: a non-root user without the docker group uses
// sudo -n for docker, trivy and the database mtime.
func TestImageVulnsScriptSudo(t *testing.T) {
	f := newFakeHost(t, "1")
	f.write(t, "id", `echo 1000`)
	f.write(t, "docker", `[ -z "${SUDO:-}" ] && exit 1
echo "$@" >> "`+f.calls+`"
case "$1" in
  version) echo "27.3.1" ;;
  image) echo "linux/amd64" ;;
esac`)
	f.write(t, "trivy", `echo "$@" >> "`+f.calls+`"
case "$1" in
  --version) echo "Version: 0.52.0" ;;
  image) cat "`+f.dir+`/trivy-out.json"; exit 0 ;;
esac`)
	f.write(t, "sudo", `[ "$1" = "-n" ] || exit 1; shift
if [ "$1" = "stat" ]; then echo "$(date +%s)"; exit 0; fi
echo "sudo $*" >> "`+f.calls+`"
SUDO=1 exec "$@"`)
	if err := os.WriteFile(filepath.Join(f.dir, "trivy-out.json"), []byte(trivyOut), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, doc := f.runVulns(t, f.bin+":/usr/bin:/bin", vulnsParams())
	if code != 0 || doc["status"] != "ok" {
		t.Fatalf("%d %v", code, doc)
	}
	calls := f.readCalls(t)
	if !strings.Contains(calls, "sudo docker image inspect") || !strings.Contains(calls, "sudo trivy image --offline-scan --skip-db-update") {
		t.Fatalf("calls %q", calls)
	}
}
