// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const (
	pkgsHex      = "1111111111111111111111111111111111111111111111111111111111111111"
	pkgsOtherHex = "2222222222222222222222222222222222222222222222222222222222222222"
	pkgsImage    = "docker.io/library/nginx@sha256:" + pkgsHex
)

// pkgsScanFlags is the exact local-only, package-only Trivy profile.
const pkgsScanFlags = "image --offline-scan --skip-db-update --skip-java-db-update --image-src docker --scanners none --list-all-pkgs --quiet --format json -- " + pkgsImage

// pkgsSecret sits in the image config the raw Trivy report carries; it
// must never leave the host.
const pkgsSecret = "SECRET_TOKEN=do-not-keep"

// pkgsTrivyDoc is a Trivy --list-all-pkgs report for hexDigest with the
// given extra package entries appended to the os-pkgs result. It carries
// fields the host must drop (image config, layers, licences).
func pkgsTrivyDoc(hexDigest string, extra ...string) string {
	entries := []string{
		`{"ID":"libssl3@3.0.15-1~deb12u1","Name":"libssl3","Identifier":{"PURL":"pkg:deb/debian/libssl3@3.0.15-1~deb12u1"},"Version":"3.0.15","Release":"1~deb12u1","SrcName":"openssl","SrcVersion":"3.0.15","SrcRelease":"1~deb12u1","Licenses":["Apache-2.0"],"Layer":{"DiffID":"sha256:` + pkgsOtherHex + `"}}`,
		`{"Name":"libc6","Version":"2.36","Release":"9+deb12u9","SrcName":"glibc","SrcVersion":"2.36","SrcRelease":"9+deb12u9","Maintainer":"GNU Libc Maintainers"}`,
	}
	entries = append(entries, extra...)
	return `{
  "SchemaVersion": 2,
  "CreatedAt": "2026-11-09T12:00:00.123456789Z",
  "ArtifactName": "nginx@sha256:` + hexDigest + `",
  "ArtifactType": "container_image",
  "Metadata": {
    "Size": 1.875e8,
    "OS": {"Family": "debian", "Name": "12.8"},
    "ImageID": "sha256:` + pkgsOtherHex + `",
    "DiffIDs": ["sha256:` + pkgsOtherHex + `"],
    "RepoTags": ["nginx:1.27"],
    "RepoDigests": ["nginx@sha256:` + hexDigest + `"],
    "ImageConfig": {"config": {"Env": ["` + pkgsSecret + `", "PATH=/usr/bin"]}}
  },
  "Results": [
    {"Target": "nginx (debian 12.8)", "Class": "os-pkgs", "Type": "debian", "Packages": [` + strings.Join(entries, ",") + `]},
    {"Target": "usr/local/bin/app", "Class": "lang-pkgs", "Type": "gobinary", "Packages": [{"Name": "golang.org/x/net", "Version": "v0.33.0"}]}
  ]
}`
}

// pkgsHost is a fake Docker host for image.packages: PATH holds only the
// tools the script needs plus fake docker and, optionally, trivy. Every
// docker and trivy call is recorded.
type pkgsHost struct {
	dir, bin, calls string
}

func newPkgsHost(t *testing.T, local bool) *pkgsHost {
	t.Helper()
	d := t.TempDir()
	h := &pkgsHost{dir: d, bin: filepath.Join(d, "bin"), calls: filepath.Join(d, "calls")}
	if err := os.Mkdir(h.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// The script needs sed and python3; the fake trivy needs cat.
	for _, tool := range []string{"sed", "python3", "cat"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Skipf("%s missing on this machine", tool)
		}
		if err := os.Symlink(p, filepath.Join(h.bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	h.cmd(t, "id", `echo 1000`)
	ok := "0"
	if local {
		ok = "1"
	}
	h.cmd(t, "docker", `echo "docker $*" >> "`+h.calls+`"
case "$1" in
  version) echo "27.3.1" ;;
  image) [ "`+ok+`" = 1 ] || exit 1; echo "sha256:`+pkgsOtherHex+`" ;;
  *) exit 64 ;;
esac`)
	for _, c := range []string{"sudo", "curl", "wget", "apt-get", "apk", "dnf", "yum"} {
		h.cmd(t, c, `echo "forbidden $0 $*" >> "`+h.calls+`"; exit 1`)
	}
	return h
}

// trivy installs a fake trivy that prints the file out and exits rc.
func (h *pkgsHost) trivy(t *testing.T, out string, rc int) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(h.dir, "trivy-out"), []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	h.cmd(t, "trivy", `echo "trivy $*" >> "`+h.calls+`"
case "$1" in
  --version) echo "Version: 0.57.1" ;;
  image) cat "`+h.dir+`/trivy-out"; exit `+fmt.Sprint(rc)+` ;;
  *) exit 64 ;;
esac`)
}

func (h *pkgsHost) cmd(t *testing.T, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(h.bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func (h *pkgsHost) readCalls(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(h.calls)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

// run runs the image.packages script for image and returns its stdout and
// exit code. HOME and TMPDIR are inside the host directory so any file the
// script wrote would be found.
func (h *pkgsHost) run(t *testing.T, image string) ([]byte, int) {
	t.Helper()
	a, ok := Lookup("image.packages")
	if !ok {
		t.Fatal("image.packages is not registered")
	}
	work := filepath.Join(h.dir, "work")
	if err := os.Mkdir(work, 0o700); err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	p := filepath.Join(h.dir, "params.json")
	if err := os.WriteFile(p, []byte(`{"image":"`+image+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := filepath.Join(h.dir, "ip.sh")
	if err := os.WriteFile(s, a.Script, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", s)
	cmd.Dir = work
	cmd.Env = []string{"PATH=" + h.bin, "NEBULA_PARAMS=" + p, "HOME=" + work, "TMPDIR=" + work}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	if calls := h.readCalls(t); strings.Contains(calls, "forbidden") {
		t.Fatalf("script ran a forbidden command: %s", calls)
	}
	if left, _ := os.ReadDir(work); len(left) != 0 {
		t.Fatalf("script left %d files in its working directory", len(left))
	}
	return stdout.Bytes(), code
}

// sameAsRaw checks that the host-side reduction changed nothing the
// parser judges: the reduced result parses exactly like the raw report.
func sameAsRaw(t *testing.T, raw string, got dockerhost.ImagePackages) {
	t.Helper()
	want, err := dockerhost.ParseImagePackages(pkgsImage, dockerhost.TrivyPackagesRun{Present: true, Output: []byte(raw)})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reduced report parses differently\n got %+v\nwant %+v", got, want)
	}
}

func parsePkgs(t *testing.T, out []byte) dockerhost.ImagePackages {
	t.Helper()
	p, err := ParseImagePackagesResult(pkgsImage, out)
	if err != nil {
		t.Fatalf("ParseImagePackagesResult: %v", err)
	}
	return p
}

// image.packages (ADR 0011 D3, VU-06) is a LOW, read-only, safely retried
// read with one digest-pinned parameter and no secrets.
func TestImagePackagesIsLowReadOnly(t *testing.T) {
	a, ok := Lookup("image.packages")
	if !ok {
		t.Fatal("image.packages is not registered")
	}
	switch {
	case a.Risk != pb.RiskClass_RISK_CLASS_LOW:
		t.Errorf("risk = %v, want LOW", a.Risk)
	case !a.ReadOnly:
		t.Error("not marked read-only")
	case a.Durable:
		t.Error("a read is not a durable job")
	case len(a.Params) != 1 || a.Params[0].Name != "image":
		t.Errorf("parameters %+v, want one image", a.Params)
	case len(a.Secrets) != 0:
		t.Errorf("has %d secret slots, want none", len(a.Secrets))
	case a.Retry != RetrySafe:
		t.Errorf("retry class %q, want %q", a.Retry, RetrySafe)
	case a.Version != "1.0.0":
		t.Errorf("version %q", a.Version)
	}
	if err := a.ValidParams(map[string]string{"image": pkgsImage}); err != nil {
		t.Fatalf("digest-pinned reference rejected: %v", err)
	}
	for _, bad := range []string{"nginx:latest", "nginx", "nginx@sha256:" + strings.Repeat("A", 64), "@sha256:" + pkgsHex} {
		if err := a.ValidParams(map[string]string{"image": bad}); err == nil {
			t.Errorf("parameter %q accepted", bad)
		}
	}
}

// The script only ever uses a Trivy that is already there, with the
// local-only profile and no vulnerability scanner: it never installs or
// pulls Trivy or an image and never refreshes a database.
func TestImagePackagesScriptNeverInstallsPullsOrRefreshes(t *testing.T) {
	a, _ := Lookup("image.packages")
	s := string(a.Script)
	for _, want := range []string{`"--offline-scan"`, `"--skip-db-update"`, `"--skip-java-db-update"`, `"--image-src", "docker"`, `"--scanners", "none"`, `"--list-all-pkgs"`} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks the local-only flag %s", want)
		}
	}
	for _, banned := range []string{"db update", "--download-db-only", "--download-java-db-only", "--reset", "clean", "docker pull", "image pull", "pull ",
		"--scanners vuln", `"vuln"`, "secret", "apt-get", "apk ", "dnf ", "yum ", "pip ", "curl", "wget", "install", "github.com", "http://", "https://"} {
		if strings.Contains(s, banned) {
			t.Errorf("script may not install, pull or refresh: contains %q", banned)
		}
	}
}

// A complete run: the exact profile is used, the result round-trips
// through the vu06a parser as a complete read, and nothing but the package
// list, OS and digest references leaves the host.
func TestImagePackagesEndToEndComplete(t *testing.T) {
	h := newPkgsHost(t, true)
	h.trivy(t, pkgsTrivyDoc(pkgsHex), 0)
	out, code := h.run(t, pkgsImage)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if !strings.Contains(h.readCalls(t), "trivy "+pkgsScanFlags+"\n") {
		t.Fatalf("calls %q", h.readCalls(t))
	}
	for _, leak := range []string{pkgsSecret, "ImageConfig", "Licenses", "Layer", "Maintainer", "PURL", "RepoTags", "CreatedAt"} {
		if bytes.Contains(out, []byte(leak)) {
			t.Errorf("result carries %q: %s", leak, out)
		}
	}
	p := parsePkgs(t, out)
	sameAsRaw(t, pkgsTrivyDoc(pkgsHex), p)
	if !p.Known || !p.Complete || p.Reason != "" {
		t.Fatalf("known=%v complete=%v reason=%q\n%s", p.Known, p.Complete, p.Reason, out)
	}
	if p.OS != (dockerhost.ImageOS{Family: "debian", Name: "12.8"}) || p.Digest != pkgsImage {
		t.Fatalf("os %+v digest %q", p.OS, p.Digest)
	}
	want := []dockerhost.ImagePackage{
		{Ecosystem: "debian", Name: "libssl3", Version: "3.0.15-1~deb12u1", SrcName: "openssl", SrcVersion: "3.0.15-1~deb12u1"},
		{Ecosystem: "debian", Name: "libc6", Version: "2.36-9+deb12u9", SrcName: "glibc", SrcVersion: "2.36-9+deb12u9"},
		{Ecosystem: "gobinary", Name: "golang.org/x/net", Version: "v0.33.0"},
	}
	if fmt.Sprint(p.Packages) != fmt.Sprint(want) {
		t.Fatalf("packages\n got %+v\nwant %+v", p.Packages, want)
	}
}

// Missing Trivy means "image packages unknown", never an empty list, and
// nothing else is tried in its place.
func TestImagePackagesAbsentTrivyIsUnknown(t *testing.T) {
	h := newPkgsHost(t, true)
	out, code := h.run(t, pkgsImage)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	p := parsePkgs(t, out)
	if p.Known || p.Complete || p.Reason != dockerhost.ReasonTrivyAbsent || len(p.Packages) != 0 {
		t.Fatalf("absent Trivy gave %+v", p)
	}
	if calls := h.readCalls(t); strings.Contains(calls, "trivy") {
		t.Fatalf("calls %q", calls)
	}
}

// A report for another image digest is a partial read: it may add
// inventory but never prove a removal or a fixed version.
func TestImagePackagesWrongDigestIsPartial(t *testing.T) {
	h := newPkgsHost(t, true)
	h.trivy(t, pkgsTrivyDoc(pkgsOtherHex), 0)
	out, code := h.run(t, pkgsImage)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	p := parsePkgs(t, out)
	sameAsRaw(t, pkgsTrivyDoc(pkgsOtherHex), p)
	if !p.Known || p.Complete || p.Reason != dockerhost.ReasonDigestMismatch {
		t.Fatalf("wrong digest gave known=%v complete=%v reason=%q", p.Known, p.Complete, p.Reason)
	}
}

// An image that is not local is never scanned (Trivy would have to pull
// it): the packages stay unknown.
func TestImagePackagesNotLocalIsUnknownWithoutScan(t *testing.T) {
	h := newPkgsHost(t, false)
	h.trivy(t, pkgsTrivyDoc(pkgsHex), 0)
	out, code := h.run(t, pkgsImage)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	p := parsePkgs(t, out)
	if p.Known || p.Complete || p.Reason != ReasonImageNotLocal {
		t.Fatalf("image not local gave %+v", p)
	}
	if strings.Contains(h.readCalls(t), "trivy image") {
		t.Fatal("a non-local image was scanned")
	}
}

// Failed, cut or unparseable Trivy output never yields a complete read.
func TestImagePackagesFailuresAreNotComplete(t *testing.T) {
	for _, tc := range []struct {
		name, out  string
		rc         int
		known      bool
		wantReason string
	}{
		{"exit nonzero with report", pkgsTrivyDoc(pkgsHex), 1, true, dockerhost.ReasonExitNonZero},
		{"exit nonzero garbage", "FATAL: no such image\n", 1, false, dockerhost.ReasonExitNonZero + "," + dockerhost.ReasonUnparseable},
		{"empty", "", 0, false, dockerhost.ReasonUnparseable},
		{"not json", "not json", 0, false, dockerhost.ReasonUnparseable},
		{"trailing data", pkgsTrivyDoc(pkgsHex) + "{}", 0, false, dockerhost.ReasonUnparseable},
		{"nan", strings.Replace(pkgsTrivyDoc(pkgsHex), "1.875e8", "NaN", 1), 0, false, dockerhost.ReasonUnparseable},
		{"duplicate top-level key", strings.Replace(pkgsTrivyDoc(pkgsHex), `"ArtifactType"`, `"CreatedAt"`, 1), 0, false, dockerhost.ReasonUnparseable},
		{"duplicate metadata key", strings.Replace(pkgsTrivyDoc(pkgsHex), `"RepoTags"`, `"ImageID"`, 1), 0, false, dockerhost.ReasonUnparseable},
		{"schema 1", strings.Replace(pkgsTrivyDoc(pkgsHex), `"SchemaVersion": 2`, `"SchemaVersion": 1`, 1), 0, false, dockerhost.ReasonUnparseable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newPkgsHost(t, true)
			h.trivy(t, tc.out, tc.rc)
			out, code := h.run(t, pkgsImage)
			if code != 0 {
				t.Fatalf("exit %d: %s", code, out)
			}
			p := parsePkgs(t, out)
			if p.Complete || p.Known != tc.known || p.Reason != tc.wantReason {
				t.Fatalf("known=%v complete=%v reason=%q", p.Known, p.Complete, p.Reason)
			}
		})
	}
}

// The host-side reduction keeps every package entry and every field the
// parser judges, verbatim: entries that are invalid in the raw report stay
// invalid, so a dropped entry still marks the read partial.
func TestImagePackagesReductionKeepsInvalidEntries(t *testing.T) {
	// Equivalence only: the parser itself decides; a lone surrogate
	// decodes to U+FFFD, which it accepts.
	for name, entry := range map[string]string{
		"lone surrogate": `{"Name":"zlib\ud8001g","Version":"1.2.13"}`,
		"unknown keys":   `{"Name":"zlib1g","Version":"1.2.13","DependsOn":["libc6"],"Identifier":{"Name":"x"},"name":"y"}`,
		"null fields":    `{"Name":"zlib1g","Version":"1.2.13","Release":null,"Epoch":null,"SrcName":null}`,
		"epoch":          `{"Name":"zlib1g","Version":"1.2.13","Release":"3","Epoch":1,"SrcName":"zlib","SrcVersion":"1.2.13","SrcEpoch":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			h := newPkgsHost(t, true)
			raw := pkgsTrivyDoc(pkgsHex, entry)
			h.trivy(t, raw, 0)
			out, code := h.run(t, pkgsImage)
			if code != 0 {
				t.Fatalf("exit %d: %s", code, out)
			}
			sameAsRaw(t, raw, parsePkgs(t, out))
		})
	}
	for name, entry := range map[string]string{
		"number name":      `{"Name":42,"Version":"1.0"}`,
		"float epoch":      `{"Name":"zlib1g","Version":"1.2.13","Epoch":1.0}`,
		"exponent epoch":   `{"Name":"zlib1g","Version":"1.2.13","Epoch":1e0}`,
		"huge epoch":       `{"Name":"zlib1g","Version":"1.2.13","Epoch":123456789012345678901234567890}`,
		"repeated field":   `{"Name":"zlib1g","Version":"1.2.13","Name":"zlib"}`,
		"null entry":       `null`,
		"string entry":     `"zlib1g"`,
		"nested name":      `{"Name":{"x":"zlib1g"},"Version":"1.2.13"}`,
		"escaped bad rune": "{\"Name\":\"zlib\\u202e1g\",\"Version\":\"1.2.13\"}",
		"raw bad rune":     `{"Name":"zlib` + string(rune(0x202e)) + `1g","Version":"1.2.13"}`,
		"missing version":  `{"Name":"zlib1g"}`,
		// The second key is "Name" spelled with a JSON escape for the "a".
		"escaped name key":  `{"Name":"zlib1g","Version":"1.2.13","N` + `\` + `u0061me":"zlib"}`,
		"whitespace in ver": `{"Name":"zlib1g","Version":"1.2 13"}`,
	} {
		t.Run(name, func(t *testing.T) {
			h := newPkgsHost(t, true)
			raw := pkgsTrivyDoc(pkgsHex, entry)
			h.trivy(t, raw, 0)
			out, code := h.run(t, pkgsImage)
			if code != 0 {
				t.Fatalf("exit %d: %s", code, out)
			}
			p := parsePkgs(t, out)
			sameAsRaw(t, raw, p)
			if !p.Known || p.Complete || p.Reason != dockerhost.ReasonEntryDropped {
				t.Fatalf("known=%v complete=%v reason=%q\n%s", p.Known, p.Complete, p.Reason, out)
			}
			if len(p.Packages) != 3 {
				t.Fatalf("%d packages, want the 3 valid ones", len(p.Packages))
			}
		})
	}
}

// Trivy output above the parser's limit is cut on the host and the
// packages stay unknown; so does a reduced list too large for a result.
func TestImagePackagesOversizedOutputIsUnknown(t *testing.T) {
	t.Run("raw output", func(t *testing.T) {
		h := newPkgsHost(t, true)
		pad := strings.Repeat("x", dockerhost.MaxImagePackagesOutput)
		h.trivy(t, strings.Replace(pkgsTrivyDoc(pkgsHex), `"CreatedAt"`, `"Pad":"`+pad+`","CreatedAt"`, 1), 0)
		out, code := h.run(t, pkgsImage)
		if code != 0 || len(out) > 4096 {
			t.Fatalf("exit %d, %d bytes", code, len(out))
		}
		p := parsePkgs(t, out)
		if p.Known || p.Complete || p.Reason != dockerhost.ReasonUnparseable {
			t.Fatalf("known=%v complete=%v reason=%q", p.Known, p.Complete, p.Reason)
		}
	})
	t.Run("reduced list", func(t *testing.T) {
		h := newPkgsHost(t, true)
		var extra []string
		for i := range 4000 {
			extra = append(extra, fmt.Sprintf(`{"Name":"pkg-%04d-%s","Version":"1.0","Release":"1","SrcName":"src-%04d-%s","SrcVersion":"1.0","SrcRelease":"1"}`,
				i, strings.Repeat("n", 100), i, strings.Repeat("s", 100)))
		}
		h.trivy(t, pkgsTrivyDoc(pkgsHex, extra...), 0)
		out, code := h.run(t, pkgsImage)
		if code != 0 || len(out) > 4096 {
			t.Fatalf("exit %d, %d bytes", code, len(out))
		}
		p := parsePkgs(t, out)
		if p.Known || p.Complete || p.Reason != dockerhost.ReasonUnparseable {
			t.Fatalf("known=%v complete=%v reason=%q", p.Known, p.Complete, p.Reason)
		}
	})
}

// When Docker needs sudo, Trivy is used the same way (sudo -n, never a
// password prompt), and a missing root Trivy is absent, not an error.
func TestImagePackagesSudoPath(t *testing.T) {
	for _, withTrivy := range []bool{true, false} {
		h := newPkgsHost(t, true)
		h.trivy(t, pkgsTrivyDoc(pkgsHex), 0)
		if !withTrivy {
			h.cmd(t, "trivy", `echo "trivy $*" >> "`+h.calls+`"; exit 127`)
		}
		// docker works only through the fake sudo.
		h.cmd(t, "sudo", `[ "$1" = "-n" ] || exit 1
shift
echo "sudo $*" >> "`+h.calls+`"
NOS_SUDO=1 exec "$@"`)
		h.cmd(t, "docker", `[ -n "${NOS_SUDO-}" ] || exit 1
case "$1" in
  version) echo "27.3.1" ;;
  image) echo "sha256:`+pkgsOtherHex+`" ;;
  *) exit 64 ;;
esac`)
		out, code := h.run(t, pkgsImage)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		p := parsePkgs(t, out)
		calls := h.readCalls(t)
		if withTrivy {
			if !p.Complete || !strings.Contains(calls, "sudo trivy "+pkgsScanFlags+"\n") {
				t.Fatalf("complete=%v reason=%q calls %q", p.Complete, p.Reason, calls)
			}
		} else if p.Known || p.Reason != dockerhost.ReasonTrivyAbsent || strings.Contains(calls, "trivy image") {
			t.Fatalf("missing root Trivy gave %+v, calls %q", p, calls)
		}
	}
}

// The script's own precheck: a bad parameter or no Docker fails the run
// instead of reporting packages.
func TestImagePackagesScriptPrecheck(t *testing.T) {
	h := newPkgsHost(t, true)
	if out, code := h.run(t, "nginx:latest"); code != 10 || !bytes.Contains(out, []byte(`"phase":"precheck"`)) {
		t.Fatalf("bad image: exit %d %s", code, out)
	}
	if err := os.Remove(filepath.Join(h.bin, "docker")); err != nil {
		t.Fatal(err)
	}
	if out, code := h.run(t, pkgsImage); code != 10 {
		t.Fatalf("no docker: exit %d %s", code, out)
	}
}

// The result document is untrusted host data: anything but a well-formed
// image-packages-v1 result for the requested image is unknown, never an
// error and never complete. Only an invalid requested digest is an error.
func TestParseImagePackagesResultRejectsMalformed(t *testing.T) {
	report := `{"SchemaVersion":2,"ArtifactName":"nginx@sha256:` + pkgsHex + `","Metadata":{"OS":{"Family":"debian","Name":"12.8"}},"Results":[{"Class":"os-pkgs","Type":"debian","Packages":[{"Name":"libc6","Version":"2.36"}]}]}`
	frame := func(fields string) []byte {
		return []byte(`{"format":"image-packages-v1","phase":"done","image":"` + pkgsImage + `"` + fields + "}")
	}
	good := frame(`,"status":"ok","present":true,"rc":0,"output":"ok","report":` + report)
	if p := parsePkgs(t, good); !p.Complete {
		t.Fatalf("well-formed result gave %+v", p)
	}
	for name, raw := range map[string][]byte{
		"empty":            nil,
		"not json":         []byte("nope"),
		"two documents":    append(append([]byte{}, good...), good...),
		"unknown field":    frame(`,"status":"ok","present":true,"rc":0,"output":"ok","report":` + report + `,"extra":1`),
		"wrong format":     bytes.Replace(good, []byte("image-packages-v1"), []byte("image-packages-v2"), 1),
		"wrong phase":      bytes.Replace(good, []byte(`"phase":"done"`), []byte(`"phase":"precheck"`), 1),
		"other image":      bytes.Replace(good, []byte(`"image":"`+pkgsImage), []byte(`"image":"docker.io/library/nginx@sha256:`+pkgsOtherHex), 1),
		"unknown status":   frame(`,"status":"cached","present":true,"rc":0,"output":"ok","report":` + report),
		"ok without rc":    frame(`,"status":"ok","present":true,"output":"ok","report":` + report),
		"ok without rep":   frame(`,"status":"ok","present":true,"rc":0,"output":"ok"`),
		"ok null report":   frame(`,"status":"ok","present":true,"rc":0,"output":"ok","report":null`),
		"ok not present":   frame(`,"status":"ok","present":false,"rc":0,"output":"ok","report":` + report),
		"cut with report":  frame(`,"status":"ok","present":true,"output":"truncated","report":` + report),
		"unknown output":   frame(`,"status":"ok","present":true,"rc":0,"output":"partial","report":` + report),
		"absent present":   frame(`,"status":"absent","present":true`),
		"absent with rep":  frame(`,"status":"absent","present":false,"report":` + report),
		"not utf-8":        frame(`,"status":"ok","present":true,"rc":0,"output":"ok","report":` + report + `,"x":"` + "\xff" + `"`),
		"oversized":        frame(`,"status":"ok","present":true,"rc":0,"output":"ok","report":` + report + `,"pad":"` + strings.Repeat("x", maxImagePackagesResult) + `"`),
		"report not trivy": frame(`,"status":"ok","present":true,"rc":0,"output":"ok","report":{"SchemaVersion":2}`),
	} {
		t.Run(name, func(t *testing.T) {
			p := parsePkgs(t, raw)
			if p.Complete || len(p.Packages) != 0 || p.Digest != pkgsImage {
				t.Fatalf("gave %+v", p)
			}
			if p.Known && name != "report not trivy" {
				t.Fatalf("malformed result is known: %+v", p)
			}
		})
	}
	if _, err := ParseImagePackagesResult("nginx:latest", good); !errors.Is(err, dockerhost.ErrImagePackagesDigest) {
		t.Fatalf("invalid digest: %v", err)
	}
}
