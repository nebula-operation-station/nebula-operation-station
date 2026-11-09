// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

// package.list_installed (ADR 0011 D3, VU-05) is a LOW, read-only,
// parameterless read that runs without secrets and is safe to retry.
func TestPackageListInstalledIsLowReadOnly(t *testing.T) {
	a, ok := Lookup("package.list_installed")
	if !ok {
		t.Fatal("package.list_installed is not registered")
	}
	switch {
	case a.Risk != pb.RiskClass_RISK_CLASS_LOW:
		t.Errorf("risk = %v, want LOW", a.Risk)
	case !a.ReadOnly:
		t.Error("not marked read-only")
	case a.Durable:
		t.Error("a read is not a durable job")
	case len(a.Params) != 0:
		t.Errorf("takes %d parameters, want none", len(a.Params))
	case len(a.Secrets) != 0:
		t.Errorf("has %d secret slots, want none", len(a.Secrets))
	case a.Retry != RetrySafe:
		t.Errorf("retry class %q, want %q", a.Retry, RetrySafe)
	case a.Version != "1.0.0":
		t.Errorf("version %q", a.Version)
	}
}

// The script reads the dpkg database and uname only: no apt, no sudo, no
// network tool, no write to a file.
func TestPackageListInstalledScriptHasNoPrivilegeOrNetwork(t *testing.T) {
	a, _ := Lookup("package.list_installed")
	var code []string
	for _, line := range strings.Split(string(a.Script), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			code = append(code, line)
		}
	}
	s := strings.Join(code, "\n")
	for _, bad := range []string{"apt", "sudo", "su ", "curl", "wget", "nc ", "dpkg ", "mktemp", "tee", "/tmp", "rm ", "base64"} {
		if strings.Contains(s, bad) {
			t.Errorf("script contains %q", bad)
		}
	}
	// The only redirections are to stderr and /dev/null.
	for _, line := range code {
		code := line
		for i := strings.IndexByte(code, '>'); i >= 0; i = strings.IndexByte(code, '>') {
			rest := code[i+1:]
			if !strings.HasPrefix(rest, "&2") && !strings.HasPrefix(rest, "&1") && !strings.HasPrefix(rest, "/dev/null") {
				t.Errorf("script writes somewhere: %q", line)
				break
			}
			code = rest
		}
	}
}

// installedRow is one dpkg database record the fake dpkg-query knows.
type installedRow struct {
	status, pkg, arch, version, source, sourceVersion, builtUsing string
}

func (r installedRow) tsv() string {
	return strings.Join([]string{r.status, r.pkg, r.arch, r.version, r.source, r.sourceVersion, r.builtUsing}, "\t") + "\n"
}

// fakeDpkgQuery emulates dpkg-query -W -f: awk -v expands the \t and \n
// escapes of the format exactly like dpkg-query, then every known ${field}
// is replaced from the row. An unknown field or argument fails, so the
// script's format string is checked against the real field names.
const fakeDpkgQuery = `fmt=""
[ "${1-}" = "-W" ] || { echo "unexpected first argument" >&2; exit 64; }
shift
while [ $# -gt 0 ]; do
  case "$1" in
    -f|--showformat) shift; fmt=$1 ;;
    --showformat=*) fmt=${1#--showformat=} ;;
    *) echo "unexpected argument" >&2; exit 64 ;;
  esac
  shift
done
[ -n "$fmt" ] || exit 64
awk -F'\t' -v fmt="$fmt" '
function rep(s, key, val,   i, out) {
  out = ""
  while ((i = index(s, key)) > 0) { out = out substr(s, 1, i - 1) val; s = substr(s, i + length(key)) }
  return out s
}
function v(x) { return rep(rep(x, "<TAB>", "\t"), "<NL>", "\n") }
function expand(f) {
  f = rep(f, "${db:Status-Status}", v($1)); f = rep(f, "${Package}", v($2))
  f = rep(f, "${Architecture}", v($3)); f = rep(f, "${Version}", v($4))
  f = rep(f, "${source:Package}", v($5)); f = rep(f, "${source:Version}", v($6))
  return rep(f, "${Built-Using}", v($7))
}
BEGIN { if (index(expand(fmt), "${") > 0) { print "unknown field" > "/dev/stderr"; exit 65 } }
{ printf "%s", expand(fmt) }' "$FAKE/rows" || exit $?
exit "$(cat "$FAKE/rc")"`

const (
	fakeRelease = "6.1.0-26-amd64"
	fakeBuild   = "#1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1 (2024-09-30)"
)

// installedHost is a PATH with a fake dpkg-query and uname. Every command
// the script must never run records its call.
type installedHost struct {
	dir, bin string
}

func newInstalledHost(t *testing.T, rows []installedRow, rc int) *installedHost {
	t.Helper()
	d := t.TempDir()
	h := &installedHost{dir: d, bin: filepath.Join(d, "bin")}
	if err := os.Mkdir(h.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(r.tsv())
	}
	h.file(t, "rows", b.String())
	h.file(t, "rc", strconv.Itoa(rc))
	h.file(t, "release", fakeRelease)
	h.file(t, "build", fakeBuild)
	h.cmd(t, "dpkg-query", fakeDpkgQuery)
	h.cmd(t, "uname", `case "$*" in -r) cat "$FAKE/release" ;; -v) cat "$FAKE/build" ;; *) exit 64 ;; esac`)
	for _, c := range []string{"apt", "apt-get", "apt-cache", "dpkg", "sudo", "su", "curl", "wget"} {
		h.cmd(t, c, `echo "$0" >> "$FAKE/forbidden"; exit 0`)
	}
	// PATH is the fake bin directory only, so the host's own dpkg-query can
	// never answer; the script and the fakes need awk and cat.
	for _, tool := range []string{"awk", "cat"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Fatalf("test needs %s: %v", tool, err)
		}
		if err := os.Symlink(p, filepath.Join(h.bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func (h *installedHost) file(t *testing.T, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(h.dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (h *installedHost) cmd(t *testing.T, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(h.bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// run runs the action's script and returns its stdout and exit code.
func (h *installedHost) run(t *testing.T) ([]byte, int) {
	t.Helper()
	a, ok := Lookup("package.list_installed")
	if !ok {
		t.Fatal("package.list_installed is not registered")
	}
	p := filepath.Join(h.dir, "action.sh")
	if err := os.WriteFile(p, a.Script, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", p)
	cmd.Dir = h.dir
	cmd.Env = []string{"PATH=" + h.bin, "FAKE=" + h.dir}
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
	if b, err := os.ReadFile(filepath.Join(h.dir, "forbidden")); err == nil {
		t.Fatalf("script ran a forbidden command: %s", b)
	}
	return stdout.Bytes(), code
}

func parseRun(out []byte, code int) osdebian.InstalledInventory {
	return osdebian.ParseInstalled(out, osdebian.ReadStatus{ExitCode: code}, vulnver.DistroDebian)
}

var debianRows = []installedRow{
	{"installed", "openssl", "amd64", "3.0.15-1~deb12u1", "openssl", "3.0.15-1~deb12u1", ""},
	{"installed", "libssl3", "amd64", "3.0.15-1~deb12u1", "openssl", "3.0.15-1~deb12u1", ""},
	{"installed", "libc6", "amd64", "2.36-9+deb12u9", "glibc", "2.36-9+deb12u9", ""},
	// A Go binary: its long Built-Using is not kept on the host.
	{"installed", "restic", "amd64", "0.14.0-1+b5", "restic", "0.14.0-1", "golang-1.19 (= 1.19.8-2), golang-github-foo (= 1.0-1)"},
	{"installed", "linux-image-6.1.0-26-amd64", "amd64", "6.1.112-1", "linux-signed-amd64", "6.1.112+1", "linux (= 6.1.112-1)"},
	{"installed", "linux-image-amd64", "amd64", "6.1.112-1", "linux-signed-amd64", "6.1.112+1", ""},
	{"config-files", "oldpkg", "amd64", "1.0-1", "oldpkg", "1.0-1", ""},
}

// A successful read on a Debian host parses into a complete inventory with
// the source version as basis and the running kernel mapped.
func TestPackageListInstalledEndToEndComplete(t *testing.T) {
	out, code := newInstalledHost(t, debianRows, 0).run(t)
	if code != 0 {
		t.Fatalf("exit %d, output %q", code, out)
	}
	inv := parseRun(out, code)
	if !inv.Complete || inv.Reason != "" || inv.Dropped != 0 {
		t.Fatalf("complete=%v reason=%q dropped=%d\n%s", inv.Complete, inv.Reason, inv.Dropped, out)
	}
	if len(inv.Packages) != 6 {
		t.Fatalf("%d packages, want 6 (config-files is not inventory)", len(inv.Packages))
	}
	byName := map[string]osdebian.InstalledPackage{}
	for _, p := range inv.Packages {
		byName[p.Name] = p
	}
	if p := byName["libssl3"]; p.Source != "openssl" || p.SourceVersion != "3.0.15-1~deb12u1" || p.Arch != "amd64" || p.Status != "installed" {
		t.Errorf("libssl3 = %+v", p)
	}
	if p := byName["restic"]; p.BuiltUsing != "" || p.SourceVersion != "0.14.0-1" {
		t.Errorf("restic = %+v (Built-Using must be dropped for non-kernel binaries)", p)
	}
	if p := byName["linux-image-6.1.0-26-amd64"]; p.BuiltUsing != "linux (= 6.1.112-1)" {
		t.Errorf("kernel image Built-Using = %q", p.BuiltUsing)
	}
	k := inv.RunningKernel
	if k.Release != fakeRelease || k.Build != fakeBuild || k.State != osdebian.KernelMapped || k.Source != "linux" || k.Version != "6.1.112-1" {
		t.Errorf("running kernel = %+v", k)
	}
	// The exact record shape: header, P lines, one K line, END with count.
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if lines[0] != osdebian.InstalledFormat {
		t.Errorf("header %q", lines[0])
	}
	if got := lines[len(lines)-2]; got != "K\t"+fakeRelease+"\t"+fakeBuild {
		t.Errorf("kernel record %q", got)
	}
	if got := lines[len(lines)-1]; got != "END\t7" {
		t.Errorf("end record %q", got)
	}
	for _, l := range lines[1 : len(lines)-2] {
		if f := strings.Split(l, "\t"); f[0] != "P" || len(f) != 9 || f[8] != "." {
			t.Errorf("package record %q", l)
		}
	}
}

// Every read that cannot prove the full inventory stays partial: it may add
// inventory but never prove a removal.
func TestPackageListInstalledEndToEndPartial(t *testing.T) {
	cases := []struct {
		name   string
		rows   []installedRow
		rc     int
		mutate func(h *installedHost, t *testing.T)
		cut    int // bytes to cut from the end of the output
		reason string
	}{
		{name: "dpkg-query fails midway", rows: debianRows[:3], rc: 2, reason: osdebian.ReasonReadFailed},
		{name: "dpkg-query missing", rows: debianRows, mutate: func(h *installedHost, t *testing.T) {
			if err := os.Remove(filepath.Join(h.bin, "dpkg-query")); err != nil {
				t.Fatal(err)
			}
		}, reason: osdebian.ReasonReadFailed},
		{name: "half-installed package", rows: append([]installedRow{{"half-installed", "vim", "amd64", "2:9.0.1378-2", "vim", "2:9.0.1378-2", ""}}, debianRows...),
			reason: osdebian.ReasonUnfinished},
		{name: "output cut", rows: debianRows, cut: 9, reason: osdebian.ReasonTruncated},
		{name: "value with a tab", rows: append([]installedRow{{"installed", "evil", "amd64", "1.0<TAB>injected", "evil", "1.0", ""}}, debianRows...),
			reason: osdebian.ReasonMalformed},
		// A folded multi-line Built-Using cannot forge a record: the
		// continuation line is malformed, and the count still matches.
		{name: "value with a newline", rows: append([]installedRow{{"installed", "linux-image-6.1.0-9-amd64", "amd64", "6.1.27-1", "linux-signed-amd64", "6.1.27+1",
			"linux (= 6.1.27-1),<NL>P<TAB>installed<TAB>forged<TAB>amd64<TAB>1<TAB>forged<TAB>1<TAB>"}}, debianRows...),
			reason: osdebian.ReasonMalformed},
		{name: "empty database", rows: nil, reason: osdebian.ReasonNoPackages},
		{name: "uname fails", rows: debianRows, mutate: func(h *installedHost, t *testing.T) {
			h.cmd(t, "uname", "exit 1")
		}, reason: osdebian.ReasonMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newInstalledHost(t, c.rows, c.rc)
			if c.mutate != nil {
				c.mutate(h, t)
			}
			out, code := h.run(t)
			if c.cut > 0 {
				out = out[:len(out)-c.cut]
			}
			inv := parseRun(out, code)
			if inv.Complete {
				t.Fatalf("partial read reported complete:\n%s", out)
			}
			if !strings.HasPrefix(inv.Reason, c.reason) {
				t.Errorf("reason %q, want %q", inv.Reason, c.reason)
			}
		})
	}
}

// A failed dpkg-query run never ends with an END record, and the script
// reports the failure in its exit code.
func TestPackageListInstalledFailedReadHasNoEnd(t *testing.T) {
	out, code := newInstalledHost(t, debianRows[:3], 2).run(t)
	if code == 0 {
		t.Fatal("failed read exited 0")
	}
	if bytes.Contains(out, []byte("\nEND\t")) {
		t.Fatalf("failed read wrote an END record:\n%s", out)
	}
	inv := parseRun(out, 0)
	if inv.Complete || inv.Reason != osdebian.ReasonNoEnd {
		t.Fatalf("without the exit code: complete=%v reason=%q", inv.Complete, inv.Reason)
	}
}
