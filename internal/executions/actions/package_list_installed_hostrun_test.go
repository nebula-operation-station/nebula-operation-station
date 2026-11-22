// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun/hostruntest"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

// typicalDebianRows is a dpkg database of n installed binaries shaped like
// a real Debian 12 server: libraries with binNMU and security versions,
// epochs, Go packages with a long Built-Using (dropped on the host), the
// kernel image with its Built-Using, and a few config-files leftovers.
func typicalDebianRows(n int) []installedRow {
	rows := []installedRow{
		{"installed", "linux-image-6.1.0-26-amd64", "amd64", "6.1.112-1", "linux-signed-amd64", "6.1.112+1", "linux (= 6.1.112-1)"},
		{"installed", "linux-image-amd64", "amd64", "6.1.112-1", "linux-signed-amd64", "6.1.112+1", ""},
	}
	goBU := strings.Repeat("golang-github-example-module-name-"+"x (= 1.2.3-1), ", 40) + "golang-1.19 (= 1.19.8-2)"
	for i := len(rows); i < n; i++ {
		src := fmt.Sprintf("source-package-%04d", i/3)
		r := installedRow{"installed", fmt.Sprintf("lib%s-binary-%04d", src, i), "amd64",
			fmt.Sprintf("1:%d.%d.%d-%d+deb12u%d+b1", i%7, i%13, i%101, i%5+1, i%3+1), src,
			fmt.Sprintf("1:%d.%d.%d-%d+deb12u%d", i%7, i%13, i%101, i%5+1, i%3+1), ""}
		switch {
		case i%50 == 0:
			r.builtUsing = goBU
		case i%97 == 0:
			r.status = "config-files"
		case i%11 == 0:
			r.arch = "all"
		}
		rows = append(rows, r)
	}
	return rows
}

func hostrunClient(t *testing.T) *ssh.Client {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	srv := hostruntest.Start(t, signer.PublicKey())
	c, err := ssh.Dial("tcp", srv.Addr, &ssh.ClientConfig{User: "nebula", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(srv.HostKey.PublicKey()), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// runThroughHostrun runs the action's script as an attached run over SSH
// (hostrun.Attached against the in-process test server), so the result is
// classified by the executor's own rule: exactly one bounded JSON document.
// Only PATH and FAKE are set in front of the unchanged script, to point it
// at the fake dpkg-query and uname.
func (h *installedHost) runThroughHostrun(t *testing.T) hostrun.Result {
	t.Helper()
	a, ok := Lookup("package.list_installed")
	if !ok {
		t.Fatal("package.list_installed is not registered")
	}
	script := "PATH='" + h.bin + "' FAKE='" + h.dir + "'; export PATH FAKE\n" + string(a.Script)
	r, err := hostrun.Attached(context.Background(), hostrunClient(t), "8a6e0804-2bd0-4f6a-8b1e-6d2f1c3a4b5c", []byte(`{}`), []byte(script), a.Timeout)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A typical host (1500 packages) gives a result the executor accepts as a
// success, well below hostrun.MaxResult, and it parses into a complete
// inventory: script -> hostrun classifier -> parser. With the plain-text
// result of 1.0.0 this run was "stdout is not exactly one JSON document".
func TestPackageListInstalledThroughHostrunIsComplete(t *testing.T) {
	rows := typicalDebianRows(1500)
	r := newInstalledHost(t, rows, 0).runThroughHostrun(t)
	if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
		t.Fatalf("class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
	}
	t.Logf("1500 packages: result %d bytes (limit %d)", len(r.Result), hostrun.MaxResult)
	if len(r.Result) > hostrun.MaxResult/4 {
		t.Errorf("result %d bytes for a typical host, want well below %d", len(r.Result), hostrun.MaxResult)
	}
	inv := parseRun(r.Result, r.ExitCode)
	if !inv.Complete || inv.Reason != "" || inv.Dropped != 0 {
		t.Fatalf("complete=%v reason=%q dropped=%d", inv.Complete, inv.Reason, inv.Dropped)
	}
	want := 0
	for _, row := range rows {
		if row.status == "installed" {
			want++
		}
	}
	if len(inv.Packages) != want {
		t.Fatalf("%d packages, want %d", len(inv.Packages), want)
	}
	if k := inv.RunningKernel; k.State != osdebian.KernelMapped || k.Source != "linux" || k.Version != "6.1.112-1" {
		t.Errorf("running kernel = %+v", k)
	}
}

// A failed dpkg-query read still prints one JSON document; the executor
// keeps it with the failure class, and the parser keeps it partial.
func TestPackageListInstalledThroughHostrunFailedRead(t *testing.T) {
	r := newInstalledHost(t, debianRows[:3], 2).runThroughHostrun(t)
	if r.Class != hostrun.ClassScriptFailed || r.ExitCode != 1 || len(r.Result) == 0 {
		t.Fatalf("class %s (%s), exit %d, result %d bytes", r.Class, r.Detail, r.ExitCode, len(r.Result))
	}
	if inv := parseRun(r.Result, r.ExitCode); inv.Complete || inv.Reason != osdebian.ReasonReadFailed {
		t.Fatalf("complete=%v reason=%q", inv.Complete, inv.Reason)
	}
}

// Values that need JSON escaping (quote, backslash, tab, control bytes,
// valid and invalid non-ASCII) never break the one-document rule: the run
// stays a success, the bad lines are malformed for the parser, the good
// ones are inventory, and the K and END records still count.
func TestPackageListInstalledEscapingThroughHostrun(t *testing.T) {
	cases := map[string]installedRow{
		"quote":            {"installed", "evil", "amd64", `1.0"},"x":"`, "evil", "1.0", ""},
		"backslash":        {"installed", "evil", "amd64", `1.0\`, "evil", `1.0\u0022`, ""},
		"tab":              {"installed", "evil", "amd64", "1.0<TAB>x", "evil", "1.0", ""},
		"control bytes":    {"installed", "evil", "amd64", "1.0\x01\x1b[31m\x7f", "evil", "1.0", ""},
		"utf-8 version":    {"installed", "evil", "amd64", "1.0-ünïcode", "evil", "1.0", ""},
		"invalid utf-8":    {"installed", "evil", "amd64", "1.0-\xff\xc3", "evil", "1.0", ""},
		"kernel built-use": {"installed", "linux-image-6.1.0-9-amd64", "amd64", "6.1.27-1", "linux-signed-amd64", "6.1.27+1", "linux (= 6.1.27-1) \"\\\x02"},
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			rows := append([]installedRow{bad}, debianRows...)
			r := newInstalledHost(t, rows, 0).runThroughHostrun(t)
			if r.Class != hostrun.ClassSuccess {
				t.Fatalf("class %s (%s), log %q", r.Class, r.Detail, r.Log)
			}
			for _, b := range r.Result {
				if (b < 0x20 && b != '\n') || b > 0x7e {
					t.Fatalf("result has raw byte %#x:\n%s", b, r.Result)
				}
			}
			doc := decodeInstalled(t, r.Result)
			if !strings.HasSuffix(doc.Text, "\nEND\t8\n") {
				t.Errorf("END record missing or wrong: %q", doc.Text[max(0, len(doc.Text)-40):])
			}
			inv := parseRun(r.Result, r.ExitCode)
			if inv.Complete || !strings.HasPrefix(inv.Reason, osdebian.ReasonMalformed+" 2") || inv.Dropped != 1 {
				t.Fatalf("complete=%v reason=%q dropped=%d\n%s", inv.Complete, inv.Reason, inv.Dropped, doc.Text)
			}
			if len(inv.Packages) != 6 {
				t.Fatalf("%d packages, want the 6 good ones", len(inv.Packages))
			}
			if k := inv.RunningKernel; k.Release != fakeRelease || k.Build != fakeBuild {
				t.Errorf("kernel record lost: %+v", k)
			}
		})
	}
}

// The kernel build string reaches the parser exactly, quotes and
// backslashes included, and an over-long one is never cut to a shorter
// valid value.
func TestPackageListInstalledKernelRecordEscaping(t *testing.T) {
	h := newInstalledHost(t, debianRows, 0)
	build := `#1 SMP "quoted" \back ` + fakeBuild
	h.file(t, "build", build)
	r := h.runThroughHostrun(t)
	if r.Class != hostrun.ClassSuccess {
		t.Fatalf("class %s (%s)", r.Class, r.Detail)
	}
	if k := parseRun(r.Result, 0).RunningKernel; k.Build != build {
		t.Errorf("build %q, want %q", k.Build, build)
	}
	h.file(t, "build", strings.Repeat("x", 1025))
	r = h.runThroughHostrun(t)
	if r.Class != hostrun.ClassSuccess {
		t.Fatalf("class %s (%s)", r.Class, r.Detail)
	}
	inv := parseRun(r.Result, 0)
	if inv.Complete || inv.RunningKernel.Build != "" || inv.RunningKernel.State != osdebian.KernelVersionUnknown {
		t.Fatalf("over-long build: complete=%v kernel %+v", inv.Complete, inv.RunningKernel)
	}
}

// A database whose list does not fit in hostrun.MaxResult still gives one
// accepted document: the records that fit, "truncated":true, no END
// record, a message on stderr, and a partial inventory.
func TestPackageListInstalledOverLimitIsTruncatedNotDropped(t *testing.T) {
	rows := typicalDebianRows(1500)
	long := strings.Repeat("v", 120)
	for i := range rows[2:] {
		r := &rows[2+i]
		r.pkg = fmt.Sprintf("very-long-binary-package-name-for-the-limit-test-%06d", i)
		r.version = "1." + long
		r.sourceVersion = "1." + long
	}
	for len(rows) < 8000 {
		rows = append(rows, rows[len(rows)%1400+2])
		rows[len(rows)-1].pkg = fmt.Sprintf("extra-binary-%06d", len(rows))
	}
	r := newInstalledHost(t, rows, 0).runThroughHostrun(t)
	if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
		t.Fatalf("class %s (%s), exit %d", r.Class, r.Detail, r.ExitCode)
	}
	t.Logf("8000 long packages: result %d bytes (limit %d)", len(r.Result), hostrun.MaxResult)
	if !strings.Contains(string(r.Log), "result limit") || !strings.Contains(string(r.Log), "truncated") {
		t.Errorf("no clear message on stderr: %q", r.Log)
	}
	doc := decodeInstalled(t, r.Result)
	if !doc.Truncated || strings.Contains(doc.Text, "\nEND\t") || !strings.Contains(doc.Text, "\nK\t"+fakeRelease+"\t") {
		t.Fatalf("truncated=%v, tail %q", doc.Truncated, doc.Text[max(0, len(doc.Text)-200):])
	}
	inv := osdebian.ParseInstalledResult(r.Result, osdebian.ReadStatus{}, vulnver.DistroDebian)
	if inv.Complete || inv.Reason != osdebian.ReasonTruncated || len(inv.Packages) < 2000 {
		t.Fatalf("complete=%v reason=%q packages=%d", inv.Complete, inv.Reason, len(inv.Packages))
	}
}

// The script's own limit is the executor's.
func TestPackageListInstalledBudgetsAgainstHostrunLimit(t *testing.T) {
	if !strings.Contains(string(packageListInstalled), "max_result="+fmt.Sprint(hostrun.MaxResult)+"\n") {
		t.Fatalf("package_list_installed.sh must budget against hostrun.MaxResult (%d)", hostrun.MaxResult)
	}
	if osdebian.MaxInstalledResult != hostrun.MaxResult {
		t.Fatalf("osdebian.MaxInstalledResult %d != hostrun.MaxResult %d", osdebian.MaxInstalledResult, hostrun.MaxResult)
	}
}
