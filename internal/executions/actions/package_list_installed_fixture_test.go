// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnver"
)

// installedFixturePath is the result of one real run of the unchanged
// package_list_installed.sh over hostrun (runThroughHostrun) on the fixed
// Debian 12 package set below. The end-to-end test in cmd/nebula-server
// reads it. This test regenerates the result on every run and compares it
// byte for byte with the file; a difference fails the test. The file is
// never written by a test.
const installedFixturePath = "testdata/package_list_installed_result.json"

// installedFixtureRows is the fixed package set of the fixture: a Debian 12
// host with the openssl source package in 3.0.14-1~deb12u1 (the version the
// fixture's feed entry lists as vulnerable, fixed in 3.0.15-1~deb12u1), a
// Go binary with a long Built-Using, the kernel image with its Built-Using,
// and one config-files leftover. Only package names and versions; no host
// names, addresses or secrets.
var installedFixtureRows = []installedRow{
	{"installed", "openssl", "amd64", "3.0.14-1~deb12u1", "openssl", "3.0.14-1~deb12u1", ""},
	{"installed", "libssl3", "amd64", "3.0.14-1~deb12u1", "openssl", "3.0.14-1~deb12u1", ""},
	{"installed", "libc6", "amd64", "2.36-9+deb12u9", "glibc", "2.36-9+deb12u9", ""},
	{"installed", "restic", "amd64", "0.14.0-1+b5", "restic", "0.14.0-1", "golang-1.19 (= 1.19.8-2), golang-github-foo (= 1.0-1)"},
	{"installed", "linux-image-6.1.0-26-amd64", "amd64", "6.1.112-1", "linux-signed-amd64", "6.1.112+1", "linux (= 6.1.112-1)"},
	{"installed", "linux-image-amd64", "amd64", "6.1.112-1", "linux-signed-amd64", "6.1.112+1", ""},
	{"config-files", "oldpkg", "amd64", "1.0-1", "oldpkg", "1.0-1", ""},
}

// TestPackageListInstalledFixtureMatchesScriptResult runs the script on the
// fixed package set and compares the result with the committed fixture.
func TestPackageListInstalledFixtureMatchesScriptResult(t *testing.T) {
	r := newInstalledHost(t, installedFixtureRows, 0).runThroughHostrun(t)
	if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
		t.Fatalf("class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
	}
	want, err := os.ReadFile(installedFixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if !bytes.Equal(r.Result, want) {
		t.Fatalf("script result differs from %s; the fixture is a real result and is not rewritten by tests\n got: %s\nwant: %s", installedFixturePath, r.Result, want)
	}
}

// TestPackageListInstalledFixtureIsCompleteDebian checks that the fixture
// is a successful, complete Debian read with the kernel mapped, so the
// end-to-end test starts from a result the server would store as complete.
func TestPackageListInstalledFixtureIsCompleteDebian(t *testing.T) {
	want, err := os.ReadFile(installedFixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	inv := osdebian.ParseInstalledResult(want, osdebian.ReadStatus{ExitCode: 0}, vulnver.DistroDebian)
	if !inv.Complete || inv.Reason != "" || inv.Dropped != 0 {
		t.Fatalf("complete=%v reason=%q dropped=%d", inv.Complete, inv.Reason, inv.Dropped)
	}
	if len(inv.Packages) != 6 {
		t.Fatalf("%d installed packages, want 6", len(inv.Packages))
	}
	if k := inv.RunningKernel; k.State != osdebian.KernelMapped || k.Release != fakeRelease {
		t.Fatalf("running kernel = %+v", k)
	}
	if doc := decodeInstalled(t, want); !strings.Contains(doc.Text, "3.0.14-1~deb12u1") {
		t.Fatalf("fixture lacks the vulnerable openssl record")
	}
}
