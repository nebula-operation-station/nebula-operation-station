// SPDX-License-Identifier: AGPL-3.0-or-later

// Package deb holds the tests of the Debian maintainer scripts. It has no
// production code; the scripts themselves ship through .goreleaser.yaml.
package deb

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	serverDropIn = "nebula-server.service.d/20-discovery.conf"
	oldDropIn    = "[Service]\nReadWritePaths=/var/lib/nebula/discovery/jobs\n"

	// executorTemplateSHA256 pins the executor drop-in template of
	// install.sh. See TestExecutorDropInTemplateIsPinned.
	executorTemplateSHA256 = "e61ae7bdc449008cdd6d9ad5e2f2e40a2608fd839b07a463e8823750e50add85"
)

// sandbox runs the real postinst with its paths moved into a temporary
// directory and the commands that need root replaced by stubs.
type sandbox struct {
	root       string
	varLib     string
	systemdDir string
	log        string
	script     string
	env        []string
}

// stubs records every call in $STUB_LOG. install creates the directory
// that is its last argument, and setpriv runs the command after --clear-groups,
// so the real effect of both stays observable without root.
const stubs = `
install|#!/bin/sh
printf 'install %s\n' "$*" >>"$STUB_LOG"
[ -n "$FAIL_INSTALL" ] && exit 1
for last; do :; done
exec mkdir -p "$last"
---
setpriv|#!/bin/sh
printf 'setpriv %s\n' "$*" >>"$STUB_LOG"
while [ "$1" != "--clear-groups" ]; do shift; done
shift
exec "$@"
---
getent|#!/bin/sh
case " $KNOWN_USERS " in *" $2 "*) exit 0;; esac
exit 2
---
useradd|#!/bin/sh
printf 'useradd %s\n' "$*" >>"$STUB_LOG"
---
systemctl|#!/bin/sh
printf 'systemctl %s\n' "$*" >>"$STUB_LOG"
if [ "$1" = daemon-reload ] && [ -f "$WATCH_FILE" ]; then
  cp "$WATCH_FILE" "$WATCH_COPY"
fi
[ "$1" != is-active ]
`

func newSandbox(t *testing.T) *sandbox {
	t.Helper()
	dir := t.TempDir()
	s := &sandbox{
		root:       dir,
		varLib:     filepath.Join(dir, "var-lib-nebula"),
		systemdDir: filepath.Join(dir, "etc-systemd-system"),
		log:        filepath.Join(dir, "calls.log"),
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, stub := range strings.Split(strings.TrimPrefix(stubs, "\n"), "---\n") {
		name, body, ok := strings.Cut(stub, "|")
		if !ok {
			t.Fatalf("malformed stub %q", stub)
		}
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	run := filepath.Join(dir, "run-systemd-system")
	if err := os.Mkdir(run, 0o755); err != nil {
		t.Fatal(err)
	}

	raw := readFile(t, "postinst")
	for _, r := range [][2]string{
		{"var_lib=/var/lib/nebula\n", "var_lib=" + s.varLib + "\n"},
		{"systemd_dir=/etc/systemd/system\n", "systemd_dir=" + s.systemdDir + "\n"},
		{"[ -d /run/systemd/system ]", "[ -d " + run + " ]"},
	} {
		if !strings.Contains(raw, r[0]) {
			t.Fatalf("postinst misses %q, which the sandbox relocates", r[0])
		}
		raw = strings.ReplaceAll(raw, r[0], r[1])
	}
	s.script = filepath.Join(dir, "postinst")
	if err := os.WriteFile(s.script, []byte(raw), 0o755); err != nil {
		t.Fatal(err)
	}
	s.env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"STUB_LOG="+s.log,
		"WATCH_FILE="+s.dropIn(),
		"WATCH_COPY="+s.dropInAtReload(),
		"KNOWN_USERS=nebula-pve-collector",
	)
	return s
}

func (s *sandbox) dropIn() string { return filepath.Join(s.systemdDir, serverDropIn) }

// dropInAtReload is the copy of the drop-in the systemctl stub takes.
func (s *sandbox) dropInAtReload() string { return filepath.Join(s.root, "at-reload.conf") }

// installed puts the sandbox into the state an older install.sh left: the
// old server drop-in and the given spool directories.
func (s *sandbox) installed(t *testing.T, dirs ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(s.dropIn()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.dropIn(), []byte(oldDropIn), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, d := range append([]string{"discovery/jobs"}, dirs...) {
		if err := os.MkdirAll(filepath.Join(s.varLib, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// run executes the postinst and fails the test unless it exits 0: a failing
// postinst leaves the package half-configured.
func (s *sandbox) run(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("sh", append([]string{s.script}, args...)...)
	cmd.Env = s.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("postinst %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func (s *sandbox) calls(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(s.log)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(raw)
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// heredoc returns the body of the here-document opened by the line that
// contains marker.
func heredoc(t *testing.T, script, marker string) string {
	t.Helper()
	_, rest, ok := strings.Cut(script, marker)
	if !ok {
		t.Fatalf("no here-document at %q", marker)
	}
	_, rest, ok = strings.Cut(rest, "\n")
	if !ok {
		t.Fatalf("here-document at %q is empty", marker)
	}
	body, _, ok := strings.Cut(rest, "\nEOF\n")
	if !ok {
		t.Fatalf("here-document at %q is not closed", marker)
	}
	return body + "\n"
}

func installScript(t *testing.T) string {
	t.Helper()
	return readFile(t, filepath.Join("..", "install.sh"))
}

// The drop-in a package upgrade leaves is byte for byte the one install.sh
// writes, so a later install.sh run sees no change and restarts nothing.
func TestUpgradeWritesServerDropInOfInstallScript(t *testing.T) {
	s := newSandbox(t)
	s.installed(t, "pve/results", "pve/guestnet", "pve/requests", "pve/live")
	s.run(t, "configure", "1.0.0")

	want := strings.ReplaceAll(heredoc(t, installScript(t), `cat > "${tmp_server_drop_in}" <<EOF`), "${var_lib}", s.varLib)
	got := readFile(t, s.dropIn())
	if got != want {
		t.Fatalf("drop-in after upgrade differs from install.sh\n got:\n%s\nwant:\n%s", got, want)
	}
	for _, d := range []string{"pve/results", "pve/guestnet"} {
		if !strings.Contains(got, "ReadWritePaths="+filepath.Join(s.varLib, d)+"\n") {
			t.Errorf("drop-in does not open %s:\n%s", d, got)
		}
	}
	fi, err := os.Stat(s.dropIn())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("drop-in mode = %o, want 644", fi.Mode().Perm())
	}
	entries, err := os.ReadDir(filepath.Dir(s.dropIn()))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("left-overs next to the drop-in: %v", entries)
	}
}

// systemd reads the drop-in at daemon-reload; written later it would not
// count at the restart the admin does next.
func TestUpgradeReloadsSystemdAfterTheDropIn(t *testing.T) {
	s := newSandbox(t)
	s.installed(t, "pve/results", "pve/guestnet", "pve/requests", "pve/live")
	s.run(t, "configure", "1.0.0")
	if got, want := readFile(t, s.dropInAtReload()), readFile(t, s.dropIn()); got != want {
		t.Fatalf("daemon-reload saw an old drop-in:\n%s", got)
	}
}

// Migrations run when the new binaries start, and the backup before that
// needs the admin (review m105): the drop-in must not cost that guarantee.
func TestUpgradeNeverRestartsServices(t *testing.T) {
	s := newSandbox(t)
	s.installed(t)
	s.run(t, "configure", "1.0.0")
	for _, line := range strings.Split(s.calls(t), "\n") {
		if strings.HasPrefix(line, "systemctl ") && !strings.Contains(line, "daemon-reload") && !strings.Contains(line, "is-active") {
			t.Errorf("unexpected call: %s", line)
		}
	}
}

// ReadWritePaths on a missing directory stops the unit with 226/NAMESPACE,
// so an upgrade from before pve/guestnet must create what the drop-in names,
// with the modes and owner of install.sh. Directories below the collector's
// pve root are made as the collector: as root, a swapped-in symlink would hand
// it the chown.
func TestUpgradeProvisionsMissingSpoolDirectories(t *testing.T) {
	spool := []string{"pve/results", "pve/guestnet", "pve/requests", "pve/live"}
	for _, existing := range spool {
		t.Run("with "+existing, func(t *testing.T) {
			s := newSandbox(t)
			s.installed(t, existing)
			s.run(t, "configure", "1.0.0")

			calls := s.calls(t)
			if strings.Contains(calls, existing) {
				t.Errorf("existing directory was touched:\n%s", calls)
			}
			for _, d := range spool {
				if d == existing {
					continue
				}
				if fi, err := os.Stat(filepath.Join(s.varLib, d)); err != nil || !fi.IsDir() {
					t.Errorf("%s not created: %v", d, err)
				}
				m := regexp.MustCompile(`install -d -m (\d+) -o nebula-pve-collector -g nebula-rpc "\$\{var_lib\}/` + d + `"`).FindStringSubmatch(installScript(t))
				if m == nil {
					t.Fatalf("install.sh does not provision %s", d)
				}
				want := fmt.Sprintf("setpriv --reuid=nebula-pve-collector --regid=nebula-rpc --clear-groups install -d -m %s %s\n", m[1], filepath.Join(s.varLib, d))
				if !strings.Contains(calls, want) {
					t.Errorf("missing call %q in:\n%s", want, calls)
				}
			}
		})
	}
}

func TestUpgradeCreatesCollectorAndSpoolRootWhenAbsent(t *testing.T) {
	s := newSandbox(t)
	s.installed(t)
	s.env = append(s.env, "KNOWN_USERS=")
	s.run(t, "configure", "1.0.0")

	calls := s.calls(t)
	want := fmt.Sprintf("useradd --system --home-dir %s --shell /usr/sbin/nologin -G nebula-rpc nebula-pve-collector\n", filepath.Join(s.varLib, "pve"))
	if !strings.Contains(calls, want) {
		t.Errorf("missing %q in:\n%s", want, calls)
	}
	want = fmt.Sprintf("install -d -m 2750 -o nebula-pve-collector -g nebula-rpc %s\n", filepath.Join(s.varLib, "pve"))
	if !strings.Contains(calls, want) {
		t.Errorf("missing %q in:\n%s", want, calls)
	}
	if !strings.Contains(installScript(t), `install -d -m 2750 -o nebula-pve-collector -g nebula-rpc "${var_lib}/pve"`) {
		t.Error("install.sh provisions the pve root differently")
	}
}

// A drop-in naming a directory that could not be made would stop the server
// at the next restart. The old drop-in only keeps the spool growing.
func TestUpgradeKeepsOldDropInWhenProvisioningFails(t *testing.T) {
	s := newSandbox(t)
	s.installed(t, "pve/results")
	s.env = append(s.env, "FAIL_INSTALL=1")
	out := s.run(t, "configure", "1.0.0")

	if got := readFile(t, s.dropIn()); got != oldDropIn {
		t.Fatalf("drop-in changed although provisioning failed:\n%s", got)
	}
	if !strings.Contains(out, "install.sh --from-package") {
		t.Fatalf("no hint to install.sh in:\n%s", out)
	}
}

// Without the drop-in the host is not configured yet: install.sh creates
// users, directories and drop-ins, and the package touches none of them.
func TestUnconfiguredHostGetsNoDropIn(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"first install", []string{"configure"}},
		{"upgrade", []string{"configure", "1.0.0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSandbox(t)
			s.run(t, tc.args...)
			if _, err := os.Stat(s.dropIn()); !os.IsNotExist(err) {
				t.Fatalf("drop-in written on an unconfigured host: %v", err)
			}
			if calls := s.calls(t); strings.Contains(calls, "install ") || strings.Contains(calls, "useradd") {
				t.Fatalf("provisioned an unconfigured host:\n%s", calls)
			}
		})
	}
}

func TestRepeatedUpgradeReportsNoChange(t *testing.T) {
	s := newSandbox(t)
	s.installed(t, "pve/results", "pve/guestnet", "pve/requests", "pve/live")
	if out := s.run(t, "configure", "1.0.0"); !strings.Contains(out, "20-discovery.conf") {
		t.Fatalf("changed drop-in not reported:\n%s", out)
	}
	if out := s.run(t, "configure", "1.0.1"); strings.Contains(out, "20-discovery.conf") {
		t.Fatalf("unchanged drop-in reported:\n%s", out)
	}
}

// The executor drop-in holds this host's admin users and RP ID, which the
// package does not know, so an upgrade leaves it alone. That only yields the
// result of install.sh while the template stays as it is: a change to it
// needs an answer for package upgrades before this hash is updated.
func TestExecutorDropInTemplateIsPinned(t *testing.T) {
	sum := sha256.Sum256([]byte(heredoc(t, installScript(t), `cat > "${tmp_drop_in}" <<EOF`)))
	if got := hex.EncodeToString(sum[:]); got != executorTemplateSHA256 {
		t.Fatalf("executor drop-in template changed (sha256 %s): the postinst does not rewrite it, so package upgrades keep the old one", got)
	}
}
