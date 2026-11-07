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
	"syscall"
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
// that is its last argument and fails when it cannot, and setpriv runs the
// command after --clear-groups, so the real effect of both stays observable
// without root. stat passes the real mode through but reports the owner and
// group from STAT_OWNERS, because the test cannot chown. chown records and
// then fails like the real one when the target is missing or FAIL_CHOWN is
// set, so a chown the postinst must not issue fails the upgrade. The service
// commands only record, so a restart through any of them is visible.
const stubs = `
install|#!/bin/sh
printf 'install %s\n' "$*" >>"$STUB_LOG"
[ -n "$FAIL_INSTALL" ] && exit 1
mode=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-m" ]; then mode="$a"; fi
  prev="$a"
done
for last; do :; done
mkdir -p "$last" || exit 1
if [ -n "$mode" ]; then chmod "$mode" "$last"; fi
exit 0
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
if [ "$1" = is-active ]; then
  [ -n "$EXECUTOR_ACTIVE" ]
else
  true
fi
---
stat|#!/bin/sh
[ -n "$REAL_STAT" ] || exit 127
out=$("$REAL_STAT" "$@") || exit 1
if [ -n "$STAT_OWNERS" ]; then
  printf '%s %s\n' "${out%% *}" "$STAT_OWNERS"
else
  printf '%s\n' "$out"
fi
---
chown|#!/bin/sh
printf 'chown %s\n' "$*" >>"$STUB_LOG"
for last; do :; done
[ -e "$last" ] || exit 1
if [ -n "$FAIL_CHOWN" ]; then exit 1; fi
exit 0
---
deb-systemd-invoke|#!/bin/sh
printf 'deb-systemd-invoke %s\n' "$*" >>"$STUB_LOG"
---
service|#!/bin/sh
printf 'service %s\n' "$*" >>"$STUB_LOG"
---
invoke-rc.d|#!/bin/sh
printf 'invoke-rc.d %s\n' "$*" >>"$STUB_LOG"
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
	realStat, err := exec.LookPath("stat")
	if err != nil {
		t.Fatal(err)
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
	raw = s.relocate(raw)
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
		"REAL_STAT="+realStat,
	)
	return s
}

func (s *sandbox) dropIn() string { return filepath.Join(s.systemdDir, serverDropIn) }

// relocate moves the absolute paths of the service commands onto the
// sandbox stubs. A postinst reaching them by absolute path, also behind a
// [ -x ... ] check, would otherwise bypass the PATH stubs and restart the
// real services on the test machine; relocated, the call is logged instead.
// The longer paths are replaced first: /usr/bin/systemctl contains
// /bin/systemctl.
func (s *sandbox) relocate(raw string) string {
	stub := func(name string) string { return filepath.Join(s.root, "bin", name) }
	for _, r := range [][2]string{
		{"/usr/bin/systemctl", stub("systemctl")},
		{"/bin/systemctl", stub("systemctl")},
		{"/usr/sbin/service", stub("service")},
		{"/usr/bin/deb-systemd-invoke", stub("deb-systemd-invoke")},
		{"/usr/sbin/invoke-rc.d", stub("invoke-rc.d")},
	} {
		raw = strings.ReplaceAll(raw, r[0], r[1])
	}
	return raw
}

// requireStub fails unless the sandbox's PATH intercepts name: the sandbox
// bin directory comes first, so without the stub a call from the postinst
// would reach the real command and escape the test.
func (s *sandbox) requireStub(t *testing.T, name string) {
	t.Helper()
	stub := filepath.Join(s.root, "bin", name)
	if fi, err := os.Stat(stub); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("no sandbox stub for %s: a call through it would escape the test", name)
	}
}

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

// octalMode formats a directory mode the way `stat -c %a` does, with the
// setgid bit shown as a leading 2, so it can be compared with the modes the
// postinst provisions. fi.Mode().Perm() alone would hide the setgid bit.
func octalMode(fi os.FileInfo) string {
	perm := fi.Mode().Perm()
	if fi.Mode()&os.ModeSetgid != 0 {
		return fmt.Sprintf("2%03o", perm)
	}
	return fmt.Sprintf("%03o", perm)
}

// spoolMode is the mode install.sh gives each pve spool directory.
func spoolMode(dir string) (os.FileMode, bool) {
	switch dir {
	case "pve/results", "pve/guestnet", "pve/requests":
		return 0o2770, true
	case "pve/live":
		return 0o2750, true
	}
	return 0, false
}

// mkdirAt creates a directory at an exact mode, setgid included. os.Chmod
// would drop the setgid bit (it applies mode.Perm()), so it uses fchmod,
// like the coreutils install the postinst runs.
func (s *sandbox) mkdirAt(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(s.varLib, dir)
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Fchmod(int(f.Fd()), uint32(mode)); err != nil {
		t.Fatal(err)
	}
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
// needs the admin (review m105): the postinst must never restart the
// services. With the executor running it reaches the running-services branch
// and must tell the admin to back up and restart instead; with it stopped it
// stays quiet. Both branches are pinned, so a restart added in either is
// caught. The stubbed systemctl is not the only restart path:
// deb-systemd-invoke, service and invoke-rc.d all reach systemd, so calls
// through any of them are caught as well.
func TestUpgradeNeverRestartsServices(t *testing.T) {
	for _, tc := range []struct {
		name       string
		active     bool
		wantNotice bool
	}{
		{"executor stopped", false, false},
		{"executor running", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSandbox(t)
			for _, name := range []string{"systemctl", "deb-systemd-invoke", "service", "invoke-rc.d"} {
				s.requireStub(t, name)
			}
			s.installed(t)
			if tc.active {
				s.env = append(s.env, "EXECUTOR_ACTIVE=1")
			}
			out := s.run(t, "configure", "1.0.0")
			for _, line := range strings.Split(s.calls(t), "\n") {
				switch {
				case strings.HasPrefix(line, "systemctl "):
					if !strings.Contains(line, "daemon-reload") && !strings.Contains(line, "is-active") {
						t.Errorf("unexpected call: %s", line)
					}
				case strings.HasPrefix(line, "deb-systemd-invoke "),
					strings.HasPrefix(line, "service "),
					strings.HasPrefix(line, "invoke-rc.d "):
					// These reach systemd like systemctl: a postinst using any
					// of them would restart the services before the admin's
					// backup (review m105).
					t.Errorf("unexpected call: %s", line)
				}
			}
			if got := strings.Contains(out, "back up, then restart"); got != tc.wantNotice {
				t.Errorf("admin notice present = %v, want %v:\n%s", got, tc.wantNotice, out)
			}
		})
	}
}

// An absolute path to a service command would bypass the PATH stubs and
// restart the real services on the test machine, with no log line; the
// sandbox relocates it onto the stub, so the call is logged and the real
// command never runs. The restart is hidden behind a [ -x ... ] check, the
// way a regression would hide it.
func TestSandboxRelocatesAbsoluteServicePaths(t *testing.T) {
	s := newSandbox(t)
	s.installed(t)
	s.env = append(s.env, "EXECUTOR_ACTIVE=1")
	raw := readFile(t, s.script)
	if !strings.HasSuffix(raw, "exit 0\n") {
		t.Fatalf("postinst no longer ends with exit 0; the test appends before it")
	}
	raw = strings.TrimSuffix(raw, "exit 0\n") + `
if [ -x /usr/sbin/invoke-rc.d ]; then
  /usr/sbin/invoke-rc.d nebula-server restart
fi
exit 0
`
	if err := os.WriteFile(s.script, []byte(s.relocate(raw)), 0o755); err != nil {
		t.Fatal(err)
	}
	s.run(t, "configure", "1.0.0")
	if !strings.Contains(s.calls(t), "invoke-rc.d nebula-server restart") {
		t.Fatalf("absolute-path restart not caught by the sandbox:\n%s", s.calls(t))
	}
}

// ReadWritePaths on a missing directory stops the unit with 226/NAMESPACE,
// so an upgrade from before pve/guestnet must create what the drop-in names,
// with the modes and owner of install.sh. Directories below the collector's
// pve root are made as the collector: as root, a swapped-in symlink would hand
// it the chown. A directory that already has install.sh's mode is left alone.
func TestUpgradeProvisionsMissingSpoolDirectories(t *testing.T) {
	spool := []string{"pve/results", "pve/guestnet", "pve/requests", "pve/live"}
	for _, existing := range spool {
		t.Run("with "+existing, func(t *testing.T) {
			s := newSandbox(t)
			s.installed(t)
			mode, _ := spoolMode(existing)
			s.mkdirAt(t, existing, mode)
			// The existing directory is in install.sh's state, owner included:
			// the test cannot chown, so the stat stub reports it.
			s.env = append(s.env, "STAT_OWNERS=nebula-pve-collector nebula-rpc")
			s.run(t, "configure", "1.0.0")

			calls := s.calls(t)
			if strings.Contains(calls, existing) {
				t.Errorf("existing directory was touched:\n%s", calls)
			}
			// No directory has a wrong owner here: the existing one is in
			// install.sh's state, the rest are absent. A chown would hit a
			// missing path and fail the upgrade on a real host.
			if strings.Contains(calls, "chown ") {
				t.Errorf("chown called although no directory has a wrong owner:\n%s", calls)
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

// A package-upgraded host whose collector created a spool directory under
// UMask=0077 left it without the setgid/group bits the server needs
// (RestrictSUIDSGID keeps the collector from fixing it, so install.sh creates
// them with their final mode). install.sh's install -d -m re-applies the mode
// of an existing directory; the postinst must do the same, so the upgraded
// server can list and unlink what it imported. The repair runs as the
// collector, so a symlink swapped in below the pve root cannot redirect it.
func TestUpgradeRepairsSpoolDirectoryModes(t *testing.T) {
	for _, tc := range []struct {
		dir   string
		wrong os.FileMode
		want  string
	}{
		{"pve/guestnet", 0o0700, "2770"},
		{"pve/results", 0o2700, "2770"},
		{"pve/live", 0o0750, "2750"},
	} {
		t.Run(tc.dir, func(t *testing.T) {
			s := newSandbox(t)
			s.installed(t)
			s.mkdirAt(t, tc.dir, tc.wrong)
			// Only the mode is wrong here: the stat stub reports
			// install.sh's owner and group, which the test cannot set.
			s.env = append(s.env, "STAT_OWNERS=nebula-pve-collector nebula-rpc")
			s.run(t, "configure", "1.0.0")

			fi, err := os.Stat(filepath.Join(s.varLib, tc.dir))
			if err != nil {
				t.Fatal(err)
			}
			if got := octalMode(fi); got != tc.want {
				t.Errorf("%s mode = %s, want %s", tc.dir, got, tc.want)
			}
			// Only the mode is wrong: the collector can chmod its own
			// directory, so root must not chown it.
			if strings.Contains(s.calls(t), "chown ") {
				t.Errorf("chown called although only the mode is wrong:\n%s", s.calls(t))
			}
			want := fmt.Sprintf("setpriv --reuid=nebula-pve-collector --regid=nebula-rpc --clear-groups install -d -m %s %s\n", tc.want, filepath.Join(s.varLib, tc.dir))
			if !strings.Contains(s.calls(t), want) {
				t.Errorf("missing repair call %q in:\n%s", want, s.calls(t))
			}
		})
	}
}

// install.sh re-applies the mode, owner and group of every spool directory
// on every run; the postinst must converge to the same state, so a
// directory with the right mode but the wrong owner or group is repaired,
// not skipped. The pve root is re-applied as root, like install.sh. Below
// it the owner and group are fixed as root with chown --no-dereference, so
// a symlink swapped in there cannot redirect them to its target, and the
// collector re-applies the mode after. The test cannot chown, so it checks
// the recorded calls and re-reads the mode from disk.
func TestUpgradeRepairsSpoolOwnership(t *testing.T) {
	for _, tc := range []struct {
		name    string
		dir     string
		mode    os.FileMode
		modeStr string
		owners  string
		// want is the call that must appear in the log; nil means the
		// directory must not be touched at all.
		want func(s *sandbox) string
	}{
		{
			name:    "pve root with wrong mode",
			dir:     "pve",
			mode:    0o0755,
			modeStr: "2750",
			owners:  "nebula-pve-collector nebula-rpc",
			want: func(s *sandbox) string {
				return fmt.Sprintf("install -d -m 2750 -o nebula-pve-collector -g nebula-rpc %s\n", filepath.Join(s.varLib, "pve"))
			},
		},
		{
			name:    "pve root with wrong owner",
			dir:     "pve",
			mode:    0o2750,
			modeStr: "2750",
			owners:  "root root",
			want: func(s *sandbox) string {
				return fmt.Sprintf("install -d -m 2750 -o nebula-pve-collector -g nebula-rpc %s\n", filepath.Join(s.varLib, "pve"))
			},
		},
		{
			name:    "pve root with wrong group",
			dir:     "pve",
			mode:    0o2750,
			modeStr: "2750",
			owners:  "nebula-pve-collector root",
			want: func(s *sandbox) string {
				return fmt.Sprintf("install -d -m 2750 -o nebula-pve-collector -g nebula-rpc %s\n", filepath.Join(s.varLib, "pve"))
			},
		},
		{
			name:    "pve root in install.sh's state",
			dir:     "pve",
			mode:    0o2750,
			modeStr: "2750",
			owners:  "nebula-pve-collector nebula-rpc",
			want:    nil,
		},
		{
			name:    "subdirectory with wrong owner",
			dir:     "pve/results",
			mode:    0o2770,
			modeStr: "2770",
			owners:  "root root",
			want: func(s *sandbox) string {
				return fmt.Sprintf("chown --no-dereference nebula-pve-collector:nebula-rpc %s\n", filepath.Join(s.varLib, "pve/results"))
			},
		},
		{
			name:    "subdirectory with wrong group",
			dir:     "pve/results",
			mode:    0o2770,
			modeStr: "2770",
			owners:  "nebula-pve-collector root",
			want: func(s *sandbox) string {
				return fmt.Sprintf("chown --no-dereference nebula-pve-collector:nebula-rpc %s\n", filepath.Join(s.varLib, "pve/results"))
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSandbox(t)
			s.installed(t)
			s.mkdirAt(t, tc.dir, tc.mode)
			s.env = append(s.env, "STAT_OWNERS="+tc.owners)
			s.run(t, "configure", "1.0.0")

			calls := s.calls(t)
			if tc.want == nil {
				if strings.Contains(calls, filepath.Join(s.varLib, tc.dir)+"\n") {
					t.Errorf("directory in install.sh's state was touched:\n%s", calls)
				}
				return
			}
			if !strings.Contains(calls, tc.want(s)) {
				t.Errorf("missing repair call %q in:\n%s", tc.want(s), calls)
			}
			if tc.dir != "pve" {
				// The chown must precede the collector's mode re-apply: while
				// the directory is not the collector's, the collector cannot
				// chmod it.
				installCall := fmt.Sprintf("setpriv --reuid=nebula-pve-collector --regid=nebula-rpc --clear-groups install -d -m %s %s\n", tc.modeStr, filepath.Join(s.varLib, tc.dir))
				chownIdx, installIdx := strings.Index(calls, tc.want(s)), strings.Index(calls, installCall)
				if chownIdx < 0 || installIdx < 0 || chownIdx > installIdx {
					t.Errorf("chown must precede the collector's mode re-apply:\n%s", calls)
				}
			}
			// Re-read the mode from disk: the stub install applies it, so the
			// repair's result is observable.
			fi, err := os.Stat(filepath.Join(s.varLib, tc.dir))
			if err != nil {
				t.Fatal(err)
			}
			if got := octalMode(fi); got != tc.modeStr {
				t.Errorf("%s mode = %s, want %s", tc.dir, got, tc.modeStr)
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

// A chown that fails (the owner is wrong and root cannot fix it) must not
// refresh the drop-in: the new drop-in would name a directory the server
// cannot list or unlink. The old drop-in only keeps the spool growing, and
// the admin is pointed to install.sh.
func TestUpgradeKeepsOldDropInWhenChownFails(t *testing.T) {
	s := newSandbox(t)
	s.installed(t, "pve/results")
	s.mkdirAt(t, "pve/results", 0o2770)
	s.env = append(s.env, "STAT_OWNERS=root root", "FAIL_CHOWN=1")
	out := s.run(t, "configure", "1.0.0")

	want := "chown --no-dereference nebula-pve-collector:nebula-rpc " + filepath.Join(s.varLib, "pve/results") + "\n"
	if !strings.Contains(s.calls(t), want) {
		t.Fatalf("chown not attempted for the wrong owner:\n%s", s.calls(t))
	}
	if got := readFile(t, s.dropIn()); got != oldDropIn {
		t.Fatalf("drop-in changed although chown failed:\n%s", got)
	}
	if !strings.Contains(out, "install.sh --from-package") {
		t.Fatalf("no hint to install.sh in:\n%s", out)
	}
}

// A file or symlink swapped in at the pve root or a spool path is not a
// directory the spool can use, and touching it could hand its target to the
// collector: install -d follows a symlink and would re-apply the mode to
// its target, install -d -o would re-own it, and a chown without
// --no-dereference would follow it. The swapped-in object is left alone,
// link and target, and the upgrade keeps the old drop-in and points the
// admin to install.sh. A link to a directory that already has install.sh's
// state is refused the same way: the state check follows the link, so the
// link check must come first.
func TestUpgradeLeavesANonDirectorySpoolPathAlone(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		link bool
		// targetInState puts the symlink target in install.sh's state, so
		// only the link check can stop the postinst from accepting it.
		targetInState bool
	}{
		{"file at pve root", "pve", false, false},
		{"symlink at pve root", "pve", true, false},
		{"symlink at pve root to a directory in install.sh's state", "pve", true, true},
		{"file at pve/results", "pve/results", false, false},
		{"symlink at pve/results", "pve/results", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSandbox(t)
			s.installed(t)
			path := filepath.Join(s.varLib, tc.path)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			var target string
			if tc.link {
				target = filepath.Join(s.varLib, "target")
				if tc.targetInState {
					s.mkdirAt(t, "target", 0o2750)
					s.env = append(s.env, "STAT_OWNERS=nebula-pve-collector nebula-rpc")
				} else {
					if err := os.MkdirAll(target, 0o755); err != nil {
						t.Fatal(err)
					}
					s.env = append(s.env, "STAT_OWNERS=root root")
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			} else {
				s.env = append(s.env, "STAT_OWNERS=root root")
				if err := os.WriteFile(path, []byte("swapped in"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			out := s.run(t, "configure", "1.0.0")

			calls := s.calls(t)
			if strings.Contains(calls, "chown ") {
				t.Errorf("non-directory spool path was chowned:\n%s", calls)
			}
			if strings.Contains(calls, path+"\n") {
				t.Errorf("install ran on the swapped-in path:\n%s", calls)
			}
			if got := readFile(t, s.dropIn()); got != oldDropIn {
				t.Errorf("drop-in changed although the spool path is not a directory:\n%s", got)
			}
			if !strings.Contains(out, "install.sh --from-package") {
				t.Errorf("no hint to install.sh in:\n%s", out)
			}
			if tc.link {
				fi, err := os.Stat(target)
				if err != nil {
					t.Fatal(err)
				}
				want := "755"
				if tc.targetInState {
					want = "2750"
				}
				if got := octalMode(fi); got != want {
					t.Errorf("symlink target mode = %s, want %s: the target must stay unchanged", got, want)
				}
				entries, err := os.ReadDir(target)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 0 {
					t.Errorf("symlink target was written: %v", entries)
				}
			} else if got, err := os.ReadFile(path); err != nil || string(got) != "swapped in" {
				t.Errorf("swapped-in file changed: %q, %v", got, err)
			}
		})
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
