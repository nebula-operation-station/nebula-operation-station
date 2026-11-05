// SPDX-License-Identifier: AGPL-3.0-or-later

package hostrun

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The check script against a fake process tree, so the owner filter, the
// kernel-thread skip, the process limit and the capability skip are
// covered on every machine. The tree is built here in Go; the check
// itself runs unchanged, with its own process linked in from the real
// /proc (same PID, so its self check still has to find itself).

const procTestID = "0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1aff"

// Capability sets for fake processes. CapPrm bit 62 is no capability any
// kernel defines, so the check (whatever it runs with) never holds it.
const (
	capsNone  = "0000000000000000"
	capsExtra = "4000000000000000"
)

// pfKthread is PF_KTHREAD in /proc/<pid>/stat field 9.
const pfKthread = 0x200000

type fakeProc struct {
	cmdline string // NUL-separated
	environ string // NUL-separated
	ppid    int
	flags   int
	name    string
	capPrm  string
	// foreign: owned by another user (environ not owned by the caller).
	foreign bool
	// environDir, cmdlineDir, statDir: the file is a directory, so
	// reading it fails while the process entry exists.
	environDir, cmdlineDir, statDir bool
	// gone: the entry is empty, like a process that exited mid-scan.
	gone bool
}

var systemdUser = fakeProc{cmdline: "/usr/lib/systemd/systemd\x00--user\x00", environDir: true, ppid: 1, name: "systemd", capPrm: capsExtra}

func writeProc(t *testing.T, root string, pid int, p fakeProc) {
	t.Helper()
	d := filepath.Join(root, strconv.Itoa(pid))
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if p.gone {
		return
	}
	file := func(name, body string, dir bool) {
		f := filepath.Join(d, name)
		var err error
		if dir {
			err = os.Mkdir(f, 0o755)
		} else {
			err = os.WriteFile(f, []byte(body), 0o644)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	name := p.name
	if name == "" {
		name = "x"
	}
	if p.capPrm == "" {
		p.capPrm = capsNone
	}
	file("cmdline", p.cmdline, p.cmdlineDir)
	file("stat", fmt.Sprintf("%d (%s) S %d %d %d 0 -1 %d 0 0 0 0 1 1 0 0 20 0 1 0\n", pid, name, p.ppid, pid, pid, p.flags), p.statDir)
	file("status", fmt.Sprintf("Name:\t%s\nUmask:\t0022\nState:\tS (sleeping)\nPid:\t%d\nPPid:\t%d\nCapInh:\t%s\nCapPrm:\t%s\nCapEff:\t%s\n",
		name, pid, p.ppid, capsNone, p.capPrm, p.capPrm), false)
	if p.foreign {
		if os.Geteuid() == 0 {
			// As root, hand the file to another user.
			file("environ", p.environ, false)
			if err := os.Lchown(filepath.Join(d, "environ"), 65534, 65534); err != nil {
				t.Fatal(err)
			}
			return
		}
		// Otherwise point it at a file root owns.
		if err := os.Symlink("/", filepath.Join(d, "environ")); err != nil {
			t.Fatal(err)
		}
		return
	}
	file("environ", p.environ, p.environDir)
}

// runFakeProc runs the check over a fake tree holding procs and returns
// its exit status. The shell links its own /proc entry into the tree and
// then execs the check with the same PID.
func runFakeProc(t *testing.T, procs map[int]fakeProc, maxProcs int) int {
	t.Helper()
	root := t.TempDir()
	for pid, p := range procs {
		writeProc(t, root, pid, p)
	}
	script, err := visibleCheck(procTestID, root, maxProcs)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", `ln -s "/proc/$$" "$1/$$" && exec /bin/sh -c "$2"`, "sh", root, script)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	err = cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		if out.String() != visibleNone+"\n" || stderr.Len() > 0 {
			t.Fatalf("exit 0 with stdout %q stderr %q", out.String(), stderr.String())
		}
		return 0
	case errors.As(err, &ee):
		return ee.ExitCode()
	}
	t.Fatalf("run: %v (stderr %q)", err, stderr.String())
	return -1
}

func TestVisibleCheckFakeProc(t *testing.T) {
	marker := "NEBULA_EXECUTION_ID=" + procTestID
	plain := fakeProc{cmdline: "/bin/sleep\x0010\x00", environ: "HOME=/x\x00", ppid: 1}
	chain := func(n int) map[int]fakeProc {
		// systemd --user at 1000 below n plain ancestors 1001..1000+n,
		// the last one a child of init.
		m := map[int]fakeProc{1: {cmdline: "/sbin/init\x00", foreign: true}}
		sd := systemdUser
		sd.ppid = 1001
		m[1000] = sd
		for i := 1; i <= n; i++ {
			p := plain
			p.foreign = true
			p.ppid = 1000 + i + 1
			if i == n {
				p.ppid = 1
			}
			m[1000+i] = p
		}
		return m
	}
	with := func(p fakeProc, f func(*fakeProc)) fakeProc { f(&p); return p }

	for name, tc := range map[string]struct {
		procs    map[int]fakeProc
		maxProcs int
		want     int
	}{
		"only itself":              {procs: map[int]fakeProc{}, want: 0},
		"unrelated own process":    {procs: map[int]fakeProc{100: plain}, want: 0},
		"ID on an own cmdline":     {procs: map[int]fakeProc{100: with(plain, func(p *fakeProc) { p.cmdline = "sh\x00-c\x00" + marker + " x\x00" })}, want: 1},
		"ID in an own environment": {procs: map[int]fakeProc{100: with(plain, func(p *fakeProc) { p.environ = "A=1\x00" + marker + "\x00" })}, want: 1},
		// test -O: another user's process cannot keep the target held.
		"ID on another user's cmdline": {procs: map[int]fakeProc{100: with(plain, func(p *fakeProc) {
			p.cmdline = "sh\x00-c\x00" + marker + "\x00"
			p.foreign = true
		})}, want: 0},
		"process gone mid-scan":       {procs: map[int]fakeProc{100: {gone: true}}, want: 0},
		"unreadable cmdline, alive":   {procs: map[int]fakeProc{100: with(plain, func(p *fakeProc) { p.cmdlineDir = true })}, want: 3},
		"unreadable stat, alive":      {procs: map[int]fakeProc{100: with(plain, func(p *fakeProc) { p.statDir = true })}, want: 3},
		"unreadable environ, alive":   {procs: map[int]fakeProc{100: with(plain, func(p *fakeProc) { p.environDir = true })}, want: 3},
		"unreadable environ, no caps": {procs: map[int]fakeProc{1: {cmdline: "/sbin/init\x00", foreign: true}, 100: with(systemdUser, func(p *fakeProc) { p.capPrm = capsNone })}, want: 3},
		// The capability skip covers systemd --user only.
		"extra caps, not systemd": {procs: map[int]fakeProc{100: with(plain, func(p *fakeProc) {
			p.environDir, p.capPrm = true, capsExtra
		})}, want: 3},
		"systemd --user":          {procs: map[int]fakeProc{1: {cmdline: "/sbin/init\x00", foreign: true}, 100: systemdUser}, want: 0},
		"systemd --user from lib": {procs: map[int]fakeProc{1: {cmdline: "/sbin/init\x00", foreign: true}, 100: with(systemdUser, func(p *fakeProc) { p.cmdline = "/lib/systemd/systemd\x00--user\x00" })}, want: 0},
		"systemd, other arguments": {procs: map[int]fakeProc{1: {cmdline: "/sbin/init\x00", foreign: true}, 100: with(systemdUser, func(p *fakeProc) {
			p.cmdline = "/usr/lib/systemd/systemd\x00--user\x00--unit=x\x00"
		})}, want: 3},
		"systemd, other path": {procs: map[int]fakeProc{1: {cmdline: "/sbin/init\x00", foreign: true}, 100: with(systemdUser, func(p *fakeProc) {
			p.cmdline = "/tmp/systemd\x00--user\x00"
		})}, want: 3},
		"systemd --user cmdline, other comm": {procs: map[int]fakeProc{1: {cmdline: "/sbin/init\x00", foreign: true}, 100: with(systemdUser, func(p *fakeProc) {
			p.name = "evil"
		})}, want: 3},
		// The parent chain: an imitation below the run's shell is seen.
		"systemd --user below the run's shell": {procs: map[int]fakeProc{
			1:   {cmdline: "/sbin/init\x00", foreign: true},
			100: with(systemdUser, func(p *fakeProc) { p.ppid = 200 }),
			200: with(plain, func(p *fakeProc) { p.cmdline = "sh\x00-c\x00" + marker + "\x00"; p.foreign = true; p.ppid = 1 }),
		}, want: 1},
		"systemd --user, parent gone": {procs: map[int]fakeProc{
			100: with(systemdUser, func(p *fakeProc) { p.ppid = 200 }),
		}, want: 3},
		"systemd --user, parent cmdline unreadable": {procs: map[int]fakeProc{
			100: with(systemdUser, func(p *fakeProc) { p.ppid = 200 }),
			200: with(plain, func(p *fakeProc) { p.cmdlineDir = true; p.foreign = true }),
		}, want: 3},
		"chain at the depth limit":     {procs: chain(visibleMaxDepth), want: 0},
		"chain beyond the depth limit": {procs: chain(visibleMaxDepth + 1), want: 3},
		// Kernel threads are skipped before anything is read and do not
		// count; an unreadable environ shows they were not read.
		"kernel thread": {procs: map[int]fakeProc{2: {environDir: true, flags: pfKthread}, 3: {environDir: true, ppid: 2, flags: pfKthread | 0x40}}, maxProcs: 1, want: 0},
		// The process limit (the check itself counts).
		"at the process limit":     {procs: map[int]fakeProc{100: plain, 101: plain}, maxProcs: 3, want: 0},
		"beyond the process limit": {procs: map[int]fakeProc{100: plain, 101: plain, 102: plain}, maxProcs: 3, want: 3},
		"other users do not count": {procs: map[int]fakeProc{100: plain, 101: plain, 102: with(plain, func(p *fakeProc) { p.foreign = true })}, maxProcs: 3, want: 0},
	} {
		t.Run(name, func(t *testing.T) {
			maxProcs := tc.maxProcs
			if maxProcs == 0 {
				maxProcs = visibleMaxProcs
			}
			if got := runFakeProc(t, tc.procs, maxProcs); got != tc.want {
				t.Fatalf("exit %d, want %d", got, tc.want)
			}
		})
	}
}

// Production scans the real /proc with the fixed limits.
func TestVisibleCommandUsesProc(t *testing.T) {
	cmd, err := visibleCommand(procTestID)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := visibleCheck(procTestID, "/proc", visibleMaxProcs)
	if cmd != "exec /bin/sh -c "+shellQuote(want) || !strings.Contains(want, "\nr='/proc'\n") ||
		!strings.Contains(want, `[ "$n" -gt 4096 ]`) || !strings.Contains(want, `[ "$i" -gt 64 ]`) {
		t.Fatalf("command %q", cmd)
	}
	if _, err := visibleCheck("not-a-uuid", "/proc", 1); err == nil {
		t.Fatal("invalid execution ID accepted")
	}
}
