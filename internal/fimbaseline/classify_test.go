// SPDX-License-Identifier: AGPL-3.0-or-later

package fimbaseline

import (
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
)

// stubSSH is a derived SSH set given as exact paths.
type stubSSH struct{ files, positions map[string]bool }

func (s stubSSH) Match(p []byte) SSHMatch {
	switch {
	case s.files[string(p)]:
		return SSHFile
	case s.positions[string(p)]:
		return SSHPosition
	}
	return SSHNone
}

// usable returns options with a usable, empty derived SSH set.
func usable() Options { return Options{SSH: stubSSH{}} }

func TestFixedCriticalPaths(t *testing.T) {
	critical := []string{
		// authorized_keys anywhere, SSH login files by fixed path.
		"/root/.ssh/authorized_keys", "/home/alice/.ssh/authorized_keys2",
		"/home/alice/.ssh/authorized_keys.bak", "/etc/ssh/authorized_keys_extra",
		"/var/lib/svc/.ssh/authorized_keys",
		"/etc/hosts.equiv", "/etc/ssh/shosts.equiv", "/root/.shosts", "/home/bob/.rhosts",
		"/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2",
		"/root/.ssh/known_hosts", "/home/bob/.ssh/known_hosts2", "/home/bob/.k5login",
		"/etc/krb5.keytab", "/etc/krb5.conf",
		"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/nsswitch.conf",
		// sudoers, PAM, sshd configuration, preload.
		"/etc/sudoers", "/etc/sudoers.d", "/etc/sudoers.d/admins",
		"/etc/pam.d", "/etc/pam.d/sshd", "/etc/security/limits.conf",
		"/usr/lib/x86_64-linux-gnu/security/pam_unix.so",
		"/etc/ssh/sshd_config", "/etc/default/ssh", "/etc/ld.so.preload",
		// systemd unit roots.
		"/etc/systemd/system/foo.service", "/etc/systemd/system/timers.target.wants/x.timer",
		"/usr/lib/systemd/system/cron.service", "/etc/systemd/user/u.service",
		// sshd units in every search path.
		"/usr/local/lib/systemd/system/ssh.service.d/opts.conf",
		"/usr/local/lib/systemd/system/ssh.service",
		"/usr/local/lib/systemd/system/multi-user.target.wants/sshd.service",
		"/usr/local/lib/systemd/system/service.d", "/usr/local/lib/systemd/system/socket.d/x.conf",
		"/usr/local/lib/systemd/system/sshd@x.service.d/y.conf",
		"/lib/systemd/system/ssh.socket", "/etc/systemd/system.control/sshd.socket",
		"/etc/systemd/system.attached/ssh@.service",
		// Crontabs.
		"/etc/crontab", "/etc/cron.d", "/etc/cron.d/backup", "/etc/cron.daily/logrotate",
		"/var/spool/cron/crontabs/root",
		// /boot, sshd and helpers, sudo, su, loader.
		"/boot", "/boot/grub/grub.cfg", "/boot/vmlinuz-6.1.0", "/boot/efi/EFI/debian/shimx64.efi",
		"/usr/sbin/sshd", "/usr/lib/openssh/sftp-server",
		"/usr/bin/sudo", "/usr/bin/su", "/bin/su",
		"/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2",
	}
	normal := []string{
		"/etc/hosts", "/etc/motd", "/etc/ssh/ssh_config", "/etc/ssh",
		"/etc/systemd/journald.conf", "/etc/apt/sources.list",
		"/usr/bin/ls", "/usr/lib/x86_64-linux-gnu/libc.so.6",
		"/usr/local/lib/systemd/system/foo.service",
		"/usr/local/lib/systemd/system/multi-user.target.wants/foo.service",
		"/etc/sudoers.bak", "/etc/pam.conf.d", "/etc/cronjob", "/opt/app/bin/run",
		"/usr/lib/x86_64-linux-gnu/pam_misc.so.0", "/bootstrap",
		"/home/alice/.ssh/config", "/usr/local/bin/sudo-wrapper",
	}
	for _, p := range critical {
		if !fixedCritical(p) {
			t.Errorf("%s: not critical", p)
		}
	}
	for _, p := range normal {
		if fixedCritical(p) {
			t.Errorf("%s: critical", p)
		}
	}
}

func TestClassifyRules(t *testing.T) {
	setuid := file("/opt/app/helper", 1)
	setuid.Mode = 0o4755
	setgid := file("/opt/app/helper", 1)
	setgid.Mode = 0o2755
	plain := file("/opt/app/helper", 1)
	ls := file("/usr/bin/ls", 1)
	localLs := file("/usr/local/bin/ls", 1)
	localTool := file("/usr/local/bin/mytool", 1)
	homeLink := symlink("/home/alice/.ssh", "/srv/dot")
	rootLink := symlink("/root", "/srv/root")
	etcLink := symlink("/etc/ssh", "/srv/ssh")
	optLink := symlink("/opt/app", "/srv/app")
	// Outside the fixed trees, so only the SSH position rule applies.
	wantsLink := symlink("/usr/local/lib/systemd/system/multi-user.target.wants", "/srv/wants")
	requiresLink := symlink("/etc/systemd/system.control/x.requires", "/srv/req")
	unitWantsLink := symlink("/lib/systemd/system/graphical.target.wants", "/srv/gwants")
	homeUserLink := symlink("/home/bob", "/srv/bob")
	homeUserSSHLink := symlink("/home/bob/.ssh", "/srv/bobssh")
	homeProjectLink := symlink("/home/bob/projects", "/srv/projects")
	usrLink := symlink("/usr", "/srv/usr")
	derived := file("/etc/ssh/sshd_config.d/10.conf", 1)
	akDir := dir("/srv/keys")
	akDirLink := symlink("/srv/keys", "/data/keys")
	ssh := Options{SSH: stubSSH{
		files:     map[string]bool{"/etc/ssh/sshd_config.d/10.conf": true},
		positions: map[string]bool{"/srv/keys": true},
	}}
	tests := []struct {
		name      string
		baseline  []fimscan.Record // also feeds the shadow set
		old, cur  *fimscan.Record
		opts      Options
		wantClass Class
		wantRules Rule
	}{
		{"plain file", nil, &plain, &plain, usable(), ClassNormal, 0},
		{"setuid after", nil, &plain, &setuid, usable(), ClassCritical, RuleSetID},
		{"setuid before", nil, &setuid, &plain, usable(), ClassCritical, RuleSetID},
		{"setgid new file", nil, nil, &setgid, usable(), ClassCritical, RuleSetID},
		{"shadowing command", []fimscan.Record{ls}, nil, &localLs, usable(), ClassCritical, RuleShadow},
		{"shadowed command itself", []fimscan.Record{ls}, &ls, &ls, usable(), ClassNormal, 0},
		{"not shadowing", []fimscan.Record{ls}, nil, &localTool, usable(), ClassNormal, 0},
		{"symlink home .ssh", nil, nil, &homeLink, usable(), ClassCritical, RuleSSHSymlink},
		{"symlink /root", nil, &rootLink, nil, usable(), ClassCritical, RuleSSHSymlink},
		{"symlink /etc/ssh", nil, nil, &etcLink, usable(), ClassCritical, RuleSSHSymlink},
		{"symlink elsewhere", nil, nil, &optLink, usable(), ClassNormal, 0},
		{"symlink /usr", nil, nil, &usrLink, usable(), ClassCritical, RuleSSHSymlink},
		{"symlink *.wants in local unit path", nil, nil, &wantsLink, usable(), ClassCritical, RuleSSHSymlink},
		{"symlink *.requires in control unit path", nil, nil, &requiresLink, usable(), ClassCritical, RuleSSHSymlink},
		{"symlink *.wants in lib unit path", nil, nil, &unitWantsLink, usable(), ClassCritical, RuleSSHSymlink},
		{"symlink home user", nil, nil, &homeUserLink, usable(), ClassCritical, RuleSSHSymlink},
		{"symlink home user .ssh", nil, nil, &homeUserSSHLink, usable(), ClassCritical, RuleSSHSymlink},
		{"symlink home project dir", nil, nil, &homeProjectLink, usable(), ClassNormal, 0},
		{"derived include", nil, nil, &derived, ssh, ClassCritical, RuleSSHDerived},
		{"derived position dir", nil, &akDir, &akDir, ssh, ClassNormal, 0},
		{"derived position symlink", nil, &akDir, &akDirLink, ssh, ClassCritical, RuleSSHSymlink},
		{"no derived set", nil, &plain, &plain, Options{}, ClassCritical, RuleUnclassifiable},
		{"no derived set and fixed", nil, nil, ptr(file("/etc/passwd", 1)), Options{}, ClassCritical, RuleFixedPath | RuleUnclassifiable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cl := newClassifier(tc.baseline, nil, tc.opts)
			p := tc.cur
			if p == nil {
				p = tc.old
			}
			c, r := cl.classify(p.Path, tc.old, tc.cur)
			if c != tc.wantClass || r != tc.wantRules {
				t.Fatalf("got %v/%b, want %v/%b", c, r, tc.wantClass, tc.wantRules)
			}
		})
	}
}

func TestShadowFromScanSide(t *testing.T) {
	// A command that only the scan has still makes a /usr/local twin
	// critical (union of baseline and run, D7 (c)).
	cl := newClassifier(nil, []fimscan.Record{file("/usr/sbin/reboot", 1)}, usable())
	if c, r := cl.classify([]byte("/usr/local/sbin/reboot"), nil, ptr(file("/usr/local/sbin/reboot", 1))); c != ClassCritical || r != RuleShadow {
		t.Fatalf("got %v/%b", c, r)
	}
}

// TestSSHSymlinkMakesEveryDeviationUnclassifiable pins the fail-closed
// interim of ADR 0015 D9 "Symlinks at or above SSH positions": until the
// executor resolves such a symlink, the files behind it cannot be
// classified, so no deviation of the run may stay critical-free.
func TestSSHSymlinkMakesEveryDeviationUnclassifiable(t *testing.T) {
	link := symlink("/home/bob/.ssh", "/home/bob/dotssh")
	kh1, kh2 := file("/home/bob/dotssh/known_hosts", 1), file("/home/bob/dotssh/known_hosts", 2)
	app1, app2 := file("/opt/app/bin/run", 1), file("/opt/app/bin/run", 2)
	cl := newClassifier([]fimscan.Record{link, kh1, app1}, []fimscan.Record{link, kh2, app2}, usable())
	tests := []struct {
		name      string
		path      string
		old, cur  *fimscan.Record
		wantClass Class
		wantRules Rule
	}{
		{"file behind the symlink", "/home/bob/dotssh/known_hosts", &kh1, &kh2, ClassCritical, RuleUnclassifiable},
		{"unrelated file, same run", "/opt/app/bin/run", &app1, &app2, ClassCritical, RuleUnclassifiable},
		{"the symlink itself", "/home/bob/.ssh", &link, &link, ClassCritical, RuleSSHSymlink | RuleUnclassifiable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, r := cl.classify([]byte(tc.path), tc.old, tc.cur)
			if c != tc.wantClass || r != tc.wantRules {
				t.Fatalf("got %v/%b, want %v/%b", c, r, tc.wantClass, tc.wantRules)
			}
		})
	}
}

// TestSymlinkOutsideSSHPositionsKeepsClassification pins the other side:
// a symlink that is no SSH position does not make the run unclassifiable.
func TestSymlinkOutsideSSHPositionsKeepsClassification(t *testing.T) {
	link := symlink("/opt/app", "/srv/app")
	app1, app2 := file("/opt/app/bin/run", 1), file("/opt/app/bin/run", 2)
	cl := newClassifier([]fimscan.Record{link, app1}, []fimscan.Record{link, app2}, usable())
	if c, r := cl.classify([]byte("/opt/app/bin/run"), &app1, &app2); c != ClassNormal || r != 0 {
		t.Fatalf("got %v/%b, want normal/0", c, r)
	}
}

// sshFileLinkCases are fixed SSH file positions (ADR 0015 D9 "SSH login
// files", "sshd command-line configuration sources") and sshd unit or
// drop-in positions that a symlink must not hide behind.
var sshFileLinkCases = []string{
	"/etc/ssh/sshd_config", "/etc/default/ssh", "/etc/passwd", "/etc/nsswitch.conf",
	"/etc/hosts.equiv", "/etc/krb5.conf",
	"/root/.ssh/authorized_keys", "/home/bob/.ssh/authorized_keys2", "/home/bob/.ssh/known_hosts",
	"/etc/systemd/system/ssh.service", "/usr/local/lib/systemd/system/ssh.service.d",
	"/etc/systemd/system/ssh.service.d/opts.conf",
}

// TestSymlinkAtSSHFilePositionMakesRunUnclassifiable pins ADR 0015 D9: a
// symlink at a fixed SSH file or drop-in position makes the run
// unclassifiable (fail closed until resolution), so a change of the file
// behind it is never classed normal.
func TestSymlinkAtSSHFilePositionMakesRunUnclassifiable(t *testing.T) {
	for _, p := range sshFileLinkCases {
		t.Run(p, func(t *testing.T) {
			link := symlink(p, "/opt/x/ssh")
			o1, o2 := file("/opt/x/ssh", 1), file("/opt/x/ssh", 2)
			cl := newClassifier([]fimscan.Record{link, o1}, []fimscan.Record{link, o2}, usable())
			if c, r := cl.classify([]byte("/opt/x/ssh"), &o1, &o2); c != ClassCritical || r != RuleUnclassifiable {
				t.Fatalf("change behind the link: got %v/%b, want critical/unclassifiable", c, r)
			}
			want := RuleSSHSymlink | RuleUnclassifiable
			if c, r := cl.classify([]byte(p), &link, &link); c != ClassCritical || r&want != want {
				t.Fatalf("the link itself: got %v/%b", c, r)
			}
		})
	}
}

// TestNonFileAtSSHFilePositionMakesRunUnclassifiable pins the D9 rule that a
// file position holding any type other than file counts like a symlink.
func TestNonFileAtSSHFilePositionMakesRunUnclassifiable(t *testing.T) {
	other := func(p string) fimscan.Record { return fimscan.Record{Path: []byte(p), Type: fimscan.TypeOther} }
	tests := []struct {
		name string
		rec  fimscan.Record
	}{
		{"directory at sshd_config", dir("/etc/ssh/sshd_config")},
		{"other at sshd_config", other("/etc/ssh/sshd_config")},
		{"directory at authorized_keys", dir("/root/.ssh/authorized_keys")},
		{"other at authorized_keys", other("/home/bob/.ssh/authorized_keys")},
		{"other at default ssh", other("/etc/default/ssh")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			old := file(string(tc.rec.Path), 1)
			o1, o2 := file("/opt/app/bin/run", 1), file("/opt/app/bin/run", 2)
			cl := newClassifier([]fimscan.Record{o1, old}, []fimscan.Record{o2, tc.rec}, usable())
			if c, r := cl.classify([]byte("/opt/app/bin/run"), &o1, &o2); c != ClassCritical || r != RuleUnclassifiable {
				t.Fatalf("unrelated change: got %v/%b, want critical/unclassifiable", c, r)
			}
			if c, r := cl.classify(tc.rec.Path, &old, &tc.rec); c != ClassCritical || r&RuleSSHSymlink == 0 {
				t.Fatalf("the entry itself: got %v/%b", c, r)
			}
		})
	}
}

// TestNonFileAtSSHDirectoryPositionKeepsClassification: a directory where
// sshd only looks for a directory (/etc/ssh) is not a file position.
func TestNonFileAtSSHDirectoryPositionKeepsClassification(t *testing.T) {
	d1, d2 := dir("/etc/ssh"), dir("/etc/ssh")
	app1, app2 := file("/opt/app/bin/run", 1), file("/opt/app/bin/run", 2)
	cl := newClassifier([]fimscan.Record{d1, app1}, []fimscan.Record{d2, app2}, usable())
	if c, r := cl.classify([]byte("/opt/app/bin/run"), &app1, &app2); c != ClassNormal || r != 0 {
		t.Fatalf("got %v/%b, want normal/0", c, r)
	}
}

// TestUsrmergeLibLinkIsKnownLimit pins the current fail-closed interim for
// the usrmerge /lib -> usr/lib link (ADR 0015 D5, D9): /lib is an SSH
// position, and resolving it needs records of /usr, which the scan does not
// record, so every deviation of such a run is unclassifiable. This is a named
// limit ("Honest limits"): safe, but ClassNormal stays unreachable on usrmerge
// hosts until resolution is implemented.
func TestUsrmergeLibLinkIsKnownLimit(t *testing.T) {
	lib := symlink("/lib", "usr/lib")
	app1, app2 := file("/opt/app/bin/run", 1), file("/opt/app/bin/run", 2)
	cl := newClassifier([]fimscan.Record{lib, app1}, []fimscan.Record{lib, app2}, usable())
	if c, r := cl.classify([]byte("/opt/app/bin/run"), &app1, &app2); c != ClassCritical || r != RuleUnclassifiable {
		t.Fatalf("got %v/%b, want critical/unclassifiable", c, r)
	}
}

func ptr[T any](v T) *T { return &v }
