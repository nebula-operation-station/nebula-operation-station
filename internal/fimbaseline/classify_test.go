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

// sshFileLinkCases are fixed SSH configuration and login file positions (ADR
// 0015 D9 "SSH login files", "sshd command-line configuration sources") that
// a symlink must not hide behind. sshd units and drop-ins are not listed:
// they are per-entry critical only (TestStandardSystemdLayoutKeepsClassification).
var sshFileLinkCases = []string{
	"/etc/ssh/sshd_config", "/etc/default/ssh", "/etc/passwd", "/etc/nsswitch.conf",
	"/etc/hosts.equiv", "/etc/krb5.conf",
	"/root/.ssh/authorized_keys", "/home/bob/.ssh/authorized_keys2", "/home/bob/.ssh/known_hosts",
}

// TestSymlinkAtSSHFilePositionMakesRunUnclassifiable pins ADR 0015 D9: a
// symlink at a fixed SSH configuration or login file position makes the run
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

// TestStandardSystemdLayoutKeepsClassification pins the round-1 regression
// fix. On normal Debian and usrmerge hosts the usrmerge link /lib -> usr/lib
// (ADR 0015 D5) and the ordinary sshd enablement and alias links
// (ssh.service in *.wants/, sshd.service in /etc/systemd/system) are recorded.
// They must not make the run unclassifiable, so an unrelated change stays
// ClassNormal. The links themselves stay critical: sshd units are critical-
// class by fixed pattern (D7 (a)).
func TestStandardSystemdLayoutKeepsClassification(t *testing.T) {
	layout := []fimscan.Record{
		symlink("/lib", "usr/lib"), symlink("/bin", "usr/bin"), symlink("/sbin", "usr/sbin"),
		file("/usr/lib/systemd/system/ssh.service", 7),
		symlink("/etc/systemd/system/multi-user.target.wants/ssh.service", "/lib/systemd/system/ssh.service"),
		symlink("/etc/systemd/system/sshd.service", "/lib/systemd/system/ssh.service"),
	}
	app1, app2 := file("/opt/app/bin/run", 1), file("/opt/app/bin/run", 2)
	cl := newClassifier(append([]fimscan.Record{app1}, layout...), append([]fimscan.Record{app2}, layout...), usable())
	if c, r := cl.classify([]byte("/opt/app/bin/run"), &app1, &app2); c != ClassNormal || r != 0 {
		t.Fatalf("unrelated change: got %v/%b, want normal/0", c, r)
	}
	for _, p := range []string{"/etc/systemd/system/multi-user.target.wants/ssh.service", "/etc/systemd/system/sshd.service"} {
		rec := symlink(p, "/lib/systemd/system/ssh.service")
		if c, r := cl.classify([]byte(p), &rec, &rec); c != ClassCritical || r&RuleUnclassifiable != 0 {
			t.Errorf("%s: got %v/%b, want critical without unclassifiable", p, c, r)
		}
	}
	// A retargeted usrmerge link is itself a per-entry critical deviation, and
	// the new record is not a standard link, so it is also run-wide.
	libOld, libNew := symlink("/lib", "usr/lib"), symlink("/lib", "/tmp/evil")
	retargeted := newClassifier(append([]fimscan.Record{app1, libOld}, layout[1:]...), append([]fimscan.Record{app2, libNew}, layout[1:]...), usable())
	if c, r := retargeted.classify([]byte("/lib"), &libOld, &libNew); c != ClassCritical || r&RuleSSHSymlink == 0 || r&RuleUnclassifiable == 0 {
		t.Errorf("/lib retargeted: got %v/%b, want critical with RuleSSHSymlink and RuleUnclassifiable", c, r)
	}
}

// TestNonStandardSymlinkAtUnitPositionIsRunWide pins the narrow exemption of
// ADR 0015 D9 (round 2). A symlink at a systemd unit position (unit search
// paths, unit drop-in directories, *.wants and *.requires, sshd unit
// entries) or at a usrmerge link (/lib, /lib64, /bin, /sbin) that is not the
// standard link makes every deviation of the run unclassifiable: the files
// behind it are not in the run, so none of them may be approved as normal.
// The classification of the entry itself stays critical.
func TestNonStandardSymlinkAtUnitPositionIsRunWide(t *testing.T) {
	tests := []struct{ path, target string }{
		{"/etc/systemd/system", "/opt/x"},
		{"/usr/local/lib/systemd", "/opt/x"},
		{"/usr/local/lib/systemd/system", "/opt/x"},
		{"/etc/systemd/system/ssh.service.d", "/opt/x"},
		{"/usr/local/lib/systemd/system/ssh.service.d", "/opt/x"},
		{"/etc/systemd/system/sshd@x.service.d", "/opt/x"},
		{"/etc/systemd/system/ssh.service", "/opt/x/ssh.service"},
		{"/etc/systemd/system/sshd.socket", "/dev/null"},
		{"/usr/lib/systemd/system/ssh.service", "/opt/x/ssh.service"},
		{"/etc/systemd/system/multi-user.target.wants", "/opt/x"},
		{"/etc/systemd/system/multi-user.target.wants/ssh.service", "/opt/x/ssh.service"},
		{"/etc/systemd/system/multi-user.target.wants/ssh.service", "/lib/systemd/system/sshd.socket"},
		{"/etc/systemd/system/sshd.service", "../../../lib/systemd/system/ssh.service"},
		{"/lib/systemd/system/sshd.service", "ssh.service"},
		{"/etc/systemd/system/multi-user.target.wants/ssh.service", "../ssh.service"},
		{"/lib/systemd", "/opt/x"},
		{"/usr", "/srv/usr"},
		{"/usr/lib", "/srv/usr/lib"},
		{"/lib", "/tmp/evil"},
		{"/lib", "usr/lib2"},
		{"/lib", "/usr/lib/../../tmp"},
		{"/lib64", "/opt/lib64"},
		{"/bin", "/tmp/bin"},
		{"/sbin", "usr/bin"},
	}
	app1, app2 := file("/opt/app/bin/run", 1), file("/opt/app/bin/run", 2)
	for _, tc := range tests {
		t.Run(tc.path+" -> "+tc.target, func(t *testing.T) {
			link := symlink(tc.path, tc.target)
			cl := newClassifier([]fimscan.Record{app1, link}, []fimscan.Record{app2, link}, usable())
			if c, r := cl.classify([]byte("/opt/app/bin/run"), &app1, &app2); c != ClassCritical || r != RuleUnclassifiable {
				t.Fatalf("unrelated change: got %v/%b, want critical/unclassifiable", c, r)
			}
			if c, r := cl.classify([]byte(tc.path), &link, &link); c != ClassCritical || r&(RuleSSHSymlink|RuleUnclassifiable) != RuleSSHSymlink|RuleUnclassifiable {
				t.Fatalf("the link itself: got %v/%b", c, r)
			}
		})
	}
}

// TestStandardUsrmergeAndUnitLinksAreNotRunWide pins the exemption from the
// other side: exactly the standard usrmerge links (/lib, /lib64, /bin, /sbin
// to usr/...) and the standard sshd unit enablement and alias links to
// /lib/systemd/system or /usr/lib/systemd/system do not make the run
// unclassifiable. The links themselves stay per-entry critical.
func TestStandardUsrmergeAndUnitLinksAreNotRunWide(t *testing.T) {
	tests := []struct{ path, target string }{
		{"/lib", "usr/lib"}, {"/lib", "/usr/lib"},
		{"/lib64", "usr/lib64"}, {"/bin", "usr/bin"}, {"/sbin", "/usr/sbin"},
		{"/etc/systemd/system/ssh.service", "/lib/systemd/system/ssh.service"},
		{"/etc/systemd/system/sshd.service", "/usr/lib/systemd/system/ssh.service"},
		{"/etc/systemd/system/multi-user.target.wants/ssh.service", "/lib/systemd/system/ssh.service"},
		{"/etc/systemd/system/multi-user.target.wants/sshd.service", "/usr/lib/systemd/system/sshd.service"},
		{"/etc/systemd/system/sshd.socket", "/lib/systemd/system/sshd.socket"},
	}
	app1, app2 := file("/opt/app/bin/run", 1), file("/opt/app/bin/run", 2)
	for _, tc := range tests {
		t.Run(tc.path+" -> "+tc.target, func(t *testing.T) {
			link := symlink(tc.path, tc.target)
			cl := newClassifier([]fimscan.Record{app1, link}, []fimscan.Record{app2, link}, usable())
			if c, r := cl.classify([]byte("/opt/app/bin/run"), &app1, &app2); c != ClassNormal || r != 0 {
				t.Fatalf("unrelated change: got %v/%b, want normal/0", c, r)
			}
			if c, r := cl.classify([]byte(tc.path), &link, &link); c != ClassCritical || r&RuleUnclassifiable != 0 {
				t.Fatalf("the link itself: got %v/%b, want critical without unclassifiable", c, r)
			}
		})
	}
}

// TestDirectoryNamedAuthorizedKeysIsNotAFixedPosition pins the fix for
// AuthorizedKeysFile /etc/ssh/authorized_keys/%u. The directory is only an SSH
// position through the derived set, so it does not make every deviation of
// the run unclassifiable, and the file behind it is classified per entry.
func TestDirectoryNamedAuthorizedKeysIsNotAFixedPosition(t *testing.T) {
	ssh := Options{SSH: stubSSH{
		files:     map[string]bool{"/etc/ssh/authorized_keys/bob": true},
		positions: map[string]bool{"/etc/ssh/authorized_keys": true},
	}}
	keysDir := dir("/etc/ssh/authorized_keys")
	bob1, bob2 := file("/etc/ssh/authorized_keys/bob", 1), file("/etc/ssh/authorized_keys/bob", 2)
	app1, app2 := file("/opt/app/bin/run", 1), file("/opt/app/bin/run", 2)
	cl := newClassifier([]fimscan.Record{keysDir, bob1, app1}, []fimscan.Record{keysDir, bob2, app2}, ssh)
	if c, r := cl.classify([]byte("/opt/app/bin/run"), &app1, &app2); c != ClassNormal || r != 0 {
		t.Fatalf("unrelated change: got %v/%b, want normal/0", c, r)
	}
	if c, r := cl.classify([]byte("/etc/ssh/authorized_keys/bob"), &bob1, &bob2); c != ClassCritical || r&RuleSSHDerived == 0 || r&RuleUnclassifiable != 0 {
		t.Fatalf("key file behind the directory: got %v/%b, want critical/RuleSSHDerived", c, r)
	}
	if c, r := cl.classify([]byte("/etc/ssh/authorized_keys"), &keysDir, &keysDir); c != ClassCritical || r&RuleUnclassifiable != 0 {
		t.Fatalf("the directory itself: got %v/%b, want critical without unclassifiable", c, r)
	}
	// A symlink at the derived directory position still fails closed.
	link := symlink("/etc/ssh/authorized_keys", "/srv/keys")
	cl = newClassifier([]fimscan.Record{link, app1}, []fimscan.Record{link, app2}, ssh)
	if c, r := cl.classify([]byte("/opt/app/bin/run"), &app1, &app2); c != ClassCritical || r != RuleUnclassifiable {
		t.Fatalf("symlink at the derived position: got %v/%b, want critical/unclassifiable", c, r)
	}
}

// TestConfigSSHFileFixedPositions pins the fixed configuration and login file
// positions: only the literal list and the home-relative login files, not any
// name that merely starts with authorized_keys.
func TestConfigSSHFileFixedPositions(t *testing.T) {
	yes := []string{"/etc/ssh/sshd_config", "/root/.ssh/authorized_keys", "/home/bob/.ssh/authorized_keys2", "/home/bob/.shosts"}
	no := []string{"/etc/ssh/authorized_keys", "/etc/ssh/authorized_keys/bob", "/etc/ssh/authorized_keys_extra", "/srv/authorized_keys"}
	for _, p := range yes {
		if !configSSHFile(p) {
			t.Errorf("%s: not a fixed SSH file position", p)
		}
	}
	for _, p := range no {
		if configSSHFile(p) {
			t.Errorf("%s: fixed SSH file position, want only the derived set to name it", p)
		}
	}
}

// countingSSH counts the Match calls per path.
type countingSSH struct {
	inner SSHSet
	calls map[string]int
}

func (c countingSSH) Match(p []byte) SSHMatch {
	c.calls[string(p)]++
	return c.inner.Match(p)
}

// TestDerivedSetQueriedOncePerPath pins the cost bound of newClassifier: the
// derived set is asked at most once per distinct path, even though the same
// records appear in the baseline, the scan and the latest complete run.
func TestDerivedSetQueriedOncePerPath(t *testing.T) {
	var base, cur []fimscan.Record
	for _, p := range []string{"/srv", "/srv/a", "/srv/a/b", "/srv/c", "/opt", "/opt/x"} {
		base = append(base, dir(p))
		cur = append(cur, dir(p))
	}
	cur = append(cur, file("/srv/a/b/new", 1))
	latest := result(append(append([]fimscan.Record{}, base...), cur...)...)
	counter := countingSSH{inner: stubSSH{}, calls: map[string]int{}}
	opts := Options{SSH: counter, LatestComplete: latest}
	cl := newClassifier(base, cur, opts)
	for _, rec := range cur {
		cl.classify(rec.Path, nil, &rec)
	}
	for p, n := range counter.calls {
		if n > 1 {
			t.Errorf("%s: derived set queried %d times, want at most 1", p, n)
		}
	}
}

// TestNonFileAtSSHUnitPositionIsNotRunWide: a directory where an sshd unit
// file is expected is critical for that entry, but it does not make the
// unrelated deviations of the run unclassifiable.
func TestNonFileAtSSHUnitPositionIsNotRunWide(t *testing.T) {
	unitDir := dir("/etc/systemd/system/ssh.service")
	app1, app2 := file("/opt/app/bin/run", 1), file("/opt/app/bin/run", 2)
	cl := newClassifier([]fimscan.Record{app1}, []fimscan.Record{app2, unitDir}, usable())
	if c, r := cl.classify([]byte("/opt/app/bin/run"), &app1, &app2); c != ClassNormal || r != 0 {
		t.Fatalf("unrelated change: got %v/%b, want normal/0", c, r)
	}
	if c, r := cl.classify([]byte("/etc/systemd/system/ssh.service"), nil, &unitDir); c != ClassCritical || r&RuleSSHSymlink == 0 {
		t.Fatalf("the entry itself: got %v/%b", c, r)
	}
}

// TestSSHConfigSymlinkStillFailsClosedOnUsrmerge: the usrmerge exemption does
// not weaken the configuration rule. A symlink at /etc/ssh/sshd_config on a
// usrmerge host still makes every deviation unclassifiable.
func TestSSHConfigSymlinkStillFailsClosedOnUsrmerge(t *testing.T) {
	lib := symlink("/lib", "usr/lib")
	cfg := symlink("/etc/ssh/sshd_config", "/srv/sshd_config")
	app1, app2 := file("/opt/app/bin/run", 1), file("/opt/app/bin/run", 2)
	cl := newClassifier([]fimscan.Record{lib, cfg, app1}, []fimscan.Record{lib, cfg, app2}, usable())
	if c, r := cl.classify([]byte("/opt/app/bin/run"), &app1, &app2); c != ClassCritical || r != RuleUnclassifiable {
		t.Fatalf("got %v/%b, want critical/unclassifiable", c, r)
	}
}

// TestSSHFileExactIsCriticalByFixedPath guards against drift: every SSH file
// position named literally is also a fixed critical-class path (D9).
func TestSSHFileExactIsCriticalByFixedPath(t *testing.T) {
	for p := range sshFileExact {
		if !fixedCritical(p) {
			t.Errorf("%s: SSH file position but not critical-class", p)
		}
	}
}

func ptr[T any](v T) *T { return &v }
