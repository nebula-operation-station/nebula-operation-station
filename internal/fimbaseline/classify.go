// SPDX-License-Identifier: AGPL-3.0-or-later

package fimbaseline

import (
	"bytes"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
)

// Class is the ADR 0015 D9 class of a deviation's path.
type Class uint8

const (
	// ClassNormal: not a critical-class path.
	ClassNormal Class = iota + 1
	// ClassCritical: a critical-class path (ADR 0015 D9 "Critical-class
	// paths"), approved only one entry at a time in the executor-local CLI.
	ClassCritical
)

// String returns the class name.
func (c Class) String() string {
	switch c {
	case ClassNormal:
		return "normal"
	case ClassCritical:
		return "critical"
	default:
		return "invalid"
	}
}

// Rule is a bit set of the reasons an entry is critical-class.
type Rule uint8

const (
	// RuleFixedPath: a fixed D9 path pattern of the profile (D7 item (a)).
	RuleFixedPath Rule = 1 << iota
	// RuleSetID: a setuid or setgid bit before or after the change (D7 (b)).
	RuleSetID
	// RuleShadow: a /usr/local/{bin,sbin} entry whose name is a command in
	// /usr/bin or /usr/sbin of the baseline or the scan (D7 (c)).
	RuleShadow
	// RuleSSHDerived: a path the derived SSH set (D7 (d)) names.
	RuleSSHDerived
	// RuleSSHSymlink: a symlink at or above an SSH position (D9 "Symlinks
	// at or above SSH positions").
	RuleSSHSymlink
	// RuleUnclassifiable: no usable derived SSH set, so every deviation is
	// critical-class (D7 "Unclassifiable means critical").
	RuleUnclassifiable
)

// SSHMatch is the answer of an SSHSet for one path.
type SSHMatch uint8

const (
	// SSHNone: the path is not covered by the derived set.
	SSHNone SSHMatch = iota
	// SSHFile: an SSH configuration entry or SSH login file target.
	SSHFile
	// SSHPosition: a directory at or above an SSH configuration or login
	// file position; critical only while the old or new record is a
	// symlink.
	SSHPosition
)

// SSHSet is the derived set (d) of ADR 0015 D7: the Include values and
// matched files of sshd_config and the SSH login file targets, as the
// union of the approved set S and the latest complete run's set. Deriving
// it from the D6 SSH configuration array is a later IG-06 part.
//
// TODO(ADR 0015 D7 (d), D9 "SSH login files"): implement the derivation
// (Include globs, AuthorizedKeysFile expansion, daemon-wide values, the
// 4,096-value limit and the overflow mark) in its own package.
type SSHSet interface {
	// Match classifies a raw path against the derived set.
	Match(path []byte) SSHMatch
}

// Options are the executor-side inputs of Diff.
type Options struct {
	// SSH is the usable derived SSH set. Nil means there is none (no
	// complete run supplied one, it overflowed, or it is not implemented
	// yet); then every deviation is critical-class (D7).
	SSH SSHSet
}

// fixedExact are D9 critical-class paths named literally.
var fixedExact = map[string]bool{
	// SSH login files by fixed path (D9 "SSH login files").
	"/etc/hosts.equiv": true, "/etc/ssh/shosts.equiv": true,
	"/etc/ssh/ssh_known_hosts": true, "/etc/ssh/ssh_known_hosts2": true,
	"/etc/krb5.keytab": true, "/etc/krb5.conf": true,
	"/etc/passwd": true, "/etc/shadow": true, "/etc/group": true,
	"/etc/gshadow": true, "/etc/nsswitch.conf": true,
	// Other D9 critical-class paths.
	"/etc/sudoers":         true,
	"/etc/ssh/sshd_config": true,
	"/etc/default/ssh":     true, // sshd command-line configuration source
	"/etc/ld.so.preload":   true,
	"/etc/crontab":         true,
	"/usr/sbin/sshd":       true,
}

// fixedSuffixes are D9 home-relative SSH login files and authorized_keys
// paths, matched anywhere.
var fixedSuffixes = []string{
	"/.shosts", "/.rhosts", "/.ssh/known_hosts", "/.ssh/known_hosts2",
	"/.k5login", "/.ssh/authorized_keys", "/.ssh/authorized_keys2",
}

// fixedTrees are D9 critical-class directories: the directory itself and
// everything below it.
var fixedTrees = []string{
	"/etc/sudoers.d",
	"/etc/pam.d", "/etc/security", // PAM configuration
	"/usr/lib/systemd/system", "/etc/systemd/system", "/etc/systemd/user", // D5 unit roots
	"/var/spool/cron/crontabs", // crontab spool
	"/boot",                    // every file under /boot
	"/usr/lib/openssh",         // sshd helpers
}

// commandDirs hold the commands sudo and su (D9 "sudo and su"); /bin and
// /sbin are the usrmerge paths (D5).
var commandDirs = []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"}

// shadowedDirs are the directories whose commands can be shadowed (D7 (c)).
var shadowedDirs = []string{"/usr/bin", "/usr/sbin"}

// shadowingDirs come first in the default PATH (D5, D9).
var shadowingDirs = []string{"/usr/local/bin", "/usr/local/sbin"}

// unitSearchPaths are the systemd system unit search paths in which the
// sshd units are critical-class independent of the D5 unit roots (D9
// "sshd command-line configuration sources").
var unitSearchPaths = []string{
	"/etc/systemd/system", "/etc/systemd/system.control", "/etc/systemd/system.attached",
	"/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system",
}

// sshdUnitNames are the units that start sshd (D9).
var sshdUnitNames = map[string]bool{
	"ssh.service": true, "ssh@.service": true, "ssh.socket": true,
	"sshd.service": true, "sshd@.service": true, "sshd.socket": true,
}

// fixedSSHDirs are the directories at or above the fixed SSH positions
// (D9 "Symlinks at or above SSH positions"): /etc/ssh/sshd_config, the
// fixed /etc login files, /etc/default/ssh, the home-relative login files
// under /root and /home/*/ (D5, D9) and the unit search paths.
var fixedSSHDirs = map[string]bool{
	"/etc": true, "/etc/ssh": true, "/etc/default": true,
	"/root": true, "/root/.ssh": true, "/home": true,
	"/etc/systemd": true,
	"/usr":         true, "/usr/lib": true, "/usr/lib/systemd": true,
	"/usr/local": true, "/usr/local/lib": true, "/usr/local/lib/systemd": true,
	"/lib": true, "/lib/systemd": true,
}

func init() {
	for _, p := range unitSearchPaths {
		fixedSSHDirs[p] = true
	}
}

// split returns the parent directory and the last component of an
// absolute path checked by checkPath.
func split(s string) (dir, name string) {
	i := strings.LastIndexByte(s, '/')
	if i == 0 {
		return "/", s[1:]
	}
	return s[:i], s[i+1:]
}

func inTree(s, root string) bool {
	return s == root || strings.HasPrefix(s, root+"/")
}

func isSSHDUnitName(n string) bool {
	if sshdUnitNames[n] {
		return true
	}
	// Instances of the template units (over-matching only adds entries).
	for _, t := range []string{"ssh@", "sshd@"} {
		if strings.HasPrefix(n, t) && strings.HasSuffix(n, ".service") {
			return true
		}
	}
	return false
}

// isSSHDDropInDir reports whether n names a drop-in directory that applies
// to an sshd unit: <unit>.d for each name, ssh@<instance>.service.d,
// sshd@<instance>.service.d, and the type-wide service.d and socket.d.
func isSSHDDropInDir(n string) bool {
	if n == "service.d" || n == "socket.d" {
		return true
	}
	base, ok := strings.CutSuffix(n, ".d")
	return ok && isSSHDUnitName(base)
}

// sshdUnitEntry reports whether s is an sshd unit, an enablement or alias
// link of one in a *.wants/ or *.requires/ directory, or an entry of an
// sshd drop-in directory, in any unit search path.
func sshdUnitEntry(s string) bool {
	for _, sp := range unitSearchPaths {
		rel, ok := strings.CutPrefix(s, sp+"/")
		if !ok {
			continue
		}
		first, rest, nested := strings.Cut(rel, "/")
		switch {
		case isSSHDUnitName(first) || isSSHDDropInDir(first):
			return true
		case nested && (strings.HasSuffix(first, ".wants") || strings.HasSuffix(first, ".requires")):
			return !strings.Contains(rest, "/") && isSSHDUnitName(rest)
		}
	}
	return false
}

// fixedCritical reports whether s matches a fixed D9 critical-class path
// pattern (D7 item (a)).
func fixedCritical(s string) bool {
	if fixedExact[s] {
		return true
	}
	for _, suf := range fixedSuffixes {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	for _, t := range fixedTrees {
		if inTree(s, t) {
			return true
		}
	}
	dir, name := split(s)
	switch {
	case strings.HasPrefix(name, "authorized_keys"):
		return true
	case strings.HasPrefix(name, "pam_") && strings.HasSuffix(name, ".so"):
		return true
	case strings.HasPrefix(name, "ld-linux"):
		return true
	case (name == "sudo" || name == "su") && containsString(commandDirs, dir):
		return true
	}
	// Crontabs: /etc/cron.*/ (D5 "Scheduled jobs"); the directory entry
	// itself and everything below it.
	if rel, ok := strings.CutPrefix(s, "/etc/"); ok {
		first, _, _ := strings.Cut(rel, "/")
		if strings.HasPrefix(first, "cron.") {
			return true
		}
	}
	return sshdUnitEntry(s)
}

// fixedSSHDir reports whether s is a directory at or above a fixed SSH
// position.
func fixedSSHDir(s string) bool {
	if fixedSSHDirs[s] {
		return true
	}
	// /home/<name> and /home/<name>/.ssh.
	if rel, ok := strings.CutPrefix(s, "/home/"); ok {
		user, rest, nested := strings.Cut(rel, "/")
		return user != "" && (!nested || rest == ".ssh")
	}
	// *.wants/ and *.requires/ directories in a unit search path hold sshd
	// enablement links.
	dir, name := split(s)
	if containsString(unitSearchPaths, dir) &&
		(strings.HasSuffix(name, ".wants") || strings.HasSuffix(name, ".requires")) {
		return true
	}
	return false
}

func containsString(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

// classifier decides the class of one deviation from executor-side data
// only (ADR 0015 D7 "The executor classifies, from its own data").
type classifier struct {
	shadowed map[string]bool // command names in /usr/bin and /usr/sbin
	ssh      SSHSet
}

func newClassifier(old, cur []fimscan.Record, opts Options) *classifier {
	c := &classifier{shadowed: map[string]bool{}, ssh: opts.SSH}
	for _, recs := range [][]fimscan.Record{old, cur} {
		for i := range recs {
			dir, name := split(string(recs[i].Path))
			if containsString(shadowedDirs, dir) {
				c.shadowed[name] = true
			}
		}
	}
	return c
}

// classify returns the class of the deviation at path p and the rules that
// made it critical. old or cur is nil when the path is absent on that side.
//
// TODO(ADR 0015 D9 "Symlinks at or above SSH positions"): resolve such a
// symlink component by component against its record set, classify the
// resolved path and the entries below it, and report targets outside the
// scanned roots. Only the symlink entry itself is classified here.
func (c *classifier) classify(p []byte, old, cur *fimscan.Record) (Class, Rule) {
	s := string(p)
	var r Rule
	if fixedCritical(s) {
		r |= RuleFixedPath
	}
	if (old != nil && old.Mode&0o6000 != 0) || (cur != nil && cur.Mode&0o6000 != 0) {
		r |= RuleSetID
	}
	if dir, name := split(s); containsString(shadowingDirs, dir) && c.shadowed[name] {
		r |= RuleShadow
	}
	symlink := (old != nil && old.Type == fimscan.TypeSymlink) || (cur != nil && cur.Type == fimscan.TypeSymlink)
	if symlink && fixedSSHDir(s) {
		r |= RuleSSHSymlink
	}
	if c.ssh == nil {
		r |= RuleUnclassifiable
	} else {
		switch c.ssh.Match(bytes.Clone(p)) {
		case SSHFile:
			r |= RuleSSHDerived
		case SSHPosition:
			if symlink {
				r |= RuleSSHSymlink
			}
		}
	}
	if r != 0 {
		return ClassCritical, r
	}
	return ClassNormal, 0
}
