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
	// /usr/bin or /usr/sbin of the baseline, the scan or the latest complete
	// run (D7 (c)).
	RuleShadow
	// RuleSSHDerived: a path the derived SSH set (D7 (d)) names.
	RuleSSHDerived
	// RuleSSHSymlink: a symlink at or above an SSH position, or a record of
	// another non-file type at an SSH file position (D9 "Symlinks at or
	// above SSH positions": "for a file position, any type other than
	// file" counts like a symlink).
	RuleSSHSymlink
	// RuleUnclassifiable: every deviation of the run is critical-class
	// (D7 "Unclassifiable means critical") because either there is no
	// usable derived SSH set, or a symlink at a configuration or login
	// position, or a non-file record at a configuration or login file
	// position, exists in the approved baseline, the scan or the latest
	// complete run (D9 "Symlinks at or above SSH positions"). A symlink at a
	// unit position is excluded only if it is a standard link (see
	// standardUnitLink), so the standard Debian and usrmerge layouts do not
	// trigger it. The second case is a
	// fail-closed interim: it is applied to the whole run, since the files
	// behind such a record are not known, and it is replaced by
	// resolution-based classification later.
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
	// LatestComplete is the host's latest complete run, or nil if there is
	// none. Its /usr/bin and /usr/sbin names join the shadowing set (D7
	// (c): the union of the approved baseline and the latest complete
	// run), so a partial scan that skips those directories classifies the
	// same way as a complete one. It must be complete and of the
	// baseline's profile; Diff rejects it otherwise.
	LatestComplete *fimscan.Result
}

// fixedExact are D9 critical-class paths named literally. The SSH file
// positions are merged in from sshFileExact by init, so the two lists cannot
// drift apart.
var fixedExact = map[string]bool{
	"/etc/sudoers":       true,
	"/etc/ld.so.preload": true,
	"/etc/crontab":       true,
	"/usr/sbin/sshd":     true,
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

// sshFileExact are the fixed SSH configuration and login file positions named
// literally: the sshd configuration and its command-line source, and the
// fixed /etc login and name-service files (D9 "SSH login files", "sshd
// command-line configuration sources"). A symlink or another non-file record
// here makes the run unclassifiable (see RuleUnclassifiable). sshd units are
// not listed here: they are per-entry only (see unitSSHDirs).
var sshFileExact = map[string]bool{
	"/etc/ssh/sshd_config": true, "/etc/default/ssh": true,
	"/etc/hosts.equiv": true, "/etc/ssh/shosts.equiv": true,
	"/etc/ssh/ssh_known_hosts": true, "/etc/ssh/ssh_known_hosts2": true,
	"/etc/krb5.keytab": true, "/etc/krb5.conf": true,
	"/etc/passwd": true, "/etc/shadow": true, "/etc/group": true,
	"/etc/gshadow": true, "/etc/nsswitch.conf": true,
}

// configSSHDirs are the directories at or above the fixed SSH configuration
// and login file positions (D9 "Symlinks at or above SSH positions"). The
// home directories (/home, /home/<name>, /home/<name>/.ssh) are matched by
// configSSHDir. A symlink at any of these makes the run unclassifiable.
var configSSHDirs = map[string]bool{
	"/etc": true, "/etc/ssh": true, "/etc/default": true,
	"/root": true, "/root/.ssh": true, "/home": true,
}

// unitSSHDirs are the directories at or above the sshd unit positions: the
// systemd unit roots and search paths, and the directories that hold them.
// A symlink at one of them is critical for its own entry (D9) and makes the
// whole run unclassifiable, unless it is a standard link (standardUnitLink):
// the units behind a non-standard link are not in the run.
var unitSSHDirs = map[string]bool{
	"/etc/systemd": true,
	"/usr":         true, "/usr/lib": true, "/usr/lib/systemd": true,
	"/usr/local": true, "/usr/local/lib": true, "/usr/local/lib/systemd": true,
	"/lib": true, "/lib/systemd": true,
}

// usrmergeLinks are the usrmerge symlinks of D5 with their standard targets,
// in relative form (the absolute form "/" + target is accepted too). They
// are directories at or above unit or command positions: /lib holds the sshd
// units, /bin and /sbin hold sudo and su. Only the standard link is exempt
// from the run-wide rule (standardUnitLink).
var usrmergeLinks = map[string]string{
	"/lib": "usr/lib", "/lib64": "usr/lib64", "/bin": "usr/bin", "/sbin": "usr/sbin",
}

// standardUnitDirs are the directories that a standard sshd unit link points
// into (the default systemd unit path on the usrmerge layout).
var standardUnitDirs = []string{"/lib/systemd/system", "/usr/lib/systemd/system"}

func init() {
	for _, p := range unitSearchPaths {
		unitSSHDirs[p] = true
	}
	for p := range sshFileExact {
		fixedExact[p] = true
	}
}

// standardUsrmergeLink reports whether the symlink at s with target t is a
// standard usrmerge link of D5.
func standardUsrmergeLink(s, t string) bool {
	rel, ok := usrmergeLinks[s]
	return ok && (t == rel || t == "/"+rel)
}

// standardUnitLink reports whether the symlink at s with target t may sit at
// a unit position without making the run unclassifiable: a standard usrmerge
// link, or a standard sshd unit link of the default layout. The latter is
// either an alias directly in a unit search path (sshd.service ->
// /lib/systemd/system/ssh.service), or an enablement link named like its unit
// in a *.wants or *.requires directory of a unit search path. Both point to an
// sshd unit under a standard unit directory. Every other symlink at a unit
// position fails closed.
func standardUnitLink(s, t string) bool {
	if standardUsrmergeLink(s, t) {
		return true
	}
	dir, name := split(s)
	tdir, tname := split(t)
	if !sshdUnitNames[name] || !sshdUnitNames[tname] || !containsString(standardUnitDirs, tdir) {
		return false
	}
	if containsString(unitSearchPaths, dir) {
		return true
	}
	parent, list := split(dir)
	return containsString(unitSearchPaths, parent) &&
		(strings.HasSuffix(list, ".wants") || strings.HasSuffix(list, ".requires")) && tname == name
}

// unitPosition reports whether s is a directory or entry at or above an sshd
// unit position, or a usrmerge link: a unit directory (unitSSHDirs), a
// *.wants or *.requires directory, an sshd unit or drop-in entry, or a
// usrmerge link.
func unitPosition(s string) bool {
	return unitSSHDirs[s] || isUnitListDir(s) || sshdUnitEntry(s) || usrmergeLinks[s] != ""
}

// isUnitListDir reports whether s is a *.wants or *.requires directory of a
// systemd unit search path.
func isUnitListDir(s string) bool {
	dir, name := split(s)
	return containsString(unitSearchPaths, dir) &&
		(strings.HasSuffix(name, ".wants") || strings.HasSuffix(name, ".requires"))
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

// configSSHFile reports whether s is a fixed SSH configuration or login file
// position (D9): a literal file of sshFileExact or a home-relative login file.
// An AuthorizedKeysFile value such as /etc/ssh/authorized_keys/%u is not fixed
// here: its positions come from the derived set, so a directory that merely
// has an authorized_keys name does not make the run unclassifiable.
func configSSHFile(s string) bool {
	if sshFileExact[s] {
		return true
	}
	for _, suf := range fixedSuffixes {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
}

// fixedSSHFile reports whether s is a fixed SSH file position for the
// per-entry checks: a configuration or login file, or an sshd unit or
// enablement or alias entry that is not itself a drop-in directory.
func fixedSSHFile(s string) bool {
	if configSSHFile(s) {
		return true
	}
	_, name := split(s)
	return sshdUnitEntry(s) && !isSSHDDropInDir(name)
}

// configSSHDir reports whether s is a directory at or above a fixed SSH
// configuration or login file position: a configSSHDirs entry, /home/<name>
// or /home/<name>/.ssh.
func configSSHDir(s string) bool {
	if configSSHDirs[s] {
		return true
	}
	if rel, ok := strings.CutPrefix(s, "/home/"); ok {
		user, rest, nested := strings.Cut(rel, "/")
		return user != "" && (!nested || rest == ".ssh")
	}
	return false
}

// fixedSSHDir reports whether s is a directory at or above a fixed SSH
// position for the per-entry checks: a configuration directory or a unit
// position directory (usrmerge links, unit search paths, *.wants and
// *.requires directories).
func fixedSSHDir(s string) bool {
	return configSSHDir(s) || unitSSHDirs[s] || isUnitListDir(s)
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
	// derivedMemo holds the derived set's answer per path, so that each path
	// is asked once per run although the record sets overlap.
	derivedMemo map[string]SSHMatch
	// sshSymlink: a symlink at a configuration or login position, a symlink at
	// a unit position that is not a standard link, or a non-file record at a
	// configuration or login file position, exists in one of the record sets.
	// Its target is not resolved yet, so the whole run is unclassifiable (fail
	// closed, see RuleUnclassifiable).
	sshSymlink bool
}

func newClassifier(old, cur []fimscan.Record, opts Options) *classifier {
	c := &classifier{shadowed: map[string]bool{}, ssh: opts.SSH, derivedMemo: map[string]SSHMatch{}}
	sets := [][]fimscan.Record{old, cur}
	if opts.LatestComplete != nil {
		// Validated by Diff (checkLatest).
		sets = append(sets, opts.LatestComplete.Records)
	}
	for _, recs := range sets {
		for i := range recs {
			dir, name := split(string(recs[i].Path))
			if containsString(shadowedDirs, dir) {
				c.shadowed[name] = true
			}
			rec := &recs[i]
			if rec.Type == fimscan.TypeSymlink && c.runWideSymlink(rec) {
				c.sshSymlink = true
			}
			if rec.Type != fimscan.TypeFile && rec.Type != fimscan.TypeSymlink && c.configFilePosition(rec.Path) {
				c.sshSymlink = true
			}
		}
	}
	return c
}

// atSSHPosition reports whether the path is an SSH position of D9 for the
// per-entry check: a configuration or login file position, a directory at or
// above one, an sshd unit or drop-in entry, a unit position directory, or
// anything the derived set names, as far as the fixed patterns and the
// derived set know it.
func (c *classifier) atSSHPosition(p []byte) bool {
	s := string(p)
	if fixedSSHDir(s) || fixedSSHFile(s) || unitPosition(s) {
		return true
	}
	return c.derived(p) != SSHNone
}

// sshFilePosition reports whether the path is an SSH file position of D9 for
// the per-entry check: a fixed one, or one the derived set names as a file.
func (c *classifier) sshFilePosition(p []byte) bool {
	return fixedSSHFile(string(p)) || c.derived(p) == SSHFile
}

// runWideSymlink reports whether the symlink record rec makes the whole run
// unclassifiable: a symlink at a configuration or login position (fixed or
// derived), or at a unit position unless it is a standard link
// (standardUnitLink). The standard links are exactly the usrmerge links of D5
// and the standard sshd unit links; every other symlink at an SSH position
// fails closed.
func (c *classifier) runWideSymlink(rec *fimscan.Record) bool {
	s := string(rec.Path)
	if configSSHDir(s) || configSSHFile(s) || c.derived(rec.Path) != SSHNone {
		return true
	}
	return unitPosition(s) && !standardUnitLink(s, string(rec.Link))
}

// configFilePosition reports whether a non-file record at p makes the whole
// run unclassifiable: a fixed or derived configuration or login file
// position. Unit positions are per-entry only: the files behind a directory
// there are records of their own.
func (c *classifier) configFilePosition(p []byte) bool {
	return configSSHFile(string(p)) || c.derived(p) == SSHFile
}

// derived matches p against the derived SSH set, if there is a usable one. The
// answer is memoised per path, so the set is asked at most once per path.
func (c *classifier) derived(p []byte) SSHMatch {
	if c.ssh == nil {
		return SSHNone
	}
	if m, ok := c.derivedMemo[string(p)]; ok {
		return m
	}
	m := c.ssh.Match(bytes.Clone(p))
	c.derivedMemo[string(p)] = m
	return m
}

// classify returns the class of the deviation at path p and the rules that
// made it critical. old or cur is nil when the path is absent on that side.
//
// TODO(ADR 0015 D9 "Symlinks at or above SSH positions"): resolve such a
// symlink component by component against its record set, classify the
// resolved path and the entries below it, and report targets outside the
// scanned roots. Until then a symlink at a configuration or login position,
// or at a unit position other than the standard links, makes every deviation
// unclassifiable (sshSymlink), so nothing behind it is approved as a normal
// change. Known limit: this is not yet named in ADR 0015 "Honest limits".
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
	// D9: a symlink at an SSH position is critical; so is a record of
	// another non-file type at an SSH file position.
	for _, rec := range []*fimscan.Record{old, cur} {
		if rec == nil {
			continue
		}
		if rec.Type == fimscan.TypeSymlink && c.atSSHPosition(p) {
			r |= RuleSSHSymlink
		}
		if rec.Type != fimscan.TypeFile && rec.Type != fimscan.TypeSymlink && c.sshFilePosition(p) {
			r |= RuleSSHSymlink
		}
	}
	if c.sshSymlink {
		r |= RuleUnclassifiable
	}
	if c.ssh == nil {
		r |= RuleUnclassifiable
	} else if c.derived(p) == SSHFile {
		r |= RuleSSHDerived
	}
	if r != 0 {
		return ClassCritical, r
	}
	return ClassNormal, 0
}
