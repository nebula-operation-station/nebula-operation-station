// SPDX-License-Identifier: AGPL-3.0-or-later

package fimscan

import (
	_ "embed"
	"regexp"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// ActionID is the ID of the built-in read-only integrity scan action.
const ActionID = "fim.scan"

// ActionVersion is the version of the embedded script.
const ActionVersion = "1.0.0"

// DefaultProfileID is the ID of the default scan profile (ADR 0015 D5).
const DefaultProfileID = "fim-default-v1"

// LookBack is the fixed incremental look-back window of fim-default-v1
// (spec 07 v26-07-01): an incremental run hashes the files whose ctime or
// mtime lies inside it. The script holds the same value (WIN, in minutes).
const LookBack = 26 * time.Hour

// ActionTimeout bounds one run: the script stops hashing after 30 minutes
// (ADR 0015 D5) and then only writes metadata.
const ActionTimeout = 40 * time.Minute

// Script is the fim.scan 1.0.0 script (scripts/fim_scan.sh). It only reads
// and writes one fim-scan-v1 document to stdout.
//
//go:embed scripts/fim_scan.sh
var Script []byte

// DefaultProfile returns fim-default-v1 as shipped (ADR 0015 D5, Q1;
// spec 10 v26-10-02), in the order the script reports its roots.
//
// Nested roots (/etc/systemd/system, /etc/systemd/user, /boot/efi,
// /usr/lib/systemd/system) are scanned as part of their parent root unless
// they are mount points; the script then scans them as their own root.
// /etc/pve is excluded (Q1); the other default excludes (Python
// __pycache__, /etc/ld.so.cache, modules.* index files) are fixed in the
// script.
func DefaultProfile() Profile {
	r := func(p string) Root { return Root{Pattern: p} }
	o := func(p string) Root { return Root{Pattern: p, Optional: true} }
	roots := []Root{
		r("/etc"), r("/etc/systemd/system"), o("/etc/systemd/user"),
		r("/boot"), o("/boot/efi"),
		r("/bin"), r("/sbin"), r("/lib"),
		r("/usr/bin"), r("/usr/sbin"), r("/usr/lib"), r("/usr/lib/systemd/system"), o("/usr/libexec"),
		r("/usr/local/bin"), r("/usr/local/sbin"), r("/usr/local/lib"), o("/opt"),
		o("/var/spool/cron/crontabs"),
	}
	for _, base := range []string{"/root", "/home/*"} {
		for _, rel := range homeFiles {
			roots = append(roots, o(base+"/"+rel))
		}
	}
	return Profile{ID: DefaultProfileID, Roots: roots}
}

// homeFiles are the home-relative SSH access files of fim-default-v1, in
// the script's order (HOME_FILES).
var homeFiles = []string{".ssh/authorized_keys*", ".shosts", ".rhosts", ".k5login", ".ssh/known_hosts", ".ssh/known_hosts2"}

// Parameter patterns of the contract. They match exactly what the script
// accepts from the canonical parameters.
var (
	modeRe    = regexp.MustCompile(`^(full|incremental)$`)
	profileRe = regexp.MustCompile(`^fim-default-v1$`)
)

// Action returns the fim.scan read-only action contract in the form of the
// other built-in read actions (spec 10 v26-10-02). It is not yet part of
// actions.Builtin or of the read-lease allowlist; wiring it to the executor
// is a separate change.
func Action() actions.Action {
	return actions.Action{
		ID: ActionID, Version: ActionVersion, Title: "Integrity scan",
		Description: "Reads type, size, mode, owner, inode, times, symlink targets and SHA-256 of the files under the fixed roots of " +
			"profile fim-default-v1 (/etc, /boot, /usr/bin, /usr/sbin, /usr/lib, /usr/libexec, /bin, /sbin, /lib, /usr/local/{bin,sbin,lib}, /opt, " +
			"the crontab spool and the SSH access files under /root and /home/*), the mount points below them and the sshd configuration. " +
			"find -P -xdev, never follows symlinks, no path parameter, nothing written on the host. Needs root (sudo -n). Read-only.",
		Risk:     pb.RiskClass_RISK_CLASS_LOW,
		Timeout:  ActionTimeout,
		ReadOnly: true,
		Script:   Script,
		Params: []actions.Param{
			{Name: "mode", Label: "Mode (full or incremental)", Pattern: modeRe},
			{Name: "profile", Label: "Profile (fim-default-v1)", Pattern: profileRe},
		},
		Retry: actions.RetrySafe,
	}
}
