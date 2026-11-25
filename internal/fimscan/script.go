// SPDX-License-Identifier: AGPL-3.0-or-later

package fimscan

import (
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
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
// (ADR 0015 D5) and then only writes metadata. It is actions.FimScanTimeout.
const ActionTimeout = actions.FimScanTimeout

// Script is the fim.scan 1.0.0 script. It is embedded in the catalog
// package (actions.FimScanScript, scripts/fim_scan.sh there) because this
// package imports that one; Script is the same slice, not a copy.
var Script = actions.FimScanScript

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

// Action returns the fim.scan read-only action contract (spec 10
// v26-10-02). The contract is defined once, as actions.FimScan; this
// function only forwards. It is not yet in actions.Builtin (see
// actions.FimScan). It is a durable job (ADR 0015 D5, decision (g) option 2;
// ActionTimeout is below the 6 h hostrun.MaxDurableTimeout) and in the
// read-lease allowlist (permit.ReadOnlyAllowlist, lease.go), whose pins
// (internal/permit/lease_fimscan.go) it must match.
func Action() actions.Action {
	return actions.FimScan()
}
