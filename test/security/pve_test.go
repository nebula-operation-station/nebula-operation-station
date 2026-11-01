// SPDX-License-Identifier: AGPL-3.0-or-later

// Acceptance tests for the Proxmox PVE collector deployment (ADR 0006,
// P1-14): the systemd unit, the installer's spool provisioning, the
// container and the release packaging. They read the deployment artifacts
// from the repository root and assert the security properties the ADR
// requires — a distinct UID/peercred role, the spool permissions, no
// collector network/capabilities or executor database access, and a locked
// startup. They run isolated (no network, no root).
package security

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecollect"
)

const collectorUnit = "deploy/systemd/nebula-pve-collector.service"

// readRepoFile reads a file from the repository root (two levels up from
// test/security) and returns it as a string.
func readRepoFile(t *testing.T, parts ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, parts...)...))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(parts...), err)
	}
	return string(b)
}

// unitDirective returns the value of the first occurrence of key in a
// systemd unit, joining backslash line continuations. It is "" if the key
// is absent.
func unitDirective(unit, key string) string {
	lines := strings.Split(unit, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, key+"=") {
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(line, key+"="))
		for strings.HasSuffix(val, "\\") && i+1 < len(lines) {
			val = strings.TrimSpace(strings.TrimSuffix(val, "\\")) + " " + strings.TrimSpace(lines[i+1])
			i++
		}
		return val
	}
	return ""
}

// TestPVECollectorUnitRunsAsDistinctUser: the collector runs as its own
// system user (nebula-pve-collector), not shared with the server, executor
// or discovery, and reaches the executor socket through the shared
// nebula-rpc group.
func TestPVECollectorUnitRunsAsDistinctUser(t *testing.T) {
	unit := readRepoFile(t, "deploy", "systemd", "nebula-pve-collector.service")
	if got := unitDirective(unit, "User"); got != "nebula-pve-collector" {
		t.Errorf("User = %q, want nebula-pve-collector (a distinct UID)", got)
	}
	if got := unitDirective(unit, "Group"); got != "nebula-pve-collector" {
		t.Errorf("Group = %q, want nebula-pve-collector", got)
	}
	if got := unitDirective(unit, "SupplementaryGroups"); got != "nebula-rpc" {
		t.Errorf("SupplementaryGroups = %q, want nebula-rpc", got)
	}
}

// TestPVECollectorUnitNoNetwork: the collector has no network — only the
// AF_UNIX family (for the executor socket) is allowed.
func TestPVECollectorUnitNoNetwork(t *testing.T) {
	unit := readRepoFile(t, "deploy", "systemd", "nebula-pve-collector.service")
	if got := unitDirective(unit, "RestrictAddressFamilies"); got != "AF_UNIX" {
		t.Errorf("RestrictAddressFamilies = %q, want exactly AF_UNIX (no network)", got)
	}
}

// TestPVECollectorUnitNoCapabilities: the collector holds no capabilities
// (ADR 0006: no capabilities).
func TestPVECollectorUnitNoCapabilities(t *testing.T) {
	unit := readRepoFile(t, "deploy", "systemd", "nebula-pve-collector.service")
	if got := unitDirective(unit, "CapabilityBoundingSet"); got != "" {
		t.Errorf("CapabilityBoundingSet = %q, want empty (no capabilities)", got)
	}
	if got := unitDirective(unit, "AmbientCapabilities"); got != "" {
		t.Errorf("AmbientCapabilities = %q, want empty (no capabilities)", got)
	}
}

// TestPVECollectorUnitNoExecutorDB: the collector never mounts or reads the
// executor's database; the spool is its only writable path.
func TestPVECollectorUnitNoExecutorDB(t *testing.T) {
	unit := readRepoFile(t, "deploy", "systemd", "nebula-pve-collector.service")
	if strings.Contains(unit, "/var/lib/nebula/executor") {
		t.Error("unit references /var/lib/nebula/executor; the collector must not access the executor DB")
	}
	if got := unitDirective(unit, "ReadWritePaths"); got != "/var/lib/nebula/pve" {
		t.Errorf("ReadWritePaths = %q, want /var/lib/nebula/pve", got)
	}
}

// TestPVECollectorUnitLockedStartup: the collector starts locked (no new
// privileges, read-only filesystem, no SUID/SGID, no W^X, seccomp).
func TestPVECollectorUnitLockedStartup(t *testing.T) {
	unit := readRepoFile(t, "deploy", "systemd", "nebula-pve-collector.service")
	for _, want := range []string{
		"NoNewPrivileges=yes",
		"ProtectSystem=strict",
		"ProtectHome=yes",
		"PrivateTmp=yes",
		"PrivateDevices=yes",
		"ProtectKernelTunables=yes",
		"ProtectKernelModules=yes",
		"ProtectKernelLogs=yes",
		"ProtectControlGroups=yes",
		"RestrictNamespaces=yes",
		"RestrictRealtime=yes",
		"RestrictSUIDSGID=yes",
		"LockPersonality=yes",
		"MemoryDenyWriteExecute=yes",
		"SystemCallArchitectures=native",
		"SystemCallFilter=@system-service",
		"LimitCORE=0",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit missing hardening directive %q", want)
		}
	}
}

// TestPVECollectorUnitSpool: the unit points the collector at the spool and
// the executor socket (matching docs/operator/proxmox.md).
func TestPVECollectorUnitSpool(t *testing.T) {
	unit := readRepoFile(t, "deploy", "systemd", "nebula-pve-collector.service")
	exec := unitDirective(unit, "ExecStart")
	for _, want := range []string{
		"-socket /run/nebula/executor.sock",
		"-executor-user nebula-executor",
		"-spool /var/lib/nebula/pve",
		"-interval 1m",
	} {
		if !strings.Contains(exec, want) {
			t.Errorf("ExecStart missing %q: %q", want, exec)
		}
	}
}

// TestPVECollectorSpoolModes: NewSpool lays out the spool with the ADR
// modes — root 0750 (setgid), results 0770 (setgid) — so the collector
// owns the writes and the shared nebula-rpc group (the server) can read the
// results.
func TestPVECollectorSpoolModes(t *testing.T) {
	dir := t.TempDir()
	s, err := pvecollect.NewSpool(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	root, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := root.Mode().Perm(); got != 0o750 {
		t.Errorf("spool root perm = %o, want 0750", got)
	}
	if root.Mode()&os.ModeSetgid == 0 {
		t.Error("spool root is not setgid")
	}

	results, err := os.Stat(filepath.Join(dir, "results"))
	if err != nil {
		t.Fatal(err)
	}
	if got := results.Mode().Perm(); got != 0o770 {
		t.Errorf("results dir perm = %o, want 0770", got)
	}
	if results.Mode()&os.ModeSetgid == 0 {
		t.Error("results dir is not setgid")
	}
}

// TestPVECollectorSpoolProvisioning: install.sh provisions the spool with
// the ADR ownership and modes (collector-owned, shared nebula-rpc group,
// setgid, not world-readable).
func TestPVECollectorSpoolProvisioning(t *testing.T) {
	install := readRepoFile(t, "deploy", "install.sh")
	root := regexp.MustCompile(`(?m)^install -d -m 2750 -o nebula-pve-collector -g nebula-rpc .*pve"\s*$`)
	if !root.MatchString(install) {
		t.Error("install.sh does not provision the PVE spool root (2750, nebula-pve-collector:nebula-rpc)")
	}
	results := regexp.MustCompile(`(?m)^install -d -m 2770 -o nebula-pve-collector -g nebula-rpc .*pve/results"\s*$`)
	if !results.MatchString(install) {
		t.Error("install.sh does not provision the PVE results dir (2770, nebula-pve-collector:nebula-rpc)")
	}
}

// TestPVECollectorInstallerUser: install.sh creates the collector as a
// distinct system user in the nebula-rpc group, and reserves the name (it
// cannot be an admin user).
func TestPVECollectorInstallerUser(t *testing.T) {
	install := readRepoFile(t, "deploy", "install.sh")
	// The collector is created as a system user in the nebula-rpc group.
	if !regexp.MustCompile(`useradd[^\n]*-G "\$\{group_name\}"[^\n]*nebula-pve-collector`).MatchString(install) {
		t.Error("install.sh does not create nebula-pve-collector in the nebula-rpc group")
	}
	// The reserved-user check must reject the collector as an admin user.
	if !regexp.MustCompile(`root\|nebula-server\|nebula-executor\|nebula-discovery\|nebula-pve-collector`).MatchString(install) {
		t.Error("install.sh does not reserve nebula-pve-collector as an admin user")
	}
}
