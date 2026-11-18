// SPDX-License-Identifier: AGPL-3.0-or-later

package deb

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Paths of the ops agent deployment (ADR 0016 D2, D3, D13).
const (
	opsUser        = "nebula-ops-agent"
	opsStateDir    = "/var/lib/nebula-ops-agent"
	opsEtcDir      = "/etc/nebula-ops-agent"
	opsConfigPath  = opsEtcDir + "/config.json"
	opsTriggerDir  = "/var/lib/nebula/opsagent/trigger"
	opsUnit        = "../systemd/nebula-ops-agent.service"
	opsTimer       = "../systemd/nebula-ops-agent.timer"
	opsPath        = "../systemd/nebula-ops-agent.path"
	opsMainGo      = "../../cmd/nebula-ops-agent/main.go"
	opsServiceName = "nebula-ops-agent.service"
)

// opsHardening is every sandbox line ADR 0016 D13 asks for, plus the
// vulnerability agent's sandbox the unit is derived from.
var opsHardening = []string{
	"Type=oneshot",
	"User=" + opsUser,
	"Group=" + opsUser,
	"ExecStart=/usr/bin/nebula-ops-agent -config " + opsConfigPath + " run",
	"TimeoutStartSec=45min",
	"UMask=0077",
	"LimitCORE=0",
	"NoNewPrivileges=yes",
	"ProtectSystem=strict",
	"ProtectHome=yes",
	"PrivateTmp=yes",
	"PrivateDevices=yes",
	"ProtectKernelTunables=yes",
	"ProtectKernelModules=yes",
	"ProtectKernelLogs=yes",
	"ProtectControlGroups=yes",
	"ProtectClock=yes",
	"ProtectHostname=yes",
	"RestrictNamespaces=yes",
	"RestrictRealtime=yes",
	"RestrictSUIDSGID=yes",
	"LockPersonality=yes",
	"MemoryDenyWriteExecute=yes",
	"SystemCallArchitectures=native",
	"SystemCallFilter=@system-service",
	"CapabilityBoundingSet=",
	"AmbientCapabilities=",
	"RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
	"IPAddressDeny=any",
	"IPAddressAllow=localhost",
	"InaccessiblePaths=-/var/lib/nebula -/etc/nebula -/run/nebula",
	"ProtectProc=invisible",
	"ProcSubset=pid",
	"ReadWritePaths=" + opsStateDir,
}

func countPrefix(lines []string, prefix string) int {
	n := 0
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}

// The unit carries every hardening line of D13, each exactly once, so a
// second line cannot widen what the first one sets.
func TestOpsAgentUnitHasEveryHardeningLine(t *testing.T) {
	lines := unitLines(t, opsUnit)
	for _, want := range opsHardening {
		if !slices.Contains(lines, want) {
			t.Errorf("unit lacks %q", want)
		}
		key, _, _ := strings.Cut(want, "=")
		if n := countPrefix(lines, key+"="); n != 1 {
			t.Errorf("unit has %d %s= lines, want 1", n, key)
		}
	}
}

// Nothing in the unit widens the sandbox, grants a group or a second write
// path, or makes the service start on its own.
func TestOpsAgentUnitHasNoWideningLine(t *testing.T) {
	lines := unitLines(t, opsUnit)
	for _, bad := range []string{
		"SupplementaryGroups=", "PrivateNetwork=no", "PermissionsStartOnly",
		"BindPaths=", "BindReadOnlyPaths=", "ReadOnlyPaths=", "StateDirectory=",
		"DynamicUser=", "ExecStartPre=", "ExecStartPost=", "Environment",
		"LoadCredential", "SetCredential", "IPAddressAllow=any", "[Install]",
		"WantedBy=", "RequiredBy=", "Alias=", "Also=",
	} {
		if n := countPrefix(lines, bad); n != 0 {
			t.Errorf("unit must not have %s", bad)
		}
	}
}

// The agent runs as its own user: never root, nebula-server or
// nebula-executor, and never with nebula-rpc as a group.
func TestOpsAgentUnitRunsAsItsOwnUser(t *testing.T) {
	for _, l := range unitLines(t, opsUnit) {
		for _, key := range []string{"User=", "Group="} {
			if v, ok := strings.CutPrefix(l, key); ok && v != opsUser {
				t.Errorf("unit runs as %q, want %s", l, opsUser)
			}
		}
		for _, bad := range []string{"nebula-server", "nebula-executor", "nebula-rpc", "root"} {
			if strings.Contains(l, bad) {
				t.Errorf("unit line names %s: %q", bad, l)
			}
		}
	}
}

// Apart from the network rules, its own write path and what it must not see
// of NOS, the sandbox is exactly the vulnerability agent's.
func TestOpsAgentUnitSandboxEqualsVulnAgent(t *testing.T) {
	drop := []string{"ReadWritePaths=", "IPAddressDeny=", "IPAddressAllow="}
	got := hardening(t, opsUnit, drop...)
	want := hardening(t, vulnUnit, drop...)
	if len(got) == 0 || !slices.Equal(got, want) {
		t.Errorf("sandbox differs from the vulnerability agent's:\ngot  %q\nwant %q", got, want)
	}
}

// The comment documents the admin's drop-in for the LLM address.
func TestOpsAgentUnitExplainsTheLLMDropIn(t *testing.T) {
	raw := readFile(t, opsUnit)
	for _, want := range []string{"systemctl edit nebula-ops-agent.service", "#     IPAddressAllow=<LLM address"} {
		if !strings.Contains(raw, want) {
			t.Errorf("unit comment lacks %q", want)
		}
	}
}

// The trigger directory the path unit watches lies below a path the agent's
// unit makes inaccessible, and outside the agent's one write path: only
// systemd sees it.
func TestOpsAgentCannotSeeTheTriggerPath(t *testing.T) {
	var watched []string
	for _, l := range unitLines(t, opsPath) {
		for _, k := range []string{"PathChanged=", "PathModified=", "PathExists=", "PathExistsGlob=", "DirectoryNotEmpty="} {
			if v, ok := strings.CutPrefix(l, k); ok {
				watched = append(watched, v)
			}
		}
	}
	if !slices.Equal(watched, []string{opsTriggerDir}) {
		t.Fatalf("path unit watches %q, want only PathChanged=%s", watched, opsTriggerDir)
	}
	var hidden []string
	for _, l := range unitLines(t, opsUnit) {
		if v, ok := strings.CutPrefix(l, "InaccessiblePaths="); ok {
			for _, p := range strings.Fields(v) {
				hidden = append(hidden, strings.TrimPrefix(p, "-"))
			}
		}
	}
	under := func(p, dir string) bool { return p == dir || strings.HasPrefix(p, dir+"/") }
	if !slices.ContainsFunc(hidden, func(h string) bool { return under(opsTriggerDir, h) }) {
		t.Errorf("trigger %s is not below an InaccessiblePaths entry %q", opsTriggerDir, hidden)
	}
	if under(opsTriggerDir, opsStateDir) || under(opsStateDir, filepath.Dir(opsTriggerDir)) {
		t.Errorf("trigger %s and state dir %s overlap", opsTriggerDir, opsStateDir)
	}
}

// The timer runs every 30 minutes with a random delay and no catch-up.
func TestOpsAgentTimerEveryThirtyMinutes(t *testing.T) {
	lines := unitLines(t, opsTimer)
	for _, want := range []string{
		"[Timer]",
		"OnCalendar=*-*-* *:00/30:00",
		"RandomizedDelaySec=5min",
		"Unit=" + opsServiceName,
		"[Install]",
		"WantedBy=timers.target",
	} {
		if !slices.Contains(lines, want) {
			t.Errorf("timer lacks %q", want)
		}
	}
	if n := countPrefix(lines, "Persistent="); n != 0 {
		t.Errorf("timer must not have Persistent=")
	}
}

// The path unit starts the agent's service on a change of the trigger.
func TestOpsAgentPathUnitStartsTheService(t *testing.T) {
	lines := unitLines(t, opsPath)
	for _, want := range []string{
		"[Path]",
		"PathChanged=" + opsTriggerDir,
		"Unit=" + opsServiceName,
		"[Install]",
		"WantedBy=multi-user.target",
	} {
		if !slices.Contains(lines, want) {
			t.Errorf("path unit lacks %q", want)
		}
	}
}

// The service timeout covers the agent's own run bound (20 calls of 90 s).
func TestOpsAgentTimeoutCoversTheRunBound(t *testing.T) {
	if !strings.Contains(readFile(t, opsMainGo), "const runTimeout = run.MaxLLMCallsPerRun * run.CallTimeout") {
		t.Errorf("cmd/nebula-ops-agent run bound changed; check TimeoutStartSec=45min")
	}
	raw, err := os.ReadFile("../../internal/opsagent/run/run.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"MaxLLMCallsPerRun = 20", "CallTimeout = 90 * time.Second"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("internal/opsagent/run no longer has %q; check TimeoutStartSec=45min", want)
		}
	}
}
