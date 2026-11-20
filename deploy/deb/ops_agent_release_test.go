// SPDX-License-Identifier: AGPL-3.0-or-later

package deb

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The release builds the ops agent (static, -trimpath, no version flags:
// its import boundary, ADR 0016 D2, has no internal/version) and the
// tarball carries it with its unit, timer, path unit and maintainer
// scripts, for install.sh --ops-agent. The NOS package and image do not
// carry the agent binary.
func TestOpsAgentBuiltIntoTheTarball(t *testing.T) {
	build := goreleaserSection(t, "builds", "nebula-ops-agent")
	for _, want := range []string{"    main: ./cmd/nebula-ops-agent\n", "    binary: nebula-ops-agent\n", "      - -trimpath\n", "      - linux\n"} {
		if !strings.Contains(build, want) {
			t.Errorf("build lacks %q", want)
		}
	}
	if strings.Contains(build, "internal/version") {
		t.Errorf("build sets internal/version, which is outside the agent's import boundary")
	}
	archive := goreleaserSection(t, "archives", "nebula")
	if strings.Contains(archive, "    ids:") {
		t.Errorf("the tarball is restricted to some builds; it must carry nebula-ops-agent")
	}
	for _, want := range []string{
		"      - src: deploy/systemd/*\n        dst: deploy/systemd/\n",
		"      - src: deploy/deb/ops-agent/postinst\n        dst: deploy/deb/ops-agent/postinst\n",
		"      - src: deploy/deb/ops-agent/prerm\n        dst: deploy/deb/ops-agent/prerm\n",
		"      - src: deploy/*.sh\n        dst: deploy/\n",
	} {
		if !strings.Contains(archive, want) {
			t.Errorf("tarball lacks %q", want)
		}
	}
	// The unit files the archive glob picks up exist under these names.
	for _, p := range []string{opsUnit, opsTimer, opsPath, opsPostinst, opsPrerm} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("shipped file missing: %v", err)
		}
	}
	main := goreleaserSection(t, "nfpms", "nebula")
	if strings.Contains(main, "ops-agent") {
		t.Errorf("the NOS package must not carry the ops agent")
	}
	if strings.Contains(goreleaserSection(t, "dockers", "nebula"), "ops-agent") {
		t.Errorf("the image must not carry the ops agent")
	}
}

// The ops agent has its own .deb like the vulnerability agent: binary in
// /usr/bin, unit, timer and path unit in /lib/systemd/system, the guide, and
// the tested maintainer scripts, which enable nothing.
func TestOpsAgentPackagedLikeTheVulnAgent(t *testing.T) {
	pkg := goreleaserSection(t, "nfpms", "nebula-ops-agent")
	for _, want := range []string{
		"    package_name: nebula-ops-agent\n",
		"    ids: [nebula-ops-agent]\n",
		"    file_name_template: \"nebula-ops-agent_{{ .Version }}_{{ .Arch }}\"\n",
		"    formats: [deb]\n",
		"    bindir: /usr/bin\n",
		"      - src: deploy/systemd/nebula-ops-agent.service\n        dst: /lib/systemd/system/nebula-ops-agent.service\n",
		"      - src: deploy/systemd/nebula-ops-agent.timer\n        dst: /lib/systemd/system/nebula-ops-agent.timer\n",
		"      - src: deploy/systemd/nebula-ops-agent.path\n        dst: /lib/systemd/system/nebula-ops-agent.path\n",
		"      - src: docs/admin/guide.md\n        dst: /usr/share/doc/nebula-ops-agent/guide.md\n",
		"    scripts:\n      postinstall: deploy/deb/ops-agent/postinst\n      preremove: deploy/deb/ops-agent/prerm\n",
	} {
		if !strings.Contains(pkg, want) {
			t.Errorf("nebula-ops-agent package lacks %q", want)
		}
	}
	for _, field := range []string{"vendor:", "homepage:", "maintainer:", "license: AGPL-3.0-or-later", "section: admin"} {
		if !strings.Contains(pkg, "    "+field) {
			t.Errorf("nebula-ops-agent package lacks %q", field)
		}
	}
	// Only its own binary and units; no config, token or setuid file: the
	// postinst writes the skeleton, the admin the token.
	for _, bad := range []string{"install.sh", "binaries.txt", "nebula-server", "nebula-executor", "vuln-agent", "/etc/nebula-ops-agent", "file_info: {mode: 06"} {
		if strings.Contains(pkg, bad) {
			t.Errorf("nebula-ops-agent package must not carry %q", bad)
		}
	}
}

// The trigger lies in nebula-server's own StateDirectory, and the server unit
// gains no write path for it (ADR 0016 amendment 2026-11-19): it stays
// ProtectSystem=strict with StateDirectory=nebula/server as its only writable
// location. This replaces the earlier check that the trigger was inert while
// the server could not write /var/lib/nebula/opsagent; the "inert" notes in
// the path unit and install.sh are gone with it.
func TestOpsAgentTriggerIsInTheServerStateDirWithoutNewWritePaths(t *testing.T) {
	server := unitLines(t, "../systemd/nebula-server.service")
	if !slices.Contains(server, "ProtectSystem=strict") {
		t.Fatalf("nebula-server.service is no longer ProtectSystem=strict")
	}
	var stateDirs []string
	for _, l := range server {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		switch k {
		case "StateDirectory":
			stateDirs = append(stateDirs, strings.Fields(v)...)
		case "ReadWritePaths", "BindPaths", "RuntimeDirectory", "CacheDirectory", "LogsDirectory", "ConfigurationDirectory":
			t.Errorf("nebula-server.service gained a write path: %q", l)
		}
	}
	if !slices.Equal(stateDirs, []string{"nebula/server"}) {
		t.Fatalf("nebula-server.service StateDirectory = %q, want only nebula/server", stateDirs)
	}
	if filepath.Dir(opsTriggerPath) != "/var/lib/"+stateDirs[0] {
		t.Errorf("trigger %s is not in the server's StateDirectory /var/lib/%s", opsTriggerPath, stateDirs[0])
	}
	if raw := readFile(t, opsPath); strings.Contains(raw, "inert") {
		t.Errorf("path unit comment still calls the trigger inert")
	}
	b := installBlock(t, "ops agent install")
	if strings.Contains(b, "inert") || strings.Contains(b, "/var/lib/nebula/opsagent") {
		t.Errorf("install.sh --ops-agent next steps still call the path unit inert or name the old trigger path")
	}
}

// opsRemoval runs install.sh's removal block against a temporary binary and
// unit directory, with stub dpkg and systemctl that log their calls.
func opsRemoval(t *testing.T, dpkgOut string, dpkgCode int) (out string, code int, calls string, bin string) {
	t.Helper()
	dir := t.TempDir()
	stubs := filepath.Join(dir, "stubs")
	units := filepath.Join(dir, "units")
	bin = filepath.Join(dir, "nebula-ops-agent")
	log := filepath.Join(dir, "calls")
	for _, d := range []string{stubs, units} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(bin, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(units, "nebula-ops-agent.service"), []byte("[Unit]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stub := func(name, body string) {
		if err := os.WriteFile(filepath.Join(stubs, name), []byte("#!/bin/sh\necho \""+name+" $*\" >> '"+log+"'\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	stub("systemctl", "exit 0\n")
	stub("dpkg", "printf '%s' '"+dpkgOut+"'\nexit "+strconv.Itoa(dpkgCode)+"\n")

	block := installBlock(t, "ops agent removal")
	const binLine = "ops_bin=/usr/bin/nebula-ops-agent\n"
	if !strings.Contains(block, binLine) {
		t.Fatalf("removal block lacks %q", binLine)
	}
	block = strings.Replace(block, binLine, "ops_bin='"+bin+"'\n", 1)
	script := "set -euo pipefail\nremove_ops_agent=1\nops_unit_dir='" + units + "'\n" + block + "exit 3\n"
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = []string{"PATH=" + stubs + ":/usr/bin:/bin", "LC_ALL=C"}
	b, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	c, err := os.ReadFile(log)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b), code, string(c), bin
}

// --remove-ops-agent refuses when a Debian package owns the binary, so
// dpkg's file list stays in sync; the admin is told to use apt remove. It
// stops nothing and deletes nothing in that case.
func TestOpsAgentRemovalRefusesAPackageInstall(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Fatalf("bash is required: %v", err)
	}
	for _, owner := range []string{"nebula-ops-agent", "nebula-ops-agent:amd64"} {
		out, code, calls, bin := opsRemoval(t, owner+": /usr/bin/nebula-ops-agent\n", 0)
		if code != 1 || !strings.Contains(out, "sudo apt remove nebula-ops-agent") {
			t.Errorf("%s: exit %d, want 1 with the apt remove hint:\n%s", owner, code, out)
		}
		if strings.Contains(calls, "systemctl") {
			t.Errorf("%s: refused removal still ran systemctl: %q", owner, calls)
		}
		if _, err := os.Stat(bin); err != nil {
			t.Errorf("%s: refused removal deleted the binary: %v", owner, err)
		}
	}
}

// Without a package owning the binary (tarball install), --remove-ops-agent
// disables the units and deletes them and the binary.
func TestOpsAgentRemovalProceedsForATarballInstall(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Fatalf("bash is required: %v", err)
	}
	out, code, calls, bin := opsRemoval(t, "", 1)
	if code != 0 || !strings.Contains(out, "nebula-ops-agent removed") {
		t.Errorf("exit %d, want 0:\n%s", code, out)
	}
	if !strings.Contains(calls, "systemctl disable --now nebula-ops-agent.timer nebula-ops-agent.path nebula-ops-agent.service\n") {
		t.Errorf("removal did not disable the units: %q", calls)
	}
	if _, err := os.Stat(bin); !os.IsNotExist(err) {
		t.Errorf("removal kept the binary: %v", err)
	}
}
