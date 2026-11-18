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

// The path unit's trigger is inert until a follow-up gives nebula-server a
// write path for it: the server runs with ProtectSystem=strict and may only
// write its own StateDirectory. The path unit and install.sh say so. When the
// server unit gains a write path for the trigger, this test fails and the
// notes must be updated together with it.
func TestOpsAgentPathTriggerIsInertUntilTheServerCanWriteIt(t *testing.T) {
	server := unitLines(t, "../systemd/nebula-server.service")
	if !slices.Contains(server, "ProtectSystem=strict") {
		t.Fatalf("nebula-server.service is no longer ProtectSystem=strict; revisit the trigger note")
	}
	trigDir := filepath.Dir(opsTriggerDir)
	under := func(p, dir string) bool { return p == dir || strings.HasPrefix(p, dir+"/") }
	for _, l := range server {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		switch k {
		case "ReadWritePaths", "StateDirectory", "RuntimeDirectory", "BindPaths":
			for _, p := range strings.Fields(v) {
				p = strings.TrimPrefix(strings.TrimPrefix(p, "-"), "+")
				if k == "StateDirectory" {
					p = "/var/lib/" + p
				}
				if under(trigDir, p) || under(p, trigDir) {
					t.Errorf("nebula-server.service now can write %s (%s); remove the inert-trigger notes and this test", trigDir, l)
				}
			}
		}
	}
	note := "inert"
	raw := readFile(t, opsPath)
	if !strings.Contains(raw, note) || !strings.Contains(raw, "nebula-server") {
		t.Errorf("path unit comment does not record that the trigger is inert until nebula-server gets a write path")
	}
	if b := installBlock(t, "ops agent install"); !strings.Contains(b, note) {
		t.Errorf("install.sh --ops-agent next steps do not say the path unit is inert for now")
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
