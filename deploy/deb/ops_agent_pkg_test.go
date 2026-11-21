// SPDX-License-Identifier: AGPL-3.0-or-later

package deb

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Maintainer scripts of the nebula-ops-agent package (ADR 0016 D13).
const (
	opsPostinst = "ops-agent/postinst"
	opsPrerm    = "ops-agent/prerm"
)

// opsSandbox runs an ops agent maintainer script with its paths moved into
// a temporary directory. It shares the stubs of the vulnerability agent's
// sandbox.
type opsSandbox struct {
	*vulnSandbox
	stateDir string
	opsEtc   string
}

func newOpsSandbox(t *testing.T) *opsSandbox {
	t.Helper()
	v := newVulnSandbox(t)
	return &opsSandbox{
		vulnSandbox: v,
		stateDir:    filepath.Join(v.root, "var-lib-nebula-ops-agent"),
		opsEtc:      filepath.Join(v.root, "etc-nebula-ops-agent"),
	}
}

func (s *opsSandbox) config() string { return filepath.Join(s.opsEtc, "config.json") }
func (s *opsSandbox) token() string  { return filepath.Join(s.opsEtc, "token") }

// run writes the named maintainer script with its absolute paths relocated
// into the sandbox, runs it and fails the test unless it exits 0: a failing
// maintainer script leaves the package half-configured.
func (s *opsSandbox) run(t *testing.T, name string, args ...string) string {
	t.Helper()
	raw := readFile(t, name)
	reloc := [][2]string{{"[ -d /run/systemd/system ]", "[ -d " + filepath.Join(s.root, "run-systemd-system") + " ]"}}
	if name == opsPostinst {
		reloc = append(reloc,
			[2]string{"ops_state_dir=" + opsStateDir + "\n", "ops_state_dir=" + s.stateDir + "\n"},
			[2]string{"ops_etc_dir=" + opsEtcDir + "\n", "ops_etc_dir=" + s.opsEtc + "\n"},
		)
	}
	for _, r := range reloc {
		if !strings.Contains(raw, r[0]) {
			t.Fatalf("%s misses %q, which the sandbox relocates", name, r[0])
		}
		raw = strings.ReplaceAll(raw, r[0], r[1])
	}
	for _, c := range []string{"systemctl", "deb-systemd-invoke", "deb-systemd-helper"} {
		raw = strings.ReplaceAll(raw, "/usr/bin/"+c, filepath.Join(s.root, "bin", c))
	}
	path := filepath.Join(s.root, "ops-"+filepath.Base(name))
	if err := os.WriteFile(path, []byte(raw), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", append([]string{path}, args...)...)
	cmd.Env = s.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// opsSkeleton returns the config skeleton here-document of a script.
func opsSkeleton(t *testing.T, script string) string {
	t.Helper()
	return heredoc(t, script, "<<'EOF' # ops agent config skeleton")
}

// A first install creates the agent's own user (no supplementary group, so
// never nebula-rpc), its state dir 0700, the root-owned config dir 0750 the
// agent can only read, and the config skeleton 0640. No secret is created.
func TestOpsAgentPostinstProvisionsUserDirsAndSkeleton(t *testing.T) {
	s := newOpsSandbox(t)
	s.run(t, opsPostinst, "configure", "")
	calls := s.calls(t)
	for _, want := range []string{
		"useradd --system --home-dir " + s.stateDir + " --shell /usr/sbin/nologin " + opsUser + "\n",
		"install -d -m 0700 -o " + opsUser + " -g " + opsUser + " " + s.stateDir + "\n",
		"install -d -m 0750 -o root -g " + opsUser + " " + s.opsEtc + "\n",
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("postinst calls lack %q:\n%s", want, calls)
		}
	}
	if !regexp.MustCompile(`(?m)^install -m 0640 -o root -g ` + opsUser + ` \S+ ` + regexp.QuoteMeta(s.config()) + `$`).MatchString(calls) {
		t.Errorf("config skeleton not installed 0640 root:%s:\n%s", opsUser, calls)
	}
	for _, bad := range []string{"nebula-rpc", " -G ", "nebula-server", "nebula-executor", "usermod"} {
		if strings.Contains(calls, bad) {
			t.Errorf("postinst calls contain %q:\n%s", bad, calls)
		}
	}
	for path, want := range map[string]string{s.stateDir: "700", s.opsEtc: "750", s.config(): "640"} {
		if got := modeOf(t, path); got != want {
			t.Errorf("%s mode %s, want %s", path, got, want)
		}
	}
	if got := readFile(t, s.config()); got != opsSkeleton(t, readFile(t, opsPostinst)) {
		t.Errorf("config is not the skeleton:\n%s", got)
	}
	entries, err := os.ReadDir(s.opsEtc)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("config dir holds more than config.json: %v", entries)
	}
}

// Neither install nor upgrade enables or starts the timer, the path unit or
// the service; the output tells the admin how to.
func TestOpsAgentPostinstNeverEnablesOrStarts(t *testing.T) {
	for _, args := range [][]string{{"configure", ""}, {"configure", "0.9.0"}} {
		s := newOpsSandbox(t)
		out := s.run(t, opsPostinst, args...)
		for _, line := range strings.Split(strings.TrimSpace(s.calls(t)), "\n") {
			for _, cmd := range []string{"systemctl ", "deb-systemd-invoke ", "deb-systemd-helper ", "service "} {
				if strings.HasPrefix(line, cmd) && line != "systemctl daemon-reload" {
					t.Errorf("postinst %v ran %q", args, line)
				}
			}
		}
		for _, want := range []string{"systemctl enable --now nebula-ops-agent.timer", "systemctl enable --now nebula-ops-agent.path"} {
			if !strings.Contains(out, want) {
				t.Errorf("postinst %v does not tell the admin %q:\n%s", args, want, out)
			}
		}
	}
}

// An existing configuration is the admin's: never overwritten.
func TestOpsAgentPostinstKeepsExistingConfig(t *testing.T) {
	s := newOpsSandbox(t)
	s.run(t, opsPostinst, "configure", "")
	if err := os.WriteFile(s.config(), []byte("{\"admin\": true}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(s.log, 0); err != nil {
		t.Fatal(err)
	}
	s.run(t, opsPostinst, "configure", "0.9.0")
	if got := readFile(t, s.config()); got != "{\"admin\": true}\n" {
		t.Errorf("existing config overwritten: %q", got)
	}
	calls := s.calls(t)
	if strings.Contains(calls, "useradd") || strings.Contains(calls, s.config()) {
		t.Errorf("second run recreated the user or touched the config:\n%s", calls)
	}
}

// A token file other than 0600 is reported; it is never read or changed.
func TestOpsAgentPostinstWarnsAboutAnOpenToken(t *testing.T) {
	for _, tc := range []struct {
		mode os.FileMode
		want string
		warn bool
	}{{0o600, "600", false}, {0o640, "640", true}, {0o644, "644", true}} {
		s := newOpsSandbox(t)
		s.run(t, opsPostinst, "configure", "")
		if err := os.WriteFile(s.token(), []byte("x"), tc.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(s.token(), tc.mode); err != nil {
			t.Fatal(err)
		}
		out := s.run(t, opsPostinst, "configure", "0.9.0")
		if got := strings.Contains(out, s.token()+" has mode"); got != tc.warn {
			t.Errorf("mode %s: warning %v, want %v:\n%s", tc.want, got, tc.warn, out)
		}
		if got := modeOf(t, s.token()); got != tc.want {
			t.Errorf("token mode changed from %s to %s", tc.want, got)
		}
		if readFile(t, s.token()) != "x" {
			t.Errorf("token content changed")
		}
	}
}

// A symlink at one of the agent's paths is left alone (install -d would
// follow it); the package still configures and names the path.
func TestOpsAgentPostinstLeavesNonDirectoryPathsAlone(t *testing.T) {
	for _, which := range []string{"state", "etc", "config", "token"} {
		t.Run(which, func(t *testing.T) {
			s := newOpsSandbox(t)
			target := filepath.Join(s.root, "target")
			if err := os.Mkdir(target, 0o755); err != nil {
				t.Fatal(err)
			}
			bad := map[string]string{"state": s.stateDir, "etc": s.opsEtc, "config": s.config(), "token": s.token()}[which]
			if which == "config" || which == "token" {
				if err := os.Mkdir(s.opsEtc, 0o750); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(target, bad); err != nil {
				t.Fatal(err)
			}
			out := s.run(t, opsPostinst, "configure", "")
			if !strings.Contains(out, bad) {
				t.Errorf("warning does not name %s:\n%s", bad, out)
			}
			if which != "token" {
				if calls := s.calls(t); strings.Contains(calls, "install ") {
					t.Errorf("install ran despite %s:\n%s", bad, calls)
				}
			}
			if entries, _ := os.ReadDir(target); len(entries) != 0 || modeOf(t, target) != "755" {
				t.Errorf("link target touched")
			}
		})
	}
}

// Removal stops and disables all three units; an upgrade keeps the admin's
// choice. Configuration, token, state and user stay.
func TestOpsAgentPrermDisablesOnRemoveOnly(t *testing.T) {
	s := newOpsSandbox(t)
	s.run(t, opsPrerm, "upgrade", "1.0.0")
	if calls := s.calls(t); calls != "" {
		t.Errorf("prerm upgrade ran: %s", calls)
	}
	s.run(t, opsPrerm, "remove")
	if calls := s.calls(t); calls != "systemctl disable --now nebula-ops-agent.timer nebula-ops-agent.path nebula-ops-agent.service\n" {
		t.Errorf("prerm remove calls: %q", calls)
	}
	for _, l := range strings.Split(readFile(t, opsPrerm), "\n") {
		if strings.HasPrefix(l, "#") {
			continue
		}
		for _, bad := range []string{"rm ", "userdel", opsEtcDir, opsStateDir} {
			if strings.Contains(l, bad) {
				t.Errorf("prerm must not run %q: %q", bad, l)
			}
		}
	}
}

// The skeleton is strict JSON with exactly the agent's config fields: the
// NOS URL is empty (the agent refuses to run until the admin sets it), the
// token is a file next to it, the state dir is the unit's one write path.
func TestOpsAgentSkeletonIsAValidStartingPoint(t *testing.T) {
	raw := opsSkeleton(t, readFile(t, opsPostinst))
	var c struct {
		NOSBaseURL   string `json:"nos_base_url"`
		NOSTokenFile string `json:"nos_token_file"`
		StateDir     string `json:"state_dir"`
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		t.Fatalf("skeleton: %v\n%s", err, raw)
	}
	if c.NOSBaseURL != "" || c.NOSTokenFile != opsEtcDir+"/token" || c.StateDir != opsStateDir {
		t.Errorf("skeleton values: %+v", c)
	}
	cfgGo := readFile(t, "../../cmd/nebula-ops-agent/config.go")
	for _, tag := range []string{`json:"nos_base_url"`, `json:"nos_token_file"`, `json:"state_dir"`} {
		if !strings.Contains(cfgGo, tag) {
			t.Errorf("cmd/nebula-ops-agent no longer has the field %s the skeleton uses", tag)
		}
	}
}

// The admin hints of the package and of install.sh --ops-agent name the
// token path that exists: nebula-server -api-token and server.json, never a
// web UI. Both name the loopback base URL example and the plain-http rule for
// llm_credential_file; neither hint suggests the hostname localhost for
// nos_base_url, which the agent refuses.
func TestOpsAgentHintsNameTheRealTokenPath(t *testing.T) {
	s := newOpsSandbox(t)
	hints := map[string]string{
		"postinst":   s.run(t, opsPostinst, "configure", ""),
		"install.sh": installBlock(t, "ops agent install"),
	}
	for name, hint := range hints {
		if strings.Contains(strings.ToLower(hint), "web ui") {
			t.Errorf("%s hint names a web UI for the ops token; it comes from nebula-server -api-token", name)
		}
		for _, want := range []string{
			"nebula-server -api-token ops-agent:ops.read,ops.notes.write",
			"server.json",
			"http://127.0.0.1:8080",
			"llm_credential_file",
		} {
			if !strings.Contains(hint, want) {
				t.Errorf("%s hint lacks %q:\n%s", name, want, hint)
			}
		}
		if strings.Contains(hint, "http://localhost") {
			t.Errorf("%s hint suggests http://localhost; the agent accepts only a loopback IP", name)
		}
	}
}

// install.sh --ops-agent renders the same skeleton as the package.
func TestOpsAgentSkeletonMatchesInstallScript(t *testing.T) {
	if pkg, inst := opsSkeleton(t, readFile(t, opsPostinst)), opsSkeleton(t, installScript(t)); pkg != inst {
		t.Errorf("skeletons differ:\npostinst:\n%s\ninstall.sh:\n%s", pkg, inst)
	}
}

// installBlock returns the part of install.sh between "# begin: <name>"
// and "# end: <name>".
func installBlock(t *testing.T, name string) string {
	t.Helper()
	_, rest, ok := strings.Cut(installScript(t), "# begin: "+name+"\n")
	if !ok {
		t.Fatalf("install.sh has no block %q", name)
	}
	body, _, ok := strings.Cut(rest, "# end: "+name+"\n")
	if !ok {
		t.Fatalf("install.sh block %q is not closed", name)
	}
	return body
}

// install.sh --ops-agent provisions like the package, installs the three
// units and enables none of them.
func TestOpsAgentInstallScriptNeverEnables(t *testing.T) {
	b := installBlock(t, "ops agent install")
	for _, want := range []string{
		"ops_units=(nebula-ops-agent.service nebula-ops-agent.timer nebula-ops-agent.path)",
		`useradd --system --home-dir "${ops_state_dir}" --shell /usr/sbin/nologin nebula-ops-agent`,
		`install -d -m 0700 -o nebula-ops-agent -g nebula-ops-agent "${ops_state_dir}"`,
		`install -d -m 0750 -o root -g nebula-ops-agent "${ops_etc_dir}"`,
		"install -m 0640 -o root -g nebula-ops-agent",
		"sudo systemctl enable --now nebula-ops-agent.timer",
		"sudo systemctl enable --now nebula-ops-agent.path",
		"IPAddressAllow=",
	} {
		if !strings.Contains(b, want) {
			t.Errorf("install.sh --ops-agent lacks %q", want)
		}
	}
	for _, l := range strings.Split(b, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "systemctl ") && l != "systemctl daemon-reload" {
			t.Errorf("install.sh --ops-agent runs %q", l)
		}
		if strings.HasPrefix(l, "useradd") && strings.Contains(l, "-G") {
			t.Errorf("install.sh --ops-agent adds a group: %q", l)
		}
	}
}

// install.sh --remove-ops-agent stops and disables the units before it
// deletes them and the binary; it keeps the configuration, the token, the
// state and the user.
func TestOpsAgentInstallScriptRemovalKeepsConfiguration(t *testing.T) {
	b := installBlock(t, "ops agent removal")
	disable := "systemctl disable --now nebula-ops-agent.timer nebula-ops-agent.path nebula-ops-agent.service"
	di, ri := strings.Index(b, disable), strings.Index(b, "rm -f ")
	if di < 0 || ri < 0 || di > ri {
		t.Errorf("removal must run %q before deleting files", disable)
	}
	for _, want := range []string{"/usr/bin/nebula-ops-agent", `"${ops_unit_dir}/${unit}"`, "systemctl daemon-reload"} {
		if !strings.Contains(b, want) {
			t.Errorf("removal lacks %q", want)
		}
	}
	for _, bad := range []string{"rm -r", "rm -rf", "userdel", "groupdel", `rm -f "${ops_etc_dir}`, `rm -f "${ops_state_dir}`, "/etc/nebula-ops-agent", "/var/lib/nebula-ops-agent"} {
		if strings.Contains(b, bad) {
			t.Errorf("removal must not contain %q", bad)
		}
	}
}

// The ops agent options parse, refuse every other option, and a dry run
// changes nothing and enables nothing.
func TestOpsAgentInstallScriptOptions(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Fatalf("bash is required: %v", err)
	}
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"--ops-agent"}, 0, "would install nebula-ops-agent, its unit, timer and path unit (not enabled)"},
		{[]string{"--remove-ops-agent"}, 0, "keeping its configuration, state and user"},
		{[]string{"--ops-agent", "--remove-ops-agent"}, 2, "take no other option"},
		{[]string{"--ops-agent", "--from-package"}, 2, "take no other option"},
		{[]string{"--ops-agent", "--rp-id", "nos.lab"}, 2, "take no other option"},
		{[]string{"--remove-ops-agent", "--admin-users", "alice"}, 2, "take no other option"},
		{[]string{"--vuln-agent", "--ops-agent"}, 2, "--vuln-agent takes no other option"},
	} {
		cmd := exec.Command("bash", append([]string{"../install.sh"}, tc.args...)...)
		cmd.Env = append(os.Environ(), "NEBULA_INSTALL_DRY_RUN=1")
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		if code != tc.code || !strings.Contains(string(out), tc.want) {
			t.Errorf("%v: exit %d, want %d with %q:\n%s", tc.args, code, tc.code, tc.want, out)
		}
	}
}

// The ops agent's user can never be an admin user of the executor.
func TestOpsAgentUserIsNoAdminUser(t *testing.T) {
	if !regexp.MustCompile(`(?m)^\s+(\S+\|)?nebula-ops-agent(\|\S+)?\)$`).MatchString(installScript(t)) {
		t.Errorf("install.sh does not refuse nebula-ops-agent as an admin user")
	}
}
