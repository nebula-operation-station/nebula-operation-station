// SPDX-License-Identifier: AGPL-3.0-or-later

package deb

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Paths of the vulnerability agent deployment (ADR 0011 Amendment 1, va08).
const (
	vulnUser       = "nebula-vuln-agent"
	vulnDataDir    = "/var/lib/nebula-vuln-agent"
	vulnEtcDir     = "/etc/nebula-vuln-agent"
	vulnConfigPath = vulnEtcDir + "/config.json"
	vulnPostinst   = "vuln-agent/postinst"
	vulnPrerm      = "vuln-agent/prerm"
	vulnUnit       = "../systemd/nebula-vuln-agent.service"
	vulnTimer      = "../systemd/nebula-vuln-agent.timer"
	pveUnit        = "../systemd/nebula-pve-collector.service"
	vulnConfigGo   = "../../cmd/nebula-vuln-agent/config.go"
	vulnMainGo     = "../../cmd/nebula-vuln-agent/main.go"
	goreleaserYAML = "../../.goreleaser.yaml"
)

// vulnStubs replace the commands of the vulnerability agent's maintainer
// scripts. getent and useradd share a users file, so a second run sees the
// user the first one created. install creates a directory (-d) or copies a
// file and applies -m, so modes stay observable without root; owners are
// only recorded. The service commands only record, so an enable or start
// through any of them is visible.
const vulnStubs = `
install|#!/bin/sh
printf 'install %s\n' "$*" >>"$STUB_LOG"
mode=""
dir=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-m" ]; then mode="$a"; fi
  if [ "$a" = "-d" ]; then dir=1; fi
  prev="$a"
done
for last; do :; done
if [ -n "$dir" ]; then
  mkdir -p "$last" || exit 1
else
  n=$#
  eval "src=\${$((n - 1))}"
  cp "$src" "$last" || exit 1
fi
if [ -n "$mode" ]; then chmod "$mode" "$last"; fi
exit 0
---
getent|#!/bin/sh
grep -qxF "$2" "$USERS_FILE"
---
useradd|#!/bin/sh
printf 'useradd %s\n' "$*" >>"$STUB_LOG"
for last; do :; done
printf '%s\n' "$last" >>"$USERS_FILE"
---
systemctl|#!/bin/sh
printf 'systemctl %s\n' "$*" >>"$STUB_LOG"
---
deb-systemd-invoke|#!/bin/sh
printf 'deb-systemd-invoke %s\n' "$*" >>"$STUB_LOG"
---
deb-systemd-helper|#!/bin/sh
printf 'deb-systemd-helper %s\n' "$*" >>"$STUB_LOG"
---
service|#!/bin/sh
printf 'service %s\n' "$*" >>"$STUB_LOG"
`

// vulnSandbox runs a vulnerability agent maintainer script with its paths
// moved into a temporary directory.
type vulnSandbox struct {
	root    string
	dataDir string
	etcDir  string
	log     string
	users   string
	env     []string
}

func newVulnSandbox(t *testing.T) *vulnSandbox {
	t.Helper()
	dir := t.TempDir()
	s := &vulnSandbox{
		root:    dir,
		dataDir: filepath.Join(dir, "var-lib-nebula-vuln-agent"),
		etcDir:  filepath.Join(dir, "etc-nebula-vuln-agent"),
		log:     filepath.Join(dir, "calls.log"),
		users:   filepath.Join(dir, "users"),
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, stub := range strings.Split(strings.TrimPrefix(vulnStubs, "\n"), "---\n") {
		name, body, ok := strings.Cut(stub, "|")
		if !ok {
			t.Fatalf("malformed stub %q", stub)
		}
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(s.users, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "run-systemd-system"), 0o755); err != nil {
		t.Fatal(err)
	}
	s.env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"STUB_LOG="+s.log,
		"USERS_FILE="+s.users,
	)
	return s
}

// script writes the named maintainer script with its absolute paths
// relocated into the sandbox and returns its path.
func (s *vulnSandbox) script(t *testing.T, name string) string {
	t.Helper()
	raw := readFile(t, name)
	stub := func(n string) string { return filepath.Join(s.root, "bin", n) }
	for _, r := range [][2]string{
		{"vuln_data_dir=" + vulnDataDir + "\n", "vuln_data_dir=" + s.dataDir + "\n"},
		{"vuln_etc_dir=" + vulnEtcDir + "\n", "vuln_etc_dir=" + s.etcDir + "\n"},
		{"[ -d /run/systemd/system ]", "[ -d " + filepath.Join(s.root, "run-systemd-system") + " ]"},
	} {
		if !strings.Contains(raw, r[0]) {
			if name == vulnPrerm && !strings.HasPrefix(r[0], "[ -d") {
				continue
			}
			t.Fatalf("%s misses %q, which the sandbox relocates", name, r[0])
		}
		raw = strings.ReplaceAll(raw, r[0], r[1])
	}
	for _, r := range [][2]string{
		{"/usr/bin/systemctl", stub("systemctl")},
		{"/bin/systemctl", stub("systemctl")},
		{"/usr/bin/deb-systemd-invoke", stub("deb-systemd-invoke")},
		{"/usr/bin/deb-systemd-helper", stub("deb-systemd-helper")},
		{"/usr/sbin/service", stub("service")},
	} {
		raw = strings.ReplaceAll(raw, r[0], r[1])
	}
	path := filepath.Join(s.root, filepath.Base(name))
	if err := os.WriteFile(path, []byte(raw), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// run executes a maintainer script and fails the test unless it exits 0: a
// failing maintainer script leaves the package half-configured.
func (s *vulnSandbox) run(t *testing.T, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command("sh", append([]string{s.script(t, name)}, args...)...)
	cmd.Env = s.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

func (s *vulnSandbox) calls(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(s.log)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(raw)
}

func (s *vulnSandbox) config() string { return filepath.Join(s.etcDir, "config.json") }

func modeOf(t *testing.T, path string) string {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return octalMode(fi)
}

// A first install creates the agent's own user (not in nebula-rpc: it never
// talks to the executor), its data directory 0700, the root-owned config
// directory the agent can only read, and the config skeleton.
func TestVulnAgentPostinstProvisionsUserDirsAndSkeleton(t *testing.T) {
	s := newVulnSandbox(t)
	s.run(t, vulnPostinst, "configure", "")
	calls := s.calls(t)
	for _, want := range []string{
		"useradd --system --home-dir " + s.dataDir + " --shell /usr/sbin/nologin " + vulnUser + "\n",
		"install -d -m 0700 -o " + vulnUser + " -g " + vulnUser + " " + s.dataDir + "\n",
		"install -d -m 0750 -o root -g " + vulnUser + " " + s.etcDir + "\n",
		" " + s.config() + "\n",
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("postinst calls lack %q:\n%s", want, calls)
		}
	}
	if strings.Contains(calls, "nebula-rpc") || strings.Contains(calls, " -G ") {
		t.Errorf("the agent user must get no supplementary group:\n%s", calls)
	}
	if !regexp.MustCompile(`(?m)^install -m 0640 -o root -g ` + vulnUser + ` \S+ ` + regexp.QuoteMeta(s.config()) + `$`).MatchString(calls) {
		t.Errorf("config skeleton not installed 0640 root:%s:\n%s", vulnUser, calls)
	}
	if got := modeOf(t, s.dataDir); got != "700" {
		t.Errorf("data dir mode %s, want 700", got)
	}
	if got := modeOf(t, s.etcDir); got != "750" {
		t.Errorf("config dir mode %s, want 750", got)
	}
	if got := modeOf(t, s.config()); got != "640" {
		t.Errorf("config mode %s, want 640", got)
	}
	if got := readFile(t, s.config()); got != vulnSkeleton(t, readFile(t, vulnPostinst)) {
		t.Errorf("config is not the skeleton:\n%s", got)
	}
	// No secret is created: the token and the LLM key are the admin's.
	entries, err := os.ReadDir(s.etcDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("config dir holds more than config.json: %v", entries)
	}
}

// The package never enables or starts the agent, on install or upgrade.
func TestVulnAgentPostinstNeverEnablesOrStarts(t *testing.T) {
	for _, args := range [][]string{{"configure", ""}, {"configure", "0.9.0"}} {
		s := newVulnSandbox(t)
		out := s.run(t, vulnPostinst, args...)
		calls := s.calls(t)
		for _, line := range strings.Split(strings.TrimSpace(calls), "\n") {
			for _, cmd := range []string{"systemctl ", "deb-systemd-invoke ", "deb-systemd-helper ", "service "} {
				if strings.HasPrefix(line, cmd) && line != "systemctl daemon-reload" {
					t.Errorf("postinst %v ran %q", args, line)
				}
			}
		}
		if !strings.Contains(out, "systemctl enable --now nebula-vuln-agent.timer") {
			t.Errorf("postinst %v does not tell the admin how to enable the timer:\n%s", args, out)
		}
	}
}

// An existing configuration is the admin's: never overwritten.
func TestVulnAgentPostinstKeepsExistingConfig(t *testing.T) {
	s := newVulnSandbox(t)
	s.run(t, vulnPostinst, "configure", "")
	if err := os.WriteFile(s.config(), []byte("{\"admin\": true}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(s.log, 0); err != nil {
		t.Fatal(err)
	}
	s.run(t, vulnPostinst, "configure", "0.9.0")
	if got := readFile(t, s.config()); got != "{\"admin\": true}\n" {
		t.Errorf("existing config overwritten: %q", got)
	}
	calls := s.calls(t)
	if strings.Contains(calls, "useradd") {
		t.Errorf("second run created the user again:\n%s", calls)
	}
	if strings.Contains(calls, s.config()) {
		t.Errorf("second run touched the config:\n%s", calls)
	}
}

// A drifted data dir mode is repaired: the agent's state is not for others.
func TestVulnAgentPostinstRepairsDataDirMode(t *testing.T) {
	s := newVulnSandbox(t)
	s.run(t, vulnPostinst, "configure", "")
	if err := os.Chmod(s.dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	s.run(t, vulnPostinst, "configure", "0.9.0")
	if got := modeOf(t, s.dataDir); got != "700" {
		t.Errorf("data dir mode %s, want 700", got)
	}
}

// A symlink or file at one of the agent's paths is left alone: install -d
// would follow a link and hand its target to the agent. The package still
// configures (exit 0) and points the admin to the path.
func TestVulnAgentPostinstLeavesNonDirectoryPathsAlone(t *testing.T) {
	for _, tc := range []struct{ name, path string }{
		{"data dir link", "data"},
		{"data dir file", "data-file"},
		{"config dir link", "etc"},
		{"config link", "config"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newVulnSandbox(t)
			target := filepath.Join(s.root, "target")
			if err := os.Mkdir(target, 0o755); err != nil {
				t.Fatal(err)
			}
			var bad string
			switch tc.path {
			case "data":
				bad = s.dataDir
				if err := os.Symlink(target, bad); err != nil {
					t.Fatal(err)
				}
			case "data-file":
				bad = s.dataDir
				if err := os.WriteFile(bad, []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "etc":
				bad = s.etcDir
				if err := os.Symlink(target, bad); err != nil {
					t.Fatal(err)
				}
			case "config":
				if err := os.Mkdir(s.etcDir, 0o750); err != nil {
					t.Fatal(err)
				}
				bad = s.config()
				if err := os.Symlink(filepath.Join(target, "c.json"), bad); err != nil {
					t.Fatal(err)
				}
			}
			out := s.run(t, vulnPostinst, "configure", "")
			if !strings.Contains(out, bad) {
				t.Errorf("warning does not name %s:\n%s", bad, out)
			}
			calls := s.calls(t)
			if strings.Contains(calls, "install ") {
				t.Errorf("install ran despite %s:\n%s", bad, calls)
			}
			if entries, _ := os.ReadDir(target); len(entries) != 0 || modeOf(t, target) != "755" {
				t.Errorf("link target touched: %v %s", entries, modeOf(t, target))
			}
		})
	}
}

// The package's skeleton is byte for byte the one install.sh --vuln-agent
// writes, so both ways of installing give the same starting point.
func TestVulnAgentSkeletonMatchesInstallScript(t *testing.T) {
	pkg := vulnSkeleton(t, readFile(t, vulnPostinst))
	inst := vulnSkeleton(t, installScript(t))
	if pkg != inst {
		t.Errorf("skeletons differ:\npostinst:\n%s\ninstall.sh:\n%s", pkg, inst)
	}
}

// vulnSkeleton returns the config skeleton here-document of a script.
func vulnSkeleton(t *testing.T, script string) string {
	t.Helper()
	return heredoc(t, script, "<<'EOF' # vuln agent config skeleton")
}

// The skeleton is strict JSON whose every key the agent knows (it rejects
// unknown fields), names the unit's one write path as data dir and keeps
// secrets in files next to it. The NOS URL is empty, so a run refuses to
// start until the admin sets it, and the LLM is off.
func TestVulnAgentSkeletonIsAValidStartingPoint(t *testing.T) {
	raw := vulnSkeleton(t, readFile(t, vulnPostinst))
	var c struct {
		DataDir string `json:"data_dir"`
		NOS     struct {
			URL       string `json:"url"`
			TokenFile string `json:"token_file"`
		} `json:"nos"`
		LLM struct {
			Enabled bool `json:"enabled"`
		} `json:"llm"`
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		t.Fatalf("skeleton: %v\n%s", err, raw)
	}
	if c.DataDir != vulnDataDir || c.NOS.URL != "" || c.NOS.TokenFile != vulnEtcDir+"/token" || c.LLM.Enabled {
		t.Errorf("skeleton values: %+v", c)
	}
	cfgGo := readFile(t, vulnConfigGo)
	for _, tag := range []string{`json:"data_dir"`, `json:"nos"`, `json:"url"`, `json:"token_file"`, `json:"llm"`, `json:"enabled"`} {
		if !strings.Contains(cfgGo, tag) {
			t.Errorf("cmd/nebula-vuln-agent no longer has the field %s the skeleton uses", tag)
		}
	}
	if !strings.Contains(readFile(t, vulnMainGo), `const defaultConfigPath = "`+vulnConfigPath+`"`) {
		t.Errorf("cmd/nebula-vuln-agent default config path is no longer %s", vulnConfigPath)
	}
}

// unitLines returns the non-comment, non-empty lines of a unit file.
func unitLines(t *testing.T, path string) []string {
	t.Helper()
	var out []string
	for _, l := range strings.Split(readFile(t, path), "\n") {
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out
}

// hardening returns the sandbox block of a unit: the lines from "# Hardening"
// to [Install] or the end, without comments.
func hardening(t *testing.T, path string, drop ...string) []string {
	t.Helper()
	_, rest, ok := strings.Cut(readFile(t, path), "\n# Hardening\n")
	if !ok {
		t.Fatalf("%s has no # Hardening block", path)
	}
	rest, _, _ = strings.Cut(rest, "[Install]")
	var out []string
	for _, l := range strings.Split(rest, "\n") {
		if l == "" || strings.HasPrefix(l, "#") || slices.ContainsFunc(drop, func(p string) bool { return strings.HasPrefix(l, p) }) {
			continue
		}
		out = append(out, l)
	}
	return out
}

// The unit runs the agent as its own user with no capabilities, a read-only
// system, network (it fetches feeds and talks to NOS and the LLM) and its
// data dir as the only writable path. It cannot see NOS state when it shares
// the host, and has no way into the executor socket.
func TestVulnAgentUnitIsHardened(t *testing.T) {
	lines := unitLines(t, vulnUnit)
	for _, want := range []string{
		"Type=oneshot",
		"User=" + vulnUser,
		"Group=" + vulnUser,
		"ExecStart=/usr/bin/nebula-vuln-agent -config " + vulnConfigPath + " run",
		"UMask=0077",
		"NoNewPrivileges=yes",
		"ProtectSystem=strict",
		"ProtectHome=yes",
		"PrivateTmp=yes",
		"PrivateDevices=yes",
		"RestrictSUIDSGID=yes",
		"CapabilityBoundingSet=",
		"AmbientCapabilities=",
		"RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
		"ReadWritePaths=" + vulnDataDir,
		"InaccessiblePaths=-/var/lib/nebula -/etc/nebula -/run/nebula",
	} {
		if !slices.Contains(lines, want) {
			t.Errorf("unit lacks %q", want)
		}
	}
	count := func(prefix string) int {
		n := 0
		for _, l := range lines {
			if strings.HasPrefix(l, prefix) {
				n++
			}
		}
		return n
	}
	for _, p := range []string{"ReadWritePaths=", "RestrictAddressFamilies=", "CapabilityBoundingSet=", "AmbientCapabilities=", "User=", "ExecStart="} {
		if n := count(p); n != 1 {
			t.Errorf("unit has %d %s lines, want 1", n, p)
		}
	}
	for _, bad := range []string{"SupplementaryGroups=", "PrivateNetwork=no", "User=root", "PermissionsStartOnly", "BindPaths=", "BindReadOnlyPaths=", "ReadOnlyPaths=", "StateDirectory=", "DynamicUser=", "ExecStartPre=", "ExecStartPost=", "Environment", "LoadCredential", "SetCredential", "[Install]"} {
		if count(bad) != 0 {
			t.Errorf("unit must not have %s", bad)
		}
	}
	// A oneshot has no start timeout by default; the run must end before
	// the next timer slot and well inside NOS's run abort.
	if !slices.Contains(lines, "TimeoutStartSec=6h") {
		t.Errorf("unit lacks TimeoutStartSec=6h")
	}
}

// Apart from the network and its own write path, the sandbox is exactly the
// collectors'.
func TestVulnAgentUnitSandboxEqualsCollectors(t *testing.T) {
	drop := []string{"ReadWritePaths=", "RestrictAddressFamilies=", "InaccessiblePaths="}
	got := hardening(t, vulnUnit, drop...)
	want := hardening(t, pveUnit, drop...)
	if len(got) == 0 || !slices.Equal(got, want) {
		t.Errorf("sandbox differs from the PVE collector's:\ngot  %q\nwant %q", got, want)
	}
}

// The timer runs the agent every 6 hours with a random delay, catches up a
// missed run after downtime, and is the only way the unit is started.
func TestVulnAgentTimerEverySixHoursRandomized(t *testing.T) {
	lines := unitLines(t, vulnTimer)
	for _, want := range []string{
		"[Timer]",
		"OnCalendar=*-*-* 00/6:00:00",
		"RandomizedDelaySec=1h",
		"Persistent=true",
		"Unit=nebula-vuln-agent.service",
		"[Install]",
		"WantedBy=timers.target",
	} {
		if !slices.Contains(lines, want) {
			t.Errorf("timer lacks %q", want)
		}
	}
}

// The prerm stops and disables the timer and the service on removal only;
// an upgrade keeps the admin's choice.
func TestVulnAgentPrermDisablesOnRemoveOnly(t *testing.T) {
	s := newVulnSandbox(t)
	s.run(t, vulnPrerm, "upgrade", "1.0.0")
	if calls := s.calls(t); calls != "" {
		t.Errorf("prerm upgrade ran: %s", calls)
	}
	s.run(t, vulnPrerm, "remove")
	if calls := s.calls(t); calls != "systemctl disable --now nebula-vuln-agent.timer nebula-vuln-agent.service\n" {
		t.Errorf("prerm remove calls: %q", calls)
	}
}

// goreleaserSection returns the list entry of .goreleaser.yaml that starts
// with "  - id: <id>" below the top-level key.
func goreleaserSection(t *testing.T, key, id string) string {
	t.Helper()
	raw := readFile(t, goreleaserYAML)
	_, rest, ok := strings.Cut(raw, "\n"+key+":\n")
	if !ok {
		t.Fatalf(".goreleaser.yaml has no %s", key)
	}
	if i := regexp.MustCompile(`(?m)^[a-z]`).FindStringIndex(rest); i != nil {
		rest = rest[:i[0]]
	}
	_, rest, ok = strings.Cut(rest, "  - id: "+id+"\n")
	if !ok {
		t.Fatalf(".goreleaser.yaml %s has no id %s", key, id)
	}
	if i := strings.Index(rest, "\n  - id: "); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// The agent ships as its own package for the VM nos-vuln: its binary, unit
// and timer and its own maintainer scripts, nothing of the server or the
// executor. The NOS package does not carry the agent binary.
func TestVulnAgentPackagedSeparately(t *testing.T) {
	build := goreleaserSection(t, "builds", "nebula-vuln-agent")
	for _, want := range []string{"    main: ./cmd/nebula-vuln-agent\n", "    binary: nebula-vuln-agent\n", "      - -trimpath\n"} {
		if !strings.Contains(build, want) {
			t.Errorf("build lacks %q", want)
		}
	}
	pkg := goreleaserSection(t, "nfpms", "nebula-vuln-agent")
	for _, want := range []string{
		"    package_name: nebula-vuln-agent\n",
		"    ids: [nebula-vuln-agent]\n",
		"    bindir: /usr/bin\n",
		"      - src: deploy/systemd/nebula-vuln-agent.service\n        dst: /lib/systemd/system/nebula-vuln-agent.service\n",
		"      - src: deploy/systemd/nebula-vuln-agent.timer\n        dst: /lib/systemd/system/nebula-vuln-agent.timer\n",
		"      postinstall: deploy/deb/vuln-agent/postinst\n",
		"      preremove: deploy/deb/vuln-agent/prerm\n",
	} {
		if !strings.Contains(pkg, want) {
			t.Errorf("nfpm nebula-vuln-agent lacks %q", want)
		}
	}
	if n := strings.Count(pkg, "      - src: "); n != 3 {
		t.Errorf("nfpm nebula-vuln-agent ships %d files, want unit, timer and guide", n)
	}
	main := goreleaserSection(t, "nfpms", "nebula")
	if strings.Contains(main, "vuln-agent") {
		t.Errorf("the NOS package must not carry the vulnerability agent")
	}
}
