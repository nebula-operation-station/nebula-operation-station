// SPDX-License-Identifier: AGPL-3.0-or-later

package deb

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// opsServerPath matches the NOS server's and executor's directories
// (/etc/nebula, /var/lib/nebula, /run/nebula, the ones InaccessiblePaths hides)
// as a whole path segment, so that /etc/nebula-ops-agent is not mistaken for
// /etc/nebula.
var opsServerPath = regexp.MustCompile(`(?:^|[^\w./-])(/etc/nebula|/var/lib/nebula|/run/nebula)(?:$|[^\w.-])`)

// underDir reports whether p is dir or lies below it, segment-wise.
func underDir(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+"/")
}

// unitValues returns every value of key in the unit's non-comment lines,
// split on whitespace, in file order.
func unitValues(t *testing.T, path, key string) []string {
	t.Helper()
	var out []string
	for _, l := range unitLines(t, path) {
		if v, ok := strings.CutPrefix(l, key+"="); ok {
			out = append(out, strings.Fields(v)...)
		}
	}
	return out
}

// unitConfigDir returns the directory of the -config argument in ExecStart.
func unitConfigDir(t *testing.T, path string) string {
	t.Helper()
	for _, l := range unitLines(t, path) {
		v, ok := strings.CutPrefix(l, "ExecStart=")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		for i := range f {
			if f[i] == "-config" && i+1 < len(f) {
				return filepath.Dir(f[i+1])
			}
		}
	}
	t.Fatalf("%s has no ExecStart with -config", path)
	return ""
}

// The state dir the skeleton names is the one writable path of the unit, and
// the token file and the configuration directory are reachable: neither lies
// below an InaccessiblePaths entry, and neither lies below the writable path.
func TestOpsAgentSandboxAllowsEveryConfiguredPath(t *testing.T) {
	var skel struct {
		NOSTokenFile string `json:"nos_token_file"`
		StateDir     string `json:"state_dir"`
	}
	if err := json.Unmarshal([]byte(opsSkeleton(t, readFile(t, opsPostinst))), &skel); err != nil {
		t.Fatalf("skeleton: %v", err)
	}
	rw := unitValues(t, opsUnit, "ReadWritePaths")
	if !slices.Equal(rw, []string{skel.StateDir}) {
		t.Fatalf("ReadWritePaths = %q, want exactly the skeleton state_dir %q", rw, skel.StateDir)
	}
	inacc := unitValues(t, opsUnit, "InaccessiblePaths")
	for i := range inacc {
		inacc[i] = strings.TrimPrefix(inacc[i], "-")
	}
	cfgDir := unitConfigDir(t, opsUnit)
	for name, p := range map[string]string{
		"state_dir":      skel.StateDir,
		"nos_token_file": skel.NOSTokenFile,
		"config dir":     cfgDir,
	} {
		for _, h := range inacc {
			if underDir(p, h) {
				t.Errorf("%s %s lies below InaccessiblePaths entry %s", name, p, h)
			}
		}
		if name != "state_dir" {
			for _, w := range rw {
				if underDir(p, w) {
					t.Errorf("%s %s lies below ReadWritePaths entry %s; it must stay read-only", name, p, w)
				}
			}
		}
	}
	if !underDir(skel.StateDir, rw[0]) {
		t.Errorf("state_dir %s is not writable", skel.StateDir)
	}
}

// opsSecretWord marks a line that talks about where a secret or CA file goes.
// The install.sh hint names the server's trigger path on purpose (it is not a
// secret), so only secret-related lines are checked.
var opsSecretWord = regexp.MustCompile(`(?i)token|credential|ca_file|\bCA\b`)

// Neither the skeleton, the install.sh hints nor the postinst hints name a
// place under the NOS server's or executor's directories for the token, the
// CA file or the LLM credential: the agent cannot read there.
func TestOpsAgentConfiguredSecretsAreNotInServerDirs(t *testing.T) {
	texts := map[string]string{
		"skeleton":   opsSkeleton(t, readFile(t, opsPostinst)),
		"install.sh": installBlock(t, "ops agent install"),
		"postinst":   newOpsSandbox(t).run(t, opsPostinst, "configure", ""),
	}
	for name, text := range texts {
		for _, l := range strings.Split(text, "\n") {
			if !opsSecretWord.MatchString(l) {
				continue
			}
			for _, m := range opsServerPath.FindAllStringSubmatch(l, -1) {
				t.Errorf("%s names %s for a secret or CA file: %q", name, m[1], l)
			}
		}
	}
}

// The path unit's trigger is the constant opsTriggerPath of nebula-server,
// and the agent's unit watches exactly that path. The server directory
// (StateDirectory) is checked by TestOpsAgentTriggerIsInTheServerStateDirWithoutNewWritePaths
// in ops_agent_release_test.go; this test does not repeat it.
// The path unit's PathChanged= is checked against opsTriggerPath in
// TestOpsAgentCannotSeeTheTriggerPath (ops_agent_test.go).
func TestOpsAgentTriggerConstantMatchesServerSource(t *testing.T) {
	src := readFile(t, "../../cmd/nebula-server/ops_trigger.go")
	m := regexp.MustCompile(`opsTriggerPath\s*=\s*"([^"]+)"`).FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("cmd/nebula-server/ops_trigger.go has no opsTriggerPath string constant")
	}
	if m[1] != opsTriggerPath {
		t.Errorf("nebula-server opsTriggerPath = %q, deb test constant = %q", m[1], opsTriggerPath)
	}
	if watched := unitValues(t, opsPath, "PathChanged"); !slices.Equal(watched, []string{m[1]}) {
		t.Errorf("path unit PathChanged = %q, want the server's trigger %q", watched, m[1])
	}
}

// The agent's unit allows IPv4 and IPv6 sockets, which the NOS API and the
// LLM endpoint need. The LLM address itself is added by a drop-in with
// IPAddressAllow=; the unit's comment names that drop-in, which
// TestOpsAgentUnitExplainsTheLLMDropIn (ops_agent_test.go) checks.
func TestOpsAgentUnitAllowsIPv4AndIPv6Sockets(t *testing.T) {
	fams := unitValues(t, opsUnit, "RestrictAddressFamilies")
	for _, want := range []string{"AF_INET", "AF_INET6"} {
		if !slices.Contains(fams, want) {
			t.Errorf("RestrictAddressFamilies = %q, lacks %s", fams, want)
		}
	}
}
