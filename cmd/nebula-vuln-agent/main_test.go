// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/agent"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnagent/run"
)

// The command tests cover usage, configuration and exit codes; every case
// ends before any network access. The run itself is tested end to end in
// internal/vulnagent/run. Synthetic credentials only.

const testToken = "nos-test-token-0123456789abcdef"

func writeFile(t *testing.T, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func call(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	code := realMain(ctx, args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestUsageErrorsExitTwo(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.json")
	for name, args := range map[string][]string{
		"no command":        {"-config", missing},
		"unknown command":   {"submit"},
		"two commands":      {"run", "dry-run"},
		"unknown flag":      {"-nope", "run"},
		"named config gone": {"-config", missing, "run"},
	} {
		t.Run(name, func(t *testing.T) {
			if code, _, _ := call(t, args...); code != exitUsage {
				t.Errorf("exit %d, want %d", code, exitUsage)
			}
		})
	}
}

func TestConfigRefusedBeforeAnyNetwork(t *testing.T) {
	data := t.TempDir()
	tok := writeFile(t, "token", testToken+"\n", 0o600)
	loose := writeFile(t, "loose-token", testToken+"\n", 0o644)
	cases := map[string]struct {
		file string
		args []string
	}{
		"unknown field":      {`{"data_dir":"` + data + `","nos_password":"x"}`, []string{"sync-only"}},
		"relative data dir":  {`{"data_dir":"data"}`, []string{"sync-only"}},
		"trailing data":      {`{"data_dir":"` + data + `"} {}`, []string{"sync-only"}},
		"http nos":           {`{"data_dir":"` + data + `","nos":{"url":"http://nos.lab","token_file":"` + tok + `"}}`, []string{"run"}},
		"nos with path":      {`{"data_dir":"` + data + `","nos":{"url":"https://nos.lab/api","token_file":"` + tok + `"}}`, []string{"run"}},
		"nos userinfo":       {`{"data_dir":"` + data + `","nos":{"url":"https://u:p@nos.lab","token_file":"` + tok + `"}}`, []string{"dry-run"}},
		"no token file":      {`{"data_dir":"` + data + `","nos":{"url":"https://nos.lab"}}`, []string{"run"}},
		"loose token file":   {`{"data_dir":"` + data + `","nos":{"url":"https://nos.lab","token_file":"` + loose + `"}}`, []string{"run"}},
		"bad language":       {`{"data_dir":"` + data + `","llm":{"language":"fr"}}`, []string{"sync-only"}},
		"bad log level":      {`{"data_dir":"` + data + `","log_level":"loud"}`, []string{"sync-only"}},
		"bad duration":       {`{"data_dir":"` + data + `","assess_phase_max":"forever"}`, []string{"sync-only"}},
		"phase too long":     {`{"data_dir":"` + data + `","assess_phase_max":"5h"}`, []string{"sync-only"}},
		"unknown csaf":       {`{"data_dir":"` + data + `","csaf":{"acme-csaf":{"key_files":["/k"]}}}`, []string{"sync-only"}},
		"csaf without keys":  {`{"data_dir":"` + data + `","csaf":{"cisco-csaf":{"key_files":[]}}}`, []string{"sync-only"}},
		"csaf key not found": {`{"data_dir":"` + data + `","csaf":{"cisco-csaf":{"key_files":["` + filepath.Join(data, "absent.asc") + `"]}}}`, []string{"sync-only"}},
		"llm enabled no window": {`{"data_dir":"` + data + `","llm":{"enabled":true,"base_url":"https://llm.lab/v1","model":"m"}}`,
			[]string{"sync-only"}},
		"llm url userinfo":    {`{"data_dir":"` + data + `","llm":{"base_url":"https://u:p@llm.lab/v1"}}`, []string{"sync-only"}},
		"llm limits over max": {`{"data_dir":"` + data + `","llm":{"limits":{"max_tool_steps":99}}}`, []string{"sync-only"}},
		"llm relative key":    {`{"data_dir":"` + data + `","llm":{"api_key_file":"key"}}`, []string{"sync-only"}},
		"llm public network":  {`{"data_dir":"` + data + `","llm":{"allowed_networks":["203.0.113.0/24"]}}`, []string{"sync-only"}},
		"llm nat64 network":   {`{"data_dir":"` + data + `","llm":{"allowed_networks":["64:ff9b::/96"]}}`, []string{"sync-only"}},
		"llm relative socket": {`{"data_dir":"` + data + `","llm":{"unix_socket":"llm.sock"}}`, []string{"sync-only"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := writeFile(t, "config.json", tc.file, 0o600)
			code, out, errOut := call(t, append([]string{"-config", cfg}, tc.args...)...)
			if code != exitUsage {
				t.Errorf("exit %d, want %d; stderr %s", code, exitUsage, errOut)
			}
			if out != "" {
				t.Errorf("stdout not empty: %q", out)
			}
			if strings.Contains(errOut, testToken) || strings.Contains(errOut, "u:p@") {
				t.Errorf("secret in stderr: %s", errOut)
			}
		})
	}
}

func TestFlagsOverrideConfigFile(t *testing.T) {
	cfg, err := loadConfig(writeFile(t, "c.json", `{"data_dir":"/var/lib/a","nos":{"url":"https://a.lab","token_file":"/a"},`+
		`"llm":{"enabled":true,"base_url":"https://llm-a/v1","model":"a","api_key_file":"/ka"},"log_level":"info"}`, 0o600), true)
	if err != nil {
		t.Fatal(err)
	}
	fv := flagValues{dataDir: "/var/lib/b", nosURL: "https://b.lab", tokenFile: "/b", caFile: "/ca", llmEnabled: false,
		llmURL: "https://llm-b/v1", llmModel: "b", llmKeyFile: "/kb", logLevel: "debug"}
	all := map[string]bool{"data-dir": true, "nos-url": true, "token-file": true, "ca-file": true, "llm-enabled": true,
		"llm-url": true, "llm-model": true, "llm-key-file": true, "log-level": true}
	cfg.applyFlags(fv, all)
	l := cfg.llm()
	if cfg.DataDir != "/var/lib/b" || cfg.NOS.URL != "https://b.lab" || cfg.NOS.TokenFile != "/b" || cfg.NOS.CAFile != "/ca" ||
		l.Enabled || l.BaseURL != "https://llm-b/v1" || l.Model != "b" || l.APIKeyFile != "/kb" || cfg.LogLevel != "debug" {
		t.Errorf("flags not applied: %+v", cfg)
	}
	if l.Language != agent.LanguageDE || l.Limits != agent.DefaultLimits() {
		t.Errorf("defaults: language %q limits %+v", l.Language, l.Limits)
	}
	// Unset flags keep the file's values.
	cfg2, _ := loadConfig(writeFile(t, "c.json", `{"data_dir":"/var/lib/a"}`, 0o600), true)
	cfg2.applyFlags(fv, map[string]bool{"nos-url": true})
	if cfg2.DataDir != "/var/lib/a" || cfg2.NOS.URL != "https://b.lab" {
		t.Errorf("partial override: %+v", cfg2)
	}
}

func TestLimitsFromConfig(t *testing.T) {
	cfg, err := loadConfig(writeFile(t, "c.json", `{"data_dir":"/d","llm":{"limits":{"max_tool_steps":4,"max_run_tokens":100000,`+
		`"llm_call_timeout":"30s","finding_timeout":"90s"}}}`, 0o600), true)
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.llm().Limits
	if l.MaxToolSteps != 4 || l.MaxRunTokens != 100000 || l.LLMCallTimeout != 30*time.Second || l.FindingTimeout != 90*time.Second ||
		l.MaxOutputTokens != agent.DefaultMaxOutputTokens {
		t.Errorf("limits = %+v", l)
	}
}

func TestLLMNetworkSettingsFromConfig(t *testing.T) {
	cfg, err := loadConfig(writeFile(t, "c.json", `{"data_dir":"/d","llm":{"allowed_networks":["100.64.0.0/16"],`+
		`"unix_socket":"/run/llm.sock"}}`, 0o600), true)
	if err != nil {
		t.Fatal(err)
	}
	l := cfg.llm()
	if len(l.AllowedNetworks) != 1 || l.AllowedNetworks[0] != "100.64.0.0/16" || l.UnixSocket != "/run/llm.sock" {
		t.Errorf("llm network settings = %+v %q", l.AllowedNetworks, l.UnixSocket)
	}
}

func TestMissingDefaultConfigIsAllowed(t *testing.T) {
	cfg, err := loadConfig(filepath.Join(t.TempDir(), "absent.json"), false)
	if err != nil || cfg.DataDir != "" {
		t.Errorf("default config absent: %v %+v", err, cfg)
	}
	big := writeFile(t, "big.json", `{"data_dir":"`+strings.Repeat("a", maxConfigBytes)+`"}`, 0o600)
	if _, err := loadConfig(big, true); !errors.Is(err, errConfig) {
		t.Errorf("oversized config = %v", err)
	}
}

func TestExitCodes(t *testing.T) {
	failed := &run.Report{Sources: []run.SourceEvidence{{Feed: "cisa-kev", Status: run.SourceFailed}}}
	for name, tc := range map[string]struct {
		rep  *run.Report
		err  error
		want int
	}{
		"ok":       {&run.Report{}, nil, exitOK},
		"degraded": {failed, nil, exitDegraded},
		"withheld": {&run.Report{Withheld: 1}, nil, exitDegraded},
		"rejected": {&run.Report{Rejected: 2}, nil, exitDegraded},
		"llm off":  {&run.Report{LLM: run.LLMEvidence{Failed: true}}, nil, exitDegraded},
		"failed":   {&run.Report{}, run.ErrUpload, exitFailed},
		"export":   {nil, run.ErrExport, exitFailed},
		"config":   {nil, run.ErrConfig, exitUsage},
	} {
		if got := exitCode(tc.rep, tc.err); got != tc.want {
			t.Errorf("%s: exit %d, want %d", name, got, tc.want)
		}
	}
}

// TestVulnAgentImportsOnlyAllowlist enforces the A1.2 import boundary on
// the binary's transitive non-test imports, including which packages may
// import the two restricted module prefixes.
func TestVulnAgentImportsOnlyAllowlist(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go tool not found: %v", err)
	}
	out, err := exec.Command(gobin, "list", "-deps", "-f", "{{.ImportPath}}|{{.Standard}}|{{join .Imports \",\"}}", ".").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	const mod = "github.com/nebula-operation-station/nebula-operation-station/"
	allowedInternal := []string{"internal/vulnagent/", "internal/vulnfeed", "internal/vulnmatch", "internal/vulnassess",
		"internal/vulnver", "internal/vulnfinding"}
	importers := map[string][]string{}
	var pkgs []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.SplitN(line, "|", 3)
		if len(f) != 3 {
			t.Fatalf("go list line %q", line)
		}
		if f[1] == "true" {
			continue
		}
		pkgs = append(pkgs, f[0])
		for _, imp := range strings.Split(f[2], ",") {
			if imp != "" {
				importers[imp] = append(importers[imp], f[0])
			}
		}
	}
	under := func(p, prefix string) bool {
		return p == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(p, prefix)
	}
	for _, p := range pkgs {
		switch {
		case p == mod+"cmd/nebula-vuln-agent":
		case strings.HasPrefix(p, "golang.org/x/crypto/"), strings.HasPrefix(p, "golang.org/x/sys/"):
		case strings.HasPrefix(p, "github.com/ProtonMail/go-crypto/"):
			for _, imp := range importers[p] {
				if !under(imp, mod+"internal/vulnfeed/") && !strings.HasPrefix(imp, "github.com/ProtonMail/go-crypto/") {
					t.Errorf("%s imported by %s", p, imp)
				}
			}
		case strings.HasPrefix(p, "github.com/cloudflare/circl/"):
			for _, imp := range importers[p] {
				if !strings.HasPrefix(imp, "github.com/ProtonMail/go-crypto/") && !strings.HasPrefix(imp, "github.com/cloudflare/circl/") {
					t.Errorf("%s imported by %s", p, imp)
				}
			}
		case strings.HasPrefix(p, mod):
			rel := strings.TrimPrefix(p, mod)
			ok := false
			for _, a := range allowedInternal {
				if rel == strings.TrimSuffix(a, "/") || strings.HasPrefix(rel, strings.TrimSuffix(a, "/")+"/") {
					ok = true
				}
			}
			if !ok {
				t.Errorf("import outside the allowlist: %s", p)
			}
		case strings.HasPrefix(p, "vendor/golang.org/x/"):
		default:
			t.Errorf("import outside the allowlist: %s", p)
		}
		if p == "os/exec" {
			t.Error("binary imports os/exec")
		}
	}
	if len(importers["os/exec"]) != 0 {
		t.Errorf("os/exec imported by %v", importers["os/exec"])
	}
}
