// SPDX-License-Identifier: AGPL-3.0-or-later

package serverconfig

import (
	"strings"
	"testing"
)

// ADR 0016 D2 and spec 13 v28-13-01: the ops scopes belong to one
// dedicated token that carries no other scope; the source allowlist is
// allowed on the vuln token and on the ops token, and nowhere else.

func TestOpsScopesAreKnownScopes(t *testing.T) {
	for _, s := range []string{ScopeOpsRead, ScopeOpsNotesWrite} {
		if !ValidAPIScope(s) || !IsOpsScope(s) {
			t.Errorf("%s: valid %v, ops %v", s, ValidAPIScope(s), IsOpsScope(s))
		}
	}
	for _, s := range []string{ScopeInventoryRead, ScopeOperationsRead, ScopeExecutionLogsRead,
		ScopeVulnInventoryRead, ScopeVulnFindingsWrite, "ops.anything"} {
		if IsOpsScope(s) {
			t.Errorf("%s counted as an ops scope", s)
		}
	}
}

func TestOpsTokenExclusivityRules(t *testing.T) {
	for name, tc := range map[string]struct {
		tokens []APIToken
		want   string
	}{
		"dedicated ops token": {tokens: []APIToken{
			{Name: DefaultOpsTokenName, SHA256: hashA, Scopes: []string{ScopeOpsRead, ScopeOpsNotesWrite}, SourceAddresses: []string{"127.0.0.1", "::1"}},
			{Name: "ha", SHA256: hashB, Scopes: []string{ScopeInventoryRead}},
		}},
		"read only ops token": {tokens: []APIToken{{Name: "ops-agent", SHA256: hashA, Scopes: []string{ScopeOpsRead}}}},
		"ops with inventory.read": {tokens: []APIToken{{Name: "ops-agent", SHA256: hashA,
			Scopes: []string{ScopeOpsRead, ScopeInventoryRead}}}, want: "carries no other scope"},
		"ops with operations.read": {tokens: []APIToken{{Name: "ops-agent", SHA256: hashA,
			Scopes: []string{ScopeOpsNotesWrite, ScopeOperationsRead}}}, want: "carries no other scope"},
		"ops with execution_logs.read": {tokens: []APIToken{{Name: "ops-agent", SHA256: hashA,
			Scopes: []string{ScopeOpsRead, ScopeExecutionLogsRead}}}, want: "carries no other scope"},
		"ops with vuln inventory scope": {tokens: []APIToken{{Name: "ops-agent", SHA256: hashA,
			Scopes: []string{ScopeOpsRead, ScopeVulnInventoryRead}}}, want: "carries no other scope"},
		"ops with vuln findings scope": {tokens: []APIToken{{Name: "ops-agent", SHA256: hashA,
			Scopes: []string{ScopeOpsNotesWrite, ScopeVulnFindingsWrite}}}, want: "carries no other scope"},
		"vuln with ops scope": {tokens: []APIToken{{Name: "hermes-vuln", SHA256: hashA,
			Scopes: []string{ScopeVulnInventoryRead, ScopeOpsRead}}}, want: "carries no other scope"},
		"two ops tokens": {tokens: []APIToken{
			{Name: "ops-agent", SHA256: hashA, Scopes: []string{ScopeOpsRead}},
			{Name: "other", SHA256: hashB, Scopes: []string{ScopeOpsNotesWrite}},
		}, want: "only one token may hold the ops scopes"},
		"ops and vuln tokens side by side": {tokens: []APIToken{
			{Name: "ops-agent", SHA256: hashA, Scopes: []string{ScopeOpsRead, ScopeOpsNotesWrite}},
			{Name: "hermes-vuln", SHA256: hashB, Scopes: []string{ScopeVulnInventoryRead, ScopeVulnFindingsWrite}},
		}},
		"allowlist on a normal token": {tokens: []APIToken{{Name: "ha", SHA256: hashA, Scopes: []string{ScopeInventoryRead},
			SourceAddresses: []string{"192.0.2.10"}}}, want: "only on the vuln token"},
		"allowlist on a normal token next to ops token": {tokens: []APIToken{
			{Name: "ops-agent", SHA256: hashA, Scopes: []string{ScopeOpsRead}},
			{Name: "ha", SHA256: hashB, Scopes: []string{ScopeOperationsRead}, SourceAddresses: []string{"192.0.2.10"}},
		}, want: "only on the vuln token"},
		"bad address on ops token": {tokens: []APIToken{{Name: "ops-agent", SHA256: hashA, Scopes: []string{ScopeOpsRead},
			SourceAddresses: []string{"nos.lan"}}}, want: "not an IP address or prefix"},
		"prefix with host bits on ops token": {tokens: []APIToken{{Name: "ops-agent", SHA256: hashA, Scopes: []string{ScopeOpsRead},
			SourceAddresses: []string{"127.0.0.1/8"}}}, want: "not an IP address or prefix"},
		"too many addresses on ops token": {tokens: []APIToken{{Name: "ops-agent", SHA256: hashA, Scopes: []string{ScopeOpsRead},
			SourceAddresses: strings.Split(strings.Repeat("127.0.0.1,", MaxSourceAddresses+1), ",")[:MaxSourceAddresses+1]}}, want: "at most"},
	} {
		t.Run(name, func(t *testing.T) {
			p := APIConfig{Enabled: true, Tokens: tc.tokens}.Problems()
			got := strings.Join(p, "\n")
			if tc.want == "" && len(p) > 0 {
				t.Fatalf("unexpected problems: %s", got)
			}
			if tc.want != "" && !strings.Contains(got, tc.want) {
				t.Fatalf("problems %q do not mention %q", got, tc.want)
			}
		})
	}
}

func TestOpsTokenIsFound(t *testing.T) {
	a := APIConfig{Enabled: true, Tokens: []APIToken{
		{Name: "ha", SHA256: hashB, Scopes: []string{ScopeInventoryRead}},
		{Name: "ops-agent", SHA256: hashA, Scopes: []string{ScopeOpsRead, ScopeOpsNotesWrite}, SourceAddresses: []string{"127.0.0.1"}},
	}}
	tok, ok := a.OpsToken()
	if !ok || tok.Name != "ops-agent" {
		t.Fatalf("%v %v", tok, ok)
	}
	if _, ok := (APIConfig{Tokens: a.Tokens[:1]}).OpsToken(); ok {
		t.Fatal("found an ops token where there is none")
	}
	if _, ok := a.VulnToken(); ok {
		t.Fatal("ops token reported as vuln token")
	}
}

func TestOpsTokenParsesFromServerJSON(t *testing.T) {
	raw := strings.Replace(tokenJSON, `"token":`, `"api":{"enabled":true,"tokens":[{"name":"ops-agent","sha256":"`+hashA+
		`","scopes":["ops.read","ops.notes.write"],"source_addresses":["127.0.0.1"]}]},"token":`, 1)
	cfg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if tok, ok := cfg.API.OpsToken(); !ok || len(tok.SourceAddresses) != 1 {
		t.Fatalf("%+v", cfg.API)
	}
}

func TestOpsTokenWithMixedScopesRefusesStart(t *testing.T) {
	raw := strings.Replace(tokenJSON, `"token":`, `"api":{"enabled":true,"tokens":[{"name":"ops-agent","sha256":"`+hashA+
		`","scopes":["ops.read","inventory.read"]}]},"token":`, 1)
	if _, err := Parse([]byte(raw)); err == nil || !strings.Contains(err.Error(), "carries no other scope") {
		t.Fatalf("Parse accepted a mixed ops token: %v", err)
	}
}
