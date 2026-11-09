// SPDX-License-Identifier: AGPL-3.0-or-later

package serverconfig

import (
	"strings"
	"testing"
)

const (
	hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestVulnScopesAreKnownScopes(t *testing.T) {
	for _, s := range []string{ScopeVulnInventoryRead, ScopeVulnFindingsWrite} {
		if !ValidAPIScope(s) || !IsVulnScope(s) {
			t.Errorf("%s: valid %v, vuln %v", s, ValidAPIScope(s), IsVulnScope(s))
		}
	}
	for _, s := range []string{ScopeInventoryRead, ScopeOperationsRead, ScopeExecutionLogsRead, "vuln.anything"} {
		if IsVulnScope(s) {
			t.Errorf("%s counted as a vuln scope", s)
		}
	}
}

// ADR 0011 D3/D5: the vuln scopes belong to one dedicated token that
// carries no other scope; the source allowlist exists only for it.
func TestVulnScopesAreExclusiveToOneDedicatedToken(t *testing.T) {
	for name, tc := range map[string]struct {
		tokens []APIToken
		want   string
	}{
		"dedicated token": {tokens: []APIToken{
			{Name: DefaultVulnTokenName, SHA256: hashA, Scopes: []string{ScopeVulnInventoryRead, ScopeVulnFindingsWrite}, SourceAddresses: []string{"192.0.2.10", "2001:db8::/64"}},
			{Name: "ha", SHA256: hashB, Scopes: []string{ScopeInventoryRead}},
		}},
		"read only vuln token": {tokens: []APIToken{{Name: "hermes-vuln", SHA256: hashA, Scopes: []string{ScopeVulnInventoryRead}}}},
		"vuln with inventory.read": {tokens: []APIToken{{Name: "hermes-vuln", SHA256: hashA,
			Scopes: []string{ScopeVulnInventoryRead, ScopeInventoryRead}}}, want: "carries no other scope"},
		"vuln with operations.read": {tokens: []APIToken{{Name: "hermes-vuln", SHA256: hashA,
			Scopes: []string{ScopeVulnFindingsWrite, ScopeOperationsRead}}}, want: "carries no other scope"},
		"vuln with execution_logs.read": {tokens: []APIToken{{Name: "hermes-vuln", SHA256: hashA,
			Scopes: []string{ScopeVulnFindingsWrite, ScopeExecutionLogsRead}}}, want: "carries no other scope"},
		"two vuln tokens": {tokens: []APIToken{
			{Name: "hermes-vuln", SHA256: hashA, Scopes: []string{ScopeVulnInventoryRead}},
			{Name: "other", SHA256: hashB, Scopes: []string{ScopeVulnFindingsWrite}},
		}, want: "only one token"},
		"allowlist on another token": {tokens: []APIToken{{Name: "ha", SHA256: hashA, Scopes: []string{ScopeInventoryRead},
			SourceAddresses: []string{"192.0.2.10"}}}, want: "only on the vuln token"},
		"bad address": {tokens: []APIToken{{Name: "hermes-vuln", SHA256: hashA, Scopes: []string{ScopeVulnInventoryRead},
			SourceAddresses: []string{"hermes.lan"}}}, want: "not an IP address or prefix"},
		"prefix with host bits": {tokens: []APIToken{{Name: "hermes-vuln", SHA256: hashA, Scopes: []string{ScopeVulnInventoryRead},
			SourceAddresses: []string{"192.0.2.10/24"}}}, want: "not an IP address or prefix"},
		"too many addresses": {tokens: []APIToken{{Name: "hermes-vuln", SHA256: hashA, Scopes: []string{ScopeVulnInventoryRead},
			SourceAddresses: strings.Split(strings.Repeat("192.0.2.1,", MaxSourceAddresses+1), ",")[:MaxSourceAddresses+1]}}, want: "at most"},
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

func TestVulnTokenIsFound(t *testing.T) {
	a := APIConfig{Enabled: true, Tokens: []APIToken{
		{Name: "ha", SHA256: hashB, Scopes: []string{ScopeInventoryRead}},
		{Name: "hermes-vuln", SHA256: hashA, Scopes: []string{ScopeVulnFindingsWrite}, SourceAddresses: []string{"192.0.2.10"}},
	}}
	tok, ok := a.VulnToken()
	if !ok || tok.Name != "hermes-vuln" {
		t.Fatalf("%v %v", tok, ok)
	}
	pfx, err := tok.SourcePrefixes()
	if err != nil || len(pfx) != 1 || pfx[0].String() != "192.0.2.10/32" {
		t.Fatalf("%v %v", pfx, err)
	}
	if _, ok := (APIConfig{Tokens: a.Tokens[:1]}).VulnToken(); ok {
		t.Fatal("found a vuln token where there is none")
	}
}

func TestVulnTokenParsesFromServerJSON(t *testing.T) {
	raw := strings.Replace(tokenJSON, `"token":`, `"api":{"enabled":true,"tokens":[{"name":"hermes-vuln","sha256":"`+hashA+
		`","scopes":["vuln.inventory.read","vuln.findings.write"],"source_addresses":["192.0.2.10"]}]},"token":`, 1)
	cfg, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if tok, ok := cfg.API.VulnToken(); !ok || len(tok.SourceAddresses) != 1 {
		t.Fatalf("%+v", cfg.API)
	}
}
