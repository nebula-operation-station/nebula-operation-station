// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fuzz test for the server.json parser (Parse is the only gate for
// server.json) and boundary tests for the vuln token's source-address
// allowlist (ADR 0011 D3, MaxSourceAddresses). Every secret in this file is
// an invented marker and every address is from a documentation range
// (RFC 5737 for IPv4, RFC 3849 for IPv6).

package serverconfig

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// Invented secret markers, one for each place a secret can sit in
// server.json: the server token and the three provider secrets. No output
// of the package (errors, JSON, %+v) may contain any of them.
const (
	markerToken    = "FAKE-SECRET-MARKER-server-token"
	markerWebhook  = "FAKE-SECRET-MARKER-webhook-secret-0123456789"
	markerNtfy     = "FAKE-SECRET-MARKER-ntfy-token"
	markerTelegram = "FAKE-SECRET-MARKER-telegram"
)

// fuzzHash is a well-formed (invented) SHA-256 hex digest for API tokens.
var fuzzHash = strings.Repeat("c", 64)

// fuzzSeedFull uses every section of server.json, including the four
// secret markers.
var fuzzSeedFull = `{
	"listen": "127.0.0.1:8080",
	"allow_remote_listen": false,
	"public_origin": "https://nebula.example.org",
	"data_dir": "/var/lib/nebula",
	"executor_socket": "/run/nebula/executor.sock",
	"executor_user": "nebula-exec",
	"discovery_dir": "/var/lib/nebula/discovery",
	"pve_spool_dir": "/var/lib/nebula/pve",
	"audit_hash_chain": true,
	"traffic": {"retention_days": 7},
	"notifications": {
		"webhook": {"url": "https://hooks.example.org/nebula", "secret": "` + markerWebhook + `"},
		"ntfy": {"url": "https://ntfy.example.org", "topic": "nebula-alerts", "token": "` + markerNtfy + `"},
		"telegram": {"bot_token": "123456:` + markerTelegram + `", "chat_id": "-1001234567890"}
	},
	"api": {"enabled": true, "tokens": [
		{"name": "hermes-vuln", "sha256": "` + fuzzHash + `",
		 "scopes": ["vuln.inventory.read", "vuln.findings.write"],
		 "source_addresses": ["192.0.2.10", "2001:db8::/64"]}
	]},
	"token": "` + markerToken + `"
}`

// fuzzSeeds returns the corpus: valid documents, and near-misses that
// exercise the strict decoder (unknown key, wrong type, trailing data,
// truncation). Markers stay in the value positions only.
func fuzzSeeds() []string {
	minimal := `{
	"public_origin": "https://nebula.example.org",
	"data_dir": "/var/lib/nebula",
	"executor_socket": "/run/nebula/executor.sock",
	"executor_user": "nebula-exec",
	"token": "` + markerToken + `"
}`
	return []string{
		fuzzSeedFull,
		minimal,
		fuzzSeedFull + ` {}`,
		fuzzSeedFull + "\n\x00",
		`{"token": "` + markerToken + `", "bogus_key": 1}`,
		`{"token": 42}`,
		`{"traffic": {"retention_days": 0}, "token": "` + markerToken + `"}`,
		`{"traffic": {"retention_days": 22}}`,
		`{"notifications": {"telegram": {"bot_token": "` + markerTelegram + `"}}}`,
		fuzzSeedFull[:len(fuzzSeedFull)/2],
		`[]`,
		`null`,
		``,
	}
}

// minSecretCheckLen is the shortest secret value the leak check looks for.
// Shorter values are indistinguishable from ordinary words in error text
// ("required"), so they would give false alarms. Real tokens are longer
// (the webhook secret must be at least 32 characters).
const minSecretCheckLen = 16

// secretValuesOf returns the values that sit in a secret-typed position of
// data: token, notifications.webhook.secret, notifications.ntfy.token and
// notifications.telegram.bot_token. The decoding is loose on purpose: a
// document that fails to decode yields what was read before the error.
func secretValuesOf(data []byte) []string {
	var doc struct {
		Token         string `json:"token"`
		Notifications struct {
			Webhook struct {
				Secret string `json:"secret"`
			} `json:"webhook"`
			Ntfy struct {
				Token string `json:"token"`
			} `json:"ntfy"`
			Telegram struct {
				BotToken string `json:"bot_token"`
			} `json:"telegram"`
		} `json:"notifications"`
	}
	_ = json.Unmarshal(data, &doc) // partial results are wanted here
	var out []string
	for _, v := range []string{doc.Token, doc.Notifications.Webhook.Secret,
		doc.Notifications.Ntfy.Token, doc.Notifications.Telegram.BotToken} {
		if len(v) >= minSecretCheckLen {
			out = append(out, v)
		}
	}
	return out
}

// checkNoSecret fails the test if out contains any of the secrets. The
// secret values are not printed on failure. where names the output.
func checkNoSecret(t *testing.T, where, out string, secrets []string) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(out, s) {
			t.Fatalf("%s contains a secret value (%d bytes)", where, len(s))
		}
	}
}

// FuzzParse feeds arbitrary bytes to Parse. It must not panic. A rejected
// input must not leak one of its secret-typed values into the error. An
// accepted input must validate, have a listen address and an effective
// retention in range, and must not leak a secret through JSON or %+v.
// Only secret-typed values are checked; see the finding recorded in the
// review report about non-secret fields echoed by Validate.
func FuzzParse(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		secrets := secretValuesOf(data)
		cfg, err := Parse(data)
		if err != nil {
			checkNoSecret(t, "Parse error", err.Error(), secrets)
			return
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Parse accepted a config that Validate rejects: %v", err)
		}
		if cfg.Listen == "" {
			t.Fatal("Parse returned an empty listen address")
		}
		if d := cfg.Traffic.EffectiveRetentionDays(); d < 1 || d > DefaultTrafficRetentionDays {
			t.Fatalf("effective retention %d outside 1-%d", d, DefaultTrafficRetentionDays)
		}
		out, err := json.Marshal(cfg)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		checkNoSecret(t, "json.Marshal output", string(out), secrets)
		checkNoSecret(t, "%+v output", fmt.Sprintf("%+v", cfg), secrets)
	})
}

// TestFuzzSeedsHoldTheSecretProperty runs the seed corpus through the same
// checks as FuzzParse, so the property is also checked on every plain
// `go test` run.
func TestFuzzSeedsHoldTheSecretProperty(t *testing.T) {
	for i, s := range fuzzSeeds() {
		secrets := secretValuesOf([]byte(s))
		if i == 0 && len(secrets) != 4 {
			t.Fatalf("full seed has %d secret values, want 4: the check would be vacuous", len(secrets))
		}
		cfg, err := Parse([]byte(s))
		if err != nil {
			if i == 0 {
				t.Fatalf("full seed rejected, the secret check would be vacuous: %v", err)
			}
			checkNoSecret(t, fmt.Sprintf("seed %d error", i), err.Error(), secrets)
			continue
		}
		out, err := json.Marshal(cfg)
		if err != nil {
			t.Fatalf("seed %d: json.Marshal: %v", i, err)
		}
		checkNoSecret(t, fmt.Sprintf("seed %d JSON", i), string(out), secrets)
		checkNoSecret(t, fmt.Sprintf("seed %d %%+v", i), fmt.Sprintf("%+v", cfg), secrets)
		if i == 0 {
			// Guard against a vacuous pass: the full seed must parse and
			// must show the redaction marker where the secrets were.
			if !strings.Contains(string(out), redacted) || !strings.Contains(fmt.Sprintf("%+v", cfg), redacted) {
				t.Fatal("full seed does not show the redaction marker; the secret check is vacuous")
			}
		}
	}
}

// vulnAPI returns an enabled API config with one vuln token that has the
// given source addresses.
func vulnAPI(addrs ...string) APIConfig {
	return APIConfig{Enabled: true, Tokens: []APIToken{{
		Name: DefaultVulnTokenName, SHA256: fuzzHash,
		Scopes: []string{ScopeVulnInventoryRead, ScopeVulnFindingsWrite}, SourceAddresses: addrs,
	}}}
}

// TestSourcePrefixesBoundaries checks the source-address allowlist at its
// edges. Cases marked "status quo" record today's behaviour; see the
// comments there.
func TestSourcePrefixesBoundaries(t *testing.T) {
	// Exactly MaxSourceAddresses addresses from 192.0.2.0/24 (RFC 5737).
	atLimit := make([]string, MaxSourceAddresses)
	for i := range atLimit {
		atLimit[i] = fmt.Sprintf("192.0.2.%d", i+1)
	}

	t.Run("exactly the limit is accepted", func(t *testing.T) {
		api := vulnAPI(atLimit...)
		if p := api.Problems(); len(p) != 0 {
			t.Fatalf("%d addresses rejected: %v", len(atLimit), p)
		}
		tok, ok := api.VulnToken()
		if !ok {
			t.Fatal("vuln token not found")
		}
		pfx, err := tok.SourcePrefixes()
		if err != nil || len(pfx) != MaxSourceAddresses {
			t.Fatalf("got %d prefixes, err %v; want %d", len(pfx), err, MaxSourceAddresses)
		}
	})

	t.Run("one above the limit is rejected", func(t *testing.T) {
		over := append(append([]string{}, atLimit...), "192.0.2.17")
		got := strings.Join(vulnAPI(over...).Problems(), "\n")
		if !strings.Contains(got, fmt.Sprintf("at most %d", MaxSourceAddresses)) {
			t.Fatalf("%d addresses: problems %q do not mention the limit", len(over), got)
		}
	})

	// Single addresses and prefixes at the edges. want is a substring of
	// the problem text, or "" for accepted. prefix, when set, is the
	// expected single prefix from SourcePrefixes.
	for name, tc := range map[string]struct {
		addr   string
		want   string
		prefix string
	}{
		"ipv4 single address": {addr: "192.0.2.10", prefix: "192.0.2.10/32"},
		"ipv4 prefix ok":      {addr: "192.0.2.0/24", prefix: "192.0.2.0/24"},
		"ipv4 host bits":      {addr: "192.0.2.10/24", want: "not an IP address or prefix"},
		"ipv6 single address": {addr: "2001:db8::1", prefix: "2001:db8::1/128"},
		"ipv6 prefix ok":      {addr: "2001:db8::/64", prefix: "2001:db8::/64"},
		"ipv6 host bits":      {addr: "2001:db8::1/64", want: "not an IP address or prefix"},
		"ipv6 zone":           {addr: "2001:db8::1%eth0", want: "not an IP address or prefix"},
		"empty":               {addr: "", want: "not an IP address or prefix"},
		// Status quo: a single IPv4-mapped address is unmapped and stored
		// as the IPv4 /32, so it matches the IPv4 client address the
		// handler compares against (vuln.go unmaps the client address).
		"ipv4-in-ipv6 single (status quo)": {addr: "::ffff:192.0.2.10", prefix: "192.0.2.10/32"},
		// Status quo: a prefix written in IPv4-mapped form is accepted and
		// kept as an IPv6 prefix. It does not match the unmapped IPv4
		// client address (see TestIPv4MappedPrefixNeverMatchesClientAddress).
		"ipv4-in-ipv6 prefix (status quo)": {addr: "::ffff:192.0.2.0/120", prefix: "::ffff:192.0.2.0/120"},
	} {
		t.Run(name, func(t *testing.T) {
			api := vulnAPI(tc.addr)
			got := strings.Join(api.Problems(), "\n")
			if tc.want == "" && got != "" {
				t.Fatalf("rejected: %s", got)
			}
			if tc.want != "" && !strings.Contains(got, tc.want) {
				t.Fatalf("problems %q do not mention %q", got, tc.want)
			}
			if tc.prefix == "" {
				return
			}
			tok, _ := api.VulnToken()
			pfx, err := tok.SourcePrefixes()
			if err != nil || len(pfx) != 1 || pfx[0].String() != tc.prefix {
				t.Fatalf("SourcePrefixes = %v, %v; want %s", pfx, err, tc.prefix)
			}
		})
	}
}

// TestIPv4MappedPrefixNeverMatchesClientAddress documents why the
// IPv4-mapped prefix form is a finding. The handler unmaps the client
// address before matching (vuln.go), and netip.Prefix.Contains never matches
// an IPv4 address against an IPv6 prefix, so the configured prefix cannot
// admit any client. The test pins this current behaviour; it does not fix it.
func TestIPv4MappedPrefixNeverMatchesClientAddress(t *testing.T) {
	tok := APIToken{SourceAddresses: []string{"::ffff:192.0.2.0/120"}}
	pfx, err := tok.SourcePrefixes()
	if err != nil || len(pfx) != 1 {
		t.Fatalf("SourcePrefixes = %v, %v", pfx, err)
	}
	client := netip.MustParseAddr("::ffff:192.0.2.5").Unmap()
	if client.Is6() {
		t.Fatalf("Unmap did not produce an IPv4 address: %v", client)
	}
	if pfx[0].Contains(client) {
		t.Fatalf("prefix %v matches unmapped client %v; finding is resolved, update the test and the report", pfx[0], client)
	}
	if !pfx[0].Contains(netip.MustParseAddr("::ffff:192.0.2.5")) {
		t.Fatal("prefix does not match its own mapped form")
	}
}
