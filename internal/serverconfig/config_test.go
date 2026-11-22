// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for the nebula-server configuration: JSON loading with unknown-key
// rejection, field validation (listen, public origin), defaults, and the
// "every problem at once" error (acceptance criteria 1-3).

package serverconfig

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/web/clientaddr"
)

// validJSON is a minimal valid config with no listen address (so the
// default applies).
const validJSON = `{
	"public_origin": "https://nebula.example.org",
	"data_dir": "/var/lib/nebula",
	"executor_socket": "/run/nebula/executor.sock",
	"executor_user": "nebula-exec"
}`

func writeConfigFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// parseFlags builds a FlagSet with every config flag registered and
// parsed from args.
func parseFlags(t *testing.T, args ...string) *flag.FlagSet {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	RegisterFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return fs
}

func TestParseUnknownKeyError(t *testing.T) {
	// An unknown key must be an error, not silently ignored.
	bad := `{"listen":"127.0.0.1:8080","public_origin":"https://n.example","data_dir":"/d","executor_socket":"/s","executor_user":"u","bogus_key":1}`
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("Parse accepted an unknown key")
	}
}

func TestParseDefaults(t *testing.T) {
	cfg, err := Parse([]byte(validJSON))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != DefaultListen {
		t.Errorf("Listen = %q, want default %q", cfg.Listen, DefaultListen)
	}
}

func TestListenNonLoopbackRefused(t *testing.T) {
	bad := `{"listen":"0.0.0.0:8080","public_origin":"https://n.example","data_dir":"/d","executor_socket":"/s","executor_user":"u"}`
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("Parse accepted a non-loopback listen without allow_remote_listen")
	}
}

func TestListenNonLoopbackAllowed(t *testing.T) {
	ok := `{"listen":"0.0.0.0:8080","allow_remote_listen":true,"public_origin":"https://n.example","data_dir":"/d","executor_socket":"/s","executor_user":"u"}`
	cfg, err := Parse([]byte(ok))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "0.0.0.0:8080" {
		t.Errorf("Listen = %q", cfg.Listen)
	}
}

func TestListenLoopbackOK(t *testing.T) {
	ok := `{"listen":"127.0.0.1:9090","public_origin":"https://n.example","data_dir":"/d","executor_socket":"/s","executor_user":"u"}`
	cfg, err := Parse([]byte(ok))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:9090" {
		t.Errorf("Listen = %q", cfg.Listen)
	}
}

func TestPublicOriginMustBeHTTPS(t *testing.T) {
	bad := `{"public_origin":"http://n.example","data_dir":"/d","executor_socket":"/s","executor_user":"u"}`
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("Parse accepted a non-https public_origin")
	}
}

func TestPublicOriginHTTPSOK(t *testing.T) {
	cfg, err := Parse([]byte(validJSON))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicOrigin != "https://nebula.example.org" {
		t.Errorf("PublicOrigin = %q", cfg.PublicOrigin)
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	if err := os.WriteFile(path, []byte(validJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != DefaultListen {
		t.Errorf("Listen = %q, want %q", cfg.Listen, DefaultListen)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("Load accepted a missing file")
	}
}

func TestValidationListsAllProblems(t *testing.T) {
	// A config with five distinct problems must report all five at once.
	cfg := Config{
		Listen:         "0.0.0.0:8080",     // non-loopback, no allow_remote_listen
		PublicOrigin:   "http://n.example", // not https
		DataDir:        "",                 // required
		ExecutorSocket: "",                 // required
		ExecutorUser:   "",                 // required
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate accepted an invalid config")
	}
	msg := err.Error()
	for _, want := range []string{
		"allow_remote_listen",
		"public_origin",
		"data_dir",
		"executor_socket",
		"executor_user",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not mention %q", msg, want)
		}
	}
}

func TestValidationClean(t *testing.T) {
	cfg := Config{
		Listen:         "127.0.0.1:8080",
		PublicOrigin:   "https://n.example",
		DataDir:        "/d",
		ExecutorSocket: "/s",
		ExecutorUser:   "u",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate rejected a valid config: %v", err)
	}
}

func TestFlagOverride(t *testing.T) {
	// The flag-override pattern: load the file, apply explicitly set
	// flags, validate once.
	path := writeConfigFile(t, validJSON)
	cfg, err := LoadWithFlags(path, parseFlags(t, "-listen", "127.0.0.1:9090"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:9090" {
		t.Errorf("override not applied: %q", cfg.Listen)
	}
	// Flags the user did not set leave the file value in place.
	if cfg.PublicOrigin != "https://nebula.example.org" {
		t.Errorf("unset flag changed file value: %q", cfg.PublicOrigin)
	}
	// A bad override must be caught by validation.
	if _, err := LoadWithFlags(path, parseFlags(t, "-listen", "0.0.0.0:9090")); err == nil {
		t.Error("expected validation error for non-loopback override")
	}
}

func TestFlagFixesBadFileValue(t *testing.T) {
	// A file value that fails validation must be fixable by a flag:
	// validation runs once, after the flags are applied.
	bad := `{"public_origin":"http://n.example","data_dir":"/d","executor_socket":"/s","executor_user":"u"}`
	path := writeConfigFile(t, bad)

	if _, err := LoadWithFlags(path, parseFlags(t)); err == nil {
		t.Fatal("LoadWithFlags accepted an invalid file value")
	}
	cfg, err := LoadWithFlags(path, parseFlags(t, "-public_origin", "https://n.example"))
	if err != nil {
		t.Fatalf("flag did not fix the bad file value: %v", err)
	}
	if cfg.PublicOrigin != "https://n.example" {
		t.Errorf("PublicOrigin = %q", cfg.PublicOrigin)
	}
}

func TestFlagOverridesEveryField(t *testing.T) {
	// The token has no flag: it is a secret and comes from the config
	// file only, so the file carries the token and the flags must leave
	// it in place.
	path := writeConfigFile(t, tokenJSON)
	// The bool flag must use the -flag=value form: a bare bool flag does
	// not consume a value argument, so "-allow_remote_listen true" would
	// treat "true" as a positional argument and stop flag parsing.
	fs := parseFlags(t,
		"-listen=127.0.0.1:9999",
		"-allow_remote_listen=true",
		"-public_origin=https://other.example",
		"-data_dir=/other/data",
		"-executor_socket=/other/sock",
		"-executor_user=other-user",
	)
	cfg, err := LoadWithFlags(path, fs)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:9999" || !cfg.AllowRemoteListen ||
		cfg.PublicOrigin != "https://other.example" || cfg.DataDir != "/other/data" ||
		cfg.ExecutorSocket != "/other/sock" || cfg.ExecutorUser != "other-user" {
		t.Errorf("flags not all applied: %+v", cfg)
	}
	if cfg.Token != tokenSecret {
		t.Errorf("token from the file was lost: %q", cfg.Token)
	}
}

func TestRegisterFlagsHasNoTokenFlag(t *testing.T) {
	// The token is a secret: it must never be passable on the command
	// line, where arguments are visible in ps and /proc. It comes from
	// the config file only.
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	RegisterFlags(fs)
	fs.VisitAll(func(f *flag.Flag) {
		if f.Name == "token" {
			t.Errorf("RegisterFlags defines a %q flag; the token must not be a command-line argument", f.Name)
		}
	})
	if err := fs.Parse([]string{"-token=abc"}); err == nil {
		t.Error("parsing -token succeeded; the flag must not exist")
	}
}

func TestFlagUnknownKeyStillError(t *testing.T) {
	bad := `{"listen":"127.0.0.1:8080","public_origin":"https://n.example","data_dir":"/d","executor_socket":"/s","executor_user":"u","bogus_key":1}`
	path := writeConfigFile(t, bad)
	if _, err := LoadWithFlags(path, parseFlags(t)); err == nil {
		t.Fatal("LoadWithFlags accepted an unknown key")
	}
}

func TestLoadWithFlagsMissingFile(t *testing.T) {
	if _, err := LoadWithFlags(filepath.Join(t.TempDir(), "nope.json"), parseFlags(t)); err == nil {
		t.Fatal("LoadWithFlags accepted a missing file")
	}
}

func TestPublicOriginRejections(t *testing.T) {
	// public_origin must be a bare origin: scheme https, host, optional
	// port. No path (not even "/"), query, fragment or userinfo.
	cases := []struct {
		name   string
		origin string
	}{
		{"empty", ""},
		{"http scheme", "http://n.example"},
		{"uppercase scheme", "HTTPS://n.example"},
		{"uppercase host", "https://Nebula.example.org"},
		{"uppercase host with port", "https://NEBULA.EXAMPLE:8443"},
		{"no host", "https://"},
		{"path", "https://n.example/path"},
		{"trailing slash", "https://n.example/"},
		{"query", "https://n.example?x=1"},
		{"empty query", "https://n.example?"},
		{"fragment", "https://n.example#frag"},
		{"empty fragment", "https://n.example#"},
		{"userinfo", "https://user:pass@n.example"},
		{"userinfo without password", "https://user@n.example"},
		{"trailing slash after port", "https://n.example:8443/"},
		{"query after port", "https://n.example:8443?x=1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if isValidHTTPSOrigin(tc.origin) {
				t.Errorf("isValidHTTPSOrigin(%q) = true, want false", tc.origin)
			}
			bad := fmt.Sprintf(`{"public_origin":%q,"data_dir":"/d","executor_socket":"/s","executor_user":"u"}`, tc.origin)
			if _, err := Parse([]byte(bad)); err == nil {
				t.Errorf("Parse accepted public_origin %q", tc.origin)
			}
		})
	}
}

func TestPublicOriginAccepts(t *testing.T) {
	for _, origin := range []string{"https://n.example", "https://n.example:8443"} {
		if !isValidHTTPSOrigin(origin) {
			t.Errorf("isValidHTTPSOrigin(%q) = false, want true", origin)
		}
	}
}

func TestPublicOriginUppercaseClearMessage(t *testing.T) {
	// Browsers send the Origin header lowercased and the middleware
	// compares exactly, so an uppercase origin must be rejected with a
	// message that says it must be lowercase.
	bad := `{"public_origin":"https://Nebula.example.org","data_dir":"/d","executor_socket":"/s","executor_user":"u"}`
	_, err := Parse([]byte(bad))
	if err == nil {
		t.Fatal("Parse accepted an uppercase public_origin")
	}
	if !strings.Contains(err.Error(), "lowercase") {
		t.Errorf("error does not say public_origin must be lowercase: %v", err)
	}
}

func TestDataDirMustBeAbsolute(t *testing.T) {
	for _, dir := range []string{"relative/dir", "./dir", "dir"} {
		bad := fmt.Sprintf(`{"public_origin":"https://n.example","data_dir":%q,"executor_socket":"/s","executor_user":"u"}`, dir)
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("Parse accepted relative data_dir %q", dir)
		}
	}
}

func TestExecutorSocketMustBeAbsolute(t *testing.T) {
	for _, sock := range []string{"relative/sock", "./sock", "sock"} {
		bad := fmt.Sprintf(`{"public_origin":"https://n.example","data_dir":"/d","executor_socket":%q,"executor_user":"u"}`, sock)
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("Parse accepted relative executor_socket %q", sock)
		}
	}
}

func TestParseRejectsTrailingData(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"second object", validJSON + "{}"},
		{"object after whitespace", validJSON + " {}"},
		{"garbage after object", validJSON + " garbage"},
		{"stray closing brace", validJSON + "}"},
		{"trailing string", validJSON + ` "x"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.data)); err == nil {
				t.Error("Parse accepted trailing data after the JSON object")
			}
		})
	}
}

func TestParseAllowsTrailingWhitespace(t *testing.T) {
	if _, err := Parse([]byte(validJSON + "\n	 ")); err != nil {
		t.Fatalf("Parse rejected trailing whitespace: %v", err)
	}
}

func TestTrafficRetentionDefault(t *testing.T) {
	// No "traffic" key (or an empty section): the 21-day default applies.
	for _, json := range []string{validJSON, validJSON[:len(validJSON)-1] + `,"traffic":{}}`} {
		cfg, err := Parse([]byte(json))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Traffic.RetentionDays != nil {
			t.Errorf("RetentionDays = %v, want nil (key absent)", *cfg.Traffic.RetentionDays)
		}
		if got := cfg.Traffic.EffectiveRetentionDays(); got != DefaultTrafficRetentionDays {
			t.Errorf("EffectiveRetentionDays = %d, want %d", got, DefaultTrafficRetentionDays)
		}
	}
}

func TestTrafficRetentionValid(t *testing.T) {
	for _, n := range []int{1, 7, 21} {
		ok := fmt.Sprintf(`{"public_origin":"https://n.example","data_dir":"/d","executor_socket":"/s","executor_user":"u","traffic":{"retention_days":%d}}`, n)
		cfg, err := Parse([]byte(ok))
		if err != nil {
			t.Fatalf("retention_days %d: %v", n, err)
		}
		if got := cfg.Traffic.EffectiveRetentionDays(); got != n {
			t.Errorf("retention_days %d: effective %d", n, got)
		}
	}
}

func TestTrafficRetentionZeroRefused(t *testing.T) {
	// An explicit 0 is not "use the default"; it is an invalid value and
	// must stop the start with a clear error naming the key.
	bad := `{"public_origin":"https://n.example","data_dir":"/d","executor_socket":"/s","executor_user":"u","traffic":{"retention_days":0}}`
	_, err := Parse([]byte(bad))
	if err == nil {
		t.Fatal("Parse accepted retention_days 0")
	}
	if !strings.Contains(err.Error(), "traffic.retention_days") {
		t.Errorf("error does not name the key: %v", err)
	}
}

// TestTrafficRetentionNegativeRefused checks that negative values are
// refused by Parse as well, not only by the range check at start.
func TestTrafficRetentionNegativeRefused(t *testing.T) {
	for _, n := range []int{-1, -21} {
		bad := fmt.Sprintf(`{"public_origin":"https://n.example","data_dir":"/d","executor_socket":"/s","executor_user":"u","traffic":{"retention_days":%d}}`, n)
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("Parse accepted retention_days %d", n)
		}
	}
}

func TestTrafficRetentionAboveMaxRefused(t *testing.T) {
	for _, n := range []int{22, 100} {
		bad := fmt.Sprintf(`{"public_origin":"https://n.example","data_dir":"/d","executor_socket":"/s","executor_user":"u","traffic":{"retention_days":%d}}`, n)
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("Parse accepted retention_days %d", n)
		}
	}
}

func TestTrafficRetentionWrongType(t *testing.T) {
	bad := `{"public_origin":"https://n.example","data_dir":"/d","executor_socket":"/s","executor_user":"u","traffic":{"retention_days":"7"}}`
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("Parse accepted a string retention_days")
	}
}

func TestAPIConfigValidation(t *testing.T) {
	good := strings.Repeat("a", 64)
	for name, tc := range map[string]struct {
		api  APIConfig
		want string
	}{
		"off":           {APIConfig{}, ""},
		"no tokens":     {APIConfig{Enabled: true}, "at least one token"},
		"ok":            {APIConfig{Enabled: true, Tokens: []APIToken{{Name: "ha", SHA256: good, Scopes: []string{ScopeInventoryRead}}}}, ""},
		"bad name":      {APIConfig{Enabled: true, Tokens: []APIToken{{Name: "Home Assistant", SHA256: good, Scopes: []string{ScopeInventoryRead}}}}, "name"},
		"bad hash":      {APIConfig{Enabled: true, Tokens: []APIToken{{Name: "ha", SHA256: "nos_plaintext", Scopes: []string{ScopeInventoryRead}}}}, "sha256"},
		"no scope":      {APIConfig{Enabled: true, Tokens: []APIToken{{Name: "ha", SHA256: good}}}, "at least one scope"},
		"unknown scope": {APIConfig{Enabled: true, Tokens: []APIToken{{Name: "ha", SHA256: good, Scopes: []string{"vault.read"}}}}, "unknown scope"},
		"same name": {APIConfig{Enabled: true, Tokens: []APIToken{{Name: "ha", SHA256: good, Scopes: []string{ScopeInventoryRead}},
			{Name: "ha", SHA256: strings.Repeat("b", 64), Scopes: []string{ScopeInventoryRead}}}}, "used twice"},
	} {
		t.Run(name, func(t *testing.T) {
			p := strings.Join(tc.api.Problems(), "; ")
			if (tc.want == "") != (p == "") || !strings.Contains(p, tc.want) {
				t.Fatalf("%q", p)
			}
		})
	}
}

// trustedJSON returns validJSON with the given extra top-level members.
func trustedJSON(extra string) []byte {
	return []byte(strings.TrimSuffix(strings.TrimSpace(validJSON), "}") + ",\n" + extra + "\n}")
}

// jsonList renders entries as a JSON array of strings.
func jsonList(entries []string) string {
	q := make([]string, len(entries))
	for i, e := range entries {
		q[i] = fmt.Sprintf("%q", e)
	}
	return "[" + strings.Join(q, ",") + "]"
}

// numberedAddrs returns n distinct IPv4 addresses (n < 250).
func numberedAddrs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("192.0.2.%d", i+1)
	}
	return out
}

// numberedNets returns n distinct /24 networks (n < 250).
func numberedNets(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("10.%d.0.0/24", i+1)
	}
	return out
}

// TestTrustedProxiesDefaultEmpty: without the keys no proxy is trusted, so
// the TCP peer is the client address (fail closed, ADR 0013 D7).
func TestTrustedProxiesDefaultEmpty(t *testing.T) {
	cfg, err := Parse([]byte(validJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TrustedProxies) != 0 || len(cfg.TrustedProxyNetworks) != 0 {
		t.Fatalf("default trusted proxies = %v / %v, want empty", cfg.TrustedProxies, cfg.TrustedProxyNetworks)
	}
	r, err := clientaddr.New(cfg.ClientAddrConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.HasTrustedProxies() {
		t.Fatal("resolver from the default configuration trusts a proxy")
	}
}

// TestTrustedProxiesAccepted: single addresses in every form ADR 0013 D7
// normalises (bare, /32, /128, IPv4-mapped, with port) and proxy-only
// networks load, and the loaded lists build the resolver unchanged.
func TestTrustedProxiesAccepted(t *testing.T) {
	singles := []string{"10.0.0.5", "10.0.0.6/32", "2001:db8::1/128", "::ffff:10.0.0.7", "10.0.0.8:443", "[2001:db8::2]:443"}
	nets := []string{"172.18.0.0/16", "fd00:1::/64"}
	cfg, err := Parse(trustedJSON(`"trusted_proxies": ` + jsonList(singles) + `, "trusted_proxy_networks": ` + jsonList(nets)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ac := cfg.ClientAddrConfig()
	if !slices.Equal(ac.TrustedProxies, singles) || !slices.Equal(ac.TrustedProxyNetworks, nets) {
		t.Fatalf("ClientAddrConfig = %v / %v, want %v / %v", ac.TrustedProxies, ac.TrustedProxyNetworks, singles, nets)
	}
	r, err := clientaddr.New(ac, nil)
	if err != nil {
		t.Fatalf("resolver refuses a configuration the loader accepted: %v", err)
	}
	if !r.HasTrustedProxies() {
		t.Fatal("resolver has no trusted proxies")
	}
}

// TestTrustedProxiesAtLimitAccepted: exactly MaxTrustedProxies entries in
// each list load.
func TestTrustedProxiesAtLimitAccepted(t *testing.T) {
	doc := trustedJSON(`"trusted_proxies": ` + jsonList(numberedAddrs(MaxTrustedProxies)) +
		`, "trusted_proxy_networks": ` + jsonList(numberedNets(MaxTrustedProxies)))
	if _, err := Parse(doc); err != nil {
		t.Fatalf("Parse at the limit: %v", err)
	}
}

// TestTrustedProxiesRejections: every invalid entry stops the start, and the
// error names the key and the entry index.
func TestTrustedProxiesRejections(t *testing.T) {
	cases := []struct {
		name  string
		extra string
		want  []string
	}{
		{"proxy not an address", `"trusted_proxies": ["proxy.example.org"]`, []string{"trusted_proxies[0]", "not an IP address"}},
		{"proxy empty", `"trusted_proxies": [""]`, []string{"trusted_proxies[0]", "not an IP address"}},
		{"proxy is a network", `"trusted_proxies": ["10.0.0.0/24"]`, []string{"trusted_proxies[0]", "single address", "trusted_proxy_networks"}},
		{"proxy prefix invalid", `"trusted_proxies": ["10.0.0.5/40"]`, []string{"trusted_proxies[0]", "not an IP address"}},
		{"proxy duplicate", `"trusted_proxies": ["10.0.0.5", "10.0.0.5"]`, []string{"trusted_proxies[1]", "duplicate of trusted_proxies[0]"}},
		{"proxy duplicate after normalisation", `"trusted_proxies": ["10.0.0.5", "::ffff:10.0.0.5"]`, []string{"trusted_proxies[1]", "duplicate of trusted_proxies[0]"}},
		{"proxy duplicate as /32", `"trusted_proxies": ["10.0.0.5:8080", "10.0.0.5/32"]`, []string{"trusted_proxies[1]", "duplicate of trusted_proxies[0]"}},
		{"too many proxies", `"trusted_proxies": ` + jsonList(numberedAddrs(MaxTrustedProxies+1)), []string{"trusted_proxies", fmt.Sprintf("at most %d entries", MaxTrustedProxies)}},
		{"network is a bare address", `"trusted_proxy_networks": ["10.0.0.5"]`, []string{"trusted_proxy_networks[0]", "network prefix"}},
		{"network not a prefix", `"trusted_proxy_networks": ["lan"]`, []string{"trusted_proxy_networks[0]", "network prefix"}},
		{"network bits out of range", `"trusted_proxy_networks": ["10.0.0.0/33"]`, []string{"trusted_proxy_networks[0]", "network prefix"}},
		{"network mapped prefix too short", `"trusted_proxy_networks": ["::ffff:10.0.0.0/88"]`, []string{"trusted_proxy_networks[0]", "network prefix"}},
		{"network host bits set", `"trusted_proxy_networks": ["10.0.0.5/24"]`, []string{"trusted_proxy_networks[0]", "host bits"}},
		{"network duplicate", `"trusted_proxy_networks": ["10.0.0.0/24", "10.0.0.0/24"]`, []string{"trusted_proxy_networks[1]", "duplicate of trusted_proxy_networks[0]"}},
		{"network duplicate after normalisation", `"trusted_proxy_networks": ["10.0.0.0/24", "::ffff:10.0.0.0/120"]`, []string{"trusted_proxy_networks[1]", "duplicate of trusted_proxy_networks[0]"}},
		{"too many networks", `"trusted_proxy_networks": ` + jsonList(numberedNets(MaxTrustedProxies+1)), []string{"trusted_proxy_networks", fmt.Sprintf("at most %d entries", MaxTrustedProxies)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(trustedJSON(tc.extra))
			if err == nil {
				t.Fatal("Parse accepted an invalid trusted-proxy configuration")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not contain %q", err, w)
				}
			}
		})
	}
}

// TestTrustedProxiesWrongTypeRefused: a string instead of a list is a parse
// error, not an empty list.
func TestTrustedProxiesWrongTypeRefused(t *testing.T) {
	for _, extra := range []string{`"trusted_proxies": "10.0.0.5"`, `"trusted_proxy_networks": "10.0.0.0/24"`, `"trusted_proxies": [5]`} {
		if _, err := Parse(trustedJSON(extra)); err == nil {
			t.Errorf("Parse accepted %s", extra)
		}
	}
}

// TestTrustedProxiesBothKeysReported: problems in both keys are listed at
// once, like every other problem of the loader.
func TestTrustedProxiesBothKeysReported(t *testing.T) {
	_, err := Parse(trustedJSON(`"trusted_proxies": ["nope"], "trusted_proxy_networks": ["10.0.0.5"]`))
	if err == nil {
		t.Fatal("Parse accepted two invalid keys")
	}
	for _, w := range []string{"trusted_proxies[0]", "trusted_proxy_networks[0]"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error %q does not name %s", err, w)
		}
	}
}

// TestTrustedProxiesLoadFailsStart: Load (the server's startup path) refuses
// a file with an invalid entry.
func TestTrustedProxiesLoadFailsStart(t *testing.T) {
	path := writeConfigFile(t, string(trustedJSON(`"trusted_proxies": ["10.0.0.0/8"]`)))
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "trusted_proxies[0]") {
		t.Fatalf("Load = %v, want an error naming trusted_proxies[0]", err)
	}
}
