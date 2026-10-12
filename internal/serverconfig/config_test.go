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
	"strings"
	"testing"
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
