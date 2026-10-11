// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for the nebula-server configuration: JSON loading with unknown-key
// rejection, field validation (listen, public origin), defaults, and the
// "every problem at once" error (acceptance criteria 1-3).

package serverconfig

import (
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
	// The flag-override pattern: load, set a field, re-validate.
	cfg, err := Parse([]byte(validJSON))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Listen = "127.0.0.1:9090"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("re-validate after override: %v", err)
	}
	if cfg.Listen != "127.0.0.1:9090" {
		t.Errorf("override not applied: %q", cfg.Listen)
	}
	// A bad override must be caught by re-validation.
	cfg.Listen = "0.0.0.0:9090"
	if err := cfg.Validate(); err == nil {
		t.Error("expected validation error for non-loopback override")
	}
}
