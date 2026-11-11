// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// parseEnroll registers the enrollment flags on a fresh flag set, parses
// args and loads the configuration as the executor start does.
func parseEnroll(t *testing.T, args ...string) (enrollConfig, error) {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	f := registerEnrollFlags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	return f.load()
}

func TestEnrollConfigDefaults(t *testing.T) {
	cfg, err := parseEnroll(t)
	if err != nil {
		t.Fatalf("defaults: %v", err)
	}
	if cfg.ManagedGroup != "nos-managed" {
		t.Errorf("managed group = %q, want nos-managed", cfg.ManagedGroup)
	}
	if len(cfg.Sources) != 0 {
		t.Errorf("sources = %v, want none", cfg.Sources)
	}
	if cfg.NetBird.Enabled() {
		t.Errorf("NetBird enabled without a management URL")
	}
	if cfg.NetBird.RootCAs != nil || cfg.NetBird.CAFile != "" {
		t.Errorf("default TLS trust is not the system trust store")
	}
	if got := cfg.NetBird.TrustName(); got != "system" {
		t.Errorf("trust = %q, want system", got)
	}
}

func TestEnrollSourcesValid(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{"single IPv4", []string{"-enroll-source", "192.0.2.10"}, []string{"192.0.2.10"}},
		{"IPv4 CIDR", []string{"-enroll-source", "192.0.2.0/24"}, []string{"192.0.2.0/24"}},
		{"IPv6", []string{"-enroll-source", "2001:db8::10"}, []string{"2001:db8::10"}},
		{"IPv6 canonicalised", []string{"-enroll-source", "2001:DB8:0:0::10"}, []string{"2001:db8::10"}},
		{"IPv6 CIDR", []string{"-enroll-source", "2001:db8:1::/48"}, []string{"2001:db8:1::/48"}},
		{"IPv6 host prefix", []string{"-enroll-source", "2001:db8::1/128"}, []string{"2001:db8::1/128"}},
		{"comma list with spaces", []string{"-enroll-source", "192.0.2.10, 2001:db8::/32"}, []string{"192.0.2.10", "2001:db8::/32"}},
		{"repeated flag", []string{"-enroll-source", "192.0.2.10", "-enroll-source", "100.64.0.0/10"}, []string{"192.0.2.10", "100.64.0.0/10"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseEnroll(t, tc.args...)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if !reflect.DeepEqual(cfg.Sources, tc.want) {
				t.Errorf("sources = %v, want %v", cfg.Sources, tc.want)
			}
		})
	}
}

func TestEnrollSourcesInvalidFailLoad(t *testing.T) {
	tooMany := make([]string, enrollSourcesMax+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("192.0.2.%d", i+1)
	}
	tests := []struct {
		name  string
		value string
	}{
		{"host name", "nos.example.org"},
		{"empty entry", "192.0.2.10,,192.0.2.11"},
		{"only comma", ","},
		{"blank", " "},
		{"garbage", "not-an-ip"},
		{"IPv4 out of range", "192.0.2.256"},
		{"IPv4 with port", "192.0.2.10:22"},
		{"bad prefix length", "192.0.2.0/33"},
		{"IPv6 bad prefix length", "2001:db8::/129"},
		{"IPv6 zone", "fe80::1%eth0"},
		{"IPv6 zone CIDR", "fe80::1%eth0/64"},
		{"IPv6 brackets", "[2001:db8::1]"},
		{"IPv4 host bits set", "192.0.2.10/24"},
		{"IPv6 host bits set", "2001:db8::1/64"},
		{"IPv4-mapped IPv6", "::ffff:192.0.2.10"},
		{"IPv4-mapped IPv6 CIDR", "::ffff:192.0.2.0/120"},
		{"duplicate", "192.0.2.10,192.0.2.10"},
		{"duplicate after canonicalisation", "2001:db8::1,2001:DB8:0::1"},
		{"shell metacharacter", "192.0.2.10'"},
		{"too long", strings.Repeat("1", enrollSourceMaxLen+1)},
		{"too many", strings.Join(tooMany, ",")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseEnroll(t, "-enroll-source", tc.value)
			if !errors.Is(err, errInvalidEnrollConfig) {
				t.Fatalf("load %q: err = %v, want errInvalidEnrollConfig", tc.value, err)
			}
			if !strings.Contains(err.Error(), "-enroll-source") {
				t.Errorf("error %q does not name the flag", err)
			}
		})
	}
}

func TestNetBirdManagementURLValid(t *testing.T) {
	for _, u := range []string{
		"https://api.netbird.io",
		"https://netbird.example.org:33073",
		"https://netbird.example.org/api",
		"https://netbird.example.org/a-b/c_d.e~f/",
		"https://192.0.2.5",
		"https://192.0.2.5:443",
		"https://[2001:db8::5]",
		"https://[2001:db8::5]:8443/mgmt",
		"https://nb",
		"https://NetBird.Example.org",
	} {
		t.Run(u, func(t *testing.T) {
			cfg, err := parseEnroll(t, "-netbird-management-url", u)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if cfg.NetBird.ManagementURL != u || !cfg.NetBird.Enabled() {
				t.Errorf("management URL = %q enabled=%v", cfg.NetBird.ManagementURL, cfg.NetBird.Enabled())
			}
		})
	}
}

func TestNetBirdManagementURLInvalidFailLoad(t *testing.T) {
	tests := []struct{ name, url string }{
		{"http", "http://netbird.example.org"},
		{"upper-case scheme", "HTTPS://netbird.example.org"},
		{"no scheme", "netbird.example.org"},
		{"scheme only", "https://"},
		{"opaque", "https:netbird.example.org"},
		{"userinfo", "https://user@netbird.example.org"},
		{"userinfo password", "https://user:pw@netbird.example.org"},
		{"query", "https://netbird.example.org/?a=b"},
		{"empty query", "https://netbird.example.org/?"},
		{"fragment", "https://netbird.example.org/#x"},
		{"percent-encoding", "https://netbird.example.org/a%20b"},
		{"space", "https://netbird.example.org/a b"},
		{"tab", "https://netbird.example.org/\t"},
		{"newline", "https://netbird.example.org\n"},
		{"quote", "https://netbird.example.org/'"},
		{"double quote", `https://netbird.example.org/"`},
		{"dollar", "https://netbird.example.org/$x"},
		{"backtick", "https://netbird.example.org/`id`"},
		{"backslash", `https://netbird.example.org\x`},
		{"semicolon", "https://netbird.example.org/;id"},
		{"non-ASCII", "https://netbird.exämple.org"},
		{"IPv6 zone", "https://[fe80::1%25eth0]"},
		{"IPv6 without brackets", "https://2001:db8::5"},
		{"IPv4 in brackets", "https://[192.0.2.5]"},
		{"IPv4-mapped in brackets", "https://[::ffff:192.0.2.5]"},
		{"port zero", "https://netbird.example.org:0"},
		{"port too large", "https://netbird.example.org:65536"},
		{"port leading zero", "https://netbird.example.org:0443"},
		{"empty port", "https://netbird.example.org:"},
		{"port not numeric", "https://netbird.example.org:https"},
		{"label leading hyphen", "https://-netbird.example.org"},
		{"label trailing hyphen", "https://netbird-.example.org"},
		{"underscore in host", "https://net_bird.example.org"},
		{"empty label", "https://netbird..example.org"},
		{"trailing dot", "https://netbird.example.org."},
		{"label too long", "https://" + strings.Repeat("a", 64) + ".example.org"},
		{"too long", "https://netbird.example.org/" + strings.Repeat("a", netBirdMgmtURLMaxLen)},
		{"dot segment", "https://netbird.example.org/../x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseEnroll(t, "-netbird-management-url", tc.url)
			if !errors.Is(err, errInvalidEnrollConfig) {
				t.Fatalf("load %q: err = %v, want errInvalidEnrollConfig", tc.url, err)
			}
			if !strings.Contains(err.Error(), "-netbird-management-url") {
				t.Errorf("error %q does not name the flag", err)
			}
		})
	}
}

func TestNetBirdManagementURLAtLimit(t *testing.T) {
	prefix := "https://netbird.example.org/"
	u := prefix + strings.Repeat("a", netBirdMgmtURLMaxLen-len(prefix))
	if len(u) != netBirdMgmtURLMaxLen {
		t.Fatalf("fixture length %d", len(u))
	}
	if _, err := parseEnroll(t, "-netbird-management-url", u); err != nil {
		t.Fatalf("URL of exactly %d bytes refused: %v", netBirdMgmtURLMaxLen, err)
	}
	if _, err := parseEnroll(t, "-netbird-management-url", u+"a"); !errors.Is(err, errInvalidEnrollConfig) {
		t.Fatalf("URL of %d bytes: err = %v", netBirdMgmtURLMaxLen+1, err)
	}
}

// writeCert writes n self-signed certificates as PEM to a new file in a
// temporary directory and returns its path.
func writeCert(t *testing.T, n int, extra string) string {
	t.Helper()
	var buf bytes.Buffer
	for i := range n {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(i + 1)),
			Subject:               pkix.Name{CommonName: "test netbird ca"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
		if err != nil {
			t.Fatal(err)
		}
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			t.Fatal(err)
		}
	}
	buf.WriteString(extra)
	return writeCAFile(t, buf.Bytes(), 0o644)
}

func writeCAFile(t *testing.T, data []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "netbird-ca.pem")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNetBirdCAFileValid(t *testing.T) {
	for _, n := range []int{1, 2} {
		p := writeCert(t, n, "")
		cfg, err := parseEnroll(t, "-netbird-management-url", "https://netbird.example.org", "-netbird-ca-file", p)
		if err != nil {
			t.Fatalf("%d certificates: %v", n, err)
		}
		if cfg.NetBird.RootCAs == nil || cfg.NetBird.CAFile != p {
			t.Fatalf("%d certificates: pinned trust not loaded", n)
		}
		if got := cfg.NetBird.TrustName(); got != "ca-file" {
			t.Errorf("trust = %q, want ca-file", got)
		}
	}
}

func TestNetBirdCAFileInvalidFailLoad(t *testing.T) {
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")}))
	tests := []struct {
		name string
		path func(t *testing.T) string
	}{
		{"relative path", func(*testing.T) string { return "netbird-ca.pem" }},
		{"missing file", func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing.pem") }},
		{"directory", func(t *testing.T) string { return t.TempDir() }},
		{"empty file", func(t *testing.T) string { return writeCAFile(t, nil, 0o644) }},
		{"no PEM", func(t *testing.T) string { return writeCAFile(t, []byte("hello\n"), 0o644) }},
		{"private key block", func(t *testing.T) string { return writeCAFile(t, []byte(keyPEM), 0o644) }},
		{"certificate plus private key", func(t *testing.T) string { return writeCert(t, 1, keyPEM) }},
		{"trailing garbage", func(t *testing.T) string { return writeCert(t, 1, "zz-content-marker\n") }},
		{"broken certificate", func(t *testing.T) string {
			return writeCAFile(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}), 0o644)
		}},
		{"world-writable", func(t *testing.T) string {
			p := writeCert(t, 1, "")
			if err := os.Chmod(p, 0o666); err != nil {
				t.Fatal(err)
			}
			return p
		}},
		{"group-writable", func(t *testing.T) string {
			p := writeCert(t, 1, "")
			if err := os.Chmod(p, 0o664); err != nil {
				t.Fatal(err)
			}
			return p
		}},
		{"too large", func(t *testing.T) string {
			return writeCAFile(t, bytes.Repeat([]byte("\n"), netBirdCAFileMaxBytes+1), 0o644)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.path(t)
			_, err := parseEnroll(t, "-netbird-management-url", "https://netbird.example.org", "-netbird-ca-file", p)
			if !errors.Is(err, errInvalidEnrollConfig) {
				t.Fatalf("err = %v, want errInvalidEnrollConfig", err)
			}
			if !strings.Contains(err.Error(), "-netbird-ca-file") {
				t.Errorf("error %q does not name the flag", err)
			}
			if strings.Contains(err.Error(), "BEGIN") || strings.Contains(err.Error(), "zz-content-marker") {
				t.Errorf("error %q echoes file content", err)
			}
		})
	}
}

func TestNetBirdCAFileWithoutURLFailsLoad(t *testing.T) {
	p := writeCert(t, 1, "")
	_, err := parseEnroll(t, "-netbird-ca-file", p)
	if !errors.Is(err, errInvalidEnrollConfig) {
		t.Fatalf("err = %v, want errInvalidEnrollConfig", err)
	}
}

func TestManagedGroup(t *testing.T) {
	valid := []string{"nos-managed", "lab_hosts", "Managed.Hosts", "a", strings.Repeat("g", managedGroupMaxLen)}
	for _, g := range valid {
		cfg, err := parseEnroll(t, "-netbird-managed-group", g)
		if err != nil {
			t.Errorf("group %q refused: %v", g, err)
			continue
		}
		if cfg.ManagedGroup != g {
			t.Errorf("group = %q, want %q", cfg.ManagedGroup, g)
		}
	}
	invalid := []string{
		"", " ", "nos managed", "-managed", ".managed", "nos'", "nos$x", "grüppe", "a\nb",
		strings.Repeat("g", managedGroupMaxLen+1),
		// NetBird's built-in group and the NOS machine's own group (ADR 0013 D6).
		"All", "all", "nos", "NOS",
	}
	for _, g := range invalid {
		_, err := parseEnroll(t, "-netbird-managed-group", g)
		if !errors.Is(err, errInvalidEnrollConfig) {
			t.Errorf("group %q: err = %v, want errInvalidEnrollConfig", g, err)
			continue
		}
		if !strings.Contains(err.Error(), "-netbird-managed-group") {
			t.Errorf("error %q does not name the flag", err)
		}
	}
}

// TestEnrollConfigHasNoSetters backs "nothing settable over RPC" (EN-06):
// the configuration types offer no setter a service could call; the values
// come only from executor flags read at start.
func TestEnrollConfigHasNoSetters(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeFor[enrollConfig](), reflect.TypeFor[*enrollConfig](), reflect.TypeFor[netBirdConfig](), reflect.TypeFor[*netBirdConfig]()} {
		for i := range typ.NumMethod() {
			m := typ.Method(i)
			if strings.HasPrefix(m.Name, "Set") {
				t.Errorf("%s has setter %s", typ, m.Name)
			}
		}
	}
}

// enrollHelperEnv makes the test binary run the executor's main with the
// arguments after "--", so the start-up exit status can be checked.
const enrollHelperEnv = "NOS_TEST_EXECUTOR_MAIN"

func TestInvalidEnrollConfigStopsStart(t *testing.T) {
	if os.Getenv(enrollHelperEnv) == "1" {
		args := os.Args
		for i, a := range args {
			if a == "--" {
				os.Args = append([]string{"nebula-executor"}, args[i+1:]...)
				break
			}
		}
		main()
		os.Exit(0)
	}
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"host name source", []string{"-enroll-source", "nos.example.org"}, "-enroll-source"},
		{"IPv6 zone source", []string{"-enroll-source", "fe80::1%eth0"}, "-enroll-source"},
		{"http management URL", []string{"-netbird-management-url", "http://netbird.example.org"}, "-netbird-management-url"},
		{"missing CA file", []string{"-netbird-management-url", "https://netbird.example.org", "-netbird-ca-file", "/nonexistent/ca.pem"}, "-netbird-ca-file"},
		{"empty managed group", []string{"-netbird-managed-group", ""}, "-netbird-managed-group"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// -data-dir points at a directory that does not exist: if the
			// enrollment check did not stop the start first, a later step
			// would fail with another message.
			args := append([]string{"-test.run=^TestInvalidEnrollConfigStopsStart$", "--", "-data-dir", filepath.Join(t.TempDir(), "absent")}, tc.args...)
			cmd := exec.Command(os.Args[0], args...)
			cmd.Env = append(os.Environ(), enrollHelperEnv+"=1")
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			err := cmd.Run()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() == 0 {
				t.Fatalf("start with %v: err = %v, want non-zero exit", tc.args, err)
			}
			msg := stderr.String()
			if !strings.Contains(msg, "invalid enrollment configuration") || !strings.Contains(msg, tc.wantErr) {
				t.Errorf("stderr = %q, want a clear enrollment configuration error naming %s", msg, tc.wantErr)
			}
		})
	}
	t.Run("valid enrollment config passes the check", func(t *testing.T) {
		args := []string{"-test.run=^TestInvalidEnrollConfigStopsStart$", "--",
			"-data-dir", filepath.Join(t.TempDir(), "absent"),
			"-enroll-source", "192.0.2.10,2001:db8::/32",
			"-netbird-management-url", "https://[2001:db8::5]:443"}
		cmd := exec.Command(os.Args[0], args...)
		cmd.Env = append(os.Environ(), enrollHelperEnv+"=1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		_ = cmd.Run() // fails later (no -rp-id, root or data dir), not on enrollment
		if strings.Contains(stderr.String(), "enrollment configuration") {
			t.Errorf("valid config refused: %q", stderr.String())
		}
	})
}
