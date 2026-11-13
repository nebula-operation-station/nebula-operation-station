// SPDX-License-Identifier: AGPL-3.0-or-later

package iconfetch

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateURLAcceptsAllowlistedHTTPS(t *testing.T) {
	cases := []struct {
		raw, wantHost, wantString string
	}{
		{"https://avatars.githubusercontent.com/u/1?v=4", "avatars.githubusercontent.com", "https://avatars.githubusercontent.com/u/1?v=4"},
		{"https://upload.wikimedia.org/wikipedia/commons/a/a1/Icon.png", "upload.wikimedia.org", "https://upload.wikimedia.org/wikipedia/commons/a/a1/Icon.png"},
		{"HTTPS://Avatars.GitHubUserContent.com/u/1", "avatars.githubusercontent.com", "https://avatars.githubusercontent.com/u/1"},
		{"https://avatars.githubusercontent.com:443/u/1", "avatars.githubusercontent.com", "https://avatars.githubusercontent.com/u/1"},
		{"https://avatars.githubusercontent.com", "avatars.githubusercontent.com", "https://avatars.githubusercontent.com"},
	}
	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			u, err := ValidateURL(c.raw, nil)
			if err != nil {
				t.Fatalf("ValidateURL(%q): %v", c.raw, err)
			}
			if u.Host != c.wantHost {
				t.Errorf("host = %q, want %q", u.Host, c.wantHost)
			}
			if got := u.String(); got != c.wantString {
				t.Errorf("String() = %q, want %q", got, c.wantString)
			}
		})
	}
}

func TestValidateURLCustomAllowlistReplacesDefault(t *testing.T) {
	allow := []string{"Icons.Example.org"}
	if _, err := ValidateURL("https://icons.example.org/a.png", allow); err != nil {
		t.Fatalf("custom allowlisted host rejected: %v", err)
	}
	if _, err := ValidateURL("https://avatars.githubusercontent.com/u/1", allow); !errors.Is(err, ErrURL) {
		t.Fatalf("default host accepted with a custom allowlist: %v", err)
	}
}

// bypassAttempts are URLs that must be refused under the default allowlist.
// FuzzValidateURL uses them as seeds.
var bypassAttempts = []struct{ name, raw string }{
	{"empty", ""},
	{"http scheme", "http://avatars.githubusercontent.com/u/1"},
	{"ftp scheme", "ftp://avatars.githubusercontent.com/u/1"},
	{"scheme relative", "//avatars.githubusercontent.com/u/1"},
	{"no scheme", "avatars.githubusercontent.com/u/1"},
	{"opaque", "https:avatars.githubusercontent.com/u/1"},
	{"userinfo", "https://user@avatars.githubusercontent.com/u/1"},
	{"userinfo password", "https://user:pw@avatars.githubusercontent.com/u/1"},
	{"userinfo is allowlisted", "https://avatars.githubusercontent.com@evil.example/u/1"},
	{"userinfo empty", "https://@avatars.githubusercontent.com/u/1"},
	{"backslash authority", "https://evil.example\\@avatars.githubusercontent.com/u/1"},
	{"backslash path", "https://avatars.githubusercontent.com\\evil.example/u/1"},
	{"trailing dot", "https://avatars.githubusercontent.com./u/1"},
	{"suffix match", "https://evil.avatars.githubusercontent.com/u/1"},
	{"prefix match", "https://avatars.githubusercontent.com.evil.example/u/1"},
	{"lookalike", "https://avatars-githubusercontent.com/u/1"},
	{"punycode", "https://xn--avatars-githubusercontent-9qc.com/u/1"},
	{"unicode host", "https://avatars.githubusercontent.cöm/u/1"},
	{"fullwidth dot", "https://avatars．githubusercontent.com/u/1"},
	{"percent encoded host", "https://avatars%2egithubusercontent.com/u/1"},
	{"percent encoded host char", "https://%61vatars.githubusercontent.com/u/1"},
	{"port 8443", "https://avatars.githubusercontent.com:8443/u/1"},
	{"port 80", "https://avatars.githubusercontent.com:80/u/1"},
	{"empty port", "https://avatars.githubusercontent.com:/u/1"},
	{"port 0443", "https://avatars.githubusercontent.com:0443/u/1"},
	{"fragment", "https://avatars.githubusercontent.com/u/1#x"},
	{"empty fragment", "https://avatars.githubusercontent.com/u/1#"},
	{"ipv4", "https://127.0.0.1/a.png"},
	{"ipv4 metadata", "https://169.254.169.254/latest/meta-data"},
	{"ipv4 public", "https://140.82.112.3/a.png"},
	{"decimal ipv4", "https://2130706433/a.png"},
	{"octal ipv4", "https://0177.0.0.1/a.png"},
	{"hex ipv4", "https://0x7f.0.0.1/a.png"},
	{"hex ipv4 whole", "https://0x7f000001/a.png"},
	{"short ipv4", "https://127.1/a.png"},
	{"ipv6", "https://[::1]/a.png"},
	{"ipv6 mapped", "https://[::ffff:127.0.0.1]/a.png"},
	{"ipv6 zone", "https://[fe80::1%25eth0]/a.png"},
	{"control char", "https://avatars.githubusercontent.com/u/1\x00"},
	{"space in host", "https://avatars githubusercontent.com/u/1"},
	{"newline", "https://avatars.githubusercontent.com/u/1\r\nHost: evil"},
	{"too long", "https://avatars.githubusercontent.com/" + strings.Repeat("a", MaxURLLen)},
	{"invalid utf8", "https://avatars.githubusercontent.com/\xff"},
}

func TestValidateURLRejectsBypassAttempts(t *testing.T) {
	for _, c := range bypassAttempts {
		t.Run(c.name, func(t *testing.T) {
			u, err := ValidateURL(c.raw, nil)
			if err == nil {
				t.Fatalf("ValidateURL(%q) accepted, host %q", c.raw, u.Host)
			}
			if !errors.Is(err, ErrURL) {
				t.Fatalf("ValidateURL(%q) error %v is not ErrURL", c.raw, err)
			}
		})
	}
}

func TestValidateURLLengthBoundary(t *testing.T) {
	const base = "https://avatars.githubusercontent.com/"
	exact := base + strings.Repeat("a", MaxURLLen-len(base))
	if len(exact) != MaxURLLen {
		t.Fatalf("test input is %d bytes, want %d", len(exact), MaxURLLen)
	}
	cases := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"exactly MaxURLLen bytes", exact, false},
		{"one byte over MaxURLLen", exact + "a", true},
		{"empty string", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ValidateURL(c.raw, nil)
			if !c.wantErr {
				if err != nil {
					t.Fatalf("ValidateURL(len %d): %v", len(c.raw), err)
				}
				return
			}
			if !errors.Is(err, ErrURL) {
				t.Fatalf("ValidateURL(len %d) error %v, want ErrURL", len(c.raw), err)
			}
		})
	}
}

func TestValidateURLIPLiteralRejectedEvenIfAllowlisted(t *testing.T) {
	allow := []string{"127.0.0.1", "2130706433", "0x7f.0.0.1", "::1", "[::1]"}
	for _, raw := range []string{"https://127.0.0.1/", "https://2130706433/", "https://0x7f.0.0.1/", "https://[::1]/"} {
		if _, err := ValidateURL(raw, allow); !errors.Is(err, ErrURL) {
			t.Errorf("ValidateURL(%q) with IP on allowlist: %v, want ErrURL", raw, err)
		}
	}
}
