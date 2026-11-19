// SPDX-License-Identifier: AGPL-3.0-or-later

package pvetransport

import (
	"strings"
	"testing"
)

// maxFuzzEndpointLen is the length of the very long seed. It only needs to
// be far larger than any realistic endpoint origin.
const maxFuzzEndpointLen = 8192

// FuzzParseEndpoint checks the invariants of ParseEndpoint for arbitrary
// input: it never panics; on success the scheme is exactly "https" and the
// host is not empty; and the accepted result, rendered back to a string and
// parsed again, is accepted as well (stability). Seeds use only example
// names and documentation addresses.
func FuzzParseEndpoint(f *testing.F) {
	seeds := []string{
		"https://pve.example",
		"https://pve.example:8006",
		"https://[2001:db8::1]:8006",
		"https://192.0.2.10:8006",
		"http://pve.example:8006",
		"",
		"https://",
		"https://:8006",
		"pve.example:8006",
		"https://user:secret@pve.example:8006",
		"https://pve.example/api2/json",
		"https://pve.example/?x=1",
		"https://pve.example?x=1",
		"https://pve.example#frag",
		"https://pve.example\x00",
		"https://pve.example\r\nHost: evil.example",
		"HTTPS://pve.example",
		"https://" + strings.Repeat("a", maxFuzzEndpointLen) + ".example",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		u, err := ParseEndpoint(raw)
		if err != nil {
			if u != nil {
				t.Fatalf("ParseEndpoint(%q) returned a URL together with error %v", raw, err)
			}
			return
		}
		if u == nil {
			t.Fatalf("ParseEndpoint(%q) returned nil URL without error", raw)
		}
		if u.Scheme != "https" {
			t.Fatalf("ParseEndpoint(%q) accepted scheme %q", raw, u.Scheme)
		}
		if u.Hostname() == "" {
			t.Fatalf("ParseEndpoint(%q) accepted an empty host", raw)
		}

		again, err := ParseEndpoint(u.String())
		if err != nil {
			t.Fatalf("ParseEndpoint(%q) accepted, but re-parse of %q failed: %v", raw, u.String(), err)
		}
		if again.Scheme != u.Scheme || again.Hostname() != u.Hostname() {
			t.Fatalf("ParseEndpoint(%q) unstable: scheme %q/%q host %q/%q",
				raw, u.Scheme, again.Scheme, u.Hostname(), again.Hostname())
		}
	})
}

// TestParseEndpointCurrentAcceptance records what ParseEndpoint accepts
// today for URLs that are not plain origins. It documents behaviour; it
// does not judge it. The doc comment says "endpoint origin", but the
// current code accepts userinfo, paths, queries and fragments as well.
func TestParseEndpointCurrentAcceptance(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		accepted bool
	}{
		{name: "origin with host", raw: "https://pve.example", accepted: true},
		{name: "origin with port", raw: "https://pve.example:8006", accepted: true},
		{name: "IPv6 literal with port", raw: "https://[2001:db8::1]:8006", accepted: true},
		{name: "uppercase scheme is normalised", raw: "HTTPS://pve.example", accepted: true},
		{name: "http scheme refused", raw: "http://pve.example:8006", accepted: false},
		{name: "scheme-less host refused", raw: "pve.example:8006", accepted: false},
		{name: "empty input refused", raw: "", accepted: false},
		{name: "empty host refused", raw: "https://", accepted: false},
		{name: "port without host refused", raw: "https://:8006", accepted: false},
		{name: "control character refused", raw: "https://pve.example\x00", accepted: false},
		// Not an origin in the strict sense, but accepted today:
		{name: "userinfo accepted", raw: "https://user:secret@pve.example:8006", accepted: true},
		{name: "path accepted", raw: "https://pve.example/api2/json", accepted: true},
		{name: "root path accepted", raw: "https://pve.example/", accepted: true},
		{name: "query accepted", raw: "https://pve.example?x=1", accepted: true},
		{name: "fragment accepted", raw: "https://pve.example#frag", accepted: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := ParseEndpoint(tt.raw)
			if got := err == nil; got != tt.accepted {
				t.Fatalf("ParseEndpoint(%q) accepted=%v, want %v (err=%v)", tt.raw, got, tt.accepted, err)
			}
			if err == nil && u.Hostname() == "" {
				t.Fatalf("ParseEndpoint(%q) accepted without host", tt.raw)
			}
		})
	}
}
