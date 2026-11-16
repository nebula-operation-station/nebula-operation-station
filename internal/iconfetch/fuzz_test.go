// SPDX-License-Identifier: AGPL-3.0-or-later

package iconfetch

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// fuzzAllowlist is a custom allowlist with one upper-case entry, so the
// fuzzer also exercises the case folding of allow entries. The IP-literal
// entries make the no-IP-literal property non-vacuous: allowlist membership
// alone must not be what refuses them.
var fuzzAllowlist = []string{"ICONS.Example.ORG", "127.0.0.1", "2130706433", "0x7f.0.0.1"}

// acceptedURLs are URLs the policy must accept; they seed FuzzValidateURL.
var acceptedURLs = []string{
	"https://avatars.githubusercontent.com/u/1?v=4",
	"https://upload.wikimedia.org/wikipedia/commons/a/a1/Icon.png",
	"HTTPS://Avatars.GitHubUserContent.com/u/1",
	"https://avatars.githubusercontent.com:443/u/1",
	"https://avatars.githubusercontent.com",
	"https://icons.example.org/a.png",
	"https://ICONS.EXAMPLE.ORG:443/a.png?x=1",
}

// ipLiteralHost reports whether host is an IP address in any form a URL
// parser might turn into one: an IPv6 literal, a canonical IPv4 address, or
// a legacy IPv4 form (decimal, octal, hex or short) whose last label is
// numeric or hex. No DNS name the allowlist can hold ends in such a label,
// so the oracle treats these as literals independently of the parser.
func ipLiteralHost(host string) bool {
	if strings.Contains(host, ":") {
		return true
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	last := host[strings.LastIndexByte(host, '.')+1:]
	if strings.HasPrefix(last, "0x") {
		return true
	}
	for i := 0; i < len(last); i++ {
		if last[i] < '0' || last[i] > '9' {
			return false
		}
	}
	return last != ""
}

// checkURLPolicy asserts every property of an accepted URL, and that every
// rejection wraps ErrURL.
func checkURLPolicy(t *testing.T, raw string, allow []string) {
	t.Helper()
	u, err := ValidateURL(raw, allow)
	if err != nil {
		if !errors.Is(err, ErrURL) {
			t.Fatalf("ValidateURL(%q): error %v does not wrap ErrURL", raw, err)
		}
		return
	}
	if u.Scheme != "https" {
		t.Fatalf("ValidateURL(%q): scheme %q", raw, u.Scheme)
	}
	if u.User != nil {
		t.Fatalf("ValidateURL(%q): user info accepted", raw)
	}
	if u.Opaque != "" {
		t.Fatalf("ValidateURL(%q): opaque %q accepted", raw, u.Opaque)
	}
	if u.Fragment != "" || u.RawFragment != "" {
		t.Fatalf("ValidateURL(%q): fragment accepted", raw)
	}
	if u.Port() != "" {
		t.Fatalf("ValidateURL(%q): port %q accepted", raw, u.Port())
	}
	if u.Host != strings.ToLower(u.Host) {
		t.Fatalf("ValidateURL(%q): host %q not lower-case", raw, u.Host)
	}
	if ipLiteralHost(u.Host) {
		t.Fatalf("ValidateURL(%q): IP literal host %q accepted", raw, u.Host)
	}
	// The normalised URL is not enough: url.Parse decodes escapes and
	// ValidateURL rewrites u.Host, so the raw authority must itself be
	// https://<host>, optionally :443, then the end, "/" or "?".
	rest, ok := strings.CutPrefix(strings.ToLower(raw), "https://"+u.Host)
	if !ok {
		t.Fatalf("ValidateURL(%q): raw authority is not https://%s", raw, u.Host)
	}
	rest, _ = strings.CutPrefix(rest, ":443")
	if rest != "" && rest[0] != '/' && rest[0] != '?' {
		t.Fatalf("ValidateURL(%q): raw authority continues with %q", raw, rest)
	}
	listed := allow
	if len(listed) == 0 {
		listed = defaultAllowlist
	}
	found := false
	for _, a := range listed {
		if strings.ToLower(a) == u.Host {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ValidateURL(%q): host %q is not an allowlist entry", raw, u.Host)
	}
	if len(raw) > MaxURLLen {
		t.Fatalf("ValidateURL(%q): %d bytes accepted, limit %d", raw, len(raw), MaxURLLen)
	}
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		if b <= 0x20 || b >= 0x7f || b == '\\' || b == '#' {
			t.Fatalf("ValidateURL(%q): byte 0x%02x at %d accepted", raw, b, i)
		}
	}
}

// FuzzValidateURL checks the icon URL policy against the default allowlist
// and against a custom allowlist with an upper-case entry.
func FuzzValidateURL(f *testing.F) {
	for _, raw := range acceptedURLs {
		f.Add(raw)
	}
	for _, c := range bypassAttempts {
		f.Add(c.raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		checkURLPolicy(t, raw, nil)
		checkURLPolicy(t, raw, fuzzAllowlist)
	})
}

// mappedAddr returns the IPv4-mapped IPv6 form ::ffff:a.b.c.d.
func mappedAddr(a, b, c, d byte) netip.Addr {
	return netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 12: a, 13: b, 14: c, 15: d})
}

// internalIPv4 reports whether an IPv4 address with the given first two
// octets lies in a range the dialer must refuse: 0/8, loopback 127/8,
// RFC 1918 10/8, 172.16/12 and 192.168/16, and link-local 169.254/16.
func internalIPv4(a, b byte) bool {
	switch {
	case a == 0, a == 10, a == 127:
		return true
	case a == 169 && b == 254:
		return true
	case a == 172 && b&0xf0 == 16:
		return true
	case a == 192 && b == 168:
		return true
	}
	return false
}

// FuzzForbiddenAddr checks the properties documented on forbiddenAddr for
// IPv4, IPv4-mapped and IPv6 addresses, with and without a zone.
func FuzzForbiddenAddr(f *testing.F) {
	seeds := []struct {
		b    []byte
		mode uint8
	}{
		{[]byte{127, 0, 0, 1}, 0},
		{[]byte{8, 8, 8, 8}, 0},
		{[]byte{10, 0, 0, 1}, 0},
		{[]byte{172, 16, 0, 1}, 2},
		{[]byte{192, 168, 1, 1}, 0},
		{[]byte{0, 1, 2, 3}, 2},
		{[]byte{169, 254, 169, 254}, 2},
		{[]byte{140, 82, 112, 3}, 2},
		{[]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 1},
		{[]byte{0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11}, 1},
		{[]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 3},
		{[]byte{0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11}, 3},
	}
	for _, s := range seeds {
		f.Add(s.b, s.mode)
	}
	f.Fuzz(func(t *testing.T, b []byte, mode uint8) {
		var v [16]byte
		copy(v[:], b)
		var a netip.Addr
		switch mode % 4 {
		case 0: // IPv4
			a = netip.AddrFrom4([4]byte{v[0], v[1], v[2], v[3]})
		case 1: // IPv6 without zone
			a = netip.AddrFrom16(v)
		case 2: // IPv4-mapped IPv6
			a = mappedAddr(v[0], v[1], v[2], v[3])
		case 3: // IPv6 with zone
			a = netip.AddrFrom16(v).WithZone("eth0")
		}

		reason, bad := forbiddenAddr(a)
		if bad && reason == "" {
			t.Fatalf("forbiddenAddr(%s) refused without a reason", a)
		}
		if !bad && reason != "" {
			t.Fatalf("forbiddenAddr(%s) allowed with reason %q", a, reason)
		}
		if a.Is6() && !a.Is4In6() && !bad {
			t.Fatalf("forbiddenAddr(%s): non-mapped IPv6 address allowed", a)
		}
		if a.Zone() != "" && !bad {
			t.Fatalf("forbiddenAddr(%s): address with zone allowed", a)
		}
		if mode%4 == 0 || mode%4 == 2 {
			// Correctness, not just consistency: an implementation that
			// allowed every IPv4 address must fail here.
			if internalIPv4(v[0], v[1]) && !bad {
				t.Fatalf("forbiddenAddr(%s): internal IPv4 address allowed", a)
			}
		}
		if mode%4 == 0 {
			if _, mbad := forbiddenAddr(mappedAddr(v[0], v[1], v[2], v[3])); mbad != bad {
				t.Fatalf("forbiddenAddr(%s) = %v but its IPv4-mapped form = %v", a, bad, mbad)
			}
		}
	})
}
