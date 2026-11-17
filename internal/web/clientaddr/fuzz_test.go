// SPDX-License-Identifier: AGPL-3.0-or-later

package clientaddr

import (
	"net/netip"
	"strings"
	"testing"
)

// fuzzTrustedProxy and fuzzTrustedNet are the fixed trusted-proxy
// configuration of the resolver fuzz target: one trusted proxy address and
// one pure proxy network.
var (
	fuzzTrustedProxy = netip.MustParseAddr("203.0.113.1")
	fuzzTrustedNet   = netip.MustParsePrefix("198.51.100.0/24")
)

// fuzzResolver builds the resolver used by FuzzResolve with default limits.
func fuzzResolver(tb testing.TB) *Resolver {
	tb.Helper()
	r, err := New(Config{
		TrustedProxies:       []string{fuzzTrustedProxy.String()},
		TrustedProxyNetworks: []string{fuzzTrustedNet.String()},
	}, nil)
	if err != nil {
		tb.Fatalf("New: %v", err)
	}
	return r
}

// oracleTrusted is an independent statement of the trusted-proxy rule for
// the fixed configuration above; it does not call the resolver.
func oracleTrusted(a netip.Addr) bool {
	return a == fuzzTrustedProxy || fuzzTrustedNet.Contains(a)
}

// oracleParse is an independent statement of the address syntax: blanks
// (space and tab) around the value are ignored, the value is either a bare
// address or an address with a port, an IPv6 zone is dropped and an
// IPv4-mapped IPv6 address is shown in IPv4 form. It does not call Normalize,
// so a too lenient or too strict Normalize shows up as a disagreement.
func oracleParse(s string) (netip.Addr, bool) {
	s = strings.Trim(s, " \t")
	if a, err := netip.ParseAddr(s); err == nil {
		return a.WithZone("").Unmap(), true
	}
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().WithZone("").Unmap(), true
}

// fuzzLines maps the two fuzzed header values to header lines. Both empty
// means no X-Forwarded-For line at all; an empty second value means a single
// line; otherwise two lines are sent (an empty first one is an empty line).
func fuzzLines(xff1, xff2 string) []string {
	switch {
	case xff1 == "" && xff2 == "":
		return nil
	case xff2 == "":
		return []string{xff1}
	default:
		return []string{xff1, xff2}
	}
}

// checkRefusal requires err to be nil or exactly one of the forwarded-header
// sentinels or ErrPeerInvalid (not a wrapped or joined error).
func checkRefusal(t *testing.T, err error) {
	t.Helper()
	if err == nil || err == ErrPeerInvalid {
		return
	}
	for _, s := range allSentinels {
		if err == s {
			return
		}
	}
	t.Fatalf("err = %v, want nil, ErrPeerInvalid or exactly one ErrForwarded* sentinel", err)
}

// checkNoFallback requires a refused request (a forwarded-header sentinel)
// to carry no client address and not be marked as forwarded. The peer may
// still be reported for logging, but a refusal never falls back to the peer
// address and never uses the header.
func checkNoFallback(t *testing.T, res Result, err error) {
	t.Helper()
	if res.Client.IsValid() || res.Forwarded {
		t.Fatalf("refused with %v: Result %+v, want no client and Forwarded=false", err, res)
	}
}

// FuzzNormalize checks that Normalize never panics, agrees with the
// independent oracle on which inputs are addresses (so non-addresses such as
// "192.0.2.1 x" are rejected) and that an accepted address is valid, unmapped
// and has no zone.
func FuzzNormalize(f *testing.F) {
	for _, s := range []string{
		"", " ", "192.0.2.1", " 192.0.2.1 ", "192.0.2.1:80", "192.0.2.1:99999",
		"[2001:db8::1]:443", "2001:db8::1", "::ffff:192.0.2.1", "[::ffff:192.0.2.1]:80",
		"fe80::1%eth0", "[fe80::1%25eth0]:80", "2001:db8::1%", "%", "@",
		"192.0.2.1 x", "\t192.0.2.1\t", "192.0.2.10, 192.0.2.11", "::",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, err := Normalize(s)
		want, ok := oracleParse(s)
		if (err == nil) != ok {
			t.Fatalf("Normalize(%q) err = %v, but the oracle accepts it: %v", s, err, ok)
		}
		if err != nil {
			return
		}
		if !a.IsValid() {
			t.Fatalf("Normalize(%q) accepted an invalid address", s)
		}
		if a.Is4In6() {
			t.Fatalf("Normalize(%q) = %v, IPv4-mapped IPv6 must be unmapped", s, a)
		}
		if a.Zone() != "" {
			t.Fatalf("Normalize(%q) = %v, zone must be stripped", s, a)
		}
		if a != want {
			t.Fatalf("Normalize(%q) = %v, oracle says %v", s, a, want)
		}
	})
}

// FuzzResolve checks the resolver for arbitrary peers and up to two
// X-Forwarded-For lines with the fixed configuration of fuzzResolver.
func FuzzResolve(f *testing.F) {
	long := strings.Repeat("[2001:db8:1::1234:5678:9abc]:65535, ", 30) + "192.0.2.10"
	many := strings.Join(append(padding(16), "192.0.2.10"), ", ")
	for _, s := range []struct{ peer, x1, x2 string }{
		{"203.0.113.1:1", "", ""},                                     // missing
		{"203.0.113.1:1", long, ""},                                   // too long
		{"203.0.113.1:1", "not-an-ip, " + long, ""},                   // too long beats garbage
		{"203.0.113.1:1", "not-an-ip, " + many, ""},                   // too many beats garbage
		{"203.0.113.1:1", "192.0.2.250, not-an-ip, 198.51.100.9", ""}, // malformed
		{"203.0.113.1:1", "not-an-ip, 192.0.2.10", ""},                // malformed left
		{"203.0.113.1:1", "192.0.2.10, not-an-ip", ""},                // malformed right
		{"203.0.113.1:1", "192.0.2.10, ", ""},                         // empty entry
		{"203.0.113.1:1", "", "192.0.2.10"},                           // empty first line
		{"203.0.113.1:1", "198.51.100.9, 203.0.113.1", ""},            // only trusted
		{"203.0.113.1:1", "198.51.100.9, 198.51.100.8", ""},           // only trusted in network
		{"203.0.113.1:1", "203.0.113.1", ""},                          // single trusted entry
		{"203.0.113.1:1", long[:600], long[600:]},                     // lines joined too long
		{"203.0.113.1:1", strings.Join(padding(9), ", "), strings.Join(append(padding(7), "192.0.2.10"), ", ")}, // lines joined too many
		{"203.0.113.1:1", "192.0.2.10", "192.0.2.11"},                                                           // client over two lines
		{"198.51.100.7:1", "192.0.2.10, 198.51.100.9", ""},                                                      // peer in proxy network
		{"[::ffff:203.0.113.1]:443", "192.0.2.10", ""},                                                          // mapped trusted peer
		{"192.0.2.77:1", "garbage", "x"},                                                                        // untrusted peer, header ignored
		{"192.0.2.77:1", long, ""},                                                                              // untrusted peer, too long ignored
		{"@", "", ""},                                                                                           // invalid peer
		{"", "192.0.2.10", ""},                                                                                  // empty peer
	} {
		f.Add(s.peer, s.x1, s.x2)
	}
	f.Fuzz(func(t *testing.T, peer, xff1, xff2 string) {
		r := fuzzResolver(t)
		lines := fuzzLines(xff1, xff2)
		res, err := r.Resolve(request(peer, lines...))
		checkRefusal(t, err)

		pa, paOK := oracleParse(peer)
		if !paOK {
			// Property: an invalid peer is refused with ErrPeerInvalid and
			// nothing else; no header value leaks into the Result.
			if err != ErrPeerInvalid || res != (Result{}) {
				t.Fatalf("peer %q: got %+v, %v; want zero Result and ErrPeerInvalid", peer, res, err)
			}
			return
		}
		if err == ErrPeerInvalid {
			t.Fatalf("valid peer %q refused as ErrPeerInvalid", peer)
		}
		if res.Peer != pa {
			t.Fatalf("peer %q: Result.Peer = %v, want %v", peer, res.Peer, pa)
		}
		if err != nil {
			// Property: a refused header never falls back to the peer or
			// to the header.
			checkNoFallback(t, res, err)
		}
		if !oracleTrusted(pa) {
			// Property: an untrusted peer is the client; headers are ignored.
			if err != nil || res.Forwarded || res.Client != pa {
				t.Fatalf("untrusted peer %v: got %+v, %v; want peer as client", pa, res, err)
			}
			return
		}

		// Trusted peer from here on: the header decides.
		if len(lines) == 0 {
			if err != ErrForwardedMissing {
				t.Fatalf("no header: err = %v, want ErrForwardedMissing", err)
			}
			return
		}
		joined := strings.Join(lines, ", ")
		if len(joined) > DefaultMaxHeaderBytes {
			// Property: an oversize composite value is always too long.
			if err != ErrForwardedTooLong {
				t.Fatalf("composite of %d bytes: err = %v, want ErrForwardedTooLong", len(joined), err)
			}
			return
		}
		if entries := strings.Count(joined, ",") + 1; entries > DefaultMaxEntries {
			if err != ErrForwardedTooManyEntries {
				t.Fatalf("%d entries: err = %v, want ErrForwardedTooManyEntries", entries, err)
			}
			return
		}
		if err == ErrForwardedMissing || err == ErrForwardedTooLong || err == ErrForwardedTooManyEntries {
			t.Fatalf("within limits: err = %v, want nil, malformed or only-trusted", err)
		}

		parts := strings.Split(joined, ",")
		addrs := make([]netip.Addr, 0, len(parts))
		malformed := false
		for _, p := range parts {
			a, ok := oracleParse(p)
			if !ok {
				malformed = true
				break
			}
			addrs = append(addrs, a)
		}
		switch {
		case malformed:
			if err != ErrForwardedMalformed {
				t.Fatalf("malformed entry in %q: err = %v, want ErrForwardedMalformed", joined, err)
			}
		case err == ErrForwardedOnlyTrusted:
			// Property: only-trusted means every entry is a trusted proxy.
			for _, a := range addrs {
				if !oracleTrusted(a) {
					t.Fatalf("ErrForwardedOnlyTrusted for %q but %v is not trusted", joined, a)
				}
			}
		case err == nil:
			// Property: the client is the rightmost untrusted entry, and it
			// is never a trusted proxy. If every entry is trusted there is
			// no such entry and the request must be refused as only-trusted.
			if !res.Forwarded {
				t.Fatalf("resolved %q without Forwarded set", joined)
			}
			var want netip.Addr
			for i := len(addrs) - 1; i >= 0; i-- {
				if !oracleTrusted(addrs[i]) {
					want = addrs[i]
					break
				}
			}
			if !want.IsValid() {
				t.Fatalf("header %q: resolved to %v although every entry is a trusted proxy; want ErrForwardedOnlyTrusted", joined, res.Client)
			}
			if res.Client != want || oracleTrusted(res.Client) {
				t.Fatalf("header %q: client = %v, want rightmost untrusted %v", joined, res.Client, want)
			}
		default:
			t.Fatalf("header %q: unexpected err = %v", joined, err)
		}
	})
}
