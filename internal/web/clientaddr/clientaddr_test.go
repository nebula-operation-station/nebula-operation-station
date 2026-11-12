// SPDX-License-Identifier: AGPL-3.0-or-later

package clientaddr

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

var allSentinels = []error{
	ErrForwardedMissing,
	ErrForwardedTooLong,
	ErrForwardedTooManyEntries,
	ErrForwardedMalformed,
	ErrForwardedOnlyTrusted,
}

// assertOnly checks that err matches want and none of the other four
// forwarded-header sentinels.
func assertOnly(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	for _, s := range allSentinels {
		if s != want && errors.Is(err, s) {
			t.Fatalf("err %v also matches %v", err, s)
		}
	}
}

func mustNew(t *testing.T, cfg Config) *Resolver {
	t.Helper()
	r, err := New(cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

func request(peer string, xff ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/enroll/x", nil)
	r.RemoteAddr = peer
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

func TestNormalizeStripsPortZoneAndMapping(t *testing.T) {
	cases := map[string]string{
		"192.0.2.7":            "192.0.2.7",
		"192.0.2.7:5555":       "192.0.2.7",
		"[2001:db8::7]:443":    "2001:db8::7",
		"fe80::7%eth0":         "fe80::7",
		"[fe80::7%eth0]:22":    "fe80::7",
		"::ffff:192.0.2.7":     "192.0.2.7",
		"[::ffff:127.0.0.1]:9": "127.0.0.1",
		" 192.0.2.7 ":          "192.0.2.7",
	}
	for in, want := range cases {
		got, err := Normalize(in)
		if err != nil {
			t.Fatalf("Normalize(%q): %v", in, err)
		}
		if got.String() != want {
			t.Fatalf("Normalize(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestNormalizeRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "not-an-ip", "[2001:db8::7]", "192.0.2.7:", "192.0.2.7:99999", "unknown", "1.2.3.4%eth0", "192.0.2.0/24", "[192.0.2.7]:80x"} {
		if _, err := Normalize(in); err == nil {
			t.Fatalf("Normalize(%q) accepted", in)
		}
	}
}

func TestTrustedProxyConfigValidation(t *testing.T) {
	ok := []Config{
		{TrustedProxies: []string{"127.0.0.1"}},
		{TrustedProxies: []string{"10.0.0.5/32"}},
		{TrustedProxies: []string{"2001:db8::1/128"}},
		{TrustedProxies: []string{"::ffff:10.0.0.5/128"}},
		{TrustedProxyNetworks: []string{"172.18.0.0/16", "fd00:1::/64"}},
	}
	for _, c := range ok {
		if _, err := New(c, slog.New(slog.DiscardHandler)); err != nil {
			t.Fatalf("New(%+v): %v", c, err)
		}
	}
	bad := []struct {
		cfg  Config
		want error
	}{
		{Config{TrustedProxies: []string{"10.0.0.0/24"}}, ErrTrustedProxyPrefix},
		{Config{TrustedProxies: []string{"10.0.0.5/31"}}, ErrTrustedProxyPrefix},
		{Config{TrustedProxies: []string{"2001:db8::/64"}}, ErrTrustedProxyPrefix},
		{Config{TrustedProxies: []string{"0.0.0.0/0"}}, ErrTrustedProxyPrefix},
		{Config{TrustedProxies: []string{"proxy.example"}}, ErrTrustedProxyInvalid},
		{Config{TrustedProxies: []string{""}}, ErrTrustedProxyInvalid},
		{Config{TrustedProxyNetworks: []string{"garbage/8"}}, ErrTrustedProxyInvalid},
		{Config{TrustedProxyNetworks: []string{"10.0.0.0"}}, ErrTrustedProxyInvalid},
		{Config{MaxHeaderBytes: -1}, ErrInvalidLimit},
		{Config{MaxEntries: -1}, ErrInvalidLimit},
	}
	for _, b := range bad {
		if _, err := New(b.cfg, slog.New(slog.DiscardHandler)); !errors.Is(err, b.want) {
			t.Fatalf("New(%+v) err = %v, want %v", b.cfg, err, b.want)
		}
	}
}

func TestTrustedProxyNetworkLoggedAsProxyOnly(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	if _, err := New(Config{TrustedProxyNetworks: []string{"172.18.0.0/16"}}, log); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "networks that contain reverse proxies and no clients") ||
		!strings.Contains(buf.String(), "172.18.0.0/16") {
		t.Fatalf("log = %q", buf.String())
	}
}

func TestMappedPeerMatchesIPv4TrustedProxy(t *testing.T) {
	r := mustNew(t, Config{TrustedProxies: []string{"127.0.0.1"}})
	got, err := r.Resolve(request("[::ffff:127.0.0.1]:41234", "192.0.2.10"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Client.String() != "192.0.2.10" || got.Peer.String() != "127.0.0.1" || !got.Forwarded {
		t.Fatalf("got %+v", got)
	}
}

func TestNonProxyPeerForgedHeaderIgnored(t *testing.T) {
	r := mustNew(t, Config{TrustedProxies: []string{"10.0.0.5"}})
	req := request("198.51.100.4:5000", "192.0.2.10", "garbage")
	req.Header.Set("Forwarded", "for=192.0.2.11")
	got, err := r.Resolve(req)
	if err != nil {
		t.Fatal(err)
	}
	if got.Client.String() != "198.51.100.4" || got.Peer.String() != "198.51.100.4" || got.Forwarded {
		t.Fatalf("got %+v", got)
	}
}

func TestNoTrustedProxyUsesPeer(t *testing.T) {
	r := mustNew(t, Config{})
	got, err := r.Resolve(request("127.0.0.1:5000", "192.0.2.10"))
	if err != nil || got.Client.String() != "127.0.0.1" || got.Forwarded {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestForwardedHeaderIgnoredFromTrustedProxy(t *testing.T) {
	r := mustNew(t, Config{TrustedProxies: []string{"127.0.0.1"}})
	req := request("127.0.0.1:5000")
	req.Header.Set("Forwarded", "for=192.0.2.11")
	_, err := r.Resolve(req)
	assertOnly(t, err, ErrForwardedMissing)
}

func TestRightmostUntrustedEntryWins(t *testing.T) {
	r := mustNew(t, Config{
		TrustedProxies:       []string{"127.0.0.1", "192.0.2.250"},
		TrustedProxyNetworks: []string{"172.18.0.0/16"},
	})
	cases := []struct {
		lines []string
		want  string
	}{
		{[]string{"192.0.2.10"}, "192.0.2.10"},
		{[]string{"203.0.113.99, 192.0.2.10"}, "192.0.2.10"},
		{[]string{"203.0.113.99, 192.0.2.10, 192.0.2.250"}, "192.0.2.10"},
		{[]string{"203.0.113.99, 192.0.2.10, 172.18.3.4, 127.0.0.1"}, "192.0.2.10"},
		{[]string{"203.0.113.99", "192.0.2.10:443"}, "192.0.2.10"},
		{[]string{"[2001:db8::7]:443"}, "2001:db8::7"},
		{[]string{"::ffff:192.0.2.7"}, "192.0.2.7"},
		{[]string{"fe80::7%eth0"}, "fe80::7"},
	}
	for _, c := range cases {
		got, err := r.Resolve(request("127.0.0.1:1", c.lines...))
		if err != nil {
			t.Fatalf("%q: %v", c.lines, err)
		}
		if got.Client.String() != c.want || !got.Forwarded || got.Peer.String() != "127.0.0.1" {
			t.Fatalf("%q: got %+v, want client %s", c.lines, got, c.want)
		}
	}
}

func TestPeerInTrustedNetworkReadsHeader(t *testing.T) {
	r := mustNew(t, Config{TrustedProxyNetworks: []string{"172.18.0.0/16"}})
	got, err := r.Resolve(request("172.18.0.2:1000", "192.0.2.10"))
	if err != nil || got.Client.String() != "192.0.2.10" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func padding(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)}).String())
	}
	return out
}

// TestForwardedRefusalOrder is the in-package overlap table: the first
// failing check wins and its sentinel is the only one returned.
func TestForwardedRefusalOrder(t *testing.T) {
	r := mustNew(t, Config{TrustedProxies: []string{"127.0.0.1", "192.0.2.250"}})
	long := strings.Repeat("[2001:db8:1::1234:5678:9abc]:65535, ", 30) + "192.0.2.10"
	if len(long) <= DefaultMaxHeaderBytes {
		t.Fatal("fixture not long enough")
	}
	many := strings.Join(append(padding(16), "192.0.2.10"), ", ")
	if len(many) > DefaultMaxHeaderBytes {
		t.Fatal("fixture too long")
	}
	cases := []struct {
		name  string
		lines []string
		want  error
	}{
		{"missing", nil, ErrForwardedMissing},
		{"too long and too many", []string{long}, ErrForwardedTooLong},
		{"too long with garbage", []string{"not-an-ip, " + long}, ErrForwardedTooLong},
		{"too many with garbage", []string{"not-an-ip, " + many}, ErrForwardedTooManyEntries},
		{"only trusted plus garbage", []string{"192.0.2.250, not-an-ip, 127.0.0.1"}, ErrForwardedMalformed},
		{"garbage left", []string{"not-an-ip, 192.0.2.10"}, ErrForwardedMalformed},
		{"garbage right", []string{"192.0.2.10, not-an-ip"}, ErrForwardedMalformed},
		{"empty entry", []string{"192.0.2.10, "}, ErrForwardedMalformed},
		{"empty line", []string{""}, ErrForwardedMalformed},
		{"only trusted", []string{"192.0.2.250, 127.0.0.1"}, ErrForwardedOnlyTrusted},
		{"lines joined too long", []string{long[:600], long[600:]}, ErrForwardedTooLong},
		{"lines joined too many", []string{strings.Join(padding(9), ", "), strings.Join(append(padding(7), "192.0.2.10"), ", ")}, ErrForwardedTooManyEntries},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := r.Resolve(request("127.0.0.1:1", c.lines...))
			assertOnly(t, err, c.want)
		})
	}
}

func TestForwardedLimitsInjected(t *testing.T) {
	r := mustNew(t, Config{TrustedProxies: []string{"127.0.0.1"}, MaxHeaderBytes: 20, MaxEntries: 2})
	_, err := r.Resolve(request("127.0.0.1:1", "192.0.2.1, 192.0.2.2, 192.0.2.3"))
	assertOnly(t, err, ErrForwardedTooLong)
	_, err = r.Resolve(request("127.0.0.1:1", "1.1.1.1,2.2.2.2,3::"))
	assertOnly(t, err, ErrForwardedTooManyEntries)
	got, err := r.Resolve(request("127.0.0.1:1", "1.1.1.1, 2.2.2.2"))
	if err != nil || got.Client.String() != "2.2.2.2" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestExactlySixteenEntriesAccepted(t *testing.T) {
	r := mustNew(t, Config{TrustedProxies: []string{"127.0.0.1"}})
	got, err := r.Resolve(request("127.0.0.1:1", strings.Join(append(padding(15), "192.0.2.10"), ",")))
	if err != nil || got.Client.String() != "192.0.2.10" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestUnparsablePeerRefused(t *testing.T) {
	r := mustNew(t, Config{})
	if _, err := r.Resolve(request("@")); !errors.Is(err, ErrPeerInvalid) {
		t.Fatalf("err = %v", err)
	}
	for _, s := range allSentinels {
		if errors.Is(ErrPeerInvalid, s) {
			t.Fatal("ErrPeerInvalid matches a forwarded sentinel")
		}
	}
}

func TestListenerWarning(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8080":    true,
		"[::1]:8080":        true,
		"10.1.2.3:8080":     true,
		"192.168.1.5:8080":  true,
		"[fd00::1]:8080":    true,
		"0.0.0.0:8080":      true,
		"[::]:8080":         true,
		":8080":             true,
		"localhost:8080":    true,
		"203.0.113.5:443":   false,
		"[2001:db8::5]:443": false,
	}
	for listen, want := range cases {
		var buf bytes.Buffer
		r := mustNew(t, Config{})
		r.WarnListener(slog.New(slog.NewTextHandler(&buf, nil)), listen, true)
		if got := strings.Contains(buf.String(), "level=WARN"); got != want {
			t.Fatalf("%s: warned=%v, want %v (%q)", listen, got, want, buf.String())
		}
	}
	// No warning when enrollment is disabled or a trusted proxy is set.
	var buf bytes.Buffer
	mustNew(t, Config{}).WarnListener(slog.New(slog.NewTextHandler(&buf, nil)), "127.0.0.1:8080", false)
	mustNew(t, Config{TrustedProxies: []string{"127.0.0.1"}}).WarnListener(slog.New(slog.NewTextHandler(&buf, nil)), "127.0.0.1:8080", true)
	if buf.Len() != 0 {
		t.Fatalf("unexpected warning %q", buf.String())
	}
}
