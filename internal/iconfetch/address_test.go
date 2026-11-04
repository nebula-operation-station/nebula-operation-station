// SPDX-License-Identifier: AGPL-3.0-or-later

package iconfetch

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
)

func TestForbiddenAddressClassification(t *testing.T) {
	forbidden := []string{
		"0.0.0.0", "0.1.2.3", // unspecified / this network
		"10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1", // private
		"127.0.0.1", "127.255.255.254", // loopback
		"169.254.169.254", "169.254.0.1", // link-local incl. metadata
		"100.64.0.1", "100.127.255.255", // CGNAT
		"192.0.0.1", "192.0.2.1", "192.88.99.1", "198.18.0.1", "198.19.255.255", "198.51.100.1", "203.0.113.1", // special purpose / documentation / benchmarking
		"224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255", // multicast / reserved / broadcast
		"::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1", // IPv4-mapped
		"::", "::1", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1", // IPv6 unspecified, loopback, link-local, ULA, multicast
		"64:ff9b::7f00:1", "2002:7f00:1::1", "2001:db8::1", // NAT64, 6to4, documentation
		"2606:4700::1111", // public IPv6: refused like every IPv6 address (mirrors servicecheck)
	}
	for _, s := range forbidden {
		a := netip.MustParseAddr(s)
		if reason, bad := forbiddenAddr(a); !bad || reason == "" {
			t.Errorf("forbiddenAddr(%s) = %q, %v; want forbidden with reason", s, reason, bad)
		}
	}
	allowed := []string{"140.82.112.3", "185.199.108.133", "198.35.26.112", "8.8.8.8", "100.63.255.255", "100.128.0.0", "172.15.255.255", "172.32.0.0", "192.169.0.1", "223.255.255.255", "::ffff:140.82.112.3"}
	for _, s := range allowed {
		a := netip.MustParseAddr(s)
		if reason, bad := forbiddenAddr(a); bad {
			t.Errorf("forbiddenAddr(%s) = %q, true; want allowed", s, reason)
		}
	}
	if _, bad := forbiddenAddr(netip.Addr{}); !bad {
		t.Error("zero netip.Addr must be forbidden")
	}
}

// stubResolver answers from a fixed sequence; call i gets answers[min(i, len-1)].
type stubResolver struct {
	mu      sync.Mutex
	answers [][]netip.Addr
	err     error
	calls   int
}

func (r *stubResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := r.calls
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	if i >= len(r.answers) {
		i = len(r.answers) - 1
	}
	return r.answers[i], nil
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

// recordingDial records every address the dialer is asked to connect to
// and never connects.
type recordingDial struct {
	mu    sync.Mutex
	addrs []string
}

var errNoConnect = errors.New("test dial: not connecting")

func (d *recordingDial) dial(_ context.Context, _, addr string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.addrs = append(d.addrs, addr)
	return nil, errNoConnect
}

func TestDialerRefusesForbiddenAnswers(t *testing.T) {
	cases := []struct {
		name    string
		answers []netip.Addr
	}{
		{"loopback", addrs("127.0.0.1")},
		{"metadata", addrs("169.254.169.254")},
		{"private", addrs("10.1.2.3")},
		{"mapped loopback", addrs("::ffff:127.0.0.1")},
		{"ipv6 loopback", addrs("::1")},
		{"mixed public and private", addrs("140.82.112.3", "192.168.0.10")},
		{"empty answer", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := &recordingDial{}
			d := &dialer{resolver: &stubResolver{answers: [][]netip.Addr{c.answers}}, allow: nil, dial: rec.dial}
			_, err := d.DialContext(context.Background(), "tcp", "avatars.githubusercontent.com:443")
			if !errors.Is(err, ErrAddress) {
				t.Fatalf("DialContext error = %v, want ErrAddress", err)
			}
			if len(rec.addrs) != 0 {
				t.Fatalf("dialed %v despite forbidden answer", rec.addrs)
			}
		})
	}
}

func TestDialerConnectsOnlyToCheckedAddress(t *testing.T) {
	rec := &recordingDial{}
	res := &stubResolver{answers: [][]netip.Addr{addrs("140.82.112.3", "140.82.112.4")}}
	d := &dialer{resolver: res, dial: rec.dial}
	if _, err := d.DialContext(context.Background(), "tcp", "avatars.githubusercontent.com:443"); !errors.Is(err, errNoConnect) {
		t.Fatalf("DialContext error = %v, want the stub dial error", err)
	}
	want := []string{"140.82.112.3:443", "140.82.112.4:443"}
	if len(rec.addrs) != len(want) {
		t.Fatalf("dialed %v, want %v", rec.addrs, want)
	}
	for i := range want {
		if rec.addrs[i] != want[i] {
			t.Fatalf("dialed %v, want %v", rec.addrs, want)
		}
	}
	if res.calls != 1 {
		t.Fatalf("resolver called %d times, want exactly 1 per dial", res.calls)
	}
}

func TestDialerRejectsHostOrPortOutsidePolicy(t *testing.T) {
	for _, addr := range []string{
		"evil.example:443",
		"avatars.githubusercontent.com:80",
		"127.0.0.1:443",
		"[::1]:443",
		"avatars.githubusercontent.com",
	} {
		rec := &recordingDial{}
		res := &stubResolver{answers: [][]netip.Addr{addrs("140.82.112.3")}}
		d := &dialer{resolver: res, dial: rec.dial}
		if _, err := d.DialContext(context.Background(), "tcp", addr); !errors.Is(err, ErrAddress) {
			t.Errorf("DialContext(%q) error = %v, want ErrAddress", addr, err)
		}
		if res.calls != 0 || len(rec.addrs) != 0 {
			t.Errorf("DialContext(%q) resolved %d times / dialed %v", addr, res.calls, rec.addrs)
		}
	}
}

func TestDialerResolverErrorIsWrapped(t *testing.T) {
	boom := errors.New("no such host")
	d := &dialer{resolver: &stubResolver{err: boom}, dial: (&recordingDial{}).dial}
	if _, err := d.DialContext(context.Background(), "tcp", "upload.wikimedia.org:443"); !errors.Is(err, boom) {
		t.Fatalf("DialContext error = %v, want wrapped resolver error", err)
	}
}

func TestDialerCapsAnswers(t *testing.T) {
	many := make([]string, maxResolvedAddrs+5)
	for i := range many {
		many[i] = netip.AddrFrom4([4]byte{140, 82, 112, byte(i + 1)}).String()
	}
	rec := &recordingDial{}
	d := &dialer{resolver: &stubResolver{answers: [][]netip.Addr{addrs(many...)}}, dial: rec.dial}
	_, _ = d.DialContext(context.Background(), "tcp", "upload.wikimedia.org:443")
	if len(rec.addrs) != maxDialAttempts {
		t.Fatalf("dial attempts = %d, want %d", len(rec.addrs), maxDialAttempts)
	}
}

func TestDialerRefusesNonTCPNetworks(t *testing.T) {
	for _, network := range []string{"tcp6", "udp", "udp4", "ip4", "unix", ""} {
		rec := &recordingDial{}
		res := &stubResolver{answers: [][]netip.Addr{addrs("140.82.112.3")}}
		d := &dialer{resolver: res, dial: rec.dial}
		if _, err := d.DialContext(context.Background(), network, "avatars.githubusercontent.com:443"); !errors.Is(err, ErrAddress) {
			t.Errorf("DialContext(%q) error = %v, want ErrAddress", network, err)
		}
		if res.calls != 0 || len(rec.addrs) != 0 {
			t.Errorf("DialContext(%q) resolved %d times / dialed %v", network, res.calls, rec.addrs)
		}
	}
	rec := &recordingDial{}
	d := &dialer{resolver: &stubResolver{answers: [][]netip.Addr{addrs("140.82.112.3")}}, dial: rec.dial}
	if _, err := d.DialContext(context.Background(), "tcp4", "avatars.githubusercontent.com:443"); !errors.Is(err, errNoConnect) {
		t.Errorf("DialContext(tcp4) error = %v, want the stub dial error", err)
	}
}
