// SPDX-License-Identifier: AGPL-3.0-or-later

package flowagg

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func sock(local, remote string, sent, recv uint64) Socket {
	return Socket{Proto: TCP, Local: ap(local), Remote: ap(remote), BytesSent: sent, BytesReceived: recv}
}

func snap(host string, at time.Time, socks ...Socket) *Snapshot {
	return &Snapshot{Host: host, Tier: "socket", Time: at, Sockets: socks}
}

func TestSnapshotValidateRejectsMalformedInput(t *testing.T) {
	many := make([]Socket, MaxSocketsPerSnapshot+1)
	for i := range many {
		many[i] = Socket{Proto: TCP, Local: netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), uint16(i%60000+1)),
			Remote: netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), uint16(i/60000+1))}
	}
	tests := []struct {
		name string
		s    Snapshot
	}{
		{"empty host", Snapshot{Tier: "socket", Time: t0}},
		{"host too long", Snapshot{Host: strings.Repeat("h", MaxHostIDLen+1), Tier: "socket", Time: t0}},
		{"host invalid utf8", Snapshot{Host: "h\xff", Tier: "socket", Time: t0}},
		{"host control char", Snapshot{Host: "h\n1", Tier: "socket", Time: t0}},
		{"empty tier", Snapshot{Host: "h", Time: t0}},
		{"tier bad chars", Snapshot{Host: "h", Tier: "Sock et", Time: t0}},
		{"tier too long", Snapshot{Host: "h", Tier: strings.Repeat("t", MaxTierLen+1), Time: t0}},
		{"unknown tier", Snapshot{Host: "h", Tier: "invented", Time: t0}},
		{"zero time", Snapshot{Host: "h", Tier: "socket"}},
		{"bad proto", Snapshot{Host: "h", Tier: "socket", Time: t0, Sockets: []Socket{{Proto: 9, Local: ap("10.0.0.1:1"), Remote: ap("10.0.0.2:2")}}}},
		{"invalid local", Snapshot{Host: "h", Tier: "socket", Time: t0, Sockets: []Socket{{Proto: TCP, Remote: ap("10.0.0.2:2")}}}},
		{"zero remote port", Snapshot{Host: "h", Tier: "socket", Time: t0, Sockets: []Socket{sock("10.0.0.1:1", "10.0.0.2:0", 0, 0)}}},
		{"unspecified remote", Snapshot{Host: "h", Tier: "socket", Time: t0, Sockets: []Socket{sock("10.0.0.1:1", "0.0.0.0:22", 0, 0)}}},
		{"unspecified local", Snapshot{Host: "h", Tier: "socket", Time: t0, Sockets: []Socket{sock("[::]:1", "[2001:db8::2]:22", 0, 0)}}},
		{"duplicate socket", Snapshot{Host: "h", Tier: "socket", Time: t0, Sockets: []Socket{
			sock("10.0.0.1:1", "10.0.0.2:22", 1, 1), sock("10.0.0.1:1", "10.0.0.2:22", 2, 2)}}},
		{"duplicate socket via v4-mapped", Snapshot{Host: "h", Tier: "socket", Time: t0, Sockets: []Socket{
			sock("10.0.0.1:1", "10.0.0.2:22", 1, 1), sock("[::ffff:10.0.0.1]:1", "[::ffff:10.0.0.2]:22", 2, 2)}}},
		{"too many sockets", Snapshot{Host: "h", Tier: "socket", Time: t0, Sockets: many}},
		{"listener zero port", Snapshot{Host: "h", Tier: "socket", Time: t0, Listeners: []Listener{{Proto: TCP, Addr: ap("0.0.0.0:0")}}}},
		{"listener invalid addr", Snapshot{Host: "h", Tier: "socket", Time: t0, Listeners: []Listener{{Proto: TCP}}}},
		{"listener bad proto", Snapshot{Host: "h", Tier: "socket", Time: t0, Listeners: []Listener{{Proto: 0, Addr: ap("0.0.0.0:22")}}}},
		{"too many listeners", Snapshot{Host: "h", Tier: "socket", Time: t0, Listeners: make([]Listener, MaxListenersPerSnapshot+1)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.s.Validate()
			if !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("Validate() = %v, want ErrInvalidSnapshot", err)
			}
		})
	}
}

func TestSnapshotValidateAcceptsIPv6AndUDP(t *testing.T) {
	s := Snapshot{Host: "pve-1", Tier: "socket", Time: t0,
		Sockets: []Socket{
			sock("[2001:db8::1]:443", "[2001:db8::2]:51000", 10, 20),
			{Proto: UDP, Local: ap("[fe80::1%eth0]:53"), Remote: ap("[fe80::2%eth0]:40000")},
			// Same 4-tuple with a different protocol or cookie is a different socket.
			{Proto: UDP, Local: ap("[2001:db8::1]:443"), Remote: ap("[2001:db8::2]:51000")},
			{Proto: TCP, Cookie: 7, Local: ap("[2001:db8::1]:443"), Remote: ap("[2001:db8::2]:51000")},
		},
		Listeners: []Listener{{Proto: TCP, Addr: ap("[::]:443")}, {Proto: TCP, Addr: ap("[::]:443")}},
	}
	if err := s.Validate(); err != nil {
		t.Fatalf("Validate() = %v", err)
	}
}

func TestDiffCountersAndResets(t *testing.T) {
	t1 := t0.Add(time.Minute)
	tests := []struct {
		name       string
		prev       []Socket
		cur        []Socket
		want       []SocketDelta
		lowerBound bool
	}{
		{
			name: "steady growth",
			prev: []Socket{sock("10.0.0.1:50000", "10.0.0.2:22", 100, 1000)},
			cur:  []Socket{sock("10.0.0.1:50000", "10.0.0.2:22", 150, 1300)},
			want: []SocketDelta{{Socket: sock("10.0.0.1:50000", "10.0.0.2:22", 150, 1300), Sent: 50, Received: 300}},
		},
		{
			name: "new socket counts since start",
			cur:  []Socket{sock("10.0.0.1:50000", "10.0.0.2:22", 70, 80)},
			want: []SocketDelta{{Socket: sock("10.0.0.1:50000", "10.0.0.2:22", 70, 80), Sent: 70, Received: 80, New: true}},
		},
		{
			name:       "counter decrease is a reset",
			prev:       []Socket{sock("10.0.0.1:50000", "10.0.0.2:22", 1000, 1000)},
			cur:        []Socket{sock("10.0.0.1:50000", "10.0.0.2:22", 10, 2000)},
			want:       []SocketDelta{{Socket: sock("10.0.0.1:50000", "10.0.0.2:22", 10, 2000), Sent: 10, Received: 2000, New: true, Reset: true}},
			lowerBound: true,
		},
		{
			name:       "64-bit wrap is treated as reset, never negative",
			prev:       []Socket{sock("10.0.0.1:50000", "10.0.0.2:22", ^uint64(0)-5, 5)},
			cur:        []Socket{sock("10.0.0.1:50000", "10.0.0.2:22", 3, 6)},
			want:       []SocketDelta{{Socket: sock("10.0.0.1:50000", "10.0.0.2:22", 3, 6), Sent: 3, Received: 6, New: true, Reset: true}},
			lowerBound: true,
		},
		{
			name:       "vanished socket only sets lower bound",
			prev:       []Socket{sock("10.0.0.1:50000", "10.0.0.2:22", 1, 1)},
			lowerBound: true,
		},
		{
			name: "unchanged socket yields zero delta",
			prev: []Socket{sock("10.0.0.1:50000", "10.0.0.2:22", 5, 5)},
			cur:  []Socket{sock("10.0.0.1:50000", "10.0.0.2:22", 5, 5)},
			want: []SocketDelta{{Socket: sock("10.0.0.1:50000", "10.0.0.2:22", 5, 5)}},
		},
		{
			name: "cookie change means a new connection on the same tuple",
			prev: []Socket{{Proto: TCP, Cookie: 1, Local: ap("10.0.0.1:50000"), Remote: ap("10.0.0.2:22"), BytesSent: 10, BytesReceived: 10}},
			cur:  []Socket{{Proto: TCP, Cookie: 2, Local: ap("10.0.0.1:50000"), Remote: ap("10.0.0.2:22"), BytesSent: 20, BytesReceived: 20}},
			want: []SocketDelta{{Socket: Socket{Proto: TCP, Cookie: 2, Local: ap("10.0.0.1:50000"), Remote: ap("10.0.0.2:22"), BytesSent: 20, BytesReceived: 20},
				Sent: 20, Received: 20, New: true}},
			lowerBound: true, // cookie 1 vanished
		},
		{
			name: "IPv6 and v4-mapped addresses match across snapshots",
			prev: []Socket{sock("[::ffff:10.0.0.1]:50000", "[::ffff:10.0.0.2]:22", 1, 2), sock("[2001:db8::1]:50001", "[2001:db8::2]:443", 3, 4)},
			cur:  []Socket{sock("10.0.0.1:50000", "10.0.0.2:22", 11, 12), sock("[2001:db8::1]:50001", "[2001:db8::2]:443", 13, 14)},
			want: []SocketDelta{
				{Socket: sock("10.0.0.1:50000", "10.0.0.2:22", 11, 12), Sent: 10, Received: 10},
				{Socket: sock("[2001:db8::1]:50001", "[2001:db8::2]:443", 13, 14), Sent: 10, Received: 10},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Diff(snap("h1", t0, tc.prev...), snap("h1", t1, tc.cur...))
			if err != nil {
				t.Fatalf("Diff: %v", err)
			}
			if d.LowerBound != tc.lowerBound {
				t.Errorf("LowerBound = %v, want %v", d.LowerBound, tc.lowerBound)
			}
			if len(d.Sockets) != len(tc.want) {
				t.Fatalf("got %d socket deltas, want %d: %+v", len(d.Sockets), len(tc.want), d.Sockets)
			}
			for i, w := range tc.want {
				g := d.Sockets[i]
				w.Socket = normalizeSocket(w.Socket)
				if g != w {
					t.Errorf("socket %d = %+v, want %+v", i, g, w)
				}
			}
		})
	}
}

func TestDiffFirstSnapshotIsBaseline(t *testing.T) {
	d, err := Diff(nil, snap("h1", t0, sock("10.0.0.1:1", "10.0.0.2:2", 1<<40, 1<<40)))
	if err != nil {
		t.Fatal(err)
	}
	if !d.From.Equal(t0) || !d.To.Equal(t0) || d.Host != "h1" || d.Tier != "socket" || !d.Baseline {
		t.Fatalf("unexpected header %+v", d)
	}
	if len(d.Sockets) != 0 || len(d.Vanished) != 0 || d.LowerBound {
		t.Fatalf("baseline must count nothing: %+v", d)
	}
	// The baseline is still validated.
	if _, err := Diff(nil, &Snapshot{Host: "h1", Tier: "socket"}); err == nil {
		t.Fatal("invalid baseline accepted")
	}
}

func TestDiffRejectsMismatchedSnapshots(t *testing.T) {
	tests := []struct {
		name string
		prev *Snapshot
		cur  *Snapshot
	}{
		{"nil current", snap("h1", t0), nil},
		{"other host", snap("h1", t0), snap("h2", t0.Add(time.Minute))},
		{"other tier", &Snapshot{Host: "h1", Tier: "conntrack", Time: t0}, snap("h1", t0.Add(time.Minute))},
		{"same time", snap("h1", t0), snap("h1", t0)},
		{"time going back", snap("h1", t0), snap("h1", t0.Add(-time.Minute))},
		{"invalid previous", &Snapshot{Host: "h1", Tier: "socket"}, snap("h1", t0)},
		{"invalid current", nil, &Snapshot{Host: "h1", Tier: "socket"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Diff(tc.prev, tc.cur); err == nil {
				t.Fatal("Diff accepted mismatched snapshots")
			}
		})
	}
}

func TestDiffOutputIsSorted(t *testing.T) {
	cur := snap("h1", t0,
		sock("10.0.0.1:3", "10.0.0.9:22", 1, 1),
		sock("[2001:db8::1]:1", "[2001:db8::2]:22", 1, 1),
		sock("10.0.0.1:1", "10.0.0.9:22", 1, 1),
		Socket{Proto: UDP, Local: ap("10.0.0.1:1"), Remote: ap("10.0.0.9:53")},
	)
	d, err := Diff(snap("h1", t0.Add(-time.Minute)), cur)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(d.Sockets); i++ {
		if compareSocketID(d.Sockets[i-1].Socket.id(), d.Sockets[i].Socket.id()) >= 0 {
			t.Fatalf("sockets not strictly sorted at %d: %+v", i, d.Sockets)
		}
	}
}
