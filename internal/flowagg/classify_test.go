// SPDX-License-Identifier: AGPL-3.0-or-later

package flowagg

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func classifyOne(t *testing.T, listeners []Listener, socks ...Socket) Report {
	t.Helper()
	// An empty previous snapshot makes every socket new, so it counts
	// from its start.
	cur := snap("h1", t0, socks...)
	cur.Listeners = listeners
	r, err := Observe(snap("h1", t0.Add(-time.Minute)), cur)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	return r
}

func TestClassifyServerSide(t *testing.T) {
	tests := []struct {
		name      string
		listeners []Listener
		socks     []Socket
		want      []Observation
	}{
		{
			name:      "local listener makes reporter the server, client port dropped",
			listeners: []Listener{{Proto: TCP, Addr: ap("10.0.0.2:22")}},
			socks:     []Socket{sock("10.0.0.2:22", "10.0.0.1:51234", 500, 40)},
			want: []Observation{{Key: FlowKey{A: addr("10.0.0.1"), B: addr("10.0.0.2"), Proto: TCP, ServerPort: 22, Server: SideB, Tier: "socket"},
				BytesAB: 40, BytesBA: 500, Connections: 1, ServerReported: true}},
		},
		{
			name:  "no matching listener makes the remote the server",
			socks: []Socket{sock("10.0.0.1:51234", "10.0.0.2:22", 40, 500)},
			want: []Observation{{Key: FlowKey{A: addr("10.0.0.1"), B: addr("10.0.0.2"), Proto: TCP, ServerPort: 22, Server: SideB, Tier: "socket"},
				BytesAB: 40, BytesBA: 500, Connections: 1}},
		},
		{
			name:      "wildcard IPv4 listener matches",
			listeners: []Listener{{Proto: TCP, Addr: ap("0.0.0.0:443")}},
			socks:     []Socket{sock("10.0.0.1:443", "10.0.0.9:40000", 7, 3)},
			want: []Observation{{Key: FlowKey{A: addr("10.0.0.1"), B: addr("10.0.0.9"), Proto: TCP, ServerPort: 443, Server: SideA, Tier: "socket"},
				BytesAB: 7, BytesBA: 3, Connections: 1, ServerReported: true}},
		},
		{
			name:      "dual-stack :: listener matches IPv4 and v4-mapped locals",
			listeners: []Listener{{Proto: TCP, Addr: ap("[::]:443")}},
			socks:     []Socket{sock("[::ffff:10.0.0.1]:443", "[::ffff:10.0.0.9]:40000", 7, 3)},
			want: []Observation{{Key: FlowKey{A: addr("10.0.0.1"), B: addr("10.0.0.9"), Proto: TCP, ServerPort: 443, Server: SideA, Tier: "socket"},
				BytesAB: 7, BytesBA: 3, Connections: 1, ServerReported: true}},
		},
		{
			name:      "IPv4 wildcard listener does not match IPv6 locals",
			listeners: []Listener{{Proto: TCP, Addr: ap("0.0.0.0:443")}},
			socks:     []Socket{sock("[2001:db8::1]:443", "[2001:db8::9]:40000", 7, 3)},
			want: []Observation{{Key: FlowKey{A: addr("2001:db8::1"), B: addr("2001:db8::9"), Proto: TCP, ServerPort: 40000, Server: SideB, Tier: "socket"},
				BytesAB: 7, BytesBA: 3, Connections: 1}},
		},
		{
			name:      "IPv6 wildcard listener matches IPv6 locals",
			listeners: []Listener{{Proto: TCP, Addr: ap("[::]:443")}},
			socks:     []Socket{sock("[2001:db8::1]:443", "[2001:db8::9]:40000", 7, 3)},
			want: []Observation{{Key: FlowKey{A: addr("2001:db8::1"), B: addr("2001:db8::9"), Proto: TCP, ServerPort: 443, Server: SideA, Tier: "socket"},
				BytesAB: 7, BytesBA: 3, Connections: 1, ServerReported: true}},
		},
		{
			name:      "listener protocol must match",
			listeners: []Listener{{Proto: UDP, Addr: ap("0.0.0.0:53")}},
			socks:     []Socket{sock("10.0.0.1:53", "10.0.0.9:40000", 7, 3)},
			want: []Observation{{Key: FlowKey{A: addr("10.0.0.1"), B: addr("10.0.0.9"), Proto: TCP, ServerPort: 40000, Server: SideB, Tier: "socket"},
				BytesAB: 7, BytesBA: 3, Connections: 1}},
		},
		{
			name:      "listener on another address does not match",
			listeners: []Listener{{Proto: TCP, Addr: ap("192.168.1.1:22")}},
			socks:     []Socket{sock("10.0.0.1:22", "10.0.0.9:40000", 1, 1)},
			want: []Observation{{Key: FlowKey{A: addr("10.0.0.1"), B: addr("10.0.0.9"), Proto: TCP, ServerPort: 40000, Server: SideB, Tier: "socket"},
				BytesAB: 1, BytesBA: 1, Connections: 1}},
		},
		{
			name:      "IPv6 with zone is stripped from the key",
			listeners: []Listener{{Proto: UDP, Addr: ap("[fe80::1%eth0]:53")}},
			socks:     []Socket{{Proto: UDP, Local: ap("[fe80::1%eth0]:53"), Remote: ap("[fe80::2%eth0]:40000"), BytesSent: 9, BytesReceived: 4}},
			want: []Observation{{Key: FlowKey{A: addr("fe80::1"), B: addr("fe80::2"), Proto: UDP, ServerPort: 53, Server: SideA, Tier: "socket"},
				BytesAB: 9, BytesBA: 4, Connections: 1, ServerReported: true}},
		},
		{
			name:      "many client sockets fold into one flow",
			listeners: []Listener{{Proto: TCP, Addr: ap("[::]:443")}},
			socks: []Socket{
				sock("[2001:db8::2]:443", "[2001:db8::1]:50001", 100, 10),
				sock("[2001:db8::2]:443", "[2001:db8::1]:50002", 200, 20),
				sock("[2001:db8::2]:443", "[2001:db8::3]:50002", 1, 1),
			},
			want: []Observation{
				{Key: FlowKey{A: addr("2001:db8::1"), B: addr("2001:db8::2"), Proto: TCP, ServerPort: 443, Server: SideB, Tier: "socket"},
					BytesAB: 30, BytesBA: 300, Connections: 2, ServerReported: true},
				{Key: FlowKey{A: addr("2001:db8::2"), B: addr("2001:db8::3"), Proto: TCP, ServerPort: 443, Server: SideA, Tier: "socket"},
					BytesAB: 1, BytesBA: 1, Connections: 1, ServerReported: true},
			},
		},
		{
			name: "loopback and same-address sockets are skipped",
			socks: []Socket{
				sock("127.0.0.1:5000", "127.0.0.1:6000", 1, 1),
				sock("[::1]:5000", "[::1]:6000", 1, 1),
				sock("10.0.0.1:5000", "10.0.0.1:6000", 1, 1),
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := classifyOne(t, tc.listeners, tc.socks...)
			if len(r.Observations) != len(tc.want) {
				t.Fatalf("got %d observations, want %d: %+v", len(r.Observations), len(tc.want), r.Observations)
			}
			for i, w := range tc.want {
				if r.Observations[i] != w {
					t.Errorf("observation %d = %+v, want %+v", i, r.Observations[i], w)
				}
			}
		})
	}
}

func TestClassifyBothEndsProduceSameKey(t *testing.T) {
	server := classifyOne(t, []Listener{{Proto: TCP, Addr: ap("0.0.0.0:22")}}, sock("10.0.0.2:22", "10.0.0.1:51234", 500, 40))
	client := classifyOne(t, nil, sock("10.0.0.1:51234", "10.0.0.2:22", 40, 500))
	s, c := server.Observations[0], client.Observations[0]
	if s.Key != c.Key || s.BytesAB != c.BytesAB || s.BytesBA != c.BytesBA {
		t.Fatalf("server %+v and client %+v disagree", s, c)
	}
	if !s.ServerReported || c.ServerReported {
		t.Fatalf("reporter side wrong: server %v client %v", s.ServerReported, c.ServerReported)
	}
}

func TestClassifyResetAndVanishedMarkLowerBound(t *testing.T) {
	l := []Listener{{Proto: TCP, Addr: ap("0.0.0.0:22")}}
	prev := snap("h1", t0, sock("10.0.0.2:22", "10.0.0.1:50000", 1000, 1000), sock("10.0.0.2:22", "10.0.0.3:50000", 10, 10))
	prev.Listeners = l
	cur := snap("h1", t0.Add(time.Minute), sock("10.0.0.2:22", "10.0.0.1:50000", 5, 5))
	cur.Listeners = l
	r, err := Observe(prev, cur)
	if err != nil {
		t.Fatal(err)
	}
	if !r.LowerBound {
		t.Fatal("report must be a lower bound")
	}
	if len(r.Observations) != 2 {
		t.Fatalf("want reset flow and vanished flow, got %+v", r.Observations)
	}
	reset, vanished := r.Observations[0], r.Observations[1]
	if !reset.LowerBound || reset.BytesAB != 5 || reset.BytesBA != 5 || reset.Connections != 1 {
		t.Errorf("reset observation %+v", reset)
	}
	if !vanished.LowerBound || vanished.BytesAB != 0 || vanished.BytesBA != 0 || vanished.Connections != 0 || vanished.Key.A != addr("10.0.0.2") {
		t.Errorf("vanished observation %+v", vanished)
	}
}

func TestClassifySaturatesInsteadOfWrapping(t *testing.T) {
	max := ^uint64(0)
	r := classifyOne(t, nil,
		sock("10.0.0.1:50000", "10.0.0.2:22", max, 1),
		sock("10.0.0.1:50001", "10.0.0.2:22", max, 1))
	if got := r.Observations[0].BytesAB; got != max {
		t.Fatalf("BytesAB = %d, want saturation at %d", got, max)
	}
}

func TestClassifyRejectsTooManyListeners(t *testing.T) {
	d, err := Diff(nil, snap("h1", t0))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Classify(d, make([]Listener, MaxListenersPerSnapshot+1))
	if !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("Classify = %v, want ErrInvalidSnapshot", err)
	}
}

func TestFlowKeyServerAddrAndProtoString(t *testing.T) {
	k := FlowKey{A: addr("10.0.0.1"), B: addr("10.0.0.2"), Proto: TCP, ServerPort: 22, Server: SideA, Tier: "socket"}
	if k.ServerAddr() != addr("10.0.0.1") {
		t.Fatalf("ServerAddr side A = %v", k.ServerAddr())
	}
	k.Server = SideB
	if k.ServerAddr() != addr("10.0.0.2") {
		t.Fatalf("ServerAddr side B = %v", k.ServerAddr())
	}
	for p, want := range map[Proto]string{TCP: "tcp", UDP: "udp", 1: "proto(1)"} {
		if p.String() != want {
			t.Errorf("Proto(%d).String() = %q, want %q", uint8(p), p.String(), want)
		}
	}
}

func TestClassifyHostInternalConnectionCountedOnce(t *testing.T) {
	client := sock("10.0.0.1:51234", "10.0.0.2:22", 40, 500)
	server := sock("10.0.0.2:22", "10.0.0.1:51234", 500, 40)
	k := FlowKey{A: addr("10.0.0.1"), B: addr("10.0.0.2"), Proto: TCP, ServerPort: 22, Server: SideB, Tier: TierSocket}
	for _, order := range [][]Socket{{client, server}, {server, client}} {
		r := classifyOne(t, []Listener{{Proto: TCP, Addr: ap("10.0.0.2:22")}}, order...)
		want := []Observation{{Key: k, BytesAB: 40, BytesBA: 500, Connections: 1, ServerReported: true}}
		if len(r.Observations) != 1 || r.Observations[0] != want[0] {
			t.Fatalf("observations = %+v, want %+v", r.Observations, want)
		}
	}
	// Without a matching listener the end with the lower local address is
	// kept, whatever the order.
	for _, order := range [][]Socket{{client, server}, {server, client}} {
		r := classifyOne(t, nil, order...)
		want := Observation{Key: k, BytesAB: 40, BytesBA: 500, Connections: 1}
		if len(r.Observations) != 1 || r.Observations[0] != want {
			t.Fatalf("observations = %+v, want %+v", r.Observations, want)
		}
	}
}
