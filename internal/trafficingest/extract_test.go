// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficingest

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"testing"

	nfresult "github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions/netfacts"
	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	hostnet "github.com/nebula-operation-station/nebula-operation-station/internal/netfacts"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
)

// exFacts returns a decoded result with an empty socket section marked ok.
func exFacts() nfresult.Facts {
	return nfresult.Facts{Sections: map[string]nfresult.Section{
		nfresult.SectionSockets: {Status: nfresult.StatusOK},
	}}
}

// exMAC returns a locally administered unicast MAC numbered n.
func exMAC(n int) net.HardwareAddr {
	return net.HardwareAddr{0x52, 0x54, 0x00, 0x00, 0x30, byte(n)}
}

// exPeer returns the i-th address of 2001:db8::/32 (RFC 3849), numbered
// from 1 and in ascending order.
func exPeer(i int) netip.Addr {
	var b [16]byte
	b[0], b[1], b[2], b[3] = 0x20, 0x01, 0x0d, 0xb8
	binary.BigEndian.PutUint32(b[12:], uint32(i+1))
	return netip.AddrFrom16(b)
}

// exSocket returns an established TCP socket to peer.
func exSocket(peer netip.AddrPort) hostnet.Socket {
	return hostnet.Socket{Proto: hostnet.ProtoTCP, State: "ESTAB",
		Local: netip.MustParseAddrPort("[2001:db8::ffff]:22"), Peer: peer}
}

// exCutFacts returns a result with macs interfaces (one address each,
// in 192.0.2.0/24) and peers established sockets to distinct addresses
// of 2001:db8::/32, none of them covered by a neighbor or interface.
func exCutFacts(macs, peers int) nfresult.Facts {
	f := exFacts()
	for i := range macs {
		f.Addrs.Entries = append(f.Addrs.Entries, hostnet.Addr{
			Name:  fmt.Sprintf("eth%d", i),
			MAC:   exMAC(i + 1),
			Addrs: []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(10 + i)}), 24)},
		})
	}
	for i := range peers {
		f.Sockets.Entries = append(f.Sockets.Entries, exSocket(netip.AddrPortFrom(exPeer(i), 443)))
	}
	return f
}

// exEP is the part of an endpoint these tests compare.
type exEP struct {
	mac   string
	vlan  int
	addrs []string
}

// exEPs reduces eps to exEP values in order; nil for no endpoints.
func exEPs(eps []trafficstore.Endpoint) []exEP {
	var out []exEP
	for _, e := range eps {
		var addrs []string
		for _, a := range e.Addresses {
			addrs = append(addrs, a.String())
		}
		out = append(out, exEP{mac: e.MAC, vlan: e.VLAN, addrs: addrs})
	}
	return out
}

// exKeys returns one comparable line per endpoint, including the
// reporter label and tier, in order.
func exKeys(eps []trafficstore.Endpoint) []string {
	out := make([]string, 0, len(eps))
	for _, e := range eps {
		out = append(out, fmt.Sprintf("%s|%d|%v|%s|%s", e.MAC, e.VLAN, e.Addresses, e.Reporter, e.Tier))
	}
	return out
}

func TestEndpointsOfCutsAtMaxEndpointsPerResult(t *testing.T) {
	const macs = 3
	const peers = MaxEndpointsPerResult + 100
	f := exCutFacts(macs, peers)

	eps, truncated := endpointsOf("host-a", t0, f)
	if !truncated {
		t.Fatalf("truncated = false with %d endpoint candidates", macs+peers)
	}
	if len(eps) != MaxEndpointsPerResult {
		t.Fatalf("endpoints = %d, want exactly MaxEndpointsPerResult = %d", len(eps), MaxEndpointsPerResult)
	}

	// MAC endpoints come first and are all kept.
	seenAddrOnly := false
	macCount := 0
	for _, e := range eps {
		switch {
		case e.MAC == "" && !seenAddrOnly:
			seenAddrOnly = true
		case e.MAC != "" && seenAddrOnly:
			t.Fatalf("MAC endpoint %s sorted after an address-only endpoint", e.MAC)
		}
		if e.MAC != "" {
			macCount++
		}
	}
	if macCount != macs {
		t.Fatalf("MAC endpoints kept = %d, want all %d", macCount, macs)
	}

	// The address-only endpoints kept are the lowest peers in order.
	kept := eps[macs:]
	for j, e := range kept {
		if len(e.Addresses) != 1 || e.Addresses[0] != exPeer(j) {
			t.Fatalf("address-only endpoint %d = %v, want %v", j, e.Addresses, exPeer(j))
		}
	}

	// The same facts give the same list, regardless of map iteration and
	// of the order the sockets were listed in.
	want := exKeys(eps)
	for i := range 20 {
		again, trunc := endpointsOf("host-a", t0, f)
		if !trunc || !slices.Equal(exKeys(again), want) {
			t.Fatalf("run %d: endpoint list differs from the first run", i)
		}
	}
	rev := exCutFacts(macs, peers)
	slices.Reverse(rev.Sockets.Entries)
	reversed, _ := endpointsOf("host-a", t0, rev)
	if !slices.Equal(exKeys(reversed), want) {
		t.Fatal("reversed socket order changes which endpoints are kept")
	}
}

func TestEndpointsOfAtLimitIsNotTruncated(t *testing.T) {
	eps, truncated := endpointsOf("host-a", t0, exCutFacts(0, MaxEndpointsPerResult))
	if truncated {
		t.Fatal("truncated = true for exactly MaxEndpointsPerResult endpoints")
	}
	if len(eps) != MaxEndpointsPerResult {
		t.Fatalf("endpoints = %d, want %d", len(eps), MaxEndpointsPerResult)
	}

	eps, truncated = endpointsOf("host-a", t0, exCutFacts(0, MaxEndpointsPerResult+1))
	if !truncated || len(eps) != MaxEndpointsPerResult {
		t.Fatalf("one over the limit: truncated = %v, endpoints = %d; want true and %d",
			truncated, len(eps), MaxEndpointsPerResult)
	}
}

func TestEndpointsOfBoundsAddressesPerEndpoint(t *testing.T) {
	const limit = trafficstore.MaxAddressesPerEndpoint
	// ifaceOf returns interface eth<n> with MAC exMAC(n) carrying addrs.
	ifaceOf := func(n int, addrs []netip.Addr) hostnet.Addr {
		var ps []netip.Prefix
		for _, a := range addrs {
			ps = append(ps, netip.PrefixFrom(a, 64))
		}
		return hostnet.Addr{Name: fmt.Sprintf("eth%d", n), MAC: exMAC(n), Addrs: ps}
	}
	peersFrom := func(from, to int) []netip.Addr {
		var out []netip.Addr
		for i := from; i < to; i++ {
			out = append(out, exPeer(i))
		}
		return out
	}

	t.Run("duplicates do not count", func(t *testing.T) {
		// Each of the limit addresses is listed twice, interleaved.
		var list []netip.Addr
		for _, a := range peersFrom(0, limit) {
			list = append(list, a, a)
		}
		f := exFacts()
		f.Addrs.Entries = []hostnet.Addr{ifaceOf(1, list)}
		eps, truncated := endpointsOf("host-a", t0, f)
		if truncated {
			t.Fatal("truncated = true although only MaxAddressesPerEndpoint distinct addresses exist")
		}
		if len(eps) != 1 || !slices.Equal(eps[0].Addresses, peersFrom(0, limit)) {
			t.Fatalf("endpoints = %v, want one endpoint with the %d distinct addresses", exEPs(eps), limit)
		}
	})

	t.Run("over the limit is cut and sorted", func(t *testing.T) {
		// limit+6 distinct addresses, listed in descending order, plus a
		// repeat of the last one in the list. The cut keeps the first
		// limit distinct addresses in input order (the highest ones),
		// then sorts them ascending.
		list := peersFrom(0, limit+6)
		slices.Reverse(list)
		list = append(list, list[len(list)-1])
		f := exFacts()
		f.Addrs.Entries = []hostnet.Addr{ifaceOf(1, list), ifaceOf(2, []netip.Addr{netip.MustParseAddr("192.0.2.99")})}
		eps, truncated := endpointsOf("host-a", t0, f)
		if !truncated {
			t.Fatal("truncated = false for more than MaxAddressesPerEndpoint addresses")
		}
		if len(eps) != 2 {
			t.Fatalf("endpoints = %d, want 2", len(eps))
		}
		var big, small trafficstore.Endpoint
		for _, e := range eps {
			if e.MAC == exMAC(1).String() {
				big = e
			} else {
				small = e
			}
		}
		// Kept: exPeer(limit+5) down to exPeer(6), sorted ascending.
		if want := peersFrom(6, limit+6); !slices.Equal(big.Addresses, want) {
			t.Fatalf("addresses of the capped endpoint = %v, want exactly %v", big.Addresses, want)
		}
		if !slices.IsSortedFunc(big.Addresses, netip.Addr.Compare) {
			t.Fatalf("addresses not sorted: %v", big.Addresses)
		}
		// The bound is per endpoint: the other interface is unaffected.
		if want := []netip.Addr{netip.MustParseAddr("192.0.2.99")}; !slices.Equal(small.Addresses, want) {
			t.Fatalf("other endpoint addresses = %v, want %v", small.Addresses, want)
		}
	})
}

func TestEndpointsOfDropsUnusableAddresses(t *testing.T) {
	type ep = exEP
	macA := exMAC(1)
	macB := exMAC(2)
	ipAddr := func(s string) netip.Prefix { return netip.MustParsePrefix(s) }
	// withEth0 returns a result with one interface eth0 (macA) carrying
	// prefixes ps.
	withEth0 := func(ps ...netip.Prefix) nfresult.Facts {
		f := exFacts()
		f.Addrs.Entries = []hostnet.Addr{{Name: "eth0", MAC: macA, Addrs: ps}}
		return f
	}

	cases := []struct {
		name  string
		facts func() nfresult.Facts
		want  []ep
	}{
		{
			name: "unspecified IPv4 address",
			facts: func() nfresult.Facts {
				return withEth0(netip.PrefixFrom(netip.IPv4Unspecified(), 32))
			},
		},
		{
			name: "unspecified IPv6 address",
			facts: func() nfresult.Facts {
				return withEth0(netip.PrefixFrom(netip.IPv6Unspecified(), 128))
			},
		},
		{
			name:  "IPv4 loopback",
			facts: func() nfresult.Facts { return withEth0(ipAddr("127.0.0.1/8")) },
		},
		{
			name:  "IPv6 loopback",
			facts: func() nfresult.Facts { return withEth0(ipAddr("::1/128")) },
		},
		{
			name:  "IPv4 multicast",
			facts: func() nfresult.Facts { return withEth0(ipAddr("224.0.0.251/32")) },
		},
		{
			name:  "IPv6 multicast",
			facts: func() nfresult.Facts { return withEth0(ipAddr("ff02::1/128")) },
		},
		{
			name:  "IPv4 broadcast",
			facts: func() nfresult.Facts { return withEth0(ipAddr("255.255.255.255/32")) },
		},
		{
			name:  "invalid address",
			facts: func() nfresult.Facts { return withEth0(netip.Prefix{}) },
		},
		{
			name: "listening socket with a peer address",
			facts: func() nfresult.Facts {
				f := exFacts()
				f.Sockets.Entries = []hostnet.Socket{{Proto: hostnet.ProtoTCP, State: "LISTEN", Listening: true,
					Local: netip.MustParseAddrPort("192.0.2.10:22"), Peer: netip.MustParseAddrPort("192.0.2.60:443")}}
				return f
			},
		},
		{
			name: "peer with port 0",
			facts: func() nfresult.Facts {
				f := exFacts()
				f.Sockets.Entries = []hostnet.Socket{{Proto: hostnet.ProtoUDP, State: "ESTAB",
					Local: netip.MustParseAddrPort("192.0.2.10:5353"), Peer: netip.MustParseAddrPort("192.0.2.61:0")}}
				return f
			},
		},
		{
			name: "IPv4-mapped address is unmapped",
			facts: func() nfresult.Facts {
				return withEth0(netip.PrefixFrom(netip.MustParseAddr("::ffff:192.0.2.70"), 120))
			},
			want: []ep{{mac: macA.String(), addrs: []string{"192.0.2.70"}}},
		},
		{
			name: "peer with zone loses the zone",
			facts: func() nfresult.Facts {
				f := exFacts()
				f.Sockets.Entries = []hostnet.Socket{{Proto: hostnet.ProtoTCP, State: "ESTAB",
					Local: netip.MustParseAddrPort("[2001:db8::ffff]:22"),
					Peer:  netip.AddrPortFrom(netip.MustParseAddr("fe80::1%eth0"), 51000)}}
				return f
			},
			want: []ep{{addrs: []string{"fe80::1"}}},
		},
		{
			name: "unusable addresses beside a usable one",
			facts: func() nfresult.Facts {
				return withEth0(ipAddr("127.0.0.1/8"), ipAddr("192.0.2.5/24"), ipAddr("255.255.255.255/32"))
			},
			want: []ep{{mac: macA.String(), addrs: []string{"192.0.2.5"}}},
		},
		{
			name: "peer already covered by a neighbor is not repeated",
			facts: func() nfresult.Facts {
				f := exFacts()
				f.Neigh = hostnet.NeighborTable{Entries: []hostnet.Neighbor{{
					IP: netip.MustParseAddr("192.0.2.80"), Dev: "eth0", MAC: macB, State: []string{"REACHABLE"}}}}
				f.Sockets.Entries = []hostnet.Socket{{Proto: hostnet.ProtoTCP, State: "ESTAB",
					Local: netip.MustParseAddrPort("192.0.2.10:22"), Peer: netip.MustParseAddrPort("192.0.2.80:443")}}
				return f
			},
			want: []ep{{mac: macB.String(), addrs: []string{"192.0.2.80"}}},
		},
		{
			name: "VLAN id comes from the vlan link of the device",
			facts: func() nfresult.Facts {
				f := exFacts()
				vlan := 20
				f.Links.Entries = []hostnet.Link{{Name: "eth0.20", Kind: "vlan", VLANID: &vlan}}
				f.Addrs.Entries = []hostnet.Addr{
					{Name: "eth0.20", MAC: macA, Addrs: []netip.Prefix{ipAddr("192.0.2.90/24")}},
					{Name: "eth0", MAC: macB, Addrs: []netip.Prefix{ipAddr("192.0.2.91/24")}},
				}
				return f
			},
			want: []ep{
				{mac: macA.String(), vlan: 20, addrs: []string{"192.0.2.90"}},
				{mac: macB.String(), addrs: []string{"192.0.2.91"}},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eps, truncated := endpointsOf("host-a", t0, tc.facts())
			if truncated {
				t.Fatal("truncated = true for a small result")
			}
			if got := exEPs(eps); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("endpoints = %+v, want %+v", got, tc.want)
			}
			for _, e := range eps {
				if e.Reporter != "host-a" || e.Tier != flowagg.TierSocket || !e.LastSeen.Equal(t0) {
					t.Fatalf("endpoint %+v: want reporter host-a, tier %s, last seen %s",
						e, flowagg.TierSocket, t0)
				}
			}
		})
	}
}

// exSocketSection returns a result whose socket section is ok, with the
// sockets and listeners as given.
func exSocketSection(socks ...hostnet.Socket) nfresult.Facts {
	f := exFacts()
	f.Sockets = hostnet.SocketTable{Entries: socks}
	return f
}

// exListeners returns n distinct TCP listeners on 192.0.2.10.
func exListeners(n int) []hostnet.Socket {
	var out []hostnet.Socket
	for i := range n {
		out = append(out, hostnet.Socket{Proto: hostnet.ProtoTCP, State: "LISTEN", Listening: true,
			Local: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.10"), uint16(i+1))})
	}
	return out
}

func TestSnapshotOfRefusesIncompleteSocketTables(t *testing.T) {
	established := exSocket(netip.MustParseAddrPort("192.0.2.50:51000"))
	cases := []struct {
		name   string
		facts  func() nfresult.Facts
		wantOK bool
	}{
		{
			name:   "complete table",
			facts:  func() nfresult.Facts { return exSocketSection(established) },
			wantOK: true,
		},
		{
			name: "sockets section missing",
			facts: func() nfresult.Facts {
				f := exSocketSection(established)
				delete(f.Sections, nfresult.SectionSockets)
				return f
			},
		},
		{
			name: "sockets section absent",
			facts: func() nfresult.Facts {
				f := exSocketSection(established)
				f.Sections[nfresult.SectionSockets] = nfresult.Section{Status: nfresult.StatusAbsent}
				return f
			},
		},
		{
			name: "sockets section failed",
			facts: func() nfresult.Facts {
				f := exSocketSection(established)
				f.Sections[nfresult.SectionSockets] = nfresult.Section{Status: nfresult.StatusFailed}
				return f
			},
		},
		{
			name: "sockets section skipped",
			facts: func() nfresult.Facts {
				f := exSocketSection(established)
				f.Sections[nfresult.SectionSockets] = nfresult.Section{Status: nfresult.StatusSkipped, Truncated: true}
				return f
			},
		},
		{
			name: "sockets section cut",
			facts: func() nfresult.Facts {
				f := exSocketSection(established)
				f.Sections[nfresult.SectionSockets] = nfresult.Section{Status: nfresult.StatusOK, Truncated: true}
				return f
			},
		},
		{
			name: "sockets section invalid",
			facts: func() nfresult.Facts {
				f := exSocketSection(established)
				f.Sections[nfresult.SectionSockets] = nfresult.Section{Status: nfresult.StatusOK, Invalid: true}
				return f
			},
		},
		{
			name: "parser dropped lines",
			facts: func() nfresult.Facts {
				f := exSocketSection(established)
				f.Sockets.Dropped, f.Sockets.Incomplete = 1, true
				return f
			},
		},
		{
			name: "parser dropped a counter",
			facts: func() nfresult.Facts {
				f := exSocketSection(established)
				f.Sockets.Incomplete = true
				return f
			},
		},
		{
			name: "same tuple twice",
			facts: func() nfresult.Facts {
				return exSocketSection(established, established)
			},
		},
		{
			name: "more listeners than MaxListenersPerSnapshot",
			facts: func() nfresult.Facts {
				return exSocketSection(exListeners(flowagg.MaxListenersPerSnapshot + 1)...)
			},
		},
		{
			name: "exactly MaxListenersPerSnapshot listeners",
			facts: func() nfresult.Facts {
				return exSocketSection(exListeners(flowagg.MaxListenersPerSnapshot)...)
			},
			wantOK: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap, ok := snapshotOf("host-a", t0, tc.facts())
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && snap == nil {
				t.Fatal("ok with a nil snapshot")
			}
			if !ok && snap != nil {
				t.Fatal("refused table returned a snapshot")
			}
		})
	}
}

func TestSnapshotOfKeepsOnlyUsableFlowEnds(t *testing.T) {
	f := exSocketSection(
		// IPv4-mapped local end is stored as IPv4.
		hostnet.Socket{Proto: hostnet.ProtoTCP, State: "ESTAB",
			Local: netip.MustParseAddrPort("[::ffff:192.0.2.10]:22"), Peer: netip.MustParseAddrPort("192.0.2.50:51000"),
			BytesAcked: 1000, BytesReceived: 300},
		// Unspecified remote end: not a usable flow end.
		hostnet.Socket{Proto: hostnet.ProtoTCP, State: "ESTAB",
			Local: netip.MustParseAddrPort("192.0.2.10:22"), Peer: netip.MustParseAddrPort("0.0.0.0:443")},
		// TIME-WAIT carries no counters and is left out.
		hostnet.Socket{Proto: hostnet.ProtoTCP, State: "TIME-WAIT",
			Local: netip.MustParseAddrPort("192.0.2.10:22"), Peer: netip.MustParseAddrPort("192.0.2.51:40000")},
		// Connected UDP: no byte counters.
		hostnet.Socket{Proto: hostnet.ProtoUDP, State: "ESTAB",
			Local: netip.MustParseAddrPort("192.0.2.10:5353"), Peer: netip.MustParseAddrPort("192.0.2.52:53"),
			BytesAcked: 9, BytesReceived: 9},
		// Local port 0 on a connection: no usable local end.
		hostnet.Socket{Proto: hostnet.ProtoTCP, State: "ESTAB",
			Local: netip.MustParseAddrPort("192.0.2.10:0"), Peer: netip.MustParseAddrPort("192.0.2.53:443")},
		// Link-local local end: the zone is dropped.
		hostnet.Socket{Proto: hostnet.ProtoTCP, State: "ESTAB",
			Local: netip.AddrPortFrom(netip.MustParseAddr("fe80::1%eth0"), 443),
			Peer:  netip.MustParseAddrPort("[2001:db8::7]:50000"), BytesAcked: 5, BytesReceived: 6},
		// Listeners: a TCP LISTEN, a port-0 LISTEN (dropped), an UNCONN UDP.
		hostnet.Socket{Proto: hostnet.ProtoTCP, State: "LISTEN", Listening: true,
			Local: netip.MustParseAddrPort("[::]:22")},
		hostnet.Socket{Proto: hostnet.ProtoTCP, State: "LISTEN", Listening: true,
			Local: netip.MustParseAddrPort("192.0.2.10:0")},
		hostnet.Socket{Proto: hostnet.ProtoUDP, State: "UNCONN", Listening: true,
			Local: netip.MustParseAddrPort("192.0.2.10:53")},
	)

	snap, ok := snapshotOf("host-a", t0, f)
	if !ok {
		t.Fatal("complete table refused")
	}
	if snap.Host != "host-a" || snap.Tier != flowagg.TierSocket || !snap.Time.Equal(t0) {
		t.Fatalf("snapshot header = %q %q %s, want host-a, socket tier, %s", snap.Host, snap.Tier, snap.Time, t0)
	}
	wantSockets := []flowagg.Socket{
		{Proto: flowagg.TCP, Local: netip.MustParseAddrPort("192.0.2.10:22"),
			Remote: netip.MustParseAddrPort("192.0.2.50:51000"), BytesSent: 1000, BytesReceived: 300},
		{Proto: flowagg.UDP, Local: netip.MustParseAddrPort("192.0.2.10:5353"),
			Remote: netip.MustParseAddrPort("192.0.2.52:53")},
		{Proto: flowagg.TCP, Local: netip.MustParseAddrPort("[fe80::1]:443"),
			Remote: netip.MustParseAddrPort("[2001:db8::7]:50000"), BytesSent: 5, BytesReceived: 6},
	}
	if !slices.Equal(snap.Sockets, wantSockets) {
		t.Fatalf("sockets = %+v\nwant %+v", snap.Sockets, wantSockets)
	}
	wantListeners := []flowagg.Listener{
		{Proto: flowagg.TCP, Addr: netip.MustParseAddrPort("[::]:22")},
		{Proto: flowagg.UDP, Addr: netip.MustParseAddrPort("192.0.2.10:53")},
	}
	if !slices.Equal(snap.Listeners, wantListeners) {
		t.Fatalf("listeners = %+v\nwant %+v", snap.Listeners, wantListeners)
	}
}
