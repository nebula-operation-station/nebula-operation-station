// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficingest

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	nfresult "github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions/netfacts"
	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	hostnet "github.com/nebula-operation-station/nebula-operation-station/internal/netfacts"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
)

// Limits on what one result may contribute.
const (
	// MaxEndpointsPerResult bounds the endpoints one net.facts result
	// writes; the rest is dropped and the host result is marked
	// truncated (ADR 0009 D7).
	MaxEndpointsPerResult = 4096
)

// snapshotOf converts the socket table of a decoded result into a
// flowagg snapshot of host at time at. ok is false when the table is not
// complete enough to diff: the section was cut, skipped or invalid, the
// parser dropped entries, or there are more listeners than flowagg
// accepts. A socket missing from one snapshot and present in the next
// would count its lifetime counters again, so such a result must not be
// diffed at all.
func snapshotOf(host string, at time.Time, f nfresult.Facts) (snap *flowagg.Snapshot, ok bool) {
	sec := f.Sections[nfresult.SectionSockets]
	if sec.Status != nfresult.StatusOK || sec.Truncated || sec.Invalid || f.Sockets.Incomplete {
		return nil, false
	}
	s := &flowagg.Snapshot{Host: host, Tier: flowagg.TierSocket, Time: at}
	type tuple struct {
		proto         flowagg.Proto
		local, remote netip.AddrPort
	}
	seenSock := map[tuple]struct{}{}
	type lkey struct {
		proto flowagg.Proto
		addr  netip.AddrPort
	}
	seenListen := map[lkey]struct{}{}
	for _, e := range f.Sockets.Entries {
		var proto flowagg.Proto
		switch e.Proto {
		case hostnet.ProtoTCP:
			proto = flowagg.TCP
		case hostnet.ProtoUDP:
			proto = flowagg.UDP
		default:
			continue
		}
		local := netip.AddrPortFrom(e.Local.Addr().Unmap().WithZone(""), e.Local.Port())
		if e.Listening {
			if !local.Addr().IsValid() || local.Port() == 0 {
				continue
			}
			k := lkey{proto, local}
			if _, dup := seenListen[k]; dup {
				continue
			}
			seenListen[k] = struct{}{}
			s.Listeners = append(s.Listeners, flowagg.Listener{Proto: proto, Addr: local})
			continue
		}
		// TIME-WAIT sockets carry no tcp_info: their zero counters on the
		// tuple of a closed connection would read as a counter reset.
		if e.State == "TIME-WAIT" {
			continue
		}
		remote := netip.AddrPortFrom(e.Peer.Addr().Unmap().WithZone(""), e.Peer.Port())
		if !usableFlowEnd(local) || !usableFlowEnd(remote) {
			continue
		}
		k := tuple{proto, local, remote}
		if _, dup := seenSock[k]; dup {
			// Two lines for one tuple cannot both be the same socket;
			// without a cookie neither can be trusted.
			return nil, false
		}
		seenSock[k] = struct{}{}
		var sent, received uint64
		if proto == flowagg.TCP {
			sent, received = e.BytesAcked, e.BytesReceived
		}
		s.Sockets = append(s.Sockets, flowagg.Socket{Proto: proto, Local: local, Remote: remote,
			BytesSent: sent, BytesReceived: received})
	}
	if len(s.Listeners) > flowagg.MaxListenersPerSnapshot || len(s.Sockets) > flowagg.MaxSocketsPerSnapshot {
		return nil, false
	}
	if s.Validate() != nil {
		return nil, false
	}
	return s, true
}

func usableFlowEnd(a netip.AddrPort) bool {
	return a.Addr().IsValid() && a.Port() != 0 && !a.Addr().IsUnspecified()
}

// usableEndpointAddr reports whether an address may name an observed
// endpoint.
func usableEndpointAddr(a netip.Addr) bool {
	return a.IsValid() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() &&
		!(a.Is4() && a == netip.AddrFrom4([4]byte{255, 255, 255, 255}))
}

// endpointsOf derives the observed endpoints of one result: the host's
// own interfaces, its neighbors (by MAC) and the peers of its sockets
// that have no neighbor entry (address only). Every endpoint carries the
// server's reporter label and the server's snapshot time. truncated is
// set when MaxEndpointsPerResult or the per-endpoint address bound cut
// something.
func endpointsOf(reporter string, at time.Time, f nfresult.Facts) (eps []trafficstore.Endpoint, truncated bool) {
	vlanOf := map[string]int{}
	for _, l := range f.Links.Entries {
		if l.Kind == "vlan" && l.VLANID != nil {
			vlanOf[l.Name] = *l.VLANID
		}
	}
	type acc struct {
		vlan  int
		addrs []netip.Addr
	}
	byMAC := map[string]*acc{}
	covered := map[netip.Addr]struct{}{}
	add := func(m, dev string, a netip.Addr) {
		a = a.Unmap().WithZone("")
		if m == "" || !usableEndpointAddr(a) {
			return
		}
		e := byMAC[m]
		if e == nil {
			e = &acc{vlan: vlanOf[dev]}
			byMAC[m] = e
		}
		covered[a] = struct{}{}
		if slices.Contains(e.addrs, a) {
			return
		}
		if len(e.addrs) >= trafficstore.MaxAddressesPerEndpoint {
			truncated = true
			return
		}
		e.addrs = append(e.addrs, a)
	}
	for _, it := range f.Addrs.Entries {
		m := usableMAC(it.MAC)
		for _, p := range it.Addrs {
			add(m, it.Name, p.Addr())
		}
	}
	for _, tab := range []hostnet.NeighborTable{f.Neigh, f.Neigh6} {
		for _, n := range tab.Entries {
			if usableNeighbor(n) {
				add(usableMAC(n.MAC), n.Dev, n.IP)
			}
		}
	}
	peers := map[netip.Addr]struct{}{}
	for _, e := range f.Sockets.Entries {
		if e.Listening || e.Peer.Port() == 0 {
			continue
		}
		a := e.Peer.Addr().Unmap().WithZone("")
		if _, ok := covered[a]; ok || !usableEndpointAddr(a) {
			continue
		}
		peers[a] = struct{}{}
	}

	for m, e := range byMAC {
		slices.SortFunc(e.addrs, netip.Addr.Compare)
		if len(e.addrs) == 0 {
			continue
		}
		eps = append(eps, trafficstore.Endpoint{MAC: m, Addresses: e.addrs, VLAN: e.vlan,
			Tier: flowagg.TierSocket, Reporter: reporter, LastSeen: at})
	}
	for a := range peers {
		eps = append(eps, trafficstore.Endpoint{Addresses: []netip.Addr{a},
			Tier: flowagg.TierSocket, Reporter: reporter, LastSeen: at})
	}
	// MAC endpoints first (they carry identity), then by MAC and address,
	// so a cut is deterministic.
	slices.SortFunc(eps, func(x, y trafficstore.Endpoint) int {
		if (x.MAC == "") != (y.MAC == "") {
			if x.MAC != "" {
				return -1
			}
			return 1
		}
		if c := strings.Compare(x.MAC, y.MAC); c != 0 {
			return c
		}
		return x.Addresses[0].Compare(y.Addresses[0])
	})
	if len(eps) > MaxEndpointsPerResult {
		eps, truncated = eps[:MaxEndpointsPerResult], true
	}
	return eps, truncated
}
