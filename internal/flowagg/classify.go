// SPDX-License-Identifier: AGPL-3.0-or-later

package flowagg

import (
	"cmp"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Side names one end of a canonical flow key.
type Side uint8

// Sides of a FlowKey.
const (
	SideA Side = 1
	SideB Side = 2
)

// FlowKey identifies an aggregated flow. A and B are the two endpoint
// addresses in canonical order (A < B by netip.Addr.Compare, IPv4-mapped
// addresses unmapped, zones removed); ServerPort is the port of the server
// end, Server says which end that is. Client ports are not part of the key.
//
// Server is an addition to the (A, B, proto, server port, tier) key of the
// ADR draft: without it, A→B:443 and B→A:443 would collapse into one key and
// both ends would claim to be the server reporter for it.
type FlowKey struct {
	A, B       netip.Addr
	Proto      Proto
	ServerPort uint16
	Server     Side
	Tier       string
}

// ServerAddr returns the address of the server end.
func (k FlowKey) ServerAddr() netip.Addr {
	if k.Server == SideA {
		return k.A
	}
	return k.B
}

// compareKey is the canonical total order on flow keys used for every
// sorted output of the package.
func compareKey(a, b FlowKey) int {
	if c := a.A.Compare(b.A); c != 0 {
		return c
	}
	if c := a.B.Compare(b.B); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Proto, b.Proto); c != 0 {
		return c
	}
	if c := cmp.Compare(a.ServerPort, b.ServerPort); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Server, b.Server); c != 0 {
		return c
	}
	return strings.Compare(a.Tier, b.Tier)
}

func (k FlowKey) validate() error {
	switch {
	case !k.A.IsValid() || !k.B.IsValid():
		return fmt.Errorf("invalid endpoint")
	case k.A.Zone() != "" || k.B.Zone() != "" || k.A.Is4In6() || k.B.Is4In6():
		return fmt.Errorf("endpoint not normalized")
	case k.A.Compare(k.B) >= 0:
		return fmt.Errorf("endpoints not in canonical order")
	case !k.Proto.valid():
		return fmt.Errorf("unsupported protocol %d", uint8(k.Proto))
	case k.ServerPort == 0:
		return fmt.Errorf("server port 0")
	case k.Server != SideA && k.Server != SideB:
		return fmt.Errorf("invalid server side %d", uint8(k.Server))
	}
	return nil
}

// Observation is the traffic of one flow key as seen by one reporting host
// over one report interval.
type Observation struct {
	Key FlowKey
	// BytesAB flows from A to B, BytesBA from B to A. Sums saturate at
	// math.MaxUint64.
	BytesAB, BytesBA uint64
	// Connections counts sockets that started (or were reset) within the
	// interval.
	Connections uint64
	// ServerReported is set when the reporting host is the server end
	// (its local address matched a listener).
	ServerReported bool
	// LowerBound is set when a socket of this flow was reset or vanished.
	LowerBound bool
}

// Report is the classified result of one Delta, ready for
// Aggregator.Ingest.
type Report struct {
	Host     string
	Tier     string
	From, To time.Time
	// Observations are sorted by key, one per key.
	Observations []Observation
	// LowerBound is copied from Delta.LowerBound.
	LowerBound bool
}

// listenKey identifies a listener; the zero Addr is the wildcard.
type listenKey struct {
	proto Proto
	addr  netip.Addr
	port  uint16
}

func listenerSet(ls []Listener) (map[listenKey]struct{}, error) {
	if len(ls) > MaxListenersPerSnapshot {
		return nil, fmt.Errorf("%w: %d listeners exceed limit %d", ErrInvalidSnapshot, len(ls), MaxListenersPerSnapshot)
	}
	set := make(map[listenKey]struct{}, len(ls))
	for i, l := range ls {
		if !l.Proto.valid() || !l.Addr.IsValid() || l.Addr.Port() == 0 {
			return nil, fmt.Errorf("%w: listener %d invalid", ErrInvalidSnapshot, i)
		}
		a := l.Addr.Addr().Unmap().WithZone("")
		if a.IsUnspecified() {
			// 0.0.0.0 and :: both accept every local address; Linux binds
			// :: dual-stack by default, so :: also matches IPv4 locals.
			a = netip.Addr{}
		}
		set[listenKey{proto: l.Proto, addr: a, port: l.Addr.Port()}] = struct{}{}
	}
	return set, nil
}

func isListening(set map[listenKey]struct{}, proto Proto, local netip.AddrPort) bool {
	if _, ok := set[listenKey{proto: proto, addr: local.Addr(), port: local.Port()}]; ok {
		return true
	}
	_, ok := set[listenKey{proto: proto, port: local.Port()}]
	return ok
}

// satAdd adds without wrapping; counters come from untrusted hosts.
func satAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

// flowOf maps a socket to its flow key and tells whether the local end is
// the server and whether local is endpoint A. ok is false for sockets that
// do not belong on the traffic map (loopback, both ends on one address).
func flowOf(s Socket, tier string, listeners map[listenKey]struct{}) (key FlowKey, serverLocal, localIsA, ok bool) {
	local := netip.AddrPortFrom(s.Local.Addr().Unmap().WithZone(""), s.Local.Port())
	remote := netip.AddrPortFrom(s.Remote.Addr().Unmap().WithZone(""), s.Remote.Port())
	la, ra := local.Addr(), remote.Addr()
	if la == ra || la.IsLoopback() || ra.IsLoopback() {
		return FlowKey{}, false, false, false
	}
	serverLocal = isListening(listeners, s.Proto, local)
	server := remote
	if serverLocal {
		server = local
	}
	localIsA = la.Compare(ra) < 0
	key = FlowKey{Proto: s.Proto, ServerPort: server.Port(), Tier: tier}
	if localIsA {
		key.A, key.B = la, ra
	} else {
		key.A, key.B = ra, la
	}
	key.Server = SideB
	if server.Addr() == key.A {
		key.Server = SideA
	}
	return key, serverLocal, localIsA, true
}

// Classify folds the socket deltas of d into flow observations. The server
// end of a socket is the local end if it matches one of listeners (the
// listeners of the reporting host at d.To), otherwise the remote end. The
// client port is dropped. Loopback sockets and sockets whose ends share one
// address are skipped.
//
// A host whose listener list is incomplete reports its served connections
// as client-side flows keyed by the remote ephemeral port; collectors must
// send the full listener table.
func Classify(d Delta, listeners []Listener) (Report, error) {
	set, err := listenerSet(listeners)
	if err != nil {
		return Report{}, fmt.Errorf("classify host %q: %w", d.Host, err)
	}
	obs := make(map[FlowKey]*Observation, len(d.Sockets))
	get := func(k FlowKey, serverLocal bool) *Observation {
		o := obs[k]
		if o == nil {
			o = &Observation{Key: k, ServerReported: serverLocal}
			obs[k] = o
		}
		return o
	}
	for _, sd := range d.Sockets {
		k, serverLocal, localIsA, ok := flowOf(sd.Socket, d.Tier, set)
		if !ok {
			continue
		}
		o := get(k, serverLocal)
		if localIsA {
			o.BytesAB, o.BytesBA = satAdd(o.BytesAB, sd.Sent), satAdd(o.BytesBA, sd.Received)
		} else {
			o.BytesAB, o.BytesBA = satAdd(o.BytesAB, sd.Received), satAdd(o.BytesBA, sd.Sent)
		}
		if sd.New {
			o.Connections = satAdd(o.Connections, 1)
		}
		if sd.Reset {
			o.LowerBound = true
		}
	}
	for _, s := range d.Vanished {
		k, serverLocal, _, ok := flowOf(s, d.Tier, set)
		if !ok {
			continue
		}
		get(k, serverLocal).LowerBound = true
	}
	r := Report{Host: d.Host, Tier: d.Tier, From: d.From, To: d.To, LowerBound: d.LowerBound,
		Observations: make([]Observation, 0, len(obs))}
	for _, o := range obs {
		r.Observations = append(r.Observations, *o)
	}
	slices.SortFunc(r.Observations, func(a, b Observation) int { return compareKey(a.Key, b.Key) })
	return r, nil
}

// Observe is Diff followed by Classify with the listeners of cur.
func Observe(prev, cur *Snapshot) (Report, error) {
	d, err := Diff(prev, cur)
	if err != nil {
		return Report{}, err
	}
	return Classify(d, cur.Listeners)
}
