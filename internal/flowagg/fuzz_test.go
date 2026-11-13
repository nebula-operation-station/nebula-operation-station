// SPDX-License-Identifier: AGPL-3.0-or-later

package flowagg

import (
	"errors"
	"math"
	"math/big"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"
)

// The fuzz targets feed Diff and Observe with snapshots a lying host could
// send. The byte stream is decoded deterministically into two snapshots:
// reads past the end yield zero, so every input decodes.
//
// Layout of the input (one byte per field unless noted):
//
//	flags        bit 0: prev is nil (first snapshot of the host)
//	host prev    index into fuzzHosts (mod len)
//	host cur     index into fuzzHosts
//	tier prev    index into fuzzTiers
//	tier cur     index into fuzzTiers
//	time prev    index into fuzzTimes
//	time cur     index into fuzzTimes
//	prev body    socket count (mod maxFuzzSockets), per socket: tuple index
//	             (mod len(fuzzTuples)), sent counter, received counter,
//	             then listener count (mod maxFuzzListeners), per listener:
//	             index into fuzzListeners (mod len)
//	cur body     same layout as prev body
//
// A counter is a selector byte (mod 5): 0 zero, 1 MaxUint64, 2 MaxUint64 minus
// the next byte, 3 the next byte, 4 the next eight bytes big-endian.

const (
	maxFuzzSockets   = 8
	maxFuzzListeners = 3
)

var (
	fuzzHosts = []string{"h1", "h2", "", "h\x01"}
	fuzzTiers = []string{TierSocket, TierConntrack, TierSensor, "bogus", ""}
	fuzzTimes = []time.Time{
		t0.Add(-time.Minute),
		t0,
		t0.Add(time.Minute),
		t0.Add(2 * time.Minute),
		{},
	}
	// fuzzTuples covers IPv4, IPv4-mapped, IPv6, zones, loopback, same
	// address, host-internal pairs, UDP and invalid values. Counters are
	// filled in by the decoder.
	fuzzTuples = []Socket{
		{Proto: TCP, Local: ap("10.0.0.2:22"), Remote: ap("10.0.0.1:50000")},
		{Proto: TCP, Local: ap("10.0.0.1:50000"), Remote: ap("10.0.0.2:22")},
		{Proto: TCP, Cookie: 7, Local: ap("10.0.0.2:22"), Remote: ap("10.0.0.1:50001")},
		{Proto: UDP, Local: ap("10.0.0.2:53"), Remote: ap("10.0.0.1:40000")},
		{Proto: TCP, Local: ap("[fe80::2%eth0]:22"), Remote: ap("[fe80::1%eth0]:50000")},
		{Proto: TCP, Local: ap("[::ffff:10.0.0.2]:22"), Remote: ap("[::ffff:10.0.0.9]:50002")},
		{Proto: TCP, Local: ap("127.0.0.1:8080"), Remote: ap("127.0.0.1:50003")},
		{Proto: TCP, Local: ap("10.0.0.1:22"), Remote: ap("10.0.0.1:50004")},
		{Proto: TCP, Local: ap("10.0.0.1:50006"), Remote: ap("10.0.0.9:443")},
		{Proto: UDP, Local: ap("10.0.0.1:5353"), Remote: ap("10.0.0.9:5353")},
		{Proto: Proto(9), Local: ap("10.0.0.1:1"), Remote: ap("10.0.0.9:2")},
		{Proto: TCP, Local: ap("10.0.0.1:50008"), Remote: ap("0.0.0.0:22")},
		{Proto: TCP, Cookie: 9, Local: ap("10.0.0.2:22"), Remote: ap("10.0.0.9:50007")},
		{Proto: TCP, Local: ap("[2001:db8::2]:443"), Remote: ap("[2001:db8::1]:51000")},
		{Proto: UDP, Local: ap("10.0.0.1:0"), Remote: ap("10.0.0.9:53")},
	}
	fuzzListeners = []Listener{
		{Proto: TCP, Addr: ap("0.0.0.0:22")},
		{Proto: TCP, Addr: ap("10.0.0.2:22")},
		{Proto: TCP, Addr: ap("[::]:22")},
		{Proto: UDP, Addr: ap("10.0.0.2:53")},
		{Proto: TCP, Addr: ap("10.0.0.1:0")},
		{Proto: Proto(0), Addr: ap("10.0.0.1:80")},
		{Proto: TCP, Addr: ap("[::ffff:10.0.0.1]:443")},
		{Proto: TCP, Addr: ap("[fe80::2%eth0]:22")},
	}
)

// fuzzReader hands out input bytes and zeros once the input is exhausted.
type fuzzReader struct{ b []byte }

func (r *fuzzReader) next() byte {
	if len(r.b) == 0 {
		return 0
	}
	v := r.b[0]
	r.b = r.b[1:]
	return v
}

func (r *fuzzReader) counter() uint64 {
	switch r.next() % 5 {
	case 0:
		return 0
	case 1:
		return math.MaxUint64
	case 2:
		return math.MaxUint64 - uint64(r.next())
	case 3:
		return uint64(r.next())
	default:
		var v uint64
		for range 8 {
			v = v<<8 | uint64(r.next())
		}
		return v
	}
}

func (r *fuzzReader) body(host, tier string, at time.Time) *Snapshot {
	s := &Snapshot{Host: host, Tier: tier, Time: at}
	n := int(r.next()) % (maxFuzzSockets + 1)
	for range n {
		sk := fuzzTuples[int(r.next())%len(fuzzTuples)]
		sk.BytesSent = r.counter()
		sk.BytesReceived = r.counter()
		s.Sockets = append(s.Sockets, sk)
	}
	m := int(r.next()) % (maxFuzzListeners + 1)
	for range m {
		s.Listeners = append(s.Listeners, fuzzListeners[int(r.next())%len(fuzzListeners)])
	}
	return s
}

// decodeFuzzInput turns fuzz bytes into the previous and current snapshot.
// prev is nil when the flags say so.
func decodeFuzzInput(data []byte) (prev, cur *Snapshot) {
	r := &fuzzReader{b: data}
	flags := r.next()
	hostP := fuzzHosts[int(r.next())%len(fuzzHosts)]
	hostC := fuzzHosts[int(r.next())%len(fuzzHosts)]
	tierP := fuzzTiers[int(r.next())%len(fuzzTiers)]
	tierC := fuzzTiers[int(r.next())%len(fuzzTiers)]
	timeP := fuzzTimes[int(r.next())%len(fuzzTimes)]
	timeC := fuzzTimes[int(r.next())%len(fuzzTimes)]
	p := r.body(hostP, tierP, timeP)
	cur = r.body(hostC, tierC, timeC)
	if flags&1 == 0 {
		prev = p
	}
	return prev, cur
}

// fuzzSeeds are hand-built inputs for the cases of the table tests in
// snapshot_test.go and classify_test.go. TestFuzzSeedsReachCases checks that
// they still reach them.
var fuzzSeeds = [][]byte{
	// Counter reset: sent 200->10, received 200->250 on tuple 0.
	{0, 0, 0, 0, 0, 1, 2,
		1, 0, 3, 200, 3, 200, 0,
		1, 0, 3, 10, 3, 250, 1, 1},
	// Socket vanished: tuples 0 and 2 before, only 0 after.
	{0, 0, 0, 0, 0, 1, 2,
		2, 0, 3, 5, 3, 5, 2, 3, 7, 3, 7, 0,
		1, 0, 3, 9, 3, 9, 0},
	// IPv6 with zone (tuple 4), UDP (tuple 3), an IPv4-mapped flow (tuple 5)
	// and the dual-stack [::]:22 listener (index 2).
	{0, 0, 0, 0, 0, 1, 2,
		3, 4, 3, 1, 3, 1, 3, 3, 2, 3, 2, 5, 3, 1, 3, 1, 0,
		3, 4, 3, 4, 3, 9, 3, 3, 5, 3, 9, 5, 3, 4, 3, 9, 1, 2},
	// Saturation: two client sockets of one flow with maximal counters. The
	// listener 10.0.0.2:22 (index 1) makes both sockets one flow key, so their
	// sums exceed MaxUint64.
	{0, 0, 0, 0, 0, 1, 2,
		1, 0, 0, 0, 0,
		2, 0, 1, 1, 2, 1, 1, 1, 1},
	// Baseline: first snapshot of the host, prev is nil.
	{1, 0, 0, 0, 0, 1, 2,
		1, 0, 3, 1, 3, 1, 0,
		1, 0, 3, 9, 3, 9, 0},
	// Same host and tier, but prev is newer: rejected as mismatch.
	{0, 0, 0, 0, 0, 2, 1,
		0, 0,
		0, 0},
	// Invalid protocol on a socket: rejected as invalid snapshot.
	{0, 0, 0, 0, 0, 1, 2,
		0, 0,
		1, 10, 3, 1, 3, 1, 0},
	// Unknown tier: rejected as invalid snapshot.
	{0, 0, 0, 0, 3, 1, 2,
		0, 0,
		0, 0},
	// Listener with an unsupported protocol (index 5): rejected as invalid.
	{0, 0, 0, 0, 0, 1, 2,
		0, 0,
		1, 0, 3, 1, 3, 1, 1, 5},
	// Listener on port 0 (index 4): rejected as invalid.
	{0, 0, 0, 0, 0, 1, 2,
		0, 0,
		1, 0, 3, 1, 3, 1, 1, 4},
}

// socketEnds is the normalized identity of a socket without its counters,
// used to look up a host-internal peer of a socket.
type socketEnds struct {
	proto         Proto
	local, remote netip.AddrPort
}

func endsOf(s Socket) socketEnds {
	s = normalizeSocket(s)
	return socketEnds{proto: s.Proto, local: s.Local, remote: s.Remote}
}

// checkDelta asserts the invariants of a successful Diff.
func checkDelta(t *testing.T, prev, cur *Snapshot, d Delta) {
	t.Helper()
	if d.Host != cur.Host || d.Tier != cur.Tier || !d.To.Equal(cur.Time) {
		t.Fatalf("delta header %q/%q/%v does not match current %q/%q/%v", d.Host, d.Tier, d.To, cur.Host, cur.Tier, cur.Time)
	}
	if prev == nil {
		switch {
		case !d.Baseline:
			t.Fatal("prev nil but not Baseline")
		case len(d.Sockets) != 0 || len(d.Vanished) != 0:
			t.Fatalf("baseline has %d sockets and %d vanished", len(d.Sockets), len(d.Vanished))
		case d.LowerBound:
			t.Fatal("baseline sets LowerBound")
		case !d.From.Equal(cur.Time):
			t.Fatalf("baseline From %v, want %v", d.From, cur.Time)
		}
		return
	}
	if d.Baseline {
		t.Fatal("Baseline set although prev is not nil")
	}
	if !d.From.Equal(prev.Time) {
		t.Fatalf("From %v, want previous snapshot time %v", d.From, prev.Time)
	}

	prevByID := make(map[socketID]Socket, len(prev.Sockets))
	for _, s := range prev.Sockets {
		prevByID[normalizeSocket(s).id()] = normalizeSocket(s)
	}
	curByID := make(map[socketID]Socket, len(cur.Sockets))
	for _, s := range cur.Sockets {
		curByID[normalizeSocket(s).id()] = normalizeSocket(s)
	}
	if len(d.Sockets) != len(cur.Sockets) {
		t.Fatalf("got %d socket deltas, current snapshot has %d sockets", len(d.Sockets), len(cur.Sockets))
	}
	anyReset := false
	for i, sd := range d.Sockets {
		id := sd.Socket.id()
		if i > 0 && compareSocketID(d.Sockets[i-1].Socket.id(), id) >= 0 {
			t.Fatalf("sockets not strictly sorted at %d", i)
		}
		cs, ok := curByID[id]
		if !ok || cs != sd.Socket {
			t.Fatalf("socket delta %d does not match a current socket: %+v", i, sd.Socket)
		}
		if sd.Sent > cs.BytesSent || sd.Received > cs.BytesReceived {
			t.Fatalf("delta %d exceeds current counters: sent %d/%d received %d/%d", i, sd.Sent, cs.BytesSent, sd.Received, cs.BytesReceived)
		}
		if sd.Reset {
			anyReset = true
			if !sd.New {
				t.Fatalf("reset socket %d not marked New", i)
			}
		}
		ps, existed := prevByID[id]
		switch {
		case sd.Reset:
			// A reset counts the current counters as the delta.
			if !existed || cs.BytesSent >= ps.BytesSent && cs.BytesReceived >= ps.BytesReceived {
				t.Fatalf("socket %d marked reset without a decreasing counter", i)
			}
			if sd.Sent != cs.BytesSent || sd.Received != cs.BytesReceived {
				t.Fatalf("reset socket %d: delta %d/%d, want current counters %d/%d", i, sd.Sent, sd.Received, cs.BytesSent, cs.BytesReceived)
			}
		case sd.New:
			if existed {
				t.Fatalf("socket %d marked New but existed in prev", i)
			}
			if sd.Sent != cs.BytesSent || sd.Received != cs.BytesReceived {
				t.Fatalf("new socket %d: delta %d/%d, counters %d/%d", i, sd.Sent, sd.Received, cs.BytesSent, cs.BytesReceived)
			}
		default:
			if !existed {
				t.Fatalf("socket %d not New but missing in prev", i)
			}
			if sd.Sent != cs.BytesSent-ps.BytesSent || sd.Received != cs.BytesReceived-ps.BytesReceived {
				t.Fatalf("socket %d: delta %d/%d, want %d/%d", i, sd.Sent, sd.Received, cs.BytesSent-ps.BytesSent, cs.BytesReceived-ps.BytesReceived)
			}
		}
	}
	for i, v := range d.Vanished {
		id := normalizeSocket(v).id()
		if i > 0 && compareSocketID(d.Vanished[i-1].id(), id) >= 0 {
			t.Fatalf("vanished not strictly sorted at %d", i)
		}
		if _, ok := prevByID[id]; !ok {
			t.Fatalf("vanished socket %d was not in prev", i)
		}
		if _, ok := curByID[id]; ok {
			t.Fatalf("vanished socket %d is still in cur", i)
		}
	}
	// Every prev socket missing from cur must be listed; the entries above
	// are each in prev and not in cur, so equal counts make the list complete.
	missing := 0
	for id := range prevByID {
		if _, ok := curByID[id]; !ok {
			missing++
		}
	}
	if len(d.Vanished) != missing {
		t.Fatalf("Vanished lists %d sockets, %d prev sockets are missing from cur", len(d.Vanished), missing)
	}
	if len(d.Vanished) > 0 && !d.LowerBound {
		t.Fatal("vanished sockets without LowerBound")
	}
	if anyReset && !d.LowerBound {
		t.Fatal("reset without LowerBound")
	}
	if want := anyReset || len(d.Vanished) > 0; d.LowerBound != want {
		t.Fatalf("LowerBound = %v, want %v (reset %v, vanished %d)", d.LowerBound, want, anyReset, len(d.Vanished))
	}
}

// checkErr asserts that an error is one of the two documented sentinels.
func checkErr(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrInvalidSnapshot) && !errors.Is(err, ErrSnapshotMismatch) {
		t.Fatalf("error %v is neither ErrInvalidSnapshot nor ErrSnapshotMismatch", err)
	}
}

func FuzzDiff(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		prev, cur := decodeFuzzInput(data)
		d, err := Diff(prev, cur)
		if err != nil {
			checkErr(t, err)
			return
		}
		checkDelta(t, prev, cur, d)
	})
}

func cloneSnapshot(s *Snapshot) *Snapshot {
	if s == nil {
		return nil
	}
	c := *s
	c.Sockets = slices.Clone(s.Sockets)
	c.Listeners = slices.Clone(s.Listeners)
	return &c
}

func reversedSnapshot(s *Snapshot) *Snapshot {
	c := cloneSnapshot(s)
	if c != nil {
		slices.Reverse(c.Sockets)
		slices.Reverse(c.Listeners)
	}
	return c
}

// keyTotals is what Classify must report for one flow key, derived from the
// delta alone. Classify drops a socket only when its host-internal peer is in
// the same delta. Sockets without such a peer are therefore certainly counted
// (the lo bounds); every socket of the key is at most counted (the hi bounds).
// A counter must lie between its saturated lo and hi sums.
type keyTotals struct {
	abLo, abHi, baLo, baHi, connLo, connHi *big.Int
	// certain is set when a certainly counted socket or vanished socket
	// belongs to the key, so the key must be reported.
	certain    bool
	lbLo, lbHi bool
}

func addU64(dst *big.Int, v uint64) { dst.Add(dst, new(big.Int).SetUint64(v)) }

// flowTotals computes the keyTotals of every flow key the delta touches. It
// uses flowOf, the same mapping Classify uses, so the expected keys agree with
// the report; the byte and flag bounds are computed independently of Classify.
func flowTotals(d Delta, listeners []Listener) (map[FlowKey]*keyTotals, error) {
	set, err := listenerSet(listeners)
	if err != nil {
		return nil, err
	}
	ends := make(map[socketEnds]bool, len(d.Sockets)+len(d.Vanished))
	for _, sd := range d.Sockets {
		ends[endsOf(sd.Socket)] = true
	}
	for _, s := range d.Vanished {
		ends[endsOf(s)] = true
	}
	hasPeer := func(s Socket) bool {
		e := endsOf(s)
		return ends[socketEnds{proto: e.proto, local: e.remote, remote: e.local}]
	}
	totals := make(map[FlowKey]*keyTotals)
	get := func(k FlowKey) *keyTotals {
		t := totals[k]
		if t == nil {
			t = &keyTotals{
				abLo: new(big.Int), abHi: new(big.Int), baLo: new(big.Int), baHi: new(big.Int),
				connLo: new(big.Int), connHi: new(big.Int),
			}
			totals[k] = t
		}
		return t
	}
	for _, sd := range d.Sockets {
		k, _, localIsA, ok := flowOf(sd.Socket, d.Tier, set)
		if !ok {
			continue
		}
		t := get(k)
		ab, ba := sd.Received, sd.Sent
		if localIsA {
			ab, ba = sd.Sent, sd.Received
		}
		addU64(t.abHi, ab)
		addU64(t.baHi, ba)
		if sd.New {
			addU64(t.connHi, 1)
		}
		if sd.Reset {
			t.lbHi = true
		}
		if hasPeer(sd.Socket) {
			continue
		}
		t.certain = true
		addU64(t.abLo, ab)
		addU64(t.baLo, ba)
		if sd.New {
			addU64(t.connLo, 1)
		}
		if sd.Reset {
			t.lbLo = true
		}
	}
	for _, s := range d.Vanished {
		k, _, _, ok := flowOf(s, d.Tier, set)
		if !ok {
			continue
		}
		t := get(k)
		t.lbHi = true
		if !hasPeer(s) {
			t.certain = true
			t.lbLo = true
		}
	}
	return totals, nil
}

// saturate returns v capped at math.MaxUint64, the value of a saturating sum.
func saturate(v *big.Int) uint64 {
	if !v.IsUint64() {
		return math.MaxUint64
	}
	return v.Uint64()
}

// checkCounter asserts that got lies between the saturated certainly-counted
// sum and the saturated possibly-counted sum. A wrapping add fails the lower
// bound whenever the true sum exceeds MaxUint64.
func checkCounter(t *testing.T, key FlowKey, name string, got uint64, lo, hi *big.Int) {
	t.Helper()
	if l := saturate(lo); got < l {
		t.Fatalf("key %+v: %s = %d, below the %d certainly counted", key, name, got, l)
	}
	if h := saturate(hi); got > h {
		t.Fatalf("key %+v: %s = %d, above the %d possibly counted", key, name, got, h)
	}
}

// checkReport asserts the invariants of a classified report. Every counter is
// bounded by the per-key sums of the delta, LowerBound follows the reset and
// vanished sockets of each key, and ServerReported names a listener of cur.
func checkReport(t *testing.T, cur, prev *Snapshot, d Delta, r Report) {
	t.Helper()
	if r.Host != d.Host || r.Tier != d.Tier || r.LowerBound != d.LowerBound || !r.To.Equal(d.To) || !r.From.Equal(d.From) {
		t.Fatalf("report header does not match delta: %+v", r)
	}
	if prev == nil && len(r.Observations) != 0 {
		t.Fatalf("baseline produced %d observations", len(r.Observations))
	}
	totals, err := flowTotals(d, cur.Listeners)
	if err != nil {
		t.Fatalf("flow totals: %v", err)
	}
	set, err := listenerSet(cur.Listeners)
	if err != nil {
		t.Fatalf("listeners: %v", err)
	}
	seen := make(map[FlowKey]bool, len(r.Observations))
	for i, o := range r.Observations {
		if err := o.Key.validate(); err != nil {
			t.Fatalf("observation %d has invalid key: %v", i, err)
		}
		if i > 0 && compareKey(r.Observations[i-1].Key, o.Key) >= 0 {
			t.Fatalf("observations not strictly sorted at %d", i)
		}
		tot := totals[o.Key]
		if tot == nil {
			t.Fatalf("observation %d for key %+v has no socket in the delta", i, o.Key)
		}
		seen[o.Key] = true
		checkCounter(t, o.Key, "BytesAB", o.BytesAB, tot.abLo, tot.abHi)
		checkCounter(t, o.Key, "BytesBA", o.BytesBA, tot.baLo, tot.baHi)
		checkCounter(t, o.Key, "Connections", o.Connections, tot.connLo, tot.connHi)
		if tot.lbLo && !o.LowerBound {
			t.Fatalf("key %+v drops LowerBound of a reset or vanished socket", o.Key)
		}
		if o.LowerBound && !tot.lbHi {
			t.Fatalf("key %+v has LowerBound without a reset or vanished socket", o.Key)
		}
		if o.LowerBound && !r.LowerBound {
			t.Fatalf("key %+v has LowerBound but the report does not", o.Key)
		}
		if o.ServerReported && !isListening(set, o.Key.Proto, netip.AddrPortFrom(o.Key.ServerAddr(), o.Key.ServerPort)) {
			t.Fatalf("key %+v is ServerReported but its server end is not a listener", o.Key)
		}
	}
	for k, tot := range totals {
		if tot.certain && !seen[k] {
			t.Fatalf("key %+v has certainly counted sockets but no observation", k)
		}
	}
}

func FuzzObserve(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		prev, cur := decodeFuzzInput(data)
		prevIn, curIn := cloneSnapshot(prev), cloneSnapshot(cur)

		r1, err1 := Observe(prev, cur)
		r2, err2 := Observe(prev, cur)
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("Observe errors differ between calls: %v vs %v", err1, err2)
		}
		if !reflect.DeepEqual(prev, prevIn) || !reflect.DeepEqual(cur, curIn) {
			t.Fatal("Observe modified its input snapshots")
		}
		if err1 != nil {
			checkErr(t, err1)
			return
		}
		if !reflect.DeepEqual(r1, r2) {
			t.Fatal("Observe is not deterministic for the same input")
		}

		// Socket and listener order in the input must not change the result.
		r3, err3 := Observe(reversedSnapshot(prev), reversedSnapshot(cur))
		if err3 != nil {
			t.Fatalf("reversed input rejected: %v", err3)
		}
		if !reflect.DeepEqual(r1, r3) {
			t.Fatalf("input order changes the report:\n%+v\n%+v", r1, r3)
		}

		d, err := Diff(prev, cur)
		if err != nil {
			t.Fatalf("Diff failed where Observe succeeded: %v", err)
		}
		checkDelta(t, prev, cur, d)
		// Observe is wired to the listeners of cur. The equality only checks
		// that wiring; the correctness of the report is checked by checkReport.
		rc, err := Classify(d, cur.Listeners)
		if err != nil {
			t.Fatalf("Classify failed on a valid delta: %v", err)
		}
		if !reflect.DeepEqual(rc, r1) {
			t.Fatal("Observe is not Diff followed by Classify with the listeners of cur")
		}
		checkReport(t, cur, prev, d, r1)
	})
}

// TestFuzzSeedsReachCases checks that the seed corpus still decodes into the
// cases it is meant to cover, so the fuzzers start from useful inputs.
func TestFuzzSeedsReachCases(t *testing.T) {
	var sawReset, sawVanished, sawSaturated, sawBaseline, sawMismatch, sawInvalid, sawIPv6, sawUDP bool
	for _, seed := range fuzzSeeds {
		prev, cur := decodeFuzzInput(seed)
		d, err := Diff(prev, cur)
		switch {
		case errors.Is(err, ErrSnapshotMismatch):
			sawMismatch = true
			continue
		case errors.Is(err, ErrInvalidSnapshot):
			sawInvalid = true
			continue
		case err != nil:
			t.Fatalf("seed: unexpected error %v", err)
		}
		if d.Baseline {
			sawBaseline = true
		}
		if len(d.Vanished) > 0 {
			sawVanished = true
		}
		for _, sd := range d.Sockets {
			if sd.Reset {
				sawReset = true
			}
			if sd.Socket.Proto == UDP {
				sawUDP = true
			}
			if sd.Socket.Local.Addr().Is6() || sd.Socket.Remote.Addr().Is6() {
				sawIPv6 = true
			}
		}
		totals, err := flowTotals(d, cur.Listeners)
		if err != nil {
			t.Fatalf("seed: flow totals: %v", err)
		}
		for _, tot := range totals {
			// A flow whose true sum exceeds MaxUint64 is saturated by Classify.
			if !tot.abHi.IsUint64() || !tot.baHi.IsUint64() {
				sawSaturated = true
			}
		}
		r, err := Observe(prev, cur)
		if err != nil {
			t.Fatalf("seed: Observe: %v", err)
		}
		checkReport(t, cur, prev, d, r)
	}
	for name, ok := range map[string]bool{
		"reset": sawReset, "vanished socket": sawVanished, "saturation": sawSaturated,
		"baseline": sawBaseline, "time mismatch": sawMismatch, "invalid snapshot": sawInvalid,
		"IPv6": sawIPv6, "UDP": sawUDP,
	} {
		if !ok {
			t.Errorf("seed corpus does not reach case %q", name)
		}
	}
}
