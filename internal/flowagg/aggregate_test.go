// SPDX-License-Identifier: AGPL-3.0-or-later

package flowagg

import (
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func newTestAgg(now time.Time, l Limits) *Aggregator {
	return NewAggregator(l, func() time.Time { return now })
}

// key22 is the flow 10.0.0.1 -> 10.0.0.2:22.
var key22 = FlowKey{A: addr("10.0.0.1"), B: addr("10.0.0.2"), Proto: TCP, ServerPort: 22, Server: SideB, Tier: "socket"}

func report(host string, from, to time.Time, obs ...Observation) Report {
	return Report{Host: host, Tier: "socket", From: from, To: to, Observations: obs}
}

// ownOf returns the addresses a report's observations claim for their
// reporter, for tests that are not about address binding. A report without
// observations gets a documentation address.
func ownOf(r Report) []netip.Addr {
	own := []netip.Addr{addr("192.0.2.254")}
	for i := range r.Observations {
		own = append(own, reporterEnd(&r.Observations[i]))
	}
	return own
}

func mustIngest(t *testing.T, a *Aggregator, r Report) IngestResult {
	t.Helper()
	res, err := a.Ingest(r, ownOf(r))
	if err != nil {
		t.Fatalf("Ingest(%s %v): %v", r.Host, r.To, err)
	}
	return res
}

func TestIngestMergesBothSidesWithoutDoubleCounting(t *testing.T) {
	now := t0.Add(2 * time.Hour)
	tests := []struct {
		name    string
		reports []Report
		want    FlowTotal
	}{
		{
			name:    "server only",
			reports: []Report{report("srv", t0, t0.Add(time.Minute), Observation{Key: key22, BytesAB: 10, BytesBA: 100, Connections: 1, ServerReported: true})},
			want:    FlowTotal{Key: key22, BytesAB: 10, BytesBA: 100, Connections: 1, ServerReported: true},
		},
		{
			name:    "client only",
			reports: []Report{report("cli", t0, t0.Add(time.Minute), Observation{Key: key22, BytesAB: 9, BytesBA: 99, Connections: 1})},
			want:    FlowTotal{Key: key22, BytesAB: 9, BytesBA: 99, Connections: 1},
		},
		{
			name: "both sides: server wins, client confirms",
			reports: []Report{
				report("cli", t0, t0.Add(time.Minute), Observation{Key: key22, BytesAB: 9, BytesBA: 99, Connections: 1}),
				report("srv", t0, t0.Add(time.Minute), Observation{Key: key22, BytesAB: 10, BytesBA: 100, Connections: 1, ServerReported: true}),
			},
			want: FlowTotal{Key: key22, BytesAB: 10, BytesBA: 100, Connections: 1, ServerReported: true, Confirmed: true},
		},
		{
			name: "server reports accumulate within the hour",
			reports: []Report{
				report("srv", t0, t0.Add(time.Minute), Observation{Key: key22, BytesAB: 10, BytesBA: 100, Connections: 1, ServerReported: true}),
				report("srv", t0.Add(time.Minute), t0.Add(2*time.Minute), Observation{Key: key22, BytesAB: 5, BytesBA: 50, ServerReported: true}),
				report("cli", t0, t0.Add(2*time.Minute), Observation{Key: key22, BytesAB: 15, BytesBA: 150, Connections: 1}),
			},
			want: FlowTotal{Key: key22, BytesAB: 15, BytesBA: 150, Connections: 1, ServerReported: true, Confirmed: true},
		},
		{
			name: "second host with the same address claiming the server side is ignored",
			reports: []Report{
				report("srv", t0, t0.Add(time.Minute), Observation{Key: key22, BytesAB: 10, BytesBA: 100, Connections: 1, ServerReported: true}),
				report("imposter", t0, t0.Add(time.Minute), Observation{Key: key22, BytesAB: 1000, BytesBA: 1000, Connections: 9, ServerReported: true}),
			},
			want: FlowTotal{Key: key22, BytesAB: 10, BytesBA: 100, Connections: 1, ServerReported: true},
		},
		{
			name: "lower bound comes from the counted side",
			reports: []Report{
				report("srv", t0, t0.Add(time.Minute), Observation{Key: key22, BytesAB: 10, ServerReported: true, LowerBound: true}),
				report("cli", t0, t0.Add(time.Minute), Observation{Key: key22, BytesAB: 10}),
			},
			want: FlowTotal{Key: key22, BytesAB: 10, ServerReported: true, Confirmed: true, LowerBound: true},
		},
		{
			name: "hours are summed across the window",
			reports: []Report{
				report("srv", t0, t0.Add(time.Minute), Observation{Key: key22, BytesAB: 1, BytesBA: 2, Connections: 1, ServerReported: true}),
				report("srv", t0.Add(time.Minute), t0.Add(time.Hour+time.Minute), Observation{Key: key22, BytesAB: 3, BytesBA: 4, Connections: 1, ServerReported: true}),
				report("cli", t0, t0.Add(time.Minute), Observation{Key: key22, BytesAB: 1, BytesBA: 2, Connections: 1}),
			},
			// The second hour has no client report, so the window is not fully confirmed.
			want: FlowTotal{Key: key22, BytesAB: 4, BytesBA: 6, Connections: 2, ServerReported: true},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := newTestAgg(now, DefaultLimits())
			first := tc.reports[0].To
			for _, r := range tc.reports {
				mustIngest(t, a, r)
			}
			got := a.TopN(addr("10.0.0.1"), Window{From: t0, To: now}, 10)
			if len(got) != 1 {
				t.Fatalf("TopN = %+v, want one flow", got)
			}
			g := got[0]
			if g.FirstSeen.IsZero() || g.LastSeen.Before(g.FirstSeen) || g.FirstSeen.Before(first.Add(-time.Hour)) {
				t.Errorf("bad first/last seen %v %v", g.FirstSeen, g.LastSeen)
			}
			g.FirstSeen, g.LastSeen = time.Time{}, time.Time{}
			if g != tc.want {
				t.Errorf("total = %+v\nwant    %+v", g, tc.want)
			}
		})
	}
}

func TestIngestRejectsDuplicateAndOverlappingReports(t *testing.T) {
	a := newTestAgg(t0.Add(time.Hour), DefaultLimits())
	obs := Observation{Key: key22, BytesAB: 10, BytesBA: 10, ServerReported: true}
	mustIngest(t, a, report("srv", t0, t0.Add(2*time.Minute), obs))
	for _, r := range []Report{
		report("srv", t0, t0.Add(2*time.Minute), obs),                  // exact duplicate
		report("srv", t0.Add(time.Minute), t0.Add(3*time.Minute), obs), // overlaps
		report("srv", t0.Add(-time.Minute), t0.Add(time.Minute), obs),  // older
	} {
		if _, err := a.Ingest(r, ownOf(r)); !errors.Is(err, ErrDuplicateReport) {
			t.Fatalf("Ingest(%v..%v) = %v, want ErrDuplicateReport", r.From, r.To, err)
		}
	}
	// Another tier of the same host is an independent reporter.
	other := report("srv", t0, t0.Add(2*time.Minute), Observation{Key: FlowKey{A: key22.A, B: key22.B, Proto: TCP, ServerPort: 22, Server: SideB, Tier: "conntrack"}, ServerReported: true})
	other.Tier = "conntrack"
	mustIngest(t, a, other)
	got := a.TopN(addr("10.0.0.1"), Window{From: t0, To: t0.Add(time.Hour)}, 10)
	if len(got) != 2 || got[0].Total() != 20 {
		t.Fatalf("duplicates were counted: %+v", got)
	}
}

func TestIngestRejectsInvalidReports(t *testing.T) {
	now := t0.Add(time.Hour)
	ok := Observation{Key: key22, ServerReported: true}
	swapped := key22
	swapped.A, swapped.B = swapped.B, swapped.A
	mapped := key22
	mapped.A = addr("::ffff:10.0.0.1")
	zoned := FlowKey{A: addr("fe80::1%eth0"), B: addr("fe80::2"), Proto: TCP, ServerPort: 22, Server: SideA, Tier: "socket"}
	badTier := key22
	badTier.Tier = "conntrack"
	noPort := key22
	noPort.ServerPort = 0
	noSide := key22
	noSide.Server = 0
	tests := []struct {
		name string
		r    Report
		want error
	}{
		{"empty host", report("", t0, t0, ok), ErrInvalidReport},
		{"bad tier", Report{Host: "h", Tier: "X", From: t0, To: t0}, ErrInvalidReport},
		{"unknown tier", Report{Host: "h", Tier: "socket2", From: t0, To: t0}, ErrInvalidReport},
		{"zero time", report("h", time.Time{}, time.Time{}, ok), ErrInvalidReport},
		{"from after to", report("h", t0.Add(time.Minute), t0, ok), ErrInvalidReport},
		{"keys not canonical", report("h", t0, t0, Observation{Key: swapped}), ErrInvalidReport},
		{"v4-mapped key", report("h", t0, t0, Observation{Key: mapped}), ErrInvalidReport},
		{"zoned key", report("h", t0, t0, Observation{Key: zoned}), ErrInvalidReport},
		{"key from other tier", report("h", t0, t0, Observation{Key: badTier}), ErrInvalidReport},
		{"server port 0", report("h", t0, t0, Observation{Key: noPort}), ErrInvalidReport},
		{"no server side", report("h", t0, t0, Observation{Key: noSide}), ErrInvalidReport},
		{"duplicate key", report("h", t0, t0, ok, ok), ErrInvalidReport},
		{"unsorted keys", report("h", t0, t0,
			Observation{Key: FlowKey{A: addr("10.0.0.5"), B: addr("10.0.0.6"), Proto: TCP, ServerPort: 1, Server: SideA, Tier: "socket"}}, ok), ErrInvalidReport},
		{"too many observations", report("h", t0, t0, make([]Observation, MaxSocketsPerSnapshot+1)...), ErrInvalidReport},
		{"older than retention", report("h", now.Add(-Retention-time.Hour), now.Add(-Retention-time.Hour), ok), ErrOutOfWindow},
		{"from the future", report("h", now.Add(time.Hour), now.Add(time.Hour), ok), ErrOutOfWindow},
		{"interval too long", report("h", t0, t0.Add(time.Hour+time.Second), ok), ErrIntervalTooLong},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := newTestAgg(now, DefaultLimits())
			if _, err := a.Ingest(tc.r, ownOf(tc.r)); !errors.Is(err, tc.want) {
				t.Fatalf("Ingest = %v, want %v", err, tc.want)
			}
			if a.Buckets() != 0 || a.Reporters() != 0 {
				t.Fatal("rejected report changed state")
			}
		})
	}
}

func TestIngestBucketLimitDropsNewFlows(t *testing.T) {
	l := DefaultLimits()
	l.MaxBuckets = 2
	a := newTestAgg(t0.Add(time.Hour), l)
	var obs []Observation
	for i := 1; i <= 4; i++ {
		obs = append(obs, Observation{Key: FlowKey{A: addr("10.0.0.1"), B: addr(fmt.Sprintf("10.0.0.%d", i+1)), Proto: TCP, ServerPort: 22, Server: SideB, Tier: "socket"}, BytesAB: 1})
	}
	res := mustIngest(t, a, report("h", t0, t0, obs...))
	if res.Applied != 2 || res.Dropped != 2 || a.Buckets() != 2 || a.Dropped() != 2 {
		t.Fatalf("result %+v, buckets %d, dropped %d", res, a.Buckets(), a.Dropped())
	}
	// Existing buckets still accept data at the limit.
	res = mustIngest(t, a, report("h", t0.Add(time.Second), t0.Add(time.Second), obs[0]))
	if res.Applied != 1 || res.Dropped != 0 {
		t.Fatalf("existing bucket not updated: %+v", res)
	}
}

func TestIngestReporterLimit(t *testing.T) {
	l := DefaultLimits()
	l.MaxReporters = 1
	a := newTestAgg(t0.Add(time.Hour), l)
	mustIngest(t, a, report("h1", t0, t0))
	if _, err := a.Ingest(report("h2", t0, t0), ownOf(Report{})); !errors.Is(err, ErrLimit) {
		t.Fatalf("Ingest = %v, want ErrLimit", err)
	}
}

func TestCutoffRemovesOldHoursAndReporters(t *testing.T) {
	now := t0.Add(30 * 24 * time.Hour)
	a := newTestAgg(now, DefaultLimits())
	oldTime := now.Add(-Retention + time.Hour)
	mustIngest(t, a, report("old", oldTime, oldTime, Observation{Key: key22, BytesAB: 1, ServerReported: true}))
	mustIngest(t, a, report("new", now, now, Observation{Key: key22, BytesAB: 2}))
	if a.Buckets() != 2 {
		t.Fatalf("buckets = %d", a.Buckets())
	}
	removed := a.Cutoff(now.Add(2*time.Hour), Retention)
	if removed != 1 || a.Buckets() != 1 {
		t.Fatalf("Cutoff removed %d, buckets %d", removed, a.Buckets())
	}
	if a.Reporters() != 1 {
		t.Fatalf("reporters = %d, want only the recent one", a.Reporters())
	}
	got := a.TopN(addr("10.0.0.2"), Window{From: time.Time{}, To: now.Add(time.Hour)}, 5)
	if len(got) != 1 || got[0].BytesAB != 2 {
		t.Fatalf("TopN after cutoff = %+v", got)
	}
}

func TestIngestPrunesExpiredHoursAutomatically(t *testing.T) {
	cur := t0
	a := NewAggregator(DefaultLimits(), func() time.Time { return cur })
	mustIngest(t, a, report("h", cur, cur, Observation{Key: key22, BytesAB: 1, ServerReported: true}))
	cur = cur.Add(Retention + 2*time.Hour)
	mustIngest(t, a, report("h", cur, cur, Observation{Key: key22, BytesAB: 1, ServerReported: true}))
	if a.Buckets() != 1 {
		t.Fatalf("expired hour not pruned on ingest: %d buckets", a.Buckets())
	}
}

func flowTo(b string, port uint16) FlowKey {
	k := FlowKey{A: addr("10.0.0.1"), B: addr(b), Proto: TCP, ServerPort: port, Server: SideB, Tier: "socket"}
	if k.A.Compare(k.B) > 0 {
		k.A, k.B, k.Server = k.B, k.A, SideA
	}
	return k
}

func TestTopNOrderingIsDeterministic(t *testing.T) {
	now := t0.Add(time.Hour)
	a := newTestAgg(now, DefaultLimits())
	mustIngest(t, a, report("h", t0, t0,
		Observation{Key: flowTo("10.0.0.2", 22), BytesAB: 50, BytesBA: 50},
		Observation{Key: flowTo("10.0.0.3", 22), BytesAB: 100},
		Observation{Key: flowTo("10.0.0.4", 22), BytesBA: 100}, // tie with .3, ordered by key
		Observation{Key: flowTo("10.0.0.4", 80), BytesAB: 1},
		Observation{Key: flowTo("10.0.0.5", 22), BytesAB: 500},
	))
	mustIngest(t, a, report("x", t0, t0,
		Observation{Key: FlowKey{A: addr("10.0.0.7"), B: addr("10.0.0.8"), Proto: TCP, ServerPort: 22, Server: SideA, Tier: "socket"}, BytesAB: 1 << 40}))
	w := Window{From: t0, To: now}
	for i := 0; i < 20; i++ {
		got := a.TopN(addr("10.0.0.1"), w, 3)
		want := []FlowKey{flowTo("10.0.0.5", 22), flowTo("10.0.0.2", 22), flowTo("10.0.0.3", 22)}
		if len(got) != len(want) {
			t.Fatalf("TopN = %+v", got)
		}
		for j := range want {
			if got[j].Key != want[j] {
				t.Fatalf("run %d pos %d = %+v, want %+v", i, j, got[j].Key, want[j])
			}
		}
	}
	if got := a.TopN(addr("10.0.0.1"), w, 0); len(got) != 0 {
		t.Fatalf("TopN n=0 = %+v", got)
	}
	if got := a.TopN(addr("::ffff:10.0.0.1"), w, 100); len(got) != 5 {
		t.Fatalf("v4-mapped node lookup = %d flows, want 5", len(got))
	}
}

func TestWindowSelectsOverlappingHours(t *testing.T) {
	now := t0.Add(5 * time.Hour)
	a := newTestAgg(now, DefaultLimits())
	for h := 0; h < 4; h++ {
		at := t0.Add(time.Duration(h)*time.Hour + 30*time.Minute)
		mustIngest(t, a, report("srv", at, at, Observation{Key: key22, BytesAB: 1 << h, ServerReported: true}))
	}
	tests := []struct {
		w    Window
		want uint64
	}{
		{Window{From: t0, To: t0.Add(4 * time.Hour)}, 15},
		{Window{From: t0.Add(time.Hour), To: t0.Add(2 * time.Hour)}, 2},
		{Window{From: t0.Add(90 * time.Minute), To: t0.Add(150 * time.Minute)}, 6}, // partial hours count fully
		{Window{From: t0.Add(4 * time.Hour), To: now}, 0},
		{Window{From: now, To: t0}, 0}, // empty window
	}
	for _, tc := range tests {
		got := a.TopN(addr("10.0.0.1"), tc.w, 1)
		var sum uint64
		for _, g := range got {
			sum += g.BytesAB
		}
		if sum != tc.want {
			t.Errorf("window %v..%v = %d, want %d", tc.w.From, tc.w.To, sum, tc.want)
		}
	}
}

func TestOverviewUnion(t *testing.T) {
	now := t0.Add(time.Hour)
	a := newTestAgg(now, DefaultLimits())
	k := func(x, y string, port uint16) FlowKey {
		return FlowKey{A: addr(x), B: addr(y), Proto: TCP, ServerPort: port, Server: SideB, Tier: "socket"}
	}
	var obs []Observation
	// Node .1 has 7 flows; only its top 2 matter with n=2.
	for i := 0; i < 7; i++ {
		obs = append(obs, Observation{Key: k("10.0.0.1", "10.0.1.1", uint16(1000+i)), BytesAB: uint64(100 + i)})
	}
	// Node .2 has one small flow that is not in .1's top set.
	obs = append(obs, Observation{Key: k("10.0.0.2", "10.0.1.1", 22), BytesAB: 1})
	mustIngest(t, a, report("h", t0, t0, sortObs(obs)...))
	w := Window{From: t0, To: now}

	got := a.OverviewUnion([]netip.Addr{addr("10.0.0.2"), addr("10.0.0.1"), addr("10.0.0.1")}, w, 2)
	want := []FlowKey{k("10.0.0.1", "10.0.1.1", 1006), k("10.0.0.1", "10.0.1.1", 1005), k("10.0.0.2", "10.0.1.1", 22)}
	if len(got) != len(want) {
		t.Fatalf("OverviewUnion = %+v", got)
	}
	for i := range want {
		if got[i].Key != want[i] {
			t.Errorf("pos %d = %+v, want %+v", i, got[i].Key, want[i])
		}
	}
	// Node 10.0.1.1 sees every flow; its top 2 equal .1's top 2, so the
	// union does not grow.
	got = a.OverviewUnion([]netip.Addr{addr("10.0.0.1"), addr("10.0.1.1")}, w, 2)
	if len(got) != 2 {
		t.Fatalf("union with overlapping top sets = %+v", got)
	}
	// n <= 0 means the default of 5 per node.
	got = a.OverviewUnion([]netip.Addr{addr("10.0.0.1")}, w, 0)
	if len(got) != DefaultOverviewN {
		t.Fatalf("default n gave %d flows", len(got))
	}
	if got := a.OverviewUnion(nil, w, 5); len(got) != 0 {
		t.Fatalf("no nodes = %+v", got)
	}
}

func sortObs(o []Observation) []Observation {
	r := Report{Observations: o}
	sortObservations(r.Observations)
	return r.Observations
}

func TestEndToEndTwoHostsIPv6(t *testing.T) {
	now := t0.Add(time.Hour)
	a := newTestAgg(now, DefaultLimits())
	srvL := []Listener{{Proto: TCP, Addr: ap("[::]:8006")}}
	srv0 := snap("pve", t0, sock("[2001:db8::10]:8006", "[2001:db8::20]:50000", 1000, 100))
	srv0.Listeners = srvL
	srv1 := snap("pve", t0.Add(time.Minute), sock("[2001:db8::10]:8006", "[2001:db8::20]:50000", 3000, 300))
	srv1.Listeners = srvL
	cli0 := snap("ws", t0, sock("[2001:db8::20]:50000", "[2001:db8::10]:8006", 100, 990))
	cli1 := snap("ws", t0.Add(time.Minute), sock("[2001:db8::20]:50000", "[2001:db8::10]:8006", 300, 2950))
	for _, pair := range [][2]*Snapshot{{nil, srv0}, {srv0, srv1}, {nil, cli0}, {cli0, cli1}} {
		r, err := Observe(pair[0], pair[1])
		if err != nil {
			t.Fatal(err)
		}
		own := map[string]netip.Addr{"pve": addr("2001:db8::10"), "ws": addr("2001:db8::20")}[r.Host]
		if _, err := a.Ingest(r, []netip.Addr{own}); err != nil {
			t.Fatal(err)
		}
	}
	got := a.TopN(addr("2001:db8::20"), Window{From: t0, To: now}, 5)
	// The first snapshots are baselines: only the traffic after them counts.
	want := FlowTotal{Key: FlowKey{A: addr("2001:db8::10"), B: addr("2001:db8::20"), Proto: TCP, ServerPort: 8006, Server: SideA, Tier: "socket"},
		BytesAB: 2000, BytesBA: 200, ServerReported: true, Confirmed: true}
	if len(got) != 1 {
		t.Fatalf("TopN = %+v", got)
	}
	g := got[0]
	g.FirstSeen, g.LastSeen = time.Time{}, time.Time{}
	if g != want {
		t.Fatalf("got  %+v\nwant %+v", g, want)
	}
}

func TestLogScale(t *testing.T) {
	tests := []struct {
		v, max uint64
		want   float64
	}{
		{0, 0, 0},
		{5, 0, 0},
		{0, 1000, 0},
		{1000, 1000, 1},
		{2000, 1000, 1}, // clamped
		{math.MaxUint64, math.MaxUint64, 1},
		{9, 99, 0.5}, // log10(10)/log10(100)
	}
	for _, tc := range tests {
		if got := LogScale(tc.v, tc.max); math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("LogScale(%d, %d) = %v, want %v", tc.v, tc.max, got, tc.want)
		}
	}
	prev := -1.0
	for v := uint64(0); v <= 1<<20; v = v*2 + 1 {
		got := LogScale(v, 1<<20)
		if got < prev || got < 0 || got > 1 {
			t.Fatalf("LogScale not monotonic in [0,1] at %d: %v", v, got)
		}
		prev = got
	}
}

// benchSetup builds snapshots for hosts hosts with flows sockets each.
func benchSetup(hosts, flows int) (prev, cur []*Snapshot) {
	for h := 0; h < hosts; h++ {
		local := netip.AddrFrom4([4]byte{10, 1, byte(h >> 8), byte(h)})
		var p, c []Socket
		for f := 0; f < flows; f++ {
			peer := (h + f + 1) % hosts
			remote := netip.AddrFrom4([4]byte{10, 1, byte(peer >> 8), byte(peer)})
			s := Socket{Proto: TCP, Local: netip.AddrPortFrom(local, uint16(40000+f)), Remote: netip.AddrPortFrom(remote, 443),
				BytesSent: uint64(f * 1000), BytesReceived: uint64(h * 10)}
			p = append(p, s)
			s.BytesSent += uint64(h*7 + f)
			s.BytesReceived += uint64(f * 13)
			c = append(c, s)
		}
		host := fmt.Sprintf("host-%d", h)
		prev = append(prev, &Snapshot{Host: host, Tier: "socket", Time: t0, Sockets: p})
		cur = append(cur, &Snapshot{Host: host, Tier: "socket", Time: t0.Add(time.Minute), Sockets: c})
	}
	return prev, cur
}

// runPipeline diffs, classifies and ingests every host, then builds the
// overview. It is the workload the 100 ms budget applies to.
func runPipeline(prev, cur []*Snapshot) ([]FlowTotal, error) {
	a := NewAggregator(DefaultLimits(), func() time.Time { return t0.Add(time.Hour) })
	nodes := make([]netip.Addr, 0, len(cur))
	for i := range cur {
		r, err := Observe(prev[i], cur[i])
		if err != nil {
			return nil, err
		}
		local := cur[i].Sockets[0].Local.Addr()
		res, err := a.Ingest(r, []netip.Addr{local})
		if err != nil {
			return nil, err
		}
		if res.Applied != len(r.Observations) {
			return nil, fmt.Errorf("host %s: %+v", r.Host, res)
		}
		nodes = append(nodes, local)
	}
	return a.OverviewUnion(nodes, Window{From: t0, To: t0.Add(time.Hour)}, DefaultOverviewN), nil
}

// expectedOverview computes the overview of benchSetup independently: host
// h is the client of flow f to host (h+f+1)%hosts on port 443 with
// 7h+f bytes sent and 13f bytes received in the interval.
func expectedOverview(hosts, flows int) []FlowTotal {
	ip := func(h int) netip.Addr { return netip.AddrFrom4([4]byte{10, 1, byte(h >> 8), byte(h)}) }
	perNode := make(map[netip.Addr][]FlowTotal)
	for h := 0; h < hosts; h++ {
		for f := 0; f < flows; f++ {
			cli, srv := ip(h), ip((h+f+1)%hosts)
			t := FlowTotal{Key: FlowKey{A: cli, B: srv, Proto: TCP, ServerPort: 443, Server: SideB, Tier: "socket"},
				BytesAB: uint64(h*7 + f), BytesBA: uint64(f * 13)}
			if srv.Less(cli) {
				t.Key.A, t.Key.B, t.Key.Server = srv, cli, SideA
				t.BytesAB, t.BytesBA = t.BytesBA, t.BytesAB
			}
			perNode[cli] = append(perNode[cli], t)
			perNode[srv] = append(perNode[srv], t)
		}
	}
	union := make(map[FlowKey]FlowTotal)
	for _, ts := range perNode {
		slices.SortFunc(ts, func(x, y FlowTotal) int { return compareTotal(&x, &y) })
		for _, t := range ts[:min(len(ts), DefaultOverviewN)] {
			union[t.Key] = t
		}
	}
	out := make([]FlowTotal, 0, len(union))
	for _, t := range union {
		out = append(out, t)
	}
	slices.SortFunc(out, func(x, y FlowTotal) int { return compareTotal(&x, &y) })
	return out
}

func TestPipeline1000Hosts(t *testing.T) {
	prev, cur := benchSetup(1000, 10)
	got, err := runPipeline(prev, cur)
	if err != nil {
		t.Fatal(err)
	}
	want := expectedOverview(1000, 10)
	if len(got) != len(want) {
		t.Fatalf("overview has %d flows, want %d", len(got), len(want))
	}
	for i := range want {
		g := got[i]
		if g.Key != want[i].Key || g.BytesAB != want[i].BytesAB || g.BytesBA != want[i].BytesBA || g.ServerReported || g.Confirmed {
			t.Fatalf("pos %d = %+v, want %+v", i, g, want[i])
		}
	}
}

func BenchmarkPipeline1000x10(b *testing.B) {
	prev, cur := benchSetup(1000, 10)
	b.ResetTimer()
	for b.Loop() {
		if _, err := runPipeline(prev, cur); err != nil {
			b.Fatal(err)
		}
	}
}

func TestIngestBindsObservationsToReporterAddresses(t *testing.T) {
	now := t0.Add(time.Hour)
	w := Window{From: t0, To: now}
	srvObs := Observation{Key: key22, BytesAB: 10, BytesBA: 100, Connections: 1, ServerReported: true}
	cliObs := Observation{Key: key22, BytesAB: 9, BytesBA: 99, Connections: 1}
	fakeSrv := Observation{Key: key22, BytesAB: 1 << 30, BytesBA: 1 << 30, Connections: 9, ServerReported: true}
	fakeCli := Observation{Key: key22, BytesAB: 1 << 30, BytesBA: 1 << 30, Connections: 9}
	// The imposter's own flow 10.0.0.2 -> 10.0.0.9:80 is allowed.
	ownFlow := Observation{Key: FlowKey{A: addr("10.0.0.2"), B: addr("10.0.0.9"), Proto: TCP, ServerPort: 80, Server: SideB, Tier: "socket"}, BytesAB: 5}
	imposter := []netip.Addr{addr("10.0.0.9")}
	want := FlowTotal{Key: key22, BytesAB: 10, BytesBA: 100, Connections: 1, ServerReported: true, Confirmed: true}

	check := func(t *testing.T, a *Aggregator) {
		t.Helper()
		got := a.TopN(addr("10.0.0.1"), w, 10)
		if len(got) != 1 {
			t.Fatalf("TopN = %+v", got)
		}
		g := got[0]
		g.FirstSeen, g.LastSeen = time.Time{}, time.Time{}
		if g != want {
			t.Fatalf("total = %+v\nwant    %+v", g, want)
		}
	}
	ingest := func(t *testing.T, a *Aggregator, host string, own []netip.Addr, obs ...Observation) IngestResult {
		t.Helper()
		res, err := a.Ingest(report(host, t0, t0.Add(time.Minute), sortObs(obs)...), own)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	t.Run("imposter first", func(t *testing.T) {
		a := newTestAgg(now, DefaultLimits())
		res := ingest(t, a, "imposter", imposter, fakeSrv)
		if res != (IngestResult{Foreign: 1}) || a.Buckets() != 0 {
			t.Fatalf("imposter server claim: %+v, %d buckets", res, a.Buckets())
		}
		res = ingest(t, a, "imposter2", imposter, fakeCli)
		if res != (IngestResult{Foreign: 1}) || a.Buckets() != 0 {
			t.Fatalf("imposter client claim: %+v, %d buckets", res, a.Buckets())
		}
		if res := ingest(t, a, "srv", []netip.Addr{addr("10.0.0.2")}, srvObs); res != (IngestResult{Applied: 1}) {
			t.Fatalf("real server: %+v", res)
		}
		// A v4-mapped address in own matches the unmapped key.
		if res := ingest(t, a, "cli", []netip.Addr{addr("::ffff:10.0.0.1")}, cliObs); res != (IngestResult{Applied: 1}) {
			t.Fatalf("real client: %+v", res)
		}
		check(t, a)
	})
	t.Run("imposter second", func(t *testing.T) {
		a := newTestAgg(now, DefaultLimits())
		ingest(t, a, "srv", []netip.Addr{addr("10.0.0.2")}, srvObs)
		ingest(t, a, "cli", []netip.Addr{addr("10.0.0.1")}, cliObs)
		res := ingest(t, a, "imposter", imposter, fakeSrv)
		if res != (IngestResult{Foreign: 1}) {
			t.Fatalf("imposter: %+v", res)
		}
		check(t, a)
	})
	t.Run("only the foreign observations of a report are refused", func(t *testing.T) {
		a := newTestAgg(now, DefaultLimits())
		res := ingest(t, a, "imposter", []netip.Addr{addr("10.0.0.2")}, ownFlow, cliObs)
		if res != (IngestResult{Applied: 1, Foreign: 1}) {
			t.Fatalf("mixed report: %+v", res)
		}
		if got := a.TopN(addr("10.0.0.9"), w, 10); len(got) != 1 || got[0].BytesAB != 5 {
			t.Fatalf("own flow = %+v", got)
		}
		if got := a.TopN(addr("10.0.0.1"), w, 10); len(got) != 0 {
			t.Fatalf("foreign client claim was stored: %+v", got)
		}
	})
}

func TestIngestRejectsBadReporterAddresses(t *testing.T) {
	r := report("h", t0, t0, Observation{Key: key22, ServerReported: true})
	many := make([]netip.Addr, MaxHostAddrs+1)
	for i := range many {
		many[i] = netip.AddrFrom4([4]byte{10, 9, byte(i >> 8), byte(i)})
	}
	for name, own := range map[string][]netip.Addr{
		"none":        nil,
		"invalid":     {{}},
		"unspecified": {netip.IPv4Unspecified()},
		"too many":    many,
	} {
		t.Run(name, func(t *testing.T) {
			a := newTestAgg(t0.Add(time.Hour), DefaultLimits())
			if _, err := a.Ingest(r, own); !errors.Is(err, ErrInvalidReport) {
				t.Fatalf("Ingest = %v, want ErrInvalidReport", err)
			}
			if a.Buckets() != 0 || a.Reporters() != 0 {
				t.Fatal("rejected report changed state")
			}
		})
	}
}

func TestIngestSplitsIntervalsAcrossHours(t *testing.T) {
	now := t0.Add(3 * time.Hour)
	a := newTestAgg(now, DefaultLimits())
	h1, h2 := t0.Add(30*time.Minute), t0.Add(time.Hour)
	// The client reports per hour; the server's collector had a gap and
	// sends one report for 10:30..11:30.
	mustIngest(t, a, report("cli", h1, h2, Observation{Key: key22, BytesAB: 300, BytesBA: 3000}))
	mustIngest(t, a, report("cli", h2, h2.Add(30*time.Minute), Observation{Key: key22, BytesAB: 300, BytesBA: 3000}))
	res := mustIngest(t, a, report("srv", h1, h2.Add(30*time.Minute), Observation{Key: key22, BytesAB: 601, BytesBA: 6000, Connections: 1, ServerReported: true}))
	if res.Applied != 2 {
		t.Fatalf("server report parts: %+v", res)
	}
	tests := []struct {
		w      Window
		ab, ba uint64
	}{
		{Window{From: t0, To: now}, 601, 6000}, // never 300 + 601
		{Window{From: t0, To: h2}, 300, 3000},
		{Window{From: h2, To: now}, 301, 3000}, // the rounding remainder goes to the last hour
	}
	for _, tc := range tests {
		got := a.TopN(addr("10.0.0.1"), tc.w, 1)
		if len(got) != 1 || got[0].BytesAB != tc.ab || got[0].BytesBA != tc.ba || !got[0].ServerReported || !got[0].Confirmed {
			t.Errorf("window %v..%v = %+v, want %d/%d from the server", tc.w.From, tc.w.To, got, tc.ab, tc.ba)
		}
	}
	if got := a.TopN(addr("10.0.0.1"), Window{From: t0, To: now}, 1); got[0].Connections != 1 {
		t.Errorf("connections = %d, want 1", got[0].Connections)
	}

	// After a gap longer than MaxInterval the report is refused; a
	// baseline report lets the collector continue.
	long := report("srv", h2.Add(30*time.Minute), now, Observation{Key: key22, BytesAB: 1, ServerReported: true})
	if _, err := a.Ingest(long, ownOf(long)); !errors.Is(err, ErrIntervalTooLong) {
		t.Fatalf("long interval = %v, want ErrIntervalTooLong", err)
	}
	mustIngest(t, a, report("srv", now, now))
}

func TestSplitHours(t *testing.T) {
	tests := []struct {
		name     string
		from, to time.Time
		hours    []int64
	}{
		{"zero length", t0.Add(time.Minute), t0.Add(time.Minute), []int64{0}},
		{"inside one hour", t0, t0.Add(time.Minute), []int64{0}},
		{"ends on the boundary", t0.Add(59 * time.Minute), t0.Add(time.Hour), []int64{0}},
		{"zero length on the boundary", t0.Add(time.Hour), t0.Add(time.Hour), []int64{1}},
		{"spans a boundary", t0.Add(59 * time.Minute), t0.Add(61 * time.Minute), []int64{0, 1}},
		{"spans three hours", t0.Add(59 * time.Minute), t0.Add(121 * time.Minute), []int64{0, 1, 2}},
	}
	base := hourOf(t0)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parts := splitHours(tc.from, tc.to)
			if len(parts) != len(tc.hours) {
				t.Fatalf("parts = %+v", parts)
			}
			for _, v := range []uint64{0, 1, 7, 1000, math.MaxUint64} {
				var sum uint64
				for i := range parts {
					if parts[i].hour-base != tc.hours[i] {
						t.Fatalf("part %d hour %d, want %d", i, parts[i].hour-base, tc.hours[i])
					}
					sum += parts[i].share(v)
				}
				if sum != v {
					t.Fatalf("shares of %d sum to %d", v, sum)
				}
			}
		})
	}
}

func TestExpiredReportersDoNotBlockNewHosts(t *testing.T) {
	cur := t0
	l := DefaultLimits()
	l.MaxReporters = 1
	a := NewAggregator(l, func() time.Time { return cur })
	mustIngest(t, a, report("h", cur, cur, Observation{Key: key22, BytesAB: 1, ServerReported: true}))
	if _, err := a.Ingest(report("other", cur, cur), ownOf(Report{})); !errors.Is(err, ErrLimit) {
		t.Fatalf("Ingest = %v, want ErrLimit", err)
	}
	// Once h has expired, the hourly prune before the limit check frees
	// its slot without a manual Cutoff.
	cur = cur.Add(Retention + 2*time.Hour)
	mustIngest(t, a, report("other", cur, cur))
	if a.Buckets() != 0 || a.Reporters() != 1 {
		t.Fatalf("expired state kept: %d buckets, %d reporters", a.Buckets(), a.Reporters())
	}
}

// manyFlows returns n observations of distinct flows whose client end is
// client, sorted.
func manyFlows(client string, n int) []Observation {
	obs := make([]Observation, n)
	for i := range obs {
		obs[i] = Observation{Key: FlowKey{A: addr(client), B: addr("203.0.113.1"), Proto: TCP, ServerPort: uint16(1000 + i), Server: SideB, Tier: TierSocket}, BytesAB: 1}
	}
	sortObservations(obs)
	return obs
}

func TestIngestPerReporterBucketCap(t *testing.T) {
	cur := t0.Add(time.Hour)
	l := DefaultLimits()
	l.MaxBuckets = 10
	l.MaxBucketsPerReporter = 3
	a := NewAggregator(l, func() time.Time { return cur })
	noisy := manyFlows("10.0.0.1", 8)
	res := mustIngest(t, a, report("noisy", t0, t0, noisy...))
	if res.Applied != 3 || res.Capped != 5 || res.Dropped != 0 {
		t.Fatalf("noisy result %+v", res)
	}
	// The host's existing buckets still accept data.
	res = mustIngest(t, a, report("noisy", t0.Add(time.Second), t0.Add(time.Second), noisy[0]))
	if res.Applied != 1 || res.Capped != 0 {
		t.Fatalf("existing bucket refused: %+v", res)
	}
	// Another hour does not give the host more room.
	res = mustIngest(t, a, report("noisy", t0.Add(time.Hour), t0.Add(time.Hour), noisy...))
	if res.Applied != 0 || res.Capped != 8 {
		t.Fatalf("noisy second hour %+v", res)
	}
	// Other hosts still get their own buckets; nothing is evicted.
	res = mustIngest(t, a, report("quiet", t0, t0, manyFlows("10.0.0.2", 3)...))
	if res.Applied != 3 || res.Capped != 0 || res.Dropped != 0 {
		t.Fatalf("quiet result %+v", res)
	}
	if a.Buckets() != 6 || a.Capped() != 13 || a.Dropped() != 0 {
		t.Fatalf("buckets %d, capped %d, dropped %d", a.Buckets(), a.Capped(), a.Dropped())
	}
	if got := a.CappedHosts(); !slices.Equal(got, []string{"noisy"}) {
		t.Fatalf("CappedHosts = %v", got)
	}
	if got := a.TopN(addr("10.0.0.1"), Window{From: t0, To: cur.Add(time.Hour)}, 100); len(got) != 3 {
		t.Fatalf("noisy flows = %d, want 3", len(got))
	}
	// Buckets that expire give the room back.
	cur = t0.Add(Retention + time.Hour)
	res = mustIngest(t, a, report("noisy", cur, cur, noisy...))
	if res.Applied != 3 || res.Capped != 5 {
		t.Fatalf("after expiry %+v", res)
	}
}

// TestCappedMarkerExpiresWithPrunedHours pins the ADR 0009 D7 contract:
// the truncated marker of a host must reflect the data that still exists,
// so it goes away when the hours holding the capped parts are pruned.
func TestCappedMarkerExpiresWithPrunedHours(t *testing.T) {
	cur := t0
	l := DefaultLimits()
	l.MaxBuckets = 10
	l.MaxBucketsPerReporter = 3
	a := NewAggregator(l, func() time.Time { return cur })
	noisy := manyFlows("10.0.0.1", 8)
	if res := mustIngest(t, a, report("noisy", t0, t0, noisy...)); res.Applied != 3 || res.Capped != 5 {
		t.Fatalf("hour 0: %+v", res)
	}
	cur = t0.Add(time.Hour)
	if res := mustIngest(t, a, report("noisy", t0.Add(time.Hour), t0.Add(time.Hour), noisy...)); res.Applied != 0 || res.Capped != 8 {
		t.Fatalf("hour 1: %+v", res)
	}
	// Prune hour 0: its capped parts go with it, and the freed bucket
	// slots let the host report cleanly in a new hour, so it stays
	// tracked after every capped hour is gone.
	cur = t0.Add(Retention + time.Hour + 30*time.Minute)
	if res := mustIngest(t, a, report("noisy", cur, cur, noisy[:3]...)); res.Applied != 3 || res.Capped != 0 {
		t.Fatalf("after hour 0 pruned: %+v", res)
	}
	if got := a.CappedHosts(); !slices.Equal(got, []string{"noisy"}) {
		t.Fatalf("after hour 0 pruned: CappedHosts = %v, want [noisy]", got)
	}
	// Prune hour 1 as well: every capped part is gone, so is the marker.
	cur = cur.Add(time.Hour)
	mustIngest(t, a, report("quiet", cur, cur))
	if got := a.CappedHosts(); len(got) != 0 {
		t.Fatalf("after all capped hours pruned: CappedHosts = %v, want none", got)
	}
}

// TestPruneAdvancesFloorBlocksReplayAfterBackwardsClockStep pins the
// replay protection: the automatic prune removes hours and reporters, so
// it must advance the floor too; otherwise a replayed report from a
// pruned reporter is counted again after the clock steps backwards.
func TestPruneAdvancesFloorBlocksReplayAfterBackwardsClockStep(t *testing.T) {
	cur := t0
	a := NewAggregator(DefaultLimits(), func() time.Time { return cur })
	old := report("h", t0, t0.Add(time.Minute), Observation{Key: key22, BytesAB: 1, ServerReported: true})
	mustIngest(t, a, old)
	// The automatic prune removes the hour and the reporter of "h".
	cur = cur.Add(Retention + 2*time.Hour)
	mustIngest(t, a, report("other", cur, cur))
	if a.Reporters() != 1 {
		t.Fatalf("reporters = %d, want only the live one", a.Reporters())
	}
	// The clock steps backwards: the replayed report is inside the
	// stepped-back window, but its hour was pruned, so it must still be
	// refused and not counted again.
	cur = t0.Add(time.Hour)
	if _, err := a.Ingest(old, ownOf(old)); !errors.Is(err, ErrOutOfWindow) {
		t.Fatalf("replay after backwards clock step = %v, want ErrOutOfWindow", err)
	}
	// A host the aggregator has not seen cannot bring the hour back
	// either.
	late := report("late", t0, t0.Add(time.Minute), Observation{Key: key22, BytesAB: 5})
	if _, err := a.Ingest(late, ownOf(late)); !errors.Is(err, ErrOutOfWindow) {
		t.Fatalf("late report = %v, want ErrOutOfWindow", err)
	}
	if got := a.TopN(addr("10.0.0.1"), Window{From: t0, To: t0.Add(2 * time.Hour)}, 10); len(got) != 0 {
		t.Fatalf("pruned hour came back: %+v", got)
	}
}

func TestIngestPerReporterCapClampedToGlobal(t *testing.T) {
	a := NewAggregator(Limits{MaxBuckets: 2, MaxBucketsPerReporter: 100}, func() time.Time { return t0 })
	if a.limits.MaxBucketsPerReporter != 2 {
		t.Fatalf("MaxBucketsPerReporter = %d", a.limits.MaxBucketsPerReporter)
	}
	if d := NewAggregator(Limits{}, time.Now).limits; d.MaxBucketsPerReporter != DefaultMaxBucketsPerReporter || d.MaxBucketsPerReporter >= d.MaxBuckets {
		t.Fatalf("default per-reporter cap %d of %d", d.MaxBucketsPerReporter, d.MaxBuckets)
	}
}

func TestReportersKeyedByHostAcrossTiers(t *testing.T) {
	l := DefaultLimits()
	l.MaxReporters = 1
	a := newTestAgg(t0.Add(time.Hour), l)
	for _, tier := range []string{TierSocket, TierConntrack, TierSensor} {
		k := key22
		k.Tier = tier
		r := report("h", t0, t0.Add(time.Minute), Observation{Key: k, BytesAB: 1, ServerReported: true})
		r.Tier = tier
		mustIngest(t, a, r)
		// Each tier keeps its own report sequence.
		if _, err := a.Ingest(r, ownOf(r)); !errors.Is(err, ErrDuplicateReport) {
			t.Fatalf("tier %s replay = %v, want ErrDuplicateReport", tier, err)
		}
	}
	if a.Reporters() != 1 {
		t.Fatalf("reporters = %d, want 1 per host", a.Reporters())
	}
	r := report("h", t0, t0.Add(time.Minute))
	r.Tier = "invented"
	if _, err := a.Ingest(r, ownOf(r)); !errors.Is(err, ErrInvalidReport) {
		t.Fatalf("invented tier = %v, want ErrInvalidReport", err)
	}
}

func TestShortCutoffKeepsReplayProtection(t *testing.T) {
	now := t0.Add(10 * time.Hour)
	a := newTestAgg(now, DefaultLimits())
	old := report("h", t0, t0.Add(time.Minute), Observation{Key: key22, BytesAB: 1, ServerReported: true})
	mustIngest(t, a, old)
	// The admin shortens the retention to 2 hours.
	if removed := a.Cutoff(now, 2*time.Hour); removed != 1 {
		t.Fatalf("Cutoff removed %d", removed)
	}
	if a.Reporters() != 1 {
		t.Fatalf("reporter inside the ingest window was removed")
	}
	if _, err := a.Ingest(old, ownOf(old)); err == nil {
		t.Fatal("replayed report accepted after cutoff")
	}
	// A host the aggregator has not seen cannot bring the hours back either.
	late := report("late", t0.Add(time.Hour), t0.Add(time.Hour+time.Minute), Observation{Key: key22, BytesAB: 5})
	if _, err := a.Ingest(late, ownOf(late)); !errors.Is(err, ErrOutOfWindow) {
		t.Fatalf("late report = %v, want ErrOutOfWindow", err)
	}
	// A report spanning the new floor keeps only the part after it.
	span := report("span", now.Add(-2*time.Hour-30*time.Minute), now.Add(-2*time.Hour+30*time.Minute), Observation{Key: key22, BytesAB: 10})
	res := mustIngest(t, a, span)
	if res.Applied != 1 || a.Buckets() != 1 {
		t.Fatalf("spanning report %+v, buckets %d", res, a.Buckets())
	}
}

func TestMaxIntervalClampedToRetention(t *testing.T) {
	now := t0.Add(10 * time.Hour)
	a := newTestAgg(now, Limits{Retention: 2 * time.Hour, MaxInterval: 1000 * time.Hour})
	r := report("h", now.Add(-3*time.Hour), now)
	if _, err := a.Ingest(r, ownOf(r)); !errors.Is(err, ErrIntervalTooLong) {
		t.Fatalf("Ingest = %v, want ErrIntervalTooLong", err)
	}
}

// TestForwardClockJumpDoesNotLockOutReports pins the floor invariant
// for a forward clock jump larger than the retention that lasts several
// hours, with reports accepted in more than one jumped hour: once the
// clock returns, new reports are accepted again, and replays of the
// hours pruned during the jump are still refused.
func TestForwardClockJumpDoesNotLockOutReports(t *testing.T) {
	cur := t0
	a := NewAggregator(DefaultLimits(), func() time.Time { return cur })
	obs := Observation{Key: key22, BytesAB: 1, ServerReported: true}
	old := report("h", t0, t0.Add(time.Minute), obs)
	mustIngest(t, a, old)
	// The clock jumps forward by more than the retention and stays there
	// for several hours; every jumped hour accepts a report and runs the
	// automatic prune, which removes the hour of t0.
	jump := t0.Add(Retention + 24*time.Hour)
	for i := range 5 {
		cur = jump.Add(time.Duration(i) * time.Hour)
		mustIngest(t, a, report("j", cur, cur.Add(time.Minute), obs))
	}
	if f := a.floorLocked(cur); f != t0.Add(time.Hour).Unix() {
		t.Fatalf("floor during the jump = %d, want the end of the pruned hour %d", f, t0.Add(time.Hour).Unix())
	}
	// The clock returns to shortly after t0 and runs on for a few hours.
	for i := range 4 {
		cur = t0.Add(time.Duration(2+i)*time.Hour + 30*time.Minute)
		r := report(fmt.Sprintf("back%d", i), cur.Add(-time.Minute), cur, Observation{Key: key22, BytesAB: 2})
		if res := mustIngest(t, a, r); res.Applied != 1 {
			t.Fatalf("report %d after the clock returned: %+v", i, res)
		}
	}
	// Replay protection survives the jump: the pruned hour stays closed,
	// for its own host and for a host the aggregator has not seen.
	if _, err := a.Ingest(old, ownOf(old)); !errors.Is(err, ErrOutOfWindow) {
		t.Fatalf("replay after jump = %v, want ErrOutOfWindow", err)
	}
	late := report("late", t0, t0.Add(time.Minute), obs)
	if _, err := a.Ingest(late, ownOf(late)); !errors.Is(err, ErrOutOfWindow) {
		t.Fatalf("late report into the pruned hour = %v, want ErrOutOfWindow", err)
	}
	// A jump lasting longer than the retention prunes jumped hours too;
	// they lie ahead of the returned clock and must not raise its floor.
	for i := range int(Retention/time.Hour) + 3 {
		cur = jump.Add(time.Duration(i) * time.Hour)
		if _, err := a.Ingest(report("j", cur, cur.Add(time.Minute), obs), ownOf(old)); err != nil && !errors.Is(err, ErrDuplicateReport) {
			t.Fatalf("jumped report %d: %v", i, err)
		}
	}
	cur = t0.Add(8*time.Hour + 30*time.Minute)
	if res := mustIngest(t, a, report("back", cur.Add(-time.Minute), cur, Observation{Key: key22, BytesAB: 3})); res.Applied != 1 {
		t.Fatalf("after a jump longer than the retention: %+v", res)
	}
	if _, err := a.Ingest(late, ownOf(late)); !errors.Is(err, ErrOutOfWindow) {
		t.Fatalf("late report after the long jump = %v, want ErrOutOfWindow", err)
	}
}

// TestClockJumpSequence drives random forward and backward clock jumps
// against the floor invariant: a report ending in the current hour of the
// clock is always accepted, and a report into a pruned hour before the
// current one is always refused.
func TestClockJumpSequence(t *testing.T) {
	l := DefaultLimits()
	retH := int64(Retention / time.Hour)
	for seed := range uint64(4) {
		rng := rand.New(rand.NewPCG(seed, 0x7a05c))
		base := t0.Add(30 * time.Minute) // mid-hour, so [now-1m, now] is one part
		cur := base
		a := NewAggregator(l, func() time.Time { return cur })
		type sent struct {
			r    Report
			hour int64
		}
		var accepted []sent
		data := map[int64]bool{}   // model: hours holding buckets
		pruned := map[int64]bool{} // model: hours pruned so far
		prunedHour, havePruned := int64(0), false
		real, offset := int64(0), int64(0) // hours since base
		for step := range 1500 {
			real++
			switch p := rng.IntN(100); {
			case p < 3: // jump far ahead, past the retention
				offset = retH + 1 + rng.Int64N(3*retH)
			case p < 6: // small jump ahead
				offset = 1 + rng.Int64N(5)
			case p < 10: // back to the real time
				offset = 0
			}
			cur = base.Add(time.Duration(real+offset) * time.Hour)
			h := hourOf(cur)
			if !havePruned || h != prunedHour {
				cutoff := cur.Add(-Retention).Unix()
				for dh := range data {
					if (dh+1)*secondsPerHour <= cutoff {
						delete(data, dh)
						pruned[dh] = true
					}
				}
				prunedHour, havePruned = h, true
			}
			r := report(fmt.Sprintf("s%d", step), cur.Add(-time.Minute), cur, Observation{Key: key22, BytesAB: 1})
			res, err := a.Ingest(r, ownOf(r))
			// A conflict means another host already holds this flow end
			// in the hour; the part was not skipped.
			if err != nil || res.Applied+res.Conflicts != 1 {
				t.Fatalf("seed %d step %d (real %dh, offset %dh): report in the current hour: %+v, %v", seed, step, real, offset, res, err)
			}
			data[h] = true
			accepted = append(accepted, sent{r, h})
			// Replay an earlier report under a fresh host.
			old := accepted[rng.IntN(len(accepted))]
			rp := old.r
			rp.Host = fmt.Sprintf("r%d", step)
			res, err = a.Ingest(rp, ownOf(rp))
			inWindow := !rp.To.Before(cur.Add(-Retention)) && !rp.To.After(cur.Add(l.MaxClockSkew))
			if inWindow && pruned[old.hour] && old.hour < h && err == nil {
				t.Fatalf("seed %d step %d: replay into pruned hour %d accepted: %+v", seed, step, old.hour, res)
			}
			if err == nil && res.Applied+res.Conflicts > 0 {
				data[old.hour] = true
			}
		}
	}
}

// TestFloorAdvanceOnMidHourCutoffKeepsLiveData guards against an
// off-by-one-hour floor when the cutoff is not on an hour boundary: the
// automatic prune closes only the hours it removed, so a report ending in
// the partly live cutoff hour, after the cutoff, is still applied.
func TestFloorAdvanceOnMidHourCutoffKeepsLiveData(t *testing.T) {
	cur := t0.Add(-time.Hour)
	a := NewAggregator(DefaultLimits(), func() time.Time { return cur })
	obs := Observation{Key: key22, BytesAB: 1, ServerReported: true}
	mustIngest(t, a, report("h", cur, cur.Add(time.Minute), obs))
	cur = t0
	mustIngest(t, a, report("h", cur, cur.Add(time.Minute), obs))
	// The clock moves so the cutoff falls mid-hour: now-Retention is
	// t0+30min, inside the hour that starts at t0. The hour before t0 is
	// pruned, the hour of t0 is not.
	cur = t0.Add(Retention + 30*time.Minute)
	if res := mustIngest(t, a, report("h2", t0.Add(40*time.Minute), t0.Add(45*time.Minute), Observation{Key: key22, BytesAB: 2})); res.Applied != 1 {
		t.Fatalf("report in the partly live cutoff hour: %+v", res)
	}
	if f := a.floorLocked(cur); f != t0.Unix() {
		t.Fatalf("floor = %d, want %d (end of the pruned hour)", f, t0.Unix())
	}
}

// TestClosedRangesBounded pins the memory bound of the closed hours: past
// maxClosedRanges the oldest runs merge, which keeps every closed hour
// closed.
func TestClosedRangesBounded(t *testing.T) {
	a := NewAggregator(DefaultLimits(), time.Now)
	for i := range int64(3 * maxClosedRanges) {
		a.closeHoursLocked(10*i, 10*i+2)
	}
	if len(a.closed) != maxClosedRanges {
		t.Fatalf("closed runs = %d, want %d", len(a.closed), maxClosedRanges)
	}
	for i := range int64(3 * maxClosedRanges) {
		f := a.floorLocked(time.Unix((10*i+3)*secondsPerHour, 0))
		if f < (10*i+3)*secondsPerHour {
			t.Fatalf("run %d reopened: floor %d", i, f)
		}
	}
	a.closeHoursLocked(-5, 10*3*maxClosedRanges)
	if len(a.closed) != 1 {
		t.Fatalf("covering run left %d runs", len(a.closed))
	}
}
