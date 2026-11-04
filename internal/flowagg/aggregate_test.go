// SPDX-License-Identifier: AGPL-3.0-or-later

package flowagg

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
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

func mustIngest(t *testing.T, a *Aggregator, r Report) IngestResult {
	t.Helper()
	res, err := a.Ingest(r)
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
			name: "second host claiming the same server side is ignored",
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
		if _, err := a.Ingest(r); !errors.Is(err, ErrDuplicateReport) {
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
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := newTestAgg(now, DefaultLimits())
			if _, err := a.Ingest(tc.r); !errors.Is(err, tc.want) {
				t.Fatalf("Ingest = %v, want %v", err, tc.want)
			}
			if a.Buckets() != 0 {
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
	if _, err := a.Ingest(report("h2", t0, t0)); !errors.Is(err, ErrLimit) {
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
		mustIngest(t, a, r)
	}
	got := a.TopN(addr("2001:db8::20"), Window{From: t0, To: now}, 5)
	want := FlowTotal{Key: FlowKey{A: addr("2001:db8::10"), B: addr("2001:db8::20"), Proto: TCP, ServerPort: 8006, Server: SideA, Tier: "socket"},
		BytesAB: 3000, BytesBA: 300, Connections: 1, ServerReported: true, Confirmed: true}
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
func runPipeline(prev, cur []*Snapshot) (int, error) {
	a := NewAggregator(DefaultLimits(), func() time.Time { return t0.Add(time.Hour) })
	nodes := make([]netip.Addr, 0, len(cur))
	for i := range cur {
		r, err := Observe(prev[i], cur[i])
		if err != nil {
			return 0, err
		}
		if _, err := a.Ingest(r); err != nil {
			return 0, err
		}
		nodes = append(nodes, cur[i].Sockets[0].Local.Addr())
	}
	return len(a.OverviewUnion(nodes, Window{From: t0, To: t0.Add(time.Hour)}, DefaultOverviewN)), nil
}

func TestPipeline1000Hosts(t *testing.T) {
	prev, cur := benchSetup(1000, 10)
	n, err := runPipeline(prev, cur)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 || n > 1000*DefaultOverviewN {
		t.Fatalf("overview has %d flows", n)
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
