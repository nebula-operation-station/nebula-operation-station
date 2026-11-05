// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficmap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
)

var (
	_ Flows             = (*trafficstore.Store)(nil)
	_ retentionReporter = (*trafficstore.Store)(nil)
)

var testNow = time.Date(2026, 11, 5, 12, 30, 15, 0, time.UTC)

// fakeFlows serves top sets from a fixed flow list, like the store.
type fakeFlows struct {
	flows   []flowagg.FlowTotal
	err     error
	windows []flowagg.Window
	ns      []int
	queried []netip.Addr
}

func (f *fakeFlows) TopN(_ context.Context, node netip.Addr, w flowagg.Window, n int) ([]flowagg.FlowTotal, error) {
	f.windows, f.ns = append(f.windows, w), append(f.ns, n)
	f.queried = append(f.queried, node)
	if f.err != nil {
		return nil, f.err
	}
	return f.top(node, n), nil
}

func (f *fakeFlows) top(node netip.Addr, n int) []flowagg.FlowTotal {
	var out []flowagg.FlowTotal
	for _, t := range f.flows {
		if t.Key.A == node || t.Key.B == node {
			out = append(out, t)
		}
	}
	slices.SortFunc(out, compareTotal)
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func (f *fakeFlows) OverviewUnion(_ context.Context, nodes []netip.Addr, w flowagg.Window, n int) ([]flowagg.FlowTotal, error) {
	f.windows, f.ns = append(f.windows, w), append(f.ns, n)
	f.queried = append(f.queried, nodes...)
	if f.err != nil {
		return nil, f.err
	}
	set := make(map[flowagg.FlowKey]flowagg.FlowTotal)
	for _, nd := range nodes {
		for _, t := range f.top(nd, n) {
			set[t.Key] = t
		}
	}
	var out []flowagg.FlowTotal
	for _, t := range set {
		out = append(out, t)
	}
	slices.SortFunc(out, compareTotal)
	return out, nil
}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

// flow is a TCP flow from a to b:port with the given bytes in each
// direction, in canonical key order.
func flow(a, b string, port uint16, ab, ba uint64) flowagg.FlowTotal {
	x, y := ip(a), ip(b)
	side := flowagg.SideB
	if x.Compare(y) > 0 {
		x, y, ab, ba, side = y, x, ba, ab, flowagg.SideA
	}
	return flowagg.FlowTotal{
		Key:     flowagg.FlowKey{A: x, B: y, Proto: flowagg.TCP, ServerPort: port, Server: side, Tier: flowagg.TierSocket},
		BytesAB: ab, BytesBA: ba, Connections: 1, Confirmed: true,
	}
}

func node(id, zone string, addrs ...string) NodeInput {
	n := NodeInput{ID: id, Label: id, Kind: KindHost, Zone: zone}
	for _, a := range addrs {
		n.Addrs = append(n.Addrs, ip(a))
	}
	return n
}

func newTestBuilder(t *testing.T, inv Inventory, f *fakeFlows, l Limits) *Builder {
	t.Helper()
	b, err := NewBuilder(func(context.Context) (Inventory, error) { return inv, nil }, f, func() time.Time { return testNow }, l)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func build(t *testing.T, b *Builder, q Query) (*Model, []byte) {
	t.Helper()
	data, err := b.Build(context.Background(), q)
	if err != nil {
		t.Fatalf("Build(%+v): %v", q, err)
	}
	var m Model
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return &m, data
}

func edgeSet(m *Model) []string {
	var out []string
	for _, e := range m.Edges {
		out = append(out, e.A+"-"+e.B)
	}
	slices.Sort(out)
	return out
}

func nodeIDs(m *Model) []string {
	var out []string
	for _, n := range m.Nodes {
		out = append(out, n.ID)
	}
	return out
}

// starInventory: p talks to b1..b5 (large) and q (tiny); q talks to
// c1..c5 (large). The tiny p-q flow is in neither top 5.
func starInventory() (Inventory, *fakeFlows) {
	inv := Inventory{Zones: []ZoneInput{{ID: "lan", Name: "LAN", VLAN: 10}}}
	f := &fakeFlows{}
	inv.Nodes = append(inv.Nodes, node("p", "lan", "10.0.0.1"), node("q", "lan", "10.0.0.2"))
	for i := 1; i <= 5; i++ {
		inv.Nodes = append(inv.Nodes, node(fmt.Sprintf("b%d", i), "lan", fmt.Sprintf("10.0.1.%d", i)),
			node(fmt.Sprintf("c%d", i), "lan", fmt.Sprintf("10.0.2.%d", i)))
		f.flows = append(f.flows,
			flow("10.0.0.1", fmt.Sprintf("10.0.1.%d", i), 443, uint64(1000*i), 10),
			flow("10.0.0.2", fmt.Sprintf("10.0.2.%d", i), 22, uint64(2000*i), 20))
	}
	f.flows = append(f.flows, flow("10.0.0.1", "10.0.0.2", 80, 1, 1))
	return inv, f
}

func TestOverviewIsUnionOfTopFive(t *testing.T) {
	inv, f := starInventory()
	m, _ := build(t, newTestBuilder(t, inv, f, Limits{}), Query{})
	want := []string{"b1-p", "b2-p", "b3-p", "b4-p", "b5-p", "c1-q", "c2-q", "c3-q", "c4-q", "c5-q"}
	if got := edgeSet(m); !slices.Equal(got, want) {
		t.Fatalf("edges %v, want %v", got, want)
	}
	if !slices.Equal(f.ns, []int{OverviewN}) {
		t.Fatalf("top set sizes %v", f.ns)
	}
	if len(m.Nodes) != 12 || m.Truncated || m.Focus != "" || m.Window != DefaultWindow {
		t.Fatalf("model: %d nodes, truncated %v, focus %q, window %q", len(m.Nodes), m.Truncated, m.Focus, m.Window)
	}
	if m.Edges[0].A != "c5" || m.Edges[0].B != "q" || m.Edges[0].BytesAB != 20 || m.Edges[0].BytesBA != 10000 {
		t.Fatalf("largest edge first, oriented by ID: %+v", m.Edges[0])
	}
}

func TestSmallDevicesKeepTheirLinks(t *testing.T) {
	// A big node with 8 peers: its own top 5 has 5, but each small peer's
	// top 5 contains its one link, so the union has all 8.
	inv := Inventory{}
	f := &fakeFlows{}
	inv.Nodes = append(inv.Nodes, node("big", "", "10.0.0.1"))
	for i := 1; i <= 8; i++ {
		inv.Nodes = append(inv.Nodes, node(fmt.Sprintf("s%d", i), "", fmt.Sprintf("10.0.3.%d", i)))
		f.flows = append(f.flows, flow(fmt.Sprintf("10.0.3.%d", i), "10.0.0.1", 53, uint64(i), uint64(i)))
	}
	m, _ := build(t, newTestBuilder(t, inv, f, Limits{}), Query{})
	if len(m.Edges) != 8 {
		t.Fatalf("got %d edges, want 8", len(m.Edges))
	}
}

func TestOverviewTopFiveIsPerNodeNotPerAddress(t *testing.T) {
	// "multi" has 12 addresses, each with one flow to "peer"; "peer" has
	// one address. Per address every flow is in a top 5, but per node
	// only the five largest are: neither node may contribute more.
	inv := Inventory{}
	f := &fakeFlows{}
	multi := node("multi", "")
	for i := 1; i <= 12; i++ {
		a := fmt.Sprintf("10.0.5.%d", i)
		multi.Addrs = append(multi.Addrs, ip(a))
		f.flows = append(f.flows, flow(a, "10.0.6.1", uint16(1000+i), uint64(100*i), 0))
	}
	inv.Nodes = append(inv.Nodes, multi, node("peer", "", "10.0.6.1"))
	m, _ := build(t, newTestBuilder(t, inv, f, Limits{}), Query{})
	if len(m.Edges) != 1 {
		t.Fatalf("edges %v", edgeSet(m))
	}
	e := m.Edges[0]
	if e.Connections != OverviewN || e.BytesAB+e.BytesBA != 100*(8+9+10+11+12) {
		t.Fatalf("edge %+v: want the %d largest flows only", e, OverviewN)
	}
	if m.Truncated || m.Omitted.Flows != 0 || m.UnmappedFlows != 0 {
		t.Fatalf("per-node selection counted as omitted: truncated %v omitted %+v unmapped %d", m.Truncated, m.Omitted, m.UnmappedFlows)
	}

	// A multi-homed node talking to many single-address peers: each peer
	// keeps its link (its own top 5), but the multi-homed node's own top
	// 5 over all its addresses is all it selects (the peers are outside
	// the inventory here, so only its own selection is counted).
	f = &fakeFlows{}
	multi = node("multi", "")
	for i := 1; i <= 12; i++ {
		a := fmt.Sprintf("10.0.5.%d", i)
		multi.Addrs = append(multi.Addrs, ip(a))
		f.flows = append(f.flows, flow(a, fmt.Sprintf("192.0.2.%d", i), 443, uint64(100*i), 0))
	}
	owner := make(map[netip.Addr]string)
	for _, a := range multi.Addrs {
		owner[a] = "multi"
	}
	got, err := newTestBuilder(t, Inventory{}, f, Limits{}).overviewFlows(context.Background(),
		map[string]*nodeRec{"multi": {node: Node{ID: "multi"}, addrs: multi.Addrs}},
		owner, map[string]bool{"multi": true}, flowagg.Window{From: testNow.Add(-time.Hour), To: testNow}, &Omitted{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != OverviewN {
		t.Fatalf("multi-homed node contributed %d flows, want %d", len(got), OverviewN)
	}
	for i, fl := range got {
		if want := uint64(100 * (12 - i)); fl.Total() != want {
			t.Fatalf("flow %d: %d bytes, want %d", i, fl.Total(), want)
		}
	}
}

func TestInternetPeersDoNotTruncate(t *testing.T) {
	inv, f := starInventory()
	f.flows = append(f.flows, flow("10.0.0.1", "203.0.113.7", 443, 1<<30, 1<<20), flow("10.0.2.1", "198.51.100.1", 53, 9, 9))
	m, _ := build(t, newTestBuilder(t, inv, f, Limits{}), Query{})
	if m.Truncated || m.Omitted != (Omitted{}) {
		t.Fatalf("internet peers flagged as truncation: truncated %v omitted %+v", m.Truncated, m.Omitted)
	}
	if m.UnmappedFlows != 2 {
		t.Fatalf("unmapped flows %d, want 2", m.UnmappedFlows)
	}
	m, _ = build(t, newTestBuilder(t, inv, f, Limits{}), Query{Focus: "p"})
	if m.Truncated || m.UnmappedFlows != 1 {
		t.Fatalf("focus: truncated %v omitted %+v unmapped %d", m.Truncated, m.Omitted, m.UnmappedFlows)
	}
}

func TestFocusShowsExactlyItsTopFive(t *testing.T) {
	inv := Inventory{}
	f := &fakeFlows{}
	// The focus has two addresses; its flows are spread over both.
	inv.Nodes = append(inv.Nodes, node("f", "", "10.0.0.1", "fd00::1"), node("other", "", "10.9.9.9"))
	for i := 1; i <= 8; i++ {
		v4 := fmt.Sprintf("10.0.4.%d", i)
		v6 := fmt.Sprintf("fd00::4:%d", i)
		inv.Nodes = append(inv.Nodes, node(fmt.Sprintf("n%d", i), "", v4, v6))
		if i%2 == 0 {
			f.flows = append(f.flows, flow("10.0.0.1", v4, 443, uint64(100*i), 0))
		} else {
			f.flows = append(f.flows, flow("fd00::1", v6, 443, uint64(100*i), 0))
		}
	}
	f.flows = append(f.flows, flow("10.9.9.9", "10.0.4.1", 22, 1<<40, 0))
	m, _ := build(t, newTestBuilder(t, inv, f, Limits{}), Query{Focus: "f"})
	want := []string{"f-n4", "f-n5", "f-n6", "f-n7", "f-n8"}
	if got := edgeSet(m); !slices.Equal(got, want) {
		t.Fatalf("edges %v, want %v", got, want)
	}
	if got := nodeIDs(m); !slices.Equal(got, []string{"f", "n4", "n5", "n6", "n7", "n8"}) {
		t.Fatalf("nodes %v", got)
	}
	if m.Focus != "f" || !slices.Equal(f.ns, []int{FocusN, FocusN}) {
		t.Fatalf("focus %q, n %v", m.Focus, f.ns)
	}
}

func TestWindowsSelectTheRange(t *testing.T) {
	for name, d := range map[string]time.Duration{
		"1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "21d": 21 * 24 * time.Hour, "": 24 * time.Hour,
	} {
		inv, f := starInventory()
		m, _ := build(t, newTestBuilder(t, inv, f, Limits{}), Query{Window: name})
		want := flowagg.Window{From: testNow.Add(-d).Truncate(time.Second), To: testNow}
		if len(f.windows) != 1 || !f.windows[0].From.Equal(want.From) || !f.windows[0].To.Equal(want.To) {
			t.Fatalf("window %q: queried %v, want %v", name, f.windows, want)
		}
		if m.From != want.From.Format(time.RFC3339) || m.To != want.To.Format(time.RFC3339) {
			t.Fatalf("window %q: model range %s..%s", name, m.From, m.To)
		}
	}
}

// shortFlows is a Flows that reports a shortened retention, like a store
// opened with trafficstore.NewWithRetention.
type shortFlows struct {
	*fakeFlows
	retention time.Duration
}

func (s shortFlows) Retention() time.Duration { return s.retention }

func TestWindowsRespectTheRetention(t *testing.T) {
	inv, f := starInventory()
	b := newTestBuilder(t, inv, f, Limits{Retention: 7 * 24 * time.Hour})
	if got := b.Windows(); !slices.Equal(got, []string{"1h", "24h", "7d"}) {
		t.Fatalf("windows %v", got)
	}
	if _, err := b.Build(context.Background(), Query{Window: "21d"}); !errors.Is(err, ErrBadWindow) {
		t.Fatalf("21d over a 7d retention: %v", err)
	}
	if m, _ := build(t, b, Query{Window: "7d"}); m.Window != "7d" {
		t.Fatalf("window %q", m.Window)
	}
	if len(f.windows) != 1 {
		t.Fatalf("refused window reached the store: %v", f.windows)
	}

	// The store's own retention applies without configuration, and the
	// default window falls back to the longest one allowed.
	inv, f = starInventory()
	b, err := NewBuilder(func(context.Context) (Inventory, error) { return inv, nil }, shortFlows{f, 12 * time.Hour},
		func() time.Time { return testNow }, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if got := b.Windows(); !slices.Equal(got, []string{"1h"}) {
		t.Fatalf("windows %v", got)
	}
	for _, w := range []string{"24h", "7d", "21d"} {
		if _, err := b.Build(context.Background(), Query{Window: w}); !errors.Is(err, ErrBadWindow) {
			t.Fatalf("%s over a 12h retention: %v", w, err)
		}
	}
	if m, _ := build(t, b, Query{}); m.Window != "1h" {
		t.Fatalf("default window %q, want 1h", m.Window)
	}

	for _, r := range []time.Duration{-time.Hour, 30 * time.Minute, flowagg.Retention + time.Hour} {
		if _, err := NewBuilder(func(context.Context) (Inventory, error) { return inv, nil }, f, nil, Limits{Retention: r}); err == nil {
			t.Errorf("retention %s accepted", r)
		}
	}
}

func TestInvalidQueriesAreRefused(t *testing.T) {
	inv, f := starInventory()
	b := newTestBuilder(t, inv, f, Limits{})
	tests := []struct {
		q    Query
		want error
	}{
		{Query{Window: "2h"}, ErrBadWindow},
		{Query{Window: "22d"}, ErrBadWindow},
		{Query{Window: "1H"}, ErrBadWindow},
		{Query{Focus: "../p"}, ErrBadFocus},
		{Query{Focus: "<p>"}, ErrBadFocus},
		{Query{Focus: strings.Repeat("a", MaxIDBytes+1)}, ErrBadFocus},
		{Query{Focus: "nope"}, ErrUnknownFocus},
	}
	for _, tc := range tests {
		if _, err := b.Build(context.Background(), tc.q); !errors.Is(err, tc.want) {
			t.Errorf("%+v: err %v, want %v", tc.q, err, tc.want)
		}
	}
	if len(f.windows) != 0 {
		t.Fatalf("refused queries reached the store: %v", f.windows)
	}
}

func TestEdgesRunViaTheGatewayAndZonesAggregate(t *testing.T) {
	inv := Inventory{
		Zones: []ZoneInput{
			{ID: "iot", Name: "IoT", VLAN: 30, Gateway: "router"},
			{ID: "lan", Name: "LAN", VLAN: 10, Gateway: "router"},
			{ID: "mgmt", Name: "Mgmt", VLAN: 99, Gateway: "missing"},
		},
		Nodes: []NodeInput{
			{ID: "router", Kind: KindRouter, Zone: "lan", Addrs: []netip.Addr{ip("10.0.0.254")}},
			node("cam", "iot", "10.30.0.5"), node("nas", "lan", "10.0.0.5"), node("pc", "lan", "10.0.0.6"),
		},
	}
	f := &fakeFlows{flows: []flowagg.FlowTotal{
		flow("10.30.0.5", "10.0.0.5", 445, 700, 30),
		flow("10.0.0.6", "10.0.0.5", 445, 50, 5),
		flow("10.30.0.5", "10.0.0.254", 53, 3, 4),
	}}
	m, _ := build(t, newTestBuilder(t, inv, f, Limits{}), Query{})
	for _, e := range m.Edges {
		switch e.A + "-" + e.B {
		case "cam-nas":
			if !slices.Equal(e.Via, []string{"router"}) || e.BytesAB != 700 || e.BytesBA != 30 {
				t.Errorf("cam-nas: %+v", e)
			}
			if !slices.Equal(e.Services, []Service{{Proto: "tcp", Port: 445}}) {
				t.Errorf("services %+v", e.Services)
			}
		case "nas-pc", "cam-router":
			if len(e.Via) != 0 {
				t.Errorf("%s-%s via %v", e.A, e.B, e.Via)
			}
		default:
			t.Errorf("unexpected edge %s-%s", e.A, e.B)
		}
	}
	if len(m.ZoneLinks) != 1 {
		t.Fatalf("zone links %+v", m.ZoneLinks)
	}
	l := m.ZoneLinks[0]
	if l.A != "iot" || l.B != "lan" || l.BytesAB != 703 || l.BytesBA != 34 || l.Flows != 2 || !slices.Equal(l.Via, []string{"router"}) {
		t.Fatalf("zone link %+v", l)
	}
	for _, z := range m.Zones {
		if z.ID == "mgmt" && z.Gateway != "" {
			t.Fatalf("dangling gateway %q", z.Gateway)
		}
		if z.ID == "lan" && (z.Nodes != 3 || *z.VLAN != 10) {
			t.Fatalf("lan zone %+v", z)
		}
	}
	// Focus on the camera keeps the hop node.
	m, _ = build(t, newTestBuilder(t, inv, f, Limits{}), Query{Focus: "cam"})
	if got := nodeIDs(m); !slices.Equal(got, []string{"cam", "nas", "router"}) {
		t.Fatalf("focus nodes %v", got)
	}
}

func TestNodeAndEdgeCapsSetTruncated(t *testing.T) {
	inv, f := starInventory()
	inv.Zones[0].Gateway = "q"
	m, _ := build(t, newTestBuilder(t, inv, f, Limits{Nodes: 3}), Query{})
	if len(m.Nodes) != 3 || !m.Truncated || m.Omitted.Nodes != 9 {
		t.Fatalf("nodes %v truncated %v omitted %+v", nodeIDs(m), m.Truncated, m.Omitted)
	}
	if !slices.Contains(nodeIDs(m), "q") {
		t.Fatalf("gateway dropped by the node cap: %v", nodeIDs(m))
	}
	if m.Omitted.Flows == 0 {
		t.Fatal("flows to capped nodes not counted")
	}
	for _, e := range m.Edges {
		if !slices.Contains(nodeIDs(m), e.A) || !slices.Contains(nodeIDs(m), e.B) {
			t.Fatalf("edge to a node outside the model: %+v", e)
		}
	}

	inv, f = starInventory()
	m, _ = build(t, newTestBuilder(t, inv, f, Limits{Edges: 2}), Query{})
	if got := edgeSet(m); !slices.Equal(got, []string{"c4-q", "c5-q"}) || !m.Truncated || m.Omitted.Edges != 8 {
		t.Fatalf("edges %v truncated %v omitted %+v", got, m.Truncated, m.Omitted)
	}
}

func TestResponseSizeCapIsEnforced(t *testing.T) {
	inv, f := starInventory()
	for i := range inv.Nodes {
		inv.Nodes[i].Label = strings.Repeat("x", 4*MaxLabelBytes)
		for k := 0; k < 40; k++ {
			inv.Nodes[i].Software = append(inv.Nodes[i].Software, Software{Key: fmt.Sprintf("sw%d", k), Count: 1, Icon: strings.Repeat("a", 64)})
		}
	}
	full, fullData := build(t, newTestBuilder(t, inv, f, Limits{}), Query{})
	if !full.Truncated || full.Omitted.Software != 12*(40-MaxSoftwarePerNode) || len(full.Nodes[0].Software) != MaxSoftwarePerNode ||
		!full.Nodes[0].SoftwareCut || !full.Nodes[0].LabelCut || len(full.Nodes[0].Label) != MaxLabelBytes {
		t.Fatalf("per-node caps: truncated %v omitted %+v node %+v", full.Truncated, full.Omitted, full.Nodes[0])
	}
	for _, cap := range []int{len(fullData) - 1, len(fullData) / 2, len(fullData) / 8, 3000} {
		b := newTestBuilder(t, inv, f, Limits{ResponseBytes: cap})
		m, data := build(t, b, Query{})
		if len(data) > cap || !m.Truncated {
			t.Fatalf("cap %d: %d bytes, truncated %v", cap, len(data), m.Truncated)
		}
		if m.Omitted.Edges+m.Omitted.Nodes == 0 {
			t.Fatalf("cap %d: nothing counted as omitted", cap)
		}
	}
	m, data := build(t, newTestBuilder(t, inv, f, Limits{ResponseBytes: 3000}), Query{Focus: "p"})
	if len(data) > 3000 || !slices.Contains(nodeIDs(m), "p") {
		t.Fatalf("focus under cap: %d bytes, nodes %v", len(data), nodeIDs(m))
	}
	if _, err := newTestBuilder(t, inv, f, Limits{ResponseBytes: 100}).Build(context.Background(), Query{}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("tiny cap: %v", err)
	}
}

func TestLimitsCannotRaiseCaps(t *testing.T) {
	inv := func(context.Context) (Inventory, error) { return Inventory{}, nil }
	for _, l := range []Limits{{Nodes: MaxNodes + 1}, {Edges: MaxEdges + 1}, {ResponseBytes: MaxResponseBytes + 1}, {Nodes: -1}} {
		if _, err := NewBuilder(inv, &fakeFlows{}, nil, l); err == nil {
			t.Errorf("limits %+v accepted", l)
		}
	}
	if _, err := NewBuilder(nil, &fakeFlows{}, nil, Limits{}); err == nil {
		t.Error("nil inventory accepted")
	}
	if _, err := NewBuilder(inv, nil, nil, Limits{}); err == nil {
		t.Error("nil flows accepted")
	}
}

func TestHostileInventoryIsCleaned(t *testing.T) {
	hostile := "<img src=x onerror=alert(1)>\xe2\x80\xae\x00\x1b]8;;http://evil\x07 \xff"
	pct := 250.0
	inv := Inventory{
		Zones: []ZoneInput{{ID: "lan", Name: hostile, VLAN: 9999}, {ID: "lan", Name: "dup"}, {ID: "bad zone"}},
		Nodes: []NodeInput{
			{ID: "h1", Label: hostile, Kind: "<script>", Zone: "lan", VLAN: -1, Addrs: []netip.Addr{ip("10.0.0.1"), ip("127.0.0.1"), {}},
				Health: Health{DiskUsedPct: &pct},
				Software: []Software{
					{Key: "postgres", Count: 2, Icon: "https://evil.example/x.svg"},
					{Key: "postgres", Count: 3},
					{Key: "<b>", Count: 1}, {Key: "nginx", Count: -5},
				}},
			{ID: "h2", Label: "", Zone: "nowhere", Addrs: []netip.Addr{ip("10.0.0.2")}},
			// Two nodes with one ID: neither is trusted.
			{ID: "twin", Label: "real", Addrs: []netip.Addr{ip("10.0.0.3")}},
			{ID: "twin", Label: "fake", Addrs: []netip.Addr{ip("10.0.0.4")}},
			// Two nodes claim one address: flows to it map to neither.
			{ID: "liar", Addrs: []netip.Addr{ip("10.0.0.2"), ip("10.0.0.5")}},
			{ID: "x/../y", Label: "bad id"},
		},
	}
	f := &fakeFlows{flows: []flowagg.FlowTotal{
		flow("10.0.0.1", "10.0.0.2", 443, 10, 10),
		flow("10.0.0.1", "10.0.0.5", 443, 5, 5),
		flow("10.0.0.1", "10.0.0.3", 443, 1, 1),
	}}
	m, data := build(t, newTestBuilder(t, inv, f, Limits{}), Query{})
	if strings.ContainsAny(string(data), "<>") {
		t.Fatalf("raw angle brackets in JSON: %s", data)
	}
	if got := nodeIDs(m); !slices.Equal(got, []string{"h1", "h2", "liar"}) {
		t.Fatalf("nodes %v", got)
	}
	h1 := m.Nodes[0]
	for _, s := range []string{h1.Label, m.Zones[0].Name} {
		for _, r := range s {
			if !unicode.IsPrint(r) {
				t.Fatalf("non-printable %U in %q", r, s)
			}
		}
	}
	if h1.Kind != KindUnknown || h1.VLAN != nil || h1.Health.DiskUsedPct != nil || m.Zones[0].VLAN != nil {
		t.Fatalf("h1 %+v zone %+v", h1, m.Zones[0])
	}
	if len(h1.Software) != 1 || h1.Software[0] != (Software{Key: "postgres", Count: 5}) {
		t.Fatalf("software %+v", h1.Software)
	}
	if h2 := m.Nodes[1]; h2.Label != "h2" || h2.Zone != "" {
		t.Fatalf("h2 %+v", h2)
	}
	if got := edgeSet(m); !slices.Equal(got, []string{"h1-liar"}) {
		t.Fatalf("edges %v", got)
	}
	want := Omitted{Zones: 2, Nodes: 3, Software: 2, Addresses: 3}
	if m.Omitted != want || !m.Truncated || m.UnmappedFlows != 2 {
		t.Fatalf("omitted %+v, want %+v, unmapped %d", m.Omitted, want, m.UnmappedFlows)
	}
	if len(m.Zones) != 1 || m.Zones[0].Name == "dup" {
		t.Fatalf("zones %+v", m.Zones)
	}
}

func TestModelCarriesNoRawFlows(t *testing.T) {
	inv, f := starInventory()
	_, data := build(t, newTestBuilder(t, inv, f, Limits{}), Query{})
	if strings.Contains(string(data), "10.0.") {
		t.Fatal("addresses in the model")
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	keys := func(v any) []string {
		var out []string
		for k := range v.(map[string]any) {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	if got := keys(raw); !slices.Equal(got, []string{"edges", "from", "lower_bound", "nodes", "omitted", "to", "truncated", "unmapped_flows", "window", "zone_links", "zones"}) {
		t.Fatalf("top-level keys %v", got)
	}
	edge := raw["edges"].([]any)[0]
	if got := keys(edge); !slices.Equal(got, []string{"a", "b", "bytes_ab", "bytes_ba", "confirmed", "connections", "lower_bound", "services", "via"}) {
		t.Fatalf("edge keys %v", got)
	}
	// Unknown health and resources are null, not absent and not zero.
	n := raw["nodes"].([]any)[0].(map[string]any)
	for _, k := range []string{"patches", "reachable", "host_key_mismatch", "backup_fresh", "failed_units", "disk_used_pct", "load"} {
		v, ok := n["health"].(map[string]any)[k]
		if !ok || v != nil {
			t.Fatalf("health %s = %v, %v", k, v, ok)
		}
	}
	for _, k := range []string{"vcpu", "ram_mib", "gpus"} {
		if v, ok := n["resources"].(map[string]any)[k]; !ok || v != nil {
			t.Fatalf("resources %s = %v, %v", k, v, ok)
		}
	}
}

func TestCountersAreExactJSONIntegers(t *testing.T) {
	inv := Inventory{Nodes: []NodeInput{node("a", "", "10.0.0.1"), node("b", "", "10.0.0.2")}}
	big := flow("10.0.0.1", "10.0.0.2", 443, math.MaxUint64, math.MaxUint64)
	big.Connections, big.LowerBound = math.MaxUint64, true
	f := &fakeFlows{flows: []flowagg.FlowTotal{big}}
	m, _ := build(t, newTestBuilder(t, inv, f, Limits{}), Query{})
	e := m.Edges[0]
	if e.BytesAB != maxJSONInt || e.BytesBA != maxJSONInt || e.Connections != maxJSONInt || !e.LowerBound || !m.LowerBound {
		t.Fatalf("edge %+v lower bound %v", e, m.LowerBound)
	}
}

func TestStoreAndInventoryErrorsPropagate(t *testing.T) {
	boom := errors.New("boom")
	inv, f := starInventory()
	f.err = boom
	b := newTestBuilder(t, inv, f, Limits{})
	for _, q := range []Query{{}, {Focus: "p"}} {
		if _, err := b.Build(context.Background(), q); !errors.Is(err, boom) {
			t.Fatalf("%+v: %v", q, err)
		}
	}
	b, _ = NewBuilder(func(context.Context) (Inventory, error) { return Inventory{}, boom }, &fakeFlows{}, nil, Limits{})
	if _, err := b.Build(context.Background(), Query{}); !errors.Is(err, boom) {
		t.Fatalf("inventory: %v", err)
	}
}

func TestEmptyInventoryGivesEmptyArrays(t *testing.T) {
	f := &fakeFlows{}
	_, data := build(t, newTestBuilder(t, Inventory{}, f, Limits{}), Query{})
	for _, k := range []string{`"zones":[]`, `"nodes":[]`, `"edges":[]`, `"zone_links":[]`, `"truncated":false`} {
		if !strings.Contains(string(data), k) {
			t.Fatalf("%s missing in %s", k, data)
		}
	}
	if len(f.windows) != 0 {
		t.Fatal("store queried without addresses")
	}
}
