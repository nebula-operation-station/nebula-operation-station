// SPDX-License-Identifier: AGPL-3.0-or-later

package sources

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/attackpath"
	"github.com/nebula-operation-station/nebula-operation-station/internal/flowagg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/inventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/trafficstore"
)

var fixedNow = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

// fakeFlows is a fixture flow store: it returns every flow touching a
// queried address, like OverviewUnion, and records the queries.
type fakeFlows struct {
	flows   []flowagg.FlowTotal
	err     error
	windows []flowagg.Window
	calls   [][]netip.Addr
}

func (f *fakeFlows) OverviewUnion(_ context.Context, nodes []netip.Addr, w flowagg.Window, n int) ([]flowagg.FlowTotal, error) {
	f.windows = append(f.windows, w)
	f.calls = append(f.calls, slices.Clone(nodes))
	if f.err != nil {
		return nil, f.err
	}
	if len(nodes) > trafficstore.MaxOverviewNodes || n > trafficstore.MaxTopN {
		return nil, trafficstore.ErrInvalidQuery
	}
	var out []flowagg.FlowTotal
	for _, fl := range f.flows {
		if slices.Contains(nodes, fl.Key.A) || slices.Contains(nodes, fl.Key.B) {
			out = append(out, fl)
		}
	}
	return out, nil
}

// flow builds a canonical flow from client to server.
func flow(client, server string, proto flowagg.Proto, port uint16) flowagg.FlowTotal {
	c, s := netip.MustParseAddr(client), netip.MustParseAddr(server)
	k := flowagg.FlowKey{A: c, B: s, Proto: proto, ServerPort: port, Server: flowagg.SideB}
	if s.Less(c) {
		k = flowagg.FlowKey{A: s, B: c, Proto: proto, ServerPort: port, Server: flowagg.SideA}
	}
	return flowagg.FlowTotal{Key: k, BytesAB: 1}
}

func owner(addr, id string, kind attackpath.NodeKind) AddressOwner {
	return AddressOwner{Addr: netip.MustParseAddr(addr), NodeID: id, Kind: kind}
}

func labFlowConfig(r FlowReader) FlowConfig {
	return FlowConfig{
		Reader: r,
		Hosts:  inventoryOf("web", "nas", "exec", "quiet"),
		Owners: []AddressOwner{
			owner("10.0.0.10", "host:web", attackpath.NodeHost),
			owner("10.0.0.20", "host:nas", attackpath.NodeHost),
			owner("10.0.0.30", "host:exec", attackpath.NodeHost),
			owner("10.0.0.40", "host:quiet", attackpath.NodeHost),
		},
		NetBird: []netip.Prefix{netip.MustParsePrefix("100.100.0.0/16")},
		Now:     func() time.Time { return fixedNow },
		TopN:    3,
	}
}

func labFlows() *fakeFlows {
	return &fakeFlows{flows: []flowagg.FlowTotal{
		flow("203.0.113.5", "10.0.0.10", flowagg.TCP, 443),  // internet -> web
		flow("100.100.1.1", "10.0.0.30", flowagg.TCP, 22),   // netbird -> exec
		flow("10.0.0.10", "10.0.0.20", flowagg.TCP, 445),    // web -> nas
		flow("192.168.5.5", "10.0.0.20", flowagg.UDP, 53),   // unmanaged -> nas
		flow("10.0.0.20", "203.0.113.9", flowagg.TCP, 443),  // nas -> internet: outbound, skipped
		flow("10.0.0.30", "10.0.0.10", flowagg.TCP, 22),     // exec -> web
		flow("100.64.0.7", "10.0.0.20", flowagg.TCP, 2049),  // CGNAT outside NetBird: unmanaged
		flow("10.0.0.10", "10.0.0.20", flowagg.Proto(1), 1), // icmp-like: invalid
	}}
}

func TestFlowsMapEndsToEntriesManagedAndUnmanaged(t *testing.T) {
	ff := labFlows()
	r, err := Flows(context.Background(), labFlowConfig(ff))
	if err != nil {
		t.Fatal(err)
	}
	obs := attackpath.EdgeNetworkObserved
	want := []attackpath.Edge{
		{From: "host:exec", To: "host:web", Kind: obs, Proto: attackpath.ProtoTCP, Port: 22},
		{From: "host:web", To: "host:nas", Kind: obs, Proto: attackpath.ProtoTCP, Port: 445},
		{From: "internet", To: "host:web", Kind: obs, Proto: attackpath.ProtoTCP, Port: 443},
		{From: "netbird", To: "host:exec", Kind: obs, Proto: attackpath.ProtoTCP, Port: 22},
		{From: "unk:100.64.0.7", To: "host:nas", Kind: obs, Proto: attackpath.ProtoTCP, Port: 2049},
		{From: "unk:192.168.5.5", To: "host:nas", Kind: obs, Proto: attackpath.ProtoUDP, Port: 53},
	}
	if !slices.Equal(r.Edges, want) {
		t.Fatalf("edges\n got %v\nwant %v", r.Edges, want)
	}
	for _, u := range []Uncertainty{
		{SourceFlows, UncertainUnmanagedEndpoint, "unk:192.168.5.5"},
		{SourceFlows, UncertainUnmanagedEndpoint, "unk:100.64.0.7"},
		{SourceFlows, UncertainNoFlows, "host:quiet"},
		{SourceFlows, UncertainFlowsIncomplete, "host:nas"},
		{SourceFlows, UncertainInvalidRecord, ""},
	} {
		if !slices.Contains(r.Uncertain, u) {
			t.Errorf("missing uncertainty %s in %v", u, r.Uncertain)
		}
	}
	if r.Status != StatusPartial {
		t.Fatalf("status %s", r.Status)
	}
	// web: 3 flows hits the top-3 cut as well; exec: 2 flows; quiet: none.
	if r.Coverage != (Coverage{Covered: 1, Total: 4}) {
		t.Fatalf("coverage %+v", r.Coverage)
	}
	if len(ff.windows) != 1 || !ff.windows[0].To.Equal(fixedNow) || !ff.windows[0].From.Equal(fixedNow.Add(-DefaultFlowLookback)) {
		t.Fatalf("window %v", ff.windows)
	}
}

func TestFlowsClientGuessedOutboundIsUncertain(t *testing.T) {
	for name, c := range map[string]struct {
		serverReported, uncertain bool
	}{
		"client guessed":  {false, true},
		"server reported": {true, false},
	} {
		f := flow("10.0.0.20", "203.0.113.9", flowagg.TCP, 443) // nas -> internet
		f.ServerReported = c.serverReported
		r, err := Flows(context.Background(), labFlowConfig(&fakeFlows{flows: []flowagg.FlowTotal{f}}))
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Edges) != 0 {
			t.Fatalf("%s: outbound flow became an edge: %v", name, r.Edges)
		}
		if got := hasUncertainty(r.Uncertain, UncertainDirectionUnverified, "host:nas"); got != c.uncertain {
			t.Fatalf("%s: direction_unverified = %v, want %v: %v", name, got, c.uncertain, r.Uncertain)
		}
		if c.uncertain && r.Status != StatusPartial {
			t.Fatalf("%s: status %s", name, r.Status)
		}
	}
}

func TestFlowsReadErrorIsUnknownNotEmpty(t *testing.T) {
	ff := &fakeFlows{err: errors.New("disk")}
	r, err := Flows(context.Background(), labFlowConfig(ff))
	if !errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf("err %v", err)
	}
	if r.Status != StatusUnknown || len(r.Edges) != 0 || len(r.Nodes) != 0 || r.Coverage.Covered != 0 {
		t.Fatalf("result %+v", r)
	}
	if _, err := Flows(context.Background(), FlowConfig{}); !errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf("nil reader: %v", err)
	}
}

func TestFlowsAmbiguousAddressIsNotAttributed(t *testing.T) {
	cfg := labFlowConfig(labFlows())
	cfg.Owners = append(cfg.Owners, owner("10.0.0.10", "ctr:web/abc", attackpath.NodeContainer))
	r, err := Flows(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range r.Edges {
		if e.To == "host:web" || e.From == "host:web" {
			t.Fatalf("ambiguous address attributed: %v", e)
		}
	}
	for _, id := range []string{"host:web", "ctr:web/abc"} {
		if !hasUncertainty(r.Uncertain, UncertainAmbiguousAddress, id) {
			t.Fatalf("missing ambiguity for %s: %v", id, r.Uncertain)
		}
	}
}

func TestFlowsRejectInvalidOwners(t *testing.T) {
	for name, o := range map[string]AddressOwner{
		"kind namespace": owner("10.0.0.50", "unk:x", attackpath.NodeHost),
		"unmanaged kind": owner("10.0.0.50", "unk:x", attackpath.NodeUnmanaged),
		"bad id":         owner("10.0.0.50", "host:a b", attackpath.NodeHost),
		"empty id":       owner("10.0.0.50", "host:", attackpath.NodeHost),
		"loopback":       owner("127.0.0.1", "host:lo", attackpath.NodeHost),
		"invalid addr":   {NodeID: "host:z", Kind: attackpath.NodeHost},
	} {
		r, err := Flows(context.Background(), FlowConfig{Reader: &fakeFlows{}, Hosts: fakeHosts{}, Owners: []AddressOwner{o}, Now: func() time.Time { return fixedNow }})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(r.Nodes) != 0 || !hasUncertainty(r.Uncertain, UncertainInvalidRecord, "") || r.Status != StatusPartial {
			t.Fatalf("%s: %+v", name, r)
		}
	}
}

func TestFlowsChunkQueriesByStoreLimit(t *testing.T) {
	var owners []AddressOwner
	for i := range trafficstore.MaxOverviewNodes + 10 {
		a := netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)})
		id, _ := nodeID("host:", "h"+a.String())
		owners = append(owners, AddressOwner{Addr: a, NodeID: id, Kind: attackpath.NodeHost})
	}
	ff := &fakeFlows{}
	r, err := Flows(context.Background(), FlowConfig{Reader: ff, Hosts: fakeHosts{}, Owners: owners, Now: func() time.Time { return fixedNow }})
	if err != nil {
		t.Fatal(err)
	}
	if len(ff.calls) != 2 || len(ff.calls[0]) != trafficstore.MaxOverviewNodes || len(ff.calls[1]) != 10 {
		t.Fatalf("calls %d", len(ff.calls))
	}
	if r.Coverage != (Coverage{Covered: 0, Total: len(owners)}) || r.Status != StatusPartial {
		t.Fatalf("coverage %+v status %s", r.Coverage, r.Status)
	}
}

func TestFlowsSelfFlowAndIPv4MappedOwner(t *testing.T) {
	cfg := FlowConfig{
		Reader: &fakeFlows{flows: []flowagg.FlowTotal{flow("10.0.0.10", "10.0.0.11", flowagg.TCP, 80)}},
		Hosts:  inventoryOf("web"),
		Owners: []AddressOwner{
			owner("::ffff:10.0.0.10", "host:web", attackpath.NodeHost),
			owner("10.0.0.11", "host:web", attackpath.NodeHost),
		},
		Now: func() time.Time { return fixedNow },
	}
	r, err := Flows(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Edges) != 0 || r.Coverage != (Coverage{Covered: 2, Total: 2}) {
		t.Fatalf("edges %v coverage %+v", r.Edges, r.Coverage)
	}
}

// inventoryOf returns a fixture inventory of the managed hosts ids.
func inventoryOf(ids ...string) fakeHosts {
	var hs []inventory.Host
	for _, id := range ids {
		hs = append(hs, inventory.Host{ID: id})
	}
	return fakeHosts{hosts: hs}
}

func TestFlowsManagedNodeWithoutAddressIsUncertain(t *testing.T) {
	cfg := labFlowConfig(labFlows())
	// hv1 is a managed host without an owner address; it is PVE node
	// pve1. Guest 101 and PVE node pve2 have no address either. Guest
	// 100 is host web, which has one.
	cfg.Hosts = inventoryOf("web", "nas", "exec", "quiet", "hv1")
	cfg.Managed = []string{"guest:lab/100", "guest:lab/101", "pve:lab/pve1", "pve:lab/pve2"}
	cfg.Aliases = map[string]string{"host:hv1": "pve:lab/pve1", "host:web": "guest:lab/100"}
	r, err := Flows(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"guest:lab/101", "pve:lab/pve1", "pve:lab/pve2", "host:quiet"} {
		if !hasUncertainty(r.Uncertain, UncertainNoFlows, id) {
			t.Errorf("no_flows_observed %s missing in %v", id, r.Uncertain)
		}
	}
	for _, id := range []string{"host:hv1", "guest:lab/100", "host:web"} {
		if hasUncertainty(r.Uncertain, UncertainNoFlows, id) {
			t.Errorf("no_flows_observed %s: %v", id, r.Uncertain)
		}
	}
	// 4 owner addresses (1 covered) and 3 managed nodes without one.
	if r.Status != StatusPartial || r.Coverage != (Coverage{Covered: 1, Total: 7}) {
		t.Fatalf("status %s coverage %+v", r.Status, r.Coverage)
	}
}

func TestFlowsEmptyOwnersWithManagedHostsIsNotComplete(t *testing.T) {
	// No owner address at all: every managed node is unknown, never a
	// complete source with nothing to cover.
	cfg := FlowConfig{Reader: &fakeFlows{}, Hosts: inventoryOf("a", "b"), Managed: []string{"guest:r/1"},
		Now: func() time.Time { return fixedNow }}
	r, err := Flows(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status == StatusComplete || r.Coverage != (Coverage{Covered: 0, Total: 3}) {
		t.Fatalf("status %s coverage %+v", r.Status, r.Coverage)
	}
	for _, id := range []string{"host:a", "host:b", "guest:r/1"} {
		if !hasUncertainty(r.Uncertain, UncertainNoFlows, id) {
			t.Errorf("no_flows_observed %s missing in %v", id, r.Uncertain)
		}
	}
}

func TestFlowsEveryManagedNodeCoveredIsComplete(t *testing.T) {
	cfg := FlowConfig{
		Reader: &fakeFlows{flows: []flowagg.FlowTotal{
			flow("10.0.0.10", "10.0.0.11", flowagg.TCP, 22),
			flow("10.0.0.11", "10.0.0.12", flowagg.TCP, 22),
		}},
		Hosts:   inventoryOf("a", "b"),
		Managed: []string{"guest:r/1", "pve:r/n1"},
		Aliases: map[string]string{"host:b": "guest:r/1"},
		Owners: []AddressOwner{
			owner("10.0.0.10", "host:a", attackpath.NodeHost),
			owner("10.0.0.11", "guest:r/1", attackpath.NodeGuest),
			owner("10.0.0.12", "pve:r/n1", attackpath.NodePVENode),
		},
		Now: func() time.Time { return fixedNow },
	}
	r, err := Flows(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != StatusComplete || len(r.Uncertain) != 0 || r.Coverage != (Coverage{Covered: 3, Total: 3}) {
		t.Fatalf("status %s uncertain %v coverage %+v", r.Status, r.Uncertain, r.Coverage)
	}
}

func TestFlowsRejectInvalidManagedNodes(t *testing.T) {
	for _, id := range []string{"unk:x", "ctr:a/bbbbbbbbbbbb", "guest:a b", "pve:", "internet", ""} {
		cfg := FlowConfig{Reader: &fakeFlows{}, Hosts: fakeHosts{}, Managed: []string{id}, Now: func() time.Time { return fixedNow }}
		r, err := Flows(context.Background(), cfg)
		if err != nil {
			t.Fatalf("%q: %v", id, err)
		}
		if !hasUncertainty(r.Uncertain, UncertainInvalidRecord, "") || r.Status != StatusPartial || r.Coverage.Total != 0 {
			t.Fatalf("%q: %+v", id, r)
		}
	}
	// A bad alias target is not used as a subject.
	cfg := FlowConfig{Reader: &fakeFlows{}, Hosts: inventoryOf("a"), Aliases: map[string]string{"host:a": "guest:a b"},
		Now: func() time.Time { return fixedNow }}
	r, err := Flows(context.Background(), cfg)
	if err != nil || !hasUncertainty(r.Uncertain, UncertainNoFlows, "host:a") {
		t.Fatalf("bad alias: %v %v", err, r.Uncertain)
	}
}

func TestFlowsHostListErrorIsUnknown(t *testing.T) {
	cfg := labFlowConfig(labFlows())
	cfg.Hosts = fakeHosts{err: errors.New("db")}
	r, err := Flows(context.Background(), cfg)
	if !errors.Is(err, ErrSourceUnavailable) || r.Status != StatusUnknown || len(r.Nodes) != 0 {
		t.Fatalf("err %v result %+v", err, r)
	}
	cfg.Hosts = nil
	if _, err := Flows(context.Background(), cfg); !errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf("no host lister: %v", err)
	}
}

func TestManagedNodesListsHostsGuestsAndPVENodes(t *testing.T) {
	r := Result{Nodes: []attackpath.Node{
		{ID: "pve:r/n1", Kind: attackpath.NodePVENode},
		{ID: "guest:r/1", Kind: attackpath.NodeGuest},
		{ID: "ctr:h/aaaaaaaaaaaa", Kind: attackpath.NodeContainer},
		{ID: "unk:10.0.0.1", Kind: attackpath.NodeUnmanaged},
		{ID: "host:a", Kind: attackpath.NodeHost},
	}}
	if got, want := ManagedNodes(r), []string{"guest:r/1", "host:a", "pve:r/n1"}; !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}
