// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// memInventory is an imported PVE inventory of remote proxmoxbai (the web
// UI adapts the real pveinventory store; ui tests cover that adapter).
type memInventory struct {
	remote string
	nodes  []string
	guests []TelemetryGuest
	err    error
	calls  int
}

func (m *memInventory) HasRemote(_ context.Context, id string) (bool, error) {
	m.calls++
	return id == m.remote, m.err
}

func (m *memInventory) HasNode(_ context.Context, id, node string) (bool, error) {
	m.calls++
	return id == m.remote && slices.Contains(m.nodes, node), m.err
}

func (m *memInventory) ActiveGuests(_ context.Context, id string, vmid uint64, limit int) ([]TelemetryGuest, error) {
	m.calls++
	var out []TelemetryGuest
	for _, g := range m.guests {
		if id == m.remote && g.VMID == vmid && len(out) < limit {
			out = append(out, g)
		}
	}
	return out, m.err
}

// telemetryFixture is a provider fake, a service and an inventory holding
// nodes pve1 and pve2, the QEMU guest 101 (generation 5) on pve1, the LXC
// guest 102 (generation 1) on pve2 and the QEMU guest 103 (generation 2) on
// pve2.
func telemetryFixture(t *testing.T) (*providerFake, *Service, *memInventory) {
	t.Helper()
	f := newProviderFake()
	s := providerService(t, f)
	inv := &memInventory{remote: "proxmoxbai", nodes: []string{"pve1", "pve2"}, guests: []TelemetryGuest{
		{VMID: 101, Generation: 5, Kind: "qemu", Node: "pve1"},
		{VMID: 102, Generation: 1, Kind: "lxc", Node: "pve2"},
		{VMID: 103, Generation: 2, Kind: "qemu", Node: "pve2"},
	}}
	return f, s, inv
}

func nodeSel(n string) ProviderMetricsSelection {
	return ProviderMetricsSelection{Node: n, Kind: permit.MetricsKindNode}
}

func guestSel(n, kind string, vmid uint64) ProviderMetricsSelection {
	return ProviderMetricsSelection{Node: n, Kind: kind, VMID: vmid}
}

// TestProposeProviderTelemetryGrantBuildsExactDoc pins every member of the
// built telemetry document: the remote bound with the executor's trust pin,
// generation and read credential version, the single method "metrics",
// the chosen targets with the generations of the imported inventory in a
// fixed order, the on-demand trigger, the live interval and the budget.
func TestProposeProviderTelemetryGrantBuildsExactDoc(t *testing.T) {
	f, s, inv := telemetryFixture(t)
	var audit strings.Builder
	s.log = slog.New(slog.NewTextHandler(&audit, nil))
	v, err := s.ProposeProviderTelemetryGrant(context.Background(), "alice", ProviderTelemetryGrantRequest{
		RemoteID: "proxmoxbai", Days: ReadGrantShortDays,
		Targets: []ProviderMetricsSelection{guestSel("pve2", "lxc", 102), nodeSel("pve1"), guestSel("pve1", "qemu", 101)},
	}, inv)
	if err != nil {
		t.Fatal(err)
	}
	now := s.now()
	d := f.sent
	if d.Grant != permit.ReadGrantFormat || d.Issuer != readGrantIssuer || !readGrantIDRe.MatchString(d.ID) ||
		d.CreatedUnix != now.Unix() || d.ExpiryUnix != now.Add(7*24*time.Hour).Unix() ||
		d.Trigger != permit.TriggerOnDemand || d.RateProfile != permit.ProviderTelemetryProfile ||
		d.MinIntervalS != 10 || d.RunBudget != 3*360 {
		t.Fatalf("sent document %+v", d)
	}
	if len(d.Actions) != 0 || len(d.Targets) != 0 || len(d.Credentials) != 0 {
		t.Fatalf("a telemetry grant carries SSH members: %+v", d)
	}
	want := []permit.ProviderTarget{{
		RemoteID: "proxmoxbai", TrustPin: testPinA, TrustGeneration: 3, CredentialVersion: 7,
		Methods: []string{permit.ProviderMethodMetrics},
		MetricsTargets: []permit.ProviderMetricsTarget{
			{Node: "pve1", Kind: "node"},
			{Node: "pve1", Kind: "qemu", VMID: 101, Generation: 5},
			{Node: "pve2", Kind: "lxc", VMID: 102, Generation: 1},
		},
	}}
	if !sameProviderTargets(d.ProviderTargets, want) {
		t.Fatalf("provider targets %+v, want %+v", d.ProviderTargets, want)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := permit.ParseReadGrant(raw, now); err != nil {
		t.Fatalf("the executor's parser refuses the built document: %v", err)
	}
	if v.ID != d.ID || v.Digest != testDigest || v.RateProfile != permit.ProviderTelemetryProfile || v.RunBudget != 1080 ||
		v.MinInterval != 10*time.Second || v.Trigger != permit.TriggerOnDemand || v.ScopeKind != ScopeProvider {
		t.Fatalf("preview %+v", v)
	}
	if len(v.Providers) != 1 || !slices.Equal(v.Providers[0].MetricsTargets, want[0].MetricsTargets) ||
		!slices.Equal(v.Providers[0].Methods, []string{"metrics"}) || v.Providers[0].CredentialVersion != 7 {
		t.Fatalf("preview providers %+v", v.Providers)
	}
	if !strings.Contains(audit.String(), "provider_telemetry_grant_proposed") || !strings.Contains(audit.String(), "user=alice") ||
		!strings.Contains(audit.String(), "targets=3") {
		t.Errorf("no audit line: %s", audit.String())
	}
	// Proposing commits nothing: approval is a separate step.
	if f.committed != nil {
		t.Error("the proposal was committed")
	}
}

// TestProviderTelemetryBudget pins the budget: one request per live
// interval for each target the executor can keep live at once (four per
// remote), never above permit.MaxProviderTelemetryBudget.
func TestProviderTelemetryBudget(t *testing.T) {
	for _, tc := range []struct {
		targets int
		want    int64
	}{{1, 360}, {2, 720}, {4, 1440}, {5, 1440}, {permit.MaxProviderMetricsTargets, 1440}} {
		got := providerTelemetryBudget(tc.targets)
		if got != tc.want {
			t.Errorf("budget(%d) = %d, want %d", tc.targets, got, tc.want)
		}
		if got < 1 || got > permit.MaxProviderTelemetryBudget {
			t.Errorf("budget(%d) = %d outside the permit limit", tc.targets, got)
		}
	}
}

// TestProposeProviderTelemetryGrantMaxTargets proposes the largest allowed
// lease and refuses one target more before the executor is asked.
func TestProposeProviderTelemetryGrantMaxTargets(t *testing.T) {
	f, s, inv := telemetryFixture(t)
	sel := []ProviderMetricsSelection{nodeSel("pve1")}
	for i := range uint64(permit.MaxProviderMetricsTargets) {
		inv.guests = append(inv.guests, TelemetryGuest{VMID: 200 + i, Generation: 1, Kind: "qemu", Node: "pve1"})
		sel = append(sel, guestSel("pve1", "qemu", 200+i))
	}
	_, err := s.ProposeProviderTelemetryGrant(context.Background(), "alice", ProviderTelemetryGrantRequest{
		RemoteID: "proxmoxbai", Days: ReadGrantShortDays, Targets: sel}, inv)
	var ie *ReadGrantInputError
	if !errors.As(err, &ie) || f.proposeCalls != 0 || inv.calls != 0 {
		t.Fatalf("65 targets: err %v, proposals %d, inventory reads %d", err, f.proposeCalls, inv.calls)
	}
	v, err := s.ProposeProviderTelemetryGrant(context.Background(), "alice", ProviderTelemetryGrantRequest{
		RemoteID: "proxmoxbai", Days: ReadGrantShortDays, Targets: sel[:permit.MaxProviderMetricsTargets]}, inv)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(v.Providers[0].MetricsTargets); n != permit.MaxProviderMetricsTargets || v.RunBudget != 1440 {
		t.Fatalf("%d targets, budget %d", n, v.RunBudget)
	}
	raw, _ := json.Marshal(f.sent)
	if _, _, _, err := permit.ParseReadGrant(raw, s.now()); err != nil {
		t.Fatalf("the executor's parser refuses the largest lease: %v", err)
	}
}

// TestProposeProviderTelemetryGrantBindsCurrentGeneration shows that the
// generation comes from the current imported inventory: a recreated guest
// (same VMID, new incarnation) is bound with its new generation, and a
// guest that left the inventory is refused.
func TestProposeProviderTelemetryGrantBindsCurrentGeneration(t *testing.T) {
	f, s, inv := telemetryFixture(t)
	// The next inventory pass: 101 was recreated, 103 is gone.
	inv.guests = []TelemetryGuest{{VMID: 101, Generation: 6, Kind: "qemu", Node: "pve1"}, {VMID: 102, Generation: 1, Kind: "lxc", Node: "pve2"}}
	if _, err := s.ProposeProviderTelemetryGrant(context.Background(), "alice", ProviderTelemetryGrantRequest{
		RemoteID: "proxmoxbai", Days: ReadGrantShortDays, Targets: []ProviderMetricsSelection{guestSel("pve1", "qemu", 101)}}, inv); err != nil {
		t.Fatal(err)
	}
	got := f.sent.ProviderTargets[0].MetricsTargets
	if len(got) != 1 || got[0].Generation != 6 {
		t.Fatalf("bound %+v, want generation 6", got)
	}
	calls := f.proposeCalls
	_, err := s.ProposeProviderTelemetryGrant(context.Background(), "alice", ProviderTelemetryGrantRequest{
		RemoteID: "proxmoxbai", Days: ReadGrantShortDays, Targets: []ProviderMetricsSelection{guestSel("pve2", "qemu", 103)}}, inv)
	var ie *ReadGrantInputError
	if !errors.As(err, &ie) || f.proposeCalls != calls {
		t.Fatalf("removed guest: err %v", err)
	}
}

// TestProposeProviderTelemetryGrantRefusals covers every refused request:
// nothing reaches the executor.
func TestProposeProviderTelemetryGrantRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		in     ProviderTelemetryGrantRequest
		mutate func(*pb.PVEAdminRemote)
	}{
		{"bad days", ProviderTelemetryGrantRequest{RemoteID: "proxmoxbai", Days: 3, Targets: []ProviderMetricsSelection{nodeSel("pve1")}}, nil},
		{"no targets", ProviderTelemetryGrantRequest{RemoteID: "proxmoxbai", Days: 7}, nil},
		{"malformed remote", ProviderTelemetryGrantRequest{RemoteID: "Bad Remote", Days: 7, Targets: []ProviderMetricsSelection{nodeSel("pve1")}}, nil},
		{"remote not imported", ProviderTelemetryGrantRequest{RemoteID: "pve-lab", Days: 7, Targets: []ProviderMetricsSelection{nodeSel("pve1")}}, nil},
		{"unknown node", ProviderTelemetryGrantRequest{RemoteID: "proxmoxbai", Days: 7, Targets: []ProviderMetricsSelection{nodeSel("pve9")}}, nil},
		{"malformed node", ProviderTelemetryGrantRequest{RemoteID: "proxmoxbai", Days: 7, Targets: []ProviderMetricsSelection{nodeSel("pve_1/x")}}, nil},
		{"node with vmid", ProviderTelemetryGrantRequest{RemoteID: "proxmoxbai", Days: 7, Targets: []ProviderMetricsSelection{{Node: "pve1", Kind: "node", VMID: 101}}}, nil},
		{"unknown kind", ProviderTelemetryGrantRequest{RemoteID: "proxmoxbai", Days: 7, Targets: []ProviderMetricsSelection{guestSel("pve1", "docker", 101)}}, nil},
		{"guest vmid out of range", ProviderTelemetryGrantRequest{RemoteID: "proxmoxbai", Days: 7, Targets: []ProviderMetricsSelection{guestSel("pve1", "qemu", 99)}}, nil},
		{"guest not in inventory", ProviderTelemetryGrantRequest{RemoteID: "proxmoxbai", Days: 7, Targets: []ProviderMetricsSelection{guestSel("pve1", "qemu", 150)}}, nil},
		{"guest kind changed", ProviderTelemetryGrantRequest{RemoteID: "proxmoxbai", Days: 7, Targets: []ProviderMetricsSelection{guestSel("pve1", "lxc", 101)}}, nil},
		{"guest moved", ProviderTelemetryGrantRequest{RemoteID: "proxmoxbai", Days: 7, Targets: []ProviderMetricsSelection{guestSel("pve2", "qemu", 101)}}, nil},
		{"duplicate", ProviderTelemetryGrantRequest{RemoteID: "proxmoxbai", Days: 7, Targets: []ProviderMetricsSelection{nodeSel("pve1"), nodeSel("pve1")}}, nil},
		{"remote blocked", ProviderTelemetryGrantRequest{RemoteID: "proxmoxbai", Days: 7, Targets: []ProviderMetricsSelection{nodeSel("pve1")}},
			func(r *pb.PVEAdminRemote) { r.State = "blocked" }},
		{"no read credential", ProviderTelemetryGrantRequest{RemoteID: "proxmoxbai", Days: 7, Targets: []ProviderMetricsSelection{nodeSel("pve1")}},
			func(r *pb.PVEAdminRemote) { r.ReadVersion = 0 }},
		{"remote not registered", ProviderTelemetryGrantRequest{RemoteID: "proxmoxbai", Days: 7, Targets: []ProviderMetricsSelection{nodeSel("pve1")}},
			func(r *pb.PVEAdminRemote) { r.RemoteId = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, s, inv := telemetryFixture(t)
			if tc.mutate != nil {
				for _, r := range f.remotes {
					if r.RemoteId == "proxmoxbai" {
						tc.mutate(r)
					}
				}
			}
			_, err := s.ProposeProviderTelemetryGrant(context.Background(), "alice", tc.in, inv)
			var ie *ReadGrantInputError
			if !errors.As(err, &ie) {
				t.Fatalf("err = %v, want an input error", err)
			}
			if f.proposeCalls != 0 {
				t.Fatal("a refused request reached the executor")
			}
		})
	}
}

// TestProposeProviderTelemetryGrantRejectsAlteredAnswer refuses an
// executor answer whose metrics targets differ from the proposal in any
// way (generation, an extra or missing target, order, a dropped list).
func TestProposeProviderTelemetryGrantRejectsAlteredAnswer(t *testing.T) {
	for name, alter := range map[string]func(*permit.ProviderTarget){
		"generation": func(p *permit.ProviderTarget) { p.MetricsTargets[1].Generation++ },
		"extra target": func(p *permit.ProviderTarget) {
			p.MetricsTargets = append(p.MetricsTargets, permit.ProviderMetricsTarget{Node: "pve2", Kind: "qemu", VMID: 103, Generation: 2})
		},
		"missing target": func(p *permit.ProviderTarget) { p.MetricsTargets = p.MetricsTargets[:1] },
		"reordered": func(p *permit.ProviderTarget) {
			p.MetricsTargets[0], p.MetricsTargets[1] = p.MetricsTargets[1], p.MetricsTargets[0]
		},
		"dropped":        func(p *permit.ProviderTarget) { p.MetricsTargets = nil },
		"node":           func(p *permit.ProviderTarget) { p.MetricsTargets[1].Node = "pve2" },
		"methods":        func(p *permit.ProviderTarget) { p.Methods = []string{"metrics", "nodes"} },
		"credential":     func(p *permit.ProviderTarget) { p.CredentialVersion++ },
		"trust gen":      func(p *permit.ProviderTarget) { p.TrustGeneration++ },
		"trigger (both)": nil,
	} {
		t.Run(name, func(t *testing.T) {
			f, s, inv := telemetryFixture(t)
			f.alter = func(d *permit.ReadGrantDoc) {
				// Deep-copy the provider targets so the record of what was
				// sent stays untouched.
				pts := slices.Clone(d.ProviderTargets)
				pts[0].MetricsTargets = slices.Clone(pts[0].MetricsTargets)
				pts[0].Methods = slices.Clone(pts[0].Methods)
				d.ProviderTargets = pts
				if alter == nil {
					d.Trigger = permit.TriggerBoth
					return
				}
				alter(&d.ProviderTargets[0])
			}
			_, err := s.ProposeProviderTelemetryGrant(context.Background(), "alice", ProviderTelemetryGrantRequest{
				RemoteID: "proxmoxbai", Days: ReadGrantShortDays,
				Targets: []ProviderMetricsSelection{nodeSel("pve1"), guestSel("pve1", "qemu", 101)}}, inv)
			if !errors.Is(err, ErrReadGrantProposalMismatch) {
				t.Fatalf("err = %v, want mismatch", err)
			}
		})
	}
}

// TestProviderReadGrantRefusesAnswerWithMetricsTargets keeps the read
// lease comparison exact: metrics targets added to a read lease answer are
// a mismatch.
func TestProviderReadGrantRefusesAnswerWithMetricsTargets(t *testing.T) {
	f := newProviderFake()
	s := providerService(t, f)
	f.alter = func(d *permit.ReadGrantDoc) {
		pts := slices.Clone(d.ProviderTargets)
		pts[0].MetricsTargets = []permit.ProviderMetricsTarget{{Node: "pve1", Kind: "node"}}
		d.ProviderTargets = pts
	}
	_, err := s.ProposeProviderReadGrant(context.Background(), "alice", ProviderReadGrantRequest{RemoteIDs: []string{"proxmoxbai"}, Days: 7})
	if !errors.Is(err, ErrReadGrantProposalMismatch) {
		t.Fatalf("err = %v, want mismatch", err)
	}
}

// TestProposeProviderTelemetryGrantRegistryUnavailable fails closed when
// the executor's remote metadata cannot be read.
func TestProposeProviderTelemetryGrantRegistryUnavailable(t *testing.T) {
	f, s, inv := telemetryFixture(t)
	f.remoteErr = errors.New("down")
	_, err := s.ProposeProviderTelemetryGrant(context.Background(), "alice", ProviderTelemetryGrantRequest{
		RemoteID: "proxmoxbai", Days: 7, Targets: []ProviderMetricsSelection{nodeSel("pve1")}}, inv)
	if !errors.Is(err, ErrProviderRemotesUnavailable) || f.proposeCalls != 0 {
		t.Fatalf("err = %v, proposals %d", err, f.proposeCalls)
	}
}

// TestProposeProviderTelemetryGrantInventoryFailure fails closed when the
// inventory cannot be read or is missing: no proposal is made.
func TestProposeProviderTelemetryGrantInventoryFailure(t *testing.T) {
	f, s, inv := telemetryFixture(t)
	inv.err = errors.New("disk")
	req := ProviderTelemetryGrantRequest{RemoteID: "proxmoxbai", Days: 7, Targets: []ProviderMetricsSelection{nodeSel("pve1")}}
	if _, err := s.ProposeProviderTelemetryGrant(context.Background(), "alice", req, inv); err == nil || f.proposeCalls != 0 {
		t.Fatalf("inventory error: err %v, proposals %d", err, f.proposeCalls)
	}
	var ie *ReadGrantInputError
	if _, err := s.ProposeProviderTelemetryGrant(context.Background(), "alice", req, nil); !errors.As(err, &ie) || f.proposeCalls != 0 {
		t.Fatalf("no inventory: err %v, proposals %d", err, f.proposeCalls)
	}
}

// telemetryDoc is an approved provider telemetry grant of remote
// proxmoxbai with a node and a guest target, at the decode times.
func telemetryDoc() permit.ReadGrantDoc {
	d := providerDoc()
	d.Trigger, d.RateProfile, d.MinIntervalS, d.RunBudget = permit.TriggerOnDemand, permit.ProviderTelemetryProfile, 10, 720
	d.ProviderTargets = []permit.ProviderTarget{{RemoteID: "proxmoxbai", TrustPin: testPinA, TrustGeneration: 3, CredentialVersion: 7,
		Methods: []string{permit.ProviderMethodMetrics}, MetricsTargets: []permit.ProviderMetricsTarget{
			{Node: "pve1", Kind: "node"}, {Node: "pve1", Kind: "qemu", VMID: 101, Generation: 5}}}}
	return d
}

// TestDecodeReadGrantShowsMetricsTargets pins that a telemetry lease view
// carries its exact metrics targets in document order.
func TestDecodeReadGrantShowsMetricsTargets(t *testing.T) {
	v := decodeRaw(marshalDoc(t, telemetryDoc()))
	if v.State != "active" || v.RateProfile != permit.ProviderTelemetryProfile || len(v.Providers) != 1 {
		t.Fatalf("view %+v", v)
	}
	if !slices.Equal(v.Providers[0].MetricsTargets, telemetryDoc().ProviderTargets[0].MetricsTargets) {
		t.Fatalf("metrics targets %+v", v.Providers[0].MetricsTargets)
	}
}

// TestDecodeReadGrantRejectsMalformedMetricsTargets marks a grant invalid
// when any rendered metrics target is malformed, repeated, too many, or on
// a remote whose methods are not exactly "metrics".
func TestDecodeReadGrantRejectsMalformedMetricsTargets(t *testing.T) {
	cases := map[string]func(*permit.ProviderTarget){
		"node with vmid": func(p *permit.ProviderTarget) { p.MetricsTargets[0].VMID = 101 },
		"guest no gen":   func(p *permit.ProviderTarget) { p.MetricsTargets[1].Generation = 0 },
		"bad kind":       func(p *permit.ProviderTarget) { p.MetricsTargets[1].Kind = "<b>" },
		"bad node":       func(p *permit.ProviderTarget) { p.MetricsTargets[0].Node = "pve 1\n" },
		"vmid range":     func(p *permit.ProviderTarget) { p.MetricsTargets[1].VMID = 5 },
		"duplicate":      func(p *permit.ProviderTarget) { p.MetricsTargets[1] = p.MetricsTargets[0] },
		"same key new gen": func(p *permit.ProviderTarget) {
			extra := p.MetricsTargets[1]
			extra.Generation++
			p.MetricsTargets = append(p.MetricsTargets, extra)
		},
		"read methods": func(p *permit.ProviderTarget) { p.Methods = []string{"nodes"} },
		"extra method": func(p *permit.ProviderTarget) { p.Methods = []string{"metrics", "nodes"} },
		"too many": func(p *permit.ProviderTarget) {
			for i := range uint64(permit.MaxProviderMetricsTargets) {
				p.MetricsTargets = append(p.MetricsTargets, permit.ProviderMetricsTarget{Node: "pve1", Kind: "lxc", VMID: 1000 + i, Generation: 1})
			}
		},
	}
	for name, mutate := range cases {
		d := telemetryDoc()
		mutate(&d.ProviderTargets[0])
		wantInvalid(t, name, decodeRaw(marshalDoc(t, d)))
	}
}

// TestReadGrantsMarksProviderBinding compares every frozen remote with the
// executor's registry: matching pin, generation and read credential version
// is current; a re-pinned, rotated or removed remote is stale; without the
// registry the binding is unknown.
func TestReadGrantsMarksProviderBinding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*pb.PVEAdminRemote)
		err    error
		want   string
	}{
		{"current", nil, nil, ProviderBindingCurrent},
		{"re-pinned", func(r *pb.PVEAdminRemote) { r.TrustGeneration, r.TrustPin = 4, testPinB }, nil, ProviderBindingStale},
		{"generation only", func(r *pb.PVEAdminRemote) { r.TrustGeneration = 4 }, nil, ProviderBindingStale},
		{"token rotated", func(r *pb.PVEAdminRemote) { r.ReadVersion = 8 }, nil, ProviderBindingStale},
		{"removed", func(r *pb.PVEAdminRemote) { r.RemoteId = "gone" }, nil, ProviderBindingStale},
		{"registry down", nil, errors.New("down"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newProviderFake()
			for _, r := range f.remotes {
				if r.RemoteId == "proxmoxbai" && tc.mutate != nil {
					tc.mutate(r)
				}
			}
			f.remoteErr = tc.err
			f.grants = []*pb.ReadGrant{pbGrant(decodeStored, decodeExpiry, time.Time{}, marshalDoc(t, telemetryDoc()))}
			s := providerService(t, f)
			s.now = func() time.Time { return decodeNow }
			views, err := s.ReadGrants(context.Background())
			if err != nil || len(views) != 1 || len(views[0].Providers) != 1 {
				t.Fatalf("views %+v err %v", views, err)
			}
			if got := views[0].Providers[0].Binding; got != tc.want {
				t.Fatalf("binding %q, want %q", got, tc.want)
			}
		})
	}
}
