// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
)

// critSource is a riskpolicy.Source with exact host criticality records and
// one trusted artifact risk.
type critSource struct {
	artifact canonical.Risk
	hosts    map[canonical.Target]canonical.Risk
}

func (s critSource) ArtifactRisk(string, string, string) (canonical.Risk, bool, error) {
	return s.artifact, s.artifact != "", nil
}

func (s critSource) HostCriticality(hostID, fp string) (canonical.Risk, bool, error) {
	c, ok := s.hosts[canonical.Target{HostID: hostID, HostKeyFingerprint: fp}]
	return c, ok, nil
}

const gib = uint64(1) << 30

func TestProvisionCapacityFactsFailClosed(t *testing.T) {
	inv := pveapi.ClusterInventory{
		Nodes: []pveapi.Node{{Name: "pve1", MaxMemory: 16 * gib}, {Name: "pve2"}},
		Guests: []pveapi.Guest{
			{Node: "pve1", MaxMemory: int64(8 * gib)},
			{Node: "pve1", MaxMemory: int64(4 * gib)},
			{Node: "pve2", MaxMemory: int64(64 * gib)},
		},
	}
	st := pveapi.Storage{ID: "local-lvm", Active: true, CapacityKnown: true, TotalBytes: 100 * gib, UsedBytes: 60 * gib}
	cases := []struct {
		name          string
		node          string
		st            pveapi.Storage
		memMiB        int
		diskGiB       int64
		wantMem, want bool
	}{
		{"fits", "pve1", st, 4096, 32, false, false},
		{"ram over", "pve1", st, 4097, 32, true, false},
		{"disk over", "pve1", st, 1024, 41, false, true},
		{"node memory unknown", "pve2", st, 1024, 8, true, false},
		{"node missing", "pve9", st, 1024, 8, true, false},
		{"storage capacity unknown", "pve1", pveapi.Storage{Active: true, TotalBytes: 100 * gib}, 1024, 8, false, true},
		{"storage inactive", "pve1", pveapi.Storage{CapacityKnown: true, TotalBytes: 100 * gib}, 1024, 8, false, true},
		{"used above total", "pve1", pveapi.Storage{Active: true, CapacityKnown: true, TotalBytes: 10 * gib, UsedBytes: 20 * gib}, 1024, 1, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, s := pveCapacityFacts(inv, c.st, c.node, c.memMiB, c.diskGiB)
			if m != c.wantMem || s != c.want {
				t.Fatalf("memory %v storage %v, want %v %v", m, s, c.wantMem, c.want)
			}
		})
	}
	// A hostile guest list that overflows the sum is over-commit.
	hostile := inv
	hostile.Guests = []pveapi.Guest{{Node: "pve1", MaxMemory: 1<<63 - 1}, {Node: "pve1", MaxMemory: 1<<63 - 1}, {Node: "pve1", MaxMemory: 1<<63 - 1}}
	if m, _ := pveCapacityFacts(hostile, st, "pve1", 1024, 1); !m {
		t.Fatal("overflowing guest memory is not over-commit")
	}
	// A duplicated node entry fails closed, whichever entry comes last.
	for _, nodes := range [][]pveapi.Node{
		{{Name: "pve1", MaxMemory: 16 * gib}, {Name: "pve1", MaxMemory: 1 << 62}},
		{{Name: "pve1", MaxMemory: 1 << 62}, {Name: "pve1", MaxMemory: 16 * gib}},
	} {
		dup := inv
		dup.Nodes = nodes
		if m, _ := pveCapacityFacts(dup, st, "pve1", 1024, 1); !m {
			t.Fatalf("duplicated node %+v clears the memory warning", nodes)
		}
	}
}

func TestProvisionCapacityWarningsAreInformationOnly(t *testing.T) {
	if w := (PveProvisionCapacity{}).Warnings(); len(w) != 0 {
		t.Fatalf("warnings without facts: %v", w)
	}
	if w := (PveProvisionCapacity{MemoryOvercommit: true, StorageOvercommit: true}).Warnings(); len(w) != 2 {
		t.Fatalf("warnings %v", w)
	}
}

func TestPveRemoteRiskTargetIsStableAndValid(t *testing.T) {
	a, err := PveRemoteRiskTarget(strings.Repeat("ab", 32))
	if err != nil || !canonical.ValidHostID(a.HostID) || !canonical.ValidHostKeyFingerprint(a.HostKeyFingerprint) {
		t.Fatalf("target %+v %v", a, err)
	}
	b, _ := PveRemoteRiskTarget(strings.Repeat("ab", 32))
	c, _ := PveRemoteRiskTarget(strings.Repeat("cd", 32))
	if a != b || a.HostID == c.HostID {
		t.Fatalf("unstable or colliding targets %+v %+v %+v", a, b, c)
	}
	if _, err := PveRemoteRiskTarget("zz"); err == nil {
		t.Fatal("bad pin accepted")
	}
}

func TestGuestProvisionRiskFloorRules(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	remote, _ := PveRemoteRiskTarget(pin)
	node, err := (permit.ProviderMutationTarget{RemoteID: "pve-lab", TrustPin: pin, Kind: permit.ProviderKindNode, Node: "pve1"}).RiskTarget()
	if err != nil {
		t.Fatal(err)
	}
	remoteOf := func(canonical.Target) (string, bool, error) { return pin, true, nil }
	linked := canonical.Target{HostID: "host-1", HostKeyFingerprint: "SHA256:" + strings.Repeat("A", 43)}
	req := canonical.Request{ActionID: PveGuestProvisionAction, ParametersHash: strings.Repeat("1", 64), ExpiryUnix: time.Now().Add(time.Hour).Unix()}
	linkedOf := func(hosts ...canonical.Target) PveLinkedHosts {
		return func(_ canonical.Request, n canonical.Target) ([]canonical.Target, error) {
			if n != node {
				return nil, errors.New("unexpected node")
			}
			return hosts, nil
		}
	}
	cases := []struct {
		name   string
		hosts  map[canonical.Target]canonical.Risk
		linked PveLinkedHosts
		want   canonical.Risk
	}{
		{"low remote and node", map[canonical.Target]canonical.Risk{remote: canonical.RiskLow, node: canonical.RiskLow}, linkedOf(), canonical.RiskMedium},
		{"medium remote and node", map[canonical.Target]canonical.Risk{remote: canonical.RiskMedium, node: canonical.RiskMedium}, linkedOf(), canonical.RiskMedium},
		{"unknown node", map[canonical.Target]canonical.Risk{remote: canonical.RiskLow}, linkedOf(), canonical.RiskHigh},
		{"unknown remote", map[canonical.Target]canonical.Risk{node: canonical.RiskLow}, linkedOf(), canonical.RiskHigh},
		{"high node", map[canonical.Target]canonical.Risk{remote: canonical.RiskLow, node: canonical.RiskHigh}, linkedOf(), canonical.RiskHigh},
		{"high remote", map[canonical.Target]canonical.Risk{remote: canonical.RiskHigh, node: canonical.RiskMedium}, linkedOf(), canonical.RiskHigh},
		{"critical remote", map[canonical.Target]canonical.Risk{remote: canonical.RiskCritical, node: canonical.RiskLow}, linkedOf(), canonical.RiskCritical},
		{"low linked host", map[canonical.Target]canonical.Risk{remote: canonical.RiskLow, node: canonical.RiskLow, linked: canonical.RiskLow}, linkedOf(linked), canonical.RiskMedium},
		{"unknown linked host", map[canonical.Target]canonical.Risk{remote: canonical.RiskLow, node: canonical.RiskLow}, linkedOf(linked), canonical.RiskHigh},
		{"critical linked host", map[canonical.Target]canonical.Risk{remote: canonical.RiskLow, node: canonical.RiskLow, linked: canonical.RiskCritical}, linkedOf(linked), canonical.RiskCritical},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pol, err := riskpolicy.New(critSource{artifact: canonical.RiskMedium, hosts: c.hosts})
			if err != nil {
				t.Fatal(err)
			}
			got, why, err := GuestProvisionRiskFloor{Next: pol, Linked: c.linked, Remote: remoteOf}.MinimumRisk(req, []canonical.Target{node})
			if err != nil || got != c.want {
				t.Fatalf("floor = %s (%s) %v, want %s", got, why, err, c.want)
			}
		})
	}

	low := critSource{artifact: canonical.RiskLow, hosts: map[canonical.Target]canonical.Risk{remote: canonical.RiskLow, node: canonical.RiskLow}}
	pol, _ := riskpolicy.New(low)
	// Base MEDIUM, never LOW, even for an artifact trusted as LOW.
	if r, _, _ := (GuestProvisionRiskFloor{Next: pol, Linked: linkedOf(), Remote: remoteOf}).MinimumRisk(req, []canonical.Target{node}); r != canonical.RiskMedium {
		t.Fatalf("low artifact = %s", r)
	}
	// Parameters the executor never built get no extra raise of their own:
	// only criticality counts (ADR 0008 decision 2).
	foreign := req
	foreign.ParametersHash = strings.Repeat("3", 64)
	if r, _, _ := (GuestProvisionRiskFloor{Next: pol, Linked: linkedOf(), Remote: remoteOf}).MinimumRisk(foreign, []canonical.Target{node}); r != canonical.RiskMedium {
		t.Fatalf("unbuilt parameters = %s", r)
	}
	// Without a linked-host source the linked hosts are unknown: HIGH.
	if r, _, _ := (GuestProvisionRiskFloor{Next: pol, Remote: remoteOf}).MinimumRisk(req, []canonical.Target{node}); r != canonical.RiskHigh {
		t.Fatalf("no linked-host source = %s, want HIGH", r)
	}
	// A failing linked-host source fails closed.
	failing := func(canonical.Request, canonical.Target) ([]canonical.Target, error) { return nil, errors.New("down") }
	if _, _, err := (GuestProvisionRiskFloor{Next: pol, Linked: failing, Remote: remoteOf}).MinimumRisk(req, []canonical.Target{node}); err == nil {
		t.Fatal("linked-host error ignored")
	}
	// Without a node target the criticality is unknown: HIGH.
	// Linked is set so the empty-targets check itself decides.
	if r, _, _ := (GuestProvisionRiskFloor{Next: pol, Linked: linkedOf(), Remote: remoteOf}).MinimumRisk(req, nil); r != canonical.RiskHigh {
		t.Fatalf("no targets = %s", r)
	}
	// Without a criticality source everything is HIGH.
	if r, _, _ := (GuestProvisionRiskFloor{}).MinimumRisk(req, []canonical.Target{node}); r != canonical.RiskHigh {
		t.Fatalf("no next policy = %s", r)
	}
	// Other actions pass through unchanged.
	other := canonical.Request{ActionID: "pve.test.mutation"}
	if r, _, _ := (GuestProvisionRiskFloor{Next: fixedRisk{}}).MinimumRisk(other, nil); r != canonical.RiskMedium {
		t.Fatalf("other action = %s", r)
	}
	if r, _, _ := (GuestProvisionRiskFloor{}).MinimumRisk(other, nil); r != canonical.RiskHigh {
		t.Fatalf("other action without next = %s", r)
	}
}
