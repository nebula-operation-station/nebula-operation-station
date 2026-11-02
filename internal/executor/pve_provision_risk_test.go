// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
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
}

func TestProvisionRiskFactsRaiseToHigh(t *testing.T) {
	if r := (PveProvisionRiskFacts{}).Risk(); r != canonical.RiskMedium {
		t.Fatalf("base = %s", r)
	}
	for _, f := range []PveProvisionRiskFacts{{PCIPassthrough: true}, {MemoryOvercommit: true}, {StorageOvercommit: true}} {
		if r := f.Risk(); r != canonical.RiskHigh {
			t.Fatalf("%+v = %s", f, r)
		}
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
	node := canonical.Target{HostID: "pvm-0123456789abcdef0123456789abcdef", HostKeyFingerprint: remote.HostKeyFingerprint}
	now := time.Unix(1_800_000_000, 0)
	req := canonical.Request{ActionID: PveGuestProvisionAction, ParametersHash: strings.Repeat("1", 64), ExpiryUnix: now.Add(time.Hour).Unix()}

	floors := &PveProvisionRiskFloors{Now: func() time.Time { return now }}
	if err := floors.record(req, canonical.RiskMedium, "facts"); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		hosts map[canonical.Target]canonical.Risk
		want  canonical.Risk
	}{
		{"low remote and node", map[canonical.Target]canonical.Risk{remote: canonical.RiskLow, node: canonical.RiskLow}, canonical.RiskMedium},
		{"unknown node", map[canonical.Target]canonical.Risk{remote: canonical.RiskLow}, canonical.RiskHigh},
		{"unknown remote", map[canonical.Target]canonical.Risk{node: canonical.RiskLow}, canonical.RiskHigh},
		{"high node", map[canonical.Target]canonical.Risk{remote: canonical.RiskLow, node: canonical.RiskHigh}, canonical.RiskHigh},
		{"high remote", map[canonical.Target]canonical.Risk{remote: canonical.RiskHigh, node: canonical.RiskMedium}, canonical.RiskHigh},
		{"critical remote", map[canonical.Target]canonical.Risk{remote: canonical.RiskCritical, node: canonical.RiskLow}, canonical.RiskCritical},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pol, err := riskpolicy.New(critSource{artifact: canonical.RiskMedium, hosts: c.hosts})
			if err != nil {
				t.Fatal(err)
			}
			got, why, err := GuestProvisionRiskFloor{Next: pol, Floors: floors}.MinimumRisk(req, []canonical.Target{node})
			if err != nil || got != c.want {
				t.Fatalf("floor = %s (%s) %v, want %s", got, why, err, c.want)
			}
		})
	}

	low := critSource{artifact: canonical.RiskLow, hosts: map[canonical.Target]canonical.Risk{remote: canonical.RiskLow, node: canonical.RiskLow}}
	pol, _ := riskpolicy.New(low)
	// Base MEDIUM even for an artifact trusted as LOW.
	if r, _, _ := (GuestProvisionRiskFloor{Next: pol, Floors: floors}).MinimumRisk(req, []canonical.Target{node}); r != canonical.RiskMedium {
		t.Fatalf("low artifact = %s", r)
	}
	// Facts recorded as HIGH raise the floor.
	high := req
	high.ParametersHash = strings.Repeat("2", 64)
	if err := floors.record(high, canonical.RiskHigh, "storage"); err != nil {
		t.Fatal(err)
	}
	if r, _, _ := (GuestProvisionRiskFloor{Next: pol, Floors: floors}).MinimumRisk(high, []canonical.Target{node}); r != canonical.RiskHigh {
		t.Fatalf("high facts = %s", r)
	}
	// A later lower record does not lower it.
	if err := floors.record(high, canonical.RiskMedium, "again"); err != nil {
		t.Fatal(err)
	}
	if r, _, _ := (GuestProvisionRiskFloor{Next: pol, Floors: floors}).MinimumRisk(high, []canonical.Target{node}); r != canonical.RiskHigh {
		t.Fatalf("lowered by a later record: %s", r)
	}
	// Parameters the executor never observed are HIGH.
	foreign := req
	foreign.ParametersHash = strings.Repeat("3", 64)
	if r, _, _ := (GuestProvisionRiskFloor{Next: pol, Floors: floors}).MinimumRisk(foreign, []canonical.Target{node}); r != canonical.RiskHigh {
		t.Fatalf("unrecorded parameters = %s", r)
	}
	// An expired record no longer counts.
	later := &PveProvisionRiskFloors{Now: func() time.Time { return now.Add(2 * time.Hour) }, m: floors.m}
	if r, _, _ := (GuestProvisionRiskFloor{Next: pol, Floors: later}).MinimumRisk(req, []canonical.Target{node}); r != canonical.RiskHigh {
		t.Fatalf("expired record = %s", r)
	}
	// Without a criticality source everything is HIGH.
	if r, _, _ := (GuestProvisionRiskFloor{Floors: floors}).MinimumRisk(req, []canonical.Target{node}); r != canonical.RiskHigh {
		t.Fatalf("no next policy = %s", r)
	}
	// Other actions pass through unchanged.
	other := canonical.Request{ActionID: "pve.test.mutation"}
	if r, _, _ := (GuestProvisionRiskFloor{Next: fixedRisk{}}).MinimumRisk(other, nil); r != canonical.RiskMedium {
		t.Fatalf("other action = %s", r)
	}
	if r, _, _ := (GuestProvisionRiskFloor{}).MinimumRisk(other, nil); r != canonical.RiskLow {
		t.Fatalf("other action without next = %s", r)
	}
}

func TestProvisionRiskFloorsAreBounded(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	f := &PveProvisionRiskFloors{Now: func() time.Time { return now }}
	for i := range maxPveProvisionFloors {
		r := canonical.Request{ParametersHash: strings.Repeat("0", 56) + hex8(i), ExpiryUnix: now.Add(time.Hour).Unix()}
		if err := f.record(r, canonical.RiskMedium, ""); err != nil {
			t.Fatal(err)
		}
	}
	extra := canonical.Request{ParametersHash: strings.Repeat("f", 64), ExpiryUnix: now.Add(time.Hour).Unix()}
	if err := f.record(extra, canonical.RiskMedium, ""); err != ErrPveProvisionFloors {
		t.Fatalf("over the bound: %v", err)
	}
	f.Now = func() time.Time { return now.Add(2 * time.Hour) }
	extra.ExpiryUnix = now.Add(3 * time.Hour).Unix()
	if err := f.record(extra, canonical.RiskMedium, ""); err != nil {
		t.Fatalf("expired records not pruned: %v", err)
	}
	if err := f.record(canonical.Request{ParametersHash: "short"}, canonical.RiskMedium, ""); err == nil {
		t.Fatal("malformed hash recorded")
	}
}

func hex8(i int) string {
	const digits = "0123456789abcdef"
	b := make([]byte, 8)
	for j := 7; j >= 0; j-- {
		b[j] = digits[i&15]
		i >>= 4
	}
	return string(b)
}
