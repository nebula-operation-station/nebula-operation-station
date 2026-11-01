// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const pveTwoNodeStatus = `{"data":[{"type":"cluster","id":"cluster","name":"lab","nodes":3,"quorate":1},` +
	`{"type":"node","id":"node/pve1","name":"pve1","online":1},{"type":"node","id":"node/pve2","name":"pve2","online":1},` +
	`{"type":"node","id":"node/pve3","name":"pve3","online":0}]}`

func clusterNodes(t *testing.T, e *pveReadEnv) map[string]*pb.PVEClusterNode {
	t.Helper()
	got, err := e.read(pb.PVEReadMethod_PVE_READ_METHOD_CLUSTER)
	if err != nil {
		t.Fatal(err)
	}
	c := got.GetCluster()
	if c.GetState() != pveAvailable {
		t.Fatalf("cluster = %v", c)
	}
	out := map[string]*pb.PVEClusterNode{}
	for _, n := range c.GetNodes() {
		out[n.GetNode()] = n
	}
	return out
}

func TestReadPVEClusterReportsVoteAndMaintenance(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindCluster)
	e.approve(e.grantDoc(pveReadGrantID, 240, allPveMethods()...))
	e.pve.set("/api2/json/cluster/status", pveTwoNodeStatus)
	e.pve.set("/api2/json/cluster/config/nodes", `{"data":[`+
		`{"node":"pve1","quorum_votes":"1","ring0_addr":"10.0.0.1"},{"node":"pve2","quorum_votes":0},{"node":"pve3"}]}`)
	e.pve.set("/api2/json/cluster/ha/status/current", `{"data":[{"id":"quorum","type":"quorum","status":"OK"},`+
		`{"id":"lrm:pve1","type":"lrm","node":"pve1","status":"pve1 (maintenance mode, Sat Nov  1 10:00:00 2026)"},`+
		`{"id":"lrm:pve2","type":"lrm","node":"pve2","status":"pve2 (active, Sat Nov  1 10:00:00 2026)"},`+
		`{"id":"service:vm:100","type":"service","sid":"vm:100","state":"started","node":"pve2"}]}`)
	nodes := clusterNodes(t, e)
	for name, want := range map[string][2]string{
		"pve1": {"yes", "yes"},
		"pve2": {"no", "no"},
		"pve3": {"yes", "unknown"}, // absent quorum_votes is the corosync default; no LRM entry
	} {
		n := nodes[name]
		if n == nil || n.GetVoteState() != want[0] || n.GetMaintenanceState() != want[1] ||
			n.GetVote() != (want[0] == "yes") || n.GetMaintenance() != (want[1] == "yes") {
			t.Errorf("%s = %v, want vote %s maintenance %s", name, n, want[0], want[1])
		}
	}
}

// Without Sys.Audit or HA the states are unknown, never a guessed "no".
func TestReadPVEClusterUnknownVoteAndMaintenanceWhenNotReported(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindCluster)
	e.approve(e.grantDoc(pveReadGrantID, 240, allPveMethods()...))
	e.pve.set("/api2/json/cluster/status", pveTwoNodeStatus)
	// No /cluster/config/nodes body: the fake answers 404.
	for _, n := range clusterNodes(t, e) {
		if n.GetVoteState() != "unknown" || n.GetVote() || n.GetMaintenanceState() != "unknown" || n.GetMaintenance() {
			t.Errorf("node = %v", n)
		}
	}
}

func TestReadPVEClusterHostileVotesUnavailable(t *testing.T) {
	for name, body := range map[string]string{
		"negative votes":  `{"data":[{"node":"pve1","quorum_votes":-1}]}`,
		"huge votes":      `{"data":[{"node":"pve1","quorum_votes":"100000"}]}`,
		"script votes":    `{"data":[{"node":"pve1","quorum_votes":"<script>"}]}`,
		"bad node name":   `{"data":[{"node":"../etc","quorum_votes":1}]}`,
		"duplicate node":  `{"data":[{"node":"pve1"},{"node":"pve1"}]}`,
		"not a node list": `{"data":"<script>"}`,
	} {
		t.Run(name, func(t *testing.T) {
			e := newPveReadEnv(t, pvecontract.KindCluster)
			e.approve(e.grantDoc(pveReadGrantID, 240, allPveMethods()...))
			e.pve.set("/api2/json/cluster/config/nodes", body)
			got, err := e.read(pb.PVEReadMethod_PVE_READ_METHOD_CLUSTER)
			if err != nil {
				t.Fatal(err)
			}
			c := got.GetCluster()
			if c.GetState() != pveUnavailable || c.GetReason() != pveReasonInvalid || len(c.GetNodes()) != 0 {
				t.Fatalf("cluster = %v", c)
			}
			if s := got.String(); strings.Contains(s, "<script>") || strings.Contains(s, "../etc") {
				t.Fatal("hostile value passed")
			}
		})
	}
}

func TestReadPVEClusterHostileLRMEntryUnavailable(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindCluster)
	e.approve(e.grantDoc(pveReadGrantID, 240, allPveMethods()...))
	e.pve.set("/api2/json/cluster/ha/status/current", `{"data":[{"id":"lrm:pve2","type":"lrm","node":"pve1","status":"pve1 (maintenance mode, x)"}]}`)
	got, err := e.read(pb.PVEReadMethod_PVE_READ_METHOD_CLUSTER)
	if err != nil {
		t.Fatal(err)
	}
	if c := got.GetCluster(); c.GetState() != pveUnavailable {
		t.Fatalf("cluster = %v", c)
	}
}
