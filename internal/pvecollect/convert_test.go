// SPDX-License-Identifier: AGPL-3.0-or-later
package pvecollect

import (
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// TestConvertStoragesCarriesNodeAndShared checks that the per-node storage
// reports keep their reporting node and PVE's shared flag, so the inventory
// can count a shared storage once and keep node-local usage per node.
func TestConvertStoragesCarriesNodeAndShared(t *testing.T) {
	res := readResult{resp: &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_Storages{Storages: &pb.PVEStorages{
		State: available,
		Storages: []*pb.PVEStorage{
			{Name: "nfs", Type: "nfs", Content: []string{"images"}, Active: true, SizeBytes: 100, FreeBytes: 40, Node: "pve1", Shared: true},
			{Name: "nfs", Type: "nfs", Content: []string{"images"}, Active: true, SizeBytes: 100, FreeBytes: 40, Node: "pve2", Shared: true},
			{Name: "local", Type: "dir", Content: []string{"iso"}, Active: true, SizeBytes: 10, FreeBytes: 5, Node: "pve2"},
		},
	}}}}
	ds := convertStorages(res)
	if ds.State != pvecontract.Available || len(ds.Value) != 3 {
		t.Fatalf("dataset = %+v", ds)
	}
	want := []struct {
		node, name string
		shared     bool
	}{{"pve1", "nfs", true}, {"pve2", "nfs", true}, {"pve2", "local", false}}
	for i, w := range want {
		if got := ds.Value[i]; got.Node != w.node || got.Name != w.name || got.Shared != w.shared {
			t.Fatalf("storage %d = %+v, want %s/%s shared=%v", i, got, w.node, w.name, w.shared)
		}
	}
	// The converted reports must pass the contract as one observation.
	o := pvecontract.Observation{Storages: ds}
	if _, err := pvecontract.ValidateObservation(o); err != nil {
		// Other datasets are empty here; only storage errors matter.
		for _, msg := range []string{"storages[", "too many storage"} {
			if strings.Contains(err.Error(), msg) {
				t.Fatalf("converted storages rejected: %v", err)
			}
		}
	}
}
