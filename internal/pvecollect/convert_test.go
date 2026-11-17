// SPDX-License-Identifier: AGPL-3.0-or-later
package pvecollect

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

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

// longReason returns a reason of n bytes made of three-byte runes, so any
// cut at a fixed byte offset that is not a multiple of three splits one.
func longReason(n int) string {
	return strings.Repeat("€", n/3+1)[:n]
}

// assertBoundedValid fails unless s is valid UTF-8 and at most maxReasonBytes.
func assertBoundedValid(t *testing.T, s string) {
	t.Helper()
	if len(s) > maxReasonBytes {
		t.Fatalf("reason is %d bytes, want <= %d", len(s), maxReasonBytes)
	}
	if !utf8.ValidString(s) {
		t.Fatalf("reason %q is not valid UTF-8", s)
	}
}

// TestBoundedReasonCutsOnRuneBoundary checks that a reason of three-byte
// runes is cut back to a whole rune, not split inside one.
func TestBoundedReasonCutsOnRuneBoundary(t *testing.T) {
	in := strings.Repeat("€", 200) // 600 bytes
	got := boundedReason(in)
	assertBoundedValid(t, got)
	// 512 / 3 = 170 whole runes fit (510 bytes); the 171st would need 513.
	if want := strings.Repeat("€", 170); got != want {
		t.Fatalf("boundedReason len=%d, want %d bytes of whole runes", len(got), len(want))
	}
}

// TestBoundedReasonReplacesInvalidUTF8 checks that invalid bytes from the
// executor are replaced before the reason is cut, never passed through.
func TestBoundedReasonReplacesInvalidUTF8(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"lone continuation byte", "a\x80b", "a�b"},
		{"truncated sequence", "ok\xe2\x82", "ok�"},
		{"invalid lead byte", "\xff\xfe", "�"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := boundedReason(tt.in)
			assertBoundedValid(t, got)
			if got != tt.want {
				t.Fatalf("boundedReason(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestBoundedReasonKeepsShortValidText checks that a valid reason within the
// limit comes back unchanged.
func TestBoundedReasonKeepsShortValidText(t *testing.T) {
	for _, in := range []string{"", "storage offline", "Größe ✓", strings.Repeat("a", maxReasonBytes)} {
		if got := boundedReason(in); got != in {
			t.Fatalf("boundedReason(%q) changed the input to %q", in, got)
		}
	}
}

// pveResponse builds a read response for one method with the given dataset
// state and reason, using the matching payload type.
func pveResponse(m pb.PVEReadMethod, st pb.PVEDatasetState, reason string) *pb.ReadPVEResponse {
	switch m {
	case pb.PVEReadMethod_PVE_READ_METHOD_NODES:
		return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_Nodes{Nodes: &pb.PVENodes{State: st, Reason: reason}}}
	case pb.PVEReadMethod_PVE_READ_METHOD_GUESTS:
		return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_Guests{Guests: &pb.PVEGuests{State: st, Reason: reason}}}
	case pb.PVEReadMethod_PVE_READ_METHOD_STORAGE:
		return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_Storages{Storages: &pb.PVEStorages{State: st, Reason: reason}}}
	case pb.PVEReadMethod_PVE_READ_METHOD_CLUSTER:
		return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_Cluster{Cluster: &pb.PVECluster{State: st, Reason: reason}}}
	case pb.PVEReadMethod_PVE_READ_METHOD_TASKS:
		return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_Tasks{Tasks: &pb.PVETasks{State: st, Reason: reason}}}
	case pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG:
		return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_GuestConfig{GuestConfig: &pb.PVEGuestConfig{State: st, Reason: reason}}}
	case pb.PVEReadMethod_PVE_READ_METHOD_GUEST_AGENT:
		return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_GuestAgent{GuestAgent: &pb.PVEGuestAgent{State: st, Reason: reason}}}
	case pb.PVEReadMethod_PVE_READ_METHOD_SNAPSHOTS:
		return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_Snapshots{Snapshots: &pb.PVESnapshots{State: st, Reason: reason}}}
	case pb.PVEReadMethod_PVE_READ_METHOD_BACKUPS:
		return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_Backups{Backups: &pb.PVEBackups{State: st, Reason: reason}}}
	}
	return nil
}

// allReadMethods lists every method that datasetUnavailable and reasonOf
// dispatch on.
var allReadMethods = []pb.PVEReadMethod{
	pb.PVEReadMethod_PVE_READ_METHOD_NODES,
	pb.PVEReadMethod_PVE_READ_METHOD_GUESTS,
	pb.PVEReadMethod_PVE_READ_METHOD_STORAGE,
	pb.PVEReadMethod_PVE_READ_METHOD_CLUSTER,
	pb.PVEReadMethod_PVE_READ_METHOD_TASKS,
	pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG,
	pb.PVEReadMethod_PVE_READ_METHOD_GUEST_AGENT,
	pb.PVEReadMethod_PVE_READ_METHOD_SNAPSHOTS,
	pb.PVEReadMethod_PVE_READ_METHOD_BACKUPS,
}

// TestDatasetUnavailableAndReadReason covers, for every read method, the
// shapes a result can take and what datasetUnavailable and readReason make
// of each one.
func TestDatasetUnavailableAndReadReason(t *testing.T) {
	const fallback = "fallback"
	const reason = "executor says no"
	for _, m := range allReadMethods {
		cases := []struct {
			name        string
			res         readResult
			unavailable bool
			wantReason  string
		}{
			{
				name:        "nil response",
				res:         readResult{req: readReq{method: m}},
				unavailable: true,
				wantReason:  fallback,
			},
			{
				name:        "call failed",
				res:         readResult{req: readReq{method: m}, err: errors.New("boom")},
				unavailable: true,
				wantReason:  fallback,
			},
			{
				name:        "call failed with response",
				res:         readResult{req: readReq{method: m}, resp: pveResponse(m, available, reason), err: errors.New("boom")},
				unavailable: true,
				wantReason:  fallback,
			},
			{
				name:        "empty payload",
				res:         readResult{req: readReq{method: m}, resp: &pb.ReadPVEResponse{}},
				unavailable: true,
				wantReason:  fallback,
			},
			{
				name:        "unavailable with reason",
				res:         readResult{req: readReq{method: m}, resp: pveResponse(m, pb.PVEDatasetState_PVE_DATASET_STATE_UNAVAILABLE, reason)},
				unavailable: true,
				wantReason:  reason,
			},
			{
				name:        "unavailable without reason",
				res:         readResult{req: readReq{method: m}, resp: pveResponse(m, pb.PVEDatasetState_PVE_DATASET_STATE_UNAVAILABLE, "")},
				unavailable: true,
				wantReason:  fallback,
			},
			{
				name:        "available",
				res:         readResult{req: readReq{method: m}, resp: pveResponse(m, available, "")},
				unavailable: false,
			},
		}
		for _, c := range cases {
			t.Run(m.String()+"/"+c.name, func(t *testing.T) {
				if got := datasetUnavailable(c.res); got != c.unavailable {
					t.Fatalf("datasetUnavailable = %v, want %v", got, c.unavailable)
				}
				if !c.unavailable {
					return
				}
				if got := readReason(c.res, fallback); got != c.wantReason {
					t.Fatalf("readReason = %q, want %q", got, c.wantReason)
				}
			})
		}
	}
}

// TestReadReasonBoundsLongExecutorReason checks that a long reason from the
// executor reaches the dataset bounded and valid, through readReason.
func TestReadReasonBoundsLongExecutorReason(t *testing.T) {
	res := readResult{
		req:  readReq{method: pb.PVEReadMethod_PVE_READ_METHOD_STORAGE},
		resp: pveResponse(pb.PVEReadMethod_PVE_READ_METHOD_STORAGE, pb.PVEDatasetState_PVE_DATASET_STATE_UNAVAILABLE, longReason(600)),
	}
	got := readReason(res, "fallback")
	assertBoundedValid(t, got)
	if got == "fallback" {
		t.Fatal("readReason used the fallback although the executor sent a reason")
	}
}

// TestConvertNodesCarriesBoundedReason checks the NODES path end to end: a
// long, invalid-UTF-8 executor reason arrives in the contract type bounded
// and valid.
func TestConvertNodesCarriesBoundedReason(t *testing.T) {
	bad := longReason(600) + "\xff"
	res := readResult{
		req:  readReq{method: pb.PVEReadMethod_PVE_READ_METHOD_NODES},
		resp: pveResponse(pb.PVEReadMethod_PVE_READ_METHOD_NODES, pb.PVEDatasetState_PVE_DATASET_STATE_UNAVAILABLE, bad),
	}
	ds := convertNodes(res)
	if ds.State != pvecontract.Unavailable {
		t.Fatalf("state = %v, want unavailable", ds.State)
	}
	assertBoundedValid(t, ds.Reason)
}

// TestConvertNodeBoundsDetailsReason checks that a node's details reason,
// which the converter forwards on its own, is bounded and valid.
func TestConvertNodeBoundsDetailsReason(t *testing.T) {
	n := &pb.PVENode{
		Node: "pve1",
		Details: &pb.PVENodeDetails{
			State:  pb.PVEDatasetState_PVE_DATASET_STATE_UNAVAILABLE,
			Reason: longReason(600),
		},
	}
	nd := convertNode(n)
	if nd.Details.State != pvecontract.Unavailable {
		t.Fatalf("details state = %v, want unavailable", nd.Details.State)
	}
	assertBoundedValid(t, nd.Details.Reason)
}

// FuzzBoundedReason checks that any input yields valid UTF-8 within the
// limit, and that a valid, short input comes back unchanged.
func FuzzBoundedReason(f *testing.F) {
	f.Add("")
	f.Add("storage offline")
	f.Add(strings.Repeat("€", 200))
	f.Add(strings.Repeat("a", maxReasonBytes+1))
	f.Add("\xff\xfe\x80")
	f.Fuzz(func(t *testing.T, s string) {
		got := boundedReason(s)
		assertBoundedValid(t, got)
		if utf8.ValidString(s) && len(s) <= maxReasonBytes && got != s {
			t.Fatalf("boundedReason(%q) = %q, want unchanged", s, got)
		}
	})
}
