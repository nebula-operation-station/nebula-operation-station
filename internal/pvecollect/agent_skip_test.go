// SPDX-License-Identifier: AGPL-3.0-or-later

package pvecollect

import (
	"context"
	"sync"
	"testing"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// A truncated task window keeps its tasks but marks the observation
// incomplete.
func TestPollOnceTruncatedTasksMarkIncomplete(t *testing.T) {
	fr := &fakeReader{remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")}, readFn: func(req *pb.ReadPVERequest) (*pb.ReadPVEResponse, error) {
		if req.Method == pb.PVEReadMethod_PVE_READ_METHOD_TASKS {
			return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_Tasks{Tasks: &pb.PVETasks{
				State: pb.PVEDatasetState_PVE_DATASET_STATE_AVAILABLE, Truncated: true,
			}}}, nil
		}
		return defaultReadFn(req)
	}}
	c, spool, _ := newTestCollector(t, fr)
	if _, err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	names, err := spool.List(context.Background())
	if err != nil || len(names) != 1 {
		t.Fatalf("spool = %v %v", names, err)
	}
	obs, err := spool.ReadFile(context.Background(), names[0])
	if err != nil {
		t.Fatal(err)
	}
	if obs.Complete || !obs.Tasks.IsAvailable() {
		t.Fatalf("complete = %v tasks = %v", obs.Complete, obs.Tasks.State)
	}
}

// Containers and stopped VMs have no guest agent to ask: the collector does
// not request GUEST_AGENT for them, reports the dataset as not applicable
// and the observation stays complete.
func TestPollOnceSkipsAgentReadForContainersAndStoppedGuests(t *testing.T) {
	var mu sync.Mutex
	agentReads := map[uint64]int{}
	fr := &fakeReader{remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")}, readFn: func(req *pb.ReadPVERequest) (*pb.ReadPVEResponse, error) {
		switch req.Method {
		case pb.PVEReadMethod_PVE_READ_METHOD_GUESTS:
			return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_Guests{Guests: &pb.PVEGuests{
				State: pb.PVEDatasetState_PVE_DATASET_STATE_AVAILABLE,
				Guests: []*pb.PVEGuest{
					{Vmid: 100, Kind: "qemu", Node: "p1", Name: "vm100", Status: "running", Generation: 1},
					{Vmid: 101, Kind: "qemu", Node: "p1", Name: "vm101", Status: "stopped", Generation: 1},
					{Vmid: 200, Kind: "lxc", Node: "p1", Name: "ct200", Status: "running", Generation: 1},
				},
			}}}, nil
		case pb.PVEReadMethod_PVE_READ_METHOD_GUEST_AGENT:
			mu.Lock()
			agentReads[req.GetGuest().GetVmid()]++
			mu.Unlock()
		}
		return defaultReadFn(req)
	}}
	c, spool, _ := newTestCollector(t, fr)
	if _, err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if len(agentReads) != 1 || agentReads[100] != 1 {
		t.Fatalf("agent reads = %v, want only guest 100", agentReads)
	}
	names, err := spool.List(context.Background())
	if err != nil || len(names) != 1 {
		t.Fatalf("spool = %v %v", names, err)
	}
	obs, err := spool.ReadFile(context.Background(), names[0])
	if err != nil {
		t.Fatal(err)
	}
	if !obs.Complete {
		t.Fatalf("observation incomplete: %q", obs.Reason)
	}
	for _, g := range obs.Guests.Value {
		switch g.VMID {
		case 100:
			if !g.Agent.IsAvailable() {
				t.Fatalf("running VM agent = %+v", g.Agent)
			}
		default:
			if g.Agent.IsAvailable() || g.Agent.Reason != reasonAgentNotApplicable {
				t.Fatalf("guest %d agent = %+v", g.VMID, g.Agent)
			}
		}
	}
}
