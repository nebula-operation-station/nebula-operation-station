// SPDX-License-Identifier: AGPL-3.0-or-later
package pvecollect

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"google.golang.org/grpc"
)

// fakeReader is a test double for the executor read surface. It records call
// counts and peak ReadPVE concurrency and answers from a per-method table.
type fakeReader struct {
	mu        sync.Mutex
	remotes   []*pb.PVERemoteInfo
	readFn    func(req *pb.ReadPVERequest) (*pb.ReadPVEResponse, error)
	block     time.Duration
	listCalls int
	readCalls int
	current   int
	peak      int
}

func (f *fakeReader) ListPVERemotes(_ context.Context, _ *pb.ListPVERemotesRequest, _ ...grpc.CallOption) (*pb.ListPVERemotesResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	return &pb.ListPVERemotesResponse{Remotes: f.remotes}, nil
}

func (f *fakeReader) ReadPVE(_ context.Context, req *pb.ReadPVERequest, _ ...grpc.CallOption) (*pb.ReadPVEResponse, error) {
	f.mu.Lock()
	f.readCalls++
	f.current++
	if f.current > f.peak {
		f.peak = f.current
	}
	fn := f.readFn
	block := f.block
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.current--
		f.mu.Unlock()
	}()
	if block > 0 {
		time.Sleep(block)
	}
	if fn == nil {
		return nil, errors.New("fakeReader: no readFn")
	}
	return fn(req)
}

// defaultReadFn answers every typed read with a small valid payload.
func defaultReadFn(req *pb.ReadPVERequest) (*pb.ReadPVEResponse, error) {
	avail := pb.PVEDatasetState_PVE_DATASET_STATE_AVAILABLE
	switch req.Method {
	case pb.PVEReadMethod_PVE_READ_METHOD_NODES:
		return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_Nodes{Nodes: &pb.PVENodes{
			State: avail,
			Nodes: []*pb.PVENode{{
				Node:          "p1",
				Status:        "online",
				UptimeSeconds: 100,
				CpuCount:      4,
				RamTotalBytes: 8 * 1024 * 1024 * 1024,
				RamUsedBytes:  2 * 1024 * 1024 * 1024,
				Details:       &pb.PVENodeDetails{State: avail, PveVersion: "8.3.1", KernelVersion: "6.8.0"},
			}},
		}}}, nil
	case pb.PVEReadMethod_PVE_READ_METHOD_GUESTS:
		return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_Guests{Guests: &pb.PVEGuests{
			State: avail,
			Guests: []*pb.PVEGuest{{
				Vmid: 100, Kind: "qemu", Node: "p1", Name: "vm100",
				Status: "running", Generation: 1,
			}},
		}}}, nil
	case pb.PVEReadMethod_PVE_READ_METHOD_GUEST_CONFIG:
		return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_GuestConfig{GuestConfig: &pb.PVEGuestConfig{
			State: avail, Vmid: req.GetGuest().Vmid, CpuCount: 2, RamBytes: 4 * 1024 * 1024 * 1024,
			Disks: []*pb.PVEDisk{{Storage: "local", Volume: "local:vm-100-disk-0", Format: "qcow2", SizeBytes: 10 * 1024 * 1024 * 1024}},
		}}}, nil
	case pb.PVEReadMethod_PVE_READ_METHOD_GUEST_AGENT:
		return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_GuestAgent{GuestAgent: &pb.PVEGuestAgent{
			State: avail, Vmid: req.GetGuest().Vmid, Hostname: "vm100", Os: "debian 12",
			Filesystems: []*pb.PVEFilesystem{{MountPoint: "/", Fstype: "ext4", SizeBytes: 10 * 1024 * 1024 * 1024, UsedBytes: 1024 * 1024 * 1024}},
		}}}, nil
	case pb.PVEReadMethod_PVE_READ_METHOD_SNAPSHOTS:
		return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_Snapshots{Snapshots: &pb.PVESnapshots{
			State: avail, Vmid: req.GetGuest().Vmid,
		}}}, nil
	case pb.PVEReadMethod_PVE_READ_METHOD_BACKUPS:
		return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_Backups{Backups: &pb.PVEBackups{
			State: avail, Vmid: req.GetGuest().Vmid,
		}}}, nil
	case pb.PVEReadMethod_PVE_READ_METHOD_STORAGE:
		return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_Storages{Storages: &pb.PVEStorages{
			State:    avail,
			Storages: []*pb.PVEStorage{{Name: "local", Type: "dir", Content: []string{"images"}, Active: true, SizeBytes: 100 * 1024 * 1024 * 1024, FreeBytes: 50 * 1024 * 1024 * 1024}},
		}}}, nil
	case pb.PVEReadMethod_PVE_READ_METHOD_CLUSTER:
		return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_Cluster{Cluster: &pb.PVECluster{
			State: avail, Quorum: "quorate",
			Nodes: []*pb.PVEClusterNode{{Node: "p1", Status: "online", Vote: true}},
		}}}, nil
	case pb.PVEReadMethod_PVE_READ_METHOD_TASKS:
		return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_Tasks{Tasks: &pb.PVETasks{
			State: avail,
		}}}, nil
	}
	return nil, fmt.Errorf("fakeReader: unexpected method %v", req.Method)
}

// newTestCollector builds a collector over a temp spool with a deterministic
// clock and zero jitter.
func newTestCollector(t *testing.T, fr Reader) (*Collector, *Spool, *time.Time) {
	t.Helper()
	dir := t.TempDir()
	spool, err := NewSpool(dir)
	if err != nil {
		t.Fatalf("NewSpool: %v", err)
	}
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	nowPtr := &now
	c, err := New(fr, spool, Config{
		Now:                func() time.Time { return *nowPtr },
		Jitter:             func() float64 { return 0 },
		Interval:           time.Minute,
		InitialBackoff:     time.Minute,
		MaxBackoff:         15 * time.Minute,
		MaxConcurrentReads: 2,
		ReadTimeout:        time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, spool, nowPtr
}

func activeRemote(id string) *pb.PVERemoteInfo {
	return &pb.PVERemoteInfo{RemoteId: id, State: pb.PVERemoteState_PVE_REMOTE_STATE_ACTIVE}
}

func TestPollOnceWritesObservation(t *testing.T) {
	fr := &fakeReader{remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")}, readFn: defaultReadFn}
	c, spool, _ := newTestCollector(t, fr)

	rep, err := c.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if rep.Polled != 1 || rep.Failed != 0 || rep.Remotes != 1 {
		t.Fatalf("report = %+v, want 1 polled, 0 failed", rep)
	}
	names, err := spool.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 1 {
		t.Fatalf("spool has %d files, want 1", len(names))
	}
	obs, err := spool.ReadFile(context.Background(), names[0])
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if obs.RemoteID != "remote-a" || !obs.Complete {
		t.Fatalf("observation = remote %q complete %v, want remote-a complete", obs.RemoteID, obs.Complete)
	}
	if !obs.Nodes.IsAvailable() || len(obs.Nodes.Value) != 1 {
		t.Fatalf("nodes dataset = %+v, want 1 node", obs.Nodes)
	}
	if !obs.Guests.IsAvailable() || len(obs.Guests.Value) != 1 {
		t.Fatalf("guests dataset = %+v, want 1 guest", obs.Guests)
	}
	g := obs.Guests.Value[0]
	if !g.Config.IsAvailable() || !g.Agent.IsAvailable() || !g.Snapshots.IsAvailable() || !g.Backups.IsAvailable() {
		t.Fatalf("guest detail datasets not all available: config=%v agent=%v snaps=%v backups=%v",
			g.Config.State, g.Agent.State, g.Snapshots.State, g.Backups.State)
	}
}

func TestPollOnceSkipsInactiveAndBackedOff(t *testing.T) {
	fr := &fakeReader{remotes: []*pb.PVERemoteInfo{
		activeRemote("remote-a"),
		{RemoteId: "remote-b", State: pb.PVERemoteState_PVE_REMOTE_STATE_BLOCKED},
	}, readFn: defaultReadFn}
	c, _, now := newTestCollector(t, fr)

	rep, err := c.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if rep.Polled != 1 || rep.Skipped != 1 {
		t.Fatalf("report = %+v, want 1 polled 1 skipped", rep)
	}

	// Immediately after, remote-a is not due again (interval 60 s).
	rep, err = c.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if rep.Polled != 0 || rep.Skipped != 2 {
		t.Fatalf("second pass = %+v, want 0 polled 2 skipped", rep)
	}

	// Advance past the interval; remote-a is due again.
	*now = now.Add(time.Minute)
	rep, err = c.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if rep.Polled != 1 || rep.Skipped != 1 {
		t.Fatalf("third pass = %+v, want 1 polled 1 skipped", rep)
	}
}

func TestPollOnceBacksOffOnFailure(t *testing.T) {
	fr := &fakeReader{
		remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")},
		readFn:  func(*pb.ReadPVERequest) (*pb.ReadPVEResponse, error) { return nil, errors.New("boom") },
	}
	c, _, now := newTestCollector(t, fr)

	if _, err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	// Within the backoff window the remote is not due.
	*now = now.Add(30 * time.Second)
	rep, err := c.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if rep.Polled != 0 || rep.Skipped != 1 {
		t.Fatalf("pass within backoff = %+v, want 0 polled 1 skipped", rep)
	}
	// After the initial backoff (1 m) it is due again.
	*now = now.Add(45 * time.Second)
	rep, err = c.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if rep.Polled != 1 {
		t.Fatalf("pass after backoff = %+v, want 1 polled", rep)
	}
}

func TestPollOnceBoundedConcurrency(t *testing.T) {
	fr := &fakeReader{remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")}, readFn: defaultReadFn, block: 20 * time.Millisecond}
	c, _, _ := newTestCollector(t, fr)

	if _, err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if fr.peak > 2 {
		t.Fatalf("peak concurrent ReadPVE = %d, want <= 2", fr.peak)
	}
	if fr.peak < 2 {
		t.Fatalf("peak concurrent ReadPVE = %d, want 2 (pool should overlap)", fr.peak)
	}
	// 5 node-scoped reads + 4 per-guest reads for one guest.
	if fr.readCalls != 9 {
		t.Fatalf("ReadPVE calls = %d, want 9", fr.readCalls)
	}
}

func TestPollOnceUnavailableDatasetMarksIncomplete(t *testing.T) {
	unavail := pb.PVEDatasetState_PVE_DATASET_STATE_UNAVAILABLE
	fr := &fakeReader{
		remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")},
		readFn: func(req *pb.ReadPVERequest) (*pb.ReadPVEResponse, error) {
			if req.Method == pb.PVEReadMethod_PVE_READ_METHOD_NODES {
				return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_Nodes{Nodes: &pb.PVENodes{
					State: unavail, Reason: "rate limited",
				}}}, nil
			}
			return defaultReadFn(req)
		},
	}
	c, spool, _ := newTestCollector(t, fr)

	if _, err := c.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	names, _ := spool.List(context.Background())
	if len(names) != 1 {
		t.Fatalf("spool has %d files, want 1", len(names))
	}
	obs, err := spool.ReadFile(context.Background(), names[0])
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if obs.Complete {
		t.Fatal("observation is complete, want incomplete (nodes unavailable)")
	}
	if obs.Nodes.IsAvailable() {
		t.Fatal("nodes dataset available, want unavailable")
	}
	if obs.Nodes.Reason != "rate limited" {
		t.Fatalf("nodes reason = %q, want %q", obs.Nodes.Reason, "rate limited")
	}
}

func TestPollOnceListRemotesError(t *testing.T) {
	c, _, _ := newTestCollector(t, listErrReader{})
	if _, err := c.PollOnce(context.Background()); err == nil {
		t.Fatal("PollOnce returned nil error, want list-remotes error")
	}
}

// listErrReader always fails ListPVERemotes.
type listErrReader struct{}

func (listErrReader) ListPVERemotes(_ context.Context, _ *pb.ListPVERemotesRequest, _ ...grpc.CallOption) (*pb.ListPVERemotesResponse, error) {
	return nil, errors.New("socket refused")
}
func (listErrReader) ReadPVE(_ context.Context, _ *pb.ReadPVERequest, _ ...grpc.CallOption) (*pb.ReadPVEResponse, error) {
	return nil, errors.New("not called")
}
