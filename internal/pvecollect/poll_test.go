// SPDX-License-Identifier: AGPL-3.0-or-later
package pvecollect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
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
	t.Cleanup(func() { spool.Close() })
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

func TestPollOnceSpoolsGuestNICsAndServerImportsWithoutReads(t *testing.T) {
	ctx := context.Background()
	fr := &fakeReader{remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")}}
	fr.readFn = func(req *pb.ReadPVERequest) (*pb.ReadPVEResponse, error) {
		resp, err := defaultReadFn(req)
		if req.Method == pb.PVEReadMethod_PVE_READ_METHOD_GUESTS {
			resp.GetGuests().Guests = append(resp.GetGuests().Guests, &pb.PVEGuest{
				Vmid: 200, Kind: "lxc", Node: "p1", Status: "stopped", Generation: 1,
			})
		}
		if cfg := resp.GetGuestConfig(); cfg != nil {
			cfg.Nics = []*pb.PVEGuestNIC{{Device: "net31", Bridge: "vnet_1", Vlan: 4094, Mac: "02:00:00:00:00:31"},
				{Device: "net0", Bridge: "vmbr0", Vlan: 42, Mac: "02:00:00:00:00:01"}}
			if cfg.Vmid == 200 {
				cfg.Nics = []*pb.PVEGuestNIC{{Device: "net1", Mac: "aa:bb:cc:dd:ee:02"}}
			}
		}
		return resp, err
	}
	c, spool, now := newTestCollector(t, fr)
	rep, err := c.PollOnce(ctx)
	if err != nil || rep.Polled != 1 || rep.Failed != 0 {
		t.Fatalf("poll = %+v, %v", rep, err)
	}
	names, err := spool.ListGuestNet(ctx)
	if err != nil || len(names) != 1 {
		t.Fatalf("guest network files = %v, %v", names, err)
	}
	got, err := spool.ReadGuestNet(ctx, names[0])
	want := GuestNetRecord{Version: GuestNetVersion, Remote: "remote-a", ObservedUnix: now.Unix(), NICs: []GuestNIC{
		{VMID: 100, Kind: pvecontract.GuestQEMU, Index: 0, Bridge: "vmbr0", VLAN: 42, MAC: "02:00:00:00:00:01"},
		{VMID: 100, Kind: pvecontract.GuestQEMU, Index: 31, Bridge: "vnet_1", VLAN: 4094, MAC: "02:00:00:00:00:31"},
		{VMID: 200, Kind: pvecontract.GuestLXC, Index: 1, MAC: "aa:bb:cc:dd:ee:02"},
	}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("record = %+v, %v; want %+v", got, err, want)
	}
	if got.NICs[0].Tap() != "tap100i0" || got.NICs[2].Tap() != "veth200i1" {
		t.Fatal("guest to tap mapping lost")
	}
	// A separate server-side importer consumes only the spool, even when
	// any further executor call would fail.
	reads := fr.readCalls
	fr.readFn = func(*pb.ReadPVERequest) (*pb.ReadPVEResponse, error) {
		t.Error("server attempted an executor read")
		return nil, errors.New("executor unavailable")
	}
	r, err := OpenSpool(spool.root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	sink := &fakeGuestNetSink{}
	im, err := NewGuestNetImporter(r, sink, nil)
	if err != nil {
		t.Fatal(err)
	}
	im.Now = func() time.Time { return *now }
	if report, err := im.ImportOnce(ctx); err != nil || report.Imported != 1 {
		t.Fatalf("import = %+v, %v", report, err)
	}
	if fr.readCalls != reads || len(sink.got) != 1 || !reflect.DeepEqual(sink.got[0], want) {
		t.Fatal("server import changed or reread the collector snapshot")
	}
}

func TestPollOnceRejectsHostileGuestNICsBeforePublishing(t *testing.T) {
	valid := func() *pb.PVEGuestNIC {
		return &pb.PVEGuestNIC{Device: "net0", Bridge: "vmbr0", Vlan: 42, Mac: "02:00:00:00:00:01"}
	}
	cases := map[string]func(*pb.PVEGuestConfig){
		"nil nic":               func(c *pb.PVEGuestConfig) { c.Nics = []*pb.PVEGuestNIC{nil} },
		"too many nics":         func(c *pb.PVEGuestConfig) { c.Nics = make([]*pb.PVEGuestNIC, 33) },
		"duplicate device":      func(c *pb.PVEGuestConfig) { c.Nics = []*pb.PVEGuestNIC{valid(), valid()} },
		"negative index":        func(c *pb.PVEGuestConfig) { c.Nics[0].Device = "net-1" },
		"index overflow":        func(c *pb.PVEGuestConfig) { c.Nics[0].Device = "net32" },
		"index alias":           func(c *pb.PVEGuestConfig) { c.Nics[0].Device = "net00" },
		"oversized index":       func(c *pb.PVEGuestConfig) { c.Nics[0].Device = "net" + strings.Repeat("1", 1024) },
		"hostile bridge":        func(c *pb.PVEGuestConfig) { c.Nics[0].Bridge = "<script>" },
		"oversized bridge":      func(c *pb.PVEGuestConfig) { c.Nics[0].Bridge = strings.Repeat("b", 16) },
		"invalid utf8":          func(c *pb.PVEGuestConfig) { c.Nics[0].Bridge = "br\xff" },
		"vlan overflow":         func(c *pb.PVEGuestConfig) { c.Nics[0].Vlan = 4095 },
		"vlan integer overflow": func(c *pb.PVEGuestConfig) { c.Nics[0].Vlan = ^uint32(0) },
		"empty mac":             func(c *pb.PVEGuestConfig) { c.Nics[0].Mac = "" },
		"zero mac":              func(c *pb.PVEGuestConfig) { c.Nics[0].Mac = "00:00:00:00:00:00" },
		"multicast mac":         func(c *pb.PVEGuestConfig) { c.Nics[0].Mac = "01:00:00:00:00:01" },
		"uppercase mac":         func(c *pb.PVEGuestConfig) { c.Nics[0].Mac = "AA:BB:CC:DD:EE:01" },
		"hostile mac":           func(c *pb.PVEGuestConfig) { c.Nics[0].Mac = "<script>" },
		"oversized mac":         func(c *pb.PVEGuestConfig) { c.Nics[0].Mac = strings.Repeat("a", 1024) },
		"wrong guest":           func(c *pb.PVEGuestConfig) { c.Vmid++ },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fr := &fakeReader{remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")}}
			fr.readFn = func(req *pb.ReadPVERequest) (*pb.ReadPVEResponse, error) {
				resp, err := defaultReadFn(req)
				if cfg := resp.GetGuestConfig(); cfg != nil {
					cfg.Nics = []*pb.PVEGuestNIC{valid()}
					mutate(cfg)
				}
				return resp, err
			}
			c, spool, _ := newTestCollector(t, fr)
			rep, err := c.PollOnce(context.Background())
			if err != nil || rep.Failed != 1 || rep.Polled != 0 {
				t.Fatalf("poll = %+v, %v; want rejection", rep, err)
			}
			if strings.Contains(strings.Join(rep.Errors, " "), "<script>") {
				t.Fatal("hostile text escaped into report")
			}
			if names, err := spool.ListGuestNet(context.Background()); err != nil || len(names) != 0 {
				t.Fatalf("invalid NICs were published: %v, %v", names, err)
			}
			if names, err := spool.List(context.Background()); err != nil || len(names) != 0 {
				t.Fatalf("invalid collection was published: %v, %v", names, err)
			}
		})
	}
}

func TestPollOnceGuestNetSnapshotAvailability(t *testing.T) {
	for _, mode := range []string{"empty nics", "no guests", "unavailable config", "config error", "nil config", "unavailable guests", "agent error"} {
		t.Run(mode, func(t *testing.T) {
			fr := &fakeReader{remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")}}
			fr.readFn = func(req *pb.ReadPVERequest) (*pb.ReadPVEResponse, error) {
				resp, err := defaultReadFn(req)
				if req.Method == pb.PVEReadMethod_PVE_READ_METHOD_GUESTS {
					if mode == "no guests" {
						resp.GetGuests().Guests = nil
					}
					if mode == "unavailable guests" {
						resp.GetGuests().State = pb.PVEDatasetState_PVE_DATASET_STATE_UNAVAILABLE
						resp.GetGuests().Reason = "unavailable"
					}
				}
				if cfg := resp.GetGuestConfig(); cfg != nil {
					switch mode {
					case "unavailable config":
						cfg.State = pb.PVEDatasetState_PVE_DATASET_STATE_UNAVAILABLE
						cfg.Reason = "unavailable"
					case "config error":
						return nil, errors.New("config unavailable")
					case "nil config":
						return nil, nil
					}
				}
				if mode == "agent error" && req.Method == pb.PVEReadMethod_PVE_READ_METHOD_GUEST_AGENT {
					return nil, errors.New("agent unavailable")
				}
				return resp, err
			}
			c, spool, _ := newTestCollector(t, fr)
			if _, err := c.PollOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			names, err := spool.ListGuestNet(context.Background())
			want := 0
			if mode == "empty nics" || mode == "no guests" || mode == "agent error" {
				want = 1
			}
			if err != nil || len(names) != want {
				t.Fatalf("guest network files = %v, %v; want %d", names, err, want)
			}
			if want == 1 {
				rec, err := spool.ReadGuestNet(context.Background(), names[0])
				if err != nil || len(rec.NICs) != 0 {
					t.Fatalf("empty snapshot = %+v, %v", rec, err)
				}
			}
		})
	}
}

func TestPollOnceGuestNetWriteFailureFailsPoll(t *testing.T) {
	fr := &fakeReader{remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")}, readFn: defaultReadFn}
	c, spool, _ := newTestCollector(t, fr)
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(spool.root, guestNetDirName)); err != nil {
		t.Fatal(err)
	}
	rep, err := c.PollOnce(context.Background())
	if err != nil || rep.Failed != 1 || rep.Polled != 0 {
		t.Fatalf("poll = %+v, %v; want failed guest network write", rep, err)
	}
	if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
		t.Fatalf("symlink target was written: %v, %v", entries, err)
	}
}

func TestPollOnceUnavailableConfigPreservesPreviousGuestNetSnapshot(t *testing.T) {
	ctx := context.Background()
	fr := &fakeReader{remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")}}
	unavailable := false
	fr.readFn = func(req *pb.ReadPVERequest) (*pb.ReadPVEResponse, error) {
		resp, err := defaultReadFn(req)
		if guests := resp.GetGuests(); guests != nil {
			guests.Guests = append(guests.Guests, &pb.PVEGuest{
				Vmid: 200, Kind: "lxc", Node: "p1", Status: "stopped", Generation: 1,
			})
		}
		if cfg := resp.GetGuestConfig(); cfg != nil {
			cfg.Nics = []*pb.PVEGuestNIC{{Device: "net0", Bridge: "vmbr0", Vlan: 42, Mac: "02:00:00:00:00:01"}}
			if unavailable && cfg.Vmid == 200 {
				cfg.State = pb.PVEDatasetState_PVE_DATASET_STATE_UNAVAILABLE
				cfg.Reason = "unavailable"
			}
		}
		return resp, err
	}
	c, spool, now := newTestCollector(t, fr)
	if rep, err := c.PollOnce(ctx); err != nil || rep.Polled != 1 {
		t.Fatalf("initial poll = %+v, %v", rep, err)
	}
	names, err := spool.ListGuestNet(ctx)
	if err != nil || len(names) != 1 {
		t.Fatalf("initial snapshots = %v, %v", names, err)
	}
	unavailable = true
	*now = now.Add(time.Minute)
	if rep, err := c.PollOnce(ctx); err != nil || rep.Failed != 1 {
		t.Fatalf("unavailable poll = %+v, %v", rep, err)
	}
	remaining, err := spool.ListGuestNet(ctx)
	if err != nil || !reflect.DeepEqual(names, remaining) {
		t.Fatalf("partial snapshot replaced previous facts: %v, %v", remaining, err)
	}
	rec, err := spool.ReadGuestNet(ctx, remaining[0])
	if err != nil || len(rec.NICs) != 2 {
		t.Fatalf("previous snapshot = %+v, %v", rec, err)
	}
}

func TestPollOnceGuestNetTotalNICLimit(t *testing.T) {
	for _, count := range []int{MaxGuestNetNICs / MaxGuestNetNICIndex, MaxGuestNetNICs/MaxGuestNetNICIndex + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			fr := &fakeReader{remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")}}
			fr.readFn = func(req *pb.ReadPVERequest) (*pb.ReadPVEResponse, error) {
				resp, err := defaultReadFn(req)
				if guests := resp.GetGuests(); guests != nil {
					guests.Guests = nil
					for i := range count {
						guests.Guests = append(guests.Guests, &pb.PVEGuest{
							Vmid: uint64(100 + i), Kind: "qemu", Node: "p1", Status: "stopped", Generation: 1,
						})
					}
				}
				if cfg := resp.GetGuestConfig(); cfg != nil {
					for i := range MaxGuestNetNICIndex {
						cfg.Nics = append(cfg.Nics, &pb.PVEGuestNIC{
							Device: fmt.Sprintf("net%d", i), Mac: "02:00:00:00:00:01",
						})
					}
				}
				return resp, err
			}
			c, spool, _ := newTestCollector(t, fr)
			rep, err := c.PollOnce(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			names, err := spool.ListGuestNet(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if count*MaxGuestNetNICIndex > MaxGuestNetNICs {
				if rep.Failed != 1 || len(names) != 0 {
					t.Fatalf("excess total accepted: %+v, %v", rep, names)
				}
			} else {
				if rep.Polled != 1 || len(names) != 1 {
					t.Fatalf("maximum total rejected: %+v, %v", rep, names)
				}
				rec, err := spool.ReadGuestNet(context.Background(), names[0])
				if err != nil || len(rec.NICs) != MaxGuestNetNICs {
					t.Fatalf("maximum snapshot count=%d, %v", len(rec.NICs), err)
				}
			}
		})
	}
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
	if rep.Failed != 1 || rep.Polled != 0 {
		t.Fatalf("pass after backoff = %+v, want 1 failed", rep)
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

// Containers and stopped VMs cannot have a guest agent: the collector does
// not ask for one, labels the dataset not applicable, and the page stays
// complete.
func TestPollOnceSkipsAgentReadsThatCannotApply(t *testing.T) {
	var mu sync.Mutex
	agentReads := map[uint64]int{}
	fr := &fakeReader{remotes: []*pb.PVERemoteInfo{activeRemote("remote-a")}, readFn: func(req *pb.ReadPVERequest) (*pb.ReadPVEResponse, error) {
		switch req.Method {
		case pb.PVEReadMethod_PVE_READ_METHOD_GUESTS:
			return &pb.ReadPVEResponse{Payload: &pb.ReadPVEResponse_Guests{Guests: &pb.PVEGuests{
				State: pb.PVEDatasetState_PVE_DATASET_STATE_AVAILABLE,
				Guests: []*pb.PVEGuest{
					{Vmid: 100, Kind: "qemu", Node: "p1", Status: "running", Generation: 1},
					{Vmid: 101, Kind: "qemu", Node: "p1", Status: "stopped", Generation: 1},
					{Vmid: 200, Kind: "lxc", Node: "p1", Status: "running", Generation: 1},
					{Vmid: 102, Kind: "qemu", Node: "p1", Status: "unknown", Generation: 1},
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
	if len(agentReads) != 2 || agentReads[100] != 1 || agentReads[102] != 1 {
		t.Fatalf("agent reads = %v, want guests 100 and 102 (unknown status is not proof of absence)", agentReads)
	}
	names, err := spool.List(context.Background())
	if err != nil || len(names) != 1 {
		t.Fatalf("spool: %v %v", names, err)
	}
	obs, err := spool.ReadFile(context.Background(), names[0])
	if err != nil {
		t.Fatal(err)
	}
	if !obs.Complete {
		t.Fatalf("observation incomplete: %q", obs.Reason)
	}
	want := map[uint64]string{100: "", 101: reasonAgentNotRunning, 102: "", 200: reasonAgentContainer}
	for _, g := range obs.Guests.Value {
		if g.Agent.Reason != want[g.VMID] || g.Agent.IsAvailable() != (g.VMID == 100 || g.VMID == 102) {
			t.Fatalf("guest %d agent = %+v", g.VMID, g.Agent)
		}
	}
}
