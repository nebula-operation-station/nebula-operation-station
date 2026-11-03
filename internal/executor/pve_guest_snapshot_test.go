// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// snapClient is a fake PVE client with the snapshot surface. It embeds the
// power fake for the guest state and task handling.
type snapClient struct {
	*powerClient
	smu       sync.Mutex
	config    map[string]string
	storages  []pveapi.Storage
	snapshots []pveapi.Snapshot
	factReads int
	// onFacts, if set, may change the facts before read n is answered.
	onFacts    func(n int, c *snapClient)
	snapSteps  []PveMutationStep
	dispatchFn func(step PveMutationStep) (string, error)
}

func (c *snapClient) SnapshotFacts(_ context.Context, _ executordb.PveRemote, _, _ string, _ uint64, _ pveapi.TokenSupplier) (PveSnapshotFacts, error) {
	c.smu.Lock()
	defer c.smu.Unlock()
	c.factReads++
	if c.onFacts != nil {
		c.onFacts(c.factReads, c)
	}
	cfg := map[string]string{}
	for k, v := range c.config {
		cfg[k] = v
	}
	return PveSnapshotFacts{Config: cfg, Storages: append([]pveapi.Storage(nil), c.storages...), StoragesComplete: true,
		Snapshots: append([]pveapi.Snapshot(nil), c.snapshots...), SnapshotsComplete: true}, nil
}

func (c *snapClient) DispatchSnapshot(_ context.Context, _ executordb.PveRemote, node string, step PveMutationStep, _, _ pveapi.TokenSupplier) (string, error) {
	c.smu.Lock()
	c.snapSteps = append(c.snapSteps, step)
	n := len(c.snapSteps)
	fn := c.dispatchFn
	c.smu.Unlock()
	if fn != nil {
		return fn(step)
	}
	tt, _ := GuestSnapshotStepTaskType(step.Method)
	id, _ := GuestSnapshotStepTaskID(step)
	return testTaskUPID(node, time.Now(), tt, id, mutActionUser, n), nil
}

func (c *snapClient) sent() []PveMutationStep {
	c.smu.Lock()
	defer c.smu.Unlock()
	return append([]PveMutationStep(nil), c.snapSteps...)
}

func (c *snapClient) set(f func(c *snapClient)) {
	c.smu.Lock()
	defer c.smu.Unlock()
	f(c)
}

type snapEnv struct {
	*powerEnv
	sc *snapClient
	g  *PveGuestSnapshot
}

func newSnapEnv(t *testing.T, kind string) *snapEnv {
	t.Helper()
	pe := newPowerEnv(t, kind)
	sc := &snapClient{powerClient: pe.client,
		config: map[string]string{"scsi0": "local-zfs:vm-101-disk-0,size=32G", "ide2": "local:iso/x.iso,media=cdrom",
			"efidisk0": "local-zfs:vm-101-disk-1,size=1M"},
		storages: []pveapi.Storage{
			{ID: "local-zfs", Type: "zfspool", Active: true},
			{ID: "local", Type: "dir", Active: true},
			{ID: "local-lvm", Type: "lvm", Active: true},
			{ID: "nfs-raw", Type: "dir", Format: "raw", Active: true},
			{ID: "down", Type: "zfspool", Active: false},
			{ID: "cephfs", Type: "cephfs", Active: true},
		},
		snapshots: []pveapi.Snapshot{
			{Name: "base", SnapTimeUnix: 1700000000},
			{Name: "pre-upgrade", Parent: "base", SnapTimeUnix: 1700001000, HasVMState: kind == permit.ProviderKindQemu},
		}}
	if kind == permit.ProviderKindLXC {
		sc.config = map[string]string{"rootfs": "local-zfs:subvol-101-disk-0,size=8G"}
	}
	e := &snapEnv{powerEnv: pe, sc: sc}
	e.restartSnap()
	return e
}

// restartSnap rebuilds the authority with the snapshot floor and the
// engine over the snapshot fake.
func (e *snapEnv) restartSnap() {
	e.t.Helper()
	e.restart()
	next, err := riskpolicy.New(e.crit)
	if err != nil {
		e.t.Fatal(err)
	}
	m := e.powerEnv.g.Mutations
	m.Client = e.sc
	bindings := &PveGuestPowerBindings{}
	floor := GuestSnapshotRiskFloor{Next: next, Criticality: e.crit, Bindings: bindings,
		Linked: func(_ canonical.Request, t canonical.Target) ([]canonical.Target, error) {
			return e.linked[t.HostID], nil
		}}
	e.g = &PveGuestSnapshot{Mutations: m, Bindings: bindings, Floor: floor}
}

var snapExecSeq int

func (e *snapEnv) propose(req PveGuestSnapshotRequest) (permit.Permit, error) {
	snapExecSeq++
	id := fmt.Sprintf("00000000-0000-4000-c000-%012d", snapExecSeq)
	return e.g.Propose(context.Background(), req, id, time.Now().Add(time.Hour))
}

func (e *snapEnv) approve(req PveGuestSnapshotRequest) PveGuestSnapshotRequest {
	e.t.Helper()
	p, err := e.propose(req)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.auth.ApproveCLI(p.Digest, 0, "admin"); err != nil {
		e.t.Fatal(err)
	}
	req.Digest = p.Digest
	return req
}

func snapReq(kind, op, name string) PveGuestSnapshotRequest {
	return PveGuestSnapshotRequest{RemoteID: mutRemote, Kind: kind, Node: "pve1", VMID: 101, Op: op, Name: name}
}

// expect returns req with the identity of the fake's snapshot name.
func (e *snapEnv) expect(req PveGuestSnapshotRequest) PveGuestSnapshotRequest {
	e.t.Helper()
	for _, s := range e.sc.snapshots {
		if s.Name == req.Name {
			req.Expect = &PveSnapshotIdentity{Name: s.Name, SnapTimeUnix: s.SnapTimeUnix, Parent: s.Parent, VMState: s.HasVMState}
			return req
		}
	}
	e.t.Fatalf("no snapshot %s", req.Name)
	return req
}

func boundParams(t *testing.T, p permit.Permit) pveSnapshotParams {
	t.Helper()
	var doc struct {
		Parameters pveSnapshotParams `json:"parameters"`
	}
	if err := json.Unmarshal(p.Parameters, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Parameters
}

func TestGuestSnapshotRiskPerOpAndCriticality(t *testing.T) {
	M, H, C := canonical.RiskMedium, canonical.RiskHigh, canonical.RiskCritical
	cases := []struct {
		name                string
		op, snap            string
		guest, node, remote canonical.Risk
		want                canonical.Risk
	}{
		{"create base", PveSnapshotCreate, "new1", M, M, M, M},
		{"delete base", PveSnapshotDelete, "base", M, M, M, H},
		{"rollback base", PveSnapshotRollback, "base", M, M, M, H},
		{"low records do not lower", PveSnapshotCreate, "new1", canonical.RiskLow, canonical.RiskLow, canonical.RiskLow, M},
		{"guest critical raises create", PveSnapshotCreate, "new1", C, M, M, C},
		{"node high raises create", PveSnapshotCreate, "new1", M, H, M, H},
		{"remote critical raises delete", PveSnapshotDelete, "base", M, M, C, C},
		{"unknown guest", PveSnapshotCreate, "new1", "", M, M, H},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newSnapEnv(t, "qemu")
			e.record("qemu", 101, c.guest, c.node, c.remote)
			p, err := e.propose(snapReq("qemu", c.op, c.snap))
			if err != nil {
				t.Fatal(err)
			}
			if p.Request.RiskClass != c.want {
				t.Fatalf("risk %s, want %s", p.Request.RiskClass, c.want)
			}
		})
	}
}

func TestGuestSnapshotRiskFloorFailsClosed(t *testing.T) {
	e := newSnapEnv(t, "qemu")
	next, _ := riskpolicy.New(e.crit)
	f := GuestSnapshotRiskFloor{Next: next, Criticality: e.crit, Bindings: e.g.Bindings,
		Linked: func(canonical.Request, canonical.Target) ([]canonical.Target, error) { return nil, nil }}
	rq := canonical.Request{ActionID: PveGuestSnapshotAction, ParametersHash: strings.Repeat("ab", 32),
		ArtifactSHA256: sha256Hex(pveSnapshotArtifact(PveSnapshotCreate))}
	if r, _, err := f.MinimumRisk(rq, nil); err != nil || r != canonical.RiskHigh {
		t.Fatalf("unbound: %s %v", r, err)
	}
	f.Bindings = nil
	if r, _, err := f.MinimumRisk(rq, nil); err != nil || r != canonical.RiskHigh {
		t.Fatalf("no bindings: %s %v", r, err)
	}
}

func TestGuestSnapshotRequestValidation(t *testing.T) {
	e := newSnapEnv(t, "lxc")
	bad := []PveGuestSnapshotRequest{
		func() PveGuestSnapshotRequest {
			r := snapReq("lxc", PveSnapshotCreate, "x1")
			r.VMState = true
			return r
		}(),
		snapReq("lxc", "prune", "x1"),
		snapReq("lxc", PveSnapshotCreate, "current"),
		snapReq("lxc", PveSnapshotCreate, "1abc"),
		snapReq("lxc", PveSnapshotCreate, "a b"),
		snapReq("lxc", PveSnapshotCreate, strings.Repeat("a", 41)),
		snapReq("lxc", PveSnapshotDelete, ""),
		snapReq("lxc", PveSnapshotDelete, "base*"),
		func() PveGuestSnapshotRequest { r := snapReq("lxc", PveSnapshotCreate, "x1"); r.Start = true; return r }(),
		func() PveGuestSnapshotRequest {
			r := snapReq("lxc", PveSnapshotCreate, "x1")
			r.Expect = &PveSnapshotIdentity{Name: "x1"}
			return r
		}(),
		func() PveGuestSnapshotRequest {
			r := snapReq("lxc", PveSnapshotDelete, "base")
			r.Start = true
			return r
		}(),
	}
	for i, r := range bad {
		if _, err := e.propose(r); !errors.Is(err, ErrPveSnapshotRequest) {
			t.Fatalf("%d: propose %v", i, err)
		}
	}
	// A run of delete or rollback must name the approved identity.
	for _, op := range []string{PveSnapshotDelete, PveSnapshotRollback} {
		if _, err := e.g.Run(context.Background(), snapReq("lxc", op, "base")); !errors.Is(err, ErrPveSnapshotRequest) {
			t.Fatalf("%s run without identity: %v", op, err)
		}
	}
	if e.sc.factReads != 0 || len(e.sc.sent()) != 0 {
		t.Fatalf("malformed requests caused I/O: reads %d sent %d", e.sc.factReads, len(e.sc.sent()))
	}
}

func TestGuestSnapshotCreateBindsDiskSetAndRAMChoice(t *testing.T) {
	e := newSnapEnv(t, "qemu")
	req := snapReq("qemu", PveSnapshotCreate, "before-patch")
	req.VMState = true
	p, err := e.propose(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.auth.ApproveCLI(p.Digest, 0, "admin"); err != nil {
		t.Fatal(err)
	}
	params := boundParams(t, p)
	if !params.VMState || params.Name != "before-patch" || params.Op != PveSnapshotCreate {
		t.Fatalf("params %+v", params)
	}
	if len(params.Disks) != 2 || params.Disks[0].Key != "efidisk0" || params.Disks[1].Key != "scsi0" ||
		params.Disks[1].Volume != "local-zfs:vm-101-disk-0" || params.Disks[1].StorageType != "zfspool" {
		t.Fatalf("disk set %+v (the CD-ROM is not part of it)", params.Disks)
	}
	// The other RAM choice is another approval.
	other := req
	other.Digest, other.VMState = p.Digest, false
	if _, err := e.g.Run(context.Background(), other); !errors.Is(err, ErrPveMutationDenied) {
		t.Fatalf("other vmstate: %v", err)
	}
	req.Digest = p.Digest
	res, err := e.g.Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	sent := e.sc.sent()
	if len(sent) != 1 || sent[0].Method != "snapshot.qemu.create" || len(res.Steps) != 1 || res.Steps[0].TaskType != "qmsnapshot" {
		t.Fatalf("sent %+v steps %+v", sent, res.Steps)
	}
	var a pveSnapshotStepArgs
	if err := json.Unmarshal(sent[0].Args, &a); err != nil || !a.VMState || a.Name != "before-patch" || a.VMID != 101 {
		t.Fatalf("args %s", sent[0].Args)
	}
}

func TestGuestSnapshotCreateRefusesUnsupportedStorage(t *testing.T) {
	cases := []struct {
		name, kind, key, val string
		want                 error
	}{
		{"lvm thick is unknown", "qemu", "scsi1", "local-lvm:vm-101-disk-2,size=4G", ErrPveSnapshotStorage},
		{"dir raw", "qemu", "virtio0", "local:101/vm-101-disk-0.raw,size=4G", ErrPveSnapshotStorage},
		{"dir storage format raw", "qemu", "sata0", "nfs-raw:101/vm-101-disk-0,size=4G", ErrPveSnapshotStorage},
		{"cephfs", "qemu", "scsi2", "cephfs:vm-101-disk-0,size=4G", ErrPveSnapshotStorage},
		{"inactive storage", "qemu", "scsi3", "down:vm-101-disk-0,size=4G", ErrPveSnapshotStorage},
		{"unlisted storage", "qemu", "scsi4", "gone:vm-101-disk-0,size=4G", ErrPveSnapshotStorage},
		{"passthrough disk", "qemu", "scsi5", "/dev/disk/by-id/ata-X,size=1T", ErrPveSnapshotStorage},
		{"lxc bind mount", "lxc", "mp0", "/srv/data,mp=/data", ErrPveSnapshotStorage},
		{"lxc mount on unknown storage", "lxc", "mp1", "local-lvm:vm-101-disk-1,mp=/x", ErrPveSnapshotStorage},
		{"locked guest", "qemu", "lock", "backup", ErrPveSnapshotState},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newSnapEnv(t, c.kind)
			e.sc.config[c.key] = c.val
			if _, err := e.propose(snapReq(c.kind, PveSnapshotCreate, "s1")); !errors.Is(err, c.want) {
				t.Fatalf("propose: %v, want %v", err, c.want)
			}
			if len(e.sc.sent()) != 0 {
				t.Fatal("dispatched")
			}
		})
	}
	t.Run("dir qcow2 is supported", func(t *testing.T) {
		e := newSnapEnv(t, "qemu")
		e.sc.config["virtio1"] = "local:101/vm-101-disk-3.qcow2,size=4G"
		if _, err := e.propose(snapReq("qemu", PveSnapshotCreate, "s1")); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("storage changed after approval", func(t *testing.T) {
		e := newSnapEnv(t, "qemu")
		req := e.approve(snapReq("qemu", PveSnapshotCreate, "s1"))
		e.sc.set(func(c *snapClient) { c.storages[0].Active = false })
		if _, err := e.g.Run(context.Background(), req); !errors.Is(err, ErrPveSnapshotStorage) {
			t.Fatalf("run: %v", err)
		}
		if len(e.sc.sent()) != 0 {
			t.Fatal("dispatched")
		}
	})
}

func TestGuestSnapshotCreateRefusals(t *testing.T) {
	e := newSnapEnv(t, "qemu")
	// The name exists.
	if _, err := e.propose(snapReq("qemu", PveSnapshotCreate, "base")); !errors.Is(err, ErrPveSnapshotChanged) {
		t.Fatalf("existing name: %v", err)
	}
	// RAM of a stopped guest.
	e.client.statusFn = func(int) string { return "stopped" }
	req := snapReq("qemu", PveSnapshotCreate, "s2")
	req.VMState = true
	if _, err := e.propose(req); !errors.Is(err, ErrPveSnapshotState) {
		t.Fatalf("vmstate on stopped guest: %v", err)
	}
	// A disk added after approval changes the bound disk set.
	e.client.statusFn = nil
	approved := e.approve(snapReq("qemu", PveSnapshotCreate, "s3"))
	e.sc.set(func(c *snapClient) { c.config["scsi9"] = "local-zfs:vm-101-disk-9,size=1G" })
	if _, err := e.g.Run(context.Background(), approved); !errors.Is(err, ErrPveMutationDenied) && !errors.Is(err, ErrPveSnapshotChanged) {
		t.Fatalf("disk set drift: %v", err)
	}
	// The name appearing between authorization and dispatch.
	e.sc.set(func(c *snapClient) { delete(c.config, "scsi9") })
	approved = e.approve(snapReq("qemu", PveSnapshotCreate, "s4"))
	e.sc.set(func(c *snapClient) {
		start := c.factReads
		c.onFacts = func(n int, c *snapClient) {
			if n == start+3 { // prepare, engine pre-authorization, then pre-intent
				c.snapshots = append(c.snapshots, pveapi.Snapshot{Name: "s4", SnapTimeUnix: 1800000000})
			}
		}
	})
	if _, err := e.g.Run(context.Background(), approved); !errors.Is(err, ErrPveSnapshotChanged) {
		t.Fatalf("name raced: %v", err)
	}
	if len(e.sc.sent()) != 0 {
		t.Fatalf("dispatched %d", len(e.sc.sent()))
	}
}

// TestGuestSnapshotIdentityDriftRefused: delete and rollback bind the exact
// snapshot; a snapshot recreated under the same name, a changed parent or
// RAM flag, or one that is gone gets nothing.
func TestGuestSnapshotIdentityDriftRefused(t *testing.T) {
	drifts := map[string]func(s *pveapi.Snapshot){
		"recreated (snaptime)": func(s *pveapi.Snapshot) { s.SnapTimeUnix += 60 },
		"parent changed":       func(s *pveapi.Snapshot) { s.Parent = "" },
		"ram flag changed":     func(s *pveapi.Snapshot) { s.HasVMState = !s.HasVMState },
		"gone":                 func(s *pveapi.Snapshot) { s.Name = "renamed" },
	}
	for _, op := range []string{PveSnapshotDelete, PveSnapshotRollback} {
		for name, drift := range drifts {
			t.Run(op+" "+name, func(t *testing.T) {
				e := newSnapEnv(t, "qemu")
				req := e.expect(e.approve(snapReq("qemu", op, "pre-upgrade")))
				e.sc.set(func(c *snapClient) { drift(&c.snapshots[1]) })
				if _, err := e.g.Run(context.Background(), req); !errors.Is(err, ErrPveSnapshotChanged) {
					t.Fatalf("run: %v", err)
				}
				if len(e.sc.sent()) != 0 {
					t.Fatal("dispatched")
				}
				// The approval is still usable once the exact snapshot is back
				// (nothing was consumed before authorization).
			})
		}
	}
	t.Run("proposal with a stale expectation", func(t *testing.T) {
		e := newSnapEnv(t, "qemu")
		req := e.expect(snapReq("qemu", PveSnapshotDelete, "pre-upgrade"))
		req.Expect.SnapTimeUnix--
		if _, err := e.propose(req); !errors.Is(err, ErrPveSnapshotChanged) {
			t.Fatalf("propose: %v", err)
		}
	})
	t.Run("a different expectation than approved", func(t *testing.T) {
		e := newSnapEnv(t, "qemu")
		req := e.expect(e.approve(snapReq("qemu", PveSnapshotDelete, "pre-upgrade")))
		// The live snapshot was recreated and the caller names the new
		// one: the approval bound the old generation.
		e.sc.set(func(c *snapClient) { c.snapshots[1].SnapTimeUnix = 1800000000 })
		req.Expect.SnapTimeUnix = 1800000000
		if _, err := e.g.Run(context.Background(), req); !errors.Is(err, ErrPveMutationDenied) {
			t.Fatalf("run: %v", err)
		}
		if len(e.sc.sent()) != 0 {
			t.Fatal("dispatched")
		}
	})
}

// TestGuestSnapshotDeleteChangedGenerationRefused: the snapshot is deleted
// and recreated under the same name between authorization and dispatch
// (new snaptime): the pre-intent recheck refuses it and nothing is sent.
func TestGuestSnapshotDeleteChangedGenerationRefused(t *testing.T) {
	e := newSnapEnv(t, "qemu")
	req := e.expect(e.approve(snapReq("qemu", PveSnapshotDelete, "base")))
	e.sc.set(func(c *snapClient) {
		start := c.factReads
		c.onFacts = func(n int, c *snapClient) {
			if n == start+3 {
				c.snapshots[0].SnapTimeUnix = 1700009999
			}
		}
	})
	res, err := e.g.Run(context.Background(), req)
	if !errors.Is(err, ErrPveSnapshotChanged) {
		t.Fatalf("run: %v", err)
	}
	if !res.PermitConsumed || len(e.sc.sent()) != 0 || len(res.Steps) != 0 {
		t.Fatalf("res %+v sent %d", res, len(e.sc.sent()))
	}
	// Unchanged generation: exactly one delete of exactly that snapshot.
	e2 := newSnapEnv(t, "lxc")
	req2 := e2.expect(e2.approve(snapReq("lxc", PveSnapshotDelete, "base")))
	if _, err := e2.g.Run(context.Background(), req2); err != nil {
		t.Fatal(err)
	}
	sent := e2.sc.sent()
	var a pveSnapshotStepArgs
	if len(sent) != 1 || sent[0].Method != "snapshot.lxc.delete" || json.Unmarshal(sent[0].Args, &a) != nil ||
		a.Name != "base" || a.SnapTime != 1700000000 || a.Parent != "" {
		t.Fatalf("sent %+v", sent)
	}
}

func TestGuestSnapshotRollbackBindsStartAndRAM(t *testing.T) {
	e := newSnapEnv(t, "qemu")
	// A disk-only snapshot with start=1 on a running guest.
	req := snapReq("qemu", PveSnapshotRollback, "base")
	req.Start = true
	p, err := e.propose(req)
	if err != nil {
		t.Fatal(err)
	}
	if p.Request.RiskClass != canonical.RiskHigh {
		t.Fatalf("risk %s", p.Request.RiskClass)
	}
	if _, err := e.auth.ApproveCLI(p.Digest, 0, "admin"); err != nil {
		t.Fatal(err)
	}
	params := boundParams(t, p)
	if params.Rollback == nil || !params.Rollback.Start || params.Rollback.RestoresRAM || !params.Rollback.GuestRunsAfter ||
		params.Rollback.StatusBefore != "running" || params.Snapshot == nil || params.Snapshot.SnapTimeUnix != 1700000000 {
		t.Fatalf("params %+v %+v", params.Rollback, params.Snapshot)
	}
	req = e.expect(req)
	req.Digest = p.Digest
	// The other start flag is not approved.
	noStart := req
	noStart.Start = false
	if _, err := e.g.Run(context.Background(), noStart); !errors.Is(err, ErrPveMutationDenied) {
		t.Fatalf("start=0 run: %v", err)
	}
	// The guest stopped since the approval: another side effect, so the
	// bound parameters differ and the permit does not cover it (unused).
	e.client.statusFn = func(int) string { return "stopped" }
	if _, err := e.g.Run(context.Background(), req); !errors.Is(err, ErrPveMutationDenied) || errors.Is(err, ErrPvePermitFinal) {
		t.Fatalf("status drift: %v", err)
	}
	if len(e.sc.sent()) != 0 {
		t.Fatal("dispatched")
	}
	e.client.statusFn = nil
	if _, err := e.g.Run(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	sent := e.sc.sent()
	var a pveSnapshotStepArgs
	if len(sent) != 1 || sent[0].Method != "snapshot.qemu.rollback" || json.Unmarshal(sent[0].Args, &a) != nil || !a.Start || a.VMState {
		t.Fatalf("sent %+v", sent)
	}

	// The guest stops between authorization and the step's intent: the
	// pre-intent precheck refuses it and nothing is sent.
	e3 := newSnapEnv(t, "lxc")
	req3 := e3.expect(e3.approve(snapReq("lxc", PveSnapshotRollback, "base")))
	e3.client.mu.Lock()
	base := e3.client.reads
	e3.client.statusFn = func(n int) string {
		if n > base+3 { // prepare, Run, engine pre-authorization
			return "stopped"
		}
		return "running"
	}
	e3.client.mu.Unlock()
	if res, err := e3.g.Run(context.Background(), req3); !errors.Is(err, ErrPveSnapshotChanged) || !res.PermitConsumed || len(e3.sc.sent()) != 0 {
		t.Fatalf("status raced: %v %+v", err, res)
	}

	// A RAM snapshot resumes the guest even with start=0; the approval
	// says so.
	e2 := newSnapEnv(t, "qemu")
	p2, err := e2.propose(snapReq("qemu", PveSnapshotRollback, "pre-upgrade"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e2.auth.ApproveCLI(p2.Digest, 0, "admin"); err != nil {
		t.Fatal(err)
	}
	params = boundParams(t, p2)
	if params.Rollback.Start || !params.Rollback.RestoresRAM || !params.Rollback.GuestRunsAfter {
		t.Fatalf("ram rollback effects %+v", params.Rollback)
	}
}

func TestGuestSnapshotNeedsSnapshotClient(t *testing.T) {
	e := newSnapEnv(t, "qemu")
	e.g.Mutations.Client = e.client // the power fake has no snapshot surface
	if _, err := e.propose(snapReq("qemu", PveSnapshotCreate, "s1")); !errors.Is(err, ErrPveSnapshotUnavailable) {
		t.Fatalf("propose: %v", err)
	}
	if _, err := e.g.Mutations.taskType(PveMutationStep{Method: "snapshot.qemu.create"}); !errors.Is(err, ErrPveMutationPlan) {
		t.Fatalf("task type without snapshot client: %v", err)
	}
	if _, err := e.g.Mutations.dispatch(context.Background(), executordb.PveRemote{}, "pve1", PveMutationStep{Method: "snapshot.qemu.create", Args: []byte(`{}`)}, nil, nil); !errors.Is(err, ErrPveRejected) {
		t.Fatalf("dispatch without snapshot client: %v", err)
	}
}

// fakeSnapWriter records snapshot writes.
type fakeSnapWriter struct {
	calls []string
}

func (w *fakeSnapWriter) CreateSnapshot(_ context.Context, r pveapi.SnapshotRequest) (string, error) {
	w.calls = append(w.calls, fmt.Sprintf("create %s %s %d %s vmstate=%t", r.Kind, r.Node, r.VMID, r.Name, r.VMState))
	return "UPID:pve1:00000001:00000001:00000001:qmsnapshot:101:a@pve!t:", nil
}

func (w *fakeSnapWriter) DeleteSnapshot(_ context.Context, kind pveapi.GuestKind, node string, vmid int64, name string) (string, error) {
	w.calls = append(w.calls, fmt.Sprintf("delete %s %s %d %s", kind, node, vmid, name))
	return "UPID:pve1:00000001:00000001:00000001:qmdelsnapshot:101:a@pve!t:", nil
}

func (w *fakeSnapWriter) RollbackSnapshot(_ context.Context, p pveapi.SnapshotRollbackPlan) (pveapi.RollbackResult, error) {
	w.calls = append(w.calls, fmt.Sprintf("rollback %s %s %d %s start=%t ram=%t", p.Kind(), p.Node(), p.VMID(), p.Name(), p.Start(), p.HasVMState()))
	return pveapi.RollbackResult{UPID: "UPID:pve1:00000001:00000001:00000001:qmrollback:101:a@pve!t:"}, nil
}

// TestDispatchGuestSnapshotStepRechecksBeforeSending: the dispatcher reads
// the snapshot list with the read token right before sending and refuses
// any drift of the bound identity.
func TestDispatchGuestSnapshotStepRechecksBeforeSending(t *testing.T) {
	var mu sync.Mutex
	list := `[{"name":"base","snaptime":1700000000},{"name":"ram","parent":"base","snaptime":1700001000,"vmstate":1},{"name":"current","parent":"ram"}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method != http.MethodGet || r.URL.Path != "/api2/json/nodes/pve1/qemu/101/snapshot" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"data":` + list + `}`))
	}))
	defer srv.Close()
	rd, err := pveapi.NewClient(srv.Client(), srv.URL+"/api2/json", func(context.Context) (string, error) { return "PVEAPIToken=r@pve!r=x", nil })
	if err != nil {
		t.Fatal(err)
	}
	step := func(method string, a pveSnapshotStepArgs) PveMutationStep {
		b, _ := json.Marshal(a)
		return PveMutationStep{Method: method, Args: b}
	}
	cases := []struct {
		name string
		step PveMutationStep
		want string // "" = refused
	}{
		{"create new", step("snapshot.qemu.create", pveSnapshotStepArgs{VMID: 101, Name: "n1", VMState: true}), "create qemu pve1 101 n1 vmstate=true"},
		{"create existing", step("snapshot.qemu.create", pveSnapshotStepArgs{VMID: 101, Name: "base"}), ""},
		{"delete exact", step("snapshot.qemu.delete", pveSnapshotStepArgs{VMID: 101, Name: "base", SnapTime: 1700000000}), "delete qemu pve1 101 base"},
		{"delete other generation", step("snapshot.qemu.delete", pveSnapshotStepArgs{VMID: 101, Name: "base", SnapTime: 1699999999}), ""},
		{"delete other parent", step("snapshot.qemu.delete", pveSnapshotStepArgs{VMID: 101, Name: "ram", SnapTime: 1700001000, VMState: true}), ""},
		{"delete missing", step("snapshot.qemu.delete", pveSnapshotStepArgs{VMID: 101, Name: "gone", SnapTime: 1}), ""},
		{"rollback with start", step("snapshot.qemu.rollback", pveSnapshotStepArgs{VMID: 101, Name: "base", SnapTime: 1700000000, Start: true}), "rollback qemu pve1 101 base start=true ram=false"},
		{"rollback ram", step("snapshot.qemu.rollback", pveSnapshotStepArgs{VMID: 101, Name: "ram", SnapTime: 1700001000, Parent: "base", VMState: true}), "rollback qemu pve1 101 ram start=false ram=true"},
		{"rollback ram flag differs", step("snapshot.qemu.rollback", pveSnapshotStepArgs{VMID: 101, Name: "ram", SnapTime: 1700001000, Parent: "base"}), ""},
		{"create with start", step("snapshot.qemu.create", pveSnapshotStepArgs{VMID: 101, Name: "n2", Start: true}), ""},
		{"unknown field", PveMutationStep{Method: "snapshot.qemu.delete", Args: []byte(`{"vmid":101,"name":"base","snaptime":1700000000,"parent":"","vmstate":false,"start":false,"force":1}`)}, ""},
		{"unknown method", step("snapshot.qemu.prune", pveSnapshotStepArgs{VMID: 101, Name: "base"}), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := &fakeSnapWriter{}
			upid, err := DispatchGuestSnapshotStep(context.Background(), w, rd, "pve1", c.step)
			if c.want == "" {
				if !errors.Is(err, ErrPveRejected) || len(w.calls) != 0 {
					t.Fatalf("err %v calls %v", err, w.calls)
				}
				return
			}
			if err != nil || upid == "" || len(w.calls) != 1 || w.calls[0] != c.want {
				t.Fatalf("err %v calls %v", err, w.calls)
			}
		})
	}
	// An unreadable list sends nothing.
	mu.Lock()
	list = `not json`
	mu.Unlock()
	w := &fakeSnapWriter{}
	if _, err := DispatchGuestSnapshotStep(context.Background(), w, rd, "pve1", step("snapshot.qemu.delete", pveSnapshotStepArgs{VMID: 101, Name: "base", SnapTime: 1700000000})); !errors.Is(err, ErrPveRejected) || len(w.calls) != 0 {
		t.Fatalf("unreadable list: %v %v", err, w.calls)
	}
}

func TestGuestSnapshotStepTaskTypesAndIDs(t *testing.T) {
	for method, want := range map[string]string{
		"snapshot.qemu.create": "qmsnapshot", "snapshot.lxc.create": "vzsnapshot",
		"snapshot.qemu.delete": "qmdelsnapshot", "snapshot.lxc.delete": "vzdelsnapshot",
		"snapshot.qemu.rollback": "qmrollback", "snapshot.lxc.rollback": "vzrollback",
	} {
		if tt, ok := GuestSnapshotStepTaskType(method); !ok || tt != want {
			t.Fatalf("%s: %s", method, tt)
		}
		if !pveStepMethodRe.MatchString(method) {
			t.Fatalf("%s is not a valid step method", method)
		}
	}
	if id, ok := GuestSnapshotStepTaskID(PveMutationStep{Method: "snapshot.qemu.delete", Args: []byte(`{"vmid":101,"name":"a","vmstate":false,"snaptime":1,"parent":"","start":false}`)}); !ok || id != "101" {
		t.Fatalf("task id %q", id)
	}
	if _, ok := GuestSnapshotStepTaskType("guest.qemu.stop"); ok {
		t.Fatal("power method claimed")
	}
}

// TestServiceGuestSnapshotRPC: the wired engine's production client has
// the snapshot surface; malformed requests are refused before any read,
// and a read-only remote is never contacted.
func TestServiceGuestSnapshotRPC(t *testing.T) {
	e := newPveReadEnv(t, pvecontract.KindStandalone)
	ctx := context.Background()
	if _, ok := e.svc.pveMutations().Client.(PveSnapshotClient); !ok {
		t.Fatal("production client has no snapshot surface")
	}
	g, err := e.svc.pveGuestSnapshot()
	if err != nil || g.Mutations != e.svc.pveMutations() || g.Bindings != &g.Mutations.snapshotBindings || g.Floor == nil {
		t.Fatalf("snapshot engine: %v", err)
	}
	codeOf := func(err error) codes.Code { return status.Code(err) }
	bad := []*pb.PVEGuestSnapshotTarget{
		nil,
		{RemoteId: pveReadRemote, Kind: "lxc", Node: "pve1", Vmid: 101, Op: "create", Name: "s1", Vmstate: true},
		{RemoteId: pveReadRemote, Kind: "qemu", Node: "pve1", Vmid: 101, Op: "prune", Name: "s1"},
		{RemoteId: pveReadRemote, Kind: "qemu", Node: "pve1", Vmid: 101, Op: "delete", Name: "current"},
	}
	for i, tg := range bad {
		if _, err := e.svc.ProposePVEGuestSnapshot(ctx, &pb.ProposePVEGuestSnapshotRequest{Target: tg}); codeOf(err) != codes.InvalidArgument {
			t.Fatalf("%d: %v", i, err)
		}
	}
	del := &pb.PVEGuestSnapshotTarget{RemoteId: pveReadRemote, Kind: "qemu", Node: "pve1", Vmid: 101, Op: "delete", Name: "base"}
	if _, err := e.svc.CommitPVEGuestSnapshot(ctx, &pb.CommitPVEGuestSnapshotRequest{Target: del, ExecutionDigest: strings.Repeat("ab", 32)}); codeOf(err) != codes.InvalidArgument {
		t.Fatalf("commit without identity: %v", err)
	}
	del.Expect = &pb.PVESnapshotIdentity{Name: "base", SnaptimeUnix: 1700000000}
	if _, err := e.svc.CommitPVEGuestSnapshot(ctx, &pb.CommitPVEGuestSnapshotRequest{Target: del, ExecutionDigest: "nope"}); codeOf(err) != codes.InvalidArgument {
		t.Fatalf("bad digest: %v", err)
	}
	create := &pb.PVEGuestSnapshotTarget{RemoteId: pveReadRemote, Kind: "qemu", Node: "pve1", Vmid: 101, Op: "create", Name: "s1"}
	if _, err := e.svc.ProposePVEGuestSnapshot(ctx, &pb.ProposePVEGuestSnapshotRequest{Target: create}); codeOf(err) != codes.FailedPrecondition {
		t.Fatalf("read-only remote: %v", err)
	}
	if _, err := e.svc.CommitPVEGuestSnapshot(ctx, &pb.CommitPVEGuestSnapshotRequest{Target: del, ExecutionDigest: strings.Repeat("ab", 32)}); codeOf(err) != codes.FailedPrecondition {
		t.Fatalf("commit on read-only remote: %v", err)
	}
	if n := e.pve.requests.Load(); n != 0 {
		t.Fatalf("remote contacted %d times", n)
	}
}

// TestGuestSnapshotLostResponseIsReconciledNotResent: a delete whose
// response is lost is identified from the task list (node, VMID, task type,
// action token) and never sent again.
func TestGuestSnapshotLostResponseIsReconciledNotResent(t *testing.T) {
	e := newSnapEnv(t, "qemu")
	req := e.expect(e.approve(snapReq("qemu", PveSnapshotDelete, "base")))
	upid := testTaskUPID("pve1", time.Now(), "qmdelsnapshot", "101", mutActionUser, 1)
	other := testTaskUPID("pve1", time.Now(), "qmdelsnapshot", "102", mutActionUser, 2)
	e.sc.set(func(c *snapClient) {
		c.dispatchFn = func(PveMutationStep) (string, error) { return "", errors.New("connection reset") }
	})
	e.client.mu.Lock()
	e.client.recent = []string{other, upid}
	e.client.mu.Unlock()
	res, err := e.g.Run(context.Background(), req)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(res.Steps) != 1 || res.Steps[0].UPID != upid || res.Steps[0].State != executordb.PveJobSucceeded {
		t.Fatalf("steps %+v", res.Steps)
	}
	if n := len(e.sc.sent()); n != 1 {
		t.Fatalf("sent %d times", n)
	}
	if _, err := e.g.Run(context.Background(), req); !errors.Is(err, ErrPveMutationDenied) {
		t.Fatalf("second run: %v", err)
	}
	if n := len(e.sc.sent()); n != 1 {
		t.Fatalf("resent: %d", n)
	}
}

// TestPveSnapshotFactsReaderFailsClosed: the production facts reader,
// against a fake PVE HTTP API, keeps every disk and refuses a disk-like
// config member (or the RAM state storage) that is not a bounded string
// instead of silently dropping it from the disk set; other members that
// are not strings (numbers, oversized descriptions) are skipped.
func TestPveSnapshotFactsReaderFailsClosed(t *testing.T) {
	var mu sync.Mutex
	config := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		switch r.URL.Path {
		case "/api2/json/nodes/pve1/qemu/101/config", "/api2/json/nodes/pve1/lxc/101/config":
			_, _ = w.Write([]byte(`{"data":` + config + `}`))
		case "/api2/json/nodes/pve1/storage":
			_, _ = w.Write([]byte(`{"data":[{"storage":"local-zfs","type":"zfspool","active":1,"content":"images,rootdir","shared":0}]}`))
		case "/api2/json/nodes/pve1/qemu/101/snapshot", "/api2/json/nodes/pve1/lxc/101/snapshot":
			_, _ = w.Write([]byte(`{"data":[{"name":"base","snaptime":1700000000},{"name":"current","parent":"base"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	read := func(context.Context) (string, error) { return "PVEAPIToken=r@pve!r=x", nil }
	facts := func(kind, cfg string) (PveSnapshotFacts, error) {
		mu.Lock()
		config = cfg
		mu.Unlock()
		return pveSnapshotFacts(context.Background(), srv.Client(), srv.URL, read, kind, "pve1", 101)
	}
	long := `"` + strings.Repeat("a", maxPveSnapshotConfigValue+1) + `"`

	// A well-formed config: disks kept, numbers and an oversized
	// description skipped, a non-string lock still seen.
	f, err := facts("qemu", `{"scsi0":"local-zfs:vm-101-disk-0,size=32G","memory":2048,"cores":2,"description":`+long+`,"lock":1}`)
	if err != nil {
		t.Fatalf("facts: %v", err)
	}
	if f.Config["scsi0"] != "local-zfs:vm-101-disk-0,size=32G" || f.Config["lock"] != "?" || !f.StoragesComplete || !f.SnapshotsComplete || len(f.Snapshots) != 1 {
		t.Fatalf("facts %+v", f)
	}
	if _, ok := f.Config["memory"]; ok {
		t.Fatal("number kept as a string")
	}
	if _, ok := f.Config["description"]; ok {
		t.Fatal("oversized description kept")
	}
	disks, err := snapshotDiskSet("qemu", PveSnapshotFacts{Config: map[string]string{"scsi0": f.Config["scsi0"]}, Storages: f.Storages, StoragesComplete: true})
	if err != nil || len(disks) != 1 || disks[0].Storage != "local-zfs" {
		t.Fatalf("disk set %+v %v", disks, err)
	}

	for name, c := range map[string]struct{ kind, cfg string }{
		"qemu disk number":         {"qemu", `{"scsi0":"local-zfs:vm-101-disk-0","scsi1":7}`},
		"qemu disk object":         {"qemu", `{"scsi0":"local-zfs:vm-101-disk-0","virtio3":{"file":"x:y"}}`},
		"qemu disk null":           {"qemu", `{"scsi0":"local-zfs:vm-101-disk-0","sata0":null}`},
		"qemu disk oversized":      {"qemu", `{"scsi0":"local-zfs:vm-101-disk-0","ide1":` + long + `}`},
		"qemu efidisk oversized":   {"qemu", `{"scsi0":"local-zfs:vm-101-disk-0","efidisk0":` + long + `}`},
		"qemu tpmstate number":     {"qemu", `{"scsi0":"local-zfs:vm-101-disk-0","tpmstate0":1}`},
		"qemu unknown disk index":  {"qemu", `{"scsi0":"local-zfs:vm-101-disk-0","scsi100":1}`},
		"qemu vmstatestorage list": {"qemu", `{"scsi0":"local-zfs:vm-101-disk-0","vmstatestorage":["a"]}`},
		"lxc rootfs number":        {"lxc", `{"rootfs":5,"hostname":"ct"}`},
		"lxc mount point oversize": {"lxc", `{"rootfs":"local-zfs:subvol-101-disk-0","mp3":` + long + `}`},
	} {
		if _, err := facts(c.kind, c.cfg); !errors.Is(err, ErrPveSnapshotState) {
			t.Errorf("%s: %v, want ErrPveSnapshotState", name, err)
		}
	}
}

// TestGuestSnapshotDiskSetRefusesUnknownDiskKeys: a disk-like key outside
// the disk patterns of the guest kind is refused, not left out of the set.
func TestGuestSnapshotDiskSetRefusesUnknownDiskKeys(t *testing.T) {
	st := []pveapi.Storage{{ID: "local-zfs", Type: "zfspool", Active: true}}
	for kind, key := range map[string]string{"qemu": "scsi100", "lxc": "scsi0"} {
		cfg := map[string]string{"scsi0": "local-zfs:vm-101-disk-0", "rootfs": "local-zfs:subvol-101-disk-0", key: "local-zfs:vm-101-disk-9"}
		if kind == "qemu" {
			delete(cfg, "rootfs")
		} else {
			delete(cfg, "scsi0")
			cfg[key] = "local-zfs:vm-101-disk-9"
		}
		if _, err := snapshotDiskSet(kind, PveSnapshotFacts{Config: cfg, Storages: st, StoragesComplete: true}); !errors.Is(err, ErrPveSnapshotState) {
			t.Errorf("%s %s: %v", kind, key, err)
		}
	}
	// The RAM state storage is not a disk.
	cfg := map[string]string{"scsi0": "local-zfs:vm-101-disk-0", "vmstatestorage": "local-zfs"}
	if d, err := snapshotDiskSet("qemu", PveSnapshotFacts{Config: cfg, Storages: st, StoragesComplete: true}); err != nil || len(d) != 1 {
		t.Fatalf("vmstatestorage: %+v %v", d, err)
	}
}

// dupSnapReader answers a snapshot list with whatever it holds.
type dupSnapReader struct{ list pveapi.SnapshotList }

func (r dupSnapReader) ListSnapshots(context.Context, string, string, int64) (pveapi.SnapshotList, error) {
	return r.list, nil
}

func (r dupSnapReader) PlanSnapshotRollback(context.Context, pveapi.GuestKind, string, int64, string, bool) (pveapi.SnapshotRollbackPlan, error) {
	return pveapi.SnapshotRollbackPlan{}, errors.New("not planned")
}

// TestDispatchGuestSnapshotStepRefusesDuplicateNames: a list with the
// name twice is ambiguous; nothing is sent for any op, even when one of
// the entries matches the bound identity exactly.
func TestDispatchGuestSnapshotStepRefusesDuplicateNames(t *testing.T) {
	rd := dupSnapReader{list: pveapi.SnapshotList{Complete: true, Snapshots: []pveapi.Snapshot{
		{Name: "base", SnapTimeUnix: 1700000000},
		{Name: "base", SnapTimeUnix: 1700000000},
	}}}
	for _, method := range []string{"snapshot.qemu.delete", "snapshot.qemu.rollback", "snapshot.lxc.delete"} {
		args, _ := json.Marshal(pveSnapshotStepArgs{VMID: 101, Name: "base", SnapTime: 1700000000})
		w := &fakeSnapWriter{}
		if _, err := DispatchGuestSnapshotStep(context.Background(), w, rd, "pve1", PveMutationStep{Method: method, Args: args}); !errors.Is(err, ErrPveRejected) || len(w.calls) != 0 {
			t.Fatalf("%s: %v %v", method, err, w.calls)
		}
	}
	// The same list without the duplicate is sent.
	rd.list.Snapshots = rd.list.Snapshots[:1]
	args, _ := json.Marshal(pveSnapshotStepArgs{VMID: 101, Name: "base", SnapTime: 1700000000})
	w := &fakeSnapWriter{}
	if _, err := DispatchGuestSnapshotStep(context.Background(), w, rd, "pve1", PveMutationStep{Method: "snapshot.qemu.delete", Args: args}); err != nil || len(w.calls) != 1 {
		t.Fatalf("single: %v %v", err, w.calls)
	}
}

// TestGuestSnapshotRollbackBindsQMPStatus: the QMP run state is part of
// the approved rollback effects; a guest paused (or resumed) since the
// approval is refused and nothing is sent.
func TestGuestSnapshotRollbackBindsQMPStatus(t *testing.T) {
	e := newSnapEnv(t, "qemu")
	p, err := e.propose(snapReq("qemu", PveSnapshotRollback, "base"))
	if err != nil {
		t.Fatal(err)
	}
	if params := boundParams(t, p); params.Rollback == nil || params.Rollback.StatusBefore != "running" || params.Rollback.QMPStatusBefore != "running" {
		t.Fatalf("params %+v", params.Rollback)
	}
	if _, err := e.auth.ApproveCLI(p.Digest, 0, "admin"); err != nil {
		t.Fatal(err)
	}
	req := e.expect(snapReq("qemu", PveSnapshotRollback, "base"))
	req.Digest = p.Digest
	e.client.qmp = "paused"
	if _, err := e.g.Run(context.Background(), req); !errors.Is(err, ErrPveMutationDenied) && !errors.Is(err, ErrPveSnapshotChanged) {
		t.Fatalf("paused run: %v", err)
	}
	if len(e.sc.sent()) != 0 {
		t.Fatal("dispatched to a paused guest")
	}

	// A paused guest's rollback binds "paused"; resuming it before the run
	// is refused as well.
	e2 := newSnapEnv(t, "qemu")
	e2.client.qmp = "paused"
	p2, err := e2.propose(snapReq("qemu", PveSnapshotRollback, "base"))
	if err != nil {
		t.Fatal(err)
	}
	if params := boundParams(t, p2); params.Rollback == nil || params.Rollback.StatusBefore != "running" || params.Rollback.QMPStatusBefore != "paused" {
		t.Fatalf("params %+v", params.Rollback)
	}
	if _, err := e2.auth.ApproveCLI(p2.Digest, 0, "admin"); err != nil {
		t.Fatal(err)
	}
	req2 := e2.expect(snapReq("qemu", PveSnapshotRollback, "base"))
	req2.Digest = p2.Digest
	e2.client.qmp = ""
	if _, err := e2.g.Run(context.Background(), req2); !errors.Is(err, ErrPveMutationDenied) && !errors.Is(err, ErrPveSnapshotChanged) {
		t.Fatalf("resumed run: %v", err)
	}
	if len(e2.sc.sent()) != 0 {
		t.Fatal("dispatched to a resumed guest")
	}
	e2.client.qmp = "paused"
	if _, err := e2.g.Run(context.Background(), req2); err != nil {
		t.Fatalf("unchanged run: %v", err)
	}
	if len(e2.sc.sent()) != 1 {
		t.Fatal("not dispatched")
	}

	// The QMP state changes between authorization and the step's intent:
	// the pre-intent precheck refuses it.
	e3 := newSnapEnv(t, "qemu")
	req3 := e3.expect(e3.approve(snapReq("qemu", PveSnapshotRollback, "base")))
	e3.client.mu.Lock()
	base := e3.client.reads
	e3.client.mu.Unlock()
	e3.client.statusFn = func(n int) string {
		if n > base+3 { // prepare, Run, engine pre-authorization
			e3.client.qmp = "paused"
		}
		return "running"
	}
	if res, err := e3.g.Run(context.Background(), req3); !errors.Is(err, ErrPveSnapshotChanged) || !res.PermitConsumed || len(e3.sc.sent()) != 0 {
		t.Fatalf("qmp raced: %v %+v", err, res)
	}
}
