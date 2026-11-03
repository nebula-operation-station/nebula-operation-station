// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// opClient is a fake PVE client with the backup and migration surfaces.
// It embeds the power fake for the guest state and task handling, and
// dispatches through the real DispatchGuestBackupStep and
// DispatchGuestMigrateStep with recording writers.
type opClient struct {
	*powerClient
	omu            sync.Mutex
	config         map[string]string
	storages       []pveapi.Storage
	targetStorages []pveapi.Storage
	cluster        pveapi.ClusterStatus
	ha             pveapi.HAStatus
	// snapshots are the guest's snapshot sections by name;
	// snapshotsIncomplete reports them as not completely read.
	snapshots           map[string]map[string]string
	snapshotsIncomplete bool
	factReads           int
	// onFacts, if set, may change the facts before read n is answered.
	onFacts func(n int, c *opClient)
	// onRecheck, if set, may change the facts after the engine's last
	// check and before the dispatcher's recheck.
	onRecheck   func(c *opClient)
	lost        bool
	backups     []pveapi.BackupRequest
	migrations  []pveapi.MigrateRequest
	opSteps     []PveMutationStep
	targetAsked []string
}

func (c *opClient) facts() (map[string]string, []pveapi.Storage, []pveapi.Storage) {
	c.factReads++
	if c.onFacts != nil {
		c.onFacts(c.factReads, c)
	}
	cfg := map[string]string{}
	for k, v := range c.config {
		cfg[k] = v
	}
	return cfg, append([]pveapi.Storage(nil), c.storages...), append([]pveapi.Storage(nil), c.targetStorages...)
}

func (c *opClient) BackupFacts(_ context.Context, _ executordb.PveRemote, _, _ string, _ uint64, _ pveapi.TokenSupplier) (PveBackupFacts, error) {
	c.omu.Lock()
	defer c.omu.Unlock()
	cfg, st, _ := c.facts()
	return PveBackupFacts{Config: cfg, Storages: st, StoragesComplete: true}, nil
}

func (c *opClient) MigrateFacts(_ context.Context, _ executordb.PveRemote, _, _ string, _ uint64, target string, _ pveapi.TokenSupplier) (PveMigrateFacts, error) {
	c.omu.Lock()
	defer c.omu.Unlock()
	c.targetAsked = append(c.targetAsked, target)
	cfg, src, dst := c.facts()
	snaps := map[string]map[string]string{}
	for name, sc := range c.snapshots {
		snaps[name] = map[string]string{}
		for k, v := range sc {
			snaps[name][k] = v
		}
	}
	return PveMigrateFacts{Config: cfg, SourceStorages: src, SourceStoragesComplete: true, TargetStorages: dst, TargetStoragesComplete: true,
		Cluster: c.cluster, HA: c.ha, Snapshots: snaps, SnapshotsComplete: !c.snapshotsIncomplete}, nil
}

func (c *opClient) record(step PveMutationStep) (int, bool) {
	c.omu.Lock()
	defer c.omu.Unlock()
	c.opSteps = append(c.opSteps, step)
	return len(c.opSteps), c.lost
}

func (c *opClient) DispatchBackup(ctx context.Context, _ executordb.PveRemote, node string, step PveMutationStep, _ pveapi.TokenSupplier) (string, error) {
	n, lost := c.record(step)
	if lost {
		return "", errors.New("connection reset")
	}
	return DispatchGuestBackupStep(ctx, &opWriter{c: c, n: n}, node, step)
}

func (c *opClient) DispatchMigrate(ctx context.Context, _ executordb.PveRemote, node string, step PveMutationStep, _, _ pveapi.TokenSupplier) (string, error) {
	n, lost := c.record(step)
	if lost {
		return "", errors.New("connection reset")
	}
	if c.onRecheck != nil {
		c.omu.Lock()
		c.onRecheck(c)
		c.omu.Unlock()
	}
	return DispatchGuestMigrateStep(ctx, &opWriter{c: c, n: n}, &opReader{c: c}, node, step)
}

func (c *opClient) sentSteps() int {
	c.omu.Lock()
	defer c.omu.Unlock()
	return len(c.opSteps)
}

type opWriter struct {
	c *opClient
	n int
}

func (w *opWriter) BackupNow(_ context.Context, r pveapi.BackupRequest) (string, error) {
	w.c.omu.Lock()
	defer w.c.omu.Unlock()
	w.c.backups = append(w.c.backups, r)
	return testTaskUPID(r.Node, time.Now(), "vzdump", strconv.FormatInt(r.VMID, 10), mutActionUser, w.n), nil
}

func (w *opWriter) MigrateGuest(_ context.Context, r pveapi.MigrateRequest) (string, error) {
	w.c.omu.Lock()
	defer w.c.omu.Unlock()
	w.c.migrations = append(w.c.migrations, r)
	tt := "qmigrate"
	if r.Kind == pveapi.GuestLXC {
		tt = "vzmigrate"
	}
	return testTaskUPID(r.Node, time.Now(), tt, strconv.FormatInt(r.VMID, 10), mutActionUser, w.n), nil
}

type opReader struct{ c *opClient }

func (r *opReader) ClusterStatus(context.Context) (pveapi.ClusterStatus, error) {
	r.c.omu.Lock()
	defer r.c.omu.Unlock()
	return r.c.cluster, nil
}

func (r *opReader) HAStatus(context.Context) (pveapi.HAStatus, error) {
	r.c.omu.Lock()
	defer r.c.omu.Unlock()
	return r.c.ha, nil
}

type opEnv struct {
	*powerEnv
	oc       *opClient
	bindings *PveGuestPowerBindings
	backup   *PveGuestBackup
	migrate  *PveGuestMigrate
}

func newOpEnv(t *testing.T, kind string) *opEnv {
	t.Helper()
	pe := newPowerEnv(t, kind)
	oc := &opClient{powerClient: pe.client,
		config: map[string]string{"scsi0": "local-zfs:vm-101-disk-0,size=32G", "ide2": "local:iso/x.iso,media=cdrom",
			"efidisk0": "ceph:vm-101-disk-1,size=1M"},
		storages: []pveapi.Storage{
			{ID: "local-zfs", Type: "zfspool", Content: []string{"images", "rootdir"}, Active: true},
			{ID: "local", Type: "dir", Content: []string{"iso", "backup"}, Active: true},
			{ID: "ceph", Type: "rbd", Content: []string{"images", "rootdir"}, Shared: true, Active: true},
			{ID: "pbs", Type: "pbs", Content: []string{"backup"}, Shared: true, Active: true},
			{ID: "pbs-down", Type: "pbs", Content: []string{"backup"}, Shared: true, Active: false},
		},
		targetStorages: []pveapi.Storage{
			{ID: "local-zfs", Type: "zfspool", Content: []string{"images", "rootdir"}, Active: true},
			{ID: "fast-zfs", Type: "zfspool", Content: []string{"images", "rootdir"}, Active: true},
			{ID: "iso-only", Type: "dir", Content: []string{"iso"}, Active: true},
			{ID: "ceph", Type: "rbd", Content: []string{"images", "rootdir"}, Shared: true, Active: true},
		},
		cluster: pveapi.ClusterStatus{Available: true, Name: "lab", Quorum: true, NodesOnline: 3, NodesTotal: 3,
			Members: []pveapi.ClusterMember{{Name: "pve1", Online: true}, {Name: "pve2", Online: true}, {Name: "pve3", Online: true}}},
		ha: pveapi.HAStatus{Available: true, Resources: []pveapi.HAResource{{VMID: 555, Type: "vm", Managed: true}}},
	}
	if kind == permit.ProviderKindLXC {
		oc.config = map[string]string{"rootfs": "local-zfs:subvol-101-disk-0,size=8G"}
	}
	e := &opEnv{powerEnv: pe, oc: oc}
	// Every target of the default guest and of the destination node pve2
	// is recorded MEDIUM.
	_, n2, _ := e.nodeTargets(kind, "pve2")
	e.crit.hosts[n2] = canonical.RiskMedium
	e.restartOp()
	return e
}

func (e *opEnv) nodeTargets(kind, node string) (guest, n, remote canonical.Target) {
	e.t.Helper()
	rm, _, err := e.pe.db.GetRemote(mutRemote)
	if err != nil {
		e.t.Fatal(err)
	}
	g, n, r, err := PveGuestRiskTargets(permit.ProviderMutationTarget{RemoteID: rm.RemoteID, TrustPin: rm.TrustPin, Kind: kind, Node: node, VMID: 101})
	if err != nil {
		e.t.Fatal(err)
	}
	return g, n, r
}

// restartOp replaces the authority and engine as an executor restart
// does. The authority's policy includes GuestOpRiskFloor, so the floor is
// enforced on approval and authorization too.
func (e *opEnv) restartOp() {
	e.t.Helper()
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "power.test", Origins: []string{"https://power.test"}, Counters: e.pe.db}, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	next, err := riskpolicy.New(e.crit)
	if err != nil {
		e.t.Fatal(err)
	}
	e.bindings = &PveGuestPowerBindings{}
	floor := GuestOpRiskFloor{Next: next, Criticality: e.crit, Bindings: e.bindings,
		Linked: func(_ canonical.Request, t canonical.Target) ([]canonical.Target, error) {
			return e.linked[t.HostID], nil
		}}
	e.auth, err = permit.New(permit.Options{Verifier: v, Store: e.pe.db, RiskPolicy: floor})
	if err != nil {
		e.t.Fatal(err)
	}
	m := &PveMutations{DB: e.pe.db, Auth: e.auth, Vault: e.pe.vault, Client: e.oc, PollInterval: time.Millisecond,
		MaxWait: 2 * time.Second, Log: slog.New(slog.NewTextHandler(e.logs, nil))}
	e.pe.admin.Mutations = m
	e.backup = &PveGuestBackup{Mutations: m, Bindings: e.bindings, Floor: floor}
	e.migrate = &PveGuestMigrate{Mutations: m, Bindings: e.bindings, Floor: floor}
}

var opExecSeq int

func nextOpExec() string {
	opExecSeq++
	return fmt.Sprintf("00000000-0000-4000-d000-%012d", opExecSeq)
}

func backupReq(kind string) PveGuestBackupRequest {
	return PveGuestBackupRequest{RemoteID: mutRemote, Kind: kind, Node: "pve1", VMID: 101, Storage: "pbs", Mode: PveBackupModeSnapshot, BandwidthKiB: 50000}
}

func (e *opEnv) approveBackup(req PveGuestBackupRequest) (PveGuestBackupRequest, permit.Permit) {
	e.t.Helper()
	p, err := e.backup.Propose(context.Background(), req, nextOpExec(), time.Now().Add(time.Hour))
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.auth.ApproveCLI(p.Digest, 0, "admin"); err != nil {
		e.t.Fatal(err)
	}
	req.Digest = p.Digest
	return req, p
}

func TestGuestBackupHappyPathBindsGuestStorageModeBandwidth(t *testing.T) {
	for _, kind := range []string{permit.ProviderKindQemu, permit.ProviderKindLXC} {
		t.Run(kind, func(t *testing.T) {
			e := newOpEnv(t, kind)
			req, p := e.approveBackup(backupReq(kind))
			if p.Request.RiskClass != canonical.RiskMedium {
				t.Fatalf("risk %s, want MEDIUM", p.Request.RiskClass)
			}
			var doc struct {
				Target permit.ProviderMutationTarget `json:"provider_target"`
				Params pveBackupParams               `json:"parameters"`
			}
			if err := json.Unmarshal(p.Parameters, &doc); err != nil {
				t.Fatal(err)
			}
			bp := doc.Params
			if doc.Target.VMID != 101 || doc.Target.Node != "pve1" || doc.Target.Kind != kind ||
				bp.Storage != "pbs" || bp.StorageType != "pbs" || bp.Mode != PveBackupModeSnapshot || bp.BandwidthKiB != 50000 ||
				bp.Compress != "zstd" || bp.Prune || bp.StatusBefore != "running" || len(bp.Steps) != 1 {
				t.Fatalf("bound %+v target %+v", bp, doc.Target)
			}
			res, err := e.backup.Run(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobSucceeded || res.Steps[0].TaskType != "vzdump" {
				t.Fatalf("steps %+v", res.Steps)
			}
			want := pveapi.BackupRequest{Node: "pve1", VMID: 101, Storage: "pbs", Mode: "snapshot", BandwidthKiB: 50000, Compress: "zstd"}
			if len(e.oc.backups) != 1 || e.oc.backups[0] != want {
				t.Fatalf("sent %+v", e.oc.backups)
			}
			// The permit is single-use.
			if _, err := e.backup.Run(context.Background(), req); !errors.Is(err, ErrPveMutationDenied) {
				t.Fatalf("second run: %v", err)
			}
		})
	}
}

func TestGuestBackupRequestRefusedWithoutIO(t *testing.T) {
	cases := map[string]func(r *PveGuestBackupRequest){
		"unknown mode":        func(r *PveGuestBackupRequest) { r.Mode = "fast" },
		"negative bandwidth":  func(r *PveGuestBackupRequest) { r.BandwidthKiB = -1 },
		"bandwidth too large": func(r *PveGuestBackupRequest) { r.BandwidthKiB = pveapi.MaxBackupBandwidthKiB + 1 },
		"malformed storage":   func(r *PveGuestBackupRequest) { r.Storage = "pbs/../x" },
		"empty storage":       func(r *PveGuestBackupRequest) { r.Storage = "" },
		"node kind":           func(r *PveGuestBackupRequest) { r.Kind = permit.ProviderKindNode },
		"bad vmid":            func(r *PveGuestBackupRequest) { r.VMID = 1 },
		"bad node":            func(r *PveGuestBackupRequest) { r.Node = "pve 1" },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			e := newOpEnv(t, permit.ProviderKindQemu)
			req := backupReq(permit.ProviderKindQemu)
			mod(&req)
			_, err := e.backup.Propose(context.Background(), req, nextOpExec(), time.Now().Add(time.Hour))
			if !errors.Is(err, ErrPveBackupRequest) && !errors.Is(err, ErrPveMutationRequest) {
				t.Fatalf("got %v", err)
			}
			if e.oc.factReads != 0 || e.client.reads != 0 {
				t.Fatalf("read the remote for a malformed request")
			}
		})
	}
}

func TestGuestBackupStorageMustAcceptBackups(t *testing.T) {
	cases := []struct {
		name    string
		storage string
		mod     func(c *opClient)
		want    error
	}{
		{"not listed", "nfs-backup", nil, ErrPveBackupStorage},
		{"inactive", "pbs-down", nil, ErrPveBackupStorage},
		{"no backup content", "local-zfs", nil, ErrPveBackupStorage},
		{"duplicate listing", "pbs", func(c *opClient) {
			c.storages = append(c.storages, pveapi.Storage{ID: "pbs", Type: "pbs", Content: []string{"backup"}, Active: true})
		}, ErrPveBackupStorage},
		{"locked guest", "pbs", func(c *opClient) { c.config["lock"] = "backup" }, ErrPveBackupState},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newOpEnv(t, permit.ProviderKindQemu)
			if tc.mod != nil {
				tc.mod(e.oc)
			}
			req := backupReq(permit.ProviderKindQemu)
			req.Storage = tc.storage
			if _, err := e.backup.Propose(context.Background(), req, nextOpExec(), time.Now().Add(time.Hour)); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestGuestBackupDriftBeforeDispatchSendsNothing(t *testing.T) {
	cases := []struct {
		name string
		mod  func(c *opClient)
		want error
	}{
		{"storage went inactive", func(c *opClient) { c.storages[3].Active = false }, ErrPveBackupStorage},
		{"storage lost backup content", func(c *opClient) { c.storages[3].Content = []string{"images"} }, ErrPveBackupStorage},
		{"guest locked", func(c *opClient) { c.config["lock"] = "migrate" }, ErrPveBackupState},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newOpEnv(t, permit.ProviderKindQemu)
			req, _ := e.approveBackup(backupReq(permit.ProviderKindQemu))
			// Reads: propose (prepare, proposal), run (prepare, before
			// authorization, before the intent = 5).
			e.oc.onFacts = func(n int, c *opClient) {
				if n == 5 {
					tc.mod(c)
				}
			}
			_, err := e.backup.Run(context.Background(), req)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if e.oc.sentSteps() != 0 {
				t.Fatal("dispatched despite drift")
			}
		})
	}
}

func TestGuestBackupPowerStateBound(t *testing.T) {
	e := newOpEnv(t, permit.ProviderKindQemu)
	req := backupReq(permit.ProviderKindQemu)
	req.Mode = PveBackupModeStop
	req, _ = e.approveBackup(req)
	e.client.statusFn = func(int) string { return "stopped" }
	if _, err := e.backup.Run(context.Background(), req); !errors.Is(err, ErrPveBackupChanged) && !errors.Is(err, ErrPveMutationDenied) {
		t.Fatalf("got %v", err)
	}
	if e.oc.sentSteps() != 0 {
		t.Fatal("dispatched after the guest's state changed")
	}
}

func TestGuestBackupRiskFloor(t *testing.T) {
	M, H, C := canonical.RiskMedium, canonical.RiskHigh, canonical.RiskCritical
	cases := []struct {
		name                string
		guest, node, remote canonical.Risk
		want                canonical.Risk
	}{
		{"base", M, M, M, M},
		{"low records do not lower", canonical.RiskLow, canonical.RiskLow, canonical.RiskLow, M},
		{"guest critical", C, M, M, C},
		{"node high", M, H, M, H},
		{"unknown remote", M, M, "", H},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newOpEnv(t, permit.ProviderKindQemu)
			e.record(permit.ProviderKindQemu, 101, tc.guest, tc.node, tc.remote)
			p, err := e.backup.Propose(context.Background(), backupReq(permit.ProviderKindQemu), nextOpExec(), time.Now().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if p.Request.RiskClass != tc.want {
				t.Fatalf("risk %s, want %s", p.Request.RiskClass, tc.want)
			}
		})
	}
}

func TestGuestOpRiskFloorFailsClosed(t *testing.T) {
	e := newOpEnv(t, permit.ProviderKindQemu)
	next, _ := riskpolicy.New(e.crit)
	f := GuestOpRiskFloor{Next: next, Criticality: e.crit, Linked: PveRegistryLinkedHosts, Bindings: &PveGuestPowerBindings{}}
	for _, action := range []string{PveGuestBackupAction, PveGuestMigrateAction} {
		r, _, err := f.MinimumRisk(canonical.Request{ActionID: action, ParametersHash: "unbound"}, nil)
		if err != nil || r != canonical.RiskHigh {
			t.Fatalf("%s unbound: %s %v", action, r, err)
		}
	}
	r, _, err := (GuestOpRiskFloor{}).MinimumRisk(canonical.Request{ActionID: PveGuestBackupAction}, nil)
	if err != nil || r != canonical.RiskHigh {
		t.Fatalf("unconfigured: %s %v", r, err)
	}
}

func TestGuestBackupRestartReconcileFindsTask(t *testing.T) {
	e := newOpEnv(t, permit.ProviderKindQemu)
	req, _ := e.approveBackup(backupReq(permit.ProviderKindQemu))
	e.oc.lost = true
	res, err := e.backup.Run(context.Background(), req)
	if !errors.Is(err, ErrPveDispatchUncertain) {
		t.Fatalf("lost response: %v", err)
	}
	if len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobReconciling {
		t.Fatalf("steps %+v", res.Steps)
	}
	e.restartOp()
	now := time.Now()
	own := testTaskUPID("pve1", now, "vzdump", "101", mutActionUser, 9)
	e.client.recent = []string{
		testTaskUPID("pve1", now, "vzdump", "102", mutActionUser, 4),
		testTaskUPID("pve1", now, "qmigrate", "101", mutActionUser, 5),
		testTaskUPID("pve1", now, "vzdump", "101", "root@pam", 6),
		own,
	}
	if err := e.backup.Mutations.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	steps, err := e.pe.db.PveJobSteps(res.ExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 1 || steps[0].UPID != own || steps[0].State != executordb.PveJobSucceeded {
		t.Fatalf("reconciled %+v", steps)
	}
	if e.oc.sentSteps() != 1 {
		t.Fatalf("reconcile dispatched again: %d", e.oc.sentSteps())
	}
}

func TestGuestBackupStepRefusedWithoutBackupSurface(t *testing.T) {
	e := newOpEnv(t, permit.ProviderKindQemu)
	e.backup.Mutations.Client = e.client // the power fake has no backup surface
	_, err := e.backup.Propose(context.Background(), backupReq(permit.ProviderKindQemu), nextOpExec(), time.Now().Add(time.Hour))
	if !errors.Is(err, ErrPveBackupUnavailable) {
		t.Fatalf("got %v", err)
	}
	if _, err := e.backup.Mutations.taskType(PveMutationStep{Method: "backup.qemu.vzdump", Args: json.RawMessage(`{}`)}); !errors.Is(err, ErrPveMutationPlan) {
		t.Fatalf("task type without surface: %v", err)
	}
}

// TestDispatchGuestBackupStepNeverPrunes sends a backup step through the
// real pveapi writer and checks the exact form: one vmid, the bound
// storage, mode, bandwidth and compression, remove=0 and none of the
// pruning, deletion or multi-guest flags.
func TestDispatchGuestBackupStepNeverPrunes(t *testing.T) {
	var form url.Values
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ = url.ParseQuery(string(body))
		path = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"data":%q}`, testTaskUPID("pve1", time.Now(), "vzdump", "101", mutActionUser, 1))
	}))
	defer srv.Close()
	tok := func(context.Context) (string, error) { return "PVEAPIToken=" + mutActionUser + "=secret", nil }
	w, err := pveapi.NewWriter(srv.URL, srv.Client(), tok, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	args, _ := json.Marshal(pveBackupStepArgs{VMID: 101, Storage: "pbs", Mode: "suspend", BandwidthKiB: 1234, Compress: "zstd"})
	if _, err := DispatchGuestBackupStep(context.Background(), w, "pve1", PveMutationStep{Method: "backup.qemu.vzdump", Args: args}); err != nil {
		t.Fatal(err)
	}
	if path != "/api2/json/nodes/pve1/vzdump" {
		t.Fatalf("path %s", path)
	}
	want := map[string]string{"vmid": "101", "storage": "pbs", "mode": "suspend", "bwlimit": "1234", "compress": "zstd", "remove": "0"}
	for k, v := range want {
		if form.Get(k) != v {
			t.Fatalf("%s = %q, want %q (form %v)", k, form.Get(k), v, form)
		}
	}
	for _, k := range []string{"prune-backups", "all", "exclude", "pool", "mailto", "script", "dumpdir", "stdout", "maxfiles", "protected"} {
		if form.Has(k) {
			t.Fatalf("form carries %s: %v", k, form)
		}
	}
	if len(form) != len(want) {
		t.Fatalf("unexpected members: %v", form)
	}
}

func TestDispatchGuestBackupStepRejectsMalformedArgs(t *testing.T) {
	w := &opWriter{c: &opClient{}}
	cases := map[string]string{
		"prune flag smuggled": `{"vmid":101,"storage":"pbs","mode":"snapshot","bwlimit_kib":0,"compress":"zstd","prune":true}`,
		"other compression":   `{"vmid":101,"storage":"pbs","mode":"snapshot","bwlimit_kib":0,"compress":"gzip"}`,
		"unknown mode":        `{"vmid":101,"storage":"pbs","mode":"fast","bwlimit_kib":0,"compress":"zstd"}`,
		"bad storage":         `{"vmid":101,"storage":"a:b","mode":"snapshot","bwlimit_kib":0,"compress":"zstd"}`,
		"bad vmid":            `{"vmid":1,"storage":"pbs","mode":"snapshot","bwlimit_kib":0,"compress":"zstd"}`,
		"negative bandwidth":  `{"vmid":101,"storage":"pbs","mode":"snapshot","bwlimit_kib":-5,"compress":"zstd"}`,
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := DispatchGuestBackupStep(context.Background(), w, "pve1", PveMutationStep{Method: "backup.qemu.vzdump", Args: json.RawMessage(args)})
			if !errors.Is(err, ErrPveRejected) {
				t.Fatalf("got %v", err)
			}
		})
	}
	if len(w.c.backups) != 0 {
		t.Fatalf("sent %+v", w.c.backups)
	}
	if _, err := DispatchGuestBackupStep(context.Background(), w, "pve1", PveMutationStep{Method: "backup.qemu.prune", Args: json.RawMessage(`{}`)}); !errors.Is(err, ErrPveRejected) {
		t.Fatalf("unknown method: %v", err)
	}
}
