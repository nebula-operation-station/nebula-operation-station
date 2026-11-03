// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pveapi"
)

// migrateReq is a live QEMU migration pve1 → pve2 of the default guest
// (scsi0 on local-zfs, efidisk0 on shared ceph).
func migrateReq() PveGuestMigrateRequest {
	return PveGuestMigrateRequest{RemoteID: mutRemote, Kind: permit.ProviderKindQemu, Node: "pve1", VMID: 101, Target: "pve2", Online: true,
		StorageMap: map[string]string{"local-zfs": "fast-zfs", "ceph": "ceph"}}
}

func lxcMigrateReq() PveGuestMigrateRequest {
	return PveGuestMigrateRequest{RemoteID: mutRemote, Kind: permit.ProviderKindLXC, Node: "pve1", VMID: 101, Target: "pve2", Restart: true,
		TimeoutSec: 120, StorageMap: map[string]string{"local-zfs": "local-zfs"}}
}

func (e *opEnv) proposeMigrate(req PveGuestMigrateRequest) (permit.Permit, error) {
	return e.migrate.Propose(context.Background(), req, nextOpExec(), time.Now().Add(time.Hour))
}

func (e *opEnv) approveMigrate(req PveGuestMigrateRequest) (PveGuestMigrateRequest, permit.Permit) {
	e.t.Helper()
	p, err := e.proposeMigrate(req)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.auth.ApproveCLI(p.Digest, 0, "admin"); err != nil {
		e.t.Fatal(err)
	}
	req.Digest = p.Digest
	return req, p
}

func migrateParams(t *testing.T, p permit.Permit) pveMigrateParams {
	t.Helper()
	var doc struct {
		Parameters pveMigrateParams `json:"parameters"`
	}
	if err := json.Unmarshal(p.Parameters, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Parameters
}

func TestGuestMigrateLiveQemuHappyPath(t *testing.T) {
	e := newOpEnv(t, permit.ProviderKindQemu)
	req, p := e.approveMigrate(migrateReq())
	if p.Request.RiskClass != canonical.RiskHigh {
		t.Fatalf("risk %s, want HIGH", p.Request.RiskClass)
	}
	mp := migrateParams(t, p)
	if mp.Source != "pve1" || mp.Target != "pve2" || !mp.Online || mp.Bound.Mapping != "ceph:ceph,local-zfs:fast-zfs" ||
		!mp.Bound.WithLocalDisks || mp.Bound.StatusBefore != "running" || mp.Bound.Cluster != "lab" || len(mp.Bound.Disks) != 2 {
		t.Fatalf("bound %+v", mp)
	}
	if d := mp.Bound.Disks; d[0].Key != "efidisk0" || !d[0].Shared || d[0].TargetStorage != "ceph" ||
		d[1].Key != "scsi0" || d[1].Shared || d[1].TargetStorage != "fast-zfs" {
		t.Fatalf("disks %+v", d)
	}
	res, err := e.migrate.Run(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobSucceeded || res.Steps[0].TaskType != "qmigrate" || res.Steps[0].Node != "pve1" {
		t.Fatalf("steps %+v", res.Steps)
	}
	want := pveapi.MigrateRequest{Kind: pveapi.GuestQEMU, Node: "pve1", VMID: 101, Target: "pve2", Online: true,
		TargetStorage: "ceph:ceph,local-zfs:fast-zfs", WithLocalDisks: true}
	if len(e.oc.migrations) != 1 || e.oc.migrations[0] != want {
		t.Fatalf("sent %+v", e.oc.migrations)
	}
}

func TestGuestMigrateLXCRestartHappyPath(t *testing.T) {
	e := newOpEnv(t, permit.ProviderKindLXC)
	req, p := e.approveMigrate(lxcMigrateReq())
	if p.Request.RiskClass != canonical.RiskHigh {
		t.Fatalf("risk %s", p.Request.RiskClass)
	}
	if _, err := e.migrate.Run(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	want := pveapi.MigrateRequest{Kind: pveapi.GuestLXC, Node: "pve1", VMID: 101, Target: "pve2", Restart: true, TimeoutSec: 120,
		TargetStorage: "local-zfs:local-zfs"}
	if len(e.oc.migrations) != 1 || e.oc.migrations[0] != want {
		t.Fatalf("sent %+v", e.oc.migrations)
	}
}

func TestGuestMigrateOfflineStoppedQemuWithSharedDisksOnly(t *testing.T) {
	e := newOpEnv(t, permit.ProviderKindQemu)
	e.client.statusFn = func(int) string { return "stopped" }
	e.oc.config = map[string]string{"scsi0": "ceph:vm-101-disk-0", "hostpci0": "0000:01:00.0,pcie=1"}
	req := migrateReq()
	req.Online = false
	req.StorageMap = map[string]string{"ceph": "ceph"}
	req, _ = e.approveMigrate(req)
	if _, err := e.migrate.Run(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	// Shared storage only: nothing moves, so no mapping or local-disk flag
	// is sent; the passthrough guest may move offline.
	want := pveapi.MigrateRequest{Kind: pveapi.GuestQEMU, Node: "pve1", VMID: 101, Target: "pve2"}
	if len(e.oc.migrations) != 1 || e.oc.migrations[0] != want {
		t.Fatalf("sent %+v", e.oc.migrations)
	}
}

func TestGuestMigrateRequestRefusedWithoutIO(t *testing.T) {
	cases := map[string]func(r *PveGuestMigrateRequest){
		"target equals source":   func(r *PveGuestMigrateRequest) { r.Target = "pve1" },
		"malformed target":       func(r *PveGuestMigrateRequest) { r.Target = "pve2/../x" },
		"empty target":           func(r *PveGuestMigrateRequest) { r.Target = "" },
		"restart on qemu":        func(r *PveGuestMigrateRequest) { r.Restart, r.TimeoutSec = true, 60 },
		"timeout on qemu":        func(r *PveGuestMigrateRequest) { r.TimeoutSec = 60 },
		"node kind":              func(r *PveGuestMigrateRequest) { r.Kind = permit.ProviderKindNode },
		"malformed storage pair": func(r *PveGuestMigrateRequest) { r.StorageMap = map[string]string{"local-zfs": "a:b", "ceph": "ceph"} },
		"too many pairs": func(r *PveGuestMigrateRequest) {
			for i := 0; i <= pveapi.MaxStorageMappingPairs; i++ {
				r.StorageMap[fmt.Sprintf("s%d", i)] = "x"
			}
		},
		"bad vmid": func(r *PveGuestMigrateRequest) { r.VMID = 7 },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			e := newOpEnv(t, permit.ProviderKindQemu)
			req := migrateReq()
			mod(&req)
			_, err := e.proposeMigrate(req)
			if !errors.Is(err, ErrPveMigrateRequest) && !errors.Is(err, ErrPveMutationRequest) {
				t.Fatalf("got %v", err)
			}
			if e.oc.factReads != 0 || e.client.reads != 0 {
				t.Fatal("read the remote for a malformed request")
			}
		})
	}
	lxc := map[string]func(r *PveGuestMigrateRequest){
		"online on lxc":           func(r *PveGuestMigrateRequest) { r.Online = true },
		"restart without timeout": func(r *PveGuestMigrateRequest) { r.TimeoutSec = 0 },
		"timeout without restart": func(r *PveGuestMigrateRequest) { r.Restart = false },
		"timeout out of range":    func(r *PveGuestMigrateRequest) { r.TimeoutSec = pveapi.MaxPowerTimeoutSec + 1 },
	}
	for name, mod := range lxc {
		t.Run(name, func(t *testing.T) {
			e := newOpEnv(t, permit.ProviderKindLXC)
			req := lxcMigrateReq()
			mod(&req)
			if _, err := e.proposeMigrate(req); !errors.Is(err, ErrPveMigrateRequest) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestGuestMigrateRefusals(t *testing.T) {
	cases := []struct {
		name string
		kind string
		mod  func(e *opEnv, r *PveGuestMigrateRequest)
		want error
	}{
		{"target not in cluster", "qemu", func(_ *opEnv, r *PveGuestMigrateRequest) { r.Target = "pve9" }, ErrPveMigrateTarget},
		{"target offline", "qemu", func(e *opEnv, _ *PveGuestMigrateRequest) { e.oc.cluster.Members[1].Online = false }, ErrPveMigrateTarget},
		{"target listed twice", "qemu", func(e *opEnv, _ *PveGuestMigrateRequest) {
			e.oc.cluster.Members = append(e.oc.cluster.Members, pveapi.ClusterMember{Name: "pve2", Online: true})
		}, ErrPveMigrateTarget},
		{"cluster without quorum", "qemu", func(e *opEnv, _ *PveGuestMigrateRequest) { e.oc.cluster.Quorum = false }, ErrPveMigrateTarget},
		{"standalone remote", "qemu", func(e *opEnv, _ *PveGuestMigrateRequest) {
			e.oc.cluster = pveapi.ClusterStatus{Reason: "standalone host: no cluster configured"}
		}, ErrPveMigrateTarget},
		{"ha-managed vm", "qemu", func(e *opEnv, _ *PveGuestMigrateRequest) {
			e.oc.ha.Resources = append(e.oc.ha.Resources, pveapi.HAResource{VMID: 101, Type: "vm", Managed: true, DesiredState: "started"})
		}, ErrPveMigrateHA},
		{"ha-managed ct", "lxc", func(e *opEnv, _ *PveGuestMigrateRequest) {
			e.oc.ha.Resources = append(e.oc.ha.Resources, pveapi.HAResource{VMID: 101, Type: "ct", Managed: true})
		}, ErrPveMigrateHA},
		{"ha resource ignored is still refused", "qemu", func(e *opEnv, _ *PveGuestMigrateRequest) {
			e.oc.ha.Resources = append(e.oc.ha.Resources, pveapi.HAResource{VMID: 101, Type: "vm", DesiredState: "ignored"})
		}, ErrPveMigrateHA},
		{"ha state unreadable", "qemu", func(e *opEnv, _ *PveGuestMigrateRequest) {
			e.oc.ha = pveapi.HAStatus{Reason: "http status 403"}
		}, ErrPveMigrateState},
		{"live with hostpci", "qemu", func(e *opEnv, _ *PveGuestMigrateRequest) {
			e.oc.config["hostpci0"] = "0000:65:00,pcie=1,x-vga=1"
		}, ErrPveMigratePassthrough},
		{"live with second hostpci", "qemu", func(e *opEnv, _ *PveGuestMigrateRequest) {
			e.oc.config["hostpci3"] = "mapping=gpu"
		}, ErrPveMigratePassthrough},
		{"mapping misses a disk", "qemu", func(_ *opEnv, r *PveGuestMigrateRequest) { delete(r.StorageMap, "ceph") }, ErrPveMigrateStorage},
		{"mapping misses an unused volume", "qemu", func(e *opEnv, _ *PveGuestMigrateRequest) {
			e.oc.config["unused0"] = "slow:vm-101-disk-7"
			e.oc.storages = append(e.oc.storages, pveapi.Storage{ID: "slow", Type: "lvm", Content: []string{"images"}, Active: true})
		}, ErrPveMigrateStorage},
		{"mapping names an unused storage", "qemu", func(_ *opEnv, r *PveGuestMigrateRequest) { r.StorageMap["local"] = "fast-zfs" }, ErrPveMigrateStorage},
		{"empty mapping", "qemu", func(_ *opEnv, r *PveGuestMigrateRequest) { r.StorageMap = nil }, ErrPveMigrateStorage},
		{"shared storage mapped away", "qemu", func(_ *opEnv, r *PveGuestMigrateRequest) { r.StorageMap["ceph"] = "fast-zfs" }, ErrPveMigrateStorage},
		{"target storage without disk content", "qemu", func(_ *opEnv, r *PveGuestMigrateRequest) { r.StorageMap["local-zfs"] = "iso-only" }, ErrPveMigrateStorage},
		{"target storage not on target node", "qemu", func(_ *opEnv, r *PveGuestMigrateRequest) { r.StorageMap["local-zfs"] = "nowhere" }, ErrPveMigrateStorage},
		{"target storage inactive", "qemu", func(e *opEnv, _ *PveGuestMigrateRequest) { e.oc.targetStorages[1].Active = false }, ErrPveMigrateStorage},
		{"passthrough disk", "qemu", func(e *opEnv, _ *PveGuestMigrateRequest) { e.oc.config["scsi1"] = "/dev/disk/by-id/ata-X" }, ErrPveMigrateStorage},
		{"bind mount", "lxc", func(e *opEnv, _ *PveGuestMigrateRequest) { e.oc.config["mp0"] = "/srv/data,mp=/data" }, ErrPveMigrateStorage},
		{"unknown disk-like key", "qemu", func(e *opEnv, _ *PveGuestMigrateRequest) { e.oc.config["efidisk1"] = "local-zfs:vm-101-disk-8" }, ErrPveMigrateState},
		{"locked guest", "qemu", func(e *opEnv, _ *PveGuestMigrateRequest) { e.oc.config["lock"] = "backup" }, ErrPveMigrateState},
		{"running qemu offline", "qemu", func(_ *opEnv, r *PveGuestMigrateRequest) { r.Online = false }, ErrPveMigrateState},
		{"paused qemu online", "qemu", func(e *opEnv, _ *PveGuestMigrateRequest) { e.client.qmp = "paused" }, ErrPveMigrateState},
		{"stopped qemu online", "qemu", func(e *opEnv, _ *PveGuestMigrateRequest) {
			e.client.statusFn = func(int) string { return "stopped" }
		}, ErrPveMigrateState},
		{"running lxc without restart", "lxc", func(_ *opEnv, r *PveGuestMigrateRequest) { r.Restart, r.TimeoutSec = false, 0 }, ErrPveMigrateState},
		{"stopped lxc with restart", "lxc", func(e *opEnv, _ *PveGuestMigrateRequest) {
			e.client.statusFn = func(int) string { return "stopped" }
		}, ErrPveMigrateState},
		{"guest on another node", "qemu", func(e *opEnv, _ *PveGuestMigrateRequest) { e.client.liveNode = "pve3" }, ErrPveTargetChanged},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newOpEnv(t, tc.kind)
			req := migrateReq()
			if tc.kind == permit.ProviderKindLXC {
				req = lxcMigrateReq()
			}
			tc.mod(e, &req)
			_, err := e.proposeMigrate(req)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if e.oc.sentSteps() != 0 {
				t.Fatal("dispatched")
			}
		})
	}
}

func TestGuestMigrateHARefusalSaysWhy(t *testing.T) {
	if !strings.Contains(ErrPveMigrateHA.Error(), "HA-managed") || !strings.Contains(ErrPveMigrateHA.Error(), "HA manager") {
		t.Fatalf("message %q", ErrPveMigrateHA)
	}
}

// TestGuestMigrateRecheckBeforeDispatch: facts that change between
// authorization and the step's intent stop the run; nothing is sent.
func TestGuestMigrateRecheckBeforeDispatch(t *testing.T) {
	cases := []struct {
		name string
		mod  func(e *opEnv, c *opClient)
		want error
	}{
		{"guest became HA-managed", func(_ *opEnv, c *opClient) {
			c.ha.Resources = append(c.ha.Resources, pveapi.HAResource{VMID: 101, Type: "vm", Managed: true})
		}, ErrPveMigrateHA},
		{"target went offline", func(_ *opEnv, c *opClient) { c.cluster.Members[1].Online = false }, ErrPveMigrateTarget},
		{"hostpci added", func(_ *opEnv, c *opClient) { c.config["hostpci0"] = "0000:01:00.0" }, ErrPveMigratePassthrough},
		{"disk added", func(_ *opEnv, c *opClient) { c.config["scsi2"] = "local-zfs:vm-101-disk-5" }, ErrPveMigrateChanged},
		{"target storage gone", func(_ *opEnv, c *opClient) { c.targetStorages = c.targetStorages[:1] }, ErrPveMigrateStorage},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newOpEnv(t, permit.ProviderKindQemu)
			req, _ := e.approveMigrate(migrateReq())
			// Fact reads: propose (2), run prepare (3), before
			// authorization (4), before the intent (5).
			e.oc.onFacts = func(n int, c *opClient) {
				if n == 5 {
					tc.mod(e, c)
				}
			}
			res, err := e.migrate.Run(context.Background(), req)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if e.oc.sentSteps() != 0 || len(res.Steps) != 0 {
				t.Fatalf("dispatched: %d steps %+v", e.oc.sentSteps(), res.Steps)
			}
		})
	}
}

// TestGuestMigrateConfigDigestRecheckedBeforeIntent: a configuration
// change after authorization (new config digest) stops the run.
func TestGuestMigrateConfigDigestRecheckedBeforeIntent(t *testing.T) {
	e := newOpEnv(t, permit.ProviderKindQemu)
	req, _ := e.approveMigrate(migrateReq())
	e.oc.onFacts = func(n int, _ *opClient) {
		if n == 4 {
			// After the run's target read, before authorization: the
			// engine's re-read before the intent sees the new digest.
			e.client.mu.Lock()
			e.client.digest = strings.Repeat("ab", 32)
			e.client.mu.Unlock()
		}
	}
	_, err := e.migrate.Run(context.Background(), req)
	if !errors.Is(err, ErrPveTargetChanged) {
		t.Fatalf("got %v", err)
	}
	if e.oc.sentSteps() != 0 {
		t.Fatal("dispatched")
	}
}

func TestGuestMigrateGuestMovedAfterApproval(t *testing.T) {
	e := newOpEnv(t, permit.ProviderKindQemu)
	req, _ := e.approveMigrate(migrateReq())
	e.client.mu.Lock()
	e.client.liveNode = "pve2"
	e.client.mu.Unlock()
	if _, err := e.migrate.Run(context.Background(), req); !errors.Is(err, ErrPveTargetChanged) {
		t.Fatalf("got %v", err)
	}
	if e.oc.sentSteps() != 0 {
		t.Fatal("dispatched")
	}
}

// TestGuestMigrateDispatcherRechecksHA: the dispatcher re-reads HA and
// cluster state right before sending; a guest put under HA after the
// engine's checks is not migrated.
func TestGuestMigrateDispatcherRechecks(t *testing.T) {
	cases := map[string]func(c *opClient){
		"ha":      func(c *opClient) { c.ha.Resources = append(c.ha.Resources, pveapi.HAResource{VMID: 101, Type: "vm"}) },
		"offline": func(c *opClient) { c.cluster.Members[1].Online = false },
		"quorum":  func(c *opClient) { c.cluster.Quorum = false },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			e := newOpEnv(t, permit.ProviderKindQemu)
			req, _ := e.approveMigrate(migrateReq())
			e.oc.onRecheck = mod
			res, err := e.migrate.Run(context.Background(), req)
			if !errors.Is(err, ErrPveStepFailed) {
				t.Fatalf("got %v", err)
			}
			if len(e.oc.migrations) != 0 {
				t.Fatalf("sent %+v", e.oc.migrations)
			}
			if len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobFailed {
				t.Fatalf("steps %+v", res.Steps)
			}
		})
	}
}

func TestGuestMigrateRiskIncludesDestinationNode(t *testing.T) {
	cases := []struct {
		name string
		dest canonical.Risk
		want canonical.Risk
	}{
		{"medium destination", canonical.RiskMedium, canonical.RiskHigh},
		{"critical destination", canonical.RiskCritical, canonical.RiskCritical},
		{"unknown destination", "", canonical.RiskHigh},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newOpEnv(t, permit.ProviderKindQemu)
			_, n2, _ := e.nodeTargets(permit.ProviderKindQemu, "pve2")
			if tc.dest == "" {
				delete(e.crit.hosts, n2)
			} else {
				e.crit.hosts[n2] = tc.dest
			}
			p, err := e.proposeMigrate(migrateReq())
			if err != nil {
				t.Fatal(err)
			}
			if p.Request.RiskClass != tc.want {
				t.Fatalf("risk %s, want %s", p.Request.RiskClass, tc.want)
			}
		})
	}
}

// TestGuestMigratePermitBindsTarget: a run with another destination or
// mapping than the approved one is not authorized.
func TestGuestMigratePermitBindsTarget(t *testing.T) {
	cases := map[string]func(r *PveGuestMigrateRequest){
		"other destination": func(r *PveGuestMigrateRequest) { r.Target = "pve3"; r.StorageMap["local-zfs"] = "local-zfs" },
		"other mapping":     func(r *PveGuestMigrateRequest) { r.StorageMap["local-zfs"] = "local-zfs" },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			e := newOpEnv(t, permit.ProviderKindQemu)
			req, _ := e.approveMigrate(migrateReq())
			mod(&req)
			if _, err := e.migrate.Run(context.Background(), req); !errors.Is(err, ErrPveMutationDenied) {
				t.Fatalf("got %v", err)
			}
			if e.oc.sentSteps() != 0 {
				t.Fatal("dispatched")
			}
		})
	}
}

func TestGuestMigrateRestartReconcileFindsTask(t *testing.T) {
	e := newOpEnv(t, permit.ProviderKindQemu)
	req, _ := e.approveMigrate(migrateReq())
	e.oc.lost = true
	res, err := e.migrate.Run(context.Background(), req)
	if !errors.Is(err, ErrPveDispatchUncertain) {
		t.Fatalf("lost response: %v", err)
	}
	if len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobReconciling || res.Steps[0].UPID != "" {
		t.Fatalf("steps %+v", res.Steps)
	}
	e.restartOp()
	now := time.Now()
	own := testTaskUPID("pve1", now, "qmigrate", "101", mutActionUser, 9)
	e.client.recent = []string{
		testTaskUPID("pve1", now, "qmigrate", "102", mutActionUser, 4),
		testTaskUPID("pve1", now, "vzdump", "101", mutActionUser, 5),
		testTaskUPID("pve1", now, "qmigrate", "101", "root@pam", 6),
		own,
	}
	if err := e.migrate.Mutations.Reconcile(context.Background()); err != nil {
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

func TestGuestMigrateRestartReconcileAmbiguousStaysUnknown(t *testing.T) {
	e := newOpEnv(t, permit.ProviderKindQemu)
	req, _ := e.approveMigrate(migrateReq())
	e.oc.lost = true
	res, _ := e.migrate.Run(context.Background(), req)
	e.restartOp()
	now := time.Now()
	e.client.recent = []string{
		testTaskUPID("pve1", now, "qmigrate", "101", mutActionUser, 7),
		testTaskUPID("pve1", now, "qmigrate", "101", mutActionUser, 8),
	}
	if err := e.migrate.Mutations.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	steps, err := e.pe.db.PveJobSteps(res.ExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 1 || steps[0].State != executordb.PveJobUnknown || steps[0].UPID != "" {
		t.Fatalf("reconciled %+v", steps)
	}
	if e.oc.sentSteps() != 1 {
		t.Fatalf("reconcile dispatched again: %d", e.oc.sentSteps())
	}
}

// TestDispatchGuestMigrateStepSendsExactForm sends a migration step
// through the real pveapi writer: exact target, online flag, mapping and
// local-disk flag; never force or migration_network.
func TestDispatchGuestMigrateStepSendsExactForm(t *testing.T) {
	var form url.Values
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ = url.ParseQuery(string(body))
		path = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"data":%q}`, testTaskUPID("pve1", time.Now(), "qmigrate", "101", mutActionUser, 1))
	}))
	defer srv.Close()
	tok := func(context.Context) (string, error) { return "PVEAPIToken=" + mutActionUser + "=secret", nil }
	w, err := pveapi.NewWriter(srv.URL, srv.Client(), tok, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	e := &opClient{cluster: pveapi.ClusterStatus{Available: true, Quorum: true,
		Members: []pveapi.ClusterMember{{Name: "pve1", Online: true}, {Name: "pve2", Online: true}}},
		ha: pveapi.HAStatus{Reason: pveHANotEnabled}}
	args, _ := json.Marshal(pveMigrateStepArgs{VMID: 101, Target: "pve2", Online: true, TargetStorage: "local-zfs:fast-zfs", WithLocalDisks: true})
	if _, err := DispatchGuestMigrateStep(context.Background(), w, &opReader{c: e}, "pve1", PveMutationStep{Method: "migrate.qemu", Args: args}); err != nil {
		t.Fatal(err)
	}
	if path != "/api2/json/nodes/pve1/qemu/101/migrate" {
		t.Fatalf("path %s", path)
	}
	want := map[string]string{"target": "pve2", "online": "1", "targetstorage": "local-zfs:fast-zfs", "with-local-disks": "1"}
	for k, v := range want {
		if form.Get(k) != v {
			t.Fatalf("%s = %q, want %q (form %v)", k, form.Get(k), v, form)
		}
	}
	if form.Has("force") || form.Has("migration_network") || len(form) != len(want) {
		t.Fatalf("unexpected members: %v", form)
	}
}

func TestDispatchGuestMigrateStepRejectsMalformedArgs(t *testing.T) {
	oc := &opClient{cluster: pveapi.ClusterStatus{Available: true, Quorum: true,
		Members: []pveapi.ClusterMember{{Name: "pve1", Online: true}, {Name: "pve2", Online: true}}},
		ha: pveapi.HAStatus{Available: true}}
	w := &opWriter{c: oc}
	cases := map[string]struct{ method, args string }{
		"target equals node":   {"migrate.qemu", `{"vmid":101,"target":"pve1","online":true,"restart":false,"timeout":0,"targetstorage":"","with_local_disks":false}`},
		"force smuggled":       {"migrate.qemu", `{"vmid":101,"target":"pve2","online":true,"force":true}`},
		"restart on qemu":      {"migrate.qemu", `{"vmid":101,"target":"pve2","restart":true,"timeout":5}`},
		"online on lxc":        {"migrate.lxc", `{"vmid":101,"target":"pve2","online":true}`},
		"local disks on lxc":   {"migrate.lxc", `{"vmid":101,"target":"pve2","with_local_disks":true}`},
		"target not a member":  {"migrate.qemu", `{"vmid":101,"target":"pve7","online":true}`},
		"unknown method":       {"migrate.node", `{"vmid":101,"target":"pve2"}`},
		"malformed target str": {"migrate.qemu", `{"vmid":101,"target":"pve2;rm","online":true}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := DispatchGuestMigrateStep(context.Background(), w, &opReader{c: oc}, "pve1", PveMutationStep{Method: tc.method, Args: json.RawMessage(tc.args)})
			if !errors.Is(err, ErrPveRejected) {
				t.Fatalf("got %v", err)
			}
		})
	}
	if len(oc.migrations) != 0 {
		t.Fatalf("sent %+v", oc.migrations)
	}
}
