// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vault"
)

// TestPveMutationMalformedRequestNeverReadsRemote: kind, node and VMID are
// validated before the read token is used for a live read.
func TestPveMutationMalformedRequestNeverReadsRemote(t *testing.T) {
	cases := map[string]func(*PveMutationRequest){
		"dotted node":    func(r *PveMutationRequest) { r.Node = "pve1.lab.test" },
		"uppercase node": func(r *PveMutationRequest) { r.Node = "PVE1" },
		"path node":      func(r *PveMutationRequest) { r.Node = "../nodes" },
		"unknown kind":   func(r *PveMutationRequest) { r.Kind = "storage" },
		"guest no vmid":  func(r *PveMutationRequest) { r.VMID = 0 },
		"node with vmid": func(r *PveMutationRequest) { r.Kind = permit.ProviderKindNode },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := newPveMutEnv(t, true)
			req := mutRequest("guest.start")
			mutate(&req)
			_, _, err := e.m.ProposalRequest(context.Background(), req, "00000000-0000-4000-a000-999999999998", canonical.RiskMedium, strings.Repeat("c", 64), time.Now().Add(time.Hour))
			if !errors.Is(err, ErrPveMutationRequest) {
				t.Fatalf("proposal: %v", err)
			}
			if _, err := e.m.Run(context.Background(), req); !errors.Is(err, ErrPveMutationRequest) {
				t.Fatalf("run: %v", err)
			}
			if e.client.targetReads != 0 || len(e.client.readHeaders) != 0 || e.client.dispatchCount() != 0 {
				t.Fatalf("malformed request reached the remote: %d reads", e.client.targetReads)
			}
		})
	}
}

// TestPveMutationRefusesMalformedGeneration: a guest generation from the
// remote that is not a PVE config digest refuses the proposal.
func TestPveMutationRefusesMalformedGeneration(t *testing.T) {
	for _, gen := range []string{strings.Repeat("9F", 20), strings.Repeat("9f", 32), "x"} {
		e := newPveMutEnv(t, true)
		e.client.generation = gen
		_, _, err := e.m.ProposalRequest(context.Background(), mutRequest("guest.start"), "00000000-0000-4000-a000-999999999997", canonical.RiskMedium, strings.Repeat("c", 64), time.Now().Add(time.Hour))
		if !errors.Is(err, ErrPveTargetChanged) {
			t.Fatalf("generation %q: %v", gen, err)
		}
	}
}

// TestPveMutationBindsGuestGeneration: the approval binds the generation
// read at proposal time; a write to the guest's config in between refuses
// the run without consuming anything.
func TestPveMutationBindsGuestGeneration(t *testing.T) {
	e := newPveMutEnv(t, true)
	e.client.generation = strings.Repeat("11", 20)
	req := e.approve(mutRequest("guest.start"))
	e.client.generation = strings.Repeat("22", 20)
	if _, err := e.m.Run(context.Background(), req); !errors.Is(err, ErrPveMutationDenied) || !errors.Is(err, ErrPvePermitFinal) {
		t.Fatalf("run after a config write: %v", err)
	}
	if e.client.dispatchCount() != 0 {
		t.Fatal("dispatched against another guest generation")
	}
}

// TestPveMutationBusyTargetKeepsApproval: a run refused because another
// step on the target is still open dispatched nothing, so its approval
// stays usable once the target is free (review L1 of PR #151).
func TestPveMutationBusyTargetKeepsApproval(t *testing.T) {
	e := newPveMutEnv(t, true)
	a := e.approve(mutRequest("guest.start"))
	b := e.approve(mutRequest("guest.start"))
	e.client.onDispatch = func(int, string) (string, error) { return "", errors.New("connection reset") }
	if _, err := e.m.Run(context.Background(), a); !errors.Is(err, ErrPveDispatchUncertain) {
		t.Fatalf("run a: %v", err)
	}
	e.client.onDispatch = nil
	resB, err := e.m.Run(context.Background(), b)
	if !errors.Is(err, ErrPveTargetBusy) || resB.PermitConsumed || len(resB.Steps) != 0 {
		t.Fatalf("busy run b: %v %+v", err, resB)
	}
	if !strings.Contains(e.logs.String(), "pve_mutation_permit_released") {
		t.Fatal("release not audited")
	}
	// A ends unknown; then the same approval of b runs once.
	e.passMatchWindow()
	if err := e.m.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.m.Now = nil
	resB, err = e.m.Run(context.Background(), b)
	if err != nil || !resB.PermitConsumed || len(resB.Steps) != 1 || resB.Steps[0].State != executordb.PveJobSucceeded {
		t.Fatalf("run b after a ended: %v %+v", err, resB)
	}
	if _, err := e.m.Run(context.Background(), b); !errors.Is(err, ErrPveMutationAlreadyRun) {
		t.Fatalf("third run of b: %v", err)
	}
	if e.client.dispatchCount() != 2 {
		t.Fatalf("dispatches: %d", e.client.dispatchCount())
	}
}

// lostStep leaves one reconciling step of a guest.start on the test remote.
func (e *pveMutEnv) lostStep() PveMutationResult {
	e.t.Helper()
	req := e.approve(mutRequest("guest.start"))
	e.client.onDispatch = func(int, string) (string, error) { return "", errors.New("connection reset") }
	res, err := e.m.Run(context.Background(), req)
	e.client.onDispatch = nil
	if !errors.Is(err, ErrPveDispatchUncertain) || len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobReconciling {
		e.t.Fatalf("lost step: %v %+v", err, res.Steps)
	}
	return res
}

// TestPveAdminCloseOpenJobsOfUnobservableRemote: the open steps of a
// removed remote, or of a blocked one that was never re-pinned, are never
// reconciled; an admin closes them through an audited path.
func TestPveAdminCloseOpenJobsOfUnobservableRemote(t *testing.T) {
	cases := map[string]func(*pveMutEnv){
		"removed": func(e *pveMutEnv) {
			if _, err := e.pe.admin.RemoveRemote(context.Background(), PveRemove{RemoteID: mutRemote, By: "admin"}); err != nil {
				e.t.Fatal(err)
			}
		},
		"blocked": func(e *pveMutEnv) {
			if _, err := e.pe.db.BlockRemote(mutRemote, "trust verification failed", "admin"); err != nil {
				e.t.Fatal(err)
			}
		},
	}
	for name, makeUnobservable := range cases {
		t.Run(name, func(t *testing.T) {
			e := newPveMutEnv(t, true)
			var audit bytes.Buffer
			e.pe.admin.Log = slog.New(slog.NewTextHandler(&audit, nil))
			res := e.lostStep()
			in := PveCloseJobs{RemoteID: mutRemote, Reason: "node reinstalled; task outcome checked by hand", By: "alice"}

			// While the remote is active, Reconcile owns the step.
			if _, err := e.pe.admin.CloseOpenJobs(context.Background(), in); !errors.Is(err, ErrPveRemoteActive) {
				t.Fatalf("close on active remote: %v", err)
			}
			makeUnobservable(e)
			// Inside the step's task match window a lost task may still
			// start, so the close is refused and audited.
			if _, err := e.pe.admin.CloseOpenJobs(context.Background(), in); !errors.Is(err, ErrPveJobMatchWindowOpen) {
				t.Fatalf("close inside the match window: %v", err)
			}
			if !strings.Contains(audit.String(), "pve_mutation_close_refused") {
				t.Fatalf("refused close not audited: %s", audit.String())
			}
			e.passMatchWindow()
			e.pe.admin.Now = e.m.Now
			if err := e.m.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if open, _ := e.pe.db.OpenPveJobs(); len(open) != 1 {
				t.Fatalf("reconcile decided an unobservable step: %+v", open)
			}

			e.pe.vault.Lock()
			if _, err := e.pe.admin.CloseOpenJobs(context.Background(), in); !errors.Is(err, vault.ErrLocked) {
				t.Fatalf("close with locked vault: %v", err)
			}
			if err := e.pe.vault.Unlock([]byte(e.pe.passphrase)); err != nil {
				t.Fatal(err)
			}
			before := e.client.dispatchCount()
			closed, err := e.pe.admin.CloseOpenJobs(context.Background(), in)
			if err != nil || len(closed) != 1 || closed[0].ExecutionID != res.ExecutionID {
				t.Fatalf("close: %v %+v", err, closed)
			}
			j, _, _ := e.pe.db.PveJob(res.ExecutionID, 1)
			if j.State != executordb.PveJobUnknown || j.ClosedBy != "alice" || j.ClosedReason != in.Reason {
				t.Fatalf("closed step: %+v", j)
			}
			if open, _ := e.pe.db.OpenPveJobs(); len(open) != 0 {
				t.Fatalf("open after close: %+v", open)
			}
			if e.client.dispatchCount() != before {
				t.Fatal("closing dispatched")
			}
			log := audit.String()
			if !strings.Contains(log, "pve_mutation_closed_by_admin") || !strings.Contains(log, res.ExecutionID) || !strings.Contains(log, "by=alice") {
				t.Fatalf("close not audited: %s", log)
			}
		})
	}
}

// TestPveAdminCloseOpenJobsRefusesInFlightRun: a step whose run is still
// in flight in this executor is never closed, even when its remote was
// blocked meanwhile and its match window has passed: the task may still
// be dispatched or running, and freeing the target could attribute it to
// another job. Once the run has ended, the close goes through.
func TestPveAdminCloseOpenJobsRefusesInFlightRun(t *testing.T) {
	e := newPveMutEnv(t, true)
	var audit bytes.Buffer
	e.pe.admin.Log = slog.New(slog.NewTextHandler(&audit, nil))
	later := time.Now().Add(pveTaskMatchWindow + pveTaskMatchSkew + time.Minute)
	e.pe.admin.Now = func() time.Time { return later }
	req := e.approve(mutRequest("guest.start"))
	in := PveCloseJobs{RemoteID: mutRemote, Reason: "remote blocked during dispatch", By: "alice"}

	var closeErr error
	e.client.onDispatch = func(int, string) (string, error) {
		if _, err := e.pe.db.BlockRemote(mutRemote, "trust verification failed", "admin"); err != nil {
			t.Error(err)
		}
		_, closeErr = e.pe.admin.CloseOpenJobs(context.Background(), in)
		return "", errors.New("connection reset")
	}
	res, err := e.m.Run(context.Background(), req)
	e.client.onDispatch = nil
	if !errors.Is(closeErr, ErrPveJobInFlight) {
		t.Fatalf("close during dispatch: %v", closeErr)
	}
	if !strings.Contains(audit.String(), "pve_mutation_close_refused") {
		t.Fatalf("refused close not audited: %s", audit.String())
	}
	if !errors.Is(err, ErrPveDispatchUncertain) || len(res.Steps) != 1 || res.Steps[0].State != executordb.PveJobReconciling {
		t.Fatalf("run: %v %+v", err, res.Steps)
	}
	j, _, _ := e.pe.db.PveJob(res.ExecutionID, 1)
	if j.ClosedBy != "" || j.State != executordb.PveJobReconciling {
		t.Fatalf("in-flight step was closed: %+v", j)
	}

	closed, err := e.pe.admin.CloseOpenJobs(context.Background(), in)
	if err != nil || len(closed) != 1 || closed[0].ExecutionID != res.ExecutionID {
		t.Fatalf("close after the run: %v %+v", err, closed)
	}
}
