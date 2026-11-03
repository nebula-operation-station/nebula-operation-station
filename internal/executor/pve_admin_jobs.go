// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
)

// ErrPveRemoteActive is returned when an admin tries to close the open
// mutation steps of an active remote: Reconcile observes those through the
// current pin and decides them itself.
var ErrPveRemoteActive = errors.New("executor: pve remote is active; its open mutation steps are reconciled, not closed")

// ErrPveJobInFlight is returned when an admin tries to close the open
// mutation steps of a remote while a run of one of them is still in
// flight in this executor: its task may still be dispatched or running on
// the remote, so freeing the target could attribute it to another job.
var ErrPveJobInFlight = errors.New("executor: a pve mutation step of the remote is still in flight; close refused")

// ErrPveJobMatchWindowOpen is returned when an admin tries to close the
// open mutation steps of a remote while one of them is still inside its
// task match window, the time a lost task may still start in.
var ErrPveJobMatchWindowOpen = errors.New("executor: a pve mutation step of the remote is inside its task match window; close refused")

// PveCloseJobs carries one request to close the open mutation steps of a
// remote.
type PveCloseJobs struct {
	// RemoteID is the remote whose open steps are closed.
	RemoteID string
	// Reason is the admin's nonsecret explanation, stored with every
	// closed step (at most executordb.MaxPveJobCloseReason bytes).
	Reason string
	// By is the authenticated admin identity.
	By string
}

// CloseOpenJobs is the audited admin path for the open mutation steps of a
// remote that Reconcile can never observe: a removed remote, or one that is
// blocked and was never re-pinned. Every open step of the remote becomes
// unknown, and its record names the admin and the reason. Without this
// path the steps would keep their targets busy forever (ErrPveTargetBusy).
// Nothing is sent to the remote, and a task that ran there stays done. An
// active remote is refused with ErrPveRemoteActive. The close is also
// refused as a whole, closing nothing, while any open step of the remote
// is still being run by a.Mutations (ErrPveJobInFlight) or is still
// inside its task match window (ErrPveJobMatchWindowOpen); the refusal is
// audited. The vault must be unlocked, as for the other remote lifecycle
// operations, and a.Mutations must be the engine that runs this
// executor's mutations.
func (a *PveAdmin) CloseOpenJobs(ctx context.Context, in PveCloseJobs) ([]executordb.PveJob, error) {
	if err := a.checkDeps(); err != nil {
		return nil, err
	}
	if a.Mutations == nil {
		return nil, errors.New("executor: pve admin: Mutations is required to close open jobs")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	at := now()
	closed, err := a.DB.ClosePveJobs(in.RemoteID, in.By, in.Reason, func(j executordb.PveJob) error {
		// The run checks in before it records the step's intent and
		// checks out after its last step, so a step of a running
		// execution is never closed under it.
		if a.Mutations.running(j.ExecutionID) {
			return fmt.Errorf("%w: execution %s step %d", ErrPveJobInFlight, j.ExecutionID, j.Step)
		}
		if at.Before(j.CreatedAt.Add(pveTaskMatchWindow + pveTaskMatchSkew)) {
			return fmt.Errorf("%w: execution %s step %d", ErrPveJobMatchWindowOpen, j.ExecutionID, j.Step)
		}
		return nil
	})
	if errors.Is(err, executordb.ErrPveRemoteActive) {
		return nil, fmt.Errorf("executor: pve close jobs: %w: %s", ErrPveRemoteActive, in.RemoteID)
	}
	if errors.Is(err, ErrPveJobInFlight) || errors.Is(err, ErrPveJobMatchWindowOpen) {
		a.log().Warn("audit", "kind", "pve_mutation_close_refused", "remote", in.RemoteID, "reason", err.Error(), "by", in.By)
	}
	if err != nil {
		return nil, fmt.Errorf("executor: pve close jobs: %w", err)
	}
	for _, j := range closed {
		a.log().Warn("audit", "kind", "pve_mutation_closed_by_admin", "remote", j.RemoteID, "execution", j.ExecutionID, "step", j.Step,
			"node", j.Node, "vmid", j.VMID, "task_known", j.UPID != "", "by", in.By)
	}
	a.log().Warn("audit", "kind", "pve_mutation_jobs_closed", "remote", in.RemoteID, "count", len(closed), "by", in.By)
	return closed, nil
}
