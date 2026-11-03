// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"fmt"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
)

// ErrPveRemoteActive is returned when an admin tries to close the open
// mutation steps of an active remote: Reconcile observes those through the
// current pin and decides them itself.
var ErrPveRemoteActive = errors.New("executor: pve remote is active; its open mutation steps are reconciled, not closed")

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
// active remote is refused with ErrPveRemoteActive. The vault must be
// unlocked, as for the other remote lifecycle operations.
func (a *PveAdmin) CloseOpenJobs(ctx context.Context, in PveCloseJobs) ([]executordb.PveJob, error) {
	if err := a.checkDeps(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	closed, err := a.DB.ClosePveJobs(in.RemoteID, in.By, in.Reason)
	if errors.Is(err, executordb.ErrPveRemoteActive) {
		return nil, fmt.Errorf("executor: pve close jobs: %w: %s", ErrPveRemoteActive, in.RemoteID)
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
