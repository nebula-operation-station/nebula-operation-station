// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Read side of the container update controls (container update plan cu04):
// what the tree offers for one host, and the exact binding a selection
// would be proposed with. The confirmation page shows these bindings; the
// proposal builds them again from the same preview, so what was shown is
// what is proposed (or the proposal is refused).

// ErrRecreationsUnavailable: the planner has no connection to the
// executor's recreation list, so no rollback can be offered.
var ErrRecreationsUnavailable = errors.New("the executor's container recreation list is not connected")

// ContainerPreview is the newest finished, successful docker.update_preview
// run of one host as the container update controls show it.
type ContainerPreview struct {
	// ID is the run; "" when the host has no such run.
	ID string
	// StartedAt is when the run started on the host.
	StartedAt time.Time
	// Stale is why the run cannot bind a proposal ("" when it can): too
	// old, of another artifact, or unreadable. A stale preview has no
	// units.
	Stale string
	// Status is the preview's status (ok, prepare_required, ...); only ok
	// carries units.
	Status string
	// Units are the preview's units, untrusted host data checked by
	// dockerhost.ParseUpdatePreview. They hold no secret: the preview
	// reports identities, digests and reasons only.
	Units []dockerhost.PreviewUnit
}

// LatestContainerPreview returns the newest finished, successful
// docker.update_preview run of hostID with the same freshness rules a
// proposal applies (freshPreviewAnyStatus).
func (b *Batches) LatestContainerPreview(ctx context.Context, hostID string) (ContainerPreview, error) {
	var (
		id      string
		started sql.NullInt64
	)
	err := b.db.QueryRowContext(ctx, `SELECT e.id, h.started_at FROM execution_hosts h JOIN executions e ON e.id = h.execution_id
		WHERE e.action_id = ? AND h.host_id = ? AND h.state = 'finished' AND h.class = 'success'
		ORDER BY h.started_at DESC, h.finished_at DESC, e.id DESC LIMIT 1`, updatePreviewAction, hostID).Scan(&id, &started)
	if errors.Is(err, sql.ErrNoRows) {
		return ContainerPreview{}, nil
	}
	if err != nil {
		return ContainerPreview{}, fmt.Errorf("latest update preview of %s: %w", hostID, err)
	}
	out := ContainerPreview{ID: id}
	if started.Valid {
		out.StartedAt = time.Unix(started.Int64, 0)
	}
	p, err := b.freshPreviewAnyStatus(ctx, hostID, id, 1)
	switch {
	case errors.Is(err, ErrBatchPreviewStale):
		out.Stale = fmt.Sprintf("the preview is older than %s; run a fresh preview", maxPreviewBindingAge)
		return out, nil
	case errors.Is(err, ErrBatchPreviewMissing):
		out.Stale = "the newest preview cannot be used (another artifact or an unreadable result); run a fresh preview"
		return out, nil
	case err != nil:
		return ContainerPreview{}, err
	}
	out.Status = p.Status
	if p.Status == dockerhost.PreviewOK {
		out.Units = p.Units
	}
	return out, nil
}

// ContainerRecreations lists the executor's container recreation rows of
// hostID, the source of every rollback offer.
func (b *Batches) ContainerRecreations(ctx context.Context, hostID string) ([]*pb.ContainerRecreationInfo, error) {
	if b.recreations == nil {
		return nil, ErrRecreationsUnavailable
	}
	cctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	list, err := b.recreations.ListContainerRecreations(cctx, &pb.ListContainerRecreationsRequest{HostId: hostID})
	if err != nil {
		return nil, fmt.Errorf("list container recreations of %s: %w", hostID, err)
	}
	return list.GetRecreations(), nil
}

// PlanContainerUpdate builds the docker.compose_update binding of spec on
// hostID exactly as ProposeBatch does, without proposing anything.
func (b *Batches) PlanContainerUpdate(ctx context.Context, hostID string, spec ContainerUpdateSpec) (canonical.BatchContainerUpdate, error) {
	return b.updateBinding(ctx, hostID, spec, 1)
}

// PlanContainerRollback builds the docker.compose_rollback binding of spec
// on hostID exactly as ProposeBatch does, without proposing anything.
func (b *Batches) PlanContainerRollback(ctx context.Context, hostID string, spec ContainerRollbackSpec) (canonical.BatchContainerUpdate, error) {
	return b.rollbackBinding(ctx, hostID, spec, 1)
}
