// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
)

// Member outcomes (ADR 0007 E13). Planned and dispatched are the only
// open outcomes; every other outcome is final. No outcome leads back to
// planned or dispatched: the server never retries, redispatches or rolls
// back a member of a batch.
const (
	// OutcomePlanned: approved or waiting for approval, not dispatched.
	OutcomePlanned = "planned"
	// OutcomeDispatched: handed to the executor; its result is open.
	OutcomeDispatched = "dispatched"
	// OutcomeSuccess: the member ran and succeeded.
	OutcomeSuccess = "success"
	// OutcomeFailed: the member ran (or could not reach its host) and failed.
	OutcomeFailed = "failed"
	// OutcomeSkipped: an admin skipped the member before dispatch.
	OutcomeSkipped = "skipped"
	// OutcomeNotExecuted: the failure policy, a lost approval or the
	// expiry stopped the member before dispatch.
	OutcomeNotExecuted = "not_executed"
	// OutcomeUnknown: the member was dispatched but its outcome could not
	// be learned. It may have changed the host and is never redispatched.
	OutcomeUnknown = "unknown"
)

// Errors of outcome recording.
var (
	ErrBatchMemberNotFound = errors.New("batch member not found")
	// ErrBatchMemberFinal refuses any change of a final outcome (no
	// retry, no redispatch, no rollback).
	ErrBatchMemberFinal = errors.New("the member already has a final outcome; a retry or rollback needs a new batch")
	// ErrBatchNotDispatchable refuses a dispatch the plan does not allow.
	ErrBatchNotDispatchable = errors.New("the member cannot be dispatched")
	// ErrBatchOutcome refuses an outcome that is not a result.
	ErrBatchOutcome = errors.New("invalid member outcome")
)

// BatchMemberView is one member as shown in the full plan: every binding
// the approval covers. Strings that came from a user or host are
// untrusted and must be rendered as text.
type BatchMemberView struct {
	// Index is the 1-based plan position.
	Index          int
	MemberID       string
	ExecutionID    string
	Stage          int
	ActionID       string
	ActionTitle    string
	ModuleVersion  string
	ArtifactSHA256 string
	ParametersHash string
	// Params is the exact parameter document (JSON text).
	Params        string
	Risk          string
	HostID        string
	Fingerprint   string
	CredentialRef string
	ContainerID   string
	Outcome       string
	Unreachable   bool
	Detail        string
	UpdatedAt     time.Time
}

// BatchStageView is one approved stage.
type BatchStageView struct {
	Number               int
	StageID              string
	Gate                 string
	FailureThreshold     int
	UnreachableThreshold int
	Members              int
}

// BatchCounts counts members by outcome.
type BatchCounts struct {
	Total, Planned, Dispatched, Success, Failed, Skipped, NotExecuted, Unknown int
}

// BatchView is a stored batch with its complete member list.
type BatchView struct {
	ID             string
	Digest         string
	State          string
	Risk           string
	Requirement    string
	Options        []byte
	ApprovalExpiry time.Time
	Expiry         time.Time
	ApprovedBy     string
	Detail         string
	CreatedBy      string
	CreatedAt      time.Time
	Stages         []BatchStageView
	Members        []BatchMemberView
	Counts         BatchCounts
	// Summary is the overall result in words (BatchSummaryText).
	Summary string
}

// BatchSummary is one row of the batch list.
type BatchSummary struct {
	ID        string
	State     string
	Risk      string
	CreatedBy string
	CreatedAt time.Time
	Counts    BatchCounts
	Summary   string
}

func memberViewOf(m plannedMember) BatchMemberView {
	r := m.member.Request
	v := BatchMemberView{MemberID: m.member.MemberID, ExecutionID: r.ExecutionID, Stage: m.stage, ActionID: r.ActionID, ActionTitle: m.action.Title,
		ModuleVersion: r.ModuleVersion, ArtifactSHA256: r.ArtifactSHA256, ParametersHash: r.ParametersHash, Params: string(m.params),
		Risk: string(r.RiskClass), CredentialRef: strings.Join(r.CredentialRefs, ","), Outcome: OutcomePlanned}
	if len(r.ResolvedTargets) == 1 {
		v.HostID, v.Fingerprint = r.ResolvedTargets[0].HostID, r.ResolvedTargets[0].HostKeyFingerprint
	}
	if m.member.Container != nil {
		v.ContainerID = m.member.Container.ContainerID
	}
	return v
}

// count adds one member outcome.
func (c *BatchCounts) count(outcome string) {
	c.Total++
	switch outcome {
	case OutcomePlanned:
		c.Planned++
	case OutcomeDispatched:
		c.Dispatched++
	case OutcomeSuccess:
		c.Success++
	case OutcomeFailed:
		c.Failed++
	case OutcomeSkipped:
		c.Skipped++
	case OutcomeNotExecuted:
		c.NotExecuted++
	case OutcomeUnknown:
		c.Unknown++
	}
}

// BatchSummaryText is the overall result of a batch in words. A batch
// with successful and failed (or unknown, or not executed) members is
// "partially failed": nothing was rolled back.
func BatchSummaryText(state string, c BatchCounts) string {
	switch {
	case state == "pending":
		return "waiting for approval"
	case c.Planned+c.Dispatched > 0 && state == "approved":
		if c.Dispatched+c.Success+c.Failed+c.Unknown+c.Skipped+c.NotExecuted == 0 {
			return "approved, not started"
		}
		return "in progress"
	case c.Total > 0 && c.Success == c.Total:
		return "succeeded"
	case c.Success > 0:
		return "partially failed"
	case c.Failed+c.Unknown > 0:
		return "failed"
	default:
		return "not executed"
	}
}

// Batch returns a stored batch with every member in plan order.
func (b *Batches) Batch(ctx context.Context, id string) (BatchView, error) {
	var v BatchView
	var approval, expiry, created int64
	err := b.db.QueryRowContext(ctx, `SELECT id, digest, state, risk, requirement, options, approval_expiry, expiry, approved_by, detail, created_by, created_at
		FROM batches WHERE id = ?`, id).Scan(&v.ID, &v.Digest, &v.State, &v.Risk, &v.Requirement, &v.Options, &approval, &expiry, &v.ApprovedBy,
		&v.Detail, &v.CreatedBy, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return BatchView{}, ErrBatchNotFound
	}
	if err != nil {
		return BatchView{}, fmt.Errorf("load batch %s: %w", id, err)
	}
	v.ApprovalExpiry, v.Expiry, v.CreatedAt = time.Unix(approval, 0), time.Unix(expiry, 0), time.Unix(created, 0)
	srows, err := b.db.QueryContext(ctx, `SELECT s.stage, s.stage_id, s.gate, s.failure_threshold, s.unreachable_threshold,
		(SELECT count(*) FROM batch_members m WHERE m.batch_id = s.batch_id AND m.stage = s.stage)
		FROM batch_stages s WHERE s.batch_id = ? ORDER BY s.stage`, id)
	if err != nil {
		return BatchView{}, fmt.Errorf("load batch %s stages: %w", id, err)
	}
	for srows.Next() {
		var s BatchStageView
		if err := srows.Scan(&s.Number, &s.StageID, &s.Gate, &s.FailureThreshold, &s.UnreachableThreshold, &s.Members); err != nil {
			srows.Close()
			return BatchView{}, err
		}
		v.Stages = append(v.Stages, s)
	}
	srows.Close()
	if err := srows.Err(); err != nil {
		return BatchView{}, err
	}
	rows, err := b.db.QueryContext(ctx, `SELECT idx, member_id, execution_id, stage, action_id, module_version, artifact_sha256, parameters_hash,
		params, risk, host_id, fingerprint, credential_ref, container_id, outcome, unreachable, detail, updated_at
		FROM batch_members WHERE batch_id = ? ORDER BY idx`, id)
	if err != nil {
		return BatchView{}, fmt.Errorf("load batch %s members: %w", id, err)
	}
	defer rows.Close()
	for rows.Next() {
		var m BatchMemberView
		var updated int64
		if err := rows.Scan(&m.Index, &m.MemberID, &m.ExecutionID, &m.Stage, &m.ActionID, &m.ModuleVersion, &m.ArtifactSHA256, &m.ParametersHash,
			&m.Params, &m.Risk, &m.HostID, &m.Fingerprint, &m.CredentialRef, &m.ContainerID, &m.Outcome, &m.Unreachable, &m.Detail, &updated); err != nil {
			return BatchView{}, err
		}
		m.Index++
		m.UpdatedAt = time.Unix(updated, 0)
		if a, ok := actions.Lookup(m.ActionID); ok {
			m.ActionTitle = a.Title
		}
		v.Counts.count(m.Outcome)
		v.Members = append(v.Members, m)
	}
	if err := rows.Err(); err != nil {
		return BatchView{}, err
	}
	v.Summary = BatchSummaryText(v.State, v.Counts)
	return v, nil
}

// ListBatches returns the newest batches with their outcome counts.
func (b *Batches) ListBatches(ctx context.Context) ([]BatchSummary, error) {
	rows, err := b.db.QueryContext(ctx, `SELECT b.id, b.state, b.risk, b.created_by, b.created_at, m.outcome, count(m.idx)
		FROM (SELECT * FROM batches ORDER BY created_at DESC, id DESC LIMIT ?) b
		JOIN batch_members m ON m.batch_id = b.id
		GROUP BY b.id, m.outcome ORDER BY b.created_at DESC, b.id DESC`, maxBatchList)
	if err != nil {
		return nil, fmt.Errorf("list batches: %w", err)
	}
	defer rows.Close()
	var out []BatchSummary
	for rows.Next() {
		var s BatchSummary
		var created int64
		var outcome string
		var n int
		if err := rows.Scan(&s.ID, &s.State, &s.Risk, &s.CreatedBy, &created, &outcome, &n); err != nil {
			return nil, err
		}
		if len(out) == 0 || out[len(out)-1].ID != s.ID {
			s.CreatedAt = time.Unix(created, 0)
			out = append(out, s)
		}
		last := &out[len(out)-1]
		for range n {
			last.Counts.count(outcome)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Summary = BatchSummaryText(out[i].State, out[i].Counts)
	}
	return out, nil
}

// memberState loads what outcome recording needs, inside tx.
func memberState(ctx context.Context, tx *sql.Tx, batchID, memberID string) (state string, expiry int64, stage int, outcome string, err error) {
	err = tx.QueryRowContext(ctx, `SELECT b.state, b.expiry, m.stage, m.outcome FROM batch_members m JOIN batches b ON b.id = m.batch_id
		WHERE m.batch_id = ? AND m.member_id = ?`, batchID, memberID).Scan(&state, &expiry, &stage, &outcome)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrBatchMemberNotFound
	}
	return state, expiry, stage, outcome, err
}

// MarkDispatched records that a member is being handed to the executor.
// Only a planned member of an approved, unexpired batch whose earlier
// stages are complete can be dispatched, and only once: a member that
// left planned can never be dispatched again.
func (b *Batches) MarkDispatched(ctx context.Context, batchID, memberID string) error {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	state, expiry, stage, outcome, err := memberState(ctx, tx, batchID, memberID)
	if err != nil {
		return err
	}
	if outcome != OutcomePlanned {
		return ErrBatchMemberFinal
	}
	if state != "approved" || !b.now().Before(time.Unix(expiry, 0)) {
		return ErrBatchNotDispatchable
	}
	var open int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM batch_members WHERE batch_id = ? AND stage < ? AND outcome IN ('planned', 'dispatched')`,
		batchID, stage).Scan(&open); err != nil {
		return err
	}
	if open > 0 {
		return ErrBatchNotDispatchable
	}
	res, err := tx.ExecContext(ctx, `UPDATE batch_members SET outcome = 'dispatched', updated_at = ? WHERE batch_id = ? AND member_id = ? AND outcome = 'planned'`,
		b.now().Unix(), batchID, memberID)
	if err != nil {
		return fmt.Errorf("dispatch member %s/%s: %w", batchID, memberID, err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrBatchMemberFinal
	}
	return tx.Commit()
}

// MemberResult is the result of a dispatched member.
type MemberResult struct {
	// Outcome is OutcomeSuccess, OutcomeFailed or OutcomeUnknown.
	Outcome string
	// Unreachable marks a failure to reach the host (counted against the
	// stage's unreachable threshold).
	Unreachable bool
	// Detail is a short explanation, shown as text.
	Detail string
}

// RecordOutcome records the result of a dispatched member and applies the
// approved failure policy: when a stage exceeds its failure or
// unreachable threshold (zero by default), every member that was not
// dispatched becomes not executed. Members that already ran keep their
// outcome; nothing is retried or rolled back.
func (b *Batches) RecordOutcome(ctx context.Context, batchID, memberID string, r MemberResult) error {
	switch r.Outcome {
	case OutcomeSuccess, OutcomeUnknown:
		if r.Unreachable {
			return ErrBatchOutcome
		}
	case OutcomeFailed:
	default:
		return ErrBatchOutcome
	}
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	_, _, stage, outcome, err := memberState(ctx, tx, batchID, memberID)
	if err != nil {
		return err
	}
	if outcome != OutcomeDispatched {
		return ErrBatchMemberFinal
	}
	now := b.now().Unix()
	if _, err := tx.ExecContext(ctx, `UPDATE batch_members SET outcome = ?, unreachable = ?, detail = ?, updated_at = ? WHERE batch_id = ? AND member_id = ? AND outcome = 'dispatched'`,
		r.Outcome, boolInt(r.Unreachable), batchTruncate(strings.ToValidUTF8(r.Detail, "�"), maxBatchDetail), now, batchID, memberID); err != nil {
		return fmt.Errorf("record member %s/%s: %w", batchID, memberID, err)
	}
	var failed, unreachable, maxFailed, maxUnreachable int
	if err := tx.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM batch_members WHERE batch_id = ?1 AND stage = ?2 AND outcome IN ('failed', 'unknown') AND unreachable = 0),
		(SELECT count(*) FROM batch_members WHERE batch_id = ?1 AND stage = ?2 AND outcome = 'failed' AND unreachable = 1),
		s.failure_threshold, s.unreachable_threshold FROM batch_stages s WHERE s.batch_id = ?1 AND s.stage = ?2`, batchID, stage).
		Scan(&failed, &unreachable, &maxFailed, &maxUnreachable); err != nil {
		return fmt.Errorf("record member %s/%s: stage policy: %w", batchID, memberID, err)
	}
	stopped := 0
	if failed > maxFailed || unreachable > maxUnreachable {
		why := fmt.Sprintf("stopped: stage %d exceeded its approved threshold (%d failed of %d allowed, %d unreachable of %d allowed); nothing is retried or rolled back",
			stage, failed, maxFailed, unreachable, maxUnreachable)
		res, err := tx.ExecContext(ctx, `UPDATE batch_members SET outcome = 'not_executed', detail = ?, updated_at = ? WHERE batch_id = ? AND outcome = 'planned'`,
			why, now, batchID)
		if err != nil {
			return fmt.Errorf("record member %s/%s: stop: %w", batchID, memberID, err)
		}
		n, _ := res.RowsAffected()
		stopped = int(n)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	b.log.Info("audit", "kind", "batch_member_finished", "batch", batchID, "member", memberID, "outcome", r.Outcome,
		"unreachable", r.Unreachable, "stopped", stopped)
	return nil
}

// SkipMember skips a planned member before dispatch (audited). A skip
// never runs anything and cannot be undone.
func (b *Batches) SkipMember(ctx context.Context, user, batchID, memberID string) error {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	state, _, _, outcome, err := memberState(ctx, tx, batchID, memberID)
	if err != nil {
		return err
	}
	if outcome != OutcomePlanned {
		return ErrBatchMemberFinal
	}
	if state != "pending" && state != "approved" {
		return ErrBatchNotDispatchable
	}
	if _, err := tx.ExecContext(ctx, `UPDATE batch_members SET outcome = 'skipped', detail = ?, updated_at = ? WHERE batch_id = ? AND member_id = ? AND outcome = 'planned'`,
		batchTruncate("skipped by "+user, maxBatchDetail), b.now().Unix(), batchID, memberID); err != nil {
		return fmt.Errorf("skip member %s/%s: %w", batchID, memberID, err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	b.log.Info("audit", "kind", "batch_member_skipped", "batch", batchID, "member", memberID, "user", user)
	return nil
}

// ReconcileBatches runs at server start, before anything is dispatched:
// a member left dispatched by the previous process has an unknown outcome
// (it may have changed its host and is never redispatched); a pending
// batch past its approval window expires; members of an expired batch
// that were never dispatched are not executed. It returns the number of
// changed members.
func (b *Batches) ReconcileBatches(ctx context.Context) (int, error) {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	now := b.now().Unix()
	changed := 0
	res, err := tx.ExecContext(ctx, `UPDATE batch_members SET outcome = 'unknown', updated_at = ?,
		detail = 'the server restarted while this member was dispatched; its outcome is unknown and it is never redispatched — check the host'
		WHERE outcome = 'dispatched'`, now)
	if err != nil {
		return 0, fmt.Errorf("reconcile batches: %w", err)
	}
	n, _ := res.RowsAffected()
	changed += int(n)
	if _, err := tx.ExecContext(ctx, `UPDATE batches SET state = 'expired', options = NULL, detail = 'not approved in time'
		WHERE state = 'pending' AND approval_expiry > 0 AND approval_expiry + ? < ?`, int64(expireGrace/time.Second), now); err != nil {
		return 0, fmt.Errorf("reconcile batches: %w", err)
	}
	res, err = tx.ExecContext(ctx, `UPDATE batch_members SET outcome = 'not_executed', updated_at = ?,
		detail = 'the batch expired or was not approved before this member was dispatched'
		WHERE outcome = 'planned' AND batch_id IN (SELECT id FROM batches WHERE state IN ('expired', 'refused') OR expiry <= ?)`, now, now)
	if err != nil {
		return 0, fmt.Errorf("reconcile batches: %w", err)
	}
	n, _ = res.RowsAffected()
	changed += int(n)
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	if changed > 0 {
		b.log.Info("audit", "kind", "batch_reconciled", "members", changed)
	}
	return changed, nil
}

// InspectBindings binds a container member to the latest successful
// docker.inspect of that container on that host, at most
// maxContainerBindingAge old: the full container ID, the SHA-256 of the
// stored inspect result as configuration hash, and the image ID as old
// and new image digest (restart, stop and start never change the image).
type InspectBindings struct {
	DB  *sql.DB
	Now func() time.Time
}

// ContainerBinding implements ContainerBindings.
func (ib *InspectBindings) ContainerBinding(ctx context.Context, hostID, containerID string) (canonical.BatchContainer, error) {
	params, err := json.Marshal(map[string]string{"container": containerID})
	if err != nil {
		return canonical.BatchContainer{}, err
	}
	var result []byte
	var finished sql.NullInt64
	err = ib.DB.QueryRowContext(ctx, `SELECT h.result, h.finished_at FROM execution_hosts h JOIN executions e ON e.id = h.execution_id
		WHERE e.action_id = 'docker.inspect' AND e.params = ? AND h.host_id = ? AND h.state = 'finished' AND h.class = 'success'
		ORDER BY h.finished_at DESC, e.id DESC LIMIT 1`, string(params), hostID).Scan(&result, &finished)
	if errors.Is(err, sql.ErrNoRows) {
		return canonical.BatchContainer{}, ErrBatchContainer
	}
	if err != nil {
		return canonical.BatchContainer{}, fmt.Errorf("container binding %s on %s: %w", containerID, hostID, err)
	}
	now := time.Now
	if ib.Now != nil {
		now = ib.Now
	}
	if !finished.Valid || now().Sub(time.Unix(finished.Int64, 0)) > maxContainerBindingAge {
		return canonical.BatchContainer{}, ErrBatchContainer
	}
	in, err := dockerhost.ParseInspect(result)
	if err != nil || in.FullID != containerID || !strings.HasPrefix(in.ImageID, "sha256:") || !fullContainerIDRe.MatchString(strings.TrimPrefix(in.ImageID, "sha256:")) {
		return canonical.BatchContainer{}, ErrBatchContainer
	}
	sum := sha256.Sum256(result)
	return canonical.BatchContainer{ContainerID: containerID, ConfigurationHash: hex.EncodeToString(sum[:]), OldImageDigest: in.ImageID, NewImageDigest: in.ImageID}, nil
}
