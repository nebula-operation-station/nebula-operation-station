// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"
)

// PVE mutation job states (migration 0017).
const (
	PveJobDispatching = "dispatching"
	PveJobRunning     = "running"
	PveJobReconciling = "reconciling"
	PveJobSucceeded   = "succeeded"
	PveJobFailed      = "failed"
	PveJobUnknown     = "unknown"
)

// Limits of the PVE job record.
const (
	// MaxPveJobSteps bounds the steps of one mutation (clone, config,
	// resize, start, ...).
	MaxPveJobSteps = 16
	// MaxPveUPIDBytes bounds a stored UPID.
	MaxPveUPIDBytes = 255
	// MaxPveExitStatusBytes bounds the stored task exit status.
	MaxPveExitStatusBytes = 128
)

var (
	// ErrPveJobExists is returned when the step already has a durable
	// record: the step was dispatched (or may have been) before and must
	// never be dispatched again.
	ErrPveJobExists = errors.New("executordb: pve job step already recorded")
	// ErrPveJobNotFound is returned for an unknown job step.
	ErrPveJobNotFound = errors.New("executordb: pve job step not found")
	// ErrPveJobState is returned when the step is not in a state that
	// allows the transition.
	ErrPveJobState = errors.New("executordb: pve job step is not in the required state")
	// ErrPveJobOrder is returned when a step is recorded before the
	// previous step has succeeded.
	ErrPveJobOrder = errors.New("executordb: previous pve job step has not succeeded")

	pveUPIDRe   = regexp.MustCompile(`^UPID:([A-Za-z0-9][A-Za-z0-9-]{0,62}):[0-9A-F]{8}:[0-9A-F]{8}:[0-9A-F]{8}:[a-z0-9]{1,32}:[A-Za-z0-9._-]{0,64}:[A-Za-z0-9_.@!-]{1,128}:$`)
	pveHex64Re  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	pveNodeRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,62}$`)
	pveActionRe = regexp.MustCompile(`^pve\.[a-z0-9_.]{1,60}$`)
)

// PveUPIDNode validates upid, which comes from the PVE remote and is
// untrusted, and returns the node it names.
func PveUPIDNode(upid string) (string, bool) {
	if len(upid) > MaxPveUPIDBytes {
		return "", false
	}
	m := pveUPIDRe.FindStringSubmatch(upid)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// PveJob is one durable PVE mutation step.
type PveJob struct {
	ExecutionID     string
	Step            int
	Digest          string // hex permit digest
	Action          string
	RemoteID        string
	TrustGeneration uint64
	Kind            string
	Node            string
	VMID            uint64
	// RequestDigest is the hex SHA-256 of the exact request the step sends.
	RequestDigest string
	State         string
	UPID          string
	TaskNode      string
	ExitStatus    string
	CreatedAt     time.Time
	DispatchedAt  time.Time // zero until the UPID is stored
	UpdatedAt     time.Time
	FinishedAt    time.Time // zero until terminal
}

// Terminal reports whether the step reached a final state.
func (j PveJob) Terminal() bool {
	return j.State == PveJobSucceeded || j.State == PveJobFailed || j.State == PveJobUnknown
}

func validatePveJob(j PveJob) error {
	switch {
	case j.ExecutionID == "" || len(j.ExecutionID) > 64:
		return fmt.Errorf("executordb: %w: pve job execution id", ErrInvalid)
	case j.Step < 1 || j.Step > MaxPveJobSteps:
		return fmt.Errorf("executordb: %w: pve job step %d outside 1..%d", ErrInvalid, j.Step, MaxPveJobSteps)
	case !pveHex64Re.MatchString(j.Digest) || !pveHex64Re.MatchString(j.RequestDigest):
		return fmt.Errorf("executordb: %w: pve job digest", ErrInvalid)
	case !pveActionRe.MatchString(j.Action):
		return fmt.Errorf("executordb: %w: pve job action", ErrInvalid)
	case j.RemoteID == "" || len(j.RemoteID) > 64 || j.TrustGeneration < 1 || j.TrustGeneration > 1<<48-1:
		return fmt.Errorf("executordb: %w: pve job remote", ErrInvalid)
	case !pveNodeRe.MatchString(j.Node) || j.VMID > 9999999999:
		return fmt.Errorf("executordb: %w: pve job target", ErrInvalid)
	}
	switch j.Kind {
	case "qemu", "lxc", "node":
		return nil
	}
	return fmt.Errorf("executordb: %w: pve job kind", ErrInvalid)
}

// CreatePveJobIntent durably records the intent to dispatch one step, in
// state dispatching, before anything is sent. It fails with
// ErrPveJobExists if the step was recorded before (so a step can be
// dispatched at most once, across restarts), and with ErrPveJobOrder unless
// every earlier step of the job has succeeded. Earlier steps must also bind
// the same permit digest and target.
func (db *DB) CreatePveJobIntent(j PveJob) error {
	if err := validatePveJob(j); err != nil {
		return err
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return fmt.Errorf("executordb: create pve job: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // a no-op after Commit
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM pve_jobs WHERE execution_id = ? AND step = ?`, j.ExecutionID, j.Step).Scan(&n); err != nil {
		return fmt.Errorf("executordb: create pve job: %w", err)
	}
	if n != 0 {
		return ErrPveJobExists
	}
	var prior, done int
	if err := tx.QueryRow(`SELECT COUNT(*), COALESCE(SUM(state = 'succeeded' AND digest = ? AND remote_id = ? AND trust_generation = ? AND kind = ? AND node = ? AND vmid = ?), 0)
		FROM pve_jobs WHERE execution_id = ?`, j.Digest, j.RemoteID, int64(j.TrustGeneration), j.Kind, j.Node, int64(j.VMID), j.ExecutionID).Scan(&prior, &done); err != nil {
		return fmt.Errorf("executordb: create pve job: %w", err)
	}
	if prior != j.Step-1 || done != prior {
		return ErrPveJobOrder
	}
	now := db.now().Unix()
	if _, err := tx.Exec(`INSERT INTO pve_jobs (execution_id, step, digest, action, remote_id, trust_generation, kind, node, vmid, request_digest, state, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'dispatching', ?, ?)`,
		j.ExecutionID, j.Step, j.Digest, j.Action, j.RemoteID, int64(j.TrustGeneration), j.Kind, j.Node, int64(j.VMID), j.RequestDigest, now, now); err != nil {
		return fmt.Errorf("executordb: create pve job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("executordb: create pve job: %w", err)
	}
	return nil
}

// RecordPveJobUPID stores the UPID returned for a dispatched step (or
// identified for it during reconciliation) and moves it to running. The
// UPID is untrusted input: it must be well-formed and name taskNode. A
// step's UPID is stored once and never replaced.
func (db *DB) RecordPveJobUPID(executionID string, step int, upid, taskNode string) error {
	node, ok := PveUPIDNode(upid)
	if !ok || node != taskNode {
		return fmt.Errorf("executordb: %w: pve task id", ErrInvalid)
	}
	now := db.now().Unix()
	res, err := db.sql.Exec(`UPDATE pve_jobs SET state = 'running', upid = ?, task_node = ?, dispatched_at = ?, updated_at = ?
		WHERE execution_id = ? AND step = ? AND state IN ('dispatching', 'reconciling') AND upid IS NULL`,
		upid, taskNode, now, now, executionID, step)
	if err != nil {
		return fmt.Errorf("executordb: record pve upid: %w", err)
	}
	return db.pveJobChanged(res, executionID, step)
}

// MarkPveJobReconciling records that the outcome of a step is uncertain
// (lost response, transport error after sending, restart). Only
// reconciliation may move it on; it is never dispatched again.
func (db *DB) MarkPveJobReconciling(executionID string, step int) error {
	res, err := db.sql.Exec(`UPDATE pve_jobs SET state = 'reconciling', updated_at = ?
		WHERE execution_id = ? AND step = ? AND state IN ('dispatching', 'running', 'reconciling')`,
		db.now().Unix(), executionID, step)
	if err != nil {
		return fmt.Errorf("executordb: mark pve job reconciling: %w", err)
	}
	return db.pveJobChanged(res, executionID, step)
}

// FinishPveJob records a terminal state. succeeded and failed need a
// stored UPID (an observed task); unknown does not. exitStatus is the
// task's exit status from the remote, which is untrusted: it is bounded
// and replaced when it is not printable UTF-8.
func (db *DB) FinishPveJob(executionID string, step int, state, exitStatus string) error {
	switch state {
	case PveJobSucceeded, PveJobFailed, PveJobUnknown:
	default:
		return fmt.Errorf("executordb: %w: pve job terminal state %q", ErrInvalid, state)
	}
	exitStatus = sanitizePveExitStatus(exitStatus)
	now := db.now().Unix()
	q := `UPDATE pve_jobs SET state = ?, exit_status = ?, updated_at = ?, finished_at = ?
		WHERE execution_id = ? AND step = ? AND state IN ('dispatching', 'running', 'reconciling')`
	if state != PveJobUnknown {
		q += ` AND upid IS NOT NULL`
	}
	res, err := db.sql.Exec(q, state, exitStatus, now, now, executionID, step)
	if err != nil {
		return fmt.Errorf("executordb: finish pve job: %w", err)
	}
	return db.pveJobChanged(res, executionID, step)
}

func sanitizePveExitStatus(s string) string {
	if len(s) > MaxPveExitStatusBytes || !utf8.ValidString(s) {
		return "invalid exit status"
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "invalid exit status"
		}
	}
	return s
}

func (db *DB) pveJobChanged(res sql.Result, executionID string, step int) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("executordb: pve job: %w", err)
	}
	if n == 1 {
		return nil
	}
	if _, ok, err := db.PveJob(executionID, step); err != nil {
		return err
	} else if !ok {
		return ErrPveJobNotFound
	}
	return ErrPveJobState
}

const pveJobColumns = `execution_id, step, digest, action, remote_id, trust_generation, kind, node, vmid, request_digest, state,
	COALESCE(upid, ''), COALESCE(task_node, ''), exit_status, created_at, COALESCE(dispatched_at, 0), updated_at, COALESCE(finished_at, 0)`

func scanPveJob(r rowScanner) (PveJob, error) {
	var j PveJob
	var gen, vmid, created, dispatched, updated, finished int64
	if err := r.Scan(&j.ExecutionID, &j.Step, &j.Digest, &j.Action, &j.RemoteID, &gen, &j.Kind, &j.Node, &vmid, &j.RequestDigest, &j.State,
		&j.UPID, &j.TaskNode, &j.ExitStatus, &created, &dispatched, &updated, &finished); err != nil {
		return PveJob{}, err
	}
	j.TrustGeneration, j.VMID = uint64(gen), uint64(vmid)
	j.CreatedAt, j.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
	if dispatched != 0 {
		j.DispatchedAt = time.Unix(dispatched, 0)
	}
	if finished != 0 {
		j.FinishedAt = time.Unix(finished, 0)
	}
	return j, nil
}

// PveJob returns one job step.
func (db *DB) PveJob(executionID string, step int) (PveJob, bool, error) {
	j, err := scanPveJob(db.sql.QueryRow(`SELECT `+pveJobColumns+` FROM pve_jobs WHERE execution_id = ? AND step = ?`, executionID, step))
	if errors.Is(err, sql.ErrNoRows) {
		return PveJob{}, false, nil
	}
	if err != nil {
		return PveJob{}, false, fmt.Errorf("executordb: pve job: %w", err)
	}
	return j, true, nil
}

// PveJobSteps returns every recorded step of one job, in step order.
func (db *DB) PveJobSteps(executionID string) ([]PveJob, error) {
	return db.queryPveJobs(`SELECT `+pveJobColumns+` FROM pve_jobs WHERE execution_id = ? ORDER BY step`, executionID)
}

// OpenPveJobs returns every step that has not reached a terminal state,
// oldest first; reconciliation walks it after a restart.
func (db *DB) OpenPveJobs() ([]PveJob, error) {
	return db.queryPveJobs(`SELECT ` + pveJobColumns + ` FROM pve_jobs WHERE state IN ('dispatching', 'running', 'reconciling') ORDER BY created_at, execution_id, step`)
}

func (db *DB) queryPveJobs(q string, args ...any) ([]PveJob, error) {
	rows, err := db.sql.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("executordb: pve jobs: %w", err)
	}
	defer rows.Close()
	var out []PveJob
	for rows.Next() {
		j, err := scanPveJob(rows)
		if err != nil {
			return nil, fmt.Errorf("executordb: pve jobs: %w", err)
		}
		out = append(out, j)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("executordb: pve jobs: %w", err)
	}
	return out, nil
}
