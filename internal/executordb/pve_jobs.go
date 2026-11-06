// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
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
	// maxPveUPIDStartUnix bounds a UPID start time (2100-01-01, as in
	// pveapi); a start time of 0 is refused too.
	maxPveUPIDStartUnix = 4102444800
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
	// ErrPveJobTask is returned when a UPID does not carry the task type
	// and token user the step expects, so it is not the step's task.
	ErrPveJobTask = errors.New("executordb: pve task does not belong to the job step")
	// ErrPveUPIDRecorded is returned when a UPID is already stored for a
	// step: one task never belongs to two steps.
	ErrPveUPIDRecorded = errors.New("executordb: pve task id already recorded for a job step")
	// ErrPveTargetBusy is returned when another step on the same target
	// (remote, kind, node, vmid) is still open: mutations of one target are
	// serialized so a lost task is never attributed to another job.
	ErrPveTargetBusy = errors.New("executordb: another pve job step on the target is still open")

	// ErrPveRemoteActive is returned when an admin tries to close the open
	// steps of a remote that is still active: reconciliation observes
	// those through the current pin and must decide them.
	ErrPveRemoteActive = errors.New("executordb: pve remote is active; its open steps are reconciled, not closed")

	// pveUPIDRe is the strict UPID grammar of the durable job record. It
	// is deliberately a subset of the pveapi task-list grammar
	// (internal/pveapi/tasks.go), which is a read-only display parser and
	// stays lenient so that no task disappears from a listing. This record
	// decides which task a mutation step is bound to, so it only takes what
	// a PVE mutation of this engine can produce:
	//   - node: permit.PveNodePattern, the same rule as the permit target,
	//     validatePveJob and the pveapi writer, with the case kept. The
	//     pveapi listing also takes any length;
	//   - pid, pstart, starttime: uppercase hex as PVE writes it; pstart
	//     (clock ticks since boot) has eight or nine digits, because it grows
	//     to nine once a node's uptime passes about 497 days at USER_HZ=100
	//     (pveapi also takes lowercase). starttime lies in (0, 2100-01-01],
	//     as in pveapi;
	//   - type: [a-z0-9]{1,32}, as in validatePveJob (pveapi: 1 to 64
	//     characters other than ':', '/' and whitespace);
	//   - id: at most 64 of [A-Za-z0-9._-] (pveapi: any number, including
	//     none, of characters other than ':', '/' and whitespace);
	//   - user: at most 128 of [A-Za-z0-9_.@!-], the task_user column bound
	//     (pveapi: 1 to 256 characters other than ':', '/' and whitespace).
	// pveapi counts characters (runes), not bytes; whitespace there is the
	// RE2 \s class (space, \t, \n, \f, \r).
	// TestPveUPIDGrammarIsSubsetOfPveapi only spot-checks this: it feeds a
	// fixed corpus of UPIDs accepted here (including the length and digit
	// bounds) to the pveapi writer's TaskStatus. It does not exercise the
	// tasks.go listing parser, and it cannot prove that a widened regexp
	// here stays a subset.
	pveUPIDRe     = regexp.MustCompile(`^UPID:(` + permit.PveNodePattern + `):[0-9A-F]{8}:[0-9A-F]{8,9}:([0-9A-F]{8}):([a-z0-9]{1,32}):([A-Za-z0-9._-]{0,64}):([A-Za-z0-9_.@!-]{1,128}):$`)
	pveHex64Re    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	pveActionRe   = regexp.MustCompile(`^pve\.[a-z0-9_.]{1,60}$`)
	pveTaskTypeRe = regexp.MustCompile(`^[a-z0-9]{1,32}$`)
	pveTaskUserRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+@[A-Za-z0-9_.-]+![A-Za-z0-9_.-]+$`)
)

// PveUPID is the parsed form of a PVE task ID.
type PveUPID struct {
	Node      string
	StartTime time.Time
	Type      string
	ID        string
	// User is the user or API token (user@realm!token) that started the
	// task.
	User string
}

// ParsePveUPID validates upid, which comes from the PVE remote and is
// untrusted, and returns its members.
func ParsePveUPID(upid string) (PveUPID, bool) {
	if len(upid) > MaxPveUPIDBytes {
		return PveUPID{}, false
	}
	m := pveUPIDRe.FindStringSubmatch(upid)
	if m == nil {
		return PveUPID{}, false
	}
	start, err := strconv.ParseUint(m[2], 16, 32)
	if err != nil || start == 0 || start > maxPveUPIDStartUnix {
		return PveUPID{}, false
	}
	return PveUPID{Node: m[1], StartTime: time.Unix(int64(start), 0), Type: m[3], ID: m[4], User: m[5]}, true
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
	// TaskType is the PVE task type (qmstart, qmclone, ...) the step's
	// task must have.
	TaskType string
	// TaskUser is the action token ID (user@realm!token) the step's task
	// must have been started by.
	TaskUser     string
	State        string
	UPID         string
	TaskNode     string
	ExitStatus   string
	CreatedAt    time.Time
	DispatchedAt time.Time // zero until the UPID is stored
	UpdatedAt    time.Time
	FinishedAt   time.Time // zero until terminal
	// ClosedBy and ClosedReason are set when an admin closed the open step
	// (ClosePveJobs); empty otherwise.
	ClosedBy     string
	ClosedReason string
}

// MaxPveJobCloseReason bounds the reason an admin gives for closing steps.
const MaxPveJobCloseReason = 256

// ClosePveJobs moves every open step of remoteID to unknown and records who
// closed it and why. It is the admin path for a remote whose open steps
// reconciliation can never observe: one that is removed, or blocked and
// not re-pinned. It fails with ErrPveRemoteActive for an active remote
// (reconciliation decides those steps) and with ErrRemoteNotFound for an
// unknown one. The remote state is checked in the same transaction, so a
// concurrent re-pin cannot slip in between. It returns the closed steps.
// Nothing is sent to the remote; a task that did run stays done there.
//
// check is called for every open step inside the transaction, before
// anything is written; if it returns an error for any step, nothing is
// closed and that error is returned. The executor uses it to refuse steps
// whose run is still in flight in this process or whose task match window
// has not passed. check is required.
func (db *DB) ClosePveJobs(remoteID, by, reason string, check func(PveJob) error) ([]PveJob, error) {
	if err := checkText("actor", by, maxActorLen, false); err != nil {
		return nil, err
	}
	if err := checkText("reason", reason, MaxPveJobCloseReason, false); err != nil {
		return nil, err
	}
	if check == nil {
		return nil, fmt.Errorf("executordb: %w: close pve jobs needs a step check", ErrInvalid)
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return nil, fmt.Errorf("executordb: close pve jobs: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // a no-op after Commit
	var state string
	err = tx.QueryRow(`SELECT state FROM pve_remotes WHERE remote_id = ?`, remoteID).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrRemoteNotFound, remoteID)
	}
	if err != nil {
		return nil, fmt.Errorf("executordb: close pve jobs: %w", err)
	}
	if state == StateActive {
		return nil, ErrPveRemoteActive
	}
	rows, err := tx.Query(`SELECT `+pveJobColumns+` FROM pve_jobs WHERE remote_id = ? AND state IN ('dispatching', 'running', 'reconciling')
		ORDER BY created_at, execution_id, step`, remoteID)
	if err != nil {
		return nil, fmt.Errorf("executordb: close pve jobs: %w", err)
	}
	var closed []PveJob
	for rows.Next() {
		j, err := scanPveJob(rows)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("executordb: close pve jobs: %w", err)
		}
		closed = append(closed, j)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("executordb: close pve jobs: %w", err)
	}
	for _, j := range closed {
		if err := check(j); err != nil {
			return nil, err
		}
	}
	now := db.now().Unix()
	for i := range closed {
		if _, err := tx.Exec(`UPDATE pve_jobs SET state = 'unknown', closed_by = ?, closed_reason = ?, updated_at = ?, finished_at = ?
			WHERE execution_id = ? AND step = ? AND state IN ('dispatching', 'running', 'reconciling')`, by, reason, now, now, closed[i].ExecutionID, closed[i].Step); err != nil {
			return nil, fmt.Errorf("executordb: close pve jobs: %w", err)
		}
		closed[i].State, closed[i].ClosedBy, closed[i].ClosedReason = PveJobUnknown, by, reason
		closed[i].UpdatedAt, closed[i].FinishedAt = time.Unix(now, 0), time.Unix(now, 0)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("executordb: close pve jobs: %w", err)
	}
	return closed, nil
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
	case !permit.ValidPveNodeName(j.Node) || j.VMID > 9999999999:
		return fmt.Errorf("executordb: %w: pve job target", ErrInvalid)
	case !pveTaskTypeRe.MatchString(j.TaskType) || len(j.TaskUser) > 128 || !pveTaskUserRe.MatchString(j.TaskUser):
		return fmt.Errorf("executordb: %w: pve job task type or user", ErrInvalid)
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
// the same permit digest and target. It fails with ErrPveTargetBusy while
// any step on the same target is open.
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
	var busy int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM pve_jobs WHERE remote_id = ? AND kind = ? AND node = ? AND vmid = ?
		AND state IN ('dispatching', 'running', 'reconciling')`, j.RemoteID, j.Kind, j.Node, int64(j.VMID)).Scan(&busy); err != nil {
		return fmt.Errorf("executordb: create pve job: %w", err)
	}
	if busy != 0 {
		return ErrPveTargetBusy
	}
	now := db.now().Unix()
	if _, err := tx.Exec(`INSERT INTO pve_jobs (execution_id, step, digest, action, remote_id, trust_generation, kind, node, vmid, request_digest, task_type, task_user, state, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'dispatching', ?, ?)`,
		j.ExecutionID, j.Step, j.Digest, j.Action, j.RemoteID, int64(j.TrustGeneration), j.Kind, j.Node, int64(j.VMID), j.RequestDigest, j.TaskType, j.TaskUser, now, now); err != nil {
		return fmt.Errorf("executordb: create pve job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("executordb: create pve job: %w", err)
	}
	return nil
}

// RecordPveJobUPID stores the UPID returned for a dispatched step (or
// identified for it during reconciliation) and moves it to running. The
// UPID is untrusted input: it must be well-formed, name taskNode and carry
// the step's task type and token user (ErrPveJobTask otherwise). A step's
// UPID is stored once and never replaced, and a UPID already stored for
// any step is refused with ErrPveUPIDRecorded.
func (db *DB) RecordPveJobUPID(executionID string, step int, upid, taskNode string) error {
	u, ok := ParsePveUPID(upid)
	if !ok || u.Node != taskNode {
		return fmt.Errorf("executordb: %w: pve task id", ErrInvalid)
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return fmt.Errorf("executordb: record pve upid: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // a no-op after Commit
	var taskType, taskUser string
	err = tx.QueryRow(`SELECT task_type, task_user FROM pve_jobs WHERE execution_id = ? AND step = ?`, executionID, step).Scan(&taskType, &taskUser)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrPveJobNotFound
	}
	if err != nil {
		return fmt.Errorf("executordb: record pve upid: %w", err)
	}
	if u.Type != taskType || u.User != taskUser {
		return ErrPveJobTask
	}
	var used int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM pve_jobs WHERE upid = ?`, upid).Scan(&used); err != nil {
		return fmt.Errorf("executordb: record pve upid: %w", err)
	}
	if used != 0 {
		return ErrPveUPIDRecorded
	}
	now := db.now().Unix()
	res, err := tx.Exec(`UPDATE pve_jobs SET state = 'running', upid = ?, task_node = ?, dispatched_at = ?, updated_at = ?
		WHERE execution_id = ? AND step = ? AND state IN ('dispatching', 'reconciling') AND upid IS NULL`,
		upid, taskNode, now, now, executionID, step)
	if err != nil {
		return fmt.Errorf("executordb: record pve upid: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("executordb: record pve upid: %w", err)
	} else if n != 1 {
		return ErrPveJobState
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("executordb: record pve upid: %w", err)
	}
	return nil
}

// PveUPIDRecorded reports whether upid is already stored for a job step.
func (db *DB) PveUPIDRecorded(upid string) (bool, error) {
	var n int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM pve_jobs WHERE upid = ?`, upid).Scan(&n); err != nil {
		return false, fmt.Errorf("executordb: pve upid recorded: %w", err)
	}
	return n != 0, nil
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

// FinishPveJob records a terminal state. succeeded needs a stored UPID (an
// observed task); failed without a UPID means the remote answered and
// refused the request, and unknown that the task could not be identified.
// exitStatus is the
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
	if state == PveJobSucceeded {
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

const pveJobColumns = `execution_id, step, digest, action, remote_id, trust_generation, kind, node, vmid, request_digest, task_type, task_user, state,
	COALESCE(upid, ''), COALESCE(task_node, ''), exit_status, created_at, COALESCE(dispatched_at, 0), updated_at, COALESCE(finished_at, 0),
	COALESCE(closed_by, ''), COALESCE(closed_reason, '')`

func scanPveJob(r rowScanner) (PveJob, error) {
	var j PveJob
	var gen, vmid, created, dispatched, updated, finished int64
	if err := r.Scan(&j.ExecutionID, &j.Step, &j.Digest, &j.Action, &j.RemoteID, &gen, &j.Kind, &j.Node, &vmid, &j.RequestDigest, &j.TaskType, &j.TaskUser, &j.State,
		&j.UPID, &j.TaskNode, &j.ExitStatus, &created, &dispatched, &updated, &finished, &j.ClosedBy, &j.ClosedReason); err != nil {
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

// UnknownPveJobs returns every step of action whose outcome is unknown,
// oldest first.
func (db *DB) UnknownPveJobs(action string) ([]PveJob, error) {
	return db.queryPveJobs(`SELECT `+pveJobColumns+` FROM pve_jobs WHERE state = 'unknown' AND action = ? ORDER BY created_at, execution_id, step`, action)
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
