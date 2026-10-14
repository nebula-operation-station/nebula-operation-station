// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Run states.
const (
	RunDispatching = "dispatching"
	RunRunning     = "running"
	RunFinished    = "finished"
)

// ErrNoRun is returned for an unknown run.
var ErrNoRun = errors.New("executordb: run not found")

// Run is one durable host run.
type Run struct {
	ExecutionID  string
	HostID       string
	Digest       string
	State        string
	Class        string
	Detail       string
	ExitCode     int
	Endpoints    []string
	Fingerprint  string
	Timeout      time.Duration
	Endpoint     string
	Result       []byte
	Log          []byte
	LogTruncated bool
	CreatedAt    time.Time
	DispatchedAt time.Time // zero until dispatched
	FinishedAt   time.Time // zero until finished
	Released     bool
}

// CreateRun records an authorized durable run in state dispatching.
func (db *DB) CreateRun(r Run) error {
	eps, err := json.Marshal(r.Endpoints)
	if err != nil {
		return err
	}
	_, err = db.sql.Exec(`INSERT INTO runs (execution_id, host_id, digest, state, endpoints, fingerprint, timeout_s, created_at)
		VALUES (?, ?, ?, 'dispatching', ?, ?, ?, ?)`, r.ExecutionID, r.HostID, r.Digest, string(eps), r.Fingerprint,
		int64(r.Timeout/time.Second), db.now().Unix())
	if err != nil {
		return fmt.Errorf("executordb: create run: %w", err)
	}
	return nil
}

// MarkRunRunning records a successful dispatch.
func (db *DB) MarkRunRunning(executionID, hostID, endpoint string) error {
	_, err := db.sql.Exec(`UPDATE runs SET state = 'running', endpoint = ?, dispatched_at = ? WHERE execution_id = ? AND host_id = ? AND state = 'dispatching'`,
		endpoint, db.now().Unix(), executionID, hostID)
	if err != nil {
		return fmt.Errorf("executordb: mark run running: %w", err)
	}
	return nil
}

// FinishRun stores the outcome. A finished run is never changed again.
func (db *DB) FinishRun(r Run) error {
	detail := r.Detail
	if len(detail) > 1000 {
		detail = detail[:1000]
	}
	_, err := db.sql.Exec(`UPDATE runs SET state = 'finished', class = ?, detail = ?, exit_code = ?, endpoint = CASE WHEN ? = '' THEN endpoint ELSE ? END,
			result = ?, log = ?, log_truncated = ?, finished_at = ?
		WHERE execution_id = ? AND host_id = ? AND state != 'finished'`,
		r.Class, detail, r.ExitCode, r.Endpoint, r.Endpoint, r.Result, r.Log, boolInt(r.LogTruncated), db.now().Unix(), r.ExecutionID, r.HostID)
	if err != nil {
		return fmt.Errorf("executordb: finish run: %w", err)
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

const runColumns = `execution_id, host_id, digest, state, class, detail, exit_code, endpoints, fingerprint, timeout_s, endpoint,
	result, log, log_truncated, created_at, dispatched_at, finished_at, released_at`

func scanRun(sc interface{ Scan(...any) error }) (Run, error) {
	var r Run
	var eps string
	var timeout, created int64
	var dispatched, finished, released sql.NullInt64
	var trunc int
	if err := sc.Scan(&r.ExecutionID, &r.HostID, &r.Digest, &r.State, &r.Class, &r.Detail, &r.ExitCode, &eps, &r.Fingerprint, &timeout,
		&r.Endpoint, &r.Result, &r.Log, &trunc, &created, &dispatched, &finished, &released); err != nil {
		return Run{}, err
	}
	if err := json.Unmarshal([]byte(eps), &r.Endpoints); err != nil {
		return Run{}, fmt.Errorf("executordb: run endpoints: %w", err)
	}
	r.Timeout, r.CreatedAt, r.LogTruncated, r.Released = time.Duration(timeout)*time.Second, time.Unix(created, 0), trunc == 1, released.Valid
	if dispatched.Valid {
		r.DispatchedAt = time.Unix(dispatched.Int64, 0)
	}
	if finished.Valid {
		r.FinishedAt = time.Unix(finished.Int64, 0)
	}
	return r, nil
}

// GetRun returns one run or ErrNoRun.
func (db *DB) GetRun(executionID, hostID string) (Run, error) {
	r, err := scanRun(db.sql.QueryRow(`SELECT `+runColumns+` FROM runs WHERE execution_id = ? AND host_id = ?`, executionID, hostID))
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, ErrNoRun
	}
	if err != nil {
		return Run{}, fmt.Errorf("executordb: get run: %w", err)
	}
	return r, nil
}

// OpenRuns returns the runs that are not finished, oldest first.
func (db *DB) OpenRuns() ([]Run, error) {
	rows, err := db.sql.Query(`SELECT ` + runColumns + ` FROM runs WHERE state != 'finished' ORDER BY created_at, execution_id, host_id`)
	if err != nil {
		return nil, fmt.Errorf("executordb: open runs: %w", err)
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ReleaseRun drops the result and log of a finished run once the server
// has stored them.
func (db *DB) ReleaseRun(executionID, hostID string) error {
	_, err := db.sql.Exec(`UPDATE runs SET result = NULL, log = NULL, released_at = ? WHERE execution_id = ? AND host_id = ? AND state = 'finished'`,
		db.now().Unix(), executionID, hostID)
	if err != nil {
		return fmt.Errorf("executordb: release run: %w", err)
	}
	return nil
}

// RunReboot is a durable run waiting for its host to come back from a
// reboot.
type RunReboot struct {
	ExecutionID  string
	HostID       string
	OldBootID    string
	Deadline     time.Time
	ExitCode     int
	Result       []byte
	Log          []byte
	LogTruncated bool
}

// AddRunReboot records that a run waits for a reboot.
func (db *DB) AddRunReboot(r RunReboot) error {
	_, err := db.sql.Exec(`INSERT INTO run_reboots (execution_id, host_id, old_boot_id, deadline, exit_code, result, log, log_truncated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`, r.ExecutionID, r.HostID, r.OldBootID, r.Deadline.Unix(), r.ExitCode,
		r.Result, r.Log, boolInt(r.LogTruncated))
	if err != nil {
		return fmt.Errorf("executordb: add run reboot: %w", err)
	}
	return nil
}

// GetRunReboot returns the reboot wait of a run, if any.
func (db *DB) GetRunReboot(executionID, hostID string) (RunReboot, bool, error) {
	r := RunReboot{ExecutionID: executionID, HostID: hostID}
	var deadline int64
	var trunc int
	err := db.sql.QueryRow(`SELECT old_boot_id, deadline, exit_code, result, log, log_truncated FROM run_reboots WHERE execution_id = ? AND host_id = ?`,
		executionID, hostID).Scan(&r.OldBootID, &deadline, &r.ExitCode, &r.Result, &r.Log, &trunc)
	if errors.Is(err, sql.ErrNoRows) {
		return RunReboot{}, false, nil
	}
	if err != nil {
		return RunReboot{}, false, fmt.Errorf("executordb: get run reboot: %w", err)
	}
	r.Deadline, r.LogTruncated = time.Unix(deadline, 0), trunc == 1
	return r, true, nil
}

// DeleteRunReboot removes the reboot wait of a run.
func (db *DB) DeleteRunReboot(executionID, hostID string) error {
	if _, err := db.sql.Exec(`DELETE FROM run_reboots WHERE execution_id = ? AND host_id = ?`, executionID, hostID); err != nil {
		return fmt.Errorf("executordb: delete run reboot: %w", err)
	}
	return nil
}
