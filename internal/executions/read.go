// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Execution is the server's record of one execution.
type Execution struct {
	ID             string
	Digest         string
	ActionID       string
	ModuleVersion  string
	ArtifactSHA256 string
	Risk           string
	Requirement    string
	State          string
	Detail         string
	Durable        bool
	Timeout        time.Duration
	// Options are the WebAuthn request options while approval is pending.
	Options        []byte
	ApprovalExpiry time.Time
	CreatedBy      string
	CreatedAt      time.Time
	FinishedAt     time.Time
	Hosts          []Host
	// Params is the JSON object of the parameters.
	Params string
	// StagePlan is the stage plan document ("" for one stage).
	StagePlan string
	// Waiting says what a staged rollout waits for.
	Waiting string
}

// Host is one host of an execution. Result and Log are untrusted host
// output.
type Host struct {
	HostID        string
	Fingerprint   string
	CredentialRef string
	Endpoints     []string
	State         string
	Class         string
	Detail        string
	ExitCode      int
	Result        []byte
	Log           []byte
	LogTruncated  bool
	StartedAt     time.Time
	FinishedAt    time.Time
	// Stage is the host's stage (1-based).
	Stage int
}

func unix(n sql.NullInt64) time.Time {
	if !n.Valid || n.Int64 == 0 {
		return time.Time{}
	}
	return time.Unix(n.Int64, 0)
}

// Get returns one execution with its hosts.
func (s *Service) Get(ctx context.Context, id string) (Execution, error) {
	var e Execution
	var durable int
	var timeout, created, expiry int64
	var finished sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT id, digest, action_id, module_version, artifact_sha256, risk, requirement, state, detail,
			durable, timeout_s, options, approval_expiry, created_by, created_at, finished_at, params, stage_plan, waiting FROM executions WHERE id = ?`, id).
		Scan(&e.ID, &e.Digest, &e.ActionID, &e.ModuleVersion, &e.ArtifactSHA256, &e.Risk, &e.Requirement, &e.State, &e.Detail,
			&durable, &timeout, &e.Options, &expiry, &e.CreatedBy, &created, &finished, &e.Params, &e.StagePlan, &e.Waiting)
	if errors.Is(err, sql.ErrNoRows) {
		return Execution{}, ErrNotFound
	}
	if err != nil {
		return Execution{}, fmt.Errorf("get execution: %w", err)
	}
	e.Durable, e.Timeout, e.CreatedAt, e.FinishedAt = durable == 1, time.Duration(timeout)*time.Second, time.Unix(created, 0), unix(finished)
	if expiry > 0 {
		e.ApprovalExpiry = time.Unix(expiry, 0)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT host_id, fingerprint, credential_ref, endpoints, state, class, detail, exit_code, result, log,
			log_truncated, started_at, finished_at, stage FROM execution_hosts WHERE execution_id = ? ORDER BY stage, host_id`, id)
	if err != nil {
		return Execution{}, fmt.Errorf("get execution hosts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var h Host
		var eps string
		var trunc int
		var started, fin sql.NullInt64
		if err := rows.Scan(&h.HostID, &h.Fingerprint, &h.CredentialRef, &eps, &h.State, &h.Class, &h.Detail, &h.ExitCode, &h.Result, &h.Log,
			&trunc, &started, &fin, &h.Stage); err != nil {
			return Execution{}, err
		}
		if err := json.Unmarshal([]byte(eps), &h.Endpoints); err != nil {
			return Execution{}, fmt.Errorf("execution host endpoints: %w", err)
		}
		h.LogTruncated, h.StartedAt, h.FinishedAt = trunc == 1, unix(started), unix(fin)
		e.Hosts = append(e.Hosts, h)
	}
	return e, rows.Err()
}

// Summary is one row of the execution list.
type Summary struct {
	ID        string
	ActionID  string
	Risk      string
	State     string
	CreatedBy string
	CreatedAt time.Time
	// FinishedAt is zero while the execution has not finished.
	FinishedAt time.Time
	Hosts      int
	Failed     int
}

// List returns the latest executions, newest first.
func (s *Service) List(ctx context.Context, limit int) ([]Summary, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT e.id, e.action_id, e.risk, e.state, e.created_by, e.created_at, e.finished_at,
		(SELECT count(*) FROM execution_hosts h WHERE h.execution_id = e.id),
		(SELECT count(*) FROM execution_hosts h WHERE h.execution_id = e.id AND h.state = 'finished' AND h.class != 'success')
		FROM executions e ORDER BY e.created_at DESC, e.id LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list executions: %w", err)
	}
	defer rows.Close()
	var out []Summary
	for rows.Next() {
		var x Summary
		var created, finished sql.NullInt64
		if err := rows.Scan(&x.ID, &x.ActionID, &x.Risk, &x.State, &x.CreatedBy, &created, &finished, &x.Hosts, &x.Failed); err != nil {
			return nil, err
		}
		x.CreatedAt, x.FinishedAt = time.Unix(created.Int64, 0), unix(finished)
		out = append(out, x)
	}
	return out, rows.Err()
}

// ListHosts returns the host IDs of the given executions in one query.
// Unknown IDs simply have no entry.
func (s *Service) ListHosts(ctx context.Context, ids []string) (map[string][]string, error) {
	out := make(map[string][]string, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	if len(ids) > 500 {
		return nil, errors.New("too many executions for ListHosts")
	}
	ph := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		ph[i], args[i] = "?", id
	}
	rows, err := s.db.QueryContext(ctx, `SELECT execution_id, host_id FROM execution_hosts WHERE execution_id IN (`+strings.Join(ph, ",")+`) ORDER BY execution_id, host_id`, args...)
	if err != nil {
		return nil, fmt.Errorf("list execution hosts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var exec, host string
		if err := rows.Scan(&exec, &host); err != nil {
			return nil, err
		}
		out[exec] = append(out[exec], host)
	}
	return out, rows.Err()
}
