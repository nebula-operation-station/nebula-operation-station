// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// LastResultRow is the latest successful result of an action on one host.
type LastResultRow struct {
	Result     []byte
	FinishedAt time.Time
}

// LastResults returns the latest successful result of action actionID for
// every host that has one, in one query (the inventory list must not do one
// query per host). The results are untrusted host output, bounded like
// every result.
func (s *Service) LastResults(ctx context.Context, actionID string) (map[string]LastResultRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT h.host_id, h.result, h.finished_at FROM execution_hosts h
		JOIN executions e ON e.id = h.execution_id
		WHERE e.action_id = ? AND h.state = 'finished' AND h.class = 'success'
		AND h.finished_at = (SELECT max(h2.finished_at) FROM execution_hosts h2
			JOIN executions e2 ON e2.id = h2.execution_id
			WHERE e2.action_id = ? AND h2.host_id = h.host_id
			AND h2.state = 'finished' AND h2.class = 'success')
		ORDER BY h.finished_at DESC, e.id DESC`, actionID, actionID)
	if err != nil {
		return nil, fmt.Errorf("last results of %s: %w", actionID, err)
	}
	defer rows.Close()
	out := map[string]LastResultRow{}
	for rows.Next() {
		var host string
		var res []byte
		var at sql.NullInt64
		if err := rows.Scan(&host, &res, &at); err != nil {
			return nil, err
		}
		if _, ok := out[host]; ok {
			continue // finished_at tie: keep the first row (newest execution id)
		}
		out[host] = LastResultRow{Result: res, FinishedAt: unix(at)}
	}
	return out, rows.Err()
}

// LastSeenAll returns the newest time any action finished on each host, in
// one query.
func (s *Service) LastSeenAll(ctx context.Context) (map[string]time.Time, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT h.host_id, max(h.finished_at) FROM execution_hosts h
		JOIN executions e ON e.id = h.execution_id
		WHERE h.state = 'finished' GROUP BY h.host_id`)
	if err != nil {
		return nil, fmt.Errorf("last seen: %w", err)
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var host string
		var at sql.NullInt64
		if err := rows.Scan(&host, &at); err != nil {
			return nil, err
		}
		if at.Valid && at.Int64 > 0 {
			out[host] = time.Unix(at.Int64, 0)
		}
	}
	return out, rows.Err()
}

// LastSeen returns the newest time any action finished on host.
func (s *Service) LastSeen(ctx context.Context, host string) (time.Time, bool, error) {
	var at sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT max(h.finished_at) FROM execution_hosts h
		JOIN executions e ON e.id = h.execution_id
		WHERE h.host_id = ? AND h.state = 'finished'`, host).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("last seen %s: %w", host, err)
	}
	if !at.Valid || at.Int64 == 0 {
		return time.Time{}, false, nil
	}
	return time.Unix(at.Int64, 0), true, nil
}

// ListHost returns the latest executions that targeted host, newest first.
func (s *Service) ListHost(ctx context.Context, host string, limit int) ([]Summary, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT e.id, e.action_id, e.risk, e.state, e.created_by, e.created_at, e.finished_at,
		(SELECT count(*) FROM execution_hosts h WHERE h.execution_id = e.id),
		(SELECT count(*) FROM execution_hosts h WHERE h.execution_id = e.id AND h.state = 'finished' AND h.class != 'success')
		FROM executions e JOIN execution_hosts h ON h.execution_id = e.id
		WHERE h.host_id = ? ORDER BY e.created_at DESC, e.id DESC LIMIT ?`, host, limit)
	if err != nil {
		return nil, fmt.Errorf("list executions of %s: %w", host, err)
	}
	defer rows.Close()
	var out []Summary
	for rows.Next() {
		var x Summary
		var created int64
		var finished sql.NullInt64
		if err := rows.Scan(&x.ID, &x.ActionID, &x.Risk, &x.State, &x.CreatedBy, &created, &finished, &x.Hosts, &x.Failed); err != nil {
			return nil, err
		}
		x.CreatedAt, x.FinishedAt = time.Unix(created, 0), unix(finished)
		out = append(out, x)
	}
	return out, rows.Err()
}
