// SPDX-License-Identifier: AGPL-3.0-or-later

package trafficingest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ExecutionSource reads net.facts results from the server database's
// execution records.
type ExecutionSource struct {
	DB *sql.DB
}

// latestSQL picks the latest successful net.facts run of one host; the
// execution ID breaks ties between runs that finished in the same
// second, so the choice is stable. The result is returned as stored; the
// decoder bounds it.
const latestSQL = `
	SELECT h.execution_id, h.host_id, h.finished_at, h.result
	FROM execution_hosts h JOIN executions e ON e.id = h.execution_id
	WHERE e.action_id = ? AND h.host_id = ? AND h.state = 'finished' AND h.class = 'success'
	  AND h.finished_at IS NOT NULL
	ORDER BY h.finished_at DESC, h.execution_id DESC
	LIMIT 1`

// LatestNetFacts returns the latest successful net.facts result of host.
// Host and Finished come from the server's execution record.
func (s ExecutionSource) LatestNetFacts(ctx context.Context, host string) (Result, bool, error) {
	var r Result
	var finished int64
	err := s.DB.QueryRowContext(ctx, latestSQL, ActionID, host).
		Scan(&r.ExecutionID, &r.Host, &finished, &r.Data)
	if errors.Is(err, sql.ErrNoRows) {
		return Result{}, false, nil
	}
	if err != nil {
		return Result{}, false, fmt.Errorf("trafficingest: latest net.facts of %s: %w", host, err)
	}
	r.Finished = time.Unix(finished, 0).UTC()
	return r, true, nil
}
