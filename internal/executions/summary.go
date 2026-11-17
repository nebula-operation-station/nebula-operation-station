// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"fmt"
	"strings"
)

// abortableLookupMax bounds the executor calls of one Abortable call: a
// running staged rollout costs one GetRollout, and the operations list
// shows at most a page of rows. Rows past the bound get no abort button.
const abortableLookupMax = 20

// abortableIDsMax bounds the IDs of one Abortable call (the same bound
// as ListHosts).
const abortableIDsMax = 500

// Abortable returns which of the given executions can be aborted from
// the operations list. The rule is the detail page's: the execution is
// staged and running or approved, and the executor's view of its rollout
// is neither aborted nor stopped. IDs that do not qualify, and IDs past
// abortableLookupMax executor calls, are absent from the map. An executor
// error for one execution leaves that execution out and is logged; the
// list still renders.
func (s *Service) Abortable(ctx context.Context, ids []string) (map[string]bool, error) {
	out := make(map[string]bool)
	if len(ids) == 0 {
		return out, nil
	}
	if len(ids) > abortableIDsMax {
		return nil, fmt.Errorf("too many executions for Abortable: %d", len(ids))
	}
	ph := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		ph[i], args[i] = "?", id
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, digest FROM executions
		WHERE id IN (`+strings.Join(ph, ",")+`) AND stage_plan != '' AND digest != ''
		AND state IN ('running', 'approved')`, args...)
	if err != nil {
		return nil, fmt.Errorf("list abortable executions: %w", err)
	}
	type candidate struct{ id, digest string }
	var cands []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.digest); err != nil {
			rows.Close()
			return nil, err
		}
		cands = append(cands, c)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	for i, c := range cands {
		if i >= abortableLookupMax {
			break
		}
		ro, err := s.rollout(ctx, c.digest)
		if err != nil {
			s.log.Warn("abortable: rollout", "execution", c.id, "error", err.Error())
			continue
		}
		if !ro.GetAborted() && ro.GetStopped() == "" {
			out[c.id] = true
		}
	}
	return out, nil
}
