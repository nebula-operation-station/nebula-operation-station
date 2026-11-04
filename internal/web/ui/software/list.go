// SPDX-License-Identifier: AGPL-3.0-or-later

package software

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/nebula-operation-station/nebula-operation-station/internal/softwarecat"
)

// listQuery reads the catalog (migration 0032) with the host and
// observation counts of each key. Observations keep the key they were
// recorded under, so an entry also counts the observations of the keys
// merged into it (merges are one level deep). Read-only.
const listQuery = `
	SELECT c.key, c.display, c.state, c.merged_into, COALESCE(c.icon_sha, ''),
	       (SELECT COUNT(DISTINCT o.host_id) FROM software_observations o
	         WHERE o.key = c.key OR o.key IN (SELECT m.key FROM software_catalog m WHERE m.merged_into = c.key)),
	       (SELECT COUNT(*) FROM software_observations o
	         WHERE o.key = c.key OR o.key IN (SELECT m.key FROM software_catalog m WHERE m.merged_into = c.key))
	FROM software_catalog c
	ORDER BY c.key
	LIMIT ?`

// SQLList returns a ListFunc that reads the catalog from the server
// database. limit is capped at MaxListRows.
//
// softwarecat.Store has no list method yet; this read-only query lives
// here until it gets one (see the TM17 report).
func SQLList(db *sql.DB) ListFunc {
	return func(ctx context.Context, limit int) ([]Row, bool, error) {
		if limit <= 0 || limit > MaxListRows {
			limit = MaxListRows
		}
		rows, err := db.QueryContext(ctx, listQuery, limit+1)
		if err != nil {
			return nil, false, fmt.Errorf("list software catalog: %w", err)
		}
		defer func() { _ = rows.Close() }()
		var out []Row
		truncated := false
		for rows.Next() {
			if len(out) == limit {
				truncated = true
				break
			}
			var r Row
			var key, state, merged string
			if err := rows.Scan(&key, &r.Display, &state, &merged, &r.IconSHA, &r.Hosts, &r.Observations); err != nil {
				return nil, false, fmt.Errorf("list software catalog: %w", err)
			}
			r.Key, r.State, r.MergedInto = softwarecat.Key(key), softwarecat.State(state), softwarecat.Key(merged)
			out = append(out, r)
		}
		if err := rows.Err(); err != nil {
			return nil, false, fmt.Errorf("list software catalog: %w", err)
		}
		return out, truncated, nil
	}
}
