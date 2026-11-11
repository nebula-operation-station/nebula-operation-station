// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

import (
	"context"
	"fmt"
)

// ConfigChangedNotDisplayed reports whether the current running config
// version of deviceID differs from the version before it only outside the
// redacted text (ADR 0010 D4): the raw_digest changed while the
// redacted_digest did not. For PAN-OS this is drift outside the allowlist,
// which the UI shows as "changed in elements not displayed" instead of an
// empty diff.
//
// The current version is the one seen last (an identical read only
// advances last_seen, so a configuration that returns to an earlier
// version makes that version current again); the version before it is the
// one seen last before that. With fewer than two stored versions there is
// no change and the result is false. The query reads at most two rows.
func (s *Store) ConfigChangedNotDisplayed(ctx context.Context, deviceID string) (bool, error) {
	rs, err := s.db.QueryContext(ctx, `SELECT raw_digest, redacted_digest FROM netdev_config_versions
		WHERE device_id = ? AND config = 'running'
		ORDER BY last_seen DESC, id DESC LIMIT 2`, deviceID)
	if err != nil {
		return false, fmt.Errorf("netdevinventory: load config versions of %s: %w", deviceID, err)
	}
	defer rs.Close()
	var raw, red [2]string
	n := 0
	for rs.Next() && n < 2 {
		if err := rs.Scan(&raw[n], &red[n]); err != nil {
			return false, fmt.Errorf("netdevinventory: scan config version of %s: %w", deviceID, err)
		}
		n++
	}
	if err := rs.Err(); err != nil {
		return false, fmt.Errorf("netdevinventory: read config versions of %s: %w", deviceID, err)
	}
	if n < 2 {
		return false, nil
	}
	return raw[0] != raw[1] && red[0] == red[1], nil
}
