// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

import (
	"context"
	"fmt"
	"time"
)

// ConfigDrift is the answer of ConfigChangedNotDisplayed.
type ConfigDrift struct {
	// NotDisplayed is set when the current running config version differs
	// from the version before it only outside the redacted text.
	NotDisplayed bool
	// ChangedAfter is the last_seen of the previous version: the change
	// happened after the read at this time. Zero unless NotDisplayed.
	ChangedAfter time.Time
	// SeenAt is the first read that showed the current version, when it is
	// known: the current version's first_seen if that is after
	// ChangedAfter. A return to an earlier version keeps that version's
	// older first_seen, so SeenAt is zero then. Zero unless NotDisplayed.
	SeenAt time.Time
	// LastSeen is the last_seen of the current version. Zero unless
	// NotDisplayed.
	LastSeen time.Time
}

// ConfigChangedNotDisplayed reports whether the current running config
// version of deviceID differs from the version before it only outside the
// redacted text (ADR 0010 D4): the raw_digest changed while the
// redacted_digest did not. For PAN-OS this is drift outside the allowlist,
// which the UI shows as "changed in elements not displayed" instead of an
// empty diff, together with when the change was seen.
//
// The current version is the one seen last (an identical read only
// advances last_seen, so a configuration that returns to an earlier
// version makes that version current again); the version before it is the
// one seen last before that. Row id and first_seen do not decide the
// order. With fewer than two stored versions there is no change and
// NotDisplayed is false. The query reads at most two rows.
func (s *Store) ConfigChangedNotDisplayed(ctx context.Context, deviceID string) (ConfigDrift, error) {
	rs, err := s.db.QueryContext(ctx, `SELECT raw_digest, redacted_digest, first_seen, last_seen FROM netdev_config_versions
		WHERE device_id = ? AND config = 'running'
		ORDER BY last_seen DESC, id DESC LIMIT 2`, deviceID)
	if err != nil {
		return ConfigDrift{}, fmt.Errorf("netdevinventory: load config versions of %s: %w", deviceID, err)
	}
	defer rs.Close()
	var raw, red [2]string
	var first, last [2]int64
	n := 0
	for rs.Next() && n < 2 {
		if err := rs.Scan(&raw[n], &red[n], &first[n], &last[n]); err != nil {
			return ConfigDrift{}, fmt.Errorf("netdevinventory: scan config version of %s: %w", deviceID, err)
		}
		n++
	}
	if err := rs.Err(); err != nil {
		return ConfigDrift{}, fmt.Errorf("netdevinventory: read config versions of %s: %w", deviceID, err)
	}
	if n < 2 || raw[0] == raw[1] || red[0] != red[1] {
		return ConfigDrift{}, nil
	}
	d := ConfigDrift{NotDisplayed: true, ChangedAfter: fromMicros(last[1]), LastSeen: fromMicros(last[0])}
	if first[0] > last[1] {
		d.SeenAt = fromMicros(first[0])
	}
	return d, nil
}
