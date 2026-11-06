// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
)

// trafficRetention returns the traffic store's retention from the server
// config (traffic.retention_days: 1-21 days, default 21). It re-checks
// the range so a config that never went through serverconfig validation
// fails closed instead of opening the store with an out-of-range
// retention.
func trafficRetention(cfg serverconfig.Config) (time.Duration, error) {
	days := cfg.Traffic.EffectiveRetentionDays()
	if days < 1 || days > serverconfig.DefaultTrafficRetentionDays {
		return 0, fmt.Errorf("traffic.retention_days: %d is outside 1-%d", days, serverconfig.DefaultTrafficRetentionDays)
	}
	return time.Duration(days) * 24 * time.Hour, nil
}
