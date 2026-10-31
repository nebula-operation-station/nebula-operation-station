// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
)

func sessionLengthFromMinutes(minutes int) (time.Duration, error) {
	// Validate the integer before conversion so a huge flag value cannot
	// overflow time.Duration into an accepted duration.
	if minutes < int(permit.MinSessionLength/time.Minute) || minutes > int(permit.MaxSessionLength/time.Minute) {
		return 0, fmt.Errorf("session-minutes must be between %d and %d", permit.MinSessionLength/time.Minute, permit.MaxSessionLength/time.Minute)
	}
	return time.Duration(minutes) * time.Minute, nil
}
