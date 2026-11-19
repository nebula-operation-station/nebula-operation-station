// SPDX-License-Identifier: AGPL-3.0-or-later

package serverconfig

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

// DefaultDigestTime is the daily digest send time when none is configured.
const DefaultDigestTime = "07:00"

// ErrDigestTime reports a daily digest time that is not "HH:MM" on a 24-hour clock.
var ErrDigestTime = errors.New("serverconfig: daily digest time must be HH:MM")

// digestTimeRe matches "HH:MM" with a 24-hour clock. Leading zeros are required.
var digestTimeRe = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

// DailyDigest configures the optional daily digest (spec 13, ADR 0016 D10).
// It is off by default. The digest carries counts only.
type DailyDigest struct {
	// Enabled turns the digest on. Default false.
	Enabled bool `json:"enabled"`
	// Time is the local send time as "HH:MM". Default "07:00".
	Time string `json:"time,omitempty"`
	// SkipEmpty suppresses the digest on a day when every count is zero.
	SkipEmpty bool `json:"skip_empty"`
}

// SendTime returns the configured send time as hour and minute. An empty
// Time means DefaultDigestTime. Any other value that is not "HH:MM" is
// ErrDigestTime.
func (d DailyDigest) SendTime() (hour, minute int, err error) {
	t := d.Time
	if t == "" {
		t = DefaultDigestTime
	}
	if !digestTimeRe.MatchString(t) {
		return 0, 0, fmt.Errorf("%w: %q", ErrDigestTime, t)
	}
	hour, _ = strconv.Atoi(t[0:2])
	minute, _ = strconv.Atoi(t[3:5])
	return hour, minute, nil
}

// problems lists what is wrong with the digest settings. The send time is
// checked even while the digest is off, so a typo is found at start. An
// enabled digest needs at least one provider to send to.
func (d DailyDigest) problems(providers int) []string {
	var p []string
	if _, _, err := d.SendTime(); err != nil {
		p = append(p, fmt.Sprintf("notifications.daily_digest.time: %v", err))
	}
	if d.Enabled && providers == 0 {
		p = append(p, "notifications.daily_digest: enabled needs at least one notification provider")
	}
	return p
}
