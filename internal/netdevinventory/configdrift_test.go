// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for ConfigChangedNotDisplayed (ADR 0010 D4, ND-20): a running
// config version whose raw_digest changed while the redacted text did not
// is reported; everything else is not.

package netdevinventory

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"
)

// cfgVersion is one stored config version for the drift tests.
type cfgVersion struct {
	config   string
	raw, red byte
	lastSeen time.Duration // offset from testBase
}

func insertDriftVersion(t *testing.T, db *sql.DB, dev string, v cfgVersion) {
	t.Helper()
	seen := micros(testBase.Add(v.lastSeen))
	if _, err := db.Exec(`INSERT INTO netdev_config_versions (device_id, config, raw_digest, redacted_digest,
		redacted_text, first_seen, last_seen) VALUES (?, ?, ?, ?, 'hostname x', ?, ?)`,
		dev, v.config, strings.Repeat(string(v.raw), 64), strings.Repeat(string(v.red), 64), seen, seen); err != nil {
		t.Fatalf("insert config version: %v", err)
	}
}

func TestConfigChangedNotDisplayedOnlyForRawOnlyDrift(t *testing.T) {
	h := time.Hour
	cases := []struct {
		name     string
		versions []cfgVersion
		other    []cfgVersion // versions of another device
		want     bool
	}{
		{name: "no versions"},
		{name: "one version", versions: []cfgVersion{{"running", 'a', '1', 0}}},
		{name: "raw and redacted changed", versions: []cfgVersion{{"running", 'a', '1', -h}, {"running", 'b', '2', 0}}},
		{name: "raw changed, redacted unchanged", want: true,
			versions: []cfgVersion{{"running", 'a', '1', -h}, {"running", 'b', '1', 0}}},
		{name: "only the newest two count", versions: []cfgVersion{
			{"running", 'a', '1', -2 * h}, {"running", 'b', '1', -h}, {"running", 'c', '2', 0}}},
		{name: "older hidden drift is history", want: true, versions: []cfgVersion{
			{"running", 'a', '9', -2 * h}, {"running", 'b', '1', -h}, {"running", 'c', '1', 0}}},
		{name: "return to an earlier version counts by last seen", want: true, versions: []cfgVersion{
			// a was first stored, b followed, then the device returned to a.
			{"running", 'b', '1', -h}, {"running", 'a', '1', 0}}},
		{name: "startup versions are ignored", versions: []cfgVersion{
			{"running", 'a', '1', -h}, {"startup", 'b', '1', 0}}},
		{name: "other devices are ignored", versions: []cfgVersion{{"running", 'a', '1', 0}},
			other: []cfgVersion{{"running", 'b', '1', -h}, {"running", 'c', '1', 0}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, db, _ := newTestStore(t)
			addDevice(t, s, panosDevice())
			addDevice(t, s, cbsDevice())
			for _, v := range c.versions {
				insertDriftVersion(t, db, panosDevice().DeviceID, v)
			}
			for _, v := range c.other {
				insertDriftVersion(t, db, cbsDevice().DeviceID, v)
			}
			got, err := s.ConfigChangedNotDisplayed(context.Background(), panosDevice().DeviceID)
			if err != nil {
				t.Fatalf("ConfigChangedNotDisplayed: %v", err)
			}
			if got != c.want {
				t.Errorf("ConfigChangedNotDisplayed = %v, want %v", got, c.want)
			}
		})
	}
}

func TestConfigChangedNotDisplayedUnknownDeviceIsNoChange(t *testing.T) {
	s, _, _ := newTestStore(t)
	got, err := s.ConfigChangedNotDisplayed(context.Background(), "missing")
	if err != nil || got {
		t.Fatalf("ConfigChangedNotDisplayed(unknown) = %v, %v; want false, nil", got, err)
	}
}

func TestConfigChangedNotDisplayedReportsStoreError(t *testing.T) {
	s, db, _ := newTestStore(t)
	db.Close()
	if _, err := s.ConfigChangedNotDisplayed(context.Background(), panosDevice().DeviceID); err == nil {
		t.Fatal("ConfigChangedNotDisplayed on a closed database succeeded")
	}
}
