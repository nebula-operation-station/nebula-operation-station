// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests for ConfigChangedNotDisplayed (ADR 0010 D4, ND-20): a running
// config version whose raw_digest changed while the redacted text did not
// is reported with when the change was seen; everything else is not. The
// current and previous versions are chosen by last_seen, never by row id
// or first_seen: the cases insert rows out of id and first_seen order so
// that either wrong order gives a different answer.

package netdevinventory

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"
)

// cfgVersion is one stored config version for the drift tests. Versions
// are inserted in slice order, so the slice order is the row id order;
// first and last are the first_seen and last_seen offsets from testBase.
type cfgVersion struct {
	config      string
	raw, red    byte
	first, last time.Duration
}

// seen is a version read once at offset d (first_seen = last_seen).
func seen(config string, raw, red byte, d time.Duration) cfgVersion {
	return cfgVersion{config, raw, red, d, d}
}

func insertDriftVersion(t *testing.T, db *sql.DB, dev string, v cfgVersion) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO netdev_config_versions (device_id, config, raw_digest, redacted_digest,
		redacted_text, first_seen, last_seen) VALUES (?, ?, ?, ?, 'hostname x', ?, ?)`,
		dev, v.config, strings.Repeat(string(v.raw), 64), strings.Repeat(string(v.red), 64),
		micros(testBase.Add(v.first)), micros(testBase.Add(v.last))); err != nil {
		t.Fatalf("insert config version: %v", err)
	}
}

// driftAt is the expected drift: changed after the read at offset after,
// first seen at offset seenAt (nil: not known) and the current version
// last seen at offset last.
func driftAt(after time.Duration, seenAt *time.Duration, last time.Duration) ConfigDrift {
	d := ConfigDrift{NotDisplayed: true, ChangedAfter: testBase.Add(after), LastSeen: testBase.Add(last)}
	if seenAt != nil {
		d.SeenAt = testBase.Add(*seenAt)
	}
	return d
}

func sameDrift(a, b ConfigDrift) bool {
	return a.NotDisplayed == b.NotDisplayed && a.ChangedAfter.Equal(b.ChangedAfter) &&
		a.SeenAt.Equal(b.SeenAt) && a.LastSeen.Equal(b.LastSeen)
}

func TestConfigChangedNotDisplayedOnlyForRawOnlyDrift(t *testing.T) {
	h := time.Hour
	at := func(d time.Duration) *time.Duration { return &d }
	cases := []struct {
		name     string
		versions []cfgVersion // inserted in this order (row id order)
		other    []cfgVersion // versions of another device
		want     ConfigDrift
	}{
		{name: "no versions"},
		{name: "one version", versions: []cfgVersion{seen("running", 'a', '1', 0)}},
		{name: "raw and redacted changed", versions: []cfgVersion{seen("running", 'a', '1', -h), seen("running", 'b', '2', 0)}},
		{name: "raw changed, redacted unchanged", want: driftAt(-h, at(0), 0),
			versions: []cfgVersion{seen("running", 'a', '1', -h), seen("running", 'b', '1', 0)}},
		{name: "current version read again keeps its first read", want: driftAt(-3*h, at(-2*h), 0),
			versions: []cfgVersion{seen("running", 'a', '1', -3*h), {"running", 'b', '1', -2 * h, 0}}},
		{name: "only the newest two count", versions: []cfgVersion{
			seen("running", 'a', '1', -2*h), seen("running", 'b', '1', -h), seen("running", 'c', '2', 0)}},
		{name: "older hidden drift is history", want: driftAt(-h, at(0), 0), versions: []cfgVersion{
			seen("running", 'a', '9', -2*h), seen("running", 'b', '1', -h), seen("running", 'c', '1', 0)}},
		// A, B, C, then back to A: A has the oldest row id and the oldest
		// first_seen but the newest last_seen. By last_seen the pair is
		// (A, C): raw-only drift, first read of the return not known.
		// Ordered by id or by first_seen the pair would be (C, B), whose
		// redacted text differs: no drift.
		{name: "return to the oldest version counts by last seen", want: driftAt(-h, nil, 0), versions: []cfgVersion{
			{"running", 'a', '1', -4 * h, 0}, seen("running", 'b', '2', -2*h), seen("running", 'c', '1', -h)}},
		// Rows stored out of time order. By id the pair would be (C, B):
		// raw-only drift. By last_seen it is (B, A), whose redacted text
		// differs: no drift.
		{name: "row id order does not decide", versions: []cfgVersion{
			seen("running", 'a', '2', -h), seen("running", 'b', '1', 0), seen("running", 'c', '1', -3*h)}},
		// By first_seen the pair would be (B, A): raw-only drift. By
		// last_seen it is (C, B), whose redacted text differs: no drift.
		{name: "first seen order does not decide", versions: []cfgVersion{
			{"running", 'a', '1', -5 * h, -4 * h}, {"running", 'b', '1', -3 * h, -h}, {"running", 'c', '2', -6 * h, 0}}},
		{name: "startup versions are ignored", versions: []cfgVersion{
			seen("running", 'a', '1', -h), seen("startup", 'b', '1', 0)}},
		{name: "other devices are ignored", versions: []cfgVersion{seen("running", 'a', '1', 0)},
			other: []cfgVersion{seen("running", 'b', '1', -h), seen("running", 'c', '1', 0)}},
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
			if !sameDrift(got, c.want) {
				t.Errorf("ConfigChangedNotDisplayed = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestConfigChangedNotDisplayedUnknownDeviceIsNoChange(t *testing.T) {
	s, _, _ := newTestStore(t)
	got, err := s.ConfigChangedNotDisplayed(context.Background(), "missing")
	if err != nil || got.NotDisplayed {
		t.Fatalf("ConfigChangedNotDisplayed(unknown) = %+v, %v; want no drift, nil", got, err)
	}
}

func TestConfigChangedNotDisplayedReportsStoreError(t *testing.T) {
	s, db, _ := newTestStore(t)
	db.Close()
	if _, err := s.ConfigChangedNotDisplayed(context.Background(), panosDevice().DeviceID); err == nil {
		t.Fatal("ConfigChangedNotDisplayed on a closed database succeeded")
	}
}
