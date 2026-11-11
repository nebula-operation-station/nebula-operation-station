// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Write-path history bound tests (ND-16 fix round 2): ReplaceDataset
// itself enforces the retention window and the per-(device, read) count
// cap inside its transaction, so history stays bounded even if Prune never
// runs. An observed_at before the retention window is refused.

package netdevinventory

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

type boundCase struct {
	read Read
	dev  netdevcontract.Device
	rows func(i int) Rows
}

// boundCases covers both families and both kinds of history bound
// (count-capped snapshots and time-spaced MAC/LLDP/hit-count history).
// The content changes with every write, so no write is a no-op.
func boundCases() []boundCase {
	return []boundCase{
		{ReadVLANs, cbsDevice(), func(i int) Rows { return VLANRows{{ID: uint16(i%3 + 1)}} }},
		{ReadFacts, cbsDevice(), func(i int) Rows { return factsRowsFor(i) }},
		{ReadMACTable, cbsDevice(), func(i int) Rows { return MACRows{mac(byte(i % 3))} }},
		{ReadFirewallPolicy, panosDevice(), func(i int) Rows { return policy("rule-" + string(rune('a'+i%3))) }},
		{ReadHitCounts, panosDevice(), func(i int) Rows {
			return HitCountRows{{RuleName: "rule-a", Hits: uint64(i + 1), LastHit: &testBase}}
		}},
	}
}

// factsRowsFor returns facts whose uptime differs with i.
func factsRowsFor(i int) Rows {
	up := uint64(i + 1)
	return FactsRows{Facts: netdevcontract.Facts{Model: "CBS350", FirmwareVersion: "3.4", UptimeSeconds: &up}}
}

func historyCount(t *testing.T, db *sql.DB, dev string, read Read) int {
	t.Helper()
	return countRows(t, db, `SELECT count(*) FROM netdev_datasets WHERE device_id = ? AND read = ? AND current = 0`,
		dev, string(read))
}

func assertCurrent(t *testing.T, s *Store, db *sql.DB, dev string, read Read, want ReplaceResult) {
	t.Helper()
	d, err := s.GetDataset(context.Background(), dev, read)
	if err != nil {
		t.Fatalf("GetDataset: %v", err)
	}
	if d.ID != want.DatasetID || !d.Current {
		t.Fatalf("current dataset = %d, want %d", d.ID, want.DatasetID)
	}
	if n := len(rowsOf(t, db, readTables(read)[0].name, d.ID)); n == 0 {
		t.Fatalf("current dataset %d lost its rows", d.ID)
	}
}

// A replaying writer delivers more than MaxSnapshotsPerRead changed
// datasets with dense, old observed_at values (all inside the window).
// Without Prune, history must stay within MaxHistoryPerRead, the oldest
// go first and the current dataset survives.
func TestReplayingWriterDenseHistoryIsCappedOnWrite(t *testing.T) {
	for _, c := range boundCases() {
		t.Run(string(c.read), func(t *testing.T) {
			t.Parallel() // each subtest has its own database
			s, db, now := newTestStore(t)
			addDevice(t, s, c.dev)
			n := MaxSnapshotsPerRead + 50
			// Dense: one second apart, starting deep inside the window.
			start := now.Add(-HistoryRetention(c.read) + time.Hour)
			var last ReplaceResult
			for i := range n {
				last = mustReplace(t, s, c.dev.DeviceID, c.read, start.Add(time.Duration(i)*time.Second), false, c.rows(i))
				if got := historyCount(t, db, c.dev.DeviceID, c.read); got > MaxHistoryPerRead(c.read) {
					t.Fatalf("after write %d: history = %d > cap %d", i, got, MaxHistoryPerRead(c.read))
				}
			}
			got := historyCount(t, db, c.dev.DeviceID, c.read)
			if countCapped(c.read) {
				if got != MaxSnapshotsPerRead {
					t.Fatalf("history = %d after %d writes, want exactly the cap %d", got, n, MaxSnapshotsPerRead)
				}
				// Oldest first: the kept history is the newest n-1-cap .. n-2.
				var oldest int64
				if err := db.QueryRow(`SELECT min(observed_at) FROM netdev_datasets WHERE device_id = ? AND read = ?`,
					c.dev.DeviceID, string(c.read)).Scan(&oldest); err != nil {
					t.Fatal(err)
				}
				if want := micros(start.Add(time.Duration(n-1-MaxSnapshotsPerRead) * time.Second)); oldest != want {
					t.Fatalf("oldest kept %d, want %d (oldest trimmed first)", oldest, want)
				}
			}
			assertCurrent(t, s, db, c.dev.DeviceID, c.read, last)
		})
	}
}

// A writer whose clock keeps moving (one changed dataset per poll
// interval for longer than the retention window) never leaves history
// older than the window behind, without Prune.
func TestReplayingWriterAdvancingClockDropsAgedHistoryOnWrite(t *testing.T) {
	for _, c := range boundCases() {
		if countCapped(c.read) {
			// 1,000 steps of a poll interval stay inside the 400-day
			// window; the count cap is covered by the dense test.
			continue
		}
		t.Run(string(c.read), func(t *testing.T) {
			t.Parallel() // each subtest has its own database
			s, db, now := newTestStore(t)
			addDevice(t, s, c.dev)
			const n = 1000
			step := HistoryRetention(c.read) / 300 // the replay spans more than three windows
			var last ReplaceResult
			for i := range n {
				*now = testBase.Add(time.Duration(i) * step)
				last = mustReplace(t, s, c.dev.DeviceID, c.read, *now, false, c.rows(i))
			}
			cutoff := micros(now.Add(-HistoryRetention(c.read)))
			if n := countRows(t, db, `SELECT count(*) FROM netdev_datasets WHERE device_id = ? AND read = ?
				AND current = 0 AND observed_at < ?`, c.dev.DeviceID, string(c.read), cutoff); n != 0 {
				t.Fatalf("%d datasets older than the window kept without Prune", n)
			}
			if got := historyCount(t, db, c.dev.DeviceID, c.read); got > MaxHistoryPerRead(c.read) || got > 301 {
				t.Fatalf("history = %d, want at most %d", got, min(MaxHistoryPerRead(c.read), 301))
			}
			assertCurrent(t, s, db, c.dev.DeviceID, c.read, last)
		})
	}
}

func TestObservedBeforeRetentionWindowIsRefused(t *testing.T) {
	for _, c := range boundCases() {
		t.Run(string(c.read), func(t *testing.T) {
			s, db, now := newTestStore(t)
			addDevice(t, s, c.dev)
			ctx := context.Background()
			edge := now.Add(-HistoryRetention(c.read))
			_, err := s.ReplaceDataset(ctx, c.dev.DeviceID, c.read, c.dev.TrustGeneration,
				edge.Add(-time.Microsecond), false, c.rows(0))
			if !errors.Is(err, ErrObservationTooOld) {
				t.Fatalf("err = %v, want ErrObservationTooOld", err)
			}
			if n := countRows(t, db, `SELECT count(*) FROM netdev_datasets`); n != 0 {
				t.Fatalf("%d datasets written for a refused observation", n)
			}
			if d, err := s.GetDevice(ctx, c.dev.DeviceID); err != nil || !d.LastSeen.IsZero() {
				t.Fatalf("device touched by a refused observation: %+v, %v", d, err)
			}
			// Exactly at the window edge it is accepted.
			mustReplace(t, s, c.dev.DeviceID, c.read, edge, false, c.rows(0))
		})
	}
}

// Trimming never removes a current dataset: not the one just written, and
// not the current dataset of another read whose age is far past its
// window.
func TestCurrentDatasetSurvivesWriteTrimming(t *testing.T) {
	s, db, now := newTestStore(t)
	addDevice(t, s, cbsDevice())
	oldVLAN := mustReplace(t, s, "sw-core", ReadVLANs, testBase, false, VLANRows{{ID: 1}})
	mustReplace(t, s, "sw-core", ReadMACTable, testBase, false, MACRows{mac(1)})

	// Years later, a MAC replay trims MAC history; the old current VLAN
	// dataset stays.
	*now = testBase.Add(3 * 365 * 24 * time.Hour)
	var last ReplaceResult
	for i := range 20 {
		last = mustReplace(t, s, "sw-core", ReadMACTable, now.Add(time.Duration(i)*time.Second), false, MACRows{mac(byte(i % 3))})
	}
	assertCurrent(t, s, db, "sw-core", ReadVLANs, oldVLAN)
	assertCurrent(t, s, db, "sw-core", ReadMACTable, last)
	// The MAC dataset from years ago was history older than the window:
	// gone on write, without Prune.
	if n := countRows(t, db, `SELECT count(*) FROM netdev_datasets WHERE read = 'mac_table' AND observed_at = ?`,
		micros(testBase)); n != 0 {
		t.Fatalf("aged MAC history kept")
	}

	// The aged current VLAN dataset is superseded and, now past its
	// window, dropped as history; the new current one survives.
	cur := mustReplace(t, s, "sw-core", ReadVLANs, *now, false, VLANRows{{ID: 2}})
	assertCurrent(t, s, db, "sw-core", ReadVLANs, cur)
	if ids := datasetIDs(t, db, ReadVLANs); len(ids) != 1 || ids[0] != cur.DatasetID {
		t.Fatalf("VLAN datasets = %v, want [%d]", ids, cur.DatasetID)
	}
}

func TestMaxHistoryPerReadMatchesSpacing(t *testing.T) {
	for _, r := range Reads {
		got := MaxHistoryPerRead(r)
		if countCapped(r) {
			if got != MaxSnapshotsPerRead {
				t.Errorf("%s: cap %d, want %d", r, got, MaxSnapshotsPerRead)
			}
			continue
		}
		want := int(HistoryRetention(r)/MinHistorySpacing(r)) + 1
		if got != want {
			t.Errorf("%s: cap %d, want %d", r, got, want)
		}
		// Normal polling must fit: one dataset per poll interval over the
		// whole window.
		if poll := int(HistoryRetention(r)/PollInterval(r)) + 1; got < poll {
			t.Errorf("%s: cap %d below normal polling %d", r, got, poll)
		}
	}
}
