// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Retention on unchanged writes (ND-16 part 1, nd16c): the Q11 window
// holds for every (device, read), also one whose payload never changes
// again, without Prune. And the count cap of the time-spaced reads (MAC,
// LLDP, hit counts) is reached and enforced exactly.

package netdevinventory

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"testing"
	"time"
)

// agedHistory counts superseded datasets of (dev, read) observed before
// the window that ends at now.
func agedHistory(t *testing.T, db *sql.DB, dev string, read Read, now time.Time) int {
	t.Helper()
	return countRows(t, db, `SELECT count(*) FROM netdev_datasets WHERE device_id = ? AND read = ?
		AND current = 0 AND observed_at < ?`, dev, string(read), micros(now.Add(-HistoryRetention(read))))
}

// expiredCarried counts rows of any dataset of (dev, read) carried over
// with a seen_at before the window that ends at now.
func expiredCarried(t *testing.T, db *sql.DB, dev string, read Read, now time.Time) int {
	t.Helper()
	n := 0
	for _, tb := range readTables(read) {
		n += countRows(t, db, `SELECT count(*) FROM `+tb.name+` r JOIN netdev_datasets d ON d.id = r.dataset_id
			WHERE d.device_id = ? AND d.read = ? AND r.seen_at IS NOT NULL AND r.seen_at < ?`,
			dev, string(read), micros(now.Add(-HistoryRetention(read))))
	}
	return n
}

// carriedCount counts rows of any dataset of (dev, read) carried over.
func carriedCount(t *testing.T, db *sql.DB, dev string, read Read) int {
	t.Helper()
	n := 0
	for _, tb := range readTables(read) {
		n += countRows(t, db, `SELECT count(*) FROM `+tb.name+` r JOIN netdev_datasets d ON d.id = r.dataset_id
			WHERE d.device_id = ? AND d.read = ? AND r.seen_at IS NOT NULL`, dev, string(read))
	}
	return n
}

// A (device, read) whose payload stops changing (a quiet switch's MAC
// table) still loses superseded datasets and expired carried rows once
// they leave the window: the identical-payload path bounds history too,
// without Prune and without rewriting the current dataset.
func TestIdenticalPayloadsDropAgedHistoryWithoutPrune(t *testing.T) {
	for _, c := range boundCases() {
		t.Run(string(c.read), func(t *testing.T) {
			t.Parallel() // each subtest has its own database
			s, db, now := newTestStore(t)
			addDevice(t, s, c.dev)
			dev := c.dev.DeviceID
			poll := PollInterval(c.read)
			mustReplace(t, s, dev, c.read, testBase, false, c.rows(0))
			*now = testBase.Add(poll)
			cur := mustReplace(t, s, dev, c.read, *now, false, c.rows(1))
			if got := historyCount(t, db, dev, c.read); got != 1 {
				t.Fatalf("history = %d after one change, want 1", got)
			}
			carried := carriedCount(t, db, dev, c.read)

			// Identical payloads inside the window keep the history.
			*now = testBase.Add(2 * poll)
			if res := mustReplace(t, s, dev, c.read, *now, false, c.rows(1)); !res.Unchanged || res.DatasetID != cur.DatasetID {
				t.Fatalf("identical write = %+v, want unchanged %d", res, cur.DatasetID)
			}
			if got := historyCount(t, db, dev, c.read); got != 1 {
				t.Fatalf("history = %d inside the window, want 1", got)
			}
			if got := carriedCount(t, db, dev, c.read); got != carried {
				t.Fatalf("carried rows = %d inside the window, want %d", got, carried)
			}

			// Only identical payloads from here on, past the window.
			for i := 1; i <= 3; i++ {
				*now = testBase.Add(HistoryRetention(c.read) + time.Duration(i)*poll)
				res := mustReplace(t, s, dev, c.read, *now, false, c.rows(1))
				if !res.Unchanged || res.DatasetID != cur.DatasetID {
					t.Fatalf("identical write %d = %+v, want unchanged %d", i, res, cur.DatasetID)
				}
				if n := agedHistory(t, db, dev, c.read, *now); n != 0 {
					t.Fatalf("write %d: %d superseded datasets older than the window kept", i, n)
				}
				if n := expiredCarried(t, db, dev, c.read, *now); n != 0 {
					t.Fatalf("write %d: %d expired carried rows kept", i, n)
				}
			}
			if got := historyCount(t, db, dev, c.read); got != 0 {
				t.Fatalf("history = %d past the window, want 0", got)
			}
			// The current dataset is kept and not rewritten.
			assertCurrent(t, s, db, dev, c.read, cur)
			if ids := datasetIDs(t, db, c.read); len(ids) != 1 || ids[0] != cur.DatasetID {
				t.Fatalf("datasets = %v, want [%d]", ids, cur.DatasetID)
			}
			d, err := s.GetDataset(context.Background(), dev, c.read)
			if err != nil {
				t.Fatal(err)
			}
			if !d.ObservedAt.Equal(*now) {
				t.Fatalf("observed_at = %s, want %s", d.ObservedAt, *now)
			}
		})
	}
}

// The same dataset delivered again is a no-op for the dataset, but the
// window still holds for the history behind it.
func TestRedeliveredDatasetDropsAgedHistory(t *testing.T) {
	for _, c := range boundCases() {
		t.Run(string(c.read), func(t *testing.T) {
			s, db, now := newTestStore(t)
			addDevice(t, s, c.dev)
			dev := c.dev.DeviceID
			ret := HistoryRetention(c.read)
			mustReplace(t, s, dev, c.read, testBase, false, c.rows(0))
			at := testBase.Add(ret - time.Hour)
			*now = at
			cur := mustReplace(t, s, dev, c.read, at, false, c.rows(1))

			*now = testBase.Add(ret + time.Minute)
			res := mustReplace(t, s, dev, c.read, at, false, c.rows(1))
			if !res.Unchanged || res.DatasetID != cur.DatasetID {
				t.Fatalf("redelivery = %+v, want unchanged %d", res, cur.DatasetID)
			}
			if n := agedHistory(t, db, dev, c.read, *now); n != 0 {
				t.Fatalf("%d superseded datasets older than the window kept", n)
			}
			if n := expiredCarried(t, db, dev, c.read, *now); n != 0 {
				t.Fatalf("%d expired carried rows kept", n)
			}
			assertCurrent(t, s, db, dev, c.read, cur)
		})
	}
}

// A changed dataset observed well before the server clock does not carry
// rows whose seen_at already left the window that ends at the server
// clock.
func TestChangedWriteDoesNotCarryRowsOutsideServerWindow(t *testing.T) {
	s, db, now := newTestStore(t)
	addDevice(t, s, cbsDevice())
	mustReplace(t, s, "sw-core", ReadMACTable, testBase, false, MACRows{mac(0), mac(1)})
	*now = testBase.Add(SwitchInterval)
	mustReplace(t, s, "sw-core", ReadMACTable, *now, false, MACRows{mac(0)})
	if got := carriedCount(t, db, "sw-core", ReadMACTable); got != 1 {
		t.Fatalf("carried rows = %d, want 1 (mac 1 absent)", got)
	}
	*now = testBase.Add(MACLLDPRetention + time.Hour)
	// Inside the window, but long before the server clock.
	cur := mustReplace(t, s, "sw-core", ReadMACTable, testBase.Add(2*time.Hour), false, MACRows{mac(0), mac(2)})
	if n := expiredCarried(t, db, "sw-core", ReadMACTable, *now); n != 0 {
		t.Fatalf("%d carried rows older than the window", n)
	}
	assertCurrent(t, s, db, "sw-core", ReadMACTable, cur)
}

// Time-spaced history (MAC, LLDP, hit counts) reaches MaxHistoryPerRead
// exactly with writes spaced at MinHistorySpacing over the whole window,
// and nothing of it is trimmed. Extra history beyond the cap (for example
// from a database written by an older version) is trimmed on the next
// write to exactly the cap, oldest first. A cap off by one either way
// fails.
func TestSpacedHistoryReachesAndHoldsCapExactly(t *testing.T) {
	for _, c := range boundCases() {
		if countCapped(c.read) {
			continue // covered by TestReplayingWriterDenseHistoryIsCappedOnWrite
		}
		t.Run(string(c.read), func(t *testing.T) {
			t.Parallel() // each subtest has its own database
			s, db, now := newTestStore(t)
			addDevice(t, s, c.dev)
			dev := c.dev.DeviceID
			ret, sp, capN := HistoryRetention(c.read), MinHistorySpacing(c.read), MaxHistoryPerRead(c.read)
			if ret%sp != 0 {
				t.Fatalf("window %s not a multiple of spacing %s", ret, sp)
			}
			start := now.Add(-ret)
			steps := int(ret / sp) // writes at start .. *now inclusive
			for i := 0; i <= steps; i++ {
				mustReplace(t, s, dev, c.read, start.Add(time.Duration(i)*sp), false, c.rows(i))
			}
			// One more within the future skew supersedes the dataset at *now.
			mustReplace(t, s, dev, c.read, now.Add(time.Minute), false, c.rows(steps+1))
			if got := historyCount(t, db, dev, c.read); got != capN {
				t.Fatalf("history = %d after spaced writes over the window, want exactly the cap %d", got, capN)
			}
			if got := historyTimes(t, db, dev, c.read); got[0] != micros(start) {
				t.Fatalf("oldest kept %d, want %d (nothing trimmed below the cap)", got[0], micros(start))
			}

			// Overfill: extra history between the existing entries.
			const extra = 5
			for i := range extra {
				at := start.Add(time.Duration(10+i)*sp + time.Second)
				if _, err := db.Exec(`INSERT INTO netdev_datasets
					(device_id, read, observed_at, stored_at, state, incomplete, payload_sha256, row_count, current)
					VALUES (?, ?, ?, ?, 'fresh', 0, ?, 0, 0)`,
					dev, string(c.read), micros(at), micros(*now), strings.Repeat("0", 64)); err != nil {
					t.Fatal(err)
				}
			}
			before := historyTimes(t, db, dev, c.read)
			if len(before) != capN+extra {
				t.Fatalf("history = %d after overfill, want %d", len(before), capN+extra)
			}
			// A changed write close to the current one collapses it, so the
			// history gains nothing and must be trimmed to the cap.
			last := mustReplace(t, s, dev, c.read, now.Add(2*time.Minute), false, c.rows(steps+2))
			after := historyTimes(t, db, dev, c.read)
			if len(after) != capN {
				t.Fatalf("history = %d after write, want exactly the cap %d", len(after), capN)
			}
			if !slices.Equal(after, before[extra:]) {
				t.Fatalf("trim kept %d..%d, want %d..%d (oldest trimmed first)",
					after[0], after[len(after)-1], before[extra], before[len(before)-1])
			}
			assertCurrent(t, s, db, dev, c.read, last)
		})
	}
}

// historyTimes returns the observed_at of the superseded datasets of
// (dev, read), oldest first.
func historyTimes(t *testing.T, db *sql.DB, dev string, read Read) []int64 {
	t.Helper()
	rs, err := db.Query(`SELECT observed_at FROM netdev_datasets WHERE device_id = ? AND read = ? AND current = 0
		ORDER BY observed_at, id`, dev, string(read))
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	var out []int64
	for rs.Next() {
		var v int64
		if err := rs.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	if err := rs.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
