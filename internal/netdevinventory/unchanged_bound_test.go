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

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
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
			mustReplace(t, s, dev, c.read, testBase, false, carryRows(c, 0))
			*now = testBase.Add(poll)
			cur := mustReplace(t, s, dev, c.read, *now, false, carryRows(c, 1))
			if got := historyCount(t, db, dev, c.read); got != 1 {
				t.Fatalf("history = %d after one change, want 1", got)
			}
			carried := carriedCount(t, db, dev, c.read)
			assertCarries(t, c.read, carried)

			// Identical payloads inside the window keep the history.
			*now = testBase.Add(2 * poll)
			if res := mustReplace(t, s, dev, c.read, *now, false, carryRows(c, 1)); !res.Unchanged || res.DatasetID != cur.DatasetID {
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
				res := mustReplace(t, s, dev, c.read, *now, false, carryRows(c, 1))
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

// The same dataset delivered again does not rewrite the dataset, but the
// window still holds for the history behind it.
func TestRedeliveredDatasetDropsAgedHistory(t *testing.T) {
	for _, c := range boundCases() {
		t.Run(string(c.read), func(t *testing.T) {
			s, db, now := newTestStore(t)
			addDevice(t, s, c.dev)
			dev := c.dev.DeviceID
			ret := HistoryRetention(c.read)
			mustReplace(t, s, dev, c.read, testBase, false, carryRows(c, 0))
			at := testBase.Add(ret - time.Hour)
			*now = at
			cur := mustReplace(t, s, dev, c.read, at, false, carryRows(c, 1))
			assertCarries(t, c.read, carriedCount(t, db, dev, c.read))

			*now = testBase.Add(ret + time.Minute)
			res := mustReplace(t, s, dev, c.read, at, false, carryRows(c, 1))
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

// keyedRows returns rows of read with one row per key, so payloads can
// differ in which rows they contain and rows missing from a later read are
// carried. Facts are a single row with a fixed key and can never carry;
// keyedRows returns nil for them.
func keyedRows(read Read, keys ...int) Rows {
	name := func(k int) string { return "rule-" + string(rune('a'+k)) }
	switch read {
	case ReadMACTable:
		var r MACRows
		for _, k := range keys {
			r = append(r, mac(byte(k)))
		}
		return r
	case ReadLLDPNeighbors:
		var r LLDPRows
		for _, k := range keys {
			r = append(r, netdevcontract.LLDPNeighbor{LocalPort: "gi1/0/1", ChassisID: "c", PortID: string(rune('a' + k))})
		}
		return r
	case ReadVLANs:
		var r VLANRows
		for _, k := range keys {
			r = append(r, netdevcontract.VLAN{ID: uint16(k + 1)})
		}
		return r
	case ReadFirewallPolicy:
		var names []string
		for _, k := range keys {
			names = append(names, name(k))
		}
		return policy(names...)
	case ReadHitCounts:
		var r HitCountRows
		for _, k := range keys {
			r = append(r, netdevcontract.HitCount{RuleName: name(k), Hits: 1, LastHit: &testBase})
		}
		return r
	}
	return nil
}

// carryRows returns payload i of a two-step sequence whose second step
// drops a row of the first, so the change carries it. Facts cannot carry
// and fall back to c.rows.
func carryRows(c boundCase, i int) Rows {
	keys := []int{0, 1}
	if i > 0 {
		keys = []int{0}
	}
	if r := keyedRows(c.read, keys...); r != nil {
		return r
	}
	return c.rows(i)
}

// assertCarries fails unless a read that can carry rows did carry some, so
// the carried-row delete is really exercised. Facts are one row with a
// fixed key and never carry.
func assertCarries(t *testing.T, read Read, carried int) {
	t.Helper()
	if read == ReadFacts {
		if carried != 0 {
			t.Fatalf("facts carried %d rows, want 0 (single fixed-key row)", carried)
		}
		return
	}
	if carried == 0 {
		t.Fatalf("%s carried no rows before the window passed; the carried-row delete is not exercised", read)
	}
}

// A superseded dataset that is still kept (observed inside the window) can
// hold carried rows whose seen_at already left it. An identical write and
// a changed write must both remove those rows from every kept dataset of
// the (device, read), not only from the current one, without Prune.
func TestKeptSupersededDatasetLosesExpiredCarriedRows(t *testing.T) {
	for _, c := range boundCases() {
		if keyedRows(c.read, 0) == nil {
			continue // facts never carry
		}
		for _, changed := range []bool{false, true} {
			name := string(c.read) + "/identical"
			if changed {
				name = string(c.read) + "/changed"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel() // each subtest has its own database
				s, db, now := newTestStore(t)
				addDevice(t, s, c.dev)
				dev := c.dev.DeviceID
				ret, poll := HistoryRetention(c.read), PollInterval(c.read)

				// d0 {0,1}; d1 {0} carries 1 (seen at testBase); d2 {0,2}
				// carries 1 again. d1 stays history inside the window.
				*now = testBase
				mustReplace(t, s, dev, c.read, *now, false, keyedRows(c.read, 0, 1))
				*now = testBase.Add(poll)
				d1 := mustReplace(t, s, dev, c.read, *now, false, keyedRows(c.read, 0))
				*now = testBase.Add(ret - poll)
				d2 := mustReplace(t, s, dev, c.read, *now, false, keyedRows(c.read, 0, 2))
				if n := carriedRowsOf(t, db, c.read, d1.DatasetID); n == 0 {
					t.Fatalf("superseded dataset %d carries no rows; setup is wrong", d1.DatasetID)
				}
				if n := carriedRowsOf(t, db, c.read, d2.DatasetID); n == 0 {
					t.Fatalf("current dataset %d carries no rows; setup is wrong", d2.DatasetID)
				}

				// Past testBase + ret the row last seen at testBase has left
				// the window; d1 (observed testBase + poll) has not.
				*now = testBase.Add(ret + poll/2)
				if n := expiredCarried(t, db, dev, c.read, *now); n == 0 {
					t.Fatal("no expired carried rows before the write; setup is wrong")
				}
				var res ReplaceResult
				if changed {
					res = mustReplace(t, s, dev, c.read, *now, false, keyedRows(c.read, 0, 3))
					if res.Unchanged || res.DatasetID == d2.DatasetID {
						t.Fatalf("changed write = %+v, want a new dataset", res)
					}
				} else {
					res = mustReplace(t, s, dev, c.read, *now, false, keyedRows(c.read, 0, 2))
					if !res.Unchanged || res.DatasetID != d2.DatasetID {
						t.Fatalf("identical write = %+v, want unchanged %d", res, d2.DatasetID)
					}
				}
				if !slices.Contains(datasetIDs(t, db, c.read), d1.DatasetID) {
					t.Fatalf("superseded dataset %d inside the window was removed", d1.DatasetID)
				}
				if n := expiredCarried(t, db, dev, c.read, *now); n != 0 {
					t.Fatalf("%d expired carried rows kept in kept datasets", n)
				}
				if n := len(rowsOf(t, db, readTables(c.read)[0].name, d1.DatasetID)); n == 0 {
					t.Fatalf("kept dataset %d lost its present rows", d1.DatasetID)
				}
				assertCurrent(t, s, db, dev, c.read, res)
			})
		}
	}
}

// carriedRowsOf counts the carried rows of one dataset of read.
func carriedRowsOf(t *testing.T, db *sql.DB, read Read, datasetID int64) int {
	t.Helper()
	n := 0
	for _, tb := range readTables(read) {
		n += countRows(t, db, `SELECT count(*) FROM `+tb.name+` WHERE dataset_id = ? AND seen_at IS NOT NULL`, datasetID)
	}
	return n
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
			steps := int(ret / sp) // datasets at start .. *now inclusive
			// Seed the older part of the window as history in one
			// transaction (thousands of single writes are too slow under
			// -race), spaced at exactly MinHistorySpacing; the newest
			// written steps go through ReplaceDataset, so the write path
			// itself reaches the cap.
			const written = 50
			seedHistory(t, db, dev, c.read, start, sp, steps-written+1, *now)
			for i := steps - written + 1; i <= steps; i++ {
				mustReplace(t, s, dev, c.read, start.Add(time.Duration(i)*sp), false, c.rows(i))
				if got := historyCount(t, db, dev, c.read); got > capN {
					t.Fatalf("after write %d: history = %d > cap %d", i, got, capN)
				}
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

// seedHistory inserts n superseded datasets of (dev, read) observed at
// start, start+sp, ... in one transaction.
func seedHistory(t *testing.T, db *sql.DB, dev string, read Read, start time.Time, sp time.Duration, n int, now time.Time) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	for i := range n {
		if _, err := tx.Exec(`INSERT INTO netdev_datasets
			(device_id, read, observed_at, stored_at, state, incomplete, payload_sha256, row_count, current)
			VALUES (?, ?, ?, ?, 'fresh', 0, ?, 0, 0)`,
			dev, string(read), micros(start.Add(time.Duration(i)*sp)), micros(now), strings.Repeat("0", 64)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
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
