// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The carried-row delete that runs on every write (ND-16 part 1, nd16cf2):
// it visits only expired carried rows through the partial seen_at index,
// it keeps a row seen exactly at the cutoff, and on the redelivery path it
// rolls back with the rest of the transaction.

package netdevinventory

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// queryPlan returns the detail lines of EXPLAIN QUERY PLAN for q.
func queryPlan(t *testing.T, db *sql.DB, q string, args ...any) []string {
	t.Helper()
	rs, err := db.Query("EXPLAIN QUERY PLAN "+q, args...)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer rs.Close()
	var out []string
	for rs.Next() {
		var id, parent, notused int
		var detail string
		if err := rs.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		out = append(out, detail)
	}
	if err := rs.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// The DELETE of dropExpiredCarried, per device (every write) and over all
// devices (Prune), searches each row table by a range on its partial
// (dataset_id, seen_at) index: it neither scans the table nor walks every
// row of a dataset through the primary key. Per device, the datasets come
// from an index too.
func TestExpiredCarriedDeleteUsesSeenAtIndex(t *testing.T) {
	_, db, _ := newTestStore(t)
	cutoff := micros(testBase.Add(-time.Hour))
	var seen []string
	for _, rd := range Reads {
		for _, tb := range readTables(rd) {
			for _, byDevice := range []bool{true, false} {
				args := []any{cutoff, string(rd)}
				if byDevice {
					args = append(args, "sw-core")
				}
				plan := queryPlan(t, db, expiredCarriedSQL(tb, byDevice), args...)
				joined := strings.Join(plan, "\n")
				// For example "SEARCH t USING COVERING INDEX idx_t_carried
				// (dataset_id=? AND seen_at>? AND seen_at<?)": equality on
				// the dataset, range on seen_at.
				ranged := slices.ContainsFunc(plan, func(d string) bool {
					return strings.HasPrefix(d, "SEARCH "+tb.name+" USING ") &&
						strings.Contains(d, "INDEX "+carriedIndex(tb)+" (dataset_id=? AND ") &&
						strings.Contains(d, "seen_at<?)")
				})
				if !ranged {
					t.Errorf("%s (by device %v): plan does not range-search %s:\n%s", tb.name, byDevice, carriedIndex(tb), joined)
				}
				if strings.Contains(joined, "SCAN "+tb.name) || strings.Contains(joined, "sqlite_autoindex_"+tb.name) {
					t.Errorf("%s (by device %v): plan walks the row table:\n%s", tb.name, byDevice, joined)
				}
				if byDevice && strings.Contains(joined, "SCAN netdev_datasets") {
					t.Errorf("%s: per-device plan scans netdev_datasets:\n%s", tb.name, joined)
				}
			}
			seen = append(seen, tb.name)
		}
	}
	// Every row table has the index (none is missed by the read list).
	for _, name := range []string{"netdev_facts", "netdev_vlans", "netdev_interfaces", "netdev_mac_entries",
		"netdev_lldp_neighbors", "netdev_fw_rules", "netdev_nat_rules", "netdev_objects", "netdev_rule_hits"} {
		if !slices.Contains(seen, name) {
			t.Errorf("row table %s is written by no read", name)
		}
		var sqlText string
		if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?`,
			"idx_"+name+"_carried").Scan(&sqlText); err != nil {
			t.Errorf("index idx_%s_carried: %v", name, err)
			continue
		}
		if !strings.Contains(sqlText, "(dataset_id, seen_at)") || !strings.Contains(sqlText, "WHERE seen_at IS NOT NULL") {
			t.Errorf("index idx_%s_carried = %q, want (dataset_id, seen_at) WHERE seen_at IS NOT NULL", name, sqlText)
		}
	}
}

// carriedSeenAt returns the distinct seen_at values of the carried rows of
// one dataset of read.
func carriedSeenAt(t *testing.T, db *sql.DB, read Read, datasetID int64) []int64 {
	t.Helper()
	var out []int64
	for _, tb := range readTables(read) {
		rs, err := db.Query(`SELECT DISTINCT seen_at FROM `+tb.name+` WHERE dataset_id = ? AND seen_at IS NOT NULL`, datasetID)
		if err != nil {
			t.Fatal(err)
		}
		for rs.Next() {
			var v int64
			if err := rs.Scan(&v); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(out, v) {
				out = append(out, v)
			}
		}
		if err := rs.Err(); err != nil {
			t.Fatal(err)
		}
		rs.Close()
	}
	return out
}

// writePaths are the three ways ReplaceDataset handles a write: a
// redelivery (same observed_at and payload), an identical payload observed
// later, and a changed payload.
var writePaths = []string{"redelivery", "identical", "changed"}

// writeOnPath writes (dev, read) at the server clock *now along path, with
// cur the current dataset; step makes changed payloads differ.
func writeOnPath(t *testing.T, s *Store, path, dev string, read Read, now time.Time, cur ReplaceResult, curObs time.Time, step int) (ReplaceResult, time.Time) {
	t.Helper()
	switch path {
	case "redelivery":
		res := mustReplace(t, s, dev, read, curObs, false, keyedRows(read, 0))
		if !res.Unchanged || res.DatasetID != cur.DatasetID {
			t.Fatalf("redelivery = %+v, want unchanged %d", res, cur.DatasetID)
		}
		return res, curObs
	case "identical":
		res := mustReplace(t, s, dev, read, now, false, keyedRows(read, 0))
		if !res.Unchanged || res.DatasetID != cur.DatasetID {
			t.Fatalf("identical write = %+v, want unchanged %d", res, cur.DatasetID)
		}
		return res, now
	}
	res := mustReplace(t, s, dev, read, now, false, keyedRows(read, 0, 2+step))
	if res.Unchanged {
		t.Fatalf("changed write = %+v, want a new dataset", res)
	}
	return res, now
}

// A carried row whose seen_at is exactly now minus HistoryRetention is
// still inside the window and kept by every write path; one microsecond
// later it is removed. So the delete is strictly "<" and the cutoff is
// exactly the window: "<=" or a cutoff off by one either way fails.
func TestCarriedRowAtCutoffKeptOneMicrosecondLaterDropped(t *testing.T) {
	for _, c := range boundCases() {
		if keyedRows(c.read, 0) == nil {
			continue // facts never carry
		}
		for _, path := range writePaths {
			t.Run(string(c.read)+"/"+path, func(t *testing.T) {
				t.Parallel() // each subtest has its own database
				s, db, now := newTestStore(t)
				addDevice(t, s, c.dev)
				dev := c.dev.DeviceID
				ret, poll := HistoryRetention(c.read), PollInterval(c.read)

				// d0 {0,1} at testBase; d1 {0} carries row 1 seen at testBase.
				*now = testBase
				mustReplace(t, s, dev, c.read, *now, false, keyedRows(c.read, 0, 1))
				*now = testBase.Add(poll)
				d1 := mustReplace(t, s, dev, c.read, *now, false, keyedRows(c.read, 0))
				if got := carriedSeenAt(t, db, c.read, d1.DatasetID); !slices.Equal(got, []int64{micros(testBase)}) {
					t.Fatalf("carried seen_at of dataset %d = %v, want [%d]; setup is wrong", d1.DatasetID, got, micros(testBase))
				}
				carried := carriedRowsOf(t, db, c.read, d1.DatasetID)

				// Exactly at the cutoff: kept.
				*now = testBase.Add(ret)
				cur, curObs := writeOnPath(t, s, path, dev, c.read, *now, d1, testBase.Add(poll), 0)
				if !slices.Contains(datasetIDs(t, db, c.read), d1.DatasetID) {
					t.Fatalf("dataset %d inside the window was removed", d1.DatasetID)
				}
				if got := carriedRowsOf(t, db, c.read, d1.DatasetID); got != carried {
					t.Fatalf("seen_at == cutoff: carried rows of %d = %d, want %d (kept)", d1.DatasetID, got, carried)
				}

				// One microsecond past it: removed from every kept dataset.
				*now = testBase.Add(ret + time.Microsecond)
				last, _ := writeOnPath(t, s, path, dev, c.read, *now, cur, curObs, 1)
				if !slices.Contains(datasetIDs(t, db, c.read), d1.DatasetID) {
					t.Fatalf("dataset %d inside the window was removed", d1.DatasetID)
				}
				if got := carriedRowsOf(t, db, c.read, d1.DatasetID); got != 0 {
					t.Fatalf("seen_at one microsecond before the cutoff: %d carried rows of %d kept, want 0", got, d1.DatasetID)
				}
				if n := expiredCarried(t, db, dev, c.read, *now); n != 0 {
					t.Fatalf("%d expired carried rows kept", n)
				}
				assertCurrent(t, s, db, dev, c.read, last)
			})
		}
	}
}

// errInjected is returned by the commit hook of the rollback tests.
var errInjected = errors.New("injected commit failure")

// A write that keeps the current dataset (redelivery or identical payload)
// and fails at its commit stage leaves the store as it was: the aged
// datasets and expired carried rows boundUnchanged deleted come back. A
// retry without the fault removes them.
func TestUnchangedWriteBoundRollsBackOnCommitFailure(t *testing.T) {
	for _, c := range boundCases() {
		if keyedRows(c.read, 0) == nil {
			continue // facts never carry
		}
		for _, path := range []string{"redelivery", "identical"} {
			t.Run(string(c.read)+"/"+path, func(t *testing.T) {
				t.Parallel() // each subtest has its own database
				s, db, now := newTestStore(t)
				ctx := context.Background()
				addDevice(t, s, c.dev)
				dev := c.dev.DeviceID
				ret := HistoryRetention(c.read)
				mustReplace(t, s, dev, c.read, testBase, false, keyedRows(c.read, 0, 1))
				at := testBase.Add(ret - time.Hour)
				*now = at
				cur := mustReplace(t, s, dev, c.read, at, false, keyedRows(c.read, 0))

				*now = testBase.Add(ret + time.Minute)
				aged, expired := agedHistory(t, db, dev, c.read, *now), expiredCarried(t, db, dev, c.read, *now)
				if aged == 0 || expired == 0 {
					t.Fatalf("aged = %d, expired carried = %d before the write; setup is wrong", aged, expired)
				}
				before := snapshot(t, s, dev, c.read)
				obs := at
				if path == "identical" {
					obs = *now
				}
				var stages []string
				s.hook = func(stage string) error {
					stages = append(stages, stage)
					if stage == "commit" {
						return errInjected
					}
					return nil
				}
				_, err := s.ReplaceDataset(ctx, dev, c.read, c.dev.TrustGeneration, obs, false, keyedRows(c.read, 0))
				s.hook = nil
				if !errors.Is(err, errInjected) {
					t.Fatalf("err = %v (stages %v), want the injected commit failure", err, stages)
				}
				if got := agedHistory(t, db, dev, c.read, *now); got != aged {
					t.Fatalf("aged datasets = %d after rollback, want %d", got, aged)
				}
				if got := expiredCarried(t, db, dev, c.read, *now); got != expired {
					t.Fatalf("expired carried rows = %d after rollback, want %d", got, expired)
				}
				if after := snapshot(t, s, dev, c.read); after != before {
					t.Fatalf("store changed:\nbefore %+v\nafter  %+v", before, after)
				}

				res := mustReplace(t, s, dev, c.read, obs, false, keyedRows(c.read, 0))
				if !res.Unchanged || res.DatasetID != cur.DatasetID {
					t.Fatalf("retry = %+v, want unchanged %d", res, cur.DatasetID)
				}
				if n := agedHistory(t, db, dev, c.read, *now); n != 0 {
					t.Fatalf("%d aged datasets kept after retry", n)
				}
				if n := expiredCarried(t, db, dev, c.read, *now); n != 0 {
					t.Fatalf("%d expired carried rows kept after retry", n)
				}
			})
		}
	}
}
