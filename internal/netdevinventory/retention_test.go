// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Retention tests (ND-16, ADR 0010 Q11): window boundaries per read, the
// newest dataset is never pruned, count caps and config version
// protection.

package netdevinventory

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

func datasetIDs(t *testing.T, db *sql.DB, read Read) []int64 {
	t.Helper()
	rs, err := db.Query(`SELECT id FROM netdev_datasets WHERE read = ? ORDER BY id`, string(read))
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	var out []int64
	for rs.Next() {
		var id int64
		if err := rs.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	return out
}

func TestPruneHistoryWindowBoundaries(t *testing.T) {
	cases := []struct {
		read   Read
		dev    netdevcontract.Device
		window time.Duration
		rows   func(i int) Rows
	}{
		{ReadMACTable, cbsDevice(), 21 * 24 * time.Hour, func(i int) Rows { return MACRows{mac(byte(i))} }},
		{ReadLLDPNeighbors, cbsDevice(), 21 * 24 * time.Hour, func(i int) Rows {
			return LLDPRows{{LocalPort: "gi1/0/1", ChassisID: "c", PortID: string(rune('a' + i))}}
		}},
		{ReadHitCounts, panosDevice(), 90 * 24 * time.Hour, func(i int) Rows {
			return HitCountRows{{RuleName: "rule-" + string(rune('a'+i)), Hits: uint64(i + 1), LastHit: &testBase}}
		}},
		{ReadVLANs, cbsDevice(), 400 * 24 * time.Hour, func(i int) Rows { return VLANRows{{ID: uint16(i + 1)}} }},
		{ReadFirewallPolicy, panosDevice(), 400 * 24 * time.Hour, func(i int) Rows {
			return policy(string(rune('a'+i)) + "-rule")
		}},
	}
	for _, c := range cases {
		t.Run(string(c.read), func(t *testing.T) {
			if HistoryRetention(c.read) != c.window {
				t.Fatalf("HistoryRetention = %v, want %v", HistoryRetention(c.read), c.window)
			}
			s, db, now := newTestStore(t)
			addDevice(t, s, c.dev)
			ctx := context.Background()
			t0 := testBase.Add(-time.Hour)
			old := mustReplace(t, s, c.dev.DeviceID, c.read, t0, false, c.rows(0))
			cur := mustReplace(t, s, c.dev.DeviceID, c.read, testBase, false, c.rows(1))

			// Exactly at the window edge the superseded dataset is kept.
			*now = t0.Add(c.window)
			rep, err := s.Prune(ctx)
			if err != nil {
				t.Fatalf("Prune: %v", err)
			}
			if rep.Datasets != 0 {
				t.Fatalf("pruned at boundary: %+v", rep)
			}
			// One microsecond later it is pruned with its rows.
			*now = t0.Add(c.window + time.Microsecond)
			rep, err = s.Prune(ctx)
			if err != nil {
				t.Fatalf("Prune: %v", err)
			}
			if rep.Datasets != 1 {
				t.Fatalf("report = %+v, want one dataset", rep)
			}
			if ids := datasetIDs(t, db, c.read); len(ids) != 1 || ids[0] != cur.DatasetID {
				t.Fatalf("datasets = %v, want [%d]", ids, cur.DatasetID)
			}
			for _, tbl := range readTables(c.read) {
				if n := countRows(t, db, `SELECT count(*) FROM `+tbl.name+` WHERE dataset_id = ?`, old.DatasetID); n != 0 {
					t.Fatalf("%s keeps %d rows of a pruned dataset", tbl.name, n)
				}
			}
			// The carried row last seen at t0 is now past the window and goes;
			// the row the current read contained stays.
			if rep.CarriedRows == 0 {
				t.Fatalf("carried rows not pruned: %+v", rep)
			}
			for _, tbl := range readTables(c.read) {
				if n := countRows(t, db, `SELECT count(*) FROM `+tbl.name+` WHERE dataset_id = ? AND seen_at IS NOT NULL`, cur.DatasetID); n != 0 {
					t.Fatalf("%s keeps %d expired carried rows", tbl.name, n)
				}
			}

			// The newest dataset survives any age.
			*now = testBase.Add(10 * 365 * 24 * time.Hour)
			if _, err := s.Prune(ctx); err != nil {
				t.Fatal(err)
			}
			if ids := datasetIDs(t, db, c.read); len(ids) != 1 || ids[0] != cur.DatasetID {
				t.Fatalf("newest dataset pruned: %v", ids)
			}
			if n := countRows(t, db, `SELECT count(*) FROM netdev_datasets d WHERE d.id = ? AND d.row_count > 0`, cur.DatasetID); n != 1 {
				t.Fatalf("newest dataset lost")
			}
		})
	}
}

func TestAbsentRowsNotCarriedPastWindow(t *testing.T) {
	s, db, now := newTestStore(t)
	addDevice(t, s, cbsDevice())
	t0 := testBase.Add(-time.Hour)
	mustReplace(t, s, "sw-core", ReadMACTable, t0, false, MACRows{mac(1), mac(2)})
	mustReplace(t, s, "sw-core", ReadMACTable, t0.Add(15*time.Minute), false, MACRows{mac(1)})

	// Exactly 21 days after mac 2 was last seen it is still carried.
	*now = t0.Add(MACLLDPRetention)
	edge := mustReplace(t, s, "sw-core", ReadMACTable, *now, false, MACRows{mac(1), mac(3)})
	if edge.Carried != 1 {
		t.Fatalf("carried at edge = %d, want 1", edge.Carried)
	}
	*now = t0.Add(MACLLDPRetention + time.Microsecond)
	past := mustReplace(t, s, "sw-core", ReadMACTable, *now, false, MACRows{mac(1)})
	got := rowsOf(t, db, "netdev_mac_entries", past.DatasetID)
	if len(got) != 2 || got[0].key != "10/aa:bb:cc:dd:ee:01" || got[1].key != "10/aa:bb:cc:dd:ee:03" || !got[1].absent {
		t.Fatalf("rows = %+v", got)
	}
}

// A replaying or buggy writer that delivers changed datasets far more
// often than the poll interval must not grow MAC, LLDP or hit-count
// history beyond window/MinHistorySpacing datasets: too dense datasets
// collapse into their successor, whose carried rows keep what they saw.
func TestDenseDatasetsCollapseHistory(t *testing.T) {
	cases := []struct {
		read Read
		dev  netdevcontract.Device
		rows func(i int) Rows
	}{
		{ReadMACTable, cbsDevice(), func(i int) Rows { return MACRows{mac(byte(i % 10))} }},
		{ReadLLDPNeighbors, cbsDevice(), func(i int) Rows {
			return LLDPRows{{LocalPort: "gi1/0/1", ChassisID: "c", PortID: string(rune('a' + i%10))}}
		}},
		{ReadHitCounts, panosDevice(), func(i int) Rows {
			return HitCountRows{{RuleName: "rule-" + string(rune('a'+i%10)), Hits: uint64(i + 1), LastHit: &testBase}}
		}},
	}
	for _, c := range cases {
		t.Run(string(c.read), func(t *testing.T) {
			spacing := MinHistorySpacing(c.read)
			if spacing <= 0 || spacing > PollInterval(c.read) {
				t.Fatalf("MinHistorySpacing = %v", spacing)
			}
			s, db, _ := newTestStore(t)
			addDevice(t, s, c.dev)
			// Replay: a changed dataset five times per MinHistorySpacing.
			const n = 60
			step := spacing / 5
			total := time.Duration(n) * step
			start := testBase.Add(-total)
			var last ReplaceResult
			for i := 0; i < n; i++ {
				last = mustReplace(t, s, c.dev.DeviceID, c.read, start.Add(time.Duration(i)*step), false, c.rows(i))
			}
			got := countRows(t, db, `SELECT count(*) FROM netdev_datasets WHERE read = ?`, string(c.read))
			bound := int(total/spacing) + 2 // history within the span plus the current dataset
			if got > bound {
				t.Fatalf("datasets = %d after %d dense writes, bound %d", got, n, bound)
			}
			if got < 2 {
				t.Fatalf("datasets = %d: history spaced by %v must be kept", got, spacing)
			}
			// Superseded datasets are spaced at least MinHistorySpacing apart.
			rs, err := db.Query(`SELECT observed_at FROM netdev_datasets WHERE read = ? AND current = 0
				ORDER BY observed_at`, string(c.read))
			if err != nil {
				t.Fatal(err)
			}
			var obs []int64
			for rs.Next() {
				var o int64
				if err := rs.Scan(&o); err != nil {
					t.Fatal(err)
				}
				obs = append(obs, o)
			}
			rs.Close()
			for i := 1; i < len(obs); i++ {
				if gap := obs[i] - obs[i-1]; gap < spacing.Microseconds() {
					t.Fatalf("history gap %dµs < %v", gap, spacing)
				}
			}
			// Rows of collapsed datasets are not lost: the current dataset
			// carries all ten keys.
			if got := len(rowsOf(t, db, readTables(c.read)[0].name, last.DatasetID)); got != 10 {
				t.Fatalf("current dataset has %d rows, want 10 (present plus carried)", got)
			}
		})
	}
}

func TestCarryOverIsCapped(t *testing.T) {
	s, db, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	saved := tblVLANs.carryCap
	tblVLANs.carryCap = 2
	t.Cleanup(func() { tblVLANs.carryCap = saved })

	mustReplace(t, s, "sw-core", ReadVLANs, testBase.Add(-3*time.Minute), false, VLANRows{{ID: 1}})
	mustReplace(t, s, "sw-core", ReadVLANs, testBase.Add(-2*time.Minute), false, VLANRows{{ID: 2}, {ID: 3}})
	res := mustReplace(t, s, "sw-core", ReadVLANs, testBase, false, VLANRows{{ID: 4}})
	got := rowsOf(t, db, "netdev_vlans", res.DatasetID)
	// The two most recently seen rows (2 and 3) are carried, not 1.
	if res.Carried != 2 || len(got) != 3 || got[0].key != "2" || got[1].key != "3" || got[2].key != "4" {
		t.Fatalf("carried = %d rows = %+v", res.Carried, got)
	}
}

func TestPruneCapsSnapshotCount(t *testing.T) {
	s, db, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	ctx := context.Background()
	// Superseded VLAN datasets within the window, inserted directly.
	const extra = 3
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := range MaxSnapshotsPerRead + extra {
		at := testBase.Add(-time.Duration(MaxSnapshotsPerRead+extra-i) * time.Minute)
		if _, err := tx.Exec(`INSERT INTO netdev_datasets (device_id, read, observed_at, stored_at, state, incomplete,
			payload_sha256, row_count, current) VALUES ('sw-core', 'vlans', ?, ?, 'fresh', 0, ?, 0, 0)`,
			micros(at), micros(at), strings.Repeat("0", 64)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	cur := mustReplace(t, s, "sw-core", ReadVLANs, testBase, false, VLANRows{{ID: 1}})
	var oldestKept int64
	rep, err := s.Prune(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Datasets != extra {
		t.Fatalf("report = %+v, want %d datasets", rep, extra)
	}
	if n := countRows(t, db, `SELECT count(*) FROM netdev_datasets WHERE current = 0`); n != MaxSnapshotsPerRead {
		t.Fatalf("superseded = %d, want %d", n, MaxSnapshotsPerRead)
	}
	if err := db.QueryRow(`SELECT min(observed_at) FROM netdev_datasets`).Scan(&oldestKept); err != nil {
		t.Fatal(err)
	}
	if want := micros(testBase.Add(-time.Duration(MaxSnapshotsPerRead) * time.Minute)); oldestKept != want {
		t.Fatalf("oldest kept %d, want %d (oldest pruned first)", oldestKept, want)
	}
	if d, _ := s.GetDataset(ctx, "sw-core", ReadVLANs); d.ID != cur.DatasetID {
		t.Fatalf("current dataset lost")
	}
}

func insertConfigVersion(t *testing.T, db *sql.DB, dev, config string, n int, lastSeen time.Time, baseline bool, changeBound *time.Time) int64 {
	t.Helper()
	digest := strings.Repeat("0", 60) + string("0123456789abcdef"[n%16]) + string("0123456789abcdef"[(n/16)%16]) +
		string("0123456789abcdef"[(n/256)%16]) + string("0123456789abcdef"[(n/4096)%16])
	var cb any
	if changeBound != nil {
		cb = micros(*changeBound)
	}
	res, err := db.Exec(`INSERT INTO netdev_config_versions (device_id, config, raw_digest, redacted_digest,
		redacted_text, first_seen, last_seen, baseline, change_bound_at) VALUES (?, ?, ?, ?, 'hostname x', ?, ?, ?, ?)`,
		dev, config, digest, digest, micros(lastSeen), micros(lastSeen), boolInt(baseline), cb)
	if err != nil {
		t.Fatalf("insert config version: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

func configIDs(t *testing.T, db *sql.DB) map[int64]bool {
	t.Helper()
	rs, err := db.Query(`SELECT id FROM netdev_config_versions`)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	out := map[int64]bool{}
	for rs.Next() {
		var id int64
		if err := rs.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out[id] = true
	}
	return out
}

func TestPruneConfigVersionsAge(t *testing.T) {
	s, db, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	edge := testBase.Add(-ConfigVersionRetention)
	past := edge.Add(-time.Microsecond)
	recentChange := testBase.Add(-24 * time.Hour)
	oldChange := past

	aged := insertConfigVersion(t, db, "sw-core", "running", 1, past, false, nil)
	atEdge := insertConfigVersion(t, db, "sw-core", "running", 2, edge, false, nil)
	baseline := insertConfigVersion(t, db, "sw-core", "running", 3, past.Add(-time.Hour), true, nil)
	bound := insertConfigVersion(t, db, "sw-core", "running", 4, past, false, &recentChange)
	boundOld := insertConfigVersion(t, db, "sw-core", "running", 5, past, false, &oldChange)
	newest := insertConfigVersion(t, db, "sw-core", "running", 6, edge.Add(time.Hour), false, nil)
	// The only (thus newest) startup version is kept however old it is.
	onlyStartup := insertConfigVersion(t, db, "sw-core", "startup", 7, past.Add(-100*24*time.Hour), false, nil)

	rep, err := s.Prune(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.ConfigVersions != 2 {
		t.Fatalf("report = %+v, want 2 config versions", rep)
	}
	ids := configIDs(t, db)
	for id, want := range map[int64]bool{aged: false, atEdge: true, baseline: true, bound: true, boundOld: false, newest: true, onlyStartup: true} {
		if ids[id] != want {
			t.Errorf("version %d kept = %v, want %v", id, ids[id], want)
		}
	}
}

func TestPruneConfigVersionsCount(t *testing.T) {
	s, db, _ := newTestStore(t)
	addDevice(t, s, cbsDevice())
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	const total = MaxConfigVersionsPerDevice + 5
	var first []int64
	for i := range total {
		at := testBase.Add(-time.Duration(total-i) * time.Hour)
		digest := strings.Repeat("0", 56) + string("0123456789abcdef"[i%16]) + string("0123456789abcdef"[(i/16)%16]) +
			string("0123456789abcdef"[(i/256)%16]) + "00000"
		res, err := tx.Exec(`INSERT INTO netdev_config_versions (device_id, config, raw_digest, redacted_digest,
			redacted_text, first_seen, last_seen, baseline) VALUES ('sw-core', 'running', ?, ?, 'x', ?, ?, ?)`,
			digest, digest, micros(at), micros(at), boolInt(i == 0))
		if err != nil {
			t.Fatal(err)
		}
		if i < 7 {
			id, _ := res.LastInsertId()
			first = append(first, id)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	rep, err := s.Prune(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Five over the limit: the oldest unprotected ones go; the baseline
	// (the oldest of all) stays.
	if rep.ConfigVersions != 5 {
		t.Fatalf("report = %+v, want 5", rep)
	}
	ids := configIDs(t, db)
	want := []bool{true, false, false, false, false, false, true}
	for i, id := range first {
		if ids[id] != want[i] {
			t.Errorf("version #%d kept = %v, want %v", i, ids[id], want[i])
		}
	}
	if len(ids) != MaxConfigVersionsPerDevice {
		t.Fatalf("kept %d, want %d", len(ids), MaxConfigVersionsPerDevice)
	}
}
