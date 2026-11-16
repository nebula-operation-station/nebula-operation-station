// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// macEntriesOf returns n distinct MAC entries on VLAN 10 port Gi1/0/1.
func macEntriesOf(n int) MACRows {
	out := make(MACRows, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, netdevcontract.MACEntry{
			VLAN: 10,
			MAC:  fmt.Sprintf("02:00:%02x:%02x:%02x:%02x", i>>24&0xff, i>>16&0xff, i>>8&0xff, i&0xff),
			Port: "Gi1/0/1",
			Type: netdevcontract.MACDynamic,
		})
	}
	return out
}

// TestCurrentTablesReadOneSnapshot pins that a list of current tables is
// one read: a dataset replaced between the dataset query and the row query
// of the same list is neither refused nor shown as an empty table under
// its superseded state (ADR 0010 D3).
func TestCurrentTablesReadOneSnapshot(t *testing.T) {
	cases := []struct {
		name string
		next MACRows // the rows of the dataset that replaces the old one
	}{
		{"replaced by a dataset with rows", MACRows{
			{VLAN: 20, MAC: "02:00:00:00:00:99", Port: "Gi1/0/9", Type: netdevcontract.MACStatic},
		}},
		{"replaced by a dataset without rows", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _, now := newTestStore(t)
			addDevice(t, s, cbsDevice())
			old := macEntriesOf(3)
			mustReplace(t, s, "sw-core", ReadMACTable, testBase, false, old)

			replaced := false
			s.hook = func(stage string) error {
				if stage != hookCurrentBetween || replaced {
					return nil
				}
				replaced = true
				*now = testBase.Add(time.Minute)
				mustReplace(t, s, "sw-core", ReadMACTable, *now, false, tc.next)
				return nil
			}
			t.Cleanup(func() { s.hook = nil })

			got, err := s.CurrentMACTables(context.Background())
			if err != nil {
				t.Fatalf("CurrentMACTables: %v", err)
			}
			if !replaced {
				t.Fatal("the replacement was not made between the two reads")
			}
			if len(got) != 1 {
				t.Fatalf("got %d tables, want 1", len(got))
			}
			if got[0].State != StateFresh {
				t.Errorf("state %s, want the state of the snapshot read (fresh)", got[0].State)
			}
			if len(got[0].Rows) != len(old) {
				t.Fatalf("got %d rows, want the %d rows of the snapshot", len(got[0].Rows), len(old))
			}
			for i := range old {
				if got[0].Rows[i] != old[i] {
					t.Errorf("row %d = %+v, want %+v", i, got[0].Rows[i], old[i])
				}
			}
		})
	}
}

// TestCurrentTableFreshOverLimitIsCutAndPartial pins the cut of a table
// over its limit whose state is fresh: only the first rows up to the limit
// are listed, and the table is marked partial. A complete read cannot
// store more rows than the limit, so the over-limit rows are inserted
// directly into the current dataset here.
func TestCurrentTableFreshOverLimitIsCutAndPartial(t *testing.T) {
	limit := netdevcontract.MaxMACEntriesPerDevice
	s, db, now := newTestStore(t)
	addDevice(t, s, cbsDevice())
	mustReplace(t, s, "sw-core", ReadMACTable, testBase, false, macEntriesOf(limit))

	var id int64
	if err := db.QueryRow(`SELECT id FROM netdev_datasets WHERE device_id = ? AND read = ? AND current = 1`,
		"sw-core", string(ReadMACTable)).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO netdev_mac_entries (dataset_id, row_key, seq, seen_at, absent, vlan, mac, port, type)
		VALUES (?, 'zz-over-limit', 0, NULL, 0, 10, '02:ff:ff:ff:ff:ff', 'Gi1/0/1', 'dynamic')`, id); err != nil {
		t.Fatal(err)
	}

	t.Run("fresh table is cut and partial", func(t *testing.T) {
		got, err := s.CurrentMACTables(context.Background())
		if err != nil {
			t.Fatalf("CurrentMACTables: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %d tables, want 1", len(got))
		}
		if len(got[0].Rows) != limit {
			t.Errorf("%d rows, want the cut at the limit %d", len(got[0].Rows), limit)
		}
		for _, r := range got[0].Rows {
			if r.MAC == "02:ff:ff:ff:ff:ff" {
				t.Fatal("the row beyond the limit was listed")
			}
		}
		if got[0].State != StatePartial {
			t.Errorf("state %s, want partial", got[0].State)
		}
	})

	t.Run("stale table keeps its stale state", func(t *testing.T) {
		*now = testBase.Add(StaleAfterIntervals*SwitchInterval + time.Minute)
		got, err := s.CurrentMACTables(context.Background())
		if err != nil {
			t.Fatalf("CurrentMACTables: %v", err)
		}
		if len(got) != 1 || len(got[0].Rows) != limit {
			t.Fatalf("got %d tables, %d rows; want 1 table cut at %d", len(got), len(got[0].Rows), limit)
		}
		if got[0].State != StateStale {
			t.Errorf("state %s, want stale", got[0].State)
		}
		*now = testBase
	})
}
