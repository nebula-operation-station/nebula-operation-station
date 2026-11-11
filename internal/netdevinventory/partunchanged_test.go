// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

import (
	"database/sql"
	"fmt"
	"testing"
	"time"
)

func policyDatasetCount(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM netdev_datasets WHERE device_id = 'fw-edge'
		AND read = 'firewall_policy'`).Scan(&n); err != nil {
		t.Fatalf("count datasets: %v", err)
	}
	return n
}

// TestUnchangedPolicyPartsStoreNoDataset polls the four policy parts
// interleaved, unchanged, many times: no poll after the first round
// creates a dataset, every one counts as unchanged, all part rows stay
// present in the current dataset, and the dataset stays fresh. A changed
// part then stores exactly one dataset.
func TestUnchangedPolicyPartsStoreNoDataset(t *testing.T) {
	s, db, clock := newTestStore(t)
	addDevice(t, s, panosDevice())
	at := testBase
	step := func() time.Time {
		at = at.Add(15 * time.Minute)
		*clock = at
		return at
	}
	for _, p := range policyParts {
		if res := mustReplace(t, s, "fw-edge", ReadFirewallPolicy, step(), false, partRows(p, "v1")); res.Unchanged {
			t.Fatalf("first read of %s reported unchanged", p)
		}
	}
	base := policyDatasetCount(t, db)
	if base != len(policyParts) {
		t.Fatalf("%d datasets after the first round, want %d", base, len(policyParts))
	}
	const polls = 200
	unchanged := 0
	for i := 0; i < polls; i++ {
		for _, p := range policyParts {
			res := mustReplace(t, s, "fw-edge", ReadFirewallPolicy, step(), false, partRows(p, "v1"))
			if res.Unchanged {
				unchanged++
			}
		}
	}
	if want := polls * len(policyParts); unchanged != want {
		t.Fatalf("%d unchanged results, want %d", unchanged, want)
	}
	if n := policyDatasetCount(t, db); n != base {
		t.Fatalf("%d datasets after unchanged polls, want %d", n, base)
	}
	for _, p := range policyParts {
		k := partKey(p, "v1")
		if !currentHas(t, db, k[0], k[1]) {
			t.Fatalf("part %s row missing from the current dataset", p)
		}
	}
	// The carried rows were refreshed: none expires before its window.
	var oldest int64
	if err := db.QueryRow(`SELECT MIN(seen_at) FROM (
			SELECT seen_at FROM netdev_objects WHERE seen_at IS NOT NULL AND dataset_id = (SELECT id FROM netdev_datasets WHERE current = 1)
			UNION ALL SELECT seen_at FROM netdev_fw_rules WHERE seen_at IS NOT NULL AND dataset_id = (SELECT id FROM netdev_datasets WHERE current = 1)
			UNION ALL SELECT seen_at FROM netdev_nat_rules WHERE seen_at IS NOT NULL AND dataset_id = (SELECT id FROM netdev_datasets WHERE current = 1))`).
		Scan(&oldest); err != nil {
		t.Fatalf("oldest carried row: %v", err)
	}
	if lag := at.Sub(fromMicros(oldest)); lag > time.Hour {
		t.Fatalf("carried part rows last seen %s ago, want refreshed by the unchanged polls", lag)
	}
	if ds := policyState(t, s); ds.State != StateFresh {
		t.Fatalf("state %s, want fresh", ds.State)
	}
	// A real change is one new dataset, and the history keeps it.
	res := mustReplace(t, s, "fw-edge", ReadFirewallPolicy, step(), false, partRows(PolicyObjects, "v2"))
	if res.Unchanged {
		t.Fatal("changed part reported unchanged")
	}
	if n := policyDatasetCount(t, db); n != base+1 {
		t.Fatalf("%d datasets after one change, want %d", n, base+1)
	}
	// Polling the changed part and the others again stores nothing.
	for i := 0; i < 10; i++ {
		for _, p := range policyParts {
			tag := "v1"
			if p == PolicyObjects {
				tag = "v2"
			}
			if r := mustReplace(t, s, "fw-edge", ReadFirewallPolicy, step(), false, partRows(p, tag)); !r.Unchanged {
				t.Fatalf("poll %d part %s: stored a dataset for unchanged content", i, p)
			}
		}
	}
	if n := policyDatasetCount(t, db); n != base+1 {
		t.Fatalf("%d datasets after unchanged polls, want %d", n, base+1)
	}
}

// TestUnchangedPolicyPartRefusesOlderRecord: after an unchanged poll of a
// part, a record of that part older than the poll but newer than its
// stored dataset is refused; it must not roll the part back.
func TestUnchangedPolicyPartRefusesOlderRecord(t *testing.T) {
	s, db, clock := newTestStore(t)
	addDevice(t, s, panosDevice())
	*clock = testBase.Add(time.Hour)
	mustReplace(t, s, "fw-edge", ReadFirewallPolicy, testBase, false, partRows(PolicyNATRules, "a"))
	mustReplace(t, s, "fw-edge", ReadFirewallPolicy, testBase.Add(time.Minute), false, partRows(PolicyZones, "a"))
	if res := mustReplace(t, s, "fw-edge", ReadFirewallPolicy, testBase.Add(3*time.Minute), false,
		partRows(PolicyNATRules, "a")); !res.Unchanged {
		t.Fatalf("unchanged part: %+v", res)
	}
	if _, err := replacePart(s, testBase.Add(2*time.Minute), false, partRows(PolicyNATRules, "b")); err == nil {
		t.Fatal("older record of the part stored after an unchanged poll")
	}
	if k := partKey(PolicyNATRules, "a"); !currentHas(t, db, k[0], k[1]) {
		t.Fatal("part row rolled back")
	}
}

// TestUnchangedPolicyPartWithLostCarriedRowsIsStored: the shortcut only
// applies while the current dataset still holds the part's rows.
func TestUnchangedPolicyPartWithLostCarriedRowsIsStored(t *testing.T) {
	s, db, clock := newTestStore(t)
	addDevice(t, s, panosDevice())
	*clock = testBase.Add(time.Hour)
	mustReplace(t, s, "fw-edge", ReadFirewallPolicy, testBase, false, partRows(PolicyNATRules, "a"))
	mustReplace(t, s, "fw-edge", ReadFirewallPolicy, testBase.Add(time.Minute), false, partRows(PolicyZones, "a"))
	if _, err := db.Exec(`DELETE FROM netdev_nat_rules WHERE dataset_id =
		(SELECT id FROM netdev_datasets WHERE current = 1)`); err != nil {
		t.Fatal(err)
	}
	res := mustReplace(t, s, "fw-edge", ReadFirewallPolicy, testBase.Add(2*time.Minute), false, partRows(PolicyNATRules, "a"))
	if res.Unchanged {
		t.Fatal("part whose rows the current dataset lost reported unchanged")
	}
	if k := partKey(PolicyNATRules, "a"); !currentHas(t, db, k[0], k[1]) {
		t.Fatal(fmt.Sprint("part row missing after the store: ", k))
	}
}
