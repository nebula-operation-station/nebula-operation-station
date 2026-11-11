// SPDX-License-Identifier: AGPL-3.0-or-later

package netdevinventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// partRows returns a read of part with one row named after tag, or no row
// for an empty tag.
func partRows(part PolicyPart, tag string) PolicyPartRows {
	var p netdevcontract.FirewallPolicy
	if tag != "" {
		switch part {
		case PolicyZones:
			p.Zones = []netdevcontract.Zone{{Name: "z-" + tag}}
		case PolicyObjects:
			p.Addresses = []netdevcontract.AddressObject{{Name: "a-" + tag, Type: netdevcontract.AddressNetmask,
				Value: "10.0.0.1/32"}}
		case PolicySecurityRules:
			p.SecurityRules = []netdevcontract.SecurityRule{{Name: "r-" + tag, Action: netdevcontract.ActionAllow}}
		case PolicyNATRules:
			p.NATRules = []netdevcontract.NATRule{{Name: "n-" + tag}}
		}
	}
	return PolicyPartRows{Part: part, Policy: p}
}

func permutations(parts []PolicyPart) [][]PolicyPart {
	if len(parts) <= 1 {
		return [][]PolicyPart{append([]PolicyPart(nil), parts...)}
	}
	var out [][]PolicyPart
	for i := range parts {
		rest := append(append([]PolicyPart(nil), parts[:i]...), parts[i+1:]...)
		for _, p := range permutations(rest) {
			out = append(out, append([]PolicyPart{parts[i]}, p...))
		}
	}
	return out
}

func policyState(t *testing.T, s *Store) Dataset {
	t.Helper()
	ds, err := s.GetDataset(context.Background(), "fw-edge", ReadFirewallPolicy)
	if err != nil {
		t.Fatalf("GetDataset: %v", err)
	}
	return ds
}

// TestIncompletePolicyPartKeepsDatasetPartial stores the four parts in
// every order, one of them incomplete: the dataset stays partial whichever
// part is stored last, and turns fresh only once that part is read
// complete again.
func TestIncompletePolicyPartKeepsDatasetPartial(t *testing.T) {
	for _, bad := range policyParts {
		t.Run(string(bad), func(t *testing.T) {
			t.Parallel()
			s, _, clock := newTestStore(t)
			addDevice(t, s, panosDevice())
			at := testBase
			step := func() time.Time {
				at = at.Add(time.Minute)
				*clock = at
				return at
			}
			for i, order := range permutations(policyParts) {
				for _, p := range order {
					mustReplace(t, s, "fw-edge", ReadFirewallPolicy, step(), p == bad, partRows(p, fmt.Sprint(i)))
				}
				if ds := policyState(t, s); ds.State != StatePartial || !ds.Incomplete {
					t.Fatalf("order %v: state %s incomplete %v, want partial", order, ds.State, ds.Incomplete)
				}
				// Another complete part does not clear it.
				other := order[0]
				if other == bad {
					other = order[1]
				}
				mustReplace(t, s, "fw-edge", ReadFirewallPolicy, step(), false, partRows(other, fmt.Sprint(i, "x")))
				if ds := policyState(t, s); ds.State != StatePartial {
					t.Fatalf("order %v: state %s after complete %s, want partial", order, ds.State, other)
				}
				mustReplace(t, s, "fw-edge", ReadFirewallPolicy, step(), false, partRows(bad, fmt.Sprint(i, "y")))
				if ds := policyState(t, s); ds.State != StateFresh || ds.Incomplete {
					t.Fatalf("order %v: state %s incomplete %v after complete %s, want fresh", order, ds.State,
						ds.Incomplete, bad)
				}
			}
		})
	}
}

// TestEmptyIncompletePolicyPartIsTracked covers a part read without rows,
// whose part only its payload hash names.
func TestEmptyIncompletePolicyPartIsTracked(t *testing.T) {
	s, _, _ := newTestStore(t)
	addDevice(t, s, panosDevice())
	mustReplace(t, s, "fw-edge", ReadFirewallPolicy, testBase, true, partRows(PolicyNATRules, ""))
	mustReplace(t, s, "fw-edge", ReadFirewallPolicy, testBase.Add(time.Minute), false, partRows(PolicyZones, "a"))
	if ds := policyState(t, s); ds.State != StatePartial {
		t.Fatalf("state %s, want partial", ds.State)
	}
	mustReplace(t, s, "fw-edge", ReadFirewallPolicy, testBase.Add(2*time.Minute), false, partRows(PolicyNATRules, ""))
	if ds := policyState(t, s); ds.State != StateFresh {
		t.Fatalf("state %s, want fresh", ds.State)
	}
}

func replacePart(s *Store, at time.Time, incomplete bool, rows PolicyPartRows) (ReplaceResult, error) {
	return s.ReplaceDataset(context.Background(), "fw-edge", ReadFirewallPolicy, 1, at, incomplete, rows)
}

func currentHas(t *testing.T, db *sql.DB, tbl, key string) bool {
	t.Helper()
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM `+tbl+` WHERE row_key = ? AND absent = 0 AND dataset_id =
		(SELECT id FROM netdev_datasets WHERE device_id = 'fw-edge' AND read = 'firewall_policy' AND current = 1)`,
		key).Scan(&n)
	if err != nil {
		t.Fatalf("query %s: %v", tbl, err)
	}
	return n == 1
}

// TestPolicyPartsAreOrderedPerPart: a part record older than another
// part's stored dataset, but newer than any read of its own part (a read
// that failed transiently, or a clock step), is stored; only a dataset of
// the same part that is at least as new refuses it.
func TestPolicyPartsAreOrderedPerPart(t *testing.T) {
	for _, late := range policyParts {
		t.Run(string(late), func(t *testing.T) {
			s, db, _ := newTestStore(t)
			addDevice(t, s, panosDevice())
			other := PolicyZones
			if late == PolicyZones {
				other = PolicyNATRules
			}
			if _, err := replacePart(s, testBase, false, partRows(late, "old")); err != nil {
				t.Fatal(err)
			}
			if _, err := replacePart(s, testBase.Add(3*time.Minute), false, partRows(other, "new")); err != nil {
				t.Fatal(err)
			}
			// Older than the other part, newer than its own: stored.
			res, err := replacePart(s, testBase.Add(time.Minute), false, partRows(late, "mid"))
			if err != nil || res.Unchanged {
				t.Fatalf("late part: %+v, %v; want stored", res, err)
			}
			ds := policyState(t, s)
			if ds.ID != res.DatasetID || ds.State != StateFresh {
				t.Fatalf("current dataset %d state %s, want %d fresh", ds.ID, ds.State, res.DatasetID)
			}
			// The redelivered record stores nothing.
			if again, err := replacePart(s, testBase.Add(time.Minute), false, partRows(late, "mid")); err != nil ||
				!again.Unchanged {
				t.Fatalf("redelivery: %+v, %v; want unchanged", again, err)
			}
			// Older than its own part's newest read, or as old with other
			// content: refused.
			for _, c := range []struct {
				at  time.Time
				tag string
			}{{testBase, "older"}, {testBase.Add(time.Minute), "other"}} {
				if _, err := replacePart(s, c.at, false, partRows(late, c.tag)); !errors.Is(err, ErrOutOfOrder) {
					t.Fatalf("%s: err = %v, want ErrOutOfOrder", c.tag, err)
				}
			}
			// The other part keeps its own order too.
			if _, err := replacePart(s, testBase.Add(2*time.Minute), false, partRows(other, "older")); !errors.Is(err, ErrOutOfOrder) {
				t.Fatalf("other part: err = %v, want ErrOutOfOrder", err)
			}
			// The late part's rows replaced the old ones; the other part's
			// rows are carried.
			tbl := partKey(late, "mid")
			if !currentHas(t, db, tbl[0], tbl[1]) {
				t.Fatalf("late part row %v missing from the current dataset", tbl)
			}
			if old := partKey(late, "old"); currentHas(t, db, old[0], old[1]) {
				t.Fatalf("old part row %v still present", old)
			}
			if o := partKey(other, "new"); !currentHas(t, db, o[0], o[1]) {
				t.Fatalf("other part row %v not carried", o)
			}
		})
	}
}

// partKey returns the row table and row key of partRows(part, tag).
func partKey(part PolicyPart, tag string) [2]string {
	switch part {
	case PolicyZones:
		return [2]string{"netdev_objects", jsonKey("zone", "z-"+tag)}
	case PolicyObjects:
		return [2]string{"netdev_objects", jsonKey("address", "a-"+tag)}
	case PolicySecurityRules:
		return [2]string{"netdev_fw_rules", "r-" + tag}
	}
	return [2]string{"netdev_nat_rules", "n-" + tag}
}

// TestPolicyPartBeyondScanBoundIsConservative: a part not found within
// maxPolicyPartScan newer datasets is refused when older than them, and
// the dataset is reported partial.
func TestPolicyPartBeyondScanBoundIsConservative(t *testing.T) {
	s, _, clock := newTestStore(t)
	addDevice(t, s, panosDevice())
	at := testBase
	if _, err := replacePart(s, at, false, partRows(PolicyNATRules, "a")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= maxPolicyPartScan; i++ {
		at = at.Add(time.Minute)
		*clock = at
		if _, err := replacePart(s, at, false, partRows(PolicyZones, fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := replacePart(s, testBase.Add(30*time.Second), false, partRows(PolicyNATRules, "b")); !errors.Is(err, ErrOutOfOrder) {
		t.Fatalf("err = %v, want ErrOutOfOrder", err)
	}
	if ds := policyState(t, s); ds.State != StatePartial {
		t.Fatalf("state %s, want partial", ds.State)
	}
	// Current reads of the parts the bound hid are stored and clear it.
	for _, p := range []PolicyPart{PolicyNATRules, PolicyObjects, PolicySecurityRules} {
		at = at.Add(time.Minute)
		*clock = at
		if _, err := replacePart(s, at, false, partRows(p, "b")); err != nil {
			t.Fatal(err)
		}
	}
	if ds := policyState(t, s); ds.State != StateFresh {
		t.Fatalf("state %s, want fresh", ds.State)
	}
}
