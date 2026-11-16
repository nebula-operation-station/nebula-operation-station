// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"errors"
	"testing"
	"time"
)

func openClockT(t *testing.T, clock *time.Time) *DB {
	t.Helper()
	db, err := open(privateDir(t), func() time.Time { return *clock })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestBaselineTamperOpensOneFindingPerHost(t *testing.T) {
	clock := t0
	db := openClockT(t, &clock)
	if fs, err := db.BaselineTamperFindings(); err != nil || len(fs) != 0 {
		t.Fatalf("empty store: %v, %v", fs, err)
	}
	f, audit, err := db.RecordBaselineTamper("web-1", dg('a'), dg('b'))
	if err != nil {
		t.Fatal(err)
	}
	if !audit || !f.Opened || f.Count != 1 || !f.FirstSeen.Equal(t0) || !f.LastSeen.Equal(t0) {
		t.Fatalf("first mismatch: audit=%v %+v", audit, f)
	}
	if f.ApprovedDigest != dg('a') || f.PresentedDigest != dg('b') || f.HostID != "web-1" {
		t.Fatalf("first mismatch digests: %+v", f)
	}

	// Repeats within the audit interval only count: no flood of audit
	// records, even with another presented digest.
	clock = t0.Add(time.Minute)
	f, audit, err = db.RecordBaselineTamper("web-1", dg('a'), dg('c'))
	if err != nil {
		t.Fatal(err)
	}
	if audit || f.Opened || f.Count != 2 || f.PresentedDigest != dg('c') || !f.FirstSeen.Equal(t0) || !f.LastSeen.Equal(clock) {
		t.Fatalf("repeat: audit=%v %+v", audit, f)
	}
	for i := 0; i < 100; i++ {
		if _, audit, err = db.RecordBaselineTamper("web-1", dg('a'), dg('b')); err != nil || audit {
			t.Fatalf("repeat %d: audit=%v err=%v", i, audit, err)
		}
	}

	// After the interval the still-open finding is audited again.
	clock = t0.Add(BaselineTamperAuditInterval)
	f, audit, err = db.RecordBaselineTamper("web-1", dg('a'), dg('b'))
	if err != nil {
		t.Fatal(err)
	}
	if !audit || f.Opened || f.Count != 103 {
		t.Fatalf("after interval: audit=%v %+v", audit, f)
	}

	// Another host gets its own finding.
	if _, audit, err := db.RecordBaselineTamper("web-2", dg('a'), dg('b')); err != nil || !audit {
		t.Fatalf("second host: audit=%v err=%v", audit, err)
	}
	fs, err := db.BaselineTamperFindings()
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 || fs[0].HostID != "web-1" || fs[1].HostID != "web-2" || fs[0].Count != 103 {
		t.Fatalf("findings = %+v", fs)
	}
}

func TestBaselineTamperRejectsMalformedInput(t *testing.T) {
	db := openAtT(t, privateDir(t), t0)
	for _, tc := range []struct{ host, approved, presented string }{
		{"", dg('a'), dg('b')},
		{"web/1", dg('a'), dg('b')},
		{"web-1", "short", dg('b')},
		{"web-1", dg('a'), dg('A')},
		{"web-1", dg('a'), dg('a')}, // equal digests are no finding
	} {
		if _, _, err := db.RecordBaselineTamper(tc.host, tc.approved, tc.presented); !errors.Is(err, ErrInvalid) {
			t.Errorf("RecordBaselineTamper(%q, %q, %q): err = %v, want ErrInvalid", tc.host, tc.approved, tc.presented, err)
		}
	}
	if fs, err := db.BaselineTamperFindings(); err != nil || len(fs) != 0 {
		t.Fatalf("store after rejections: %v, %v", fs, err)
	}
}

func TestBaselineTamperFindingsCannotBeDeleted(t *testing.T) {
	db := openAtT(t, privateDir(t), t0)
	if _, _, err := db.RecordBaselineTamper("web-1", dg('a'), dg('b')); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.Exec(`DELETE FROM integrity_baseline_tamper`); err == nil {
		t.Fatal("delete of an open tamper finding succeeded")
	}
	if _, err := db.sql.Exec(`UPDATE integrity_baseline_tamper SET first_seen = first_seen + 1`); err == nil {
		t.Fatal("first_seen changed")
	}
	if _, err := db.sql.Exec(`UPDATE integrity_baseline_tamper SET count = 0`); err == nil {
		t.Fatal("count lowered")
	}
}

// A comparison must never write the approved digest: recording a finding
// leaves the stored digest and its history untouched.
func TestBaselineTamperKeepsApprovedDigest(t *testing.T) {
	db := openAtT(t, privateDir(t), t0)
	if _, err := db.StoreApprovedBaselineDigest(BaselineDigest{HostID: "web-1", Digest: dg('a'), Kind: BaselineApprovalInitial}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.RecordBaselineTamper("web-1", dg('a'), dg('b')); err != nil {
		t.Fatal(err)
	}
	cur, err := db.ApprovedBaselineDigest("web-1")
	if err != nil || cur.Digest != dg('a') {
		t.Fatalf("approved = %+v, %v", cur, err)
	}
	var n int
	if err := db.sql.QueryRow(`SELECT count(*) FROM integrity_baseline_digests`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("digest rows = %d, %v", n, err)
	}
}
