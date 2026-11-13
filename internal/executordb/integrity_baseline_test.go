// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func dg(c byte) string { return strings.Repeat(string(c), 64) }

func TestBaselineDigestInitialThenChained(t *testing.T) {
	db := openAtT(t, privateDir(t), t0)
	if _, err := db.ApprovedBaselineDigest("web-1"); !errors.Is(err, ErrNoBaselineDigest) {
		t.Fatalf("empty store: err = %v, want ErrNoBaselineDigest", err)
	}
	got, err := db.StoreApprovedBaselineDigest(BaselineDigest{HostID: "web-1", Digest: dg('a'), Kind: BaselineApprovalInitial})
	if err != nil {
		t.Fatal(err)
	}
	if !got.ApprovedAt.Equal(t0) {
		t.Fatalf("approved_at = %v, want %v", got.ApprovedAt, t0)
	}
	if _, err := db.StoreApprovedBaselineDigest(BaselineDigest{HostID: "web-1", Digest: dg('b'), PreviousDigest: dg('a'), Kind: BaselineApprovalCLI}); err != nil {
		t.Fatal(err)
	}
	cur, err := db.ApprovedBaselineDigest("web-1")
	if err != nil {
		t.Fatal(err)
	}
	if cur.Digest != dg('b') || cur.PreviousDigest != dg('a') || cur.Kind != BaselineApprovalCLI || cur.HostID != "web-1" {
		t.Fatalf("active = %+v", cur)
	}
	var n int
	if err := db.sql.QueryRow(`SELECT count(*) FROM integrity_baseline_digests WHERE host_id = 'web-1'`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("history rows = %d, %v; want 2", n, err)
	}
	// Another host is independent.
	if _, err := db.ApprovedBaselineDigest("web-2"); !errors.Is(err, ErrNoBaselineDigest) {
		t.Fatalf("other host: err = %v", err)
	}
}

func TestBaselineDigestRejectsStaleApprovals(t *testing.T) {
	db := openAtT(t, privateDir(t), t0)
	mustStore := func(d BaselineDigest) {
		t.Helper()
		if _, err := db.StoreApprovedBaselineDigest(d); err != nil {
			t.Fatal(err)
		}
	}
	// Non-initial without any digest.
	if _, err := db.StoreApprovedBaselineDigest(BaselineDigest{HostID: "h1", Digest: dg('b'), PreviousDigest: dg('a'), Kind: BaselineApprovalBrowser}); !errors.Is(err, ErrBaselineDigestStale) {
		t.Fatalf("non-initial on empty: err = %v", err)
	}
	mustStore(BaselineDigest{HostID: "h1", Digest: dg('a'), Kind: BaselineApprovalInitial})
	for name, d := range map[string]BaselineDigest{
		"second initial":     {HostID: "h1", Digest: dg('c'), Kind: BaselineApprovalInitial},
		"wrong previous":     {HostID: "h1", Digest: dg('c'), PreviousDigest: dg('f'), Kind: BaselineApprovalCLI},
		"browser wrong prev": {HostID: "h1", Digest: dg('c'), PreviousDigest: dg('0'), Kind: BaselineApprovalBrowser},
	} {
		if _, err := db.StoreApprovedBaselineDigest(d); !errors.Is(err, ErrBaselineDigestStale) {
			t.Errorf("%s: err = %v, want ErrBaselineDigestStale", name, err)
		}
	}
	cur, err := db.ApprovedBaselineDigest("h1")
	if err != nil || cur.Digest != dg('a') {
		t.Fatalf("after rejections: %+v, %v; want digest a unchanged", cur, err)
	}
}

func TestBaselineDigestRejectsMalformed(t *testing.T) {
	db := openAtT(t, privateDir(t), t0)
	for name, d := range map[string]BaselineDigest{
		"bad host":             {HostID: "", Digest: dg('a'), Kind: BaselineApprovalInitial},
		"host control":         {HostID: "h\x1b", Digest: dg('a'), Kind: BaselineApprovalInitial},
		"uppercase digest":     {HostID: "h1", Digest: dg('A'), Kind: BaselineApprovalInitial},
		"short digest":         {HostID: "h1", Digest: "abc", Kind: BaselineApprovalInitial},
		"unknown kind":         {HostID: "h1", Digest: dg('a'), Kind: "server"},
		"initial with prev":    {HostID: "h1", Digest: dg('a'), PreviousDigest: dg('b'), Kind: BaselineApprovalInitial},
		"cli without prev":     {HostID: "h1", Digest: dg('a'), Kind: BaselineApprovalCLI},
		"cli bad prev":         {HostID: "h1", Digest: dg('a'), PreviousDigest: "zz", Kind: BaselineApprovalCLI},
		"digest with trailing": {HostID: "h1", Digest: dg('a') + "\n", Kind: BaselineApprovalInitial},
	} {
		if _, err := db.StoreApprovedBaselineDigest(d); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	if _, err := db.ApprovedBaselineDigest("h\x00"); !errors.Is(err, ErrInvalid) {
		t.Errorf("read malformed host: err = %v", err)
	}
}

// TestBaselineDigestIsImmutableInSQL pins the triggers: an approved digest
// cannot be rewritten, deleted or inserted out of chain, even with direct
// SQL.
func TestBaselineDigestIsImmutableInSQL(t *testing.T) {
	db := openAtT(t, privateDir(t), t0)
	if _, err := db.StoreApprovedBaselineDigest(BaselineDigest{HostID: "h1", Digest: dg('a'), Kind: BaselineApprovalInitial}); err != nil {
		t.Fatal(err)
	}
	for name, q := range map[string]string{
		"rewrite digest":   `UPDATE integrity_baseline_digests SET digest = '` + dg('b') + `' WHERE host_id = 'h1'`,
		"delete":           `DELETE FROM integrity_baseline_digests WHERE host_id = 'h1'`,
		"second initial":   `INSERT INTO integrity_baseline_digests (host_id, digest, approval_kind, approved_at, active) VALUES ('h1', '` + dg('b') + `', 'initial', 1, 1)`,
		"second active":    `INSERT INTO integrity_baseline_digests (host_id, digest, previous_digest, approval_kind, approved_at, active) VALUES ('h1', '` + dg('b') + `', '` + dg('a') + `', 'cli', 1, 1)`,
		"orphan non-init":  `INSERT INTO integrity_baseline_digests (host_id, digest, previous_digest, approval_kind, approved_at, active) VALUES ('h2', '` + dg('b') + `', '` + dg('a') + `', 'cli', 1, 1)`,
		"inactive insert":  `INSERT INTO integrity_baseline_digests (host_id, digest, approval_kind, approved_at, active, superseded_at) VALUES ('h3', '` + dg('b') + `', 'initial', 1, 0, 1)`,
		"uppercase digest": `INSERT INTO integrity_baseline_digests (host_id, digest, approval_kind, approved_at, active) VALUES ('h4', '` + dg('B') + `', 'initial', 1, 1)`,
	} {
		if _, err := db.sql.Exec(q); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	cur, err := db.ApprovedBaselineDigest("h1")
	if err != nil || cur.Digest != dg('a') {
		t.Fatalf("after attempts: %+v, %v", cur, err)
	}
}

func TestBaselineDigestSurvivesRestart(t *testing.T) {
	dir := privateDir(t)
	db, err := open(dir, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.StoreApprovedBaselineDigest(BaselineDigest{HostID: "h1", Digest: dg('a'), Kind: BaselineApprovalInitial}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db2 := openAtT(t, dir, t0.Add(time.Hour))
	cur, err := db2.ApprovedBaselineDigest("h1")
	if err != nil {
		t.Fatal(err)
	}
	if cur.Digest != dg('a') || cur.Kind != BaselineApprovalInitial || !cur.ApprovedAt.Equal(t0) {
		t.Fatalf("after restart: %+v", cur)
	}
}
