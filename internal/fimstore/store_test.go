// SPDX-License-Identifier: AGPL-3.0-or-later

package fimstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimbaseline"
	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

const testProfile = "fim-test-v1"

var testNow = time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)

// file returns a hashed regular file record whose content is content.
func file(p string, content byte) fimscan.Record {
	return fimscan.Record{
		Path: []byte(p), Type: fimscan.TypeFile, Size: 10, Mode: 0o644,
		Inode: 100, Mtime: 1000, Ctime: 1000,
		Hash: fimscan.Hash{Kind: fimscan.HashKeyed, Sum: sha256.Sum256([]byte{content})},
	}
}

// scan wraps records in a complete scan result.
func scan(recs ...fimscan.Record) *fimscan.Result {
	return &fimscan.Result{
		ProfileID: testProfile, Mode: fimscan.ModeFull, Records: recs,
		SSHConfigState: fimscan.SSHConfigValid,
	}
}

// partialScan wraps records in a run that did not complete.
func partialScan(recs ...fimscan.Record) *fimscan.Result {
	r := scan(recs...)
	r.Partial = []fimscan.Reason{fimscan.ReasonRootSkipped}
	return r
}

// newTestStore opens a fresh server database with one host and returns the
// store, the database and the host ID.
func newTestStore(t *testing.T, name string) (*Store, *sql.DB, HostID) {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "nebula.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	res, err := db.Exec(`INSERT INTO hosts(name, created_at, updated_at) VALUES (?, '2026-11-13T00:00:00Z', '2026-11-13T00:00:00Z')`, name)
	if err != nil {
		t.Fatalf("insert host: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(db, func() time.Time { return testNow })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, db, HostID(id)
}

// digestOf is the digest fimbaseline computes for the records of res.
func digestOf(t *testing.T, res *fimscan.Result) fimbaseline.Digest {
	t.Helper()
	b, err := fimbaseline.NewBaseline(res)
	if err != nil {
		t.Fatalf("NewBaseline: %v", err)
	}
	return b.Digest()
}

// proposeAndApprove proposes res and approves it with the given previous
// digest (nil for the first baseline).
func proposeAndApprove(t *testing.T, s *Store, host HostID, prev *fimbaseline.Digest, res *fimscan.Result) Approved {
	t.Helper()
	p, err := s.Propose(context.Background(), host, res)
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	a, err := s.Approve(context.Background(), host, Approval{Previous: prev, Digest: p.Digest})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	return a
}

func countRows(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestFirstCompleteScanBecomesTrustOnFirstScanProposal(t *testing.T) {
	s, _, host := newTestStore(t, "web-1")
	res := scan(file("/etc/hosts", 1), file("/etc/passwd", 2))
	p, err := s.Propose(context.Background(), host, res)
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	if !p.TrustOnFirstScan() || p.BaseVersion != 0 || p.BaseDigest != nil {
		t.Errorf("first proposal not marked trust on first scan: %+v", p)
	}
	if p.Digest != digestOf(t, res) {
		t.Errorf("proposal digest %s, want %s", p.Digest, digestOf(t, res))
	}
	if p.Entries != 2 || p.ProfileID != testProfile {
		t.Errorf("proposal entries %d profile %q", p.Entries, p.ProfileID)
	}
	if _, err := s.GetApproved(context.Background(), host); !errors.Is(err, ErrNoBaseline) {
		t.Errorf("proposal visible as approved baseline: %v", err)
	}
	if err := s.ForEachApproved(context.Background(), host, func(fimscan.Record) error { return nil }); !errors.Is(err, ErrNoBaseline) {
		t.Errorf("streaming a proposal as baseline: %v", err)
	}
}

func TestProposalBecomesBaselineOnlyWithMatchingDigest(t *testing.T) {
	s, _, host := newTestStore(t, "web-1")
	res := scan(file("/etc/hosts", 1))
	p, err := s.Propose(context.Background(), host, res)
	if err != nil {
		t.Fatal(err)
	}
	wrong := digestOf(t, scan(file("/etc/hosts", 9)))
	if _, err := s.Approve(context.Background(), host, Approval{Digest: wrong}); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("approval with wrong digest: %v, want ErrDigestMismatch", err)
	}
	if _, err := s.GetApproved(context.Background(), host); !errors.Is(err, ErrNoBaseline) {
		t.Fatalf("refused approval still created a baseline: %v", err)
	}
	if _, err := s.GetProposal(context.Background(), host); err != nil {
		t.Fatalf("refused approval removed the proposal: %v", err)
	}
	a, err := s.Approve(context.Background(), host, Approval{Digest: p.Digest})
	if err != nil {
		t.Fatalf("approval with matching digest refused: %v", err)
	}
	if a.Version != 1 || a.Digest != p.Digest {
		t.Errorf("approved %+v, want version 1 digest %s", a, p.Digest)
	}
	if _, err := s.GetProposal(context.Background(), host); !errors.Is(err, ErrNoProposal) {
		t.Errorf("proposal survived its approval: %v", err)
	}
}

func TestApprovalNeedsTheExpectedPreviousDigest(t *testing.T) {
	s, _, host := newTestStore(t, "web-1")
	first := proposeAndApprove(t, s, host, nil, scan(file("/etc/hosts", 1)))

	second := scan(file("/etc/hosts", 2))
	p, err := s.Propose(context.Background(), host, second)
	if err != nil {
		t.Fatal(err)
	}
	if p.BaseVersion != first.Version || p.BaseDigest == nil || *p.BaseDigest != first.Digest {
		t.Fatalf("proposal built on %d %v, want approved %d %s", p.BaseVersion, p.BaseDigest, first.Version, first.Digest)
	}
	// An approved baseline exists, so "no previous digest" is refused.
	if _, err := s.Approve(context.Background(), host, Approval{Digest: p.Digest}); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("approval without previous digest: %v", err)
	}
	wrongPrev := digestOf(t, scan(file("/etc/hosts", 7)))
	if _, err := s.Approve(context.Background(), host, Approval{Previous: &wrongPrev, Digest: p.Digest}); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("approval with wrong previous digest: %v", err)
	}
	a, err := s.Approve(context.Background(), host, Approval{Previous: &first.Digest, Digest: p.Digest})
	if err != nil {
		t.Fatalf("approval with expected previous digest refused: %v", err)
	}
	if a.Version != 2 || a.Digest != p.Digest {
		t.Errorf("approved %+v, want version 2", a)
	}
	got, err := s.GetApproved(context.Background(), host)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 2 || got.Entries != 1 {
		t.Errorf("stored baseline %+v", got)
	}
}

func TestApprovalWithoutAProposalIsRefused(t *testing.T) {
	s, _, host := newTestStore(t, "web-1")
	d := digestOf(t, scan(file("/etc/hosts", 1)))
	if _, err := s.Approve(context.Background(), host, Approval{Digest: d}); !errors.Is(err, ErrNoProposal) {
		t.Errorf("approval without proposal: %v, want ErrNoProposal", err)
	}
}

func TestNewProposalReplacesTheOpenOne(t *testing.T) {
	s, db, host := newTestStore(t, "web-1")
	ctx := context.Background()
	a, err := s.Propose(ctx, host, scan(file("/etc/hosts", 1), file("/etc/motd", 1)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Propose(ctx, host, scan(file("/etc/hosts", 2)))
	if err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM fim_baseline_proposals WHERE host_id = ?`, host); n != 1 {
		t.Errorf("%d open proposals for one host", n)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM fim_baseline_proposal_entries WHERE host_id = ?`, host); n != 1 {
		t.Errorf("%d proposal entries after replacement, want 1", n)
	}
	cur, err := s.GetProposal(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	if cur.Digest != b.Digest || cur.Digest == a.Digest {
		t.Errorf("open proposal %s, want the newer %s", cur.Digest, b.Digest)
	}
	if _, err := s.Approve(ctx, host, Approval{Digest: a.Digest}); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("replaced proposal approved: %v", err)
	}
}

func TestPartialScanNeverBecomesAProposal(t *testing.T) {
	s, db, host := newTestStore(t, "web-1")
	_, err := s.Propose(context.Background(), host, partialScan(file("/etc/hosts", 1)))
	if !errors.Is(err, fimbaseline.ErrPartialScan) {
		t.Fatalf("partial scan: %v, want ErrPartialScan", err)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM fim_baseline_proposals`); n != 0 {
		t.Errorf("%d proposals after a partial scan", n)
	}
}

func TestPartialScanReplacesNothing(t *testing.T) {
	s, _, host := newTestStore(t, "web-1")
	open, err := s.Propose(context.Background(), host, scan(file("/etc/hosts", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Propose(context.Background(), host, partialScan(file("/etc/hosts", 2))); !errors.Is(err, fimbaseline.ErrPartialScan) {
		t.Fatalf("partial scan: %v", err)
	}
	cur, err := s.GetProposal(context.Background(), host)
	if err != nil {
		t.Fatalf("open proposal lost after a refused partial scan: %v", err)
	}
	if cur.Digest != open.Digest {
		t.Errorf("open proposal changed to %s", cur.Digest)
	}
}

func TestUnhashedFileNeverBecomesAProposal(t *testing.T) {
	s, _, host := newTestStore(t, "web-1")
	unhashed := file("/etc/hosts", 1)
	unhashed.Hash = fimscan.Hash{}
	if _, err := s.Propose(context.Background(), host, scan(unhashed)); !errors.Is(err, fimbaseline.ErrUnhashedFile) {
		t.Errorf("unhashed file: %v, want ErrUnhashedFile", err)
	}
}

func TestRecordLimitRefusesWithReason(t *testing.T) {
	s, db, host := newTestStore(t, "web-1")
	recs := make([]fimscan.Record, MaxRecordsPerHost+1)
	_, err := s.Propose(context.Background(), host, scan(recs...))
	if !errors.Is(err, fimbaseline.ErrLimit) {
		t.Fatalf("over the record limit: %v, want ErrLimit", err)
	}
	if !strings.Contains(err.Error(), "300001") || !strings.Contains(err.Error(), "300000") {
		t.Errorf("refusal does not give the reason: %v", err)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM fim_baseline_proposals`); n != 0 {
		t.Errorf("%d proposals after a refused limit", n)
	}
}

func TestLongPathRefusedAsLimit(t *testing.T) {
	s, _, host := newTestStore(t, "web-1")
	long := file("/"+strings.Repeat("a", fimbaseline.MaxPathBytes), 1)
	if _, err := s.Propose(context.Background(), host, scan(long)); !errors.Is(err, fimbaseline.ErrLimit) {
		t.Errorf("path over the limit: %v, want ErrLimit", err)
	}
}

func TestHostsKeepSeparateBaselines(t *testing.T) {
	s, db, h1 := newTestStore(t, "web-1")
	res, err := db.Exec(`INSERT INTO hosts(name, created_at, updated_at) VALUES ('web-2', '2026-11-13T00:00:00Z', '2026-11-13T00:00:00Z')`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	h2 := HostID(id)
	ctx := context.Background()

	a1 := proposeAndApprove(t, s, h1, nil, scan(file("/etc/hosts", 1)))
	p2, err := s.Propose(ctx, h2, scan(file("/etc/hosts", 2), file("/etc/motd", 2)))
	if err != nil {
		t.Fatal(err)
	}
	if !p2.TrustOnFirstScan() {
		t.Errorf("second host sees the first host's baseline: %+v", p2)
	}
	if _, err := s.Approve(ctx, h2, Approval{Previous: &a1.Digest, Digest: p2.Digest}); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("host 2 approved on host 1's digest: %v", err)
	}
	if _, err := s.Approve(ctx, h2, Approval{Digest: p2.Digest}); err != nil {
		t.Fatalf("host 2 approval: %v", err)
	}
	// Discarding a proposal on host 1 must not touch host 2.
	if _, err := s.Propose(ctx, h1, scan(file("/etc/hosts", 3))); err != nil {
		t.Fatal(err)
	}
	cur, err := s.GetApproved(ctx, h1)
	if err != nil || cur.Digest != a1.Digest {
		t.Errorf("host 1 baseline %+v, %v", cur, err)
	}
	cur2, err := s.GetApproved(ctx, h2)
	if err != nil || cur2.Entries != 2 {
		t.Errorf("host 2 baseline %+v, %v", cur2, err)
	}
}

func TestDiscardNeedsTheProposalDigest(t *testing.T) {
	s, _, host := newTestStore(t, "web-1")
	ctx := context.Background()
	if err := s.Discard(ctx, host, fimbaseline.Digest{}); !errors.Is(err, ErrNoProposal) {
		t.Errorf("discard without proposal: %v", err)
	}
	p, err := s.Propose(ctx, host, scan(file("/etc/hosts", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Discard(ctx, host, digestOf(t, scan(file("/etc/hosts", 9)))); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("discard with wrong digest: %v", err)
	}
	if err := s.Discard(ctx, host, p.Digest); err != nil {
		t.Fatalf("discard: %v", err)
	}
	if _, err := s.GetProposal(ctx, host); !errors.Is(err, ErrNoProposal) {
		t.Errorf("discarded proposal still there: %v", err)
	}
}

func TestApprovedBaselineStreamsRawBytesInPathOrder(t *testing.T) {
	s, _, host := newTestStore(t, "web-1")
	raw := []byte{'/', 'e', 't', 'c', '/', 0xff, 0xfe}
	link := fimscan.Record{Path: []byte("/etc/alt"), Type: fimscan.TypeSymlink, Size: 7, Mode: 0o777,
		Inode: 1 << 63, Mtime: 5, Ctime: 6, Link: []byte("/etc/x\xff")}
	plain := fimscan.Record{Path: []byte("/etc/a"), Type: fimscan.TypeFile, Size: 3, Mode: 0o640,
		UID: 1000, GID: 1000, Inode: 42, Mtime: 1, Ctime: 2,
		Hash: fimscan.Hash{Kind: fimscan.HashPlain, Sum: sha256.Sum256([]byte("a"))}}
	unhashed := fimscan.Record{Path: raw, Type: fimscan.TypeDir, Size: 4096, Mode: 0o755, Inode: 2, Mtime: 1, Ctime: 1}
	res := scan(link, plain, unhashed)
	proposeAndApprove(t, s, host, nil, res)

	var got []fimscan.Record
	err := s.ForEachApproved(context.Background(), host, func(r fimscan.Record) error {
		got = append(got, r)
		return nil
	})
	if err != nil {
		t.Fatalf("ForEachApproved: %v", err)
	}
	// Byte order: "/etc/a" < "/etc/alt" < "/etc/\xff\xfe".
	want := []fimscan.Record{plain, link, unhashed}
	if len(got) != len(want) {
		t.Fatalf("streamed %d records, want %d", len(got), len(want))
	}
	for i := range want {
		if !recordsEqual(got[i], want[i]) {
			t.Errorf("record %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestStreamingStopsAtTheFirstError(t *testing.T) {
	s, _, host := newTestStore(t, "web-1")
	proposeAndApprove(t, s, host, nil, scan(file("/etc/a", 1), file("/etc/b", 2)))
	stop := errors.New("stop")
	calls := 0
	err := s.ForEachApproved(context.Background(), host, func(fimscan.Record) error {
		calls++
		return stop
	})
	if !errors.Is(err, stop) || calls != 1 {
		t.Errorf("err %v after %d calls, want stop after 1", err, calls)
	}
}

func TestInvalidInputIsRefused(t *testing.T) {
	s, _, host := newTestStore(t, "web-1")
	ctx := context.Background()
	if _, err := s.Propose(ctx, host, nil); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("nil scan: %v", err)
	}
	if _, err := s.Propose(ctx, 0, scan(file("/etc/a", 1))); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("host 0: %v", err)
	}
	if _, err := s.Propose(ctx, 999, scan(file("/etc/a", 1))); !errors.Is(err, ErrUnknownHost) {
		t.Errorf("unknown host: %v", err)
	}
	if _, err := New(nil, nil); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("nil database: %v", err)
	}
}

// recordsEqual compares every field of two records, bytes included.
func recordsEqual(a, b fimscan.Record) bool {
	return bytes.Equal(a.Path, b.Path) && a.Type == b.Type && a.Size == b.Size &&
		a.Mode == b.Mode && a.UID == b.UID && a.GID == b.GID && a.Inode == b.Inode &&
		a.Mtime == b.Mtime && a.Ctime == b.Ctime && a.Hash == b.Hash && bytes.Equal(a.Link, b.Link) &&
		(a.Link == nil) == (b.Link == nil)
}
