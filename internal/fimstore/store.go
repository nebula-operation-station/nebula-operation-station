// SPDX-License-Identifier: AGPL-3.0-or-later

// Package fimstore keeps the per-host FIM baseline on NOS (ADR 0015 D7):
// the approved record list in the server database, and at most one open
// proposal per host. A proposal is built from a complete scan, is never a
// baseline by itself, and becomes one only when an approval names its digest
// and the approved digest it was built on (compare-and-swap).
//
// The digest is computed and checked here; who confirms it and where a copy
// is kept outside NOS is decided by IG-06c.
package fimstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimbaseline"
	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
)

// MaxRecordsPerHost is the record limit of one host's baseline and of one
// proposal (ADR 0015 "Consequences": about 300,000 records per host at most).
// A scan above it is refused with fimbaseline.ErrLimit and a reason.
const MaxRecordsPerHost = fimbaseline.MaxEntries

// Errors callers branch on. Partial scans, unhashed files and path limits
// are reported as the fimbaseline sentinels (fimbaseline.ErrPartialScan,
// ErrUnhashedFile, ErrLimit).
var (
	// ErrInvalidInput: a host ID, scan or database is missing or malformed.
	ErrInvalidInput = errors.New("fimstore: invalid input")
	// ErrUnknownHost: the host ID names no host.
	ErrUnknownHost = errors.New("fimstore: unknown host")
	// ErrNoBaseline: the host has no approved baseline.
	ErrNoBaseline = errors.New("fimstore: no approved baseline")
	// ErrNoProposal: the host has no open proposal.
	ErrNoProposal = errors.New("fimstore: no open proposal")
	// ErrDigestMismatch: the digest the caller expected is not the stored one
	// (the previous approved digest, the proposal digest, or a discard).
	ErrDigestMismatch = errors.New("fimstore: digest mismatch")
	// ErrStaleProposal: the proposal was built on an approved baseline that
	// is no longer the approved one. It must be rebuilt from a new scan.
	ErrStaleProposal = errors.New("fimstore: proposal built on another baseline")
)

// HostID is the server database ID of a host.
type HostID int64

func (h HostID) validate() error {
	if h <= 0 {
		return fmt.Errorf("%w: host ID %d", ErrInvalidInput, h)
	}
	return nil
}

// Store reads and writes baselines and proposals. It is safe for concurrent
// use; writes are serialised by a mutex and by the database write lock.
type Store struct {
	db  *sql.DB
	now func() time.Time
	mu  sync.Mutex
}

// New returns a store on db. A nil now uses time.Now.
func New(db *sql.DB, now func() time.Time) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("fimstore: new: %w: nil database", ErrInvalidInput)
	}
	if now == nil {
		now = time.Now
	}
	return &Store{db: db, now: now}, nil
}

// Approved is the approved baseline of a host.
type Approved struct {
	// Version counts approvals of the host, starting at 1.
	Version int64
	// Digest is the baseline digest (fimbaseline.Baseline.Digest).
	Digest fimbaseline.Digest
	// ProfileID is the profile the baseline was taken with.
	ProfileID string
	// Entries is the number of records.
	Entries int
	// ApprovedAt is when the baseline was approved.
	ApprovedAt time.Time
}

// Proposal is the open proposal of a host. It is not a baseline.
type Proposal struct {
	// BaseVersion is the approved version the proposal was built on; 0 means
	// there was none, so the proposal is "trust on first scan" (ADR 0015 D7).
	BaseVersion int64
	// BaseDigest is the approved digest the proposal was built on; nil when
	// BaseVersion is 0.
	BaseDigest *fimbaseline.Digest
	// Digest is the digest of the proposed record list.
	Digest fimbaseline.Digest
	// ProfileID is the profile of the scan.
	ProfileID string
	// Entries is the number of proposed records.
	Entries int
	// ProposedAt is when the proposal was built.
	ProposedAt time.Time
}

// TrustOnFirstScan reports whether the proposal has no approved baseline to
// compare with: the admin is then told that NOS cannot know whether the host
// was already compromised (ADR 0015 D7).
func (p Proposal) TrustOnFirstScan() bool { return p.BaseVersion == 0 }

// Approval is what an admin approves: the digest of the proposal, and the
// approved digest it must replace. Previous is nil only when the host has no
// approved baseline (the first one, trust on first scan).
type Approval struct {
	Previous *fimbaseline.Digest
	Digest   fimbaseline.Digest
}

// Propose builds the open proposal of host from res and replaces the one
// that was open before. res must be a complete scan; a partial scan, an
// unhashed file or more than MaxRecordsPerHost records is refused and changes
// nothing. The proposal is not a baseline until Approve accepts it.
func (s *Store) Propose(ctx context.Context, host HostID, res *fimscan.Result) (Proposal, error) {
	if err := host.validate(); err != nil {
		return Proposal{}, fmt.Errorf("propose: %w", err)
	}
	if res == nil {
		return Proposal{}, fmt.Errorf("propose: %w: nil scan", ErrInvalidInput)
	}
	if len(res.Records) > MaxRecordsPerHost {
		return Proposal{}, fmt.Errorf("propose: %w: %d records, the limit is %d per host",
			fimbaseline.ErrLimit, len(res.Records), MaxRecordsPerHost)
	}
	base, err := fimbaseline.NewBaseline(res)
	if err != nil {
		return Proposal{}, fmt.Errorf("propose: %w", err)
	}
	entries := base.Entries()

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.writeTx(ctx)
	if err != nil {
		return Proposal{}, fmt.Errorf("propose: %w", err)
	}
	defer tx.Rollback()
	if err := requireHost(ctx, tx, host); err != nil {
		return Proposal{}, fmt.Errorf("propose: %w", err)
	}
	cur, err := readApproved(ctx, tx, host)
	if err != nil {
		return Proposal{}, fmt.Errorf("propose: %w", err)
	}
	now := s.now()
	p := Proposal{
		Digest:     base.Digest(),
		ProfileID:  base.ProfileID(),
		Entries:    base.Len(),
		ProposedAt: now,
	}
	var baseDigest any
	if cur != nil {
		p.BaseVersion = cur.Version
		d := cur.Digest
		p.BaseDigest = &d
		baseDigest = d[:]
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM fim_baseline_proposals WHERE host_id = ?`, host); err != nil {
		return Proposal{}, fmt.Errorf("propose: replace open proposal: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO fim_baseline_proposals
		(host_id, base_version, base_digest, digest, profile_id, entry_count, proposed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		host, p.BaseVersion, baseDigest, p.Digest[:], p.ProfileID, p.Entries, now.Unix()); err != nil {
		return Proposal{}, fmt.Errorf("propose: insert proposal: %w", err)
	}
	if _, err := insertEntries(ctx, tx, proposalEntries, host, entries); err != nil {
		return Proposal{}, fmt.Errorf("propose: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Proposal{}, fmt.Errorf("propose: commit: %w", err)
	}
	return p, nil
}

// Approve makes the open proposal of host the approved baseline if the
// proposal's digest is ap.Digest and the approved digest is ap.Previous.
// Any other combination is refused and changes nothing. The approval replaces
// the approved entries and removes the proposal.
func (s *Store) Approve(ctx context.Context, host HostID, ap Approval) (Approved, error) {
	if err := host.validate(); err != nil {
		return Approved{}, fmt.Errorf("approve: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.writeTx(ctx)
	if err != nil {
		return Approved{}, fmt.Errorf("approve: %w", err)
	}
	defer tx.Rollback()
	if err := requireHost(ctx, tx, host); err != nil {
		return Approved{}, fmt.Errorf("approve: %w", err)
	}
	cur, err := readApproved(ctx, tx, host)
	if err != nil {
		return Approved{}, fmt.Errorf("approve: %w", err)
	}
	switch {
	case cur == nil && ap.Previous != nil:
		return Approved{}, fmt.Errorf("approve: %w: expected approved digest %s, host has none", ErrDigestMismatch, ap.Previous)
	case cur != nil && (ap.Previous == nil || *ap.Previous != cur.Digest):
		return Approved{}, fmt.Errorf("approve: %w: approved digest is %s", ErrDigestMismatch, cur.Digest)
	}
	prop, err := readProposal(ctx, tx, host)
	if err != nil {
		return Approved{}, fmt.Errorf("approve: %w", err)
	}
	if prop.Digest != ap.Digest {
		return Approved{}, fmt.Errorf("approve: %w: proposal digest is %s", ErrDigestMismatch, prop.Digest)
	}
	if prop.BaseVersion != versionOf(cur) || !sameDigest(prop.BaseDigest, cur) {
		return Approved{}, fmt.Errorf("approve: %w", ErrStaleProposal)
	}
	next := Approved{
		Version:    versionOf(cur) + 1,
		Digest:     prop.Digest,
		ProfileID:  prop.ProfileID,
		Entries:    prop.Entries,
		ApprovedAt: s.now(),
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO fim_baselines
		(host_id, version, digest, profile_id, entry_count, approved_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (host_id) DO UPDATE SET version = excluded.version, digest = excluded.digest,
			profile_id = excluded.profile_id, entry_count = excluded.entry_count, approved_at = excluded.approved_at`,
		host, next.Version, next.Digest[:], next.ProfileID, next.Entries, next.ApprovedAt.Unix()); err != nil {
		return Approved{}, fmt.Errorf("approve: write baseline: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM fim_baseline_entries WHERE host_id = ?`, host); err != nil {
		return Approved{}, fmt.Errorf("approve: replace entries: %w", err)
	}
	if _, err := tx.ExecContext(ctx, copyEntriesSQL, host); err != nil {
		return Approved{}, fmt.Errorf("approve: copy entries: %w", err)
	}
	var copied int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM fim_baseline_entries WHERE host_id = ?`, host).Scan(&copied); err != nil {
		return Approved{}, fmt.Errorf("approve: count entries: %w", err)
	}
	if copied != prop.Entries {
		return Approved{}, fmt.Errorf("approve: copied %d entries, proposal has %d", copied, prop.Entries)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM fim_baseline_proposals WHERE host_id = ?`, host); err != nil {
		return Approved{}, fmt.Errorf("approve: remove proposal: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Approved{}, fmt.Errorf("approve: commit: %w", err)
	}
	return next, nil
}

// Discard removes the open proposal of host if its digest is d.
func (s *Store) Discard(ctx context.Context, host HostID, d fimbaseline.Digest) error {
	if err := host.validate(); err != nil {
		return fmt.Errorf("discard: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.writeTx(ctx)
	if err != nil {
		return fmt.Errorf("discard: %w", err)
	}
	defer tx.Rollback()
	prop, err := readProposal(ctx, tx, host)
	if err != nil {
		return fmt.Errorf("discard: %w", err)
	}
	if prop.Digest != d {
		return fmt.Errorf("discard: %w: proposal digest is %s", ErrDigestMismatch, prop.Digest)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM fim_baseline_proposals WHERE host_id = ?`, host); err != nil {
		return fmt.Errorf("discard: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("discard: commit: %w", err)
	}
	return nil
}

// GetApproved returns the approved baseline of host, or ErrNoBaseline.
func (s *Store) GetApproved(ctx context.Context, host HostID) (Approved, error) {
	if err := host.validate(); err != nil {
		return Approved{}, fmt.Errorf("get baseline: %w", err)
	}
	a, err := readApproved(ctx, s.db, host)
	if err != nil {
		return Approved{}, fmt.Errorf("get baseline: %w", err)
	}
	if a == nil {
		return Approved{}, fmt.Errorf("get baseline: %w", ErrNoBaseline)
	}
	return *a, nil
}

// GetProposal returns the open proposal of host, or ErrNoProposal.
func (s *Store) GetProposal(ctx context.Context, host HostID) (Proposal, error) {
	if err := host.validate(); err != nil {
		return Proposal{}, fmt.Errorf("get proposal: %w", err)
	}
	p, err := readProposal(ctx, s.db, host)
	if err != nil {
		return Proposal{}, fmt.Errorf("get proposal: %w", err)
	}
	return p, nil
}

// ForEachApproved calls fn for every record of the approved baseline of host,
// in raw path byte order, reading one row at a time from a read transaction.
// The records are copies owned by fn. The first error from fn stops the
// stream and is returned wrapped. fn must not write through the same database
// handle while the stream is open.
func (s *Store) ForEachApproved(ctx context.Context, host HostID, fn func(fimscan.Record) error) error {
	if err := host.validate(); err != nil {
		return fmt.Errorf("stream baseline: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("stream baseline: begin: %w", err)
	}
	defer tx.Rollback()
	cur, err := readApproved(ctx, tx, host)
	if err != nil {
		return fmt.Errorf("stream baseline: %w", err)
	}
	if cur == nil {
		return fmt.Errorf("stream baseline: %w", ErrNoBaseline)
	}
	rows, err := tx.QueryContext(ctx, `SELECT path, type, size, mode, uid, gid, inode, mtime, ctime,
		hash_kind, hash_secret, hash_sum, link FROM fim_baseline_entries WHERE host_id = ? ORDER BY path`, host)
	if err != nil {
		return fmt.Errorf("stream baseline: query: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		rec, err := scanEntry(rows)
		if err != nil {
			return fmt.Errorf("stream baseline: %w", err)
		}
		if err := fn(rec); err != nil {
			return fmt.Errorf("stream baseline: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("stream baseline: %w", err)
	}
	return nil
}

// writeTx starts a write transaction that holds the database write lock
// before it reads, as integritystore does: it bumps the lock row first.
func (s *Store) writeTx(ctx context.Context) (*sql.Tx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE fim_store_state SET lock_counter = lock_counter + 1 WHERE id = 1`); err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("lock: %w", err)
	}
	return tx, nil
}

// queryer is the read side shared by *sql.DB and *sql.Tx.
type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func requireHost(ctx context.Context, q queryer, host HostID) error {
	var n int
	if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM hosts WHERE id = ?`, host).Scan(&n); err != nil {
		return fmt.Errorf("check host: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("%w: %d", ErrUnknownHost, host)
	}
	return nil
}

// readApproved returns the approved baseline of host, or nil when there is
// none.
func readApproved(ctx context.Context, q queryer, host HostID) (*Approved, error) {
	var (
		a          Approved
		digest     []byte
		approvedAt int64
		entries    int64
	)
	err := q.QueryRowContext(ctx, `SELECT version, digest, profile_id, entry_count, approved_at
		FROM fim_baselines WHERE host_id = ?`, host).Scan(&a.Version, &digest, &a.ProfileID, &entries, &approvedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	if err := copyDigest(&a.Digest, digest); err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	a.Entries = int(entries)
	a.ApprovedAt = time.Unix(approvedAt, 0).UTC()
	return &a, nil
}

// readProposal returns the open proposal of host, or ErrNoProposal.
func readProposal(ctx context.Context, q queryer, host HostID) (Proposal, error) {
	var (
		p          Proposal
		baseDigest []byte
		digest     []byte
		entries    int64
		proposedAt int64
	)
	err := q.QueryRowContext(ctx, `SELECT base_version, base_digest, digest, profile_id, entry_count, proposed_at
		FROM fim_baseline_proposals WHERE host_id = ?`, host).
		Scan(&p.BaseVersion, &baseDigest, &digest, &p.ProfileID, &entries, &proposedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Proposal{}, fmt.Errorf("%w: host %d", ErrNoProposal, host)
	}
	if err != nil {
		return Proposal{}, fmt.Errorf("read proposal: %w", err)
	}
	if err := copyDigest(&p.Digest, digest); err != nil {
		return Proposal{}, fmt.Errorf("read proposal: %w", err)
	}
	if baseDigest != nil {
		var d fimbaseline.Digest
		if err := copyDigest(&d, baseDigest); err != nil {
			return Proposal{}, fmt.Errorf("read proposal: base: %w", err)
		}
		p.BaseDigest = &d
	}
	p.Entries = int(entries)
	p.ProposedAt = time.Unix(proposedAt, 0).UTC()
	return p, nil
}

func copyDigest(dst *fimbaseline.Digest, src []byte) error {
	if len(src) != len(dst) {
		return fmt.Errorf("%w: digest of %d bytes", ErrInvalidInput, len(src))
	}
	copy(dst[:], src)
	return nil
}

func versionOf(a *Approved) int64 {
	if a == nil {
		return 0
	}
	return a.Version
}

// sameDigest reports whether the proposal's base digest equals the approved
// baseline's digest; both nil (no baseline) is the same.
func sameDigest(base *fimbaseline.Digest, cur *Approved) bool {
	if cur == nil {
		return base == nil
	}
	return base != nil && *base == cur.Digest
}
