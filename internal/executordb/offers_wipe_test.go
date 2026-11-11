// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// copyCrashImage copies the database, its -wal file and the marker from
// dir into a new private directory while the DB in dir is still open, as a
// crash (or a power cut) would leave them: synchronous=FULL has synced
// every committed frame to the -wal file.
func copyCrashImage(t *testing.T, dir string) string {
	t.Helper()
	crash := privateDir(t)
	for _, name := range []string{FileName, FileName + "-wal", MarkerName} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(crash, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return crash
}

// TestOpenCheckpointPurgesWipedSaltLeftInWAL: a crash between a salt
// wipe's commit and its checkpoint leaves the committed wipe and the old
// salt in the -wal file. Open replays the WAL and checkpoints it with
// TRUNCATE before it returns, so the salt is gone from every file while
// the reopened DB is open, and the wipe still holds.
func TestOpenCheckpointPurgesWipedSaltLeftInWAL(t *testing.T) {
	dir := privateDir(t)
	clk := &offerClock{t: t0}
	db := openOfferDB(t, dir, clk)
	live := mustCreateOffer(t, db, false)
	n := mustCreateOffer(t, db, false)

	// The wipe commits, and the process dies before purgeWipedSalt.
	if _, err := db.sql.Exec(`UPDATE enroll_offers SET state = 'revoked', state_changed_at = ?, salt = NULL
		WHERE id_hash = ? AND state = 'open'`, clk.Now().Unix(), n.IDHash[:]); err != nil {
		t.Fatal(err)
	}
	crash := copyCrashImage(t, dir)
	if in := saltOnDisk(t, crash, n.Salt); !slices.Contains(in, FileName+"-wal") {
		t.Fatalf("crash image has the wiped salt in %v, want it in the -wal file: the test proves nothing", in)
	}

	reopened := openOfferDB(t, crash, clk)
	if in := saltOnDisk(t, crash, n.Salt); len(in) != 0 {
		t.Fatalf("wiped salt still in %v after Open returned", in)
	}
	if fi, err := os.Stat(filepath.Join(crash, FileName+"-wal")); err == nil && fi.Size() != 0 {
		t.Fatalf("-wal file has %d bytes after Open, want it truncated", fi.Size())
	}
	if o := mustOffer(t, reopened, n.IDHash); o.State != OfferRevoked || o.Salt != nil {
		t.Fatalf("wiped offer after reopen: %s, salt %v", o.State, o.Salt != nil)
	}
	// The live offer is replayed too and keeps its salt, on disk as well.
	if o := mustOffer(t, reopened, live.IDHash); o.State != OfferOpen || !bytes.Equal(o.Salt, live.Salt[:]) {
		t.Fatalf("live offer after reopen: %s, salt %v", o.State, o.Salt != nil)
	}
	if in := saltOnDisk(t, crash, live.Salt); len(in) == 0 {
		t.Fatal("live salt missing on disk after reopen")
	}
}

// openBlockableDB opens the database in dir without the exclusive locking
// mode and with two connections, so that a reader on one connection can
// block the wipe's checkpoint on the other. Open never builds a DB like
// this; it exists to reach the ErrOfferWipeIncomplete path.
func openBlockableDB(t *testing.T, dir string, clk *offerClock) *DB {
	t.Helper()
	sdb, err := sql.Open("sqlite", filepath.Join(dir, FileName)+
		"?_pragma=busy_timeout(50)&_pragma=foreign_keys(1)&_pragma=secure_delete(1)&_journal_mode=WAL&_synchronous=FULL")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sdb.Close() })
	sdb.SetMaxOpenConns(2)
	return &DB{sql: sdb, now: clk.Now, offerLimits: offerLimits{live: 1 << 20, liveNetBird: 1 << 20, perHour: 1 << 20}}
}

// errScan stands for a read error after the sweep's UPDATE committed.
var errScan = errors.New("injected scan failure")

// failingScan reads the rows as the sweep does and then fails.
func failingScan(rows *sql.Rows) ([][offerHashLen]byte, error) {
	if _, err := scanOfferIDs(rows); err != nil {
		return nil, err
	}
	return nil, errScan
}

// TestOfferWipeIncompleteWhenCheckpointBlocked: when a reader blocks the
// checkpoint, every wiping call fails with ErrOfferWipeIncomplete, but the
// final state and the NULL salt are committed and stay, also across a
// restart, whose Open removes the salt from the WAL. The error carries no
// salt.
func TestOfferWipeIncompleteWhenCheckpointBlocked(t *testing.T) {
	for _, tc := range []struct {
		name     string
		prep     func(*DB, [32]byte) error
		wipe     func(*DB, *offerClock, [32]byte) ([][offerHashLen]byte, error)
		want     OfferState
		sweepErr bool // the sweep's commit reports an error too
	}{
		{"revoke", nil, func(db *DB, _ *offerClock, id [32]byte) ([][offerHashLen]byte, error) {
			return nil, db.EndOffer(id, OfferOpen, OfferRevoked)
		}, OfferRevoked, false},
		{"complete", proposeOffer, func(db *DB, _ *offerClock, id [32]byte) ([][offerHashLen]byte, error) {
			return nil, db.CompleteOffer(id)
		}, OfferEnrolled, false},
		{"expiry sweep", nil, func(db *DB, clk *offerClock, _ [32]byte) ([][offerHashLen]byte, error) {
			clk.Add(OfferLifetime)
			return db.ExpireOffers()
		}, OfferExpired, false},
		{"expiry sweep with commit failure", nil, func(db *DB, clk *offerClock, _ [32]byte) ([][offerHashLen]byte, error) {
			clk.Add(OfferLifetime)
			commitSweep = committedButFailing
			defer func() { commitSweep = (*sql.Tx).Commit }()
			return db.ExpireOffers()
		}, OfferExpired, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := privateDir(t)
			clk := &offerClock{t: t0}
			db := openOfferDB(t, dir, clk)
			n := mustCreateOffer(t, db, false)
			if tc.prep != nil {
				if err := tc.prep(db, n.IDHash); err != nil {
					t.Fatal(err)
				}
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			bdb := openBlockableDB(t, dir, clk)
			reader, err := bdb.sql.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Rollback()
			var salt []byte
			if err := reader.QueryRow(`SELECT salt FROM enroll_offers WHERE id_hash = ?`, n.IDHash[:]).Scan(&salt); err != nil {
				t.Fatal(err)
			}
			if len(salt) == 0 {
				t.Fatal("reader snapshot does not hold the salt")
			}

			got, err := tc.wipe(bdb, clk, n.IDHash)
			if !errors.Is(err, ErrOfferWipeIncomplete) {
				t.Fatalf("wipe with a blocked checkpoint: %v, want ErrOfferWipeIncomplete", err)
			}
			if tc.sweepErr != errors.Is(err, errCommit) {
				t.Fatalf("wipe error %v: commit failure reported %v, want %v", err, !tc.sweepErr, tc.sweepErr)
			}
			msg := err.Error()
			if strings.Contains(msg, hex.EncodeToString(n.Salt[:])) || strings.Contains(msg, string(n.Salt[:])) ||
				strings.Contains(msg, fmt.Sprintf("%x", n.Salt[:4])) {
				t.Fatalf("error carries the salt: %q", msg)
			}
			if tc.want == OfferExpired && (len(got) != 1 || got[0] != n.IDHash) {
				t.Fatalf("sweep returned %x with the error, want the expired offer", got)
			}
			// The state change is committed although the purge failed.
			if o := mustOffer(t, bdb, n.IDHash); o.State != tc.want || o.Salt != nil {
				t.Fatalf("offer after incomplete wipe: %s, salt %v", o.State, o.Salt != nil)
			}
			// The error is truthful: the salt is still in the WAL.
			if in := saltOnDisk(t, dir, n.Salt); len(in) == 0 {
				t.Fatal("salt gone from disk although the wipe reported it incomplete")
			}

			if err := reader.Rollback(); err != nil {
				t.Fatal(err)
			}
			// Restart from the files as they are while bdb is still open:
			// closing its last connection would checkpoint the WAL itself,
			// so only Open's checkpoint can remove the salt here. (The
			// blocked checkpoint left the old page with the salt in the
			// main file and the wipe in the -wal file.)
			crash := copyCrashImage(t, dir)
			if in := saltOnDisk(t, crash, n.Salt); len(in) == 0 {
				t.Fatal("crash image has no salt on disk: the restart proves nothing")
			}
			reopened := openOfferDB(t, crash, clk)
			if o := mustOffer(t, reopened, n.IDHash); o.State != tc.want || o.Salt != nil {
				t.Fatalf("offer after restart: %s, salt %v", o.State, o.Salt != nil)
			}
			if in := saltOnDisk(t, crash, n.Salt); len(in) != 0 {
				t.Fatalf("wiped salt in %v after restart", in)
			}
		})
	}
}

// errCommit stands for an error reported by the sweep's COMMIT.
var errCommit = errors.New("injected commit failure")

// committedButFailing commits and then reports an error, as a commit whose
// outcome the caller cannot know.
func committedButFailing(tx *sql.Tx) error {
	if err := tx.Commit(); err != nil {
		return err
	}
	return errCommit
}

// rolledBackButFailing rolls back and reports an error, as a commit that
// did not happen.
func rolledBackButFailing(tx *sql.Tx) error {
	if err := tx.Rollback(); err != nil {
		return err
	}
	return errCommit
}

// tooManyIDs returns one ID more than a sweep may end.
func tooManyIDs(rows *sql.Rows) ([][offerHashLen]byte, error) {
	if _, err := scanOfferIDs(rows); err != nil {
		return nil, err
	}
	return make([][offerHashLen]byte, maxSweptOffers+1), nil
}

// TestExpireOffersReadFailureEndsNothing: the sweep reads the IDs of the
// offers it ends before it commits. If that read fails (or returns more
// IDs than the bound), the sweep rolls back and returns only the error, so
// no offer has ended without its ID being returned: the offer is unchanged
// with its salt, and the next sweep ends it, returns its ID and removes
// the salt from disk.
func TestExpireOffersReadFailureEndsNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		scan func(*sql.Rows) ([][offerHashLen]byte, error)
		is   func(error) bool
	}{
		{"scan error", failingScan, func(err error) bool { return errors.Is(err, errScan) }},
		{"too many IDs", tooManyIDs, func(err error) bool {
			return err != nil && strings.Contains(err.Error(), fmt.Sprintf("more than %d", maxSweptOffers))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := privateDir(t)
			clk := &offerClock{t: t0}
			db := openOfferDB(t, dir, clk)
			n := mustCreateOffer(t, db, false)

			clk.Add(OfferLifetime)
			scanExpiredOffers = tc.scan
			got, err := db.ExpireOffers()
			scanExpiredOffers = scanOfferIDs
			if !tc.is(err) || errors.Is(err, ErrOfferWipeIncomplete) || got != nil {
				t.Fatalf("sweep with a failing read: %x, %v; want only the read error", got, err)
			}
			if o := mustOffer(t, db, n.IDHash); o.State != OfferOpen || !bytes.Equal(o.Salt, n.Salt[:]) {
				t.Fatalf("offer after the failed sweep: %s, salt kept %v; want it unchanged", o.State, o.Salt != nil)
			}

			got, err = db.ExpireOffers()
			if err != nil || len(got) != 1 || got[0] != n.IDHash {
				t.Fatalf("next sweep: %x, %v; want the offer", got, err)
			}
			if o := mustOffer(t, db, n.IDHash); o.State != OfferExpired || o.Salt != nil {
				t.Fatalf("offer after the next sweep: %s, salt %v", o.State, o.Salt != nil)
			}
			if in := saltOnDisk(t, dir, n.Salt); len(in) != 0 {
				t.Fatalf("wiped salt still in %v after the sweep returned", in)
			}
		})
	}
}

// TestExpireOffersCommitFailureReturnsIDs: when the sweep's COMMIT reports
// an error, the sweep cannot know whether the offers ended, so it returns
// their IDs with the error and purges the WAL. If the commit happened, the
// offers are expired and their salts gone from disk; if not, the next
// sweep returns the same IDs again: an audit record may repeat but is
// never lost. When the purge fails too, both errors are returned
// (errors.Join), still with the IDs.
func TestExpireOffersCommitFailureReturnsIDs(t *testing.T) {
	for _, tc := range []struct {
		name       string
		commit     func(*sql.Tx) error
		committed  bool
		checkpoint bool // the purge's checkpoint fails as well
	}{
		{"committed", committedButFailing, true, false},
		{"rolled back", rolledBackButFailing, false, false},
		{"committed, purge fails", committedButFailing, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := privateDir(t)
			clk := &offerClock{t: t0}
			db := openOfferDB(t, dir, clk)
			n := mustCreateOffer(t, db, false)
			m := mustCreateOffer(t, db, true)

			clk.Add(OfferLifetime)
			commitSweep = tc.commit
			t.Cleanup(func() { commitSweep = (*sql.Tx).Commit })
			if tc.checkpoint {
				replaceWalCheckpoint(t, checkpointFaults[0].run)
			}
			got, err := db.ExpireOffers()
			commitSweep = (*sql.Tx).Commit
			if !errors.Is(err, errCommit) {
				t.Fatalf("sweep with a failing commit: %v, want the commit error", err)
			}
			if tc.checkpoint != errors.Is(err, ErrOfferWipeIncomplete) || tc.checkpoint != errors.Is(err, errCheckpoint) {
				t.Fatalf("sweep error %v: purge failure reported %v, want %v", err, !tc.checkpoint, tc.checkpoint)
			}
			want := [][offerHashLen]byte{n.IDHash, m.IDHash}
			if !sameIDs(got, want) {
				t.Fatalf("sweep returned %x with the error, want %x", got, want)
			}

			if !tc.committed {
				if o := mustOffer(t, db, n.IDHash); o.State != OfferOpen {
					t.Fatalf("offer after a rolled-back sweep: %s", o.State)
				}
				again, err := db.ExpireOffers()
				if err != nil || !sameIDs(again, want) {
					t.Fatalf("next sweep: %x, %v; want %x again", again, err, want)
				}
			}
			for _, o := range []NewOffer{n, m} {
				if got := mustOffer(t, db, o.IDHash); got.State != OfferExpired || got.Salt != nil {
					t.Fatalf("offer after the sweep: %s, salt %v", got.State, got.Salt != nil)
				}
				if in := saltOnDisk(t, dir, o.Salt); tc.checkpoint == (len(in) == 0) {
					t.Fatalf("wiped salt in %v with purge failure %v", in, tc.checkpoint)
				}
			}
		})
	}
}

// sameIDs reports whether a and b hold the same IDs in any order.
func sameIDs(a, b [][offerHashLen]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for _, id := range b {
		if !slices.Contains(a, id) {
			return false
		}
	}
	return true
}

// TestExpireOffersSweepIsBounded: one sweep ends at most maxSweptOffers
// offers, the ones that expired first; the next sweep ends the rest.
func TestExpireOffersSweepIsBounded(t *testing.T) {
	dir := privateDir(t)
	clk := &offerClock{t: t0}
	db := openOfferDB(t, dir, clk)
	var ids [][offerHashLen]byte
	for range maxSweptOffers + 1 {
		ids = append(ids, mustCreateOffer(t, db, false).IDHash)
		clk.Add(time.Second)
	}

	clk.Add(OfferLifetime)
	first, err := db.ExpireOffers()
	if err != nil || !sameIDs(first, ids[:maxSweptOffers]) {
		t.Fatalf("first sweep: %d IDs, %v; want the %d oldest", len(first), err, maxSweptOffers)
	}
	rest, err := db.ExpireOffers()
	if err != nil || !sameIDs(rest, ids[maxSweptOffers:]) {
		t.Fatalf("second sweep: %x, %v; want the newest offer", rest, err)
	}
}
