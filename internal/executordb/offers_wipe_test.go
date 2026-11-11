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
		name    string
		prep    func(*DB, [32]byte) error
		wipe    func(*DB, *offerClock, [32]byte) ([][offerHashLen]byte, error)
		want    OfferState
		scanErr bool // the sweep's scan fails too
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
		{"expiry sweep with scan failure", nil, func(db *DB, clk *offerClock, _ [32]byte) ([][offerHashLen]byte, error) {
			clk.Add(OfferLifetime)
			scanExpiredOffers = failingScan
			defer func() { scanExpiredOffers = scanOfferIDs }()
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
			if tc.scanErr != errors.Is(err, errScan) {
				t.Fatalf("wipe error %v: scan failure reported %v, want %v", err, !tc.scanErr, tc.scanErr)
			}
			msg := err.Error()
			if strings.Contains(msg, hex.EncodeToString(n.Salt[:])) || strings.Contains(msg, string(n.Salt[:])) ||
				strings.Contains(msg, fmt.Sprintf("%x", n.Salt[:4])) {
				t.Fatalf("error carries the salt: %q", msg)
			}
			if tc.want == OfferExpired && !tc.scanErr && (len(got) != 1 || got[0] != n.IDHash) {
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
			if err := bdb.sql.Close(); err != nil {
				t.Fatal(err)
			}
			reopened := openOfferDB(t, dir, clk)
			if o := mustOffer(t, reopened, n.IDHash); o.State != tc.want || o.Salt != nil {
				t.Fatalf("offer after restart: %s, salt %v", o.State, o.Salt != nil)
			}
			if in := saltOnDisk(t, dir, n.Salt); len(in) != 0 {
				t.Fatalf("wiped salt in %v after restart", in)
			}
		})
	}
}

// TestExpireOffersPurgesAfterScanFailure: if reading the swept IDs fails
// after the UPDATE committed, the sweep still removes the wiped salts from
// the WAL before it returns its error.
func TestExpireOffersPurgesAfterScanFailure(t *testing.T) {
	dir := privateDir(t)
	clk := &offerClock{t: t0}
	db := openOfferDB(t, dir, clk)
	n := mustCreateOffer(t, db, false)
	if in := saltOnDisk(t, dir, n.Salt); len(in) == 0 {
		t.Fatal("live salt not found on disk: the scan proves nothing")
	}

	clk.Add(OfferLifetime)
	scanExpiredOffers = failingScan
	t.Cleanup(func() { scanExpiredOffers = scanOfferIDs })
	got, err := db.ExpireOffers()
	if !errors.Is(err, errScan) || errors.Is(err, ErrOfferWipeIncomplete) || got != nil {
		t.Fatalf("sweep with a failing scan: %x, %v; want only the scan error", got, err)
	}
	if o := mustOffer(t, db, n.IDHash); o.State != OfferExpired || o.Salt != nil {
		t.Fatalf("offer after sweep: %s, salt %v", o.State, o.Salt != nil)
	}
	if in := saltOnDisk(t, dir, n.Salt); len(in) != 0 {
		t.Fatalf("wiped salt still in %v after the failed sweep returned", in)
	}
}
