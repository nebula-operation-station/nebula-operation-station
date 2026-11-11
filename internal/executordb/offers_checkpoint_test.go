// SPDX-License-Identifier: AGPL-3.0-or-later

package executordb

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
)

// errCheckpoint stands for a failed PRAGMA wal_checkpoint query.
var errCheckpoint = errors.New("injected checkpoint failure")

// checkpointFault is one way the checkpoint can fail: the query fails, or
// SQLite reports it as blocked.
type checkpointFault struct {
	name string
	run  func(*sql.DB) (int64, int64, int64, error)
	// is reports whether err is the failure this fault injects.
	is func(error) bool
}

var checkpointFaults = []checkpointFault{
	{"query error",
		func(*sql.DB) (int64, int64, int64, error) { return 0, 0, 0, errCheckpoint },
		func(err error) bool { return errors.Is(err, errCheckpoint) }},
	{"blocked",
		func(*sql.DB) (int64, int64, int64, error) { return 1, 7, 3, nil },
		func(err error) bool {
			return err != nil && strings.Contains(err.Error(), "wal checkpoint blocked (3 of 7 frames copied)")
		}},
}

// replaceWalCheckpoint swaps the checkpoint seam until the returned restore
// function (or the test's cleanup) puts the real one back.
func replaceWalCheckpoint(t *testing.T, f func(*sql.DB) (int64, int64, int64, error)) (restore func()) {
	t.Helper()
	orig := walCheckpoint
	walCheckpoint = f
	restore = func() { walCheckpoint = orig }
	t.Cleanup(restore)
	return restore
}

// TestOpenCheckpointFailureClosesDB: when the checkpoint at the end of
// Open fails, in either branch, Open returns that error and no DB, and it
// has closed the SQLite handle and released the directory lock, so the
// next Open on the same directory succeeds.
func TestOpenCheckpointFailureClosesDB(t *testing.T) {
	for _, f := range checkpointFaults {
		t.Run(f.name, func(t *testing.T) {
			dir := privateDir(t)
			clk := &offerClock{t: t0}
			db := openOfferDB(t, dir, clk)
			n := mustCreateOffer(t, db, false)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			var seen []*sql.DB
			restore := replaceWalCheckpoint(t, func(sdb *sql.DB) (int64, int64, int64, error) {
				seen = append(seen, sdb)
				return f.run(sdb)
			})
			got, err := open(dir, clk.Now)
			restore()
			if got != nil {
				got.Close()
				t.Fatal("Open returned a DB although its checkpoint failed")
			}
			if !f.is(err) {
				t.Fatalf("Open with a failing checkpoint: %v, want the injected failure", err)
			}
			if !strings.HasPrefix(err.Error(), "executordb: wal checkpoint") {
				t.Fatalf("Open error %q lacks context", err)
			}
			if len(seen) != 1 {
				t.Fatalf("Open ran %d checkpoints, want 1", len(seen))
			}
			if perr := seen[0].Ping(); perr == nil || !strings.Contains(perr.Error(), "database is closed") {
				t.Fatalf("SQLite handle after failed Open: ping %v, want it closed", perr)
			}

			// The directory flock and SQLite's exclusive lock are released.
			reopened := openOfferDB(t, dir, clk)
			if o := mustOffer(t, reopened, n.IDHash); o.State != OfferOpen {
				t.Fatalf("offer after reopen: %s", o.State)
			}
		})
	}
}

// TestOfferWipeCheckpointFailure: when the checkpoint after a committed
// wipe fails, in either branch, every wiping call returns
// ErrOfferWipeIncomplete wrapping that failure; the final state and the
// NULL salt stay committed (the sweep still returns the IDs it ended), and
// the next Open removes the salt from disk.
func TestOfferWipeCheckpointFailure(t *testing.T) {
	wipes := []struct {
		name string
		prep func(*DB, [32]byte) error
		wipe func(*DB, *offerClock, [32]byte) ([][offerHashLen]byte, error)
		want OfferState
	}{
		{"revoke", nil, func(db *DB, _ *offerClock, id [32]byte) ([][offerHashLen]byte, error) {
			return nil, db.EndOffer(id, OfferOpen, OfferRevoked)
		}, OfferRevoked},
		{"complete", proposeOffer, func(db *DB, _ *offerClock, id [32]byte) ([][offerHashLen]byte, error) {
			return nil, db.CompleteOffer(id)
		}, OfferEnrolled},
		{"expiry sweep", nil, func(db *DB, clk *offerClock, _ [32]byte) ([][offerHashLen]byte, error) {
			clk.Add(OfferLifetime)
			return db.ExpireOffers()
		}, OfferExpired},
	}
	for _, f := range checkpointFaults {
		for _, w := range wipes {
			t.Run(f.name+"/"+w.name, func(t *testing.T) {
				dir := privateDir(t)
				clk := &offerClock{t: t0}
				db := openOfferDB(t, dir, clk)
				n := mustCreateOffer(t, db, false)
				if w.prep != nil {
					if err := w.prep(db, n.IDHash); err != nil {
						t.Fatal(err)
					}
				}

				restore := replaceWalCheckpoint(t, f.run)
				got, err := w.wipe(db, clk, n.IDHash)
				restore()
				if !errors.Is(err, ErrOfferWipeIncomplete) || !f.is(err) {
					t.Fatalf("wipe with a failing checkpoint: %v, want ErrOfferWipeIncomplete with the injected failure", err)
				}
				if w.want == OfferExpired && (len(got) != 1 || got[0] != n.IDHash) {
					t.Fatalf("sweep returned %x with the error, want the expired offer", got)
				}
				if o := mustOffer(t, db, n.IDHash); o.State != w.want || o.Salt != nil {
					t.Fatalf("offer after incomplete wipe: %s, salt %v", o.State, o.Salt != nil)
				}

				// Copy the files while the DB is open, so that its Close
				// cannot checkpoint them first: the restart has to.
				crash := copyCrashImage(t, dir)
				if in := saltOnDisk(t, crash, n.Salt); len(in) == 0 {
					t.Fatal("salt not on disk after the failed checkpoint: the restart proves nothing")
				}
				reopened := openOfferDB(t, crash, clk)
				if o := mustOffer(t, reopened, n.IDHash); o.State != w.want || o.Salt != nil {
					t.Fatalf("offer after restart: %s, salt %v", o.State, o.Salt != nil)
				}
				if in := saltOnDisk(t, crash, n.Salt); len(in) != 0 {
					t.Fatalf("wiped salt in %v after restart", in)
				}
			})
		}
	}
}
