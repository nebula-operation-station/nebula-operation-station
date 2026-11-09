// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// applyTxOverhead is what an apply transaction writes besides its row
// budget: the lock row, the run report, the run state and one closure
// that starts below the budget and ends above it.
const applyTxOverhead = 4

// rowBudget is the row budget the tests hold an apply transaction to,
// fixed here so that raising maxApplyRows (up to one transaction for the
// whole complete) fails them instead of loosening them.
const rowBudget = 1024

// applyTxStat is one committed apply transaction: the rows it changed
// (SQLite's own count, independent of the store's budget) and how long it
// held the write lock.
type applyTxStat struct {
	rows int64
	held time.Duration
}

// recordApplyTx makes the store report every apply transaction.
func recordApplyTx(st *Store) func() []applyTxStat {
	var mu sync.Mutex
	var stats []applyTxStat
	st.applyDone = func(rows int64, held time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		stats = append(stats, applyTxStat{rows: rows, held: held})
	}
	return func() []applyTxStat {
		mu.Lock()
		defer mu.Unlock()
		return append([]applyTxStat(nil), stats...)
	}
}

// writerStat is what one concurrent writer saw.
type writerStat struct {
	writes  int
	slowest time.Duration
	err     error
}

// startWriters starts n writers of server.db, each on its own connection
// pool with the default busy timeout and outside the store's mutex, that
// insert rows in a loop. The returned stop ends them and returns what each
// saw.
func startWriters(t *testing.T, path string, n int) func() []writerStat {
	t.Helper()
	dbs := make([]*sql.DB, n)
	for i := range dbs {
		db, err := serverdb.OpenWithOptions(path, serverdb.Options{BusyTimeout: serverdb.DefaultBusyTimeout})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		dbs[i] = db
	}
	if _, err := dbs[0].Exec(`CREATE TABLE IF NOT EXISTS other_writer (w INTEGER NOT NULL, n INTEGER NOT NULL, at INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	stats := make([]writerStat, n)
	var wg sync.WaitGroup
	for i := range dbs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st := &stats[i]
			for {
				select {
				case <-done:
					return
				default:
				}
				begin := time.Now()
				if _, err := dbs[i].Exec(`INSERT INTO other_writer (w, n, at) VALUES (?, ?, ?)`, i, st.writes, begin.UnixNano()); err != nil {
					st.err = err
					return
				}
				st.writes++
				st.slowest = max(st.slowest, time.Since(begin))
				// Paced like the other writers of server.db (sessions,
				// audit, ingest), not a tight loop: in a tight loop the
				// writers would starve each other, complete or not.
				time.Sleep(time.Duration(20+7*i) * time.Millisecond)
			}
		}(i)
	}
	return func() []writerStat {
		close(done)
		wg.Wait()
		return stats
	}
}

// checkWriters fails the test unless every writer wrote and none waited
// for the lock up to its busy timeout.
func checkWriters(t *testing.T, stats []writerStat) {
	t.Helper()
	for i, w := range stats {
		t.Logf("writer %d: %d writes, slowest %v", i, w.writes, w.slowest)
		if w.err != nil {
			t.Errorf("writer %d failed during complete after %d writes: %v", i, w.writes, w.err)
			continue
		}
		if w.writes == 0 {
			t.Errorf("writer %d wrote nothing during complete", i)
		}
		if w.slowest >= serverdb.DefaultBusyTimeout {
			t.Errorf("writer %d waited %v, busy timeout %v", i, w.slowest, serverdb.DefaultBusyTimeout)
		}
	}
}

// checkApplyTx fails the test unless every apply transaction stayed inside
// the row budget and the complete took at least minTx of them. A complete
// in one write transaction, or one bounded by statements rather than
// rows, fails it.
func checkApplyTx(t *testing.T, stats []applyTxStat, minTx int) {
	t.Helper()
	var rows int64
	var longest time.Duration
	for i, s := range stats {
		rows += s.rows
		longest = max(longest, s.held)
		if s.rows > rowBudget+applyTxOverhead {
			t.Errorf("apply transaction %d changed %d rows, budget %d", i, s.rows, rowBudget)
		}
	}
	t.Logf("%d apply transactions, %d rows, longest lock hold %v", len(stats), rows, longest)
	if len(stats) < minTx {
		t.Errorf("%d apply transactions, want at least %d", len(stats), minTx)
	}
	if longest >= serverdb.DefaultBusyTimeout/2 {
		t.Errorf("an apply transaction held the write lock %v", longest)
	}
}

// seedSupersededHolds gives host n held closures of an older run (what a
// guard trip on a run of that size leaves), on closed findings with an
// empty record so that a later run plans nothing for them and only drops
// the holds.
func seedSupersededHolds(t *testing.T, e *env, host string, n int) {
	t.Helper()
	begin := time.Now()
	defer func() { t.Logf("seeded %d superseded holds in %v", n, time.Since(begin)) }()
	items := e.seed(t, host, 1)
	subj := hostSubj(host).String()
	var runID string
	var seq int64
	if err := e.st.db.QueryRow(`SELECT id, run_seq FROM vuln_runs ORDER BY run_seq DESC LIMIT 1`).Scan(&runID, &seq); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.db.Exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?)
		INSERT INTO vuln_findings (finding_key, subject, subject_kind, record, nos_checked, state, closed_by, closed_at,
			state_run_seq, episode_opened_at, episode_opened_run_seq, episode_peak_tier, first_seen_at, last_seen_at, updated_at)
		SELECT randomblob(32), subject, subject_kind, '{}', nos_checked, 'fixed', 'nos_inventory', updated_at,
			state_run_seq, episode_opened_at, episode_opened_run_seq, episode_peak_tier, first_seen_at, last_seen_at, updated_at
		FROM vuln_findings, n WHERE finding_key = ?`, n-1, items[0].Finding.Key[:]); err != nil {
		t.Fatalf("seed findings: %v", err)
	}
	res, err := e.st.db.Exec(`INSERT INTO vuln_held_closures (run_id, finding_key, run_seq, subject, reason, finding_rev, created_at)
		SELECT ?, finding_key, ?, subject, 'run_guard', rev, updated_at FROM vuln_findings WHERE subject = ?`, runID, seq, subj)
	if err != nil {
		t.Fatalf("seed holds: %v", err)
	}
	if got, _ := res.RowsAffected(); got != int64(n) {
		t.Fatalf("seeded %d holds, want %d", got, n)
	}
}

func heldOn(t *testing.T, e *env, host string) int {
	t.Helper()
	var n int
	if err := e.st.db.QueryRow(`SELECT COUNT(*) FROM vuln_held_closures WHERE subject = ?`, hostSubj(host).String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A run covering a subject with MaxFindingsPerRun superseded holds (fewer
// under the race detector, see supersededHoldsAtScale) drops them in
// apply transactions bounded by rows, not in one statement, and several
// other writers of server.db get every write through meanwhile. A
// complete in one transaction, or bounded by statements, fails it.
func TestCompleteDropsSupersededHoldsInRowBoundedTransactions(t *testing.T) {
	e, _, path := newPathEnv(t, ClassEvidenced)
	holds := supersededHoldsAtScale
	seedSupersededHolds(t, e, "big", holds)
	var covered []Subject
	var keys []vulnfinding.Key
	for i := 0; i < 50; i++ {
		h := fmt.Sprintf("h%03d", i)
		for _, it := range e.seed(t, h, 1) {
			keys = append(keys, it.Finding.Key)
		}
		covered = append(covered, hostSubj(h))
	}
	covered = append(covered, hostSubj("big"))
	r := e.start(t)
	e.submit(t, r, 0, covered)

	stats := recordApplyTx(e.st)
	stop := startWriters(t, path, 4)
	c, err := e.st.Complete(e.ctx, r.ID)
	checkWriters(t, stop())
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	checkApplyTx(t, stats(), holds/(rowBudget+applyTxOverhead))
	if c.ClosedEvidenced != 50+1 {
		t.Fatalf("completion = %+v", c)
	}
	if n := heldOn(t, e, "big"); n != 0 {
		t.Fatalf("%d superseded holds left", n)
	}
	for _, k := range keys {
		e.wantState(t, k, StateFixed, ClosedByNOSInventory)
	}
}

// A complete cut while it drops superseded holds resumes the drop and
// ends with the same completion.
func TestCompleteCutDuringHoldDropResumes(t *testing.T) {
	e, _, _ := newPathEnv(t, ClassEvidenced)
	const holds = 5*maxApplyRows + 100
	seedSupersededHolds(t, e, "big", holds)
	r := e.start(t)
	e.submit(t, r, 0, []Subject{hostSubj("big")})
	cut := 0
	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	e.st.chunkDone = func(n int) {
		if cut = n; n == 3 {
			cancel()
		}
	}
	if _, err := e.st.Complete(ctx, r.ID); err == nil {
		t.Fatal("cut complete succeeded")
	}
	e.st.chunkDone = nil
	if cut != 3 || !completing(t, e, r.ID) {
		t.Fatalf("cut after %d transactions, completing %v", cut, completing(t, e, r.ID))
	}
	if n := heldOn(t, e, "big"); n == 0 || n == holds {
		t.Fatalf("%d holds left after a cut drop", n)
	}
	got, err := e.st.ResumeComplete(e.ctx, r.ID, "hermes-vuln")
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	want := Completion{ClosedEvidenced: 1, Held: map[HoldReason]int{}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("completion = %+v, want %+v", got, want)
	}
	if n := heldOn(t, e, "big"); n != 0 {
		t.Fatalf("%d superseded holds left", n)
	}
}
