// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
)

// newPathEnv is newCancelEnv that also returns the database path, so a test
// can open a second connection pool as another writer of server.db.
func newPathEnv(t *testing.T, class Class) (*env, *cancelClassifier, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.db")
	db, err := serverdb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	clk := &clock{t: t0}
	cls := &cancelClassifier{class: class}
	return &env{st: openStore(t, db, clk, cls), clk: clk, ctx: context.Background()}, cls, path
}

// completing reports whether the run has a durable completing state.
func completing(t *testing.T, e *env, runID string) bool {
	t.Helper()
	run, err := loadRun(e.ctx, e.st.db, runID)
	if err != nil {
		t.Fatal(err)
	}
	return parseReport(run.reportRaw).Completing != nil
}

// While the largest allowed run completes, another writer of server.db
// (its own pool, default busy timeout, outside the store's mutex) gets
// every write through: complete never holds the write lock for long.
func TestConcurrentWriterDuringLargestCompleteSucceeds(t *testing.T) {
	e, _, path := newPathEnv(t, ClassEvidenced)
	r, keys := largestRun(t, e)

	other, err := serverdb.OpenWithOptions(path, serverdb.Options{BusyTimeout: serverdb.DefaultBusyTimeout})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.Exec(`CREATE TABLE other_writer (n INTEGER NOT NULL, at INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	var wg sync.WaitGroup
	var writes int
	var slowest time.Duration
	var werr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			begin := time.Now()
			_, err := other.Exec(`INSERT INTO other_writer (n, at) VALUES (?, ?)`, writes, begin.UnixNano())
			if err != nil {
				werr = err
				return
			}
			writes++
			slowest = max(slowest, time.Since(begin))
			time.Sleep(2 * time.Millisecond)
		}
	}()
	begin := time.Now()
	c, cerr := e.st.Complete(e.ctx, r.ID)
	took := time.Since(begin)
	close(done)
	wg.Wait()
	if cerr != nil {
		t.Fatalf("complete: %v", cerr)
	}
	t.Logf("complete of %d subjects took %v; other writer: %d writes, slowest %v", MaxCoveredPerRun, took, writes, slowest)
	if werr != nil {
		t.Fatalf("other writer failed during complete after %d writes: %v", writes, werr)
	}
	if writes == 0 {
		t.Fatal("other writer wrote nothing during complete")
	}
	if slowest >= serverdb.DefaultBusyTimeout {
		t.Fatalf("other writer waited %v, busy timeout %v", slowest, serverdb.DefaultBusyTimeout)
	}
	if c.ClosedEvidenced != MaxCoveredPerRun {
		t.Fatalf("completion = %+v", c)
	}
	for _, k := range []vulnfinding.Key{keys[0], keys[MaxCoveredPerRun/2], keys[MaxCoveredPerRun-1]} {
		e.wantState(t, k, StateFixed, ClosedByNOSInventory)
	}
}

// resumeBig is the number of findings of the big host in resumeScenario:
// more closures than one apply transaction takes.
const resumeBig = maxApplyWrites + 100

// resumeScenario: 30 hosts with one finding each and one host with
// resumeBig, none reported by a run that covers all of them. The big host
// needs several apply transactions of its own.
func resumeScenario(t *testing.T, e *env) (Run, []vulnfinding.Key) {
	t.Helper()
	var keys []vulnfinding.Key
	var covered []Subject
	for i := 0; i < 30; i++ {
		h := fmt.Sprintf("h%02d", i)
		for _, it := range e.seed(t, h, 1) {
			keys = append(keys, it.Finding.Key)
		}
		covered = append(covered, hostSubj(h))
	}
	big := make([]Item, resumeBig)
	for i := range big {
		big[i] = item(t, "big", cve(i))
		keys = append(keys, big[i].Finding.Key)
	}
	seedRun := e.start(t)
	for b := 0; b*MaxFindingsPerBatch < len(big); b++ {
		e.submit(t, seedRun, int64(b), nil, big[b*MaxFindingsPerBatch:min(len(big), (b+1)*MaxFindingsPerBatch)]...)
	}
	covered = append(covered, hostSubj("big"))
	r := e.start(t)
	e.submit(t, r, 0, covered)
	return r, keys
}

// A complete cancelled after part of its closures committed leaves a
// durable completing state: the run takes no batches, is not aborted at
// its time limit, and the retry resumes and ends with the same findings
// and the same completion as an uninterrupted complete.
func TestCompleteCancelledDuringApplyResumesToTheSameResult(t *testing.T) {
	for _, tc := range []struct {
		name  string
		class Class
	}{
		{"evidenced", ClassEvidenced}, // closures
		{"guarded", ClassUnconfirmed}, // the run guard trips: holds
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref, _, _ := newPathEnv(t, tc.class)
			refRun, refKeys := resumeScenario(t, ref)
			counter := newCutCtx(0)
			want, err := ref.st.Complete(counter, refRun.ID)
			if err != nil {
				t.Fatalf("reference complete: %v", err)
			}
			if tc.class == ClassEvidenced && want.ClosedEvidenced != 30+resumeBig || tc.class == ClassUnconfirmed && (!want.RunGuard || want.Held[HoldRunGuard] != 30+resumeBig) {
				t.Fatalf("reference completion = %+v", want)
			}
			wantStates := states(t, ref, refKeys)
			total := counter.calls

			partial := false
			// Planning makes most of the statements; the last cut points
			// fall into the apply transactions after the first.
			for _, cut := range []int{total / 5, total / 2, total * 9 / 10, total * 99 / 100, total - 100, total - 40} {
				t.Run(fmt.Sprintf("cut%d", cut), func(t *testing.T) {
					e, _, _ := newPathEnv(t, tc.class)
					r, keys := resumeScenario(t, e)
					before := states(t, e, keys)
					if _, err := e.st.Complete(newCutCtx(cut), r.ID); err == nil {
						t.Fatalf("complete cut at %d of %d succeeded", cut, total)
					}
					if _, err := e.st.CompletionOf(e.ctx, r.ID, "hermes-vuln"); !errors.Is(err, ErrRunNotRunning) {
						t.Fatalf("completion after cut: %v, want ErrRunNotRunning", err)
					}
					if completing(t, e, r.ID) {
						partial = true
						if _, err := e.st.SubmitBatch(e.ctx, r.ID, batchOf(1, []Subject{hostSubj("h00")})); !errors.Is(err, ErrRunNotRunning) {
							t.Fatalf("batch to a completing run: %v, want ErrRunNotRunning", err)
						}
						// Past the time limit the completing run is not aborted;
						// the retry still finishes it.
						e.clk.Add(MaxRunDuration + time.Minute)
						if _, err := e.st.AbortExpiredRuns(e.ctx); err != nil {
							t.Fatalf("abort expired runs: %v", err)
						}
						if run, err := loadRun(e.ctx, e.st.db, r.ID); err != nil || run.state != "running" {
							t.Fatalf("completing run after abort of expired runs: %q, %v; want running", run.state, err)
						}
					} else if got := states(t, e, keys); !reflect.DeepEqual(got, before) {
						t.Fatalf("cut complete without completing state changed findings")
					}
					got := e.complete(t, r)
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("resumed completion = %+v, want %+v", got, want)
					}
					if gotStates := states(t, e, keys); !reflect.DeepEqual(gotStates, wantStates) {
						t.Fatalf("final states differ from an uninterrupted complete")
					}
					saved, err := e.st.CompletionOf(e.ctx, r.ID, "hermes-vuln")
					if err != nil || !reflect.DeepEqual(saved, want) {
						t.Fatalf("saved completion = %+v, %v; want %+v", saved, err, want)
					}
					if completing(t, e, r.ID) {
						t.Fatal("completed run keeps its completing state")
					}
					if _, err := e.st.Complete(e.ctx, r.ID); !errors.Is(err, ErrRunNotRunning) {
						t.Fatalf("complete after completion: %v, want ErrRunNotRunning", err)
					}
				})
			}
			if !partial {
				t.Fatal("no cut point left a partly applied complete; the run fits one write transaction")
			}
		})
	}
}

// Another store on the same database (another process) cannot apply a
// chunk over a completing state it did not read: the progress check
// refuses it and the first store's resume still ends correctly.
func TestCompleteRefusesStaleProgress(t *testing.T) {
	e, _, path := newPathEnv(t, ClassEvidenced)
	r, keys := resumeScenario(t, e)
	counter := newCutCtx(0)
	ref, _, _ := newPathEnv(t, ClassEvidenced)
	refRun, _ := resumeScenario(t, ref)
	if _, err := ref.st.Complete(counter, refRun.ID); err != nil {
		t.Fatal(err)
	}
	// Planning makes most of the statements; cut late, in the apply phase.
	for pct := 85; !completing(t, e, r.ID); pct++ {
		if pct == 100 {
			t.Fatal("no cut point left a completing state")
		}
		if _, err := e.st.Complete(newCutCtx(counter.calls*pct/100), r.ID); err == nil {
			t.Fatalf("complete cut at %d%% succeeded", pct)
		}
	}
	run, err := loadRun(e.ctx, e.st.db, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	prog := parseReport(run.reportRaw).Completing
	// A second process resumes and finishes the run.
	db2, err := serverdb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	st2 := openStore(t, db2, e.clk, &cancelClassifier{class: ClassEvidenced})
	c, err := st2.Complete(e.ctx, r.ID)
	if err != nil || c.ClosedEvidenced != 30+resumeBig {
		t.Fatalf("second store complete = %+v, %v", c, err)
	}
	// A chunk planned on the old progress is refused.
	tx, err := e.st.writeTx(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := checkProgress(e.ctx, tx, r.ID, prog); !errors.Is(err, ErrRunNotRunning) {
		t.Fatalf("stale progress check: %v, want ErrRunNotRunning", err)
	}
	tx.Rollback()
	for _, k := range keys {
		e.wantState(t, k, StateFixed, ClosedByNOSInventory)
	}
}
