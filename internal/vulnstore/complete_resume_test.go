// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
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

// While the largest allowed run completes, several other writers of
// server.db (each its own pool, default busy timeout, outside the store's
// mutex) get every write through, and every apply transaction stays inside
// the row budget: complete never holds the write lock for long. A
// single-transaction complete fails the row and transaction count checks.
func TestConcurrentWriterDuringLargestCompleteSucceeds(t *testing.T) {
	e, _, path := newPathEnv(t, ClassEvidenced)
	r, keys := largestRun(t, e)

	stats := recordApplyTx(e.st)
	stop := startWriters(t, path, 4)
	begin := time.Now()
	c, cerr := e.st.Complete(e.ctx, r.ID)
	took := time.Since(begin)
	checkWriters(t, stop())
	if cerr != nil {
		t.Fatalf("complete: %v", cerr)
	}
	t.Logf("complete of %d subjects took %v", MaxCoveredPerRun, took)
	// Each subject moves its watermark and closes one finding with its
	// history row: at least 3 rows per subject.
	checkApplyTx(t, stats(), 3*MaxCoveredPerRun/(rowBudget+applyTxOverhead))
	if c.ClosedEvidenced != MaxCoveredPerRun {
		t.Fatalf("completion = %+v", c)
	}
	for _, k := range []vulnfinding.Key{keys[0], keys[MaxCoveredPerRun/2], keys[MaxCoveredPerRun-1]} {
		e.wantState(t, k, StateFixed, ClosedByNOSInventory)
	}
}

// resumeBig is the number of findings of the big host in resumeScenario:
// more closures than one apply transaction takes.
const resumeBig = resumeRows + 100

// resumeRows is the row budget of the stores in resumeScenario, fixed so
// that the scenario's size does not follow maxApplyRows; resuming does
// not depend on the budget (the startup case of
// TestServerFinishesCompletingRun resumes with the default one).
const resumeRows = 1024

// resumeScenario: 30 hosts with one finding each and one host with
// resumeBig, none reported by a run that covers all of them. The big host
// needs several apply transactions of its own.
func resumeScenario(t *testing.T, e *env) (Run, []vulnfinding.Key) {
	t.Helper()
	e.st.applyRows = resumeRows
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
			total := counter.Calls()

			// Cut points: by statement count (planning makes most of the
			// statements, so these fall into planning or the first apply
			// transaction), and after the n-th apply transaction committed.
			type cutPoint struct{ calls, chunk int }
			cuts := []cutPoint{{calls: total / 5}, {calls: total / 2}, {calls: total * 9 / 10}, {chunk: 1}}
			if tc.class == ClassEvidenced {
				cuts = append(cuts, cutPoint{chunk: 2}) // three apply transactions
			}
			for _, cut := range cuts {
				t.Run(fmt.Sprintf("calls%d-chunk%d", cut.calls, cut.chunk), func(t *testing.T) {
					e, _, _ := newPathEnv(t, tc.class)
					r, keys := resumeScenario(t, e)
					before := states(t, e, keys)
					var ctx context.Context = newCutCtx(cut.calls)
					if cut.chunk > 0 {
						cctx, cancel := context.WithCancel(e.ctx)
						defer cancel()
						e.st.chunkDone = func(n int) {
							if n == cut.chunk {
								cancel()
							}
						}
						ctx = cctx
					}
					if _, err := e.st.Complete(ctx, r.ID); err == nil {
						t.Fatalf("complete cut at %+v of %d calls succeeded", cut, total)
					}
					e.st.chunkDone = nil
					if cut.chunk > 0 && !completing(t, e, r.ID) {
						t.Fatalf("no completing state after apply transaction %d", cut.chunk)
					}
					if _, err := e.st.CompletionOf(e.ctx, r.ID, "hermes-vuln"); !errors.Is(err, ErrRunNotRunning) {
						t.Fatalf("completion after cut: %v, want ErrRunNotRunning", err)
					}
					if completing(t, e, r.ID) {
						if _, err := e.st.SubmitBatch(e.ctx, r.ID, batchOf(1, []Subject{hostSubj("h00")})); !errors.Is(err, ErrRunNotRunning) {
							t.Fatalf("batch to a completing run: %v, want ErrRunNotRunning", err)
						}
						// Past the time limit the completing run is not aborted
						// by a batch or a retry; the retry still finishes it.
						// (ResumeCompleting and Prune finish it too, see
						// TestServerFinishesCompletingRun.)
						e.clk.Add(MaxRunDuration + time.Minute)
						if _, err := e.st.SubmitBatch(e.ctx, r.ID, batchOf(2, []Subject{hostSubj("h00")})); !errors.Is(err, ErrRunNotRunning) {
							t.Fatalf("batch to an expired completing run: %v, want ErrRunNotRunning", err)
						}
						if run, err := loadRun(e.ctx, e.st.db, r.ID); err != nil || run.state != "running" {
							t.Fatalf("expired completing run: %q, %v; want running", run.state, err)
						}
					} else if got := states(t, e, keys); !reflect.DeepEqual(got, before) {
						t.Fatalf("cut complete without completing state changed findings")
					} else if _, err := e.st.ResumeComplete(e.ctx, r.ID, "hermes-vuln"); !errors.Is(err, ErrRunNotRunning) {
						t.Fatalf("resume of a run that is not completing: %v, want ErrRunNotRunning", err)
					}
					var got Completion
					if completing(t, e, r.ID) {
						// After a restart the caller only has the run ID: it
						// resumes, and only for the run's own token.
						if _, err := e.st.ResumeComplete(e.ctx, r.ID, "other-token"); !errors.Is(err, ErrRunNotFound) {
							t.Fatalf("resume for another token: %v, want ErrRunNotFound", err)
						}
						if got, err = e.st.ResumeComplete(e.ctx, r.ID, "hermes-vuln"); err != nil {
							t.Fatalf("resume: %v", err)
						}
					} else {
						got = e.complete(t, r)
					}
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
		})
	}
}

// Another store on the same database (another process) cannot apply a
// chunk over a completing state it did not read: the progress check
// refuses it and the first store's resume still ends correctly.
func TestCompleteRefusesStaleProgress(t *testing.T) {
	e, _, path := newPathEnv(t, ClassEvidenced)
	r, keys := resumeScenario(t, e)
	ctx, cancel := context.WithCancel(e.ctx)
	defer cancel()
	e.st.chunkDone = func(int) { cancel() }
	if _, err := e.st.Complete(ctx, r.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("cut complete: %v, want context.Canceled", err)
	}
	e.st.chunkDone = nil
	if !completing(t, e, r.ID) {
		t.Fatal("no completing state after the first apply transaction")
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

// A run whose client never comes back after a complete stopped part-way is
// finished by the store's server-side entry points (cmd/nebula-server
// calls ResumeCompleting at startup and Prune periodically):
// AbortExpiredRuns, Prune (the periodic sweep), and ResumeCompleting at
// startup on a fresh store.
// It ends completed (not aborted) with the closures and the completion of
// an uninterrupted complete, and the client's late retry reads them.
func TestServerFinishesCompletingRun(t *testing.T) {
	ref, _, _ := newPathEnv(t, ClassEvidenced)
	refRun, refKeys := resumeScenario(t, ref)
	want, err := ref.st.Complete(ref.ctx, refRun.ID)
	if err != nil {
		t.Fatalf("reference complete: %v", err)
	}
	wantStates := states(t, ref, refKeys)

	for _, tc := range []struct {
		name string
		// finish runs the server side; it returns the completing runs it
		// finished (-1: not reported) and the expired runs it aborted.
		finish func(t *testing.T, e *env, path string) (finished, aborted int)
	}{
		{"abort sweep", func(t *testing.T, e *env, _ string) (int, int) {
			n, err := e.st.AbortExpiredRuns(e.ctx)
			if err != nil {
				t.Fatalf("abort expired runs: %v", err)
			}
			return -1, n
		}},
		{"prune", func(t *testing.T, e *env, _ string) (int, int) {
			res, err := e.st.Prune(e.ctx)
			if err != nil {
				t.Fatalf("prune: %v", err)
			}
			return res.ResumedRuns, res.AbortedRuns
		}},
		{"startup", func(t *testing.T, e *env, path string) (int, int) {
			// A restart: a new store on the same database.
			db2, err := serverdb.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { db2.Close() })
			st2 := openStore(t, db2, e.clk, &cancelClassifier{class: ClassEvidenced})
			n, err := st2.ResumeCompleting(e.ctx)
			if err != nil {
				t.Fatalf("resume completing: %v", err)
			}
			return n, 0
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _, path := newPathEnv(t, ClassEvidenced)
			// The scenario's seed run stays running: the sweep aborts it.
			r, keys := resumeScenario(t, e)
			ctx, cancel := context.WithCancel(e.ctx)
			defer cancel()
			e.st.chunkDone = func(int) { cancel() }
			if _, err := e.st.Complete(ctx, r.ID); !errors.Is(err, context.Canceled) {
				t.Fatalf("cut complete: %v, want context.Canceled", err)
			}
			e.st.chunkDone = nil
			if !completing(t, e, r.ID) {
				t.Fatal("no completing state after the first apply transaction")
			}
			e.clk.Add(MaxRunDuration + time.Minute)

			finished, aborted := tc.finish(t, e, path)
			if finished != -1 && finished != 1 {
				t.Fatalf("finished %d completing runs, want 1", finished)
			}
			if tc.name != "startup" && aborted != 1 {
				t.Fatalf("aborted %d runs, want 1", aborted)
			}
			run, err := loadRun(e.ctx, e.st.db, r.ID)
			if err != nil || run.state != "completed" || completing(t, e, r.ID) {
				t.Fatalf("completing run after the server finished it: %q, %v", run.state, err)
			}
			if got := states(t, e, keys); !reflect.DeepEqual(got, wantStates) {
				t.Fatal("final states differ from an uninterrupted complete")
			}
			// The client's late retry reads the saved completion.
			if _, err := e.st.Complete(e.ctx, r.ID); !errors.Is(err, ErrRunNotRunning) {
				t.Fatalf("late complete: %v, want ErrRunNotRunning", err)
			}
			if _, err := e.st.ResumeComplete(e.ctx, r.ID, "hermes-vuln"); !errors.Is(err, ErrRunNotRunning) {
				t.Fatalf("late resume: %v, want ErrRunNotRunning", err)
			}
			got, err := e.st.CompletionOf(e.ctx, r.ID, "hermes-vuln")
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("saved completion = %+v, %v; want %+v", got, err, want)
			}
			// Nothing is left to finish.
			if n, err := e.st.ResumeCompleting(e.ctx); err != nil || n != 0 {
				t.Fatalf("second resume = %d, %v; want 0", n, err)
			}
		})
	}
}

// A sweep (Prune) whose context ends while it resumes a completing run
// returns the context error and leaves the run completing, not aborted and
// not half applied; the next sweep finishes it with the result of an
// uninterrupted complete. This is the bound the caller relies on: a
// deadline on the sweep's context limits how long it holds the store.
func TestSweepDeadlineLeavesCompletingRunResumable(t *testing.T) {
	e, _, _ := newPathEnv(t, ClassEvidenced)
	r, keys := resumeScenario(t, e)
	cut := func() context.Context {
		ctx, cancel := context.WithCancel(e.ctx)
		t.Cleanup(cancel)
		e.st.chunkDone = func(int) { cancel() }
		return ctx
	}
	// The client's complete stops after its first apply transaction.
	if _, err := e.st.Complete(cut(), r.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("cut complete: %v, want context.Canceled", err)
	}
	e.clk.Add(MaxRunDuration + time.Minute)
	// The sweep's context ends after the resume's first apply transaction
	// (the scenario has three).
	res, err := e.st.Prune(cut())
	e.st.chunkDone = nil
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cut sweep: %+v, %v; want context.Canceled", res, err)
	}
	if res.ResumedRuns != 0 {
		t.Fatalf("cut sweep resumed %d runs, want 0", res.ResumedRuns)
	}
	run, err := loadRun(e.ctx, e.st.db, r.ID)
	if err != nil || run.state != "running" || !completing(t, e, r.ID) {
		t.Fatalf("run after a cut sweep: %q, %v; want running and completing", run.state, err)
	}
	// The next sweep finishes it with every closure (the uninterrupted
	// result of this scenario, see
	// TestCompleteCancelledDuringApplyResumesToTheSameResult).
	res, err = e.st.Prune(e.ctx)
	if err != nil || res.ResumedRuns != 1 {
		t.Fatalf("second sweep = %+v, %v; want 1 resumed run", res, err)
	}
	if run, err := loadRun(e.ctx, e.st.db, r.ID); err != nil || run.state != "completed" {
		t.Fatalf("run after the second sweep: %q, %v; want completed", run.state, err)
	}
	got, err := e.st.CompletionOf(e.ctx, r.ID, "hermes-vuln")
	if err != nil || got.ClosedEvidenced != 30+resumeBig {
		t.Fatalf("saved completion = %+v, %v; want %d closed", got, err, 30+resumeBig)
	}
	for _, k := range keys {
		e.wantState(t, k, StateFixed, ClosedByNOSInventory)
	}
}
