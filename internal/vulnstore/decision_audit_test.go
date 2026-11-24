// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnstore

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/auditlog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

// audit returns the audit log on the store's database, as the server
// passes it.
func (e *env) audit() *auditlog.Store { return auditlog.New(e.st.db, true) }

// failAppend runs the decision through the real audit log, but every
// audit line fails.
type failAppend struct{ log *auditlog.Store }

func (f failAppend) WithTx(ctx context.Context, fn func(*sql.Tx, func(string, map[string]string) error) error) error {
	return f.log.WithTx(ctx, func(tx *sql.Tx, _ func(string, map[string]string) error) error {
		return fn(tx, func(string, map[string]string) error { return errors.New("disk full") })
	})
}

// decisionCase is one maintainer decision: run applies it through audit,
// applied counts the stored decision rows of its kind.
type decisionCase struct {
	name    string
	kind    string
	run     func(e *env, audit DecisionAuditor) error
	applied func(t *testing.T, e *env) int
}

func countRows(t *testing.T, e *env, q string, args ...any) int {
	t.Helper()
	var n int
	if err := e.st.db.QueryRowContext(e.ctx, q, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// heldEnv seeds one finding on web01 whose closure is held, and returns
// the run that held it.
func heldEnv(t *testing.T) (*env, Run, []Item) {
	t.Helper()
	e := newEnv(t)
	items := e.seed(t, "web01", 1, withKEV("2026-01-01"))
	r := e.start(t)
	e.submit(t, r, 0, []Subject{hostSubj("web01")})
	e.complete(t, r)
	if h, err := e.st.Holds(e.ctx, items[0].Finding.Key); err != nil || len(h) != 1 {
		t.Fatalf("fixture: holds %+v %v", h, err)
	}
	return e, r, items
}

func decisionCases(t *testing.T) []func() (*env, decisionCase) {
	return []func() (*env, decisionCase){
		func() (*env, decisionCase) {
			e := newEnv(t)
			k := e.seed(t, "web01", 1)[0].Finding.Key
			return e, decisionCase{
				name: "SetAcceptedRisk", kind: AuditVulnAcceptedRisk,
				run: func(e *env, a DecisionAuditor) error {
					return e.st.SetAcceptedRisk(e.ctx, k, AcceptRisk{Approver: "admin", Reason: "isolated host", BasisVersion: "1.0-1"}, a)
				},
				applied: func(t *testing.T, e *env) int {
					return countRows(t, e, `SELECT COUNT(*) FROM vuln_findings WHERE state = 'accepted_risk'`)
				},
			}
		},
		func() (*env, decisionCase) {
			e := newEnv(t)
			k := e.seed(t, "web01", 1)[0].Finding.Key
			return e, decisionCase{
				name: "SetFalsePositive", kind: AuditVulnFalsePositive,
				run: func(e *env, a DecisionAuditor) error {
					return e.st.SetFalsePositive(e.ctx, k, MarkFalsePositive{By: "admin", Category: CategoryBackportFixed, Reason: "patched", BasisVersion: "1.0-1"}, a)
				},
				applied: func(t *testing.T, e *env) int {
					return countRows(t, e, `SELECT COUNT(*) FROM vuln_findings WHERE state = 'false_positive'`)
				},
			}
		},
		func() (*env, decisionCase) {
			e, r, items := heldEnv(t)
			k := items[0].Finding.Key
			return e, decisionCase{
				name: "ConfirmHeld", kind: AuditVulnHoldConfirmed,
				run: func(e *env, a DecisionAuditor) error {
					_, err := e.st.ConfirmHeld(e.ctx, r.ID, k, "admin", "checked by hand", a)
					return err
				},
				applied: func(t *testing.T, e *env) int {
					return countRows(t, e, `SELECT COUNT(*) FROM vuln_findings WHERE state = 'fixed' AND closed_admin = 'admin'`) +
						countRows(t, e, `SELECT 1 - COUNT(*) FROM vuln_held_closures`)
				},
			}
		},
		func() (*env, decisionCase) {
			e, r, items := heldEnv(t)
			k := items[0].Finding.Key
			return e, decisionCase{
				name: "DiscardHeld", kind: AuditVulnHoldDiscarded,
				run: func(e *env, a DecisionAuditor) error {
					return e.st.DiscardHeld(e.ctx, r.ID, k, "admin", a)
				},
				applied: func(t *testing.T, e *env) int {
					return countRows(t, e, `SELECT 1 - COUNT(*) FROM vuln_held_closures`)
				},
			}
		},
		func() (*env, decisionCase) {
			e := newEnv(t)
			_, d, r := regressOSV(t, e, 1, e.clk.Now().Add(-4*time.Hour))
			return e, decisionCase{
				name: "ResetMark", kind: AuditVulnMarkReset,
				run: func(e *env, a DecisionAuditor) error {
					_, err := e.st.ResetMark(e.ctx, MarkResetRequest{SourceID: "osv", RunID: r.ID, ContentDate: d.Add(-3 * time.Hour),
						Admin: "admin", Reason: "provider re-dated data"}, a)
					return err
				},
				applied: func(t *testing.T, e *env) int {
					return countRows(t, e, `SELECT COUNT(*) FROM vuln_mark_resets`) +
						countRows(t, e, `SELECT COUNT(*) FROM vuln_source_marks WHERE source_id = 'osv' AND probation = 1`)
				},
			}
		},
	}
}

// Each decision writes exactly one decision and one audit line of its
// kind, naming the admin, in one transaction.
func TestDecisionWritesDecisionAndOneAuditLine(t *testing.T) {
	for _, mk := range decisionCases(t) {
		e, c := mk()
		t.Run(c.name, func(t *testing.T) {
			log := e.audit()
			if err := c.run(e, log); err != nil {
				t.Fatalf("decision: %v", err)
			}
			if n := c.applied(t, e); n == 0 { // exact counts: TestDecisionRowCounts
				t.Fatalf("decision rows = %d", n)
			}
			got, err := log.List(e.ctx, 0, 10, "")
			if err != nil || len(got) != 1 {
				t.Fatalf("audit lines = %+v, %v; want exactly one", got, err)
			}
			if got[0].Kind != c.kind || got[0].User != "admin" || got[0].Attrs["actor"] != "admin" {
				t.Fatalf("audit line = %+v, want kind %s by admin", got[0], c.kind)
			}
			if n, err := log.Verify(e.ctx); err != nil || n != 1 {
				t.Fatalf("chain: %d %v", n, err)
			}
		})
	}
}

// Exact decision row counts where the case counts two facts of one
// decision (row + side effect).
func TestDecisionRowCounts(t *testing.T) {
	want := map[string]int{"SetAcceptedRisk": 1, "SetFalsePositive": 1, "ConfirmHeld": 2, "DiscardHeld": 1, "ResetMark": 2}
	for _, mk := range decisionCases(t) {
		e, c := mk()
		t.Run(c.name, func(t *testing.T) {
			if n := c.applied(t, e); n != 0 {
				t.Fatalf("fixture already applied: %d", n)
			}
			if err := c.run(e, e.audit()); err != nil {
				t.Fatal(err)
			}
			if n := c.applied(t, e); n != want[c.name] {
				t.Fatalf("decision rows = %d, want %d", n, want[c.name])
			}
		})
	}
}

// A failing audit line leaves no decision and no line; the error carries
// the context and the decision can be applied afterwards.
func TestDecisionFailingAuditorLeavesNoDecision(t *testing.T) {
	for _, mk := range decisionCases(t) {
		e, c := mk()
		t.Run(c.name, func(t *testing.T) {
			log := e.audit()
			err := c.run(e, failAppend{log: log})
			if err == nil || !strings.Contains(err.Error(), "audit: disk full") || !strings.HasPrefix(err.Error(), "vulnstore: ") {
				t.Fatalf("decision with failing audit: %v", err)
			}
			if n := c.applied(t, e); n != 0 {
				t.Fatalf("decision stored without audit line: %d rows", n)
			}
			if got, err := log.List(e.ctx, 0, 10, ""); err != nil || len(got) != 0 {
				t.Fatalf("audit lines = %+v, %v", got, err)
			}
			// Nothing was half-applied: the same decision still succeeds.
			if err := c.run(e, log); err != nil {
				t.Fatalf("decision after the failed one: %v", err)
			}
		})
	}
}

// A commit that fails after the audit line was written leaves neither.
func TestDecisionFailedCommitLeavesNoDecision(t *testing.T) {
	for _, mk := range decisionCases(t) {
		e, c := mk()
		t.Run(c.name, func(t *testing.T) {
			log := e.audit()
			ctx, cancel := context.WithCancel(e.ctx)
			defer cancel()
			ce := *e
			ce.ctx = ctx
			if err := c.run(&ce, cancelAfterAudit{log: log, cancel: cancel}); err == nil {
				t.Fatal("decision with a failed commit succeeded")
			}
			if n := c.applied(t, e); n != 0 {
				t.Fatalf("decision stored without commit: %d rows", n)
			}
			if got, err := log.List(e.ctx, 0, 10, ""); err != nil || len(got) != 0 {
				t.Fatalf("audit lines = %+v, %v", got, err)
			}
		})
	}
}

// A nil auditor is refused before anything is written.
func TestDecisionNilAuditorRefused(t *testing.T) {
	for _, mk := range decisionCases(t) {
		e, c := mk()
		t.Run(c.name, func(t *testing.T) {
			if err := c.run(e, nil); !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "auditor is required") {
				t.Fatalf("nil auditor: %v", err)
			}
			if n := c.applied(t, e); n != 0 {
				t.Fatalf("decision stored without auditor: %d rows", n)
			}
		})
	}
}

// An auditor whose transaction runs on another database fails at the
// store's write lock and stores nothing on either database.
func TestDecisionAuditorOnOtherDatabaseRefused(t *testing.T) {
	other, err := serverdb.Open(filepath.Join(t.TempDir(), "other.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { other.Close() })
	if _, err := other.Exec(`DROP TABLE vuln_store_state`); err != nil {
		t.Fatal(err)
	}
	otherLog := auditlog.New(other, true)
	for _, mk := range decisionCases(t) {
		e, c := mk()
		t.Run(c.name, func(t *testing.T) {
			if err := c.run(e, otherLog); err == nil || !strings.Contains(err.Error(), "lock") {
				t.Fatalf("decision on another database: %v", err)
			}
			if n := c.applied(t, e); n != 0 {
				t.Fatalf("decision stored: %d rows", n)
			}
		})
	}
	if got, err := otherLog.List(context.Background(), 0, 10, ""); err != nil || len(got) != 0 {
		t.Fatalf("audit lines on the other database: %+v, %v", got, err)
	}
}

// A confirm that finds its hold superseded drops the hold and audits the
// drop in one transaction; with a failing audit line the hold stays.
func TestConfirmHeldSupersededDropIsAudited(t *testing.T) {
	setup := func(t *testing.T) (*env, Run, []Item) {
		e, r1, items := heldEnv(t)
		// A newer, partial run updates the finding without covering the
		// subject: the hold is superseded.
		r2 := e.start(t)
		e.submit(t, r2, 0, nil, items[0])
		e.complete(t, r2)
		return e, r1, items
	}
	e, r1, items := setup(t)
	k := items[0].Finding.Key
	log := e.audit()
	if _, err := e.st.ConfirmHeld(e.ctx, r1.ID, k, "admin", "ok", failAppend{log: log}); err == nil || errors.Is(err, ErrHoldSuperseded) {
		t.Fatalf("superseded confirm with failing audit: %v", err)
	}
	if h, _ := e.st.Holds(e.ctx, k); len(h) != 1 {
		t.Fatal("hold dropped without audit line")
	}
	if _, err := e.st.ConfirmHeld(e.ctx, r1.ID, k, "admin", "ok", log); !errors.Is(err, ErrHoldSuperseded) {
		t.Fatalf("superseded confirm: %v", err)
	}
	if h, _ := e.st.Holds(e.ctx, k); len(h) != 0 {
		t.Fatal("superseded hold kept")
	}
	got, err := log.List(e.ctx, 0, 10, "")
	if err != nil || len(got) != 1 || got[0].Kind != AuditVulnHoldSuperseded || got[0].User != "admin" {
		t.Fatalf("audit lines = %+v, %v", got, err)
	}
	e.wantState(t, k, StateOpen, "")
}

// Refused decisions write no audit line.
func TestRefusedDecisionWritesNoAuditLine(t *testing.T) {
	e, r, items := heldEnv(t)
	k := items[0].Finding.Key
	log := e.audit()
	e.cls.set(k, ClassContradicted)
	if _, err := e.st.ConfirmHeld(e.ctx, r.ID, k, "admin", "x", log); !errors.Is(err, ErrContradicted) {
		t.Fatalf("contradicted: %v", err)
	}
	if err := e.st.DiscardHeld(e.ctx, "no-such-run", k, "admin", log); !errors.Is(err, ErrHoldNotFound) {
		t.Fatalf("discard unknown hold: %v", err)
	}
	if err := e.st.DiscardHeld(e.ctx, r.ID, k, "bad admin", log); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("discard with bad admin: %v", err)
	}
	if got, err := log.List(e.ctx, 0, 10, ""); err != nil || len(got) != 0 {
		t.Fatalf("audit lines = %+v, %v", got, err)
	}
}
