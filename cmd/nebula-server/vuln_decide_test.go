// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/auditlog"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverconfig"
	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/api"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// vdEnv is the decision backend over a real findings store, audit log and
// vault of challenges; the executor's login is the fake of the agent settings
// tests (single-use challenges, one good assertion, user named by the fake).
type vdEnv struct {
	e     *vtEnv
	login *vaLogins
	admin bool
	dec   *vulnDecider
}

// newVDEnv returns the backend; wrap, when set, wraps the audit log (tests
// inject a failing write there).
func newVDEnv(t *testing.T, loginUser string, wrap func(vulnstore.DecisionAuditor) vulnstore.DecisionAuditor) *vdEnv {
	t.Helper()
	e := clsEnv(t)
	x := &vdEnv{e: e, login: newVALogins(loginUser), admin: true}
	var audit vulnstore.DecisionAuditor = e.audit
	if wrap != nil {
		audit = wrap(audit)
	}
	dec, err := newVulnDecider(e.svc, audit, func(context.Context) bool { return x.admin }, x.login, e.clk.Now,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	x.dec = dec
	return x
}

// vdFailingAudit runs the decision and then fails the write, so the
// transaction of the decision must roll back.
type vdFailingAudit struct{ inner vulnstore.DecisionAuditor }

func (a vdFailingAudit) WithTx(ctx context.Context, fn func(tx *sql.Tx, appendLine func(kind string, attrs map[string]string) error) error) error {
	return a.inner.WithTx(ctx, func(tx *sql.Tx, appendLine func(kind string, attrs map[string]string) error) error {
		if err := fn(tx, appendLine); err != nil {
			return err
		}
		return errors.New("audit write failed")
	})
}

// vdFinding is an open finding of clsHost with NOS's own read of the old
// version, so its version basis is known.
func vdFinding(t *testing.T, e *vtEnv, cve string) vulnstore.Finding {
	t.Helper()
	f := clsFinding(t, e, clsRecord(cve, "openssl", clsOld, clsNew))
	clsSettle(e)
	clsPut(t, e, clsRead("r-"+cve, f.Updated.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1"), clsComp("openssl", clsOld)))
	return f
}

// vdHeld is a finding held for an admin: a known exploited (KEV) finding
// that a run closes on a stale read, so the closure is unconfirmed and
// held. It returns the finding and the held run.
func vdHeld(t *testing.T, e *vtEnv, cve string) (vulnstore.Finding, string) {
	t.Helper()
	rec := clsRecord(cve, "openssl", clsOld, clsNew)
	rec["scores"] = map[string]any{"kev": map[string]any{"date_added": "2026-11-01"}}
	f := clsFinding(t, e, rec)
	// The complete read has no openssl line: NOS shows neither the fix nor the
	// old version, so the closure is unconfirmed (not contradicted).
	clsPut(t, e, clsRead("stale-"+cve, f.Updated.Add(-time.Minute), true, clsKernel("6.1.119-1"), clsComp("bash", "5.2.15-2")))
	run := clsRunCovering(t, e)
	clsComplete(t, e, run)
	holds, err := e.svc.store.Holds(context.Background(), f.Key)
	if err != nil || len(holds) != 1 {
		t.Fatalf("holds = %+v, %v; want one held closure", holds, err)
	}
	return f, run
}

// vdStartRun starts a run whose three sources are dated at, and completes
// it without findings.
func vdStartRun(t *testing.T, e *vtEnv, at time.Time) string {
	t.Helper()
	var sources []any
	for _, id := range []string{"debian-tracker", "kev", "osv"} {
		sources = append(sources, map[string]any{"source_id": id, "snapshot_id": "snap-" + id, "integrity": "none",
			"date_kind": "data", "content_date": at.Format(time.RFC3339)})
	}
	rec := e.do(t, http.MethodPost, "/api/v1/vuln/runs", vtToken, vtHermes,
		map[string]any{"inventory_snapshot_id": "snap-1", "matcher_version": "1.4.0", "sources": sources})
	if rec.Code != http.StatusCreated {
		t.Fatalf("start run: %d %s", rec.Code, rec.Body)
	}
	var started struct {
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	clsComplete(t, e, started.RunID)
	return started.RunID
}

// vdMarkRegressed moves debian-tracker's mark to an accepted date and then
// has a later run report it lower (regressed). It returns the regressed run.
func vdMarkRegressed(t *testing.T, e *vtEnv) string {
	t.Helper()
	d1 := e.clk.Now().Add(-2 * time.Hour).Truncate(time.Second)
	vdStartRun(t, e, d1)
	run := vdStartRun(t, e, d1.Add(-24*time.Hour))
	view, err := e.svc.store.MarkResetCandidate(context.Background(), "debian-tracker")
	if err != nil || view.RunID != run {
		t.Fatalf("reset view = %+v, %v; want the regressed run %s", view, err, run)
	}
	return run
}

// begin begins d as user and returns the challenge ID.
func (x *vdEnv) begin(t *testing.T, user string, d ui.VulnDecision) string {
	t.Helper()
	ch, err := x.dec.BeginVulnDecision(context.Background(), user, d)
	if err != nil || ch.ID == "" {
		t.Fatalf("begin %s = %+v, %v", d.Kind, ch, err)
	}
	return ch.ID
}

// audits returns the audit lines of kind.
func (x *vdEnv) audits(t *testing.T, kind string) []auditlog.Entry {
	t.Helper()
	got, err := x.e.audit.List(context.Background(), 0, 10, kind)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// state returns the stored state of finding f.
func (x *vdEnv) state(t *testing.T, f vulnstore.Finding) vulnstore.State {
	t.Helper()
	got, err := x.e.svc.store.Get(context.Background(), f.Key)
	if err != nil {
		t.Fatal(err)
	}
	return got.State
}

// vdAccept is an accept_risk decision on f, expiring in thirty days.
func vdAccept(x *vdEnv, f vulnstore.Finding) ui.VulnDecision {
	return ui.VulnDecision{Kind: ui.VulnAcceptRisk, Key: f.Key, Approver: "alice", Reason: "vendor patch scheduled",
		Expires: x.e.clk.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)}
}

// TestVulnDecisionKindsApplyOnceWithAssertion: each of the five kinds is
// applied by one good assertion, writes its audit line once, and the same
// challenge cannot be used again.
func TestVulnDecisionKindsApplyOnceWithAssertion(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name  string
		kind  string
		setup func(t *testing.T, x *vdEnv) (ui.VulnDecision, func())
	}{
		{"accept_risk", vulnstore.AuditVulnAcceptedRisk, func(t *testing.T, x *vdEnv) (ui.VulnDecision, func()) {
			f := vdFinding(t, x.e, "CVE-2026-8101")
			return vdAccept(x, f), func() {
				if got := x.state(t, f); got != vulnstore.StateAcceptedRisk {
					t.Fatalf("state = %s, want accepted_risk", got)
				}
			}
		}},
		{"false_positive", vulnstore.AuditVulnFalsePositive, func(t *testing.T, x *vdEnv) (ui.VulnDecision, func()) {
			f := vdFinding(t, x.e, "CVE-2026-8102")
			d := ui.VulnDecision{Kind: ui.VulnFalsePositive, Key: f.Key, Category: vulnstore.CategoryVendorDisputed, Reason: "vendor disputes it"}
			return d, func() {
				if got := x.state(t, f); got != vulnstore.StateFalsePositive {
					t.Fatalf("state = %s, want false_positive", got)
				}
			}
		}},
		{"confirm_hold", vulnstore.AuditVulnHoldConfirmed, func(t *testing.T, x *vdEnv) (ui.VulnDecision, func()) {
			f, run := vdHeld(t, x.e, "CVE-2026-8103")
			d := ui.VulnDecision{Kind: ui.VulnConfirmHold, Key: f.Key, RunID: run, Reason: "checked by hand"}
			return d, func() {
				if h, err := x.e.svc.store.Holds(ctx, f.Key); err != nil || len(h) != 0 {
					t.Fatalf("holds after confirm = %+v, %v; want none", h, err)
				}
			}
		}},
		{"discard_hold", vulnstore.AuditVulnHoldDiscarded, func(t *testing.T, x *vdEnv) (ui.VulnDecision, func()) {
			f, run := vdHeld(t, x.e, "CVE-2026-8104")
			d := ui.VulnDecision{Kind: ui.VulnDiscardHold, Key: f.Key, RunID: run}
			return d, func() {
				if h, err := x.e.svc.store.Holds(ctx, f.Key); err != nil || len(h) != 0 {
					t.Fatalf("holds after discard = %+v, %v; want none", h, err)
				}
				if got := x.state(t, f); got != vulnstore.StateOpen {
					t.Fatalf("state = %s, want open", got)
				}
			}
		}},
		{"mark_reset", vulnstore.AuditVulnMarkReset, func(t *testing.T, x *vdEnv) (ui.VulnDecision, func()) {
			run := vdMarkRegressed(t, x.e)
			d := ui.VulnDecision{Kind: ui.VulnMarkReset, SourceID: "debian-tracker", RunID: run, Reason: "feed was rolled back"}
			return d, func() {
				// The mark moved down to the regressed value and the source is
				// on probation until a run names it above the pre-reset mark.
				view, err := x.e.svc.store.MarkResetCandidate(ctx, "debian-tracker")
				if err != nil || !view.Probation || !view.MarkDate.Equal(view.ReportedDate) || !view.PreResetDate.After(view.MarkDate) {
					t.Fatalf("reset view after reset = %+v, %v; want the mark at the reported value, on probation", view, err)
				}
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := newVDEnv(t, "alice", nil)
			d, check := tt.setup(t, x)
			id := x.begin(t, "alice", d)
			if err := x.dec.CommitVulnDecision(ctx, "alice", id, d, []byte(vaGoodAssertion)); err != nil {
				t.Fatalf("commit = %v", err)
			}
			check()
			got := x.audits(t, tt.kind)
			if len(got) != 1 || got[0].User != "alice" {
				t.Fatalf("audit %s = %+v; want one line by alice", tt.kind, got)
			}
			if err := x.dec.CommitVulnDecision(ctx, "alice", id, d, []byte(vaGoodAssertion)); !errors.Is(err, ui.ErrVulnAssertionRefused) {
				t.Fatalf("second commit with the same challenge = %v, want refused", err)
			}
			if n := x.login.finishedCount(); n != 1 {
				t.Fatalf("executor verified %d assertions, want 1", n)
			}
		})
	}
}

// TestVulnDecisionRefusedWithoutAValidAssertion: every refusal leaves the
// finding, the hold and the audit log as they were, for each kind.
func TestVulnDecisionRefusedWithoutAValidAssertion(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		// run performs the refused attempt and returns its error.
		run func(t *testing.T, x *vdEnv, f vulnstore.Finding, run string, d ui.VulnDecision) error
	}{
		{"not the maintainer at begin", func(t *testing.T, x *vdEnv, _ vulnstore.Finding, _ string, d ui.VulnDecision) error {
			x.admin = false
			_, err := x.dec.BeginVulnDecision(ctx, "alice", d)
			return err
		}},
		{"not the maintainer at commit", func(t *testing.T, x *vdEnv, _ vulnstore.Finding, _ string, d ui.VulnDecision) error {
			id := x.begin(t, "alice", d)
			x.admin = false
			return x.dec.CommitVulnDecision(ctx, "alice", id, d, []byte(vaGoodAssertion))
		}},
		{"other user commits", func(t *testing.T, x *vdEnv, _ vulnstore.Finding, _ string, d ui.VulnDecision) error {
			id := x.begin(t, "alice", d)
			return x.dec.CommitVulnDecision(ctx, "bob", id, d, []byte(vaGoodAssertion))
		}},
		{"assertion of another user", func(t *testing.T, x *vdEnv, _ vulnstore.Finding, _ string, d ui.VulnDecision) error {
			x.login.user = "bob"
			id := x.begin(t, "alice", d)
			return x.dec.CommitVulnDecision(ctx, "alice", id, d, []byte(vaGoodAssertion))
		}},
		{"other digest", func(t *testing.T, x *vdEnv, _ vulnstore.Finding, _ string, d ui.VulnDecision) error {
			id := x.begin(t, "alice", d)
			other := d
			other.Reason = "a different reason"
			return x.dec.CommitVulnDecision(ctx, "alice", id, other, []byte(vaGoodAssertion))
		}},
		{"expired", func(t *testing.T, x *vdEnv, _ vulnstore.Finding, _ string, d ui.VulnDecision) error {
			id := x.begin(t, "alice", d)
			x.e.clk.Add(vulnDecisionChallengeTTL + time.Second)
			return x.dec.CommitVulnDecision(ctx, "alice", id, d, []byte(vaGoodAssertion))
		}},
		{"refused assertion", func(t *testing.T, x *vdEnv, _ vulnstore.Finding, _ string, d ui.VulnDecision) error {
			id := x.begin(t, "alice", d)
			return x.dec.CommitVulnDecision(ctx, "alice", id, d, []byte(`{"id":"forged"}`))
		}},
		{"no assertion", func(t *testing.T, x *vdEnv, _ vulnstore.Finding, _ string, d ui.VulnDecision) error {
			id := x.begin(t, "alice", d)
			return x.dec.CommitVulnDecision(ctx, "alice", id, d, nil)
		}},
		{"unknown challenge", func(t *testing.T, x *vdEnv, _ vulnstore.Finding, _ string, d ui.VulnDecision) error {
			return x.dec.CommitVulnDecision(ctx, "alice", strings.Repeat("a", 32), d, []byte(vaGoodAssertion))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := newVDEnv(t, "alice", nil)
			f := vdFinding(t, x.e, "CVE-2026-8201")
			err := tt.run(t, x, f, "", vdAccept(x, f))
			if !errors.Is(err, ui.ErrVulnAssertionRefused) {
				t.Fatalf("err = %v, want refused", err)
			}
			if got := x.state(t, f); got != vulnstore.StateOpen {
				t.Fatalf("state = %s, want open", got)
			}
			if got := x.audits(t, vulnstore.AuditVulnAcceptedRisk); len(got) != 0 {
				t.Fatalf("audit = %+v, want none", got)
			}
		})
	}
}

// TestVulnDecisionDiscardHoldNeedsAnAssertion: discarding a held closure is
// refused without an assertion and with a refused one, and the hold stays.
func TestVulnDecisionDiscardHoldNeedsAnAssertion(t *testing.T) {
	ctx := context.Background()
	x := newVDEnv(t, "alice", nil)
	f, run := vdHeld(t, x.e, "CVE-2026-8301")
	d := ui.VulnDecision{Kind: ui.VulnDiscardHold, Key: f.Key, RunID: run}
	for name, assertion := range map[string][]byte{"no assertion": nil, "refused assertion": []byte(`{"id":"forged"}`)} {
		t.Run(name, func(t *testing.T) {
			id := x.begin(t, "alice", d)
			if err := x.dec.CommitVulnDecision(ctx, "alice", id, d, assertion); !errors.Is(err, ui.ErrVulnAssertionRefused) {
				t.Fatalf("commit = %v, want refused", err)
			}
			if h, err := x.e.svc.store.Holds(ctx, f.Key); err != nil || len(h) != 1 {
				t.Fatalf("holds = %+v, %v; want the hold kept", h, err)
			}
			if got := x.audits(t, vulnstore.AuditVulnHoldDiscarded); len(got) != 0 {
				t.Fatalf("audit = %+v, want none", got)
			}
		})
	}
}

// TestVulnDecisionAuditFailureWritesNoDecision: when the audit line cannot be
// written, the decision is not stored either.
func TestVulnDecisionAuditFailureWritesNoDecision(t *testing.T) {
	ctx := context.Background()
	x := newVDEnv(t, "alice", func(a vulnstore.DecisionAuditor) vulnstore.DecisionAuditor { return vdFailingAudit{inner: a} })
	f := vdFinding(t, x.e, "CVE-2026-8401")
	d := vdAccept(x, f)
	id := x.begin(t, "alice", d)
	if err := x.dec.CommitVulnDecision(ctx, "alice", id, d, []byte(vaGoodAssertion)); err == nil {
		t.Fatal("commit succeeded although the audit line failed")
	}
	if got := x.state(t, f); got != vulnstore.StateOpen {
		t.Fatalf("state = %s, want open: the decision must not be stored", got)
	}
	if got := x.audits(t, vulnstore.AuditVulnAcceptedRisk); len(got) != 0 {
		t.Fatalf("audit = %+v, want none", got)
	}
}

// TestVulnDecisionBasisComesFromNOS: a finding NOS cannot judge gets no
// decision (no version basis is known), whatever the browser sends.
func TestVulnDecisionBasisComesFromNOS(t *testing.T) {
	ctx := context.Background()
	x := newVDEnv(t, "alice", nil)
	f := clsFinding(t, x.e, clsRecord("CVE-2026-8501", "openssl", clsOld, clsNew))
	d := vdAccept(x, f)
	id := x.begin(t, "alice", d)
	if err := x.dec.CommitVulnDecision(ctx, "alice", id, d, []byte(vaGoodAssertion)); err == nil {
		t.Fatal("commit succeeded without a NOS version basis")
	}
	if got := x.state(t, f); got != vulnstore.StateOpen {
		t.Fatalf("state = %s, want open", got)
	}
}

// TestVulnDecisionChallengesAreBounded: begun decisions are bounded like the
// agent settings challenges.
func TestVulnDecisionChallengesAreBounded(t *testing.T) {
	ctx := context.Background()
	x := newVDEnv(t, "alice", nil)
	f := vdFinding(t, x.e, "CVE-2026-8601")
	d := vdAccept(x, f)
	for i := 0; i < maxVulnDecisionChallenges; i++ {
		x.begin(t, "alice", d)
	}
	if _, err := x.dec.BeginVulnDecision(ctx, "alice", d); !errors.Is(err, errVulnDecisionChallengeFull) {
		t.Fatalf("begin over the bound = %v, want %v", err, errVulnDecisionChallengeFull)
	}
}

// TestNewVulnDeciderNeedsDependencies: no dependency may be missing.
func TestNewVulnDeciderNeedsDependencies(t *testing.T) {
	x := newVDEnv(t, "alice", nil)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	admin := func(context.Context) bool { return true }
	if _, err := newVulnDecider(nil, x.e.audit, admin, x.login, nil, log); err == nil {
		t.Fatal("no findings service accepted")
	}
	if _, err := newVulnDecider(x.e.svc, nil, admin, x.login, nil, log); err == nil {
		t.Fatal("no audit log accepted")
	}
	if _, err := newVulnDecider(x.e.svc, x.e.audit, nil, x.login, nil, log); err == nil {
		t.Fatal("no admin check accepted")
	}
	if _, err := newVulnDecider(x.e.svc, x.e.audit, admin, nil, nil, log); err == nil {
		t.Fatal("no executor accepted")
	}
	if _, err := newVulnDecider(x.e.svc, x.e.audit, admin, x.login, nil, nil); err == nil {
		t.Fatal("no log accepted")
	}
}

// TestRunWiresVulnDecisions starts the server through runServer and proves
// the decision endpoints over real HTTP: the maintainer's begin gets a
// challenge, another user and a missing or refused assertion are refused,
// and the decision reaches the real backend (a missing finding answers 404).
func TestRunWiresVulnDecisions(t *testing.T) {
	dir := t.TempDir()
	logins := newVALogins("alice")
	sock := serveExecutor(t, vaExecutor{vtExecutor: vtExecutor{expiry: time.Now().Add(time.Hour).Unix()}, logins: logins})
	alice, bob := vrSessions(t, dir)
	cfg := vrConfig(t, dir, sock, map[string]any{"enabled": true, "tokens": []any{map[string]any{
		"name": serverconfig.DefaultVulnTokenName, "sha256": api.HashToken(vrToken),
		"scopes":           []string{serverconfig.ScopeVulnInventoryRead, serverconfig.ScopeVulnFindingsWrite},
		"source_addresses": []string{"127.0.0.1"}}}})
	s := startVR(t, dir, cfg)

	waitFor(t, "the privileged session", func() bool {
		code, _ := s.do(t, http.MethodPost, "/privileged/finish", alice, "", map[string]any{"assertion": map[string]any{"id": "k"}})
		return code == http.StatusOK
	})
	key := strings.Repeat("0", 2*len(vulnfinding.Key{}))
	d := map[string]any{"kind": "discard_hold", "key": key, "run_id": "run-1"}
	if code, body := s.do(t, http.MethodPost, "/vulnerabilities/decide/begin", bob, "", d); code != http.StatusForbidden {
		t.Fatalf("begin by another user = %d %s, want 403", code, body)
	}
	code, body := s.do(t, http.MethodPost, "/vulnerabilities/decide/begin", alice, "", d)
	if code != http.StatusOK {
		t.Fatalf("begin = %d %s (log: %s)", code, body, s.stderr)
	}
	var ch struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &ch); err != nil || ch.ID == "" {
		t.Fatalf("begin body %s: %v", body, err)
	}
	if code, body := s.do(t, http.MethodPost, "/vulnerabilities/decide/commit", alice, "",
		map[string]any{"id": ch.ID, "assertion": nil}); code != http.StatusForbidden {
		t.Fatalf("discard_hold without an assertion = %d %s, want 403", code, body)
	}
	code, body = s.do(t, http.MethodPost, "/vulnerabilities/decide/begin", alice, "", d)
	if code != http.StatusOK {
		t.Fatalf("second begin = %d %s", code, body)
	}
	var ch2 struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &ch2); err != nil || ch2.ID == "" {
		t.Fatalf("second begin body %s: %v", body, err)
	}
	if code, body := s.do(t, http.MethodPost, "/vulnerabilities/decide/commit", alice, "",
		map[string]any{"id": ch2.ID, "assertion": json.RawMessage(`{"id":"forged"}`)}); code != http.StatusForbidden {
		t.Fatalf("refused assertion = %d %s, want 403", code, body)
	}
	code, body = s.do(t, http.MethodPost, "/vulnerabilities/decide/commit", alice, "",
		map[string]any{"id": ch.ID, "assertion": json.RawMessage(vaGoodAssertion)})
	if code != http.StatusNotFound {
		t.Fatalf("commit of a good assertion for a missing hold = %d %s (log: %s), want 404", code, body, s.stderr)
	}
	if n := logins.finishedCount(); n != 2 {
		t.Fatalf("executor verified %d assertions, want 2 (the refused one and the good one)", n)
	}
	s.stop()

	db, err := serverdb.Open(filepath.Join(dir, "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if got, err := auditlog.New(db, false).List(context.Background(), 0, 10, vulnstore.AuditVulnHoldDiscarded); err != nil || len(got) != 0 {
		t.Fatalf("audit %+v %v; want no discard line", got, err)
	}
}
