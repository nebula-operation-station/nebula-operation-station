// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnnotify"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// vdDrainEvents runs the queued notification events of e in the caller, as
// runEvents would (the test has no event loop).
func vdDrainEvents(e *vtEnv) {
	ctx := context.Background()
	for len(e.svc.events) > 0 {
		f := <-e.svc.events
		f(ctx)
	}
}

// TestMarkResetCommitNotifiesOnce: an applied mark reset, committed through
// the assertion path, raises exactly one vuln.feed_mark_reset event; a replay
// of the same challenge is refused and raises none.
func TestMarkResetCommitNotifiesOnce(t *testing.T) {
	x := newVDEnv(t, "alice", nil)
	run := vdMarkRegressed(t, x.e)
	d := ui.VulnDecision{Kind: ui.VulnMarkReset, SourceID: "debian-tracker", RunID: run, Reason: "feed was rolled back"}
	id := x.begin(t, "alice", d)
	if err := vdCommit(x, "alice", id, d); err != nil {
		t.Fatalf("commit = %v", err)
	}
	vdDrainEvents(x.e)
	if got := x.e.sink.reasons(vulnnotify.KindFeedMarkReset); len(got) != 1 {
		t.Fatalf("mark reset events after commit = %d, want 1", len(got))
	}

	if err := vdCommit(x, "alice", id, d); !errors.Is(err, ui.ErrVulnAssertionRefused) {
		t.Fatalf("replayed commit = %v, want refused", err)
	}
	vdDrainEvents(x.e)
	if got := x.e.sink.reasons(vulnnotify.KindFeedMarkReset); len(got) != 1 {
		t.Fatalf("mark reset events after replay = %d, want still 1", len(got))
	}
}

// TestMarkResetFailingInStoreRaisesNoEvent: a mark reset that reaches
// ResetMark and fails there (the audit write fails, so the reset rolls back)
// returns an error, raises no vuln.feed_mark_reset event, and leaves the mark
// as it was.
func TestMarkResetFailingInStoreRaisesNoEvent(t *testing.T) {
	ctx := context.Background()
	x := newVDEnv(t, "alice", func(a vulnstore.DecisionAuditor) vulnstore.DecisionAuditor { return vdFailingAudit{inner: a} })
	run := vdMarkRegressed(t, x.e)
	d := ui.VulnDecision{Kind: ui.VulnMarkReset, SourceID: "debian-tracker", RunID: run, Reason: "feed was rolled back"}
	id := x.begin(t, "alice", d)
	if err := vdCommit(x, "alice", id, d); err == nil {
		t.Fatal("commit = nil, want error: the audit line failed")
	}
	vdDrainEvents(x.e)
	if got := x.e.sink.reasons(vulnnotify.KindFeedMarkReset); len(got) != 0 {
		t.Fatalf("mark reset events = %d, want none after a failed reset", len(got))
	}
	view, err := x.e.svc.store.MarkResetCandidate(ctx, "debian-tracker")
	if err != nil || view.Probation || view.RunID != run {
		t.Fatalf("reset view = %+v, %v; want the mark unchanged (run %s, not on probation)", view, err, run)
	}
}

// TestMarkResetRefusedRaisesNoEvent: a mark reset that is refused, by the
// assertion or by the server's own check of the run, applies nothing and
// raises no vuln.feed_mark_reset event.
func TestMarkResetRefusedRaisesNoEvent(t *testing.T) {
	tests := []struct {
		name string
		// user is the requesting user; the executor names the asserting user
		// loginUser, so a mismatch is refused.
		loginUser string
		// runOf returns the run the decision names.
		runOf func(run string) string
	}{
		{"assertion of another user", "mallory", func(run string) string { return run }},
		{"latest regressed run changed", "alice", func(string) string { return "run-not-the-latest" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			x := newVDEnv(t, tt.loginUser, nil)
			run := vdMarkRegressed(t, x.e)
			d := ui.VulnDecision{Kind: ui.VulnMarkReset, SourceID: "debian-tracker", RunID: tt.runOf(run), Reason: "feed was rolled back"}
			id := x.begin(t, "alice", d)
			if err := x.dec.CommitVulnDecision(ctx, "alice", id, d, []byte(vaGoodAssertion)); err == nil {
				t.Fatal("commit = nil, want refused")
			}
			vdDrainEvents(x.e)
			if got := x.e.sink.reasons(vulnnotify.KindFeedMarkReset); len(got) != 0 {
				t.Fatalf("mark reset events = %d, want none", len(got))
			}
			view, err := x.e.svc.store.MarkResetCandidate(ctx, "debian-tracker")
			if err != nil || view.Probation {
				t.Fatalf("reset view = %+v, %v; want the mark unchanged, not on probation", view, err)
			}
		})
	}
}
