// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// TestSweepReopensAcceptedRiskWhenBasisChanges: a sweep re-checks the human
// states (ADR 0011 D6). An accepted risk whose version basis is unchanged
// stays accepted; once NOS's own read shows a different version of the
// component, the next sweep re-opens it.
func TestSweepReopensAcceptedRiskWhenBasisChanges(t *testing.T) {
	ctx := context.Background()
	x := newVDEnv(t, "alice", nil)
	f := vdFinding(t, x.e, "CVE-2026-8901")
	d := vdAccept(x, f)
	id := x.begin(t, "alice", d)
	if err := vdCommit(x, "alice", id, d); err != nil {
		t.Fatalf("commit = %v", err)
	}
	if got := x.state(t, f); got != vulnstore.StateAcceptedRisk {
		t.Fatalf("state after accept = %s, want accepted_risk", got)
	}

	if _, err := x.e.svc.sweepOnce(ctx); err != nil {
		t.Fatalf("sweep with unchanged basis: %v", err)
	}
	if got := x.state(t, f); got != vulnstore.StateAcceptedRisk {
		t.Fatalf("state after sweep with unchanged basis = %s, want accepted_risk", got)
	}

	// NOS now reads the component at the fixed version: the basis of the
	// accepted risk (clsOld) is no longer the current one.
	x.e.clk.Add(clsLag + 2*time.Minute)
	clsPut(t, x.e, clsRead("r-changed-"+f.Key.String()[:8], x.e.clk.Now(), true, clsKernel("6.1.119-1"), clsComp("openssl", clsNew)))
	if _, err := x.e.svc.sweepOnce(ctx); err != nil {
		t.Fatalf("sweep with changed basis: %v", err)
	}
	if got := x.state(t, f); got != vulnstore.StateOpen {
		t.Fatalf("state after sweep with changed basis = %s, want open", got)
	}
}

// TestSweepRunsTheHumanStateReview: runSweeps reaches the review through
// sweepOnce, so the loop re-opens a changed accepted risk without any direct
// call to the store.
func TestSweepRunsTheHumanStateReview(t *testing.T) {
	x := newVDEnv(t, "alice", nil)
	f := vdFinding(t, x.e, "CVE-2026-8902")
	d := vdAccept(x, f)
	id := x.begin(t, "alice", d)
	if err := vdCommit(x, "alice", id, d); err != nil {
		t.Fatalf("commit = %v", err)
	}
	x.e.clk.Add(clsLag + 2*time.Minute)
	clsPut(t, x.e, clsRead("r-loop-"+f.Key.String()[:8], x.e.clk.Now(), true, clsKernel("6.1.119-1"), clsComp("openssl", clsNew)))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	swept := make(chan struct{}, 1)
	x.e.svc.swept = func(vulnstore.PruneResult, error) {
		select {
		case swept <- struct{}{}:
		default:
		}
	}
	go func() { x.e.svc.runSweeps(ctx, 10*time.Millisecond); close(done) }()
	select {
	case <-swept:
	case <-time.After(vtWait):
		cancel()
		<-done
		t.Fatal("no sweep ran")
	}
	cancel()
	<-done
	if got := x.state(t, f); got != vulnstore.StateOpen {
		t.Fatalf("state after the sweep loop = %s, want open", got)
	}
}

// TestSweepOpenFindingsAreNotReviewed: a finding that is open (no human
// state) is left alone by the review.
func TestSweepOpenFindingsAreNotReviewed(t *testing.T) {
	x := newVDEnv(t, "alice", nil)
	f := vdFinding(t, x.e, "CVE-2026-8903")
	if _, err := x.e.svc.sweepOnce(context.Background()); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if got := x.state(t, f); got != vulnstore.StateOpen {
		t.Fatalf("state = %s, want open", got)
	}
}
