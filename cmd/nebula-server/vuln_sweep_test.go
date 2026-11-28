// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulninventory"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
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

// TestSweepReopensFalsePositiveWhenBasisChanges: a false positive is bound to
// its version basis like an accepted risk (ADR 0011 D4, D6). Unchanged, it
// stays; once NOS reads a different version the next sweep re-opens it.
func TestSweepReopensFalsePositiveWhenBasisChanges(t *testing.T) {
	ctx := context.Background()
	x := newVDEnv(t, "alice", nil)
	f := vdFinding(t, x.e, "CVE-2026-8904")
	d := ui.VulnDecision{Kind: ui.VulnFalsePositive, Key: f.Key, Category: vulnstore.CategoryVendorDisputed, Reason: "vendor disputes it"}
	id := x.begin(t, "alice", d)
	if err := vdCommit(x, "alice", id, d); err != nil {
		t.Fatalf("commit = %v", err)
	}
	if _, err := x.e.svc.sweepOnce(ctx); err != nil {
		t.Fatalf("sweep with unchanged basis: %v", err)
	}
	if got := x.state(t, f); got != vulnstore.StateFalsePositive {
		t.Fatalf("state after sweep with unchanged basis = %s, want false_positive", got)
	}

	x.e.clk.Add(clsLag + 2*time.Minute)
	clsPut(t, x.e, clsRead("r-fp-changed-"+f.Key.String()[:8], x.e.clk.Now(), true, clsKernel("6.1.119-1"), clsComp("openssl", clsNew)))
	if _, err := x.e.svc.sweepOnce(ctx); err != nil {
		t.Fatalf("sweep with changed basis: %v", err)
	}
	if got := x.state(t, f); got != vulnstore.StateOpen {
		t.Fatalf("state after sweep with changed basis = %s, want open", got)
	}
}

// TestSweepReopensExpiredAcceptedRisk: an accepted risk re-opens once its
// expiry has passed, even though NOS's basis did not change (D6).
func TestSweepReopensExpiredAcceptedRisk(t *testing.T) {
	ctx := context.Background()
	x := newVDEnv(t, "alice", nil)
	f := vdFinding(t, x.e, "CVE-2026-8905")
	d := vdAccept(x, f)
	id := x.begin(t, "alice", d)
	if err := vdCommit(x, "alice", id, d); err != nil {
		t.Fatalf("commit = %v", err)
	}
	// The decision expires after thirty days; the sweep is past that.
	x.e.clk.Add(31 * 24 * time.Hour)
	if _, err := x.e.svc.sweepOnce(ctx); err != nil {
		t.Fatalf("sweep after expiry: %v", err)
	}
	if got := x.state(t, f); got != vulnstore.StateOpen {
		t.Fatalf("state after expiry = %s, want open", got)
	}
}

// TestSweepReopensAcceptedRiskWhenComponentUnknown: when NOS's own read no
// longer names the component of an accepted risk, NOS cannot judge its
// version basis and the sweep re-opens the risk (basis_unknown, D6).
func TestSweepReopensAcceptedRiskWhenComponentUnknown(t *testing.T) {
	ctx := context.Background()
	x := newVDEnv(t, "alice", nil)
	f := vdFinding(t, x.e, "CVE-2026-8906")
	d := vdAccept(x, f)
	id := x.begin(t, "alice", d)
	if err := vdCommit(x, "alice", id, d); err != nil {
		t.Fatalf("commit = %v", err)
	}
	x.e.clk.Add(clsLag + 2*time.Minute)
	clsPut(t, x.e, clsRead("r-unknown-"+f.Key.String()[:8], x.e.clk.Now(), true, clsKernel("6.1.119-1"), clsComp("other-pkg", clsNew)))
	if _, err := x.e.svc.sweepOnce(ctx); err != nil {
		t.Fatalf("sweep with unknown component: %v", err)
	}
	if got := x.state(t, f); got != vulnstore.StateOpen {
		t.Fatalf("state after sweep with unknown component = %s, want open", got)
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

// TestSweepKeepsAcceptedRiskWhenClassifierFails: a classifier failure in the
// sweep is not an unknown component (D6). Here the newest read keeps moving
// while NOS reads the pair (errVulnReadRace), so the basis cannot be judged.
// The accepted risk stays accepted and the log says the basis could not be
// judged (basis_error), which separates it from a component NOS really does
// not know.
func TestSweepKeepsAcceptedRiskWhenClassifierFails(t *testing.T) {
	ctx := context.Background()
	x := newVDEnv(t, "alice", nil)
	f := vdFinding(t, x.e, "CVE-2026-8907")
	d := vdAccept(x, f)
	id := x.begin(t, "alice", d)
	if err := vdCommit(x, "alice", id, d); err != nil {
		t.Fatalf("commit = %v", err)
	}
	x.e.clk.Add(clsLag + 2*time.Minute)
	n := 0
	x.e.svc.classifier.betweenReads = func() {
		n++
		clsPut(t, x.e, clsRead(fmt.Sprintf("bm%d-%s", n, f.Key.String()[:8]), x.e.clk.Now().Add(time.Duration(n)*time.Second),
			true, clsKernel("6.1.119-1"), clsComp("openssl", clsOld)))
	}
	var logs bytes.Buffer
	x.e.svc.log = slog.New(slog.NewTextHandler(&logs, nil))

	if _, err := x.e.svc.sweepOnce(ctx); err != nil {
		t.Fatalf("sweep with failing classifier: %v", err)
	}
	if got := x.state(t, f); got != vulnstore.StateAcceptedRisk {
		t.Fatalf("state after sweep with failing classifier = %s, want accepted_risk", got)
	}
	if !strings.Contains(logs.String(), "basis_error=1") {
		t.Fatalf("log does not name the basis error:\n%s", logs.String())
	}
}

// vdFalsePositive is a false positive of f on the finding's current basis,
// committed as alice. It fails the test when the decision is refused.
func vdFalsePositive(t *testing.T, x *vdEnv, f vulnstore.Finding) {
	t.Helper()
	d := ui.VulnDecision{Kind: ui.VulnFalsePositive, Key: f.Key, Category: vulnstore.CategoryVendorDisputed, Reason: "vendor disputes it"}
	id := x.begin(t, "alice", d)
	if err := vdCommit(x, "alice", id, d); err != nil {
		t.Fatalf("commit = %v", err)
	}
}

// TestSweepReopensFalsePositiveWithoutInventory: a host NOS holds no complete
// package read for cannot be judged (errVulnNoInventory, D5). The false
// positive of such a finding is re-opened as basis_unknown (D4, D6) instead of
// staying suppressed for good (fail open).
func TestSweepReopensFalsePositiveWithoutInventory(t *testing.T) {
	ctx := context.Background()
	x := newVDEnv(t, "alice", nil)
	f := clsFinding(t, x.e, clsRecord("CVE-2026-8910", "openssl", clsOld, clsNew))
	// The decider refuses a decision on a basis NOS cannot judge, so the
	// false positive is stored directly, bound to the version NOS knew before
	// its inventory was lost.
	m := vulnstore.MarkFalsePositive{By: "alice", Category: vulnstore.CategoryVendorDisputed,
		Reason: "vendor disputes it", BasisVersion: clsOld}
	if err := x.e.svc.store.SetFalsePositive(ctx, f.Key, m, x.e.audit); err != nil {
		t.Fatalf("set false positive: %v", err)
	}
	if got := x.state(t, f); got != vulnstore.StateFalsePositive {
		t.Fatalf("state after the decision = %s, want false_positive", got)
	}
	var logs bytes.Buffer
	x.e.svc.log = slog.New(slog.NewTextHandler(&logs, nil))

	if _, err := x.e.svc.sweepOnce(ctx); err != nil {
		t.Fatalf("sweep without inventory: %v", err)
	}
	if got := x.state(t, f); got != vulnstore.StateOpen {
		t.Fatalf("state after sweep without inventory = %s, want open", got)
	}
	if !strings.Contains(logs.String(), "reason=basis_unknown") {
		t.Fatalf("log does not name the basis_unknown re-open:\n%s", logs.String())
	}
}

// TestSweepReopensFalsePositiveWithoutKernelData: when neither NOS read carries
// running kernel data, the kernel basis of a kernel finding cannot be judged
// (errVulnNoKernel, D4). The false positive re-opens as basis_unknown.
func TestSweepReopensFalsePositiveWithoutKernelData(t *testing.T) {
	ctx := context.Background()
	x := newVDEnv(t, "alice", nil)
	f := clsFinding(t, x.e, clsRecord("CVE-2026-8911", "linux", "6.1.119-1", "6.1.120-1"))
	clsSettle(x.e)
	clsPut(t, x.e, clsRead("r-kernel-"+f.Key.String()[:8], f.Updated.Add(clsLag+time.Minute), true, clsKernel("6.1.119-1")))
	vdFalsePositive(t, x, f)
	if got := x.state(t, f); got != vulnstore.StateFalsePositive {
		t.Fatalf("state after the decision = %s, want false_positive", got)
	}

	// A newer complete read carries no kernel data: neither read does.
	x.e.clk.Add(clsLag + 2*time.Minute)
	clsPut(t, x.e, clsRead("r-nokernel-"+f.Key.String()[:8], x.e.clk.Now(), true, vulninventory.Kernel{}, clsComp("openssl", clsOld)))
	var logs bytes.Buffer
	x.e.svc.log = slog.New(slog.NewTextHandler(&logs, nil))

	if _, err := x.e.svc.sweepOnce(ctx); err != nil {
		t.Fatalf("sweep without kernel data: %v", err)
	}
	if got := x.state(t, f); got != vulnstore.StateOpen {
		t.Fatalf("state after sweep without kernel data = %s, want open", got)
	}
	if !strings.Contains(logs.String(), "reason=basis_unknown") {
		t.Fatalf("log does not name the basis_unknown re-open:\n%s", logs.String())
	}
}
