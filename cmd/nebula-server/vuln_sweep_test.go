// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"errors"
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

// vdStoreFalsePositive stores a false positive of f bound to the version NOS
// knew before (clsOld). The decider would refuse a decision on a basis that
// cannot be judged, so the state is set directly.
func vdStoreFalsePositive(t *testing.T, x *vdEnv, f vulnstore.Finding) {
	t.Helper()
	m := vulnstore.MarkFalsePositive{By: "alice", Category: vulnstore.CategoryVendorDisputed,
		Reason: "vendor disputes it", BasisVersion: clsOld}
	if err := x.e.svc.store.SetFalsePositive(context.Background(), f.Key, m, x.e.audit); err != nil {
		t.Fatalf("set false positive: %v", err)
	}
	if got := x.state(t, f); got != vulnstore.StateFalsePositive {
		t.Fatalf("state after the decision = %s, want false_positive", got)
	}
}

// vdSweepReopens runs one sweep and checks that the finding re-opened and
// that the log names the given reason.
func vdSweepReopens(t *testing.T, x *vdEnv, f vulnstore.Finding, reason string) {
	t.Helper()
	var logs bytes.Buffer
	x.e.svc.log = slog.New(slog.NewTextHandler(&logs, nil))
	if _, err := x.e.svc.sweepOnce(context.Background()); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if got := x.state(t, f); got != vulnstore.StateOpen {
		t.Fatalf("state after sweep = %s, want open; log:\n%s", got, logs.String())
	}
	if !strings.Contains(logs.String(), reason) {
		t.Fatalf("log does not name %s:\n%s", reason, logs.String())
	}
}

// TestSweepReopensFalsePositiveWithMalformedFixedVersion: a malformed episode
// fixed version from the feed is a permanent error for this one finding. It
// is not transient, so the false positive re-opens as basis_unknown instead of
// staying suppressed for good (fail open, D6).
func TestSweepReopensFalsePositiveWithMalformedFixedVersion(t *testing.T) {
	x := newVDEnv(t, "alice", nil)
	f := clsFinding(t, x.e, clsRecord("CVE-2026-8920", "openssl", clsOld, clsNew))
	// The ingest validates the fixed version of a record, so the malformed
	// episode fix is stored directly, as an older feed version could have left it.
	if _, err := x.e.db.Exec("UPDATE vuln_findings SET episode_fixed_version = ? WHERE finding_key = ?",
		"3.0.16 !!malformed", f.Key[:]); err != nil {
		t.Fatalf("store malformed episode fix: %v", err)
	}
	clsSettle(x.e)
	clsPut(t, x.e, clsRead("r-malfix-"+f.Key.String()[:8], f.Updated.Add(clsLag+time.Minute), true,
		clsKernel("6.1.119-1"), clsComp("openssl", clsOld)))
	vdStoreFalsePositive(t, x, f)
	vdSweepReopens(t, x, f, "reason=basis_unknown")
}

// TestSweepReopensFalsePositiveWithUnknownEcosystem: an ecosystem NOS has no
// version scheme for is a permanent error of the finding (fail closed).
func TestSweepReopensFalsePositiveWithUnknownEcosystem(t *testing.T) {
	x := newVDEnv(t, "alice", nil)
	f := clsFinding(t, x.e, clsRecord("CVE-2026-8921", "openssl", clsOld, clsNew))
	// The ingest rejects such an ecosystem, so the record's ecosystem is
	// replaced directly. "alpine:" passes the checkable prefix but has no
	// release, so it has no version scheme (vulnver.SchemeForEcosystem).
	if _, err := x.e.db.Exec("UPDATE vuln_findings SET record = json_set(record, '$.ecosystem', 'alpine:') WHERE finding_key = ?",
		f.Key[:]); err != nil {
		t.Fatalf("store unknown ecosystem: %v", err)
	}
	clsSettle(x.e)
	clsPut(t, x.e, clsRead("r-eco-"+f.Key.String()[:8], f.Updated.Add(clsLag+time.Minute), true,
		clsKernel("6.1.119-1"), clsComp("openssl", clsOld)))
	vdStoreFalsePositive(t, x, f)
	vdSweepReopens(t, x, f, "reason=basis_unknown")
}

// TestSweepReopensFalsePositiveWhenBasisDoesNotCompare: a NOS version that
// cannot be compared with the episode fix is a permanent error of the finding
// (fail closed). The false positive re-opens as basis_unknown.
func TestSweepReopensFalsePositiveWhenBasisDoesNotCompare(t *testing.T) {
	x := newVDEnv(t, "alice", nil)
	f := clsFinding(t, x.e, clsRecord("CVE-2026-8922", "openssl", clsOld, clsNew))
	clsSettle(x.e)
	clsPut(t, x.e, clsRead("r-cmp-"+f.Key.String()[:8], f.Updated.Add(clsLag+time.Minute), true,
		clsKernel("6.1.119-1"), clsComp("openssl", "abc-bad")))
	vdStoreFalsePositive(t, x, f)
	vdSweepReopens(t, x, f, "reason=basis_unknown")
}

// TestSweepKeepsFalsePositiveWhenStoreReadIsCanceled: a deadline that passes
// while NOS reads the inventory is transient. The false positive stays for
// this sweep, the log names the basis error (basis_error), and the next sweep
// judges it again.
func TestSweepKeepsFalsePositiveWhenStoreReadIsCanceled(t *testing.T) {
	x := newVDEnv(t, "alice", nil)
	f := clsFinding(t, x.e, clsRecord("CVE-2026-8923", "openssl", clsOld, clsNew))
	clsSettle(x.e)
	clsPut(t, x.e, clsRead("r-dl-"+f.Key.String()[:8], f.Updated.Add(clsLag+time.Minute), true,
		clsKernel("6.1.119-1"), clsComp("openssl", clsOld)))
	vdStoreFalsePositive(t, x, f)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	x.e.svc.classifier.betweenReads = func() { <-ctx.Done() }
	var logs bytes.Buffer
	x.e.svc.log = slog.New(slog.NewTextHandler(&logs, nil))

	if _, err := x.e.svc.sweepOnce(ctx); err != nil {
		t.Logf("sweep error (only the review matters here): %v", err)
	}
	if got := x.state(t, f); got != vulnstore.StateFalsePositive {
		t.Fatalf("state after sweep with a canceled read = %s, want false_positive", got)
	}
	if !strings.Contains(logs.String(), "basis_error=1") {
		t.Fatalf("log does not name the basis error:\n%s", logs.String())
	}
	if strings.Contains(logs.String(), "reason=basis_unknown") {
		t.Fatalf("a canceled read must not re-open as basis_unknown:\n%s", logs.String())
	}
}

// TestBasisErrorsFailClosedUnlessTransient: only the named transient errors
// keep a human state for one sweep (isTransientBasisErr). Every other error,
// including a malformed stored read, means the basis is unknown.
func TestBasisErrorsFailClosedUnlessTransient(t *testing.T) {
	badRead := storeReadErr("latest read", fmt.Errorf("decode: %w", vulninventory.ErrInvalidRead))
	dbErr := storeReadErr("latest read", errors.New("database is locked"))
	cases := []struct {
		name      string
		err       error
		transient bool
	}{
		{"read race", errVulnReadRace, true},
		{"deadline", fmt.Errorf("classify: %w", context.DeadlineExceeded), true},
		{"canceled", fmt.Errorf("classify: %w", context.Canceled), true},
		{"database read", dbErr, true},
		{"database read wrapped by a later step", fmt.Errorf("classify: again: %w", dbErr), true},
		{"malformed stored read", badRead, false},
		{"no inventory", errVulnNoInventory, false},
		{"no kernel", errVulnNoKernel, false},
		{"other ecosystem", errVulnEcosystem, false},
		{"no ecosystem", errVulnNoEcosystem, false},
		{"malformed fixed version", fmt.Errorf("classify: episode fixed version: %w", errors.New("bad")), false},
		{"unknown scheme", fmt.Errorf("classify: ecosystem: %w", errors.New("no scheme")), false},
		{"compare", fmt.Errorf("classify: compare basis: %w", errors.New("bad")), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isTransientBasisErr(c.err); got != c.transient {
				t.Fatalf("isTransientBasisErr(%v) = %v, want %v", c.err, got, c.transient)
			}
		})
	}
}
