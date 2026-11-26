// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// fimGrantB is a second approved lease ID, distinct from testGrantID.
const fimGrantB = "6f1c2a3b-4d5e-4f60-8a71-92b3c4d5e6f8"

// fimCanonFull is the canonical parameter document of fim.scan's full mode.
const fimCanonFull = `{"mode":"full","profile":"fim-default-v1"}`

// fimLeaseDoc is an approved ordinary lease on hosts whose document binds
// fim.scan in mode, plus the other actions. It lasts 14 days, so tests that
// tick for more than a week stay inside it.
func fimLeaseDoc(t *testing.T, now time.Time, hosts []string, mode string, others ...string) permit.ReadGrantDoc {
	t.Helper()
	doc := leaseDoc(t, now, hosts, others...)
	doc.ExpiryUnix = now.Add(14 * 24 * time.Hour).Unix()
	_, h, ok := fimScanModeParams(mode)
	if !ok {
		t.Fatalf("no fim.scan mode %q", mode)
	}
	doc.Actions = append(doc.Actions, fimEntry(t, h))
	return doc
}

// fimEntry is the grant entry of fim.scan bound to hash.
func fimEntry(t *testing.T, hash string) permit.ReadGrantAction {
	t.Helper()
	a, ok := actions.Lookup(permit.FimScanActionID)
	if !ok {
		t.Fatal("fim.scan is not in the catalog")
	}
	return permit.ReadGrantAction{ActionID: a.ID, ModuleVersion: a.Version, ArtifactSHA256: a.SHA256(), ParametersHash: hash}
}

// hashOf is the canonical parameters hash of raw JSON.
func hashOf(t *testing.T, raw string) string {
	t.Helper()
	h, err := canonical.HashParameters([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// fimFloorFake answers fim.scan the way the executor does: a run of one mode
// on one host sooner than the mode's floor after its last accepted run is
// refused with ResourceExhausted. Every fim.scan request that is refused is
// kept in early; the test fails on any of them. Other actions go to the
// embedded fake.
type fimFloorFake struct {
	*leaseRunFake
	clock    *time.Time
	accepted map[string]time.Time // host and parameters -> last accepted run
	times    []time.Time          // accepted fim.scan runs, in order
	early    []*pb.RunReadGrantRequest
}

func (f *fimFloorFake) RunReadGrant(ctx context.Context, in *pb.RunReadGrantRequest, opts ...grpc.CallOption) (*pb.RunReadGrantResponse, error) {
	run := in.GetRun()
	if run.GetActionId() != permit.FimScanActionID {
		return f.leaseRunFake.RunReadGrant(ctx, in, opts...)
	}
	floor := permit.FimScanIncrementalMinInterval
	if h, err := canonical.HashParameters(run.GetParametersJson()); err == nil && h == permit.FimScanFullParametersHash {
		floor = permit.FimScanFullMinInterval
	}
	key := run.GetHostId() + "\x00" + string(run.GetParametersJson())
	if at, ok := f.accepted[key]; ok && f.clock.Sub(at) < floor {
		f.early = append(f.early, in)
		f.runs = append(f.runs, in)
		return nil, status.Error(codes.ResourceExhausted, "read_grant_budget_exhausted: read interval or rolling-hour budget exhausted")
	}
	f.accepted[key] = *f.clock
	f.times = append(f.times, *f.clock)
	return f.leaseRunFake.RunReadGrant(ctx, in, opts...)
}

// setupFimFloor is setupLeases with the fim.scan floor executor double.
func setupFimFloor(t *testing.T, now *time.Time, grants ...func(time.Time) *pb.ReadGrant) (*Service, *fimFloorFake) {
	t.Helper()
	s, f := setupLeases(t, now, grants...)
	ff := &fimFloorFake{leaseRunFake: f, clock: now, accepted: map[string]time.Time{}}
	s.exec = ff
	return s, ff
}

// fimRunsOf returns the fim.scan requests the executor received, by grant.
func fimRunsOf(runs []*pb.RunReadGrantRequest) map[string]int {
	out := map[string]int{}
	for _, r := range runs {
		if r.GetRun().GetActionId() == permit.FimScanActionID {
			out[r.GetGrantId()]++
		}
	}
	return out
}

// TestFimScanEntrySendsItsCanonicalParameters checks that the runner sends the
// canonical parameters of the granted mode, whose hash is the grant's
// ParametersHash, and stores them with the run.
func TestFimScanEntrySendsItsCanonicalParameters(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s, f := setupLeases(t, &now, func(n time.Time) *pb.ReadGrant {
		return leaseEntry(t, fimLeaseDoc(t, n, []string{"web"}, "full"), n)
	})
	s.RunDueReadGrants(context.Background())
	if len(f.runs) != 1 {
		t.Fatalf("%d runs, want 1 fim.scan run", len(f.runs))
	}
	run := f.runs[0].GetRun()
	a, _ := actions.Lookup(permit.FimScanActionID)
	if run.GetActionId() != a.ID || run.GetModuleVersion() != a.Version || string(run.GetArtifact()) != string(a.Script) {
		t.Fatalf("not the catalog contract: %s %s", run.GetActionId(), run.GetModuleVersion())
	}
	sent := run.GetParametersJson()
	if string(sent) != fimCanonFull {
		t.Fatalf("sent %s, want %s", sent, fimCanonFull)
	}
	if h := hashOf(t, string(sent)); h != permit.FimScanFullParametersHash {
		t.Fatalf("sent bytes hash to %s, not the grant's hash", h)
	}
	if f.runs[0].GetTimeoutSeconds() != uint32(a.Timeout/time.Second) {
		t.Fatalf("timeout %d s, want %d s", f.runs[0].GetTimeoutSeconds(), uint32(a.Timeout/time.Second))
	}
	var stored string
	if err := s.db.QueryRow(`SELECT params FROM executions WHERE action_id = ? AND schedule_id = ?`,
		permit.FimScanActionID, testGrantID).Scan(&stored); err != nil || stored != fimCanonFull {
		t.Fatalf("stored parameters %q: %v", stored, err)
	}
}

// TestFimScanEntryWithAForeignBindingIsNeverRun checks that a foreign profile,
// a foreign mode, a wrong hash or the hash of "{}" never yields parameters, and
// that no such entry reaches the executor.
func TestFimScanEntryWithAForeignBindingIsNeverRun(t *testing.T) {
	for _, tc := range []struct {
		name, hash string
	}{
		{"foreign profile", hashOf(t, `{"mode":"full","profile":"other-v1"}`)},
		{"foreign mode", hashOf(t, `{"mode":"weekly","profile":"fim-default-v1"}`)},
		{"wrong hash", strings.Repeat("e", 64)},
		{"parameters of {}", hashOf(t, `{}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if params, ok := fimScanParams(tc.hash); ok {
				t.Fatalf("fimScanParams accepts the hash, with %s", params)
			}
			now := time.Now().Truncate(time.Second)
			doc := leaseDoc(t, now, []string{"web"}, "core.facts")
			doc.Actions = append(doc.Actions, fimEntry(t, tc.hash))
			s, f := setupLeases(t, &now, func(n time.Time) *pb.ReadGrant { return leaseEntry(t, doc, n) })
			s.RunDueReadGrants(context.Background())
			if n := fimRunsOf(f.runs)[testGrantID]; n != 0 {
				t.Fatalf("%d fim.scan requests for a binding the executor never granted", n)
			}
		})
	}
}

// TestFullFimScanIsNotRequestedBeforeSevenDaysMinusSixHours ticks hourly for
// just over eight days. The executor refuses any fim.scan full run sooner than
// its floor, and the test fails if the runner asks for one.
func TestFullFimScanIsNotRequestedBeforeSevenDaysMinusSixHours(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s, f := setupFimFloor(t, &now, func(n time.Time) *pb.ReadGrant {
		return leaseEntry(t, fimLeaseDoc(t, n, []string{"web"}, "full"), n)
	})
	ctx := context.Background()
	for i := 0; i <= 8*24; i++ {
		s.RunDueReadGrants(ctx)
		now = now.Add(time.Hour)
	}
	if len(f.early) != 0 {
		t.Fatalf("%d full fim.scan requests before their floor", len(f.early))
	}
	if len(f.times) != 2 {
		t.Fatalf("%d accepted full runs in eight days, want 2", len(f.times))
	}
	gap := f.times[1].Sub(f.times[0])
	if gap < permit.FimScanFullMinInterval || gap >= permit.FimScanFullMinInterval+time.Hour {
		t.Fatalf("second full run %s after the first, want %s (hourly ticks)", gap, permit.FimScanFullMinInterval)
	}
}

// TestFreshRunOfOneModeDoesNotDelayTheOther grants one lease incremental and
// one full on the same host. Both run in the first tick. An hour later only
// the incremental one is due, and the full one is not asked for.
func TestFreshRunOfOneModeDoesNotDelayTheOther(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s, f := setupFimFloor(t, &now,
		func(n time.Time) *pb.ReadGrant {
			return leaseEntry(t, fimLeaseDoc(t, n, []string{"web"}, "incremental"), n)
		},
		func(n time.Time) *pb.ReadGrant {
			doc := fimLeaseDoc(t, n, []string{"web"}, "full")
			doc.ID = fimGrantB
			return leaseEntry(t, doc, n)
		})
	ctx := context.Background()

	s.RunDueReadGrants(ctx)
	if got := fimRunsOf(f.runs); got[testGrantID] != 1 || got[fimGrantB] != 1 {
		t.Fatalf("first tick fim.scan requests %v, want one per lease", got)
	}
	now = now.Add(time.Hour)
	before := len(f.runs)
	s.RunDueReadGrants(ctx)
	if got := fimRunsOf(f.runs[before:]); got[testGrantID] != 1 || got[fimGrantB] != 0 {
		t.Fatalf("one hour later fim.scan requests %v, want only the incremental lease", got)
	}
	if len(f.early) != 0 {
		t.Fatalf("%d refused fim.scan requests", len(f.early))
	}
}

// TestRefusedFimScanDoesNotStopTheOtherActionsOfTheHost refuses the fim.scan
// entry, listed before core.facts. core.facts still runs in the same tick.
func TestRefusedFimScanDoesNotStopTheOtherActionsOfTheHost(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	doc := fimLeaseDoc(t, now, []string{"web"}, "full")
	doc.Actions = append(doc.Actions, leaseDoc(t, now, []string{"web"}, "core.facts").Actions...)
	s, f := setupLeases(t, &now, func(n time.Time) *pb.ReadGrant { return leaseEntry(t, doc, n) })
	ff := &imageRunFake{leaseRunFake: f, refuse: map[string]error{
		permit.FimScanActionID: status.Error(codes.ResourceExhausted, "read_grant_budget_exhausted: read interval or rolling-hour budget exhausted"),
	}}
	s.exec = ff
	s.RunDueReadGrants(context.Background())
	if got := runActions(ff); len(got) != 2 || got[0] != permit.FimScanActionID || got[1] != "core.facts" {
		t.Fatalf("runs %v, want fim.scan refused then core.facts", got)
	}
}

// callDeadlineFake records how long a read call may take.
type callDeadlineFake struct {
	*leaseRunFake
	left time.Duration
}

func (f *callDeadlineFake) RunReadGrant(ctx context.Context, in *pb.RunReadGrantRequest, opts ...grpc.CallOption) (*pb.RunReadGrantResponse, error) {
	if dl, ok := ctx.Deadline(); ok {
		f.left = time.Until(dl)
	}
	return f.leaseRunFake.RunReadGrant(ctx, in, opts...)
}

// TestFimScanCallDoesNotWaitForTheJob checks that the call that starts a
// durable fim.scan read is bounded by durableReadCallTimeout, not by the job's
// 40 minutes.
func TestFimScanCallDoesNotWaitForTheJob(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s, f := setupLeases(t, &now, func(n time.Time) *pb.ReadGrant {
		return leaseEntry(t, fimLeaseDoc(t, n, []string{"web"}, "full"), n)
	})
	cf := &callDeadlineFake{leaseRunFake: f}
	s.exec = cf
	s.RunDueReadGrants(context.Background())
	if len(f.runs) != 1 {
		t.Fatalf("%d runs, want 1", len(f.runs))
	}
	if cf.left <= 0 || cf.left > durableReadCallTimeout {
		t.Fatalf("call deadline %s away, want at most %s", cf.left, durableReadCallTimeout)
	}
}
