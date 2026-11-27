// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"database/sql"
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

// TestTwoLeasesOnOneHostShareTheFullFloor grants two leases that both bind
// fim.scan full on the same host. The executor's floor is per host and mode,
// so only one full run may be asked for per floor: the second lease waits for
// the first lease's run, and the runner never asks the executor early.
func TestTwoLeasesOnOneHostShareTheFullFloor(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s, f := setupFimFloor(t, &now,
		func(n time.Time) *pb.ReadGrant {
			return leaseEntry(t, fimLeaseDoc(t, n, []string{"web"}, "full"), n)
		},
		func(n time.Time) *pb.ReadGrant {
			doc := fimLeaseDoc(t, n, []string{"web"}, "full")
			doc.ID = fimGrantB
			return leaseEntry(t, doc, n)
		})
	ctx := context.Background()
	for i := 0; i <= 8*24; i++ {
		s.RunDueReadGrants(ctx)
		now = now.Add(time.Hour)
	}
	if len(f.early) != 0 {
		t.Fatalf("%d full fim.scan requests before the host's floor", len(f.early))
	}
	if len(f.times) != 2 {
		t.Fatalf("%d accepted full runs on the host in eight days, want 2", len(f.times))
	}
	if gap := f.times[1].Sub(f.times[0]); gap < permit.FimScanFullMinInterval {
		t.Fatalf("second full run %s after the first, want at least %s", gap, permit.FimScanFullMinInterval)
	}
}

// jobFake is an executor whose durable fim.scan job ends only when final is
// set: until then GetRun reports it running. Its release is recorded.
type jobFake struct {
	*leaseRunFake
	final    *pb.RunStatus
	released bool
}

func (f *jobFake) GetRun(_ context.Context, in *pb.GetRunRequest, _ ...grpc.CallOption) (*pb.GetRunResponse, error) {
	if in.GetRelease() {
		f.released = true
		return &pb.GetRunResponse{Run: f.final}, nil
	}
	if f.final == nil {
		return &pb.GetRunResponse{Run: &pb.RunStatus{State: "running"}}, nil
	}
	return &pb.GetRunResponse{Run: f.final}, nil
}

// TestFimScanJobIsRunningUntilItsOutcomeIsCollected checks that a fim.scan
// read the executor started is stored as running, with no class and no finish
// time, and that its real outcome is stored once the job has ended.
func TestFimScanJobIsRunningUntilItsOutcomeIsCollected(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s, f := setupLeases(t, &now, func(n time.Time) *pb.ReadGrant {
		return leaseEntry(t, fimLeaseDoc(t, n, []string{"web"}, "full"), n)
	})
	jf := &jobFake{leaseRunFake: f}
	s.exec = jf
	ctx := context.Background()

	s.RunDueReadGrants(ctx)
	if len(f.runs) != 1 {
		t.Fatalf("%d runs, want 1 fim.scan run", len(f.runs))
	}
	var state, class string
	var durable int
	var finished sql.NullInt64
	if err := s.db.QueryRow(`SELECT h.state, h.class, e.durable, e.finished_at FROM execution_hosts h
		JOIN executions e ON e.id = h.execution_id WHERE e.action_id = ? AND e.schedule_id = ?`,
		permit.FimScanActionID, testGrantID).Scan(&state, &class, &durable, &finished); err != nil {
		t.Fatal(err)
	}
	if state != "running" || class != "" || durable != 1 || finished.Valid {
		t.Fatalf("while the job runs: host %q class %q durable %d finished %v; want running, no class, durable, unfinished",
			state, class, durable, finished)
	}

	jf.final = &pb.RunStatus{State: "finished", Class: "script_failed", ExitCode: 3, Detail: "scan broke", Result: []byte(`{"ok":false}`)}
	now = now.Add(time.Hour)
	s.RunDueReadGrants(ctx)
	var exitCode int
	if err := s.db.QueryRow(`SELECT h.state, h.class, h.exit_code, e.finished_at FROM execution_hosts h
		JOIN executions e ON e.id = h.execution_id WHERE e.action_id = ? AND e.schedule_id = ?`,
		permit.FimScanActionID, testGrantID).Scan(&state, &class, &exitCode, &finished); err != nil {
		t.Fatal(err)
	}
	if state != "finished" || class != "script_failed" || exitCode != 3 || !finished.Valid {
		t.Fatalf("after the job ended: host %q class %q exit %d finished %v; want finished with the job's outcome",
			state, class, exitCode, finished)
	}
	if !jf.released {
		t.Fatal("the job's result was not released on the executor after it was stored")
	}
}

// TestOnlyFimScanIsDurableInALease checks the runner's own durability rule for
// every built-in action. The grant allowlist refuses the other durable actions
// too, but that check is not the runner's, so the rule is tested on its own:
// fim.scan is the one durable action a lease may run, and every attached
// action is allowed. docker.update_preview is durable and read-only, so the
// test fails if the rule admits every durable read-only action.
func TestOnlyFimScanIsDurableInALease(t *testing.T) {
	durableOther := 0
	for _, a := range actions.Builtin {
		ok := durableLeaseOK(a)
		switch {
		case a.ID == permit.FimScanActionID && !ok:
			t.Errorf("fim.scan is refused by the lease runner")
		case a.Durable && a.ID != permit.FimScanActionID:
			durableOther++
			if ok {
				t.Errorf("%s is durable and runs from a read lease (read-only %v)", a.ID, a.ReadOnly)
			}
		case !a.Durable && !ok:
			t.Errorf("%s is attached and refused by the lease runner", a.ID)
		}
	}
	if durableOther == 0 {
		t.Fatal("the catalog has no durable action besides fim.scan; the check ran on nothing")
	}
	// The rule is durable == (ID == fim.scan), so fim.scan without the durable
	// flag is refused too: a rule that drops the flag would accept it.
	fs, ok := actions.Lookup(permit.FimScanActionID)
	if !ok {
		t.Fatal("fim.scan is not in the catalog")
	}
	fs.Durable = false
	if durableLeaseOK(fs) {
		t.Error("fim.scan without the durable flag is accepted by the lease runner")
	}
}

// manualGetRunFake is a jobFake that reports the run manual, a durable run a
// user started on the host, as unknown: NotFound on any read of it, release
// included. Every such read is recorded in touched.
type manualGetRunFake struct {
	*jobFake
	manual  string
	touched []string
}

func (f *manualGetRunFake) GetRun(ctx context.Context, in *pb.GetRunRequest, opts ...grpc.CallOption) (*pb.GetRunResponse, error) {
	if in.GetExecutionId() == f.manual {
		f.touched = append(f.touched, in.GetExecutionId())
		return nil, status.Error(codes.NotFound, "no record of this run")
	}
	return f.jobFake.GetRun(ctx, in, opts...)
}

// TestManualDurableRunIsNotCollectedAsALeaseJob checks that collectLeaseJobs
// reads only the durable jobs of leases. A user's durable fim.scan run in
// flight on the same host, with no schedule, is never read, marked unknown or
// finished, or released, while the lease's own job is still collected.
func TestManualDurableRunIsNotCollectedAsALeaseJob(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s, f := setupLeases(t, &now, func(n time.Time) *pb.ReadGrant {
		return leaseEntry(t, fimLeaseDoc(t, n, []string{"web"}, "full"), n)
	})
	const manualID = "00000000-0000-4000-8000-0000000000c1"
	mf := &manualGetRunFake{jobFake: &jobFake{leaseRunFake: f}, manual: manualID}
	s.exec = mf
	ctx := context.Background()

	s.RunDueReadGrants(ctx)
	if len(f.runs) != 1 {
		t.Fatalf("%d runs, want 1 fim.scan run of the lease", len(f.runs))
	}
	insertManualFimScan(t, s, manualID, "incremental", "running", "running", "", now)

	mf.final = &pb.RunStatus{State: "finished", Class: "success", Result: []byte(`{"ok":true}`)}
	now = now.Add(time.Hour)
	s.RunDueReadGrants(ctx)

	if len(mf.touched) != 0 {
		t.Fatalf("the manual durable run was read %d times as a lease job, want 0", len(mf.touched))
	}
	var hostState, class, execState string
	var finished sql.NullInt64
	if err := s.db.QueryRow(`SELECT h.state, h.class, e.state, e.finished_at FROM execution_hosts h
		JOIN executions e ON e.id = h.execution_id WHERE e.id = ?`, manualID).Scan(&hostState, &class, &execState, &finished); err != nil {
		t.Fatal(err)
	}
	if hostState != "running" || class != "" || execState != "running" || finished.Valid {
		t.Fatalf("manual run: host %q class %q state %q finished %v; want untouched and running",
			hostState, class, execState, finished)
	}
	var leaseState string
	if err := s.db.QueryRow(`SELECT h.state FROM execution_hosts h
		JOIN executions e ON e.id = h.execution_id WHERE e.action_id = ? AND e.schedule_id = ?`,
		permit.FimScanActionID, testGrantID).Scan(&leaseState); err != nil {
		t.Fatal(err)
	}
	if leaseState != "finished" || !mf.released {
		t.Fatalf("lease job host %q released %v; want the lease job collected and released", leaseState, mf.released)
	}
}

// insertManualFimScan stores a fim.scan execution of mode that no lease
// stored, with the states the executor leaves it in. startedAt is the host's
// start; the zero time means it never started.
func insertManualFimScan(t *testing.T, s *Service, id, mode, state, hostState, class string, startedAt time.Time) {
	t.Helper()
	a, ok := actions.Lookup(permit.FimScanActionID)
	if !ok {
		t.Fatal("fim.scan is not in the catalog")
	}
	canon, _, ok := fimScanModeParams(mode)
	if !ok {
		t.Fatalf("no fim.scan mode %q", mode)
	}
	if _, err := s.db.Exec(`INSERT INTO executions (id, digest, action_id, module_version, artifact_sha256, risk, requirement, state,
			durable, timeout_s, created_by, created_at, params) VALUES (?, '', ?, ?, ?, 'LOW', ?, ?, 1, ?, 'user', ?, ?)`,
		id, a.ID, a.Version, a.SHA256(), leaseRunRequirement, state, int64(a.Timeout/time.Second), s.now().Unix(), string(canon)); err != nil {
		t.Fatal(err)
	}
	var started any
	if !startedAt.IsZero() {
		started = startedAt.Unix()
	}
	if _, err := s.db.Exec(`INSERT INTO execution_hosts (execution_id, host_id, fingerprint, credential_ref, endpoints, state, class, started_at)
			VALUES (?, 'web', ?, 'nebula-default', '[]', ?, ?, ?)`, id, leaseWebKey, hostState, class, started); err != nil {
		t.Fatal(err)
	}
}

// TestRequestsTheExecutorNeverStartedDoNotMoveTheFullFloor stores full fim.scan
// requests on the host that never ran: pending, rejected, expired, and one
// the job collection ended as unknown. None of them moves the host's floor,
// so the lease asks for its full scan at once.
func TestRequestsTheExecutorNeverStartedDoNotMoveTheFullFloor(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s, f := setupFimFloor(t, &now, func(n time.Time) *pb.ReadGrant {
		return leaseEntry(t, fimLeaseDoc(t, n, []string{"web"}, "full"), n)
	})
	insertManualFimScan(t, s, "00000000-0000-4000-8000-0000000000a1", "full", "pending", "waiting", "", time.Time{})
	insertManualFimScan(t, s, "00000000-0000-4000-8000-0000000000a2", "full", "rejected", "waiting", "", time.Time{})
	insertManualFimScan(t, s, "00000000-0000-4000-8000-0000000000a3", "full", "expired", "finished", "not_executed", time.Time{})
	insertManualFimScan(t, s, "00000000-0000-4000-8000-0000000000a4", "full", "finished", "finished", "unknown", now)

	s.RunDueReadGrants(context.Background())
	if len(f.times) != 1 || !f.times[0].Equal(now) {
		t.Fatalf("full fim.scan requests at %v, want one at once", f.times)
	}
}

// TestStartedManualFullRunMovesTheFloor stores a full fim.scan run on the host
// that the executor started, still running or finished. The lease asks for its
// own full scan no sooner than 7 d - 6 h after that start.
func TestStartedManualFullRunMovesTheFloor(t *testing.T) {
	cases := []struct{ name, state, hostState, class string }{
		{"running", "running", "running", ""},
		{"finished", "finished", "finished", "success"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			now := time.Now().Truncate(time.Second)
			s, f := setupFimFloor(t, &now, func(n time.Time) *pb.ReadGrant {
				return leaseEntry(t, fimLeaseDoc(t, n, []string{"web"}, "full"), n)
			})
			start := now
			insertManualFimScan(t, s, "00000000-0000-4000-8000-0000000000b1", "full", c.state, c.hostState, c.class, start)

			ctx := context.Background()
			for i := 0; i <= 8*24; i++ {
				s.RunDueReadGrants(ctx)
				now = now.Add(time.Hour)
			}
			if len(f.times) == 0 {
				t.Fatal("no full fim.scan request in eight days")
			}
			if gap := f.times[0].Sub(start); gap < permit.FimScanFullMinInterval {
				t.Fatalf("first full request %s after the started run, want at least %s", gap, permit.FimScanFullMinInterval)
			}
		})
	}
}

// TestFimScanLeaseRunIsRunningWhileItsJobRuns checks that the execution of a
// dispatched fim.scan job is running, not finished, while the job runs: no
// execution is ever finished without a finish time.
func TestFimScanLeaseRunIsRunningWhileItsJobRuns(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s, f := setupLeases(t, &now, func(n time.Time) *pb.ReadGrant {
		return leaseEntry(t, fimLeaseDoc(t, n, []string{"web"}, "full"), n)
	})
	jf := &jobFake{leaseRunFake: f}
	s.exec = jf
	ctx := context.Background()

	s.RunDueReadGrants(ctx)
	if len(f.runs) != 1 {
		t.Fatalf("%d runs, want 1 fim.scan run", len(f.runs))
	}
	var state string
	var finished sql.NullInt64
	if err := s.db.QueryRow(`SELECT state, finished_at FROM executions WHERE action_id = ? AND schedule_id = ?`,
		permit.FimScanActionID, testGrantID).Scan(&state, &finished); err != nil {
		t.Fatal(err)
	}
	if state != "running" || finished.Valid {
		t.Fatalf("while the job runs: execution state %q finished %v; want running, unfinished", state, finished)
	}
	var bad int
	if err := s.db.QueryRow(`SELECT count(*) FROM executions WHERE state = 'finished' AND finished_at IS NULL`).Scan(&bad); err != nil {
		t.Fatal(err)
	}
	if bad != 0 {
		t.Fatalf("%d executions are finished without a finish time", bad)
	}
}

// TestFimScanLeaseRunIsFinalWhenItsJobIsCollected checks that collecting the
// job's outcome sets the execution's final state and its finish time.
func TestFimScanLeaseRunIsFinalWhenItsJobIsCollected(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s, f := setupLeases(t, &now, func(n time.Time) *pb.ReadGrant {
		return leaseEntry(t, fimLeaseDoc(t, n, []string{"web"}, "full"), n)
	})
	jf := &jobFake{leaseRunFake: f}
	s.exec = jf
	ctx := context.Background()

	s.RunDueReadGrants(ctx)
	jf.final = &pb.RunStatus{State: "finished", Class: "success", Result: []byte(`{"ok":true}`)}
	now = now.Add(time.Hour)
	s.RunDueReadGrants(ctx)

	var state string
	var finished sql.NullInt64
	if err := s.db.QueryRow(`SELECT state, finished_at FROM executions WHERE action_id = ? AND schedule_id = ?`,
		permit.FimScanActionID, testGrantID).Scan(&state, &finished); err != nil {
		t.Fatal(err)
	}
	if state != "finished" || !finished.Valid || finished.Int64 != now.Unix() {
		t.Fatalf("after collection: execution state %q finished %v; want finished at %d", state, finished, now.Unix())
	}
	if !jf.released {
		t.Fatal("the job's result was not released on the executor after collection")
	}
}

// TestFimScanDueCheckCountsADispatchedJobAsStarted checks that a fim.scan job
// the executor started, still running, moves the host's floor: the due check
// must not propose the same run again while the job runs.
func TestFimScanDueCheckCountsADispatchedJobAsStarted(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s, f := setupLeases(t, &now, func(n time.Time) *pb.ReadGrant {
		return leaseEntry(t, fimLeaseDoc(t, n, []string{"web"}, "full"), n)
	})
	jf := &jobFake{leaseRunFake: f}
	s.exec = jf
	ctx := context.Background()

	s.RunDueReadGrants(ctx)
	started := now
	now = now.Add(time.Hour)
	s.RunDueReadGrants(ctx)
	if len(f.runs) != 1 {
		t.Fatalf("%d runs, want 1: the running job must not be proposed again", len(f.runs))
	}
	canon, _, ok := fimScanModeParams("full")
	if !ok {
		t.Fatal(`no fim.scan mode "full"`)
	}
	last, err := s.fimScanLastRuns(ctx, canon)
	if err != nil {
		t.Fatal(err)
	}
	if at, ok := last["web"]; !ok || !at.Equal(started) {
		t.Fatalf("last full run on web %v (present %v), want %v", at, ok, started)
	}
}

// orphanRunning counts the executions stored as running that have no host row,
// and the finished hosts whose execution is still running. Either one is a row
// that collectLeaseJobs can never complete.
func orphanRunning(t *testing.T, s *Service) (orphans, mismatched int) {
	t.Helper()
	if err := s.db.QueryRow(`SELECT count(*) FROM executions e WHERE e.state = 'running'
		AND NOT EXISTS (SELECT 1 FROM execution_hosts h WHERE h.execution_id = e.id)`).Scan(&orphans); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT count(*) FROM execution_hosts h JOIN executions e ON e.id = h.execution_id
		WHERE h.state = 'finished' AND e.state = 'running'`).Scan(&mismatched); err != nil {
		t.Fatal(err)
	}
	return orphans, mismatched
}

// TestFimScanJobWithoutItsHostRowIsNotStored checks that a fim.scan job whose
// host row cannot be inserted leaves no execution stored as running: the
// execution row goes with the failed host row, so no run is left that
// collectLeaseJobs can never complete.
func TestFimScanJobWithoutItsHostRowIsNotStored(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s, f := setupLeases(t, &now, func(n time.Time) *pb.ReadGrant {
		return leaseEntry(t, fimLeaseDoc(t, n, []string{"web"}, "full"), n)
	})
	jf := &jobFake{leaseRunFake: f}
	s.exec = jf
	if _, err := s.db.Exec(`CREATE TRIGGER fail_fim_host_insert BEFORE INSERT ON execution_hosts
		WHEN NEW.state = 'running' AND (SELECT action_id FROM executions WHERE id = NEW.execution_id) = '` + permit.FimScanActionID + `'
		BEGIN SELECT RAISE(ABORT, 'forced host insert failure'); END`); err != nil {
		t.Fatal(err)
	}

	s.RunDueReadGrants(context.Background())
	if len(f.runs) != 1 {
		t.Fatalf("%d runs, want 1 fim.scan run", len(f.runs))
	}
	if orphans, _ := orphanRunning(t, s); orphans != 0 {
		t.Fatalf("%d executions are running without a host row; want none", orphans)
	}
}

// TestFailedExecutionUpdateLeavesFimScanHostRunning checks that the outcome of
// a fim.scan job is stored in one transaction: when the execution's final
// update fails, the host's outcome is not stored either, so the host is never
// finished while its execution is still running. The job stays running, is
// not released on the executor, and is stored by the next tick.
func TestFailedExecutionUpdateLeavesFimScanHostRunning(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s, f := setupLeases(t, &now, func(n time.Time) *pb.ReadGrant {
		return leaseEntry(t, fimLeaseDoc(t, n, []string{"web"}, "full"), n)
	})
	jf := &jobFake{leaseRunFake: f}
	s.exec = jf
	ctx := context.Background()

	s.RunDueReadGrants(ctx)
	if len(f.runs) != 1 {
		t.Fatalf("%d runs, want 1 fim.scan run", len(f.runs))
	}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_fim_finish BEFORE UPDATE ON executions
		WHEN NEW.state = 'finished' AND OLD.action_id = '` + permit.FimScanActionID + `'
		BEGIN SELECT RAISE(ABORT, 'forced finish failure'); END`); err != nil {
		t.Fatal(err)
	}
	jf.final = &pb.RunStatus{State: "finished", Class: "success", Result: []byte(`{"ok":true}`)}
	now = now.Add(time.Hour)
	s.RunDueReadGrants(ctx)

	var hostState, execState string
	var finished sql.NullInt64
	if err := s.db.QueryRow(`SELECT h.state, e.state, e.finished_at FROM execution_hosts h
		JOIN executions e ON e.id = h.execution_id WHERE e.action_id = ? AND e.schedule_id = ?`,
		permit.FimScanActionID, testGrantID).Scan(&hostState, &execState, &finished); err != nil {
		t.Fatal(err)
	}
	if hostState != "running" || execState != "running" || finished.Valid {
		t.Fatalf("after a failed final update: host %q execution %q finished %v; want both running, unfinished",
			hostState, execState, finished)
	}
	if jf.released {
		t.Fatal("the job's result was released although its outcome was not stored")
	}
	if orphans, mismatched := orphanRunning(t, s); orphans != 0 || mismatched != 0 {
		t.Fatalf("%d running executions without a host, %d finished hosts of running executions; want none", orphans, mismatched)
	}

	if _, err := s.db.Exec(`DROP TRIGGER fail_fim_finish`); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	s.RunDueReadGrants(ctx)
	if err := s.db.QueryRow(`SELECT h.state, e.state, e.finished_at FROM execution_hosts h
		JOIN executions e ON e.id = h.execution_id WHERE e.action_id = ? AND e.schedule_id = ?`,
		permit.FimScanActionID, testGrantID).Scan(&hostState, &execState, &finished); err != nil {
		t.Fatal(err)
	}
	if hostState != "finished" || execState != "finished" || !finished.Valid || finished.Int64 != now.Unix() {
		t.Fatalf("after the next tick: host %q execution %q finished %v; want both finished at %d",
			hostState, execState, finished, now.Unix())
	}
	if !jf.released {
		t.Fatal("the job's result was not released after it was stored")
	}
}

// TestLegacyFimScanRowWithoutFinishTimeIsCompleted checks the repair of a row
// that an earlier version stored as finished without a finish time while its
// host was still running: collecting the job completes both.
func TestLegacyFimScanRowWithoutFinishTimeIsCompleted(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s, f := setupLeases(t, &now, func(n time.Time) *pb.ReadGrant {
		return leaseEntry(t, fimLeaseDoc(t, n, []string{"web"}, "full"), n)
	})
	jf := &jobFake{leaseRunFake: f, final: &pb.RunStatus{State: "finished", Class: "success", Result: []byte(`{"ok":true}`)}}
	s.exec = jf
	ctx := context.Background()

	a, ok := actions.Lookup(permit.FimScanActionID)
	if !ok {
		t.Fatal("fim.scan is not in the catalog")
	}
	const id = "5c3d1e2f-0a1b-4c2d-8e3f-a1b2c3d4e5f6"
	s.storeLeaseJob(ctx, testGrantID, a, canonical.Target{HostID: "web", HostKeyFingerprint: leaseWebKey}, "nebula-default", []byte(fimCanonFull), id)
	if _, err := s.db.Exec(`UPDATE executions SET state = 'finished' WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}

	if err := s.collectLeaseJobs(ctx); err != nil {
		t.Fatal(err)
	}
	var hostState, execState string
	var finished sql.NullInt64
	if err := s.db.QueryRow(`SELECT h.state, e.state, e.finished_at FROM execution_hosts h
		JOIN executions e ON e.id = h.execution_id WHERE e.id = ?`, id).Scan(&hostState, &execState, &finished); err != nil {
		t.Fatal(err)
	}
	if hostState != "finished" || execState != "finished" || !finished.Valid || finished.Int64 != now.Unix() {
		t.Fatalf("legacy row after collection: host %q execution %q finished %v; want both finished at %d",
			hostState, execState, finished, now.Unix())
	}
}

// unknownRunFake answers GetRun for every run as NotFound: the executor has no
// record of the run.
type unknownRunFake struct {
	*leaseRunFake
}

func (f *unknownRunFake) GetRun(_ context.Context, _ *pb.GetRunRequest, _ ...grpc.CallOption) (*pb.GetRunResponse, error) {
	return nil, status.Error(codes.NotFound, "no such run")
}

// TestFimScanJobTheExecutorNoLongerKnowsIsFinalWhenCollected checks the
// NotFound branch of collectLeaseJobs: the host ends as unknown and the
// execution's state and finish time are set together.
func TestFimScanJobTheExecutorNoLongerKnowsIsFinalWhenCollected(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s, f := setupLeases(t, &now, func(n time.Time) *pb.ReadGrant {
		return leaseEntry(t, fimLeaseDoc(t, n, []string{"web"}, "full"), n)
	})
	s.exec = &unknownRunFake{leaseRunFake: f}
	ctx := context.Background()

	a, ok := actions.Lookup(permit.FimScanActionID)
	if !ok {
		t.Fatal("fim.scan is not in the catalog")
	}
	const id = "7e8f9a0b-1c2d-4e3f-9a4b-5c6d7e8f9a0b"
	s.storeLeaseJob(ctx, testGrantID, a, canonical.Target{HostID: "web", HostKeyFingerprint: leaseWebKey}, "nebula-default", []byte(fimCanonFull), id)

	if err := s.collectLeaseJobs(ctx); err != nil {
		t.Fatal(err)
	}
	var hostState, class, execState string
	var finished sql.NullInt64
	if err := s.db.QueryRow(`SELECT h.state, h.class, e.state, e.finished_at FROM execution_hosts h
		JOIN executions e ON e.id = h.execution_id WHERE e.id = ?`, id).Scan(&hostState, &class, &execState, &finished); err != nil {
		t.Fatal(err)
	}
	if hostState != "finished" || class != "unknown" || execState != "finished" || !finished.Valid || finished.Int64 != now.Unix() {
		t.Fatalf("after NotFound: host %q class %q execution %q finished %v; want finished, unknown, finished at %d",
			hostState, class, execState, finished, now.Unix())
	}
}
