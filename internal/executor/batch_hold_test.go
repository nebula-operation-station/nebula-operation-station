// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// restart replaces the batch execution state as an executor restart does
// (EnableBatchExecution restores the persisted holds) and wires the fakes
// again.
func (e *dispatchEnv) restart(t *testing.T) {
	t.Helper()
	if err := e.svc.EnableBatchExecution(); err != nil {
		t.Fatal(err)
	}
	e.svc.batchRun.attached = e.attached.run
	e.svc.batchRun.visible = e.visible.run
	e.svc.batchRun.holdWait, e.svc.batchRun.holdPoll = 300*time.Millisecond, 20*time.Millisecond
}

func (e *dispatchEnv) heldPath() string { return filepath.Join(e.svc.dataDir, batchHeldFile) }

// holdTarget runs a one-member batch on host whose run times out while the
// target keeps showing it, so the target stays held. It returns the held
// execution ID.
func (e *dispatchEnv) holdTarget(t *testing.T, host string) string {
	t.Helper()
	d, members, n := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: host})
	e.visible.set(true)
	e.attached.mu.Lock()
	e.attached.mayRun = true
	e.attached.mu.Unlock()
	resp, err := e.server.RunBatchMember(context.Background(), e.runReq(d, n, 0, host))
	e.attached.mu.Lock()
	e.attached.mayRun = false
	e.attached.mu.Unlock()
	if err != nil || !strings.Contains(resp.GetDetail(), "held") {
		t.Fatalf("hold %s: %+v %v", host, resp, err)
	}
	return members[0].Request.ExecutionID
}

// runOne proposes and runs a one-member batch on host.
func (e *dispatchEnv) runOne(t *testing.T, host string) (*pb.RunBatchMemberResponse, canonical.BatchMember, error) {
	t.Helper()
	d, members, n := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: host})
	resp, err := e.server.RunBatchMember(context.Background(), e.runReq(d, n, 0, host))
	return resp, members[0], err
}

// A held target survives an executor restart: the hold is persisted with
// only host ID, fingerprint, endpoints, execution ID and time (no script,
// parameters or secrets), restored at startup, and rechecked before any
// member starts there; once the target shows the run gone it is freed and
// the file forgets it.
func TestHeldTargetSurvivesRestart(t *testing.T) {
	e := newDispatchEnv(t, "web-1", "web-2")
	ctx := context.Background()
	e.failureThreshold = 1
	exec := e.holdTarget(t, "web-1")

	raw, err := os.ReadFile(e.heldPath())
	if err != nil {
		t.Fatal(err)
	}
	hk, _, _ := e.db.HostKey("web-1")
	for _, want := range []string{`"host_id":"web-1"`, exec, hk.Fingerprint, e.ssh["web-1"].addr} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Fatalf("held file lacks %q: %s", want, raw)
		}
	}
	for _, never := range []string{"echo plan", `step`, "BEGIN", "PRIVATE"} {
		if bytes.Contains(raw, []byte(never)) {
			t.Fatalf("held file contains %q: %s", never, raw)
		}
	}
	if fi, err := os.Stat(e.heldPath()); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("held file mode %v %v", fi.Mode(), err)
	}

	e.restart(t)
	if got := e.svc.HeldBatchTargets(); len(got) != 1 || got[0].HostID != "web-1" || got[0].ExecutionID != exec || got[0].Expired {
		t.Fatalf("restored holds %+v", got)
	}
	if len(e.logs.find("batch_target_held_restored", exec)) != 1 {
		t.Error("restored hold not audited")
	}
	before := e.visible.count()
	d, members, n := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: "web-1"})
	_, err = e.server.RunBatchMember(ctx, e.runReq(d, n, 0, "web-1"))
	e.requireRefused(t, err, codes.FailedPrecondition, members[0], 1)
	if !strings.Contains(status.Convert(err).Message(), "batch_host_busy") || e.visible.count() == before {
		t.Fatalf("restored hold: %v, %d checks", err, e.visible.count()-before)
	}
	// Another target is not held up.
	if resp, _, err := e.runOne(t, "web-2"); err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS {
		t.Fatalf("other target: %+v %v", resp, err)
	}
	e.visible.set(false)
	if resp, err := e.server.RunBatchMember(ctx, e.runReq(d, n, 0, "web-1")); err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS {
		t.Fatalf("after the run is gone: %+v %v", resp, err)
	}
	recs, err := readHeld(e.heldPath())
	if err != nil || len(recs) != 0 {
		t.Fatalf("held file after release: %+v %v", recs, err)
	}
}

// heldJSON is a valid held-target file with one record changed by mut.
func heldJSON(t *testing.T, addr string, mut func(*heldRecord)) []byte {
	t.Helper()
	r := heldRecord{HostID: "web-1", Fingerprint: "SHA256:x", ExecutionID: "00000000-0000-4000-8000-000000000001",
		Endpoints: []string{addr}, HeldAtUnix: 1_800_000_000}
	if mut != nil {
		mut(&r)
	}
	raw, err := json.Marshal(heldDocument{Version: batchHeldVersion, Targets: []heldRecord{r}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// A held-target store that cannot be used (no data directory, a file that
// is not exactly a valid held-target document) refuses every batch member
// on every host before anything is claimed: a lost hold must never let a
// member start.
func TestHeldStoreBrokenRefusesAllMembers(t *testing.T) {
	addr := "127.0.0.1:22"
	cases := map[string][]byte{
		"not JSON":       []byte("{"),
		"unknown field":  []byte(`{"version":1,"targets":[],"x":1}`),
		"wrong version":  []byte(`{"version":2,"targets":[]}`),
		"trailing data":  []byte(`{"version":1,"targets":[]} {}`),
		"not UTF-8":      []byte("{\"version\":1,\"targets\":[]}\xff"),
		"oversize":       append([]byte(`{"version":1,"targets":[]}`), bytes.Repeat([]byte(" "), maxBatchHeldFileBytes)...),
		"bad execution":  heldJSON(t, addr, func(r *heldRecord) { r.ExecutionID = "../../x" }),
		"host newline":   heldJSON(t, addr, func(r *heldRecord) { r.HostID = "web-1\nkind=forged" }),
		"no host":        heldJSON(t, addr, func(r *heldRecord) { r.HostID = "" }),
		"bad endpoint":   heldJSON(t, addr, func(r *heldRecord) { r.Endpoints = []string{"127.0.0.1:99999"} }),
		"no endpoints":   heldJSON(t, addr, func(r *heldRecord) { r.Endpoints = nil }),
		"no hold time":   heldJSON(t, addr, func(r *heldRecord) { r.HeldAtUnix = 0 }),
		"no data dir":    nil,
		"duplicate host": nil,
	}
	{
		var doc heldDocument
		if err := json.Unmarshal(heldJSON(t, addr, nil), &doc); err != nil {
			t.Fatal(err)
		}
		doc.Targets = append(doc.Targets, doc.Targets[0])
		cases["duplicate host"], _ = json.Marshal(doc)
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			e := newDispatchEnv(t, "web-1", "web-2")
			if name == "no data dir" {
				e.svc.SetBackupDirs("", "")
			} else if err := os.WriteFile(e.heldPath(), content, 0o600); err != nil {
				t.Fatal(err)
			}
			e.restart(t)
			for _, host := range []string{"web-1", "web-2"} {
				_, m, err := e.runOne(t, host)
				e.requireRefused(t, err, codes.FailedPrecondition, m, 0)
				if !strings.Contains(status.Convert(err).Message(), "batch_hold_store_unavailable") {
					t.Fatalf("refusal = %v", err)
				}
			}
			if len(e.logs.find("batch_hold_store_error", "")) == 0 {
				t.Error("broken store not audited")
			}
		})
	}
}

// A hold whose write after the member returned fails is kept in memory
// and keeps every batch member from starting, on every host, until a
// write succeeds; the file already holds the target from its reservation.
func TestHeldStoreWriteFailureBlocksMembers(t *testing.T) {
	e := newDispatchEnv(t, "web-1", "web-2")
	e.failureThreshold = 1
	// allow is how many writes still succeed (-1: all).
	var allow atomic.Int32
	allow.Store(-1)
	write := e.svc.batchRun.writeHeld
	e.svc.batchRun.writeHeld = func(p string, b []byte) error {
		if allow.Load() == 0 {
			return errors.New("no space left on device")
		}
		allow.Add(-1)
		return write(p, b)
	}
	// The reservation is written; the hold after the run is not.
	allow.Store(1)
	exec := e.holdTarget(t, "web-1")
	if recs, err := readHeld(e.heldPath()); err != nil || len(recs) != 1 || recs[0].ExecutionID != exec {
		t.Fatalf("held file while the store fails %+v %v", recs, err)
	}
	d, members, n := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: "web-2"})
	_, err := e.server.RunBatchMember(context.Background(), e.runReq(d, n, 0, "web-2"))
	e.requireRefused(t, err, codes.FailedPrecondition, members[0], 1)
	allow.Store(-1)
	if resp, err := e.server.RunBatchMember(context.Background(), e.runReq(d, n, 0, "web-2")); err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS {
		t.Fatalf("after the store recovered: %+v %v", resp, err)
	}
	recs, err := readHeld(e.heldPath())
	if err != nil || len(recs) != 1 || recs[0].ExecutionID != exec {
		t.Fatalf("held file %+v %v", recs, err)
	}
}

// A hold lasts at most batchHoldMax with automatic rechecks. Past it the
// hold expires into a terminal state (persisted, audited) that no recheck
// ends, even when the target would show the run gone; only the audited
// operator release frees it, and only when the target shows the run gone
// at that moment. A refused release leaves the target held.
func TestHeldTargetExpiresAndNeedsOperatorRelease(t *testing.T) {
	e := newDispatchEnv(t, "web-1")
	ctx := context.Background()
	e.failureThreshold = 1
	exec := e.holdTarget(t, "web-1")

	e.clock.Add(batchHoldMax + time.Minute)
	e.visible.set(false)
	before := e.visible.count()
	d, members, n := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: "web-1"})
	_, err := e.server.RunBatchMember(ctx, e.runReq(d, n, 0, "web-1"))
	e.requireRefused(t, err, codes.FailedPrecondition, members[0], 1)
	if e.visible.count() != before {
		t.Fatal("an expired hold was rechecked automatically")
	}
	if len(e.logs.find("batch_target_hold_expired", exec)) != 1 {
		t.Error("expiry not audited")
	}
	if got := e.svc.HeldBatchTargets(); len(got) != 1 || !got[0].Expired {
		t.Fatalf("holds %+v", got)
	}
	// The terminal state survives a restart.
	e.restart(t)
	if got := e.svc.HeldBatchTargets(); len(got) != 1 || !got[0].Expired || got[0].ExecutionID != exec {
		t.Fatalf("holds after restart %+v", got)
	}
	_, err = e.server.RunBatchMember(ctx, e.runReq(d, n, 0, "web-1"))
	e.requireRefused(t, err, codes.FailedPrecondition, members[0], 1)

	stillHeld := func(t *testing.T) {
		t.Helper()
		if got := e.svc.HeldBatchTargets(); len(got) != 1 {
			t.Fatalf("target freed: %+v", got)
		}
	}
	for _, tc := range []struct {
		name            string
		host, exec, by  string
		reason          string
		running         bool
		visErr, writErr error
		want            error
	}{
		{name: "no operator", host: "web-1", exec: exec, reason: "checked", want: ErrBatchHoldReason},
		{name: "reason with a newline", host: "web-1", exec: exec, by: "alice", reason: "ok\nkind=forged", want: ErrBatchHoldReason},
		{name: "other execution", host: "web-1", exec: "00000000-0000-4000-8000-000000000999", by: "alice", reason: "checked", want: ErrBatchTargetNotHeld},
		{name: "other host", host: "web-9", exec: exec, by: "alice", reason: "checked", want: ErrBatchTargetNotHeld},
		{name: "still running", host: "web-1", exec: exec, by: "alice", reason: "checked", running: true, want: ErrBatchTargetStillRunning},
		{name: "visibility unknown", host: "web-1", exec: exec, by: "alice", reason: "checked",
			visErr: fmt.Errorf("%w: exit status 3", hostrun.ErrVisibilityUnknown), want: ErrBatchTargetStillRunning},
		{name: "store fails", host: "web-1", exec: exec, by: "alice", reason: "checked", writErr: errors.New("read-only file system"), want: ErrBatchHoldStore},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e.visible.set(tc.running)
			e.visible.setErr(tc.visErr)
			write := e.svc.batchRun.writeHeld
			if tc.writErr != nil {
				e.svc.batchRun.writeHeld = func(string, []byte) error { return tc.writErr }
				defer func() { e.svc.batchRun.writeHeld = write }()
			}
			if err := e.svc.ReleaseHeldBatchTarget(ctx, tc.host, tc.exec, tc.by, tc.reason); !errors.Is(err, tc.want) {
				t.Fatalf("release = %v, want %v", err, tc.want)
			}
			stillHeld(t)
		})
	}
	if len(e.logs.find("batch_target_released_by_operator", exec)) != 0 {
		t.Fatal("a refused release was audited as a release")
	}
	recs, err := readHeld(e.heldPath())
	if err != nil || len(recs) != 1 || !recs[0].Expired {
		t.Fatalf("held file after refused releases %+v %v", recs, err)
	}

	e.visible.set(false)
	e.visible.setErr(nil)
	if err := e.svc.ReleaseHeldBatchTarget(ctx, "web-1", exec, "alice", "checked the host by hand"); err != nil {
		t.Fatalf("release: %v", err)
	}
	rel := e.logs.find("batch_target_released_by_operator", exec)
	if len(rel) != 1 || rel[0].attrs["by"] != "alice" || rel[0].attrs["reason"] != "checked the host by hand" {
		t.Fatalf("release audit %+v", rel)
	}
	if recs, err := readHeld(e.heldPath()); err != nil || len(recs) != 0 || len(e.svc.HeldBatchTargets()) != 0 {
		t.Fatalf("after release: %+v %v", recs, err)
	}
	if resp, err := e.server.RunBatchMember(ctx, e.runReq(d, n, 0, "web-1")); err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS {
		t.Fatalf("after the release: %+v %v", resp, err)
	}
	// A target that is not held cannot be released.
	if err := e.svc.ReleaseHeldBatchTarget(ctx, "web-1", exec, "alice", "again"); !errors.Is(err, ErrBatchTargetNotHeld) {
		t.Fatalf("second release = %v", err)
	}
}

// Before the maximum hold the target is still freed automatically once it
// shows the run gone (the expiry does not shorten a normal hold).
func TestHeldTargetBeforeMaximumIsRechecked(t *testing.T) {
	e := newDispatchEnv(t, "web-1")
	e.failureThreshold = 1
	e.holdTarget(t, "web-1")
	e.clock.Add(batchHoldMax - time.Minute)
	e.visible.set(false)
	if resp, _, err := e.runOne(t, "web-1"); err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS {
		t.Fatalf("before the maximum hold: %+v %v", resp, err)
	}
}

// The reservation is persisted before the member starts: an executor
// crash or kill during the attached run restarts with the target held (no
// longer running), so the next member there runs only after the target
// shows the run gone. While the member runs, neither a recheck nor the
// operator release frees the target.
func TestReservationSurvivesCrashDuringRun(t *testing.T) {
	e := newDispatchEnv(t, "web-1")
	ctx := context.Background()
	e.failureThreshold = 1
	e.attached.started = make(chan string, 1)
	e.attached.block = make(chan struct{})
	d, members, n := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: "web-1"})
	exec := members[0].Request.ExecutionID
	done := make(chan error, 1)
	go func() {
		_, err := e.server.RunBatchMember(ctx, e.runReq(d, n, 0, "web-1"))
		done <- err
	}()
	if got := <-e.attached.started; got != exec {
		t.Fatalf("started %s", got)
	}
	recs, err := readHeld(e.heldPath())
	if err != nil || len(recs) != 1 || recs[0].HostID != "web-1" || recs[0].ExecutionID != exec || recs[0].Expired {
		t.Fatalf("held file during the run: %+v %v", recs, err)
	}
	if got := e.svc.HeldBatchTargets(); len(got) != 1 || !got[0].Running {
		t.Fatalf("holds during the run: %+v", got)
	}
	e.visible.set(false)
	if err := e.svc.ReleaseHeldBatchTarget(ctx, "web-1", exec, "alice", "looks done"); !errors.Is(err, ErrBatchHoldBusy) {
		t.Fatalf("release during the run: %v", err)
	}
	if e.svc.recheckHeld(ctx, e.svc.batchRun, "web-1") {
		t.Fatal("a recheck freed a running target")
	}

	// The process dies here: the old state never writes again.
	old := e.svc.batchRun
	old.mu.Lock()
	old.writeHeld = func(string, []byte) error { return nil }
	old.mu.Unlock()
	e.restart(t)
	close(e.attached.block)
	<-done

	if got := e.svc.HeldBatchTargets(); len(got) != 1 || got[0].HostID != "web-1" || got[0].ExecutionID != exec || got[0].Running || got[0].Expired {
		t.Fatalf("holds after the restart: %+v", got)
	}
	e.attached.mu.Lock()
	e.attached.started, e.attached.block = nil, nil
	e.attached.mu.Unlock()
	e.visible.set(true)
	before := e.visible.count()
	d2, members2, n2 := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: "web-1"})
	_, err = e.server.RunBatchMember(ctx, e.runReq(d2, n2, 0, "web-1"))
	e.requireRefused(t, err, codes.FailedPrecondition, members2[0], 1)
	if !strings.Contains(status.Convert(err).Message(), "batch_host_busy") || e.visible.count() == before {
		t.Fatalf("after the restart: %v, %d checks", err, e.visible.count()-before)
	}
	e.visible.set(false)
	if resp, err := e.server.RunBatchMember(ctx, e.runReq(d2, n2, 0, "web-1")); err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS {
		t.Fatalf("after the run is gone: %+v %v", resp, err)
	}
	if recs, err := readHeld(e.heldPath()); err != nil || len(recs) != 0 || len(e.svc.HeldBatchTargets()) != 0 {
		t.Fatalf("held file after the member: %+v %v", recs, err)
	}
}

// A reservation that cannot be persisted does not start the member (fail
// closed): nothing is claimed or run and the target stays free.
func TestReservationWriteFailureDoesNotStart(t *testing.T) {
	e := newDispatchEnv(t, "web-1")
	var fail atomic.Bool
	write := e.svc.batchRun.writeHeld
	e.svc.batchRun.writeHeld = func(p string, b []byte) error {
		if fail.Load() {
			return errors.New("no space left on device")
		}
		return write(p, b)
	}
	fail.Store(true)
	d, members, n := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: "web-1"})
	_, err := e.server.RunBatchMember(context.Background(), e.runReq(d, n, 0, "web-1"))
	e.requireRefused(t, err, codes.FailedPrecondition, members[0], 0)
	if !strings.Contains(status.Convert(err).Message(), "batch_hold_store_unavailable") || len(e.svc.HeldBatchTargets()) != 0 {
		t.Fatalf("refusal %v, holds %+v", err, e.svc.HeldBatchTargets())
	}
	fail.Store(false)
	if resp, err := e.server.RunBatchMember(context.Background(), e.runReq(d, n, 0, "web-1")); err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS {
		t.Fatalf("after the store recovered: %+v %v", resp, err)
	}
	if recs, err := readHeld(e.heldPath()); err != nil || len(recs) != 0 {
		t.Fatalf("held file after the member: %+v %v", recs, err)
	}
}
