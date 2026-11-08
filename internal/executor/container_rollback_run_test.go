// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Rollback members end to end over RunBatchMember (ADR 0006 P2-04,
// container update plan cu03): proposed and approved through the batch
// authority, claimed, checked against the executor's own recreation row
// (checkRollbackSource: only a retained recreation inside its window, with
// a baseline and the bound recovery plan), dispatched as a durable job and
// judged against the recorded update's baseline.

// rollbackScript is the stand-in job for docker.compose_rollback: trusted
// for that action at the rollback version as MEDIUM and pinned as its
// artifact.
func (e *containerEnv) rollbackScript(t *testing.T, tag string, code int) []byte {
	t.Helper()
	// A distinct artifact from any update stand-in with the same tag.
	s := append(e.stubScript(tag, code), []byte("# rollback\n")...)
	e.trustFor(t, s, composeRollbackAction, composeRollbackVersion)
	e.svc.batchRun.composePins = append(e.svc.batchRun.composePins, containerArtifact{ActionID: composeRollbackAction,
		ModuleVersion: composeRollbackVersion, SHA256: sha256Hex(s)})
	return s
}

// rollbackSource stores the update row of rollbackFixture as completed at
// completedAt (the window runs from there), with or without its baseline,
// and its recovery plan; it returns the row and the rollback binding that
// equals it, bound to the stored plan.
func (e *containerEnv) rollbackSource(t *testing.T, completedAt time.Time, withBaseline bool) (executordb.ContainerRecreation, canonical.BatchContainerUpdate) {
	t.Helper()
	row, plan, rb := rollbackFixture(t, e.clock.Now())
	if err := e.db.CreateContainerRecreation(row); err != nil {
		t.Fatal(err)
	}
	baseline := row.Baseline
	if !withBaseline {
		baseline = nil
	}
	if err := e.db.CompleteContainerRecreation(row.ExecutionID, executordb.RecreationCompletion{State: row.State, Images: row.Images,
		Containers: row.Containers, Baseline: baseline, Verdict: row.Verdict}, completedAt, DefaultRollbackWindow); err != nil {
		t.Fatal(err)
	}
	stored, err := e.db.SetContainerRecoveryPlan(plan.HostID, plan.Unit, plan.Kind, plan.Reference, plan.Actor)
	if err != nil {
		t.Fatal(err)
	}
	rb.RecoveryPlanDigest = stored.Digest()
	return row, rb
}

// A rollback inside the window of a retained recreation runs end to end
// over RunBatchMember: as a durable job with the fixed mutation timeout and
// exactly the parameters rendered from the rollback binding (the bound
// earlier definition, nothing else), judged against the update's baseline,
// a succeeded member, and the update row is rolled back afterwards, so a
// second rollback of it is refused before anything runs.
func TestRollbackInsideWindowRunsOverRunBatchMember(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	row, rb := e.rollbackSource(t, e.clock.Now(), true)
	art := e.rollbackScript(t, "rb", 0)
	e.writeResult(t, passingRollbackResult(rb, updateBaselineOf(t, row)))
	d, members := e.proposeContainerAction(t, "web-1", composeRollbackAction, composeRollbackVersion, rb, art)
	resp, err := e.server.RunBatchMember(context.Background(), e.req(d, 0, "web-1", art))
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS || resp.GetClass() != hostrun.ClassSuccess {
		t.Fatalf("response %+v", resp)
	}
	want, _, err := canonical.ContainerUpdateParameters(rb)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(e.dir, "params-rb.json"))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("the job got %q (%v), want the rollback binding's rendering %q", got, err, want)
	}
	execID := members[0].Request.ExecutionID
	run, err := e.db.GetRun(execID, "web-1")
	if err != nil || run.State != executordb.RunFinished || run.ActionID != composeRollbackAction || run.Timeout != containerMutationTimeout {
		t.Fatalf("run %+v %v", run, err)
	}
	if e.attached.count() != 0 {
		t.Fatal("a rollback member ran attached")
	}
	rrow, err := e.db.GetContainerRecreation(execID)
	if err != nil || rrow.Kind != canonical.ContainerUpdateKindRollback || rrow.RollbackOf != row.ExecutionID ||
		rrow.State != executordb.RecreationRecreated || !rrow.Verdict.Passed {
		t.Fatalf("rollback row %+v %v", rrow, err)
	}
	src, err := e.db.GetContainerRecreation(row.ExecutionID)
	if err != nil || src.State != executordb.RecreationRolledBack {
		t.Fatalf("update row after the rollback %+v %v", src.State, err)
	}
	if held := e.svc.HeldBatchTargets(); len(held) != 0 {
		t.Fatalf("target still held: %+v", held)
	}

	// The same rollback again: the update row is no source any more.
	if err := os.Remove(filepath.Join(e.dir, "params-rb.json")); err != nil {
		t.Fatal(err)
	}
	d2, members2 := e.proposeContainerAction(t, "web-1", composeRollbackAction, composeRollbackVersion, rb, art)
	resp, err = e.server.RunBatchMember(context.Background(), e.req(d2, 0, "web-1", art))
	if err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_NOT_EXECUTED || resp.GetClass() != classBatchNotExecuted ||
		!strings.Contains(resp.GetDetail(), errRollbackState.Error()) {
		t.Fatalf("second rollback: %+v %v", resp, err)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "params-rb.json")); err == nil {
		t.Fatal("the second rollback's job ran")
	}
	if _, err := e.db.GetContainerRecreation(members2[0].Request.ExecutionID); !errors.Is(err, executordb.ErrNoRecreation) {
		t.Fatalf("a refused rollback left a row: %v", err)
	}
}

// A rollback whose job fails its postcheck is a failed member and leaves
// the update row a rollback source (the way forward is a new update).
func TestFailedRollbackLeavesUpdateRow(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	row, rb := e.rollbackSource(t, e.clock.Now(), true)
	art := e.rollbackScript(t, "rbfail", 0)
	r := passingRollbackResult(rb, updateBaselineOf(t, row))
	r.After[afterOf(t, r, "web", "1")].ImageID = pulledImageID
	e.writeResult(t, r)
	d, members := e.proposeContainerAction(t, "web-1", composeRollbackAction, composeRollbackVersion, rb, art)
	resp, err := e.server.RunBatchMember(context.Background(), e.req(d, 0, "web-1", art))
	if err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_FAILURE || resp.GetClass() != hostrun.ClassPostcheckFailed ||
		!strings.Contains(resp.GetDetail(), "does not run the prior image") {
		t.Fatalf("response %+v %v", resp, err)
	}
	if rrow, err := e.db.GetContainerRecreation(members[0].Request.ExecutionID); err != nil || rrow.State != executordb.RecreationPartial {
		t.Fatalf("rollback row %+v %v", rrow, err)
	}
	if src, err := e.db.GetContainerRecreation(row.ExecutionID); err != nil || src.State != row.State {
		t.Fatalf("update row after a failed rollback %+v %v", src.State, err)
	}
}

// A rollback is refused before anything runs on the host when its source
// is outside the rollback window or has no baseline: the member fails as
// not executed with the reason, no job is dispatched, no rollback row is
// written, and the update row stays as it was.
func TestRollbackRefusedOutsideWindowOrWithoutBaseline(t *testing.T) {
	cases := []struct {
		name        string
		completedAt func(now time.Time) time.Time
		baseline    bool
		want        error
	}{
		{"after the window", func(now time.Time) time.Time { return now.Add(-DefaultRollbackWindow - time.Minute) }, true, errRollbackWindow},
		{"window just over", func(now time.Time) time.Time { return now.Add(-DefaultRollbackWindow) }, true, errRollbackWindow},
		{"missing baseline", func(now time.Time) time.Time { return now }, false, errRollbackNoBaseline},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newContainerEnv(t, "web-1")
			row, rb := e.rollbackSource(t, tc.completedAt(e.clock.Now()), tc.baseline)
			art := e.rollbackScript(t, "refused", 0)
			e.writeResult(t, passingRollbackResult(rb, updateBaselineOf(t, row)))
			d, members := e.proposeContainerAction(t, "web-1", composeRollbackAction, composeRollbackVersion, rb, art)
			resp, err := e.server.RunBatchMember(context.Background(), e.req(d, 0, "web-1", art))
			if err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_NOT_EXECUTED || resp.GetClass() != classBatchNotExecuted ||
				!strings.Contains(resp.GetDetail(), tc.want.Error()) {
				t.Fatalf("response %+v %v", resp, err)
			}
			if _, err := os.Stat(filepath.Join(e.dir, "params-refused.json")); err == nil {
				t.Fatal("the refused rollback's job ran")
			}
			if _, err := e.db.GetContainerRecreation(members[0].Request.ExecutionID); !errors.Is(err, executordb.ErrNoRecreation) {
				t.Fatalf("a refused rollback left a row: %v", err)
			}
			if src, err := e.db.GetContainerRecreation(row.ExecutionID); err != nil || src.State != row.State {
				t.Fatalf("update row %+v %v", src.State, err)
			}
			if held := e.svc.HeldBatchTargets(); len(held) != 0 {
				t.Fatalf("target held after a refusal: %+v", held)
			}
		})
	}
}

// The shipped docker.compose_rollback 1.0.0 artifact, with nothing but the
// shipped pins, runs end to end over RunBatchMember for a rollback inside
// the window: claimed, dispatched as a durable job with the rendered
// binding, executed on the host and reconciled. The test host is no
// prepared Docker host, so the script stops in its precheck with its typed
// result and changes nothing; the row is not_recreated and the update row
// stays a rollback source. The same artifact as docker.compose_update, or
// under another version, is refused before the claim.
func TestShippedComposeRollbackArtifactRunsOverRunBatchMember(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	a, ok := actions.Lookup(composeRollbackAction)
	if !ok {
		t.Fatal("docker.compose_rollback missing")
	}
	art := a.Script
	for _, v := range []string{composeRollbackVersion, "1.0.1"} {
		e.trustFor(t, art, composeRollbackAction, v)
	}
	e.trust(t, art, composeUpdateVersion)
	row, rb := e.rollbackSource(t, e.clock.Now(), true)

	d, members := e.proposeContainerAction(t, "web-1", composeRollbackAction, "1.0.1", rb, art)
	if _, err := e.server.RunBatchMember(context.Background(), e.req(d, 0, "web-1", art)); err == nil ||
		!strings.Contains(err.Error(), errContainerArtifact.Error()) {
		t.Fatalf("rollback artifact at 1.0.1: %v", err)
	}
	if _, err := e.db.GetRun(members[0].Request.ExecutionID, "web-1"); err == nil {
		t.Fatal("a refused member left a run")
	}
	d, _ = e.proposeContainerVersion(t, "web-1", composeUpdateVersion, testComposeUpdate(), art)
	if _, err := e.server.RunBatchMember(context.Background(), e.req(d, 0, "web-1", art)); err == nil ||
		!strings.Contains(err.Error(), errContainerArtifact.Error()) {
		t.Fatalf("rollback artifact as an update: %v", err)
	}

	d, members = e.proposeContainerAction(t, "web-1", composeRollbackAction, composeRollbackVersion, rb, art)
	resp, err := e.server.RunBatchMember(context.Background(), e.req(d, 0, "web-1", art))
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(resp.GetResult(), &result); err != nil {
		t.Fatalf("result %q: %v (%+v)", resp.GetResult(), err, resp)
	}
	if resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_FAILURE || resp.GetClass() != hostrun.ClassPrecheckFailed ||
		result["format"] != composeRollbackFormat || result["phase"] != "precheck" || result["reason"] == "" || result["reason"] == "binding_invalid" {
		t.Fatalf("response %+v result %v", resp, result)
	}
	t.Logf("the shipped rollback artifact stopped in its precheck: %v", result["reason"])
	run, err := e.db.GetRun(members[0].Request.ExecutionID, "web-1")
	if err != nil || run.State != executordb.RunFinished || run.ActionID != composeRollbackAction || run.Timeout != containerMutationTimeout {
		t.Fatalf("run %+v %v", run, err)
	}
	if rrow, err := e.db.GetContainerRecreation(members[0].Request.ExecutionID); err != nil || rrow.State != executordb.RecreationNotRecreated {
		t.Fatalf("rollback row %+v %v", rrow, err)
	}
	if src, err := e.db.GetContainerRecreation(row.ExecutionID); err != nil || src.State != row.State {
		t.Fatalf("update row %+v %v", src.State, err)
	}
	if held := e.svc.HeldBatchTargets(); len(held) != 0 {
		t.Fatalf("target still held: %+v", held)
	}
}
