// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/dispatch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

const testUpdateExec = "00000000-0000-4000-8000-000000000001"

func testDispatchRun(t *testing.T, u canonical.BatchContainerUpdate) dispatch.Run {
	t.Helper()
	m, params := testContainerMember(t, u)
	m.Request.ExecutionID = testUpdateExec
	return dispatch.Run{ParentDigest: hexOf("f"), MemberID: m.MemberID, ExecutionID: testUpdateExec, ActionID: composeUpdateAction,
		Member: m, Parameters: params}
}

// A member whose job ends with class success but without a passing
// verdict (here: a result no judge reads) is a failed member, and the
// rollout stops before the next member.
func TestMemberWithoutVerdictIsFailed(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	art, next := e.script(t, "noverdict", 0), e.script(t, "next", 0)
	d, members := e.proposeContainer(t, "web-1", testComposeUpdate(), art, next)
	resp, err := e.server.RunBatchMember(context.Background(), e.req(d, 0, "web-1", art))
	if err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_FAILURE || resp.GetClass() != hostrun.ClassPostcheckFailed {
		t.Fatalf("response %+v %v", resp, err)
	}
	run, err := e.db.GetRun(members[0].Request.ExecutionID, "web-1")
	if err != nil || run.Class != hostrun.ClassSuccess {
		t.Fatalf("the run record keeps the host's class: %+v %v", run, err)
	}
	row, err := e.db.GetContainerRecreation(members[0].Request.ExecutionID)
	if err != nil || row.State != executordb.RecreationUncertain || row.Verdict.Passed {
		t.Fatalf("row %+v %v", row, err)
	}
	if _, err := e.server.RunBatchMember(context.Background(), e.req(d, 1, "web-1", next)); err == nil {
		t.Fatal("the next member ran after a member without a verdict")
	}
	if _, err := os.Stat(filepath.Join(e.dir, "params-next.json")); err == nil {
		t.Fatal("the next member's job ran")
	}
}

// A failed postcheck (a lost published port) fails the member and stops
// the rollout; nothing is retried or rolled back automatically: the only
// runs are the failed member's.
func TestFailedPostcheckStopsRollout(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	art, next := e.script(t, "lostport", 0), e.script(t, "next", 0)
	u := testComposeUpdate()
	r := passingComposeResult(u)
	r.After[0].Ports = []string{}
	e.writeResult(t, r)
	d, members := e.proposeContainer(t, "web-1", u, art, next)
	resp, err := e.server.RunBatchMember(context.Background(), e.req(d, 0, "web-1", art))
	if err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_FAILURE ||
		!strings.Contains(resp.GetDetail(), "published ports changed") {
		t.Fatalf("response %+v %v", resp, err)
	}
	row, err := e.db.GetContainerRecreation(members[0].Request.ExecutionID)
	if err != nil || row.State != executordb.RecreationPartial || row.Verdict.Passed || len(row.Baseline) == 0 {
		t.Fatalf("row %+v %v", row, err)
	}
	if _, err := e.server.RunBatchMember(context.Background(), e.req(d, 1, "web-1", next)); err == nil {
		t.Fatal("the next member ran after a failed postcheck")
	}
	rows, err := e.db.ListContainerRecreations("")
	if err != nil || len(rows) != 1 {
		t.Fatalf("a retry or rollback was started: %d rows %v", len(rows), err)
	}
}

// The row is written before the job is dispatched: a job that cannot get
// its row is not dispatched at all.
func TestIntentWrittenBeforeDispatch(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	art := e.script(t, "intent", 0)
	e.writeResult(t, passingComposeResult(testComposeUpdate()))
	d, members := e.proposeContainer(t, "web-1", testComposeUpdate(), art)
	// Occupy the execution's row so the intent write fails.
	run := testDispatchRun(t, testComposeUpdate())
	run.ExecutionID = members[0].Request.ExecutionID
	occupied, err := recreationIntent(run, "web-1", "SHA256:x")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.db.CreateContainerRecreation(occupied); err != nil {
		t.Fatal(err)
	}
	resp, err := e.server.RunBatchMember(context.Background(), e.req(d, 0, "web-1", art))
	if err == nil && resp.GetOutcome() == pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS {
		t.Fatalf("member ran without its own intent row: %+v", resp)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "params-intent.json")); err == nil {
		t.Fatal("the job was dispatched without its intent row")
	}
}

// A run that finished while its row stayed in intent (a crash between
// finishing the run and judging it) is judged on the next reconcile pass.
func TestFinishedRunJudgedAfterCrashInIntent(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	u := testComposeUpdate()
	run := testDispatchRun(t, u)
	row, err := recreationIntent(run, "web-1", "SHA256:k")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.db.CreateContainerRecreation(row); err != nil {
		t.Fatal(err)
	}
	r := executordb.Run{ExecutionID: run.ExecutionID, HostID: "web-1", Digest: hexOf("f"), Endpoints: []string{"127.0.0.1:22"},
		Timeout: containerMutationTimeout, MemberID: "member-0", ActionID: composeUpdateAction}
	if err := e.db.CreateRun(r); err != nil {
		t.Fatal(err)
	}
	r.State, r.Class, r.Result = executordb.RunFinished, hostrun.ClassSuccess, mustResultJSON(t, passingComposeResult(u))
	if err := e.db.FinishRun(r); err != nil {
		t.Fatal(err)
	}
	e.svc.ReconcileOnce(context.Background())
	got, err := e.db.GetContainerRecreation(run.ExecutionID)
	if err != nil || got.State != executordb.RecreationRecreated || !got.Verdict.Passed ||
		!got.WindowExpiresAt.Equal(e.clock.Now().Add(DefaultRollbackWindow).Truncate(time.Second).UTC()) {
		t.Fatalf("row %+v %v", got, err)
	}
	// Judged once: a later pass leaves the row alone.
	e.svc.ReconcileOnce(context.Background())
	again, _ := e.db.GetContainerRecreation(run.ExecutionID)
	if !again.UpdatedAt.Equal(got.UpdatedAt) || !again.WindowExpiresAt.Equal(got.WindowExpiresAt) {
		t.Fatalf("row changed on a second pass: %+v", again)
	}
}

// rollbackFixture is an update row in state recreated with a baseline, its
// recovery plan and the rollback binding that equals it.
func rollbackFixture(t *testing.T, now time.Time) (executordb.ContainerRecreation, executordb.RecoveryPlan, canonical.BatchContainerUpdate) {
	t.Helper()
	u := testComposeUpdate()
	row, err := recreationIntent(testDispatchRun(t, u), "web-1", "SHA256:k")
	if err != nil {
		t.Fatal(err)
	}
	c := recreationCompletion(row, hostrun.ClassSuccess, mustResultJSON(t, passingComposeResult(u)))
	row.State, row.Images, row.Containers, row.Baseline, row.Verdict = c.State, c.Images, c.Containers, c.Baseline, c.Verdict
	row.WindowExpiresAt = now.Add(DefaultRollbackWindow)
	plan := executordb.RecoveryPlan{HostID: "web-1", Unit: "site", Kind: executordb.RecoveryNoData, Actor: "alice", Version: 1, RecordedAt: now}
	rb := canonical.BatchContainerUpdate{Kind: canonical.ContainerUpdateKindRollback, Form: u.Form, Project: u.Project,
		SourceDigest: u.SourceDigest, WorkingDirHash: u.WorkingDirHash, ConfigFilesHash: u.ConfigFilesHash,
		Dependencies: u.Dependencies, RollbackOf: row.ExecutionID, RecoveryPlanDigest: plan.Digest()}
	for _, img := range row.Images {
		rb.Images = append(rb.Images, canonical.ContainerUpdateImage{Service: img.Service, Repository: img.Repository, OldTag: img.NewTag,
			NewTag: img.OldTag, Rollback: &canonical.ContainerRollbackImage{PriorImageID: img.PriorImageID, RetainedTag: img.RetainedTag,
				RetainedReference: img.RetainedReference}})
	}
	for _, x := range row.Containers {
		if x.Service == "web" {
			rb.Targets = append(rb.Targets, canonical.ContainerUpdateTarget{Service: x.Service, ContainerID: x.IDAfter, ContainerName: x.Name,
				ImageID: x.ImageAfter, RunningReference: x.ReferenceAfter, ConfigurationDigest: x.ConfigAfter})
		}
	}
	return row, plan, rb
}

func TestRollbackSourceChecks(t *testing.T) {
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		mut  func(*executordb.ContainerRecreation, **executordb.RecoveryPlan, *canonical.BatchContainerUpdate)
		want error
	}{
		{"equal binding, open window", func(*executordb.ContainerRecreation, **executordb.RecoveryPlan, *canonical.BatchContainerUpdate) {}, nil},
		{"partial row with a baseline", func(r *executordb.ContainerRecreation, _ **executordb.RecoveryPlan, _ *canonical.BatchContainerUpdate) {
			r.State = executordb.RecreationPartial
		}, nil},
		{"uncertain recreation blocks rollback", func(r *executordb.ContainerRecreation, _ **executordb.RecoveryPlan, _ *canonical.BatchContainerUpdate) {
			r.State = executordb.RecreationUncertain
		}, errRollbackState},
		{"not recreated", func(r *executordb.ContainerRecreation, _ **executordb.RecoveryPlan, _ *canonical.BatchContainerUpdate) {
			r.State = executordb.RecreationNotRecreated
		}, errRollbackState},
		{"already rolled back", func(r *executordb.ContainerRecreation, _ **executordb.RecoveryPlan, _ *canonical.BatchContainerUpdate) {
			r.State = executordb.RecreationRolledBack
		}, errRollbackState},
		{"rollback of rollback", func(r *executordb.ContainerRecreation, _ **executordb.RecoveryPlan, _ *canonical.BatchContainerUpdate) {
			r.Kind = canonical.ContainerUpdateKindRollback
		}, errRollbackOfRollback},
		{"without baseline", func(r *executordb.ContainerRecreation, _ **executordb.RecoveryPlan, _ *canonical.BatchContainerUpdate) {
			r.Baseline = nil
		}, errRollbackNoBaseline},
		{"after window", func(r *executordb.ContainerRecreation, _ **executordb.RecoveryPlan, _ *canonical.BatchContainerUpdate) {
			r.WindowExpiresAt = now
		}, errRollbackWindow},
		{"window never set", func(r *executordb.ContainerRecreation, _ **executordb.RecoveryPlan, _ *canonical.BatchContainerUpdate) {
			r.WindowExpiresAt = time.Time{}
		}, errRollbackWindow},
		{"without recovery plan", func(_ *executordb.ContainerRecreation, p **executordb.RecoveryPlan, _ *canonical.BatchContainerUpdate) {
			*p = nil
		}, errRollbackRecoveryPlan},
		{"recovery plan changed", func(_ *executordb.ContainerRecreation, p **executordb.RecoveryPlan, _ *canonical.BatchContainerUpdate) {
			changed := **p
			changed.Version, changed.Kind, changed.Reference = 2, executordb.RecoveryPlanReference, "restic"
			*p = &changed
		}, errRollbackRecoveryPlan},
		{"other row", func(_ *executordb.ContainerRecreation, _ **executordb.RecoveryPlan, u *canonical.BatchContainerUpdate) {
			u.RollbackOf = "00000000-0000-4000-8000-000000000009"
		}, errRollbackNoRow},
		{"source changed", func(_ *executordb.ContainerRecreation, _ **executordb.RecoveryPlan, u *canonical.BatchContainerUpdate) {
			u.SourceDigest = hexOf("0")
		}, errRollbackBindingDiffers},
		{"dependencies differ", func(_ *executordb.ContainerRecreation, _ **executordb.RecoveryPlan, u *canonical.BatchContainerUpdate) {
			u.Dependencies = []canonical.ContainerUpdateDependency{}
		}, errRollbackBindingDiffers},
		{"configuration changed", func(_ *executordb.ContainerRecreation, _ **executordb.RecoveryPlan, u *canonical.BatchContainerUpdate) {
			u.Targets[0].ConfigurationDigest = hexOf("0")
		}, errRollbackBindingDiffers},
		{"old incarnation bound", func(_ *executordb.ContainerRecreation, _ **executordb.RecoveryPlan, u *canonical.BatchContainerUpdate) {
			u.Targets[0].ContainerID = hexOf("1")
		}, errRollbackBindingDiffers},
		{"retained tag differs", func(_ *executordb.ContainerRecreation, _ **executordb.RecoveryPlan, u *canonical.BatchContainerUpdate) {
			u.Images[0].Rollback.RetainedTag = "nos-retained:00000000-0000-4000-8000-000000000009-0"
		}, errRollbackBindingDiffers},
		{"tags not reversed", func(_ *executordb.ContainerRecreation, _ **executordb.RecoveryPlan, u *canonical.BatchContainerUpdate) {
			u.Images[0].NewTag = "1.28"
		}, errRollbackBindingDiffers},
		{"entry without target while a container is present", func(_ *executordb.ContainerRecreation, _ **executordb.RecoveryPlan, u *canonical.BatchContainerUpdate) {
			u.Targets = nil
		}, errRollbackBindingDiffers},
		{"all-missing service bound without target", func(r *executordb.ContainerRecreation, _ **executordb.RecoveryPlan, u *canonical.BatchContainerUpdate) {
			r.State = executordb.RecreationPartial
			for i := range r.Containers {
				if r.Containers[i].Service == "web" {
					r.Containers[i].Status, r.Containers[i].IDAfter = executordb.ContainerMissing, ""
				}
			}
			u.Targets = nil
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			row, plan, rb := rollbackFixture(t, now)
			p := &plan
			tc.mut(&row, &p, &rb)
			err := checkRollbackSource(rb, row, p, "web-1", now)
			if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	// Another host's row is no source.
	row, plan, rb := rollbackFixture(t, now)
	if err := checkRollbackSource(rb, row, &plan, "db-1", now); !errors.Is(err, errRollbackNoRow) {
		t.Fatalf("other host: %v", err)
	}
}

// A rollback member is still never executed (no rollback script is
// pinned), but the executor refuses it first for its row: a rollback
// without a recorded update, or of an uncertain one, names the reason.
func TestRollbackMemberCheckedAgainstOwnRow(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	now := e.clock.Now()
	row, plan, rb := rollbackFixture(t, now)
	m := canonical.BatchMember{MemberID: "member-0", ContainerUpdate: &rb, Request: canonical.Request{ActionID: "docker.compose_rollback"}}
	if err := e.svc.checkRollbackMember(m, "web-1"); !errors.Is(err, errRollbackNoRow) {
		t.Fatalf("no row: %v", err)
	}
	if err := e.db.CreateContainerRecreation(row); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.checkRollbackMember(m, "web-1"); !errors.Is(err, errRollbackState) {
		t.Fatalf("intent row: %v", err)
	}
	if err := e.db.CompleteContainerRecreation(row.ExecutionID, executordb.RecreationCompletion{State: row.State, Images: row.Images,
		Containers: row.Containers, Baseline: row.Baseline, Verdict: row.Verdict}, now, DefaultRollbackWindow); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.checkRollbackMember(m, "web-1"); !errors.Is(err, errRollbackRecoveryPlan) {
		t.Fatalf("no plan: %v", err)
	}
	stored, err := e.db.SetContainerRecoveryPlan(plan.HostID, plan.Unit, plan.Kind, plan.Reference, plan.Actor)
	if err != nil {
		t.Fatal(err)
	}
	rb.RecoveryPlanDigest = stored.Digest()
	if err := e.svc.checkRollbackMember(m, "web-1"); err != nil {
		t.Fatalf("equal rollback refused by the row check: %v", err)
	}
	// It still does not run: no rollback artifact is pinned.
	if err := checkContainerMember(m, nil, shippedComposeUpdatePin()); !errors.Is(err, errContainerUnsupported) {
		t.Fatalf("rollback member: %v", err)
	}
}

// ContainerRecreations never returns the definition or the baseline.
func TestContainerRecreationsListIsSanitized(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	row, _, _ := rollbackFixture(t, e.clock.Now())
	if err := e.db.CreateContainerRecreation(row); err != nil {
		t.Fatal(err)
	}
	if err := e.db.CompleteContainerRecreation(row.ExecutionID, executordb.RecreationCompletion{State: row.State, Baseline: row.Baseline,
		Containers: row.Containers}, e.clock.Now(), DefaultRollbackWindow); err != nil {
		t.Fatal(err)
	}
	rows, err := e.svc.ContainerRecreations("web-1")
	if err != nil || len(rows) != 1 || rows[0].Definition != nil || rows[0].Baseline != nil || len(rows[0].Images) != 1 {
		t.Fatalf("%+v %v", rows, err)
	}
}
