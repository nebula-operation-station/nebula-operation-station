// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/dispatch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
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

// oversizeBaselineResult is a well-formed result within the result limit
// whose baseline is over the row's baseline limit: extra baseline entries
// with the most and longest mounts the parser allows.
func oversizeBaselineResult(t *testing.T, u canonical.BatchContainerUpdate) composeUpdateResult {
	t.Helper()
	r := passingComposeResult(u)
	mounts := make([]snapshotMount, maxSnapshotMounts)
	for i := range mounts {
		p := "/" + strings.Repeat(string(rune('a'+i%26)), maxSnapshotPath-1)
		mounts[i] = snapshotMount{Type: "bind", Source: p, Destination: p, Mode: "rw", RW: true}
	}
	for i := 0; i < 4; i++ {
		x := r.Baseline[0]
		x.ID, x.Name, x.Replica, x.Mounts = fmt.Sprintf("%064x", 1000+i), "site-pad-"+strconv.Itoa(i+1), strconv.Itoa(i+1), mounts
		x.Service = "pad"
		r.Baseline = append(r.Baseline, x)
	}
	return r
}

// oversizeContainersResult is a well-formed result within the result limit
// whose per-container record is over the row's containers limit: the most
// snapshot entries with the longest names and references.
func oversizeContainersResult(t *testing.T, u canonical.BatchContainerUpdate) composeUpdateResult {
	t.Helper()
	r := passingComposeResult(u)
	r.Baseline, r.After = nil, nil
	ref := "nginx:" + strings.Repeat("a", maxSnapshotReference-len("nginx:"))
	for i := 1; i <= maxSnapshotEntries; i++ {
		replica := strconv.Itoa(i)
		name := "site-web-" + replica + "-"
		name += strings.Repeat("x", 130-len(name))
		b := snapshotEntry{ID: fmt.Sprintf("%064x", i), Name: name, Service: "web", Replica: replica, State: "running",
			StartedAt: "2026-11-08T01:00:00Z", Health: "none", ImageID: digestOf("d"), RunningReference: ref, ConfigurationDigest: hexOf("2")}
		a := b
		a.ID, a.ImageID = newIncarnation(b.ID), pulledImageID
		r.Baseline, r.After = append(r.Baseline, b), append(r.After, a)
	}
	return r
}

// A host-controlled result within the result limit whose baseline or
// container record is over its column limit still completes the row, once:
// as uncertain, without the record that does not fit, so the row leaves
// intent and is not judged again on every reconcile pass.
func TestOversizeRecordCompletesBounded(t *testing.T) {
	u := testComposeUpdate()
	cases := []struct {
		name    string
		result  composeUpdateResult
		finding string
		over    func(composeUpdateResult) bool
	}{
		{"baseline over its limit", oversizeBaselineResult(t, u), "baseline is over its", func(r composeUpdateResult) bool {
			b, _ := json.Marshal(r.Baseline)
			return len(b) > executordb.MaxRecreationBaselineBytes
		}},
		{"containers over their limit", oversizeContainersResult(t, u), "container record is over its", func(r composeUpdateResult) bool {
			b, _ := json.Marshal(recreationContainers(r.Baseline, r.After))
			return len(b) > executordb.MaxRecreationContainersBytes
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := mustResultJSON(t, tc.result)
			if len(raw) > maxJudgedResultBytes || !tc.over(tc.result) {
				t.Fatalf("fixture: %d result bytes, over the column limit %v", len(raw), tc.over(tc.result))
			}
			if _, err := parseComposeUpdateResult(raw); err != nil {
				t.Fatalf("fixture not well-formed: %v", err)
			}
			e := newContainerEnv(t, "web-1")
			run := testDispatchRun(t, u)
			row, err := recreationIntent(run, "web-1", "SHA256:k")
			if err != nil {
				t.Fatal(err)
			}
			c := recreationCompletion(row, hostrun.ClassSuccess, raw)
			if c.State != executordb.RecreationUncertain || c.Verdict.Passed ||
				!strings.Contains(strings.Join(c.Verdict.Findings, "|"), tc.finding) {
				t.Fatalf("completion %s passed=%v findings %v", c.State, c.Verdict.Passed, c.Verdict.Findings)
			}
			if err := e.db.CreateContainerRecreation(row); err != nil {
				t.Fatal(err)
			}
			r := executordb.Run{ExecutionID: run.ExecutionID, HostID: "web-1", Digest: hexOf("f"), Endpoints: []string{"127.0.0.1:22"},
				Timeout: containerMutationTimeout, MemberID: "member-0", ActionID: composeUpdateAction}
			if err := e.db.CreateRun(r); err != nil {
				t.Fatal(err)
			}
			r.State, r.Class, r.Result = executordb.RunFinished, hostrun.ClassSuccess, raw
			if err := e.db.FinishRun(r); err != nil {
				t.Fatal(err)
			}
			e.svc.ReconcileOnce(context.Background())
			got, err := e.db.GetContainerRecreation(run.ExecutionID)
			if err != nil || got.State != executordb.RecreationUncertain || got.Verdict.Passed {
				t.Fatalf("row %+v %v", got.State, err)
			}
			if containerMemberOutcome(hostrun.ClassSuccess, got) == permit.OutcomeSucceeded {
				t.Fatal("an unrecorded update succeeded")
			}
			if left, err := e.db.ContainerRecreationsInIntent(); err != nil || len(left) != 0 {
				t.Fatalf("still in intent: %d %v", len(left), err)
			}
			e.svc.ReconcileOnce(context.Background())
			again, _ := e.db.GetContainerRecreation(run.ExecutionID)
			if !again.UpdatedAt.Equal(got.UpdatedAt) || again.State != got.State {
				t.Fatalf("row changed on a second pass: %+v", again.State)
			}
		})
	}
}

// A run that stopped in phases 1 to 4 changed nothing: a baseline or
// container record over its column limit is left out, but the row stays
// not_recreated instead of becoming uncertain.
func TestStoppedRunWithOversizeRecordStaysNotRecreated(t *testing.T) {
	u := testComposeUpdate()
	run := testDispatchRun(t, u)
	row, err := recreationIntent(run, "web-1", "SHA256:k")
	if err != nil {
		t.Fatal(err)
	}
	fixtures := []struct {
		name    string
		result  composeUpdateResult
		finding string
	}{
		{"baseline over its limit", oversizeBaselineResult(t, u), "baseline is over its"},
		{"containers over their limit", oversizeContainersResult(t, u), "container record is over its"},
	}
	for _, fx := range fixtures {
		for _, phase := range []string{phasePrecheck, phaseResolve, phasePull, phaseRetain} {
			t.Run(fx.name+"/"+phase, func(t *testing.T) {
				r := fx.result
				r.Phase, r.Reason, r.After, r.UpExit = phase, "pull_failed", nil, nil
				raw := mustResultJSON(t, r)
				if _, err := parseComposeUpdateResult(raw); err != nil {
					t.Fatalf("fixture not well-formed: %v", err)
				}
				c := recreationCompletion(row, hostrun.ClassPrecheckFailed, raw)
				all := strings.Join(c.Verdict.Findings, "|")
				if c.State != executordb.RecreationNotRecreated || c.Verdict.Passed ||
					!strings.Contains(all, fx.finding) || !strings.Contains(all, "nothing was recreated") {
					t.Fatalf("completion %s passed=%v findings %v", c.State, c.Verdict.Passed, c.Verdict.Findings)
				}
				if b, _ := json.Marshal(c.Containers); len(c.Baseline) > executordb.MaxRecreationBaselineBytes ||
					len(b) > executordb.MaxRecreationContainersBytes {
					t.Fatalf("completion over its column limits: baseline %d, containers %d", len(c.Baseline), len(b))
				}
			})
		}
	}
}

// A completion over a column limit prepends its own findings to a full
// verdict; the bound keeps the "more findings omitted" marker and the
// trailing class finding.
func TestBoundCompletionKeepsTrailingFindings(t *testing.T) {
	judged := make([]string, 0, maxVerdictFindings+2)
	for i := 0; i < maxVerdictFindings; i++ {
		judged = append(judged, fmt.Sprintf("finding %02d", i))
	}
	judged = append(judged, "more findings omitted", "the run's class is script_failed, not success")
	c := executordb.RecreationCompletion{State: executordb.RecreationPartial,
		Baseline:   make([]byte, executordb.MaxRecreationBaselineBytes+1),
		Containers: oversizeContainersCompletion(t),
		Verdict:    executordb.RecreationVerdict{Judged: true, Findings: slices.Clone(judged)}}
	got := boundCompletion(c)
	f := got.Verdict.Findings
	if got.State != executordb.RecreationUncertain || len(f) != len(judged)+2 {
		t.Fatalf("state %s, %d findings %v", got.State, len(f), f)
	}
	if !strings.Contains(f[0], "baseline is over its") || !strings.Contains(f[1], "container record is over its") ||
		!slices.Equal(f[2:], judged) {
		t.Fatalf("findings %v", f)
	}
	// A list longer than any judge produces is still bounded, keeping its
	// last two findings.
	long := slices.Clone(judged[:maxVerdictFindings])
	long = append(long, "extra 1", "extra 2", "extra 3")
	long = append(long, judged[maxVerdictFindings:]...)
	c.Verdict.Findings = long
	f = boundCompletion(c).Verdict.Findings
	if len(f) != maxVerdictFindings+4 || !slices.Equal(f[len(f)-2:], judged[maxVerdictFindings:]) {
		t.Fatalf("%d findings, tail %v", len(f), f[len(f)-2:])
	}
}

// oversizeContainersCompletion is a container record over the row's
// containers limit.
func oversizeContainersCompletion(t *testing.T) []executordb.RecreationContainer {
	t.Helper()
	r := oversizeContainersResult(t, testComposeUpdate())
	return recreationContainers(r.Baseline, r.After)
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

// The pinned update artifact never prunes, removes or untags an image or
// container, never logs in to a registry, and pulls only with an empty
// DOCKER_CONFIG, so no host credential serves a pull (R7, R9). The
// executor's own container code names no such command either.
func TestNoPruneInContainerActions(t *testing.T) {
	a, ok := actions.Lookup(composeUpdateAction)
	if !ok || sha256Hex(a.Script) != composeUpdateArtifactSHA256 {
		t.Fatal("the pinned docker.compose_update artifact is not in the catalog")
	}
	s := string(a.Script)
	for _, banned := range []string{`"prune"`, `"rmi"`, `"down"`, `"rm"`, `"untag"`, `"login"`, "docker login", "--rm", "rm -v", "compose pull"} {
		if strings.Contains(s, banned) {
			t.Errorf("the pinned update artifact contains %q", banned)
		}
	}
	if !strings.Contains(s, `env["DOCKER_CONFIG"] = empty`) || !strings.Contains(s, `"docker", "pull", "-q", "--", ref`) {
		t.Error("the pinned artifact does not pull by digest with an empty DOCKER_CONFIG")
	}
	for _, f := range []string{"container_member.go", "container_judge.go", "container_recreation.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, banned := range []string{`"prune"`, `"rmi"`, `"rm"`, `"login"`, "docker login", "image prune", "system prune"} {
			if strings.Contains(string(b), banned) {
				t.Errorf("%s names %q", f, banned)
			}
		}
	}
}

// argvBannedWords are docker subcommands and verbs no container action may
// name in any argument vector or command string: removing, untagging or
// pruning an image or container, taking a project down, logging in.
var argvBannedWords = map[string]bool{"prune": true, "rmi": true, "rm": true, "remove": true, "untag": true,
	"login": true, "logout": true, "down": true, "kill": true}

// argvViolations reads words, the words of every string literal of a
// source in order, as one argument stream and returns each banned word,
// and each docker or compose "pull" that is not the one allowed form,
// docker pull -q -- <ref> (a pull by digest; compose pull would use the
// project's credentials). "pull" as a bare phase name is no command.
func argvViolations(words []string) []string {
	const window = 6
	var out []string
	for i, w := range words {
		if argvBannedWords[w] {
			out = append(out, w)
		}
		if w != "pull" {
			continue
		}
		allowed := i > 0 && words[i-1] == "docker" && i+2 < len(words) && words[i+1] == "-q" && words[i+2] == "--"
		command := i > 0 && (words[i-1] == "docker" || words[i-1] == "image")
		for j := max(0, i-window); j < i; j++ {
			command = command || words[j] == "compose"
		}
		if command && !allowed {
			out = append(out, words[max(0, i-1)]+" pull")
		}
	}
	return out
}

func literalWords(lits []string) []string {
	var words []string
	for _, l := range lits {
		words = append(words, strings.Fields(l)...)
	}
	return words
}

// scriptLiterals returns the string literals of the shipped script (shell
// with embedded Python), in order, skipping comment lines.
func scriptLiterals(s string) []string {
	re := regexp.MustCompile(`"((?:[^"\\\n]|\\.)*)"|'((?:[^'\\\n]|\\.)*)'`)
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		for _, m := range re.FindAllStringSubmatch(line, -1) {
			out = append(out, m[1]+m[2])
		}
	}
	return out
}

// goLiterals returns the string literals of a Go file, in source order.
func goLiterals(t *testing.T, path string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		if l, ok := n.(*ast.BasicLit); ok && l.Kind == token.STRING {
			s, err := strconv.Unquote(l.Value)
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			out = append(out, s)
		}
		return true
	})
	return out
}

// TestNoPruneInContainerArgv checks the argument vectors, not substrings:
// "image", "remove" or "compose", "pull" as separate elements is caught as
// well as a command string.
func TestNoPruneInContainerArgv(t *testing.T) {
	// The detector itself catches every argv form the substring list missed.
	for name, src := range map[string]string{
		"image remove":     `call(["docker", "image", "remove", iid], budget)`,
		"container remove": `call(["docker", "container", "remove", "-f", cid], budget)`,
		"compose pull":     `call(["docker", "compose", "-p", p, "pull"], budget)`,
		"image prune":      `call(["docker", "image", "prune", "-af"], budget)`,
		"login string":     `call(["sh", "-c", "docker login ghcr.io"], budget)`,
		"compose down":     `call(["docker", "compose", "down"], budget)`,
	} {
		if v := argvViolations(literalWords(scriptLiterals(src))); len(v) == 0 {
			t.Errorf("%s: not caught", name)
		}
	}
	if v := argvViolations(literalWords(scriptLiterals(`call(["docker", "pull", "-q", "--", ref], budget)`))); len(v) != 0 {
		t.Errorf("the allowed pull by digest is flagged: %v", v)
	}

	a, ok := actions.Lookup(composeUpdateAction)
	if !ok || sha256Hex(a.Script) != composeUpdateArtifactSHA256 {
		t.Fatal("the pinned docker.compose_update artifact is not in the catalog")
	}
	if v := argvViolations(literalWords(scriptLiterals(string(a.Script)))); len(v) != 0 {
		t.Errorf("the pinned update artifact names %v", v)
	}
	for _, f := range []string{"container_member.go", "container_judge.go", "container_recreation.go"} {
		if v := argvViolations(literalWords(goLiterals(t, f))); len(v) != 0 {
			t.Errorf("%s names %v", f, v)
		}
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
