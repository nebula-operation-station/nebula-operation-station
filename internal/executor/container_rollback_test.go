// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/dispatch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
)

// Rollback members (ADR 0006 P2-04, container update plan cu03): the
// rollback judge, the result parser and the completion of a rollback row.
// The member end to end over RunBatchMember is in
// container_rollback_run_test.go.

// updateBaselineOf is the baseline an update row holds.
func updateBaselineOf(t *testing.T, row executordb.ContainerRecreation) []snapshotEntry {
	t.Helper()
	var out []snapshotEntry
	if err := json.Unmarshal(row.Baseline, &out); err != nil || len(out) == 0 {
		t.Fatalf("update baseline %q: %v", row.Baseline, err)
	}
	return out
}

// passingRollbackResult is a compose-rollback-v1 result of a clean rollback
// of rb to updateBaseline: the rollback's own baseline lists the bound
// targets as recorded and the dependency containers; every replica of the
// update's baseline is recreated on the prior image under the retained
// reference, with that baseline's health, ports, mounts and networks; the
// dependencies are untouched.
func passingRollbackResult(rb canonical.BatchContainerUpdate, updateBaseline []snapshotEntry) composeUpdateResult {
	zero := 0
	r := composeUpdateResult{Format: composeRollbackFormat, Phase: phaseAfterSnapshot, Project: rb.Project, UpExit: &zero,
		Baseline: []snapshotEntry{}, After: []snapshotEntry{}}
	images := map[string]canonical.ContainerUpdateImage{}
	for _, img := range rb.Images {
		images[img.Service] = img
	}
	deps := map[string]bool{}
	for _, d := range rb.Dependencies {
		for _, c := range d.Containers {
			deps[c.ContainerID] = true
		}
	}
	byName := map[string]snapshotEntry{}
	for _, e := range updateBaseline {
		byName[e.Name] = e
	}
	for _, t := range rb.Targets {
		b := byName[t.ContainerName]
		b.ID, b.ImageID, b.RunningReference, b.ConfigurationDigest = t.ContainerID, t.ImageID, t.RunningReference, t.ConfigurationDigest
		b.StartedAt = "2026-11-08T02:00:00Z"
		r.Baseline = append(r.Baseline, b)
	}
	for _, e := range updateBaseline {
		if deps[e.ID] {
			r.Baseline, r.After = append(r.Baseline, e), append(r.After, e)
			continue
		}
		img, ok := images[e.Service]
		if !ok {
			continue
		}
		a := e
		a.ID, a.StartedAt = newIncarnation("rollback:"+e.ID), "2026-11-08T03:00:00Z"
		a.ImageID, a.RunningReference, a.ConfigurationDigest = img.Rollback.PriorImageID, img.Rollback.RetainedReference, hexOf("b")
		a.Ports, a.Mounts, a.Networks = append([]string(nil), e.Ports...), append([]snapshotMount(nil), e.Mounts...), append([]string(nil), e.Networks...)
		r.After = append(r.After, a)
	}
	return r
}

// afterOf is the index of service's replica in r.After.
func afterOf(t *testing.T, r composeUpdateResult, service, replica string) int {
	t.Helper()
	for i, e := range r.After {
		if e.Service == service && e.Replica == replica {
			return i
		}
	}
	t.Fatalf("no %s replica %s in the after-snapshot", service, replica)
	return -1
}

// The rollback judge passes a clean rollback and fails every deviation
// from the update's baseline, the bound prior image and reference, the
// rollback's own baseline and the dependency rules, one finding per case.
func TestJudgeComposeRollbackPostchecks(t *testing.T) {
	row, _, rb := rollbackFixture(t, time.Now())
	ub := updateBaselineOf(t, row)
	if v := judgeComposeRollback(rb, ub, passingRollbackResult(rb, ub)); !v.Passed || len(v.Findings) != 0 {
		t.Fatalf("clean rollback: %+v", v)
	}
	cases := []struct {
		name string
		mut  func(t *testing.T, rb *canonical.BatchContainerUpdate, ub *[]snapshotEntry, r *composeUpdateResult)
		want string
	}{
		{"a lost published port", func(t *testing.T, _ *canonical.BatchContainerUpdate, _ *[]snapshotEntry, r *composeUpdateResult) {
			r.After[afterOf(t, *r, "web", "1")].Ports = []string{}
		}, "published ports changed"},
		{"a changed host port", func(t *testing.T, _ *canonical.BatchContainerUpdate, _ *[]snapshotEntry, r *composeUpdateResult) {
			r.After[afterOf(t, *r, "web", "1")].Ports = []string{"80/tcp->0.0.0.0:9090"}
		}, "published ports changed"},
		{"a lost mount", func(t *testing.T, _ *canonical.BatchContainerUpdate, _ *[]snapshotEntry, r *composeUpdateResult) {
			r.After[afterOf(t, *r, "web", "1")].Mounts = nil
		}, "mounts changed"},
		{"a changed network", func(t *testing.T, _ *canonical.BatchContainerUpdate, _ *[]snapshotEntry, r *composeUpdateResult) {
			r.After[afterOf(t, *r, "web", "1")].Networks = []string{"other"}
		}, "networks changed"},
		{"not the prior image", func(t *testing.T, _ *canonical.BatchContainerUpdate, _ *[]snapshotEntry, r *composeUpdateResult) {
			r.After[afterOf(t, *r, "web", "1")].ImageID = pulledImageID
		}, "does not run the prior image"},
		{"not the retained reference", func(t *testing.T, rb *canonical.BatchContainerUpdate, _ *[]snapshotEntry, r *composeUpdateResult) {
			r.After[afterOf(t, *r, "web", "1")].RunningReference = "nginx:1.27"
		}, "does not run the retained reference"},
		{"the update's reference still runs", func(t *testing.T, rb *canonical.BatchContainerUpdate, _ *[]snapshotEntry, r *composeUpdateResult) {
			r.After[afterOf(t, *r, "web", "1")].RunningReference = rb.Targets[0].RunningReference
		}, "does not run the retained reference"},
		{"not running", func(t *testing.T, _ *canonical.BatchContainerUpdate, _ *[]snapshotEntry, r *composeUpdateResult) {
			r.After[afterOf(t, *r, "web", "1")].State = "exited"
		}, "not running"},
		{"starting past the wait", func(t *testing.T, _ *canonical.BatchContainerUpdate, _ *[]snapshotEntry, r *composeUpdateResult) {
			r.After[afterOf(t, *r, "web", "1")].Health = "starting"
		}, "health healthy before, starting after"},
		{"a replica fewer than the update's baseline", func(t *testing.T, _ *canonical.BatchContainerUpdate, _ *[]snapshotEntry, r *composeUpdateResult) {
			i := afterOf(t, *r, "web", "1")
			r.After = append(r.After[:i], r.After[i+1:]...)
		}, "missing after the rollback"},
		{"a replica the update's baseline did not have", func(t *testing.T, _ *canonical.BatchContainerUpdate, _ *[]snapshotEntry, r *composeUpdateResult) {
			extra := r.After[afterOf(t, *r, "web", "1")]
			extra.ID, extra.Name, extra.Replica = hexOf("e"), "site-web-2", "2"
			r.After = append(r.After, extra)
		}, "was not there before the update"},
		{"a dependency recreated", func(t *testing.T, _ *canonical.BatchContainerUpdate, _ *[]snapshotEntry, r *composeUpdateResult) {
			i := afterOf(t, *r, "db", "1")
			r.After[i].ID = hexOf("e")
		}, "was recreated or removed"},
		{"a dependency restarted without restart_on_update", func(t *testing.T, _ *canonical.BatchContainerUpdate, _ *[]snapshotEntry, r *composeUpdateResult) {
			r.After[afterOf(t, *r, "db", "1")].StartedAt = "2026-11-08T09:00:00Z"
		}, "restarted without restart_on_update"},
		{"a dependency stopped", func(t *testing.T, _ *canonical.BatchContainerUpdate, _ *[]snapshotEntry, r *composeUpdateResult) {
			r.After[afterOf(t, *r, "db", "1")].State = "exited"
		}, "was running and is exited now"},
		{"pulled images reported", func(_ *testing.T, _ *canonical.BatchContainerUpdate, _ *[]snapshotEntry, r *composeUpdateResult) {
			r.Pulled = []resultImage{{Service: "web", ImageID: pulledImageID}}
		}, "reported pulled or retained images"},
		{"retained images reported", func(_ *testing.T, _ *canonical.BatchContainerUpdate, _ *[]snapshotEntry, r *composeUpdateResult) {
			r.Retained = []resultRetained{{Service: "web", Tag: retainedTag(testUpdateExec, 0)}}
		}, "reported pulled or retained images"},
		{"own baseline drifted from the bound incarnation", func(_ *testing.T, _ *canonical.BatchContainerUpdate, _ *[]snapshotEntry, r *composeUpdateResult) {
			r.Baseline[0].ConfigurationDigest = hexOf("0")
		}, "drifted from the approved binding: configuration"},
		{"a bound target missing from the own baseline", func(_ *testing.T, _ *canonical.BatchContainerUpdate, _ *[]snapshotEntry, r *composeUpdateResult) {
			r.Baseline = r.Baseline[1:]
		}, "a bound target is missing from the baseline"},
		{"no update baseline", func(_ *testing.T, _ *canonical.BatchContainerUpdate, ub *[]snapshotEntry, _ *composeUpdateResult) {
			*ub = nil
		}, "the recorded update has no baseline"},
		{"oversize entry in the update baseline", func(_ *testing.T, _ *canonical.BatchContainerUpdate, ub *[]snapshotEntry, _ *composeUpdateResult) {
			*ub = append(*ub, snapshotEntry{ID: hexOf("e"), Oversize: true})
		}, "update's baseline is too large to judge"},
		{"truncated after-snapshot", func(_ *testing.T, _ *canonical.BatchContainerUpdate, _ *[]snapshotEntry, r *composeUpdateResult) {
			r.AfterTruncated = true
		}, "truncated"},
		{"no after-snapshot", func(_ *testing.T, _ *canonical.BatchContainerUpdate, _ *[]snapshotEntry, r *composeUpdateResult) {
			r.After = nil
		}, "no after-snapshot"},
		{"stopped in retain", func(_ *testing.T, _ *canonical.BatchContainerUpdate, _ *[]snapshotEntry, r *composeUpdateResult) {
			r.Phase, r.Reason = phaseRetain, "retained_image_missing"
		}, "ended in phase retain"},
		{"up failed", func(_ *testing.T, _ *canonical.BatchContainerUpdate, _ *[]snapshotEntry, r *composeUpdateResult) {
			one := 1
			r.UpExit, r.Reason = &one, "up_failed"
		}, "did not succeed"},
		{"another project", func(_ *testing.T, _ *canonical.BatchContainerUpdate, _ *[]snapshotEntry, r *composeUpdateResult) {
			r.Project = "other"
		}, "not the bound project"},
		{"an update binding", func(_ *testing.T, rb *canonical.BatchContainerUpdate, _ *[]snapshotEntry, _ *composeUpdateResult) {
			rb.Kind = canonical.ContainerUpdateKindUpdate
		}, "no rollback postcheck exists"},
		{"no prior image bound", func(_ *testing.T, rb *canonical.BatchContainerUpdate, _ *[]snapshotEntry, _ *composeUpdateResult) {
			rb.Images[0].Rollback = nil
		}, "names no prior image"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			row, _, rb := rollbackFixture(t, time.Now())
			ub := updateBaselineOf(t, row)
			r := passingRollbackResult(rb, ub)
			tc.mut(t, &rb, &ub, &r)
			v := judgeComposeRollback(rb, ub, r)
			if v.Passed || !strings.Contains(strings.Join(v.Findings, "\n"), tc.want) {
				t.Fatalf("verdict %+v, want a finding %q", v, tc.want)
			}
		})
	}
	// The update judge never passes a rollback binding.
	if v := judgeComposeUpdate(rb, expectedRetained(rb, testUpdateExec), passingRollbackResult(rb, ub)); v.Passed {
		t.Fatal("the update judge passed a rollback")
	}
}

// A rollback result is read only as compose-rollback-v1: no update result,
// no resolve or pull phase, no pulled or retained list; and an update
// result is never read as a rollback's.
func TestRollbackResultParser(t *testing.T) {
	row, _, rb := rollbackFixture(t, time.Now())
	good := mustResultJSON(t, passingRollbackResult(rb, updateBaselineOf(t, row)))
	if _, err := parseContainerResult(good, composeRollbackFormat); err != nil {
		t.Fatalf("good rollback result: %v", err)
	}
	if _, err := parseComposeUpdateResult(good); !errors.Is(err, errComposeResult) {
		t.Fatalf("a rollback result read as an update's: %v", err)
	}
	if _, err := parseContainerResult(mustResultJSON(t, passingComposeResult(testComposeUpdate())), composeRollbackFormat); !errors.Is(err, errComposeResult) {
		t.Fatalf("an update result read as a rollback's: %v", err)
	}
	for name, edit := range map[string]func(*composeUpdateResult){
		"pulled list":   func(r *composeUpdateResult) { r.Pulled = []resultImage{} },
		"retained list": func(r *composeUpdateResult) { r.Retained = []resultRetained{} },
		"resolve phase": func(r *composeUpdateResult) { r.Phase = phaseResolve },
		"pull phase":    func(r *composeUpdateResult) { r.Phase = phasePull },
	} {
		r := passingRollbackResult(rb, updateBaselineOf(t, row))
		edit(&r)
		if _, err := parseContainerResult(mustResultJSON(t, r), composeRollbackFormat); !errors.Is(err, errComposeResult) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := parseContainerResult(good, "compose-rollback-v2"); !errors.Is(err, errComposeResult) {
		t.Fatalf("unknown format: %v", err)
	}
}

// rollbackDispatchRun is the dispatch run of a rollback member of rb.
func rollbackDispatchRun(t *testing.T, rb canonical.BatchContainerUpdate, execution string) dispatch.Run {
	t.Helper()
	m, params := testRollbackMember(t, rb)
	m.Request.ExecutionID = execution
	return dispatch.Run{ParentDigest: hexOf("f"), MemberID: m.MemberID, ExecutionID: execution, ActionID: composeRollbackAction,
		Member: m, Parameters: params}
}

// A rollback row records what it returns to and is completed by the
// rollback judge against the recorded update's baseline: recreated with a
// passing verdict, partial without that baseline, not_recreated when the
// retained image was gone before any change.
func TestRollbackRowCompletion(t *testing.T) {
	row, _, rb := rollbackFixture(t, time.Now())
	const exec = "00000000-0000-4000-8000-000000000002"
	intent, err := recreationIntent(rollbackDispatchRun(t, rb, exec), "web-1", "SHA256:k")
	if err != nil {
		t.Fatal(err)
	}
	if intent.Kind != canonical.ContainerUpdateKindRollback || intent.RollbackOf != row.ExecutionID || len(intent.Images) != 1 ||
		intent.Images[0].PriorImageID != row.Images[0].PriorImageID || intent.Images[0].RetainedTag != row.Images[0].RetainedTag ||
		intent.Images[0].RetainedReference != row.Images[0].RetainedReference {
		t.Fatalf("rollback intent %+v", intent)
	}
	ub := updateBaselineOf(t, row)
	res := mustResultJSON(t, passingRollbackResult(rb, ub))
	c := recreationCompletionWith(intent, row.Baseline, hostrun.ClassSuccess, res)
	if c.State != executordb.RecreationRecreated || !c.Verdict.Judged || !c.Verdict.Passed || len(c.Baseline) == 0 {
		t.Fatalf("clean rollback completion %+v", c)
	}
	if c = recreationCompletionWith(intent, nil, hostrun.ClassSuccess, res); c.State != executordb.RecreationPartial || c.Verdict.Passed {
		t.Fatalf("completion without the update's baseline %+v", c)
	}
	// Read as an update's result, a rollback result is uncertain.
	if c = recreationCompletion(row, hostrun.ClassSuccess, res); c.State != executordb.RecreationUncertain {
		t.Fatalf("rollback result on an update row %+v", c)
	}
	stopped := composeUpdateResult{Format: composeRollbackFormat, Phase: phaseRetain, Reason: "retained_image_missing", Project: rb.Project,
		Baseline: passingRollbackResult(rb, ub).Baseline}
	if c = recreationCompletionWith(intent, row.Baseline, hostrun.ClassPrecheckFailed, mustResultJSON(t, stopped)); c.State != executordb.RecreationNotRecreated {
		t.Fatalf("stopped rollback %+v", c)
	}
}
