// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// The postchecks of a standalone member (container update plan cu05): one
// container, matched by its bound name, judged with the same per-replica
// rules as a compose replica (running, no health regression, the same
// published ports, mounts and networks).

// judgeStandaloneUpdate is the postflight of a standalone update
// (kind=update, form=standalone) over the run's standalone-update-v1
// result: the run reached its after-snapshot with recreate_exit 0 and no
// reason; the baseline is exactly the bound target with its bound image,
// running reference and configuration digest; the prior image is retained
// under exactly retainedTag (the intent row's); one image was pulled; and
// the after-snapshot is exactly one new container under the bound name,
// running, with no health regression and the baseline's ports, mounts and
// networks, on the pulled image under the approved reference.
func judgeStandaloneUpdate(u canonical.BatchContainerUpdate, retainedTag string, r composeUpdateResult) containerVerdict {
	j := newJudgement(u)
	if u.Kind != canonical.ContainerUpdateKindUpdate || u.Form != canonical.ContainerUpdateFormAlone || len(u.Images) != 1 || len(u.Targets) != 1 {
		j.fail("no standalone postcheck exists for kind %s, form %s", u.Kind, u.Form)
		return j.verdict()
	}
	if !j.standalonePreamble(r) {
		return j.verdict()
	}
	if len(r.Retained) != 1 || retainedTag == "" || r.Retained[0].Tag != retainedTag {
		j.fail("prior image not retained under %s", retainedTag)
	}
	pulled := ""
	if len(r.Pulled) == 1 {
		pulled = r.Pulled[0].ImageID
	} else {
		j.fail("no single verified pulled image reported")
	}
	before, _ := j.baseline(r.Baseline)
	b, ok := before[replicaKey("", "1")]
	if !ok {
		return j.verdict()
	}
	a, ok := j.standaloneAfter(r.After, b, b)
	if !ok {
		return j.verdict()
	}
	if a.ImageID != pulled || pulled == "" {
		j.fail("container %s does not run the image pulled for the approved digest", b.Name)
	}
	if a.RunningReference != expectedReference(u.Images[0]) {
		j.fail("container %s does not run the approved reference", b.Name)
	}
	return j.verdict()
}

// judgeStandaloneRollback is the postflight of a standalone rollback
// (kind=rollback, form=standalone) over the run's standalone-rollback-v1
// result, against updateBaseline, the recorded update's baseline (what the
// rollback returns to): the rollback's own baseline is exactly the bound
// target; the after-snapshot is exactly one new container under the bound
// name, which is the update baseline's name, running, with no health
// regression and that baseline's ports, mounts and networks, on the bound
// prior image under the bound retained reference. Nothing may be reported
// pulled or retained.
func judgeStandaloneRollback(u canonical.BatchContainerUpdate, updateBaseline []snapshotEntry, r composeUpdateResult) containerVerdict {
	j := newJudgement(u)
	if u.Kind != canonical.ContainerUpdateKindRollback || u.Form != canonical.ContainerUpdateFormAlone || len(u.Images) != 1 || len(u.Targets) != 1 {
		j.fail("no standalone rollback postcheck exists for kind %s, form %s", u.Kind, u.Form)
		return j.verdict()
	}
	rb := u.Images[0].Rollback
	if rb == nil {
		j.fail("the binding names no prior image")
		return j.verdict()
	}
	if len(updateBaseline) != 1 || updateBaseline[0].Oversize || updateBaseline[0].Name != u.Targets[0].ContainerName {
		j.fail("the recorded update has no baseline of the bound container; nothing to return to")
		return j.verdict()
	}
	if !j.standalonePreamble(r) {
		return j.verdict()
	}
	if len(r.Pulled) > 0 || len(r.Retained) > 0 {
		j.fail("the rollback reported pulled or retained images")
	}
	before, _ := j.baseline(r.Baseline)
	b, ok := before[replicaKey("", "1")]
	if !ok {
		return j.verdict()
	}
	// Judged against what the rollback returns to.
	a, ok := j.standaloneAfter(r.After, b, updateBaseline[0])
	if !ok {
		return j.verdict()
	}
	if a.ImageID != rb.PriorImageID {
		j.fail("container %s does not run the prior image", b.Name)
	}
	if a.RunningReference != rb.RetainedReference {
		j.fail("container %s does not run the retained reference", b.Name)
	}
	return j.verdict()
}

// standalonePreamble checks the run's end (phase, recreate, reason) and
// that both snapshots are there. false: nothing more to judge.
func (j *judgement) standalonePreamble(r composeUpdateResult) bool {
	if r.Phase != phaseAfterSnapshot {
		j.fail("the run ended in phase %s (%s); nothing to judge", r.Phase, reasonText(r.Reason))
		return false
	}
	if r.RecreateExit == nil || *r.RecreateExit != 0 {
		j.fail("the recreate did not succeed (%s)", reasonText(r.Reason))
	} else if r.Reason != "" {
		j.fail("the run reported %s", reasonText(r.Reason))
	}
	if len(r.Baseline) == 0 {
		j.fail("no baseline snapshot")
		return false
	}
	if r.After == nil {
		j.fail("no after-snapshot; the recreation is uncertain")
		return false
	}
	if r.AfterTruncated {
		j.fail("the after-snapshot was truncated; the recreation cannot be judged in full")
	}
	return true
}

// standaloneAfter reads the after-snapshot of a standalone run: exactly
// one container, under the baseline's (the bound) name, a new incarnation
// of b, judged against ref by sameReplica. ok is false when there is none
// to judge further.
func (j *judgement) standaloneAfter(entries []snapshotEntry, b, ref snapshotEntry) (snapshotEntry, bool) {
	switch {
	case len(entries) == 0:
		j.fail("container %s is missing after the recreate", b.Name)
		return snapshotEntry{}, false
	case len(entries) > 1:
		j.fail("the after-snapshot lists more than one container")
		return snapshotEntry{}, false
	case entries[0].Oversize:
		j.fail("an after-snapshot entry is too large to judge")
		return snapshotEntry{}, false
	}
	a := entries[0]
	if a.Name != b.Name {
		j.fail("the after-snapshot container is %s, not the bound %s", a.Name, b.Name)
		return snapshotEntry{}, false
	}
	if a.ID == b.ID {
		j.fail("container %s was not recreated", b.Name)
	}
	j.sameReplica(ref, a)
	return a, true
}
