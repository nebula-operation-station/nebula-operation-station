// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// The postcheck steps shared by the update and the rollback judge, and the
// two judges themselves (ADR 0006 P2-04, container update plan cu03).

// judgeComposeUpdate is the before/after postflight of an update member
// (kind=update, form=compose) over the run's result. Per frozen service,
// matched by service and replica number against the baseline: the same
// replica count, each running, no health regression, the same published
// ports, mounts and networks, and the image the run pulled and verified
// for the approved digest, under the approved reference. Each bound target
// is in the baseline with its bound service, image, running reference and
// configuration digest. Each frozen service's prior image is retained under
// exactly the tag recorded for it (retained: service to
// nos-retained:<execution>-<index>), and nothing else is reported retained.
// The result is about the bound project. Each dependency container is
// reported under its bound dependency service in both snapshots, keeps
// its ID, configuration digest and run state, has no health regression,
// and restarts only with restart_on_update. A missing, or truncated,
// baseline or after-snapshot, an unreadable entry and an unmatched
// container fail.
func judgeComposeUpdate(u canonical.BatchContainerUpdate, retained map[string]string, r composeUpdateResult) containerVerdict {
	j := newJudgement(u)
	if u.Kind != canonical.ContainerUpdateKindUpdate || u.Form != canonical.ContainerUpdateFormCompose {
		j.fail("no postcheck exists for kind %s, form %s", u.Kind, u.Form)
		return j.verdict()
	}
	if !j.preamble(r) {
		return j.verdict()
	}
	gotRetained := map[string]string{}
	for _, t := range r.Retained {
		switch _, dup := gotRetained[t.Service]; {
		case j.frozen[t.Service].Service == "":
			j.fail("the run retained an image for %s, which is no frozen service", t.Service)
		case dup:
			j.fail("service %s: prior image retained twice", t.Service)
		default:
			gotRetained[t.Service] = t.Tag
		}
	}
	for _, img := range u.Images {
		want := retained[img.Service]
		if got, ok := gotRetained[img.Service]; !ok || want == "" || got != want {
			j.fail("service %s: prior image not retained under %s", img.Service, want)
		}
	}
	pulled := map[string]string{}
	for _, p := range r.Pulled {
		if old, dup := pulled[p.Service]; dup && old != p.ImageID {
			j.fail("service %s: two pulled images reported", p.Service)
		}
		pulled[p.Service] = p.ImageID
	}

	before, beforeByID := j.baseline(r.Baseline)
	after, afterByID := j.after(r.After, before, "update")
	for k, b := range before {
		a, ok := after[k]
		if !ok {
			j.fail("%s replica %s is missing after the update", b.Service, b.Replica)
			continue
		}
		j.sameReplica(b, a)
		want, ok := pulled[b.Service]
		switch {
		case !ok:
			j.fail("service %s: no verified pulled image reported", b.Service)
		case a.ImageID != want:
			j.fail("%s replica %s does not run the image pulled for the approved digest", b.Service, b.Replica)
		}
		if a.RunningReference != expectedReference(j.frozen[b.Service]) {
			j.fail("%s replica %s does not run the approved reference", b.Service, b.Replica)
		}
	}
	j.dependencies(beforeByID, afterByID)
	return j.verdict()
}

// judgeComposeRollback is the postflight of a rollback member (kind=
// rollback, form=compose) over the rollback run's result. The recreated
// services are judged against the recorded update's baseline (what the
// rollback returns to), the dependencies against the rollback's own
// baseline: per bound service, every replica of the update's baseline is
// back, running, with no health regression against that baseline and the
// same published ports, mounts and networks, on the bound prior image under
// the bound retained reference; no other replica exists. The rollback's
// own baseline is exactly the bound targets (with their recorded image,
// running reference and configuration digest) and dependency containers.
// Nothing may be reported pulled or retained. A missing update baseline,
// a missing or truncated snapshot and an unmatched container fail.
func judgeComposeRollback(u canonical.BatchContainerUpdate, updateBaseline []snapshotEntry, r composeUpdateResult) containerVerdict {
	j := newJudgement(u)
	if u.Kind != canonical.ContainerUpdateKindRollback || u.Form != canonical.ContainerUpdateFormCompose {
		j.fail("no rollback postcheck exists for kind %s, form %s", u.Kind, u.Form)
		return j.verdict()
	}
	for _, img := range u.Images {
		if img.Rollback == nil {
			j.fail("service %s: the binding names no prior image", img.Service)
			return j.verdict()
		}
	}
	if len(updateBaseline) == 0 {
		j.fail("the recorded update has no baseline; nothing to return to")
		return j.verdict()
	}
	if !j.preamble(r) {
		return j.verdict()
	}
	if len(r.Pulled) > 0 || len(r.Retained) > 0 {
		j.fail("the rollback reported pulled or retained images")
	}
	_, beforeByID := j.baseline(r.Baseline)

	// What the rollback returns to: the update's baseline replicas of the
	// bound services.
	restore := map[string]snapshotEntry{}
	for _, e := range updateBaseline {
		if e.Oversize {
			j.fail("an entry of the update's baseline is too large to judge")
			continue
		}
		if _, ok := j.frozen[e.Service]; !ok {
			continue
		}
		k := replicaKey(e.Service, e.Replica)
		if _, dup := restore[k]; dup {
			j.fail("the update's baseline lists %s replica %s twice", e.Service, e.Replica)
			continue
		}
		restore[k] = e
	}
	after, afterByID := j.after(r.After, restore, "update")
	for k, b := range restore {
		img := j.frozen[b.Service]
		a, ok := after[k]
		if !ok {
			j.fail("%s replica %s is missing after the rollback", b.Service, b.Replica)
			continue
		}
		j.sameReplica(b, a)
		if a.ImageID != img.Rollback.PriorImageID {
			j.fail("%s replica %s does not run the prior image", b.Service, b.Replica)
		}
		if a.RunningReference != img.Rollback.RetainedReference {
			j.fail("%s replica %s does not run the retained reference", b.Service, b.Replica)
		}
	}
	j.dependencies(beforeByID, afterByID)
	return j.verdict()
}

// judgement collects the findings of one postcheck over a binding.
type judgement struct {
	u           canonical.BatchContainerUpdate
	findings    []string
	frozen      map[string]canonical.ContainerUpdateImage
	depByID     map[string]canonical.ContainerUpdateDependency
	depServices map[string]bool
	targets     map[string]canonical.ContainerUpdateTarget
}

func newJudgement(u canonical.BatchContainerUpdate) *judgement {
	j := &judgement{u: u, frozen: map[string]canonical.ContainerUpdateImage{}, depByID: map[string]canonical.ContainerUpdateDependency{},
		depServices: map[string]bool{}, targets: map[string]canonical.ContainerUpdateTarget{}}
	for _, img := range u.Images {
		j.frozen[img.Service] = img
	}
	for _, d := range u.Dependencies {
		j.depServices[d.Service] = true
		for _, c := range d.Containers {
			j.depByID[c.ContainerID] = d
		}
	}
	for _, t := range u.Targets {
		j.targets[t.ContainerID] = t
	}
	return j
}

func (j *judgement) fail(f string, a ...any) { j.findings = append(j.findings, fmt.Sprintf(f, a...)) }

func (j *judgement) verdict() containerVerdict {
	findings := j.findings
	sort.Strings(findings)
	if len(findings) > maxVerdictFindings {
		findings = append(findings[:maxVerdictFindings], "more findings omitted")
	}
	return containerVerdict{Passed: len(findings) == 0, Findings: findings}
}

// preamble checks the run's end (phase, up, reason), that both snapshots
// are there and complete, and the project. false: nothing more to judge.
func (j *judgement) preamble(r composeUpdateResult) bool {
	if r.Phase != phaseAfterSnapshot {
		j.fail("the run ended in phase %s (%s); nothing to judge", r.Phase, reasonText(r.Reason))
		return false
	}
	if r.UpExit == nil || *r.UpExit != 0 {
		j.fail("docker compose up did not succeed (%s)", reasonText(r.Reason))
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
	if r.Project != j.u.Project {
		j.fail("the result is about project %s, not the bound project %s", r.Project, j.u.Project)
	}
	return true
}

// baseline checks the run's own baseline: exactly the bound targets and
// dependency containers, each once, every target under its bound service
// with its bound image, running reference and configuration digest, and a
// unique replica key per service. It returns the targets by replica key
// and every entry by ID.
func (j *judgement) baseline(entries []snapshotEntry) (map[string]snapshotEntry, map[string]snapshotEntry) {
	before := map[string]snapshotEntry{}
	beforeByID := map[string]snapshotEntry{}
	for _, e := range entries {
		if e.Oversize {
			j.fail("a baseline entry is too large to judge")
			continue
		}
		if _, dup := beforeByID[e.ID]; dup {
			j.fail("baseline lists container %s twice", e.Name)
			continue
		}
		beforeByID[e.ID] = e
		t, isTarget := j.targets[e.ID]
		if !isTarget && j.depByID[e.ID].Service == "" {
			j.fail("baseline container %s is neither a bound target nor a bound dependency", e.Name)
			continue
		}
		if d, ok := j.depByID[e.ID]; ok && !isTarget && e.Service != d.Service {
			j.fail("baseline container %s is reported under service %s, bound to %s", e.Name, e.Service, d.Service)
			continue
		}
		if !isTarget {
			continue
		}
		if e.Service != t.Service {
			j.fail("baseline container %s is reported under service %s, bound to %s", e.Name, e.Service, t.Service)
			continue
		}
		if _, ok := j.frozen[e.Service]; !ok {
			j.fail("baseline container %s belongs to no frozen service", e.Name)
			continue
		}
		var drift []string
		if e.ImageID != t.ImageID {
			drift = append(drift, "image")
		}
		if e.RunningReference != t.RunningReference {
			drift = append(drift, "running reference")
		}
		if e.ConfigurationDigest != t.ConfigurationDigest {
			drift = append(drift, "configuration")
		}
		if len(drift) > 0 {
			j.fail("target %s drifted from the approved binding: %s", e.Name, strings.Join(drift, ", "))
		}
		k := replicaKey(e.Service, e.Replica)
		if _, dup := before[k]; dup {
			j.fail("baseline lists %s replica %s twice", e.Service, e.Replica)
			continue
		}
		before[k] = e
	}
	for id := range j.targets {
		if _, ok := beforeByID[id]; !ok {
			j.fail("a bound target is missing from the baseline")
		}
	}
	for id := range j.depByID {
		if _, ok := beforeByID[id]; !ok {
			j.fail("a bound dependency container is missing from the baseline")
		}
	}
	return before, beforeByID
}

// after reads the after-snapshot: every container belongs to a frozen
// service (as a replica that is in reference, once) or is a bound
// dependency container under its bound service. It returns the frozen
// services' replicas by key and every entry by ID.
func (j *judgement) after(entries []snapshotEntry, reference map[string]snapshotEntry, what string) (map[string]snapshotEntry, map[string]snapshotEntry) {
	after := map[string]snapshotEntry{}
	afterByID := map[string]snapshotEntry{}
	for _, e := range entries {
		if e.Oversize {
			j.fail("an after-snapshot entry is too large to judge")
			continue
		}
		if _, dup := afterByID[e.ID]; dup {
			j.fail("after-snapshot lists container %s twice", e.Name)
			continue
		}
		afterByID[e.ID] = e
		if d, ok := j.depByID[e.ID]; ok && e.Service != d.Service {
			// A bound dependency container stays under its bound service;
			// it is still judged as that dependency below.
			j.fail("dependency %s is reported under service %s, bound to %s", e.Name, e.Service, d.Service)
			continue
		}
		switch {
		case j.frozen[e.Service].Service != "":
			k := replicaKey(e.Service, e.Replica)
			if _, dup := after[k]; dup {
				j.fail("after-snapshot lists %s replica %s twice", e.Service, e.Replica)
				continue
			}
			if _, ok := reference[k]; !ok {
				j.fail("%s replica %s was not there before the %s", e.Service, e.Replica, what)
			}
			after[k] = e
		case j.depServices[e.Service]:
			if _, ok := j.depByID[e.ID]; !ok {
				j.fail("dependency service %s has a container that is not bound (%s)", e.Service, e.Name)
			}
		default:
			j.fail("after-snapshot container %s belongs to no frozen service or dependency", e.Name)
		}
	}
	return after, afterByID
}

// sameReplica applies the per-replica rules that do not depend on the
// image: running, no health regression, the same published ports, mounts
// and networks as b.
func (j *judgement) sameReplica(b, a snapshotEntry) {
	if a.State != "running" {
		j.fail("%s replica %s is %s, not running", b.Service, b.Replica, a.State)
	}
	if healthRegressed(b.Health, a.Health) {
		j.fail("%s replica %s: health %s before, %s after", b.Service, b.Replica, b.Health, a.Health)
	}
	if !sameStrings(b.Ports, a.Ports) {
		j.fail("%s replica %s: published ports changed", b.Service, b.Replica)
	}
	if !sameMounts(b.Mounts, a.Mounts) {
		j.fail("%s replica %s: mounts changed", b.Service, b.Replica)
	}
	if !sameStrings(b.Networks, a.Networks) {
		j.fail("%s replica %s: networks changed", b.Service, b.Replica)
	}
}

// dependencies judges each bound dependency container between the run's
// own baseline and after-snapshot: the same ID, configuration digest and
// run state, no health regression, and a restart only with
// restart_on_update.
func (j *judgement) dependencies(beforeByID, afterByID map[string]snapshotEntry) {
	for id, d := range j.depByID {
		b, okB := beforeByID[id]
		if !okB {
			continue
		}
		a, ok := afterByID[id]
		if !ok {
			j.fail("dependency %s was recreated or removed", b.Name)
			continue
		}
		var bound string
		for _, c := range d.Containers {
			if c.ContainerID == id {
				bound = c.ConfigurationDigest
			}
		}
		if a.ConfigurationDigest != bound || b.ConfigurationDigest != bound {
			j.fail("dependency %s changed its configuration", b.Name)
		}
		if a.State != b.State {
			j.fail("dependency %s was %s and is %s now", b.Name, b.State, a.State)
		}
		if healthRegressed(b.Health, a.Health) {
			j.fail("dependency %s: health %s before, %s after", b.Name, b.Health, a.Health)
		}
		if a.StartedAt != b.StartedAt && !d.RestartOnUpdate {
			j.fail("dependency %s was restarted without restart_on_update", b.Name)
		}
	}
}
