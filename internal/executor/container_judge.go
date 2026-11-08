// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
)

// Postchecks of a container update (ADR 0006 P2-04, container update plan
// cu03, spec 11 v23-11-02). The executor judges a finished
// docker.compose_update 2.0.0 run itself, from the frozen binding and the
// two snapshots the script reports (phase 1 baseline, phase 6
// after-snapshot), before it records the member's outcome. Everything in
// the result comes from the managed host and is untrusted: the parser is
// strict and bounded, and anything it cannot read, or the judge cannot
// match, fails the verdict. Unknown is not success.
//
// The plan puts parser and judge into a new protected package
// internal/containerjudge (Q11). They live here, in the protected executor
// package, until that package is added to the protected list; the
// unprotected internal/executions/dockerhost only parses for display.

// composeUpdateFormat is the result format of docker.compose_update 2.0.0.
const composeUpdateFormat = "compose-update-v2"

// Limits of a judged compose-update-v2 result, enforced by the parser.
const (
	// maxJudgedResultBytes is the result limit of a durable job.
	maxJudgedResultBytes = hostrun.MaxResult
	// maxSnapshotEntries bounds each snapshot: the binding has at most 50
	// containers, the after-snapshot may list more (extra replicas), which
	// the judge refuses anyway.
	maxSnapshotEntries = 200
	// maxSnapshotPorts, maxSnapshotMounts and maxSnapshotNetworks bound the
	// lists of one entry.
	maxSnapshotPorts    = 64
	maxSnapshotMounts   = 64
	maxSnapshotNetworks = 32
	// maxSnapshotReference bounds a running reference (the script cuts at 512).
	maxSnapshotReference = 512
	// maxSnapshotPath bounds a mount source or destination.
	maxSnapshotPath = 1024
	// maxResultImages bounds the pulled and retained lists.
	maxResultImages = 20
	// maxVerdictFindings bounds the findings stored with a verdict.
	maxVerdictFindings = 50
)

// Phases of a compose-update-v2 result. The first four stop before any
// container changed.
const (
	phasePrecheck      = "precheck"
	phaseResolve       = "resolve"
	phasePull          = "pull"
	phaseRetain        = "retain"
	phaseRecreate      = "recreate"
	phaseAfterSnapshot = "after_snapshot"
)

var (
	// errComposeResult: the result is not a well-formed compose-update-v2
	// result within its limits.
	errComposeResult = errors.New("not a well-formed compose-update-v2 result")

	resultReasonRe   = regexp.MustCompile(`^[a-z][a-z_]{0,39}$`)
	snapServiceRe    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)
	snapNameRe       = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,129}$`)
	snapReplicaRe    = regexp.MustCompile(`^[1-9][0-9]{0,7}$`)
	snapHex64Re      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	snapImageIDRe    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	snapStartedAtRe  = regexp.MustCompile(`^[0-9TZ:.+-]{0,40}$`)
	snapRetainedTagR = regexp.MustCompile(`^nos-retained:[0-9a-f-]{36}-[0-9]{1,2}$`)
	snapStates       = map[string]bool{"created": true, "running": true, "paused": true, "restarting": true, "removing": true, "exited": true, "dead": true}
	snapHealth       = map[string]bool{"none": true, "starting": true, "healthy": true, "unhealthy": true}
	resultPhases     = map[string]bool{phasePrecheck: true, phaseResolve: true, phasePull: true, phaseRetain: true, phaseRecreate: true, phaseAfterSnapshot: true}
)

// snapshotMount is one mount of a snapshot entry.
type snapshotMount struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Mode        string `json:"mode"`
	RW          bool   `json:"rw"`
}

// snapshotEntry is one container of a baseline or after-snapshot.
type snapshotEntry struct {
	ID                  string          `json:"id"`
	Name                string          `json:"name"`
	Service             string          `json:"service"`
	Replica             string          `json:"replica"`
	State               string          `json:"state"`
	StartedAt           string          `json:"started_at"`
	Health              string          `json:"health"`
	Ports               []string        `json:"ports"`
	Mounts              []snapshotMount `json:"mounts"`
	Networks            []string        `json:"networks"`
	ImageID             string          `json:"image_id"`
	RunningReference    string          `json:"running_reference"`
	ConfigurationDigest string          `json:"configuration_digest"`
	Oversize            bool            `json:"oversize"`
}

type resultImage struct {
	Service string `json:"service"`
	ImageID string `json:"image_id"`
}

type resultRetained struct {
	Service string `json:"service"`
	Tag     string `json:"tag"`
}

// composeUpdateResult is a parsed compose-update-v2 result. Baseline and
// After are nil when the result does not carry them.
type composeUpdateResult struct {
	Format   string           `json:"format"`
	Phase    string           `json:"phase"`
	Reason   string           `json:"reason"`
	Service  string           `json:"service"`
	Project  string           `json:"project"`
	UpExit   *int             `json:"up_exit"`
	Baseline []snapshotEntry  `json:"baseline"`
	After    []snapshotEntry  `json:"after"`
	Pulled   []resultImage    `json:"pulled"`
	Retained []resultRetained `json:"retained"`
	// AfterTruncated is set when the script cut the after-snapshot at its
	// total bound (cu02t): the list is incomplete.
	AfterTruncated bool `json:"after_truncated"`
}

// stopped reports whether the run stopped in phases 1 to 4, before any
// container was touched.
func (r composeUpdateResult) stopped() bool {
	switch r.Phase {
	case phasePrecheck, phaseResolve, phasePull, phaseRetain:
		return true
	}
	return false
}

func boundedText(s string, limit int) bool {
	if len(s) > limit || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == 0x2028 || r == 0x2029 || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0xfeff {
			return false
		}
	}
	return true
}

func checkSnapshotEntry(e snapshotEntry) error {
	if !snapHex64Re.MatchString(e.ID) {
		return errors.New("entry without a full container ID")
	}
	if e.Oversize {
		// The script reports an entry over its size limit by ID only.
		if e.Name != "" || e.Service != "" || e.State != "" || e.ImageID != "" || len(e.Ports)+len(e.Mounts)+len(e.Networks) > 0 {
			return errors.New("oversize entry with fields")
		}
		return nil
	}
	switch {
	case !snapNameRe.MatchString(e.Name), !snapServiceRe.MatchString(e.Service), !snapReplicaRe.MatchString(e.Replica):
		return errors.New("entry with a malformed name, service or replica")
	case !snapStates[e.State], !snapHealth[e.Health], !snapStartedAtRe.MatchString(e.StartedAt):
		return errors.New("entry with a malformed state, health or start time")
	case !snapImageIDRe.MatchString(e.ImageID), !snapHex64Re.MatchString(e.ConfigurationDigest),
		e.RunningReference == "" || !boundedText(e.RunningReference, maxSnapshotReference):
		return errors.New("entry with a malformed image, reference or configuration digest")
	case len(e.Ports) > maxSnapshotPorts, len(e.Mounts) > maxSnapshotMounts, len(e.Networks) > maxSnapshotNetworks:
		return errors.New("entry over its list limits")
	}
	for _, p := range e.Ports {
		if !boundedText(p, 128) {
			return errors.New("entry with a malformed port")
		}
	}
	for _, n := range e.Networks {
		if n == "" || !boundedText(n, 128) {
			return errors.New("entry with a malformed network")
		}
	}
	for _, m := range e.Mounts {
		if !boundedText(m.Type, 16) || !boundedText(m.Source, maxSnapshotPath) || !boundedText(m.Destination, maxSnapshotPath) || !boundedText(m.Mode, 32) {
			return errors.New("entry with a malformed mount")
		}
	}
	return nil
}

// parseComposeUpdateResult reads a compose-update-v2 result strictly:
// bounded size, valid UTF-8, one JSON document, no unknown field, every
// value in its expected shape.
func parseComposeUpdateResult(b []byte) (composeUpdateResult, error) {
	if len(b) == 0 || len(b) > maxJudgedResultBytes || !utf8.Valid(b) {
		return composeUpdateResult{}, errComposeResult
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r composeUpdateResult
	if err := dec.Decode(&r); err != nil {
		return composeUpdateResult{}, fmt.Errorf("%w: %w", errComposeResult, err)
	}
	if dec.More() {
		return composeUpdateResult{}, fmt.Errorf("%w: trailing data", errComposeResult)
	}
	switch {
	case r.Format != composeUpdateFormat || !resultPhases[r.Phase]:
		return composeUpdateResult{}, fmt.Errorf("%w: format or phase", errComposeResult)
	case r.Reason != "" && !resultReasonRe.MatchString(r.Reason):
		return composeUpdateResult{}, fmt.Errorf("%w: reason", errComposeResult)
	case r.Service != "" && !snapServiceRe.MatchString(r.Service):
		return composeUpdateResult{}, fmt.Errorf("%w: service", errComposeResult)
	case !boundedText(r.Project, 63):
		return composeUpdateResult{}, fmt.Errorf("%w: project", errComposeResult)
	case len(r.Baseline) > maxSnapshotEntries, len(r.After) > maxSnapshotEntries,
		len(r.Pulled) > maxResultImages, len(r.Retained) > maxResultImages:
		return composeUpdateResult{}, fmt.Errorf("%w: over a list limit", errComposeResult)
	}
	for _, side := range [][]snapshotEntry{r.Baseline, r.After} {
		for _, e := range side {
			if err := checkSnapshotEntry(e); err != nil {
				return composeUpdateResult{}, fmt.Errorf("%w: %w", errComposeResult, err)
			}
		}
	}
	for _, p := range r.Pulled {
		if !snapServiceRe.MatchString(p.Service) || !snapImageIDRe.MatchString(p.ImageID) {
			return composeUpdateResult{}, fmt.Errorf("%w: pulled image", errComposeResult)
		}
	}
	for _, t := range r.Retained {
		if !snapServiceRe.MatchString(t.Service) || !snapRetainedTagR.MatchString(t.Tag) {
			return composeUpdateResult{}, fmt.Errorf("%w: retained image", errComposeResult)
		}
	}
	return r, nil
}

// containerVerdict is the executor's postcheck verdict of one member run.
type containerVerdict struct {
	Passed   bool
	Findings []string
}

// replicaKey identifies a replica across a recreate (IDs change).
func replicaKey(service, replica string) string { return service + "/" + replica }

// healthRegressed applies the health rule: healthy or starting before must
// be healthy after (starting past the wait is a regression); no health
// check must stay none; unhealthy before is no regression.
func healthRegressed(before, after string) bool {
	switch before {
	case "healthy", "starting":
		return after != "healthy"
	case "none":
		return after != "none"
	}
	return false
}

func sameStrings(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	sort.Strings(x)
	sort.Strings(y)
	return slices.Equal(x, y)
}

func sameMounts(a, b []snapshotMount) bool {
	key := func(ms []snapshotMount) []string {
		out := make([]string, len(ms))
		for i, m := range ms {
			out[i] = fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%t", m.Type, m.Source, m.Destination, m.Mode, m.RW)
		}
		return out
	}
	return sameStrings(key(a), key(b))
}

// expectedReference is the reference phase 5 writes into the NOS override
// for an image entry.
func expectedReference(img canonical.ContainerUpdateImage) string {
	return img.Repository + ":" + img.NewTag + "@" + img.NewPlatformDigest
}

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
// The result is about the bound project. Each dependency container keeps
// its ID, configuration digest and run state, has no health regression,
// and restarts only with restart_on_update. A missing, or truncated,
// baseline or after-snapshot, an unreadable entry and an unmatched
// container fail.
func judgeComposeUpdate(u canonical.BatchContainerUpdate, retained map[string]string, r composeUpdateResult) containerVerdict {
	var findings []string
	fail := func(f string, a ...any) { findings = append(findings, fmt.Sprintf(f, a...)) }
	verdict := func() containerVerdict {
		sort.Strings(findings)
		if len(findings) > maxVerdictFindings {
			findings = append(findings[:maxVerdictFindings], "more findings omitted")
		}
		return containerVerdict{Passed: len(findings) == 0, Findings: findings}
	}
	if u.Kind != canonical.ContainerUpdateKindUpdate || u.Form != canonical.ContainerUpdateFormCompose {
		fail("no postcheck exists for kind %s, form %s", u.Kind, u.Form)
		return verdict()
	}
	if r.Phase != phaseAfterSnapshot {
		fail("the run ended in phase %s (%s); nothing to judge", r.Phase, reasonText(r.Reason))
		return verdict()
	}
	if r.UpExit == nil || *r.UpExit != 0 {
		fail("docker compose up did not succeed (%s)", reasonText(r.Reason))
	} else if r.Reason != "" {
		fail("the run reported %s", reasonText(r.Reason))
	}
	if len(r.Baseline) == 0 {
		fail("no baseline snapshot")
		return verdict()
	}
	if r.After == nil {
		fail("no after-snapshot; the recreation is uncertain")
		return verdict()
	}
	if r.AfterTruncated {
		fail("the after-snapshot was truncated; the recreation cannot be judged in full")
	}
	if r.Project != u.Project {
		fail("the result is about project %s, not the bound project %s", r.Project, u.Project)
	}
	frozen := map[string]canonical.ContainerUpdateImage{}
	for _, img := range u.Images {
		frozen[img.Service] = img
	}
	gotRetained := map[string]string{}
	for _, t := range r.Retained {
		switch _, dup := gotRetained[t.Service]; {
		case frozen[t.Service].Service == "":
			fail("the run retained an image for %s, which is no frozen service", t.Service)
		case dup:
			fail("service %s: prior image retained twice", t.Service)
		default:
			gotRetained[t.Service] = t.Tag
		}
	}
	for _, img := range u.Images {
		want := retained[img.Service]
		if got, ok := gotRetained[img.Service]; !ok || want == "" || got != want {
			fail("service %s: prior image not retained under %s", img.Service, want)
		}
	}
	pulled := map[string]string{}
	for _, p := range r.Pulled {
		if old, dup := pulled[p.Service]; dup && old != p.ImageID {
			fail("service %s: two pulled images reported", p.Service)
		}
		pulled[p.Service] = p.ImageID
	}
	depByID := map[string]canonical.ContainerUpdateDependency{}
	depServices := map[string]bool{}
	for _, d := range u.Dependencies {
		depServices[d.Service] = true
		for _, c := range d.Containers {
			depByID[c.ContainerID] = d
		}
	}
	targets := map[string]bool{}
	boundTarget := map[string]canonical.ContainerUpdateTarget{}
	for _, t := range u.Targets {
		targets[t.ContainerID] = true
		boundTarget[t.ContainerID] = t
	}

	// The baseline must be exactly the bound targets and dependency
	// containers, each once, with a unique replica key per service.
	before := map[string]snapshotEntry{}
	beforeByID := map[string]snapshotEntry{}
	for _, e := range r.Baseline {
		if e.Oversize {
			fail("a baseline entry is too large to judge")
			continue
		}
		if _, dup := beforeByID[e.ID]; dup {
			fail("baseline lists container %s twice", e.Name)
			continue
		}
		beforeByID[e.ID] = e
		if !targets[e.ID] && depByID[e.ID].Service == "" {
			fail("baseline container %s is neither a bound target nor a bound dependency", e.Name)
			continue
		}
		if targets[e.ID] {
			t := boundTarget[e.ID]
			if e.Service != t.Service {
				fail("baseline container %s is reported under service %s, bound to %s", e.Name, e.Service, t.Service)
				continue
			}
			if _, ok := frozen[e.Service]; !ok {
				fail("baseline container %s belongs to no frozen service", e.Name)
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
				fail("target %s drifted from the approved binding: %s", e.Name, strings.Join(drift, ", "))
			}
			k := replicaKey(e.Service, e.Replica)
			if _, dup := before[k]; dup {
				fail("baseline lists %s replica %s twice", e.Service, e.Replica)
				continue
			}
			before[k] = e
		}
	}
	for id := range targets {
		if _, ok := beforeByID[id]; !ok {
			fail("a bound target is missing from the baseline")
		}
	}
	for id := range depByID {
		if _, ok := beforeByID[id]; !ok {
			fail("a bound dependency container is missing from the baseline")
		}
	}

	after := map[string]snapshotEntry{}
	afterByID := map[string]snapshotEntry{}
	for _, e := range r.After {
		if e.Oversize {
			fail("an after-snapshot entry is too large to judge")
			continue
		}
		if _, dup := afterByID[e.ID]; dup {
			fail("after-snapshot lists container %s twice", e.Name)
			continue
		}
		afterByID[e.ID] = e
		switch {
		case frozen[e.Service].Service != "":
			k := replicaKey(e.Service, e.Replica)
			if _, dup := after[k]; dup {
				fail("after-snapshot lists %s replica %s twice", e.Service, e.Replica)
				continue
			}
			if _, ok := before[k]; !ok {
				fail("%s replica %s was not there before the update", e.Service, e.Replica)
			}
			after[k] = e
		case depServices[e.Service]:
			if _, ok := depByID[e.ID]; !ok {
				fail("dependency service %s has a container that is not bound (%s)", e.Service, e.Name)
			}
		default:
			fail("after-snapshot container %s belongs to no frozen service or dependency", e.Name)
		}
	}

	for k, b := range before {
		img := frozen[b.Service]
		a, ok := after[k]
		if !ok {
			fail("%s replica %s is missing after the update", b.Service, b.Replica)
			continue
		}
		if a.State != "running" {
			fail("%s replica %s is %s, not running", b.Service, b.Replica, a.State)
		}
		if healthRegressed(b.Health, a.Health) {
			fail("%s replica %s: health %s before, %s after", b.Service, b.Replica, b.Health, a.Health)
		}
		if !sameStrings(b.Ports, a.Ports) {
			fail("%s replica %s: published ports changed", b.Service, b.Replica)
		}
		if !sameMounts(b.Mounts, a.Mounts) {
			fail("%s replica %s: mounts changed", b.Service, b.Replica)
		}
		if !sameStrings(b.Networks, a.Networks) {
			fail("%s replica %s: networks changed", b.Service, b.Replica)
		}
		want, ok := pulled[b.Service]
		switch {
		case !ok:
			fail("service %s: no verified pulled image reported", b.Service)
		case a.ImageID != want:
			fail("%s replica %s does not run the image pulled for the approved digest", b.Service, b.Replica)
		}
		if a.RunningReference != expectedReference(img) {
			fail("%s replica %s does not run the approved reference", b.Service, b.Replica)
		}
	}

	for id, d := range depByID {
		b, okB := beforeByID[id]
		if !okB {
			continue
		}
		a, ok := afterByID[id]
		if !ok {
			fail("dependency %s was recreated or removed", b.Name)
			continue
		}
		var bound string
		for _, c := range d.Containers {
			if c.ContainerID == id {
				bound = c.ConfigurationDigest
			}
		}
		if a.ConfigurationDigest != bound || b.ConfigurationDigest != bound {
			fail("dependency %s changed its configuration", b.Name)
		}
		if a.State != b.State {
			fail("dependency %s was %s and is %s now", b.Name, b.State, a.State)
		}
		if healthRegressed(b.Health, a.Health) {
			fail("dependency %s: health %s before, %s after", b.Name, b.Health, a.Health)
		}
		if a.StartedAt != b.StartedAt && !d.RestartOnUpdate {
			fail("dependency %s was restarted without restart_on_update", b.Name)
		}
	}
	return verdict()
}

func reasonText(reason string) string {
	if reason == "" {
		return "no reason given"
	}
	return reason
}

// containerPostcheckLabel is the fixed label of a container member's
// postcheck hash.
const containerPostcheckLabel = "nos-container-postcheck-v1"

// containerPostcheckHash is the member's own postcheck hash: SHA-256 over a
// fixed label and the member ID, so a stage needs the verdict of every
// member and one member's hash does not stand in for another's. The plan
// names it canonical.ContainerPostcheckHash; it moves there with the
// planner change that lists one hash per member in RequiredPostchecks.
func containerPostcheckHash(memberID string) string {
	d := sha256.Sum256([]byte(containerPostcheckLabel + "\x00" + memberID))
	return hex.EncodeToString(d[:])
}

// boundFindings trims each finding to a fixed size.
func boundFindings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, f := range in {
		if len(f) > 300 {
			f = strings.ToValidUTF8(f[:300], "")
		}
		out = append(out, f)
	}
	return out
}
