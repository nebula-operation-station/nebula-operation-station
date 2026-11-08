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

// composeRollbackFormat is the result format of docker.compose_rollback
// 1.0.0: the compose-update-v2 shape, without the resolve and pull phases
// and without pulled or retained images.
const composeRollbackFormat = "compose-rollback-v1"

// standaloneUpdateFormat and standaloneRollbackFormat are the result
// formats of docker.update and docker.rollback 1.0.0 (cu05): the shapes of
// compose-update-v2 and compose-rollback-v1 for one container, with no
// project, the recreate's exit status in recreate_exit instead of up_exit,
// and every snapshot entry, pulled and retained image under service ""
// (the one container is matched by name; its replica is "1").
const (
	standaloneUpdateFormat   = "standalone-update-v1"
	standaloneRollbackFormat = "standalone-rollback-v1"
)

// containerResultFormat is the result format of a binding's kind and form.
func containerResultFormat(u canonical.BatchContainerUpdate) string {
	rollback := u.Kind == canonical.ContainerUpdateKindRollback
	switch {
	case u.Form == canonical.ContainerUpdateFormAlone && rollback:
		return standaloneRollbackFormat
	case u.Form == canonical.ContainerUpdateFormAlone:
		return standaloneUpdateFormat
	case rollback:
		return composeRollbackFormat
	}
	return composeUpdateFormat
}

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
	// (or compose-rollback-v1) result within its limits.
	errComposeResult = errors.New("not a well-formed compose-update-v2 or compose-rollback-v1 result")

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
	Format  string `json:"format"`
	Phase   string `json:"phase"`
	Reason  string `json:"reason"`
	Service string `json:"service"`
	Project string `json:"project"`
	UpExit  *int   `json:"up_exit"`
	// RecreateExit is the standalone recreate's exit status (standalone
	// formats only).
	RecreateExit *int             `json:"recreate_exit"`
	Baseline     []snapshotEntry  `json:"baseline"`
	After        []snapshotEntry  `json:"after"`
	Pulled       []resultImage    `json:"pulled"`
	Retained     []resultRetained `json:"retained"`
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

// checkSnapshotEntry checks one snapshot entry. A standalone entry has
// service "" and replica "1"; a compose entry a service name and replica
// number.
func checkSnapshotEntry(e snapshotEntry, standalone bool) error {
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
	unit := snapServiceRe.MatchString(e.Service) && snapReplicaRe.MatchString(e.Replica)
	if standalone {
		unit = e.Service == "" && e.Replica == "1"
	}
	switch {
	case !snapNameRe.MatchString(e.Name), !unit:
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
	return parseContainerResult(b, composeUpdateFormat)
}

// parseContainerResult reads a result of format (compose-update-v2,
// compose-rollback-v1, standalone-update-v1 or standalone-rollback-v1)
// with the same strict rules. A rollback result has no resolve or pull
// phase and reports no pulled or retained image. A compose result carries
// no recreate_exit; a standalone result no project, service or up_exit,
// and only service "" entries and images.
func parseContainerResult(b []byte, format string) (composeUpdateResult, error) {
	standalone := format == standaloneUpdateFormat || format == standaloneRollbackFormat
	rollback := format == composeRollbackFormat || format == standaloneRollbackFormat
	if format != composeUpdateFormat && format != composeRollbackFormat && !standalone {
		return composeUpdateResult{}, fmt.Errorf("%w: unknown format", errComposeResult)
	}
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
	case r.Format != format || !resultPhases[r.Phase]:
		return composeUpdateResult{}, fmt.Errorf("%w: format or phase", errComposeResult)
	case rollback && (r.Phase == phaseResolve || r.Phase == phasePull || r.Pulled != nil || r.Retained != nil):
		return composeUpdateResult{}, fmt.Errorf("%w: a rollback resolves, pulls and retains nothing", errComposeResult)
	case standalone && (r.Project != "" || r.Service != "" || r.UpExit != nil):
		return composeUpdateResult{}, fmt.Errorf("%w: a standalone result names no project or service and has no up_exit", errComposeResult)
	case !standalone && r.RecreateExit != nil:
		return composeUpdateResult{}, fmt.Errorf("%w: a compose result has no recreate_exit", errComposeResult)
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
			if err := checkSnapshotEntry(e, standalone); err != nil {
				return composeUpdateResult{}, fmt.Errorf("%w: %w", errComposeResult, err)
			}
		}
	}
	service := func(s string) bool {
		if standalone {
			return s == ""
		}
		return snapServiceRe.MatchString(s)
	}
	for _, p := range r.Pulled {
		if !service(p.Service) || !snapImageIDRe.MatchString(p.ImageID) {
			return composeUpdateResult{}, fmt.Errorf("%w: pulled image", errComposeResult)
		}
	}
	for _, t := range r.Retained {
		if !service(t.Service) || !snapRetainedTagR.MatchString(t.Tag) {
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

// judgeComposeUpdate and judgeComposeRollback are in container_judges.go.

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
