// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// compose-update-v2 is the result of docker.compose_update 2.0.0 (container
// update plan cu02): a baseline and an after-snapshot of structured
// container entries. This parser serves the operations view only. The
// verdict that decides a rollout is the executor's own (cu03), computed
// against the frozen binding; the display verdict here compares the two
// snapshots without the binding and never replaces it.

const (
	// maxComposeV2Bytes bounds a compose-update-v2 result (hostrun.MaxResult).
	maxComposeV2Bytes = 1 << 20
	// maxComposeV2Containers bounds each snapshot of a compose-update-v2
	// result; a longer list is not a result of the script.
	maxComposeV2Containers = 200
)

var (
	composeV2ReasonRe  = regexp.MustCompile(`^[a-z][a-z_]{0,39}$`)
	composeV2ReplicaRe = regexp.MustCompile(`^[0-9]{1,8}$`)
	composeV2Stops     = map[string]bool{"precheck": true, "resolve": true, "pull": true, "retain": true}
	composeV2Health    = map[string]string{"none": "", "healthy": "healthy", "unhealthy": "unhealthy", "starting": "starting"}
)

type composeV2Mount struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Mode        string `json:"mode"`
	RW          bool   `json:"rw"`
}

type composeV2Entry struct {
	ID                  string           `json:"id"`
	Name                string           `json:"name"`
	Service             string           `json:"service"`
	Replica             string           `json:"replica"`
	State               string           `json:"state"`
	StartedAt           string           `json:"started_at"`
	Health              string           `json:"health"`
	Ports               []string         `json:"ports"`
	Mounts              []composeV2Mount `json:"mounts"`
	Networks            []string         `json:"networks"`
	ImageID             string           `json:"image_id"`
	RunningReference    string           `json:"running_reference"`
	ConfigurationDigest string           `json:"configuration_digest"`
	Oversize            bool             `json:"oversize"`
}

type composeV2Doc struct {
	Format   string            `json:"format"`
	Phase    string            `json:"phase"`
	Reason   string            `json:"reason"`
	Service  string            `json:"service"`
	Project  string            `json:"project"`
	UpExit   *int              `json:"up_exit"`
	Baseline *[]composeV2Entry `json:"baseline"`
	After    *[]composeV2Entry `json:"after"`
	Pulled   json.RawMessage   `json:"pulled"`
	Retained json.RawMessage   `json:"retained"`
	// AfterTruncated marks an after-snapshot the script cut at its total
	// bound: the list is incomplete.
	AfterTruncated bool `json:"after_truncated"`
}

// composeV2Key is the replica identity across a recreate: IDs change.
func composeV2Key(e composeV2Entry) string { return e.Service + "/" + e.Replica }

// displayEntry turns a snapshot entry into a display row; ok is false for
// an entry the parser does not show (oversize, malformed).
func displayEntry(e composeV2Entry) (ComposeContainer, bool) {
	if e.Oversize || !nameRe.MatchString(e.Name) || !states[e.State] {
		return ComposeContainer{}, false
	}
	h, ok := composeV2Health[e.Health]
	if !ok {
		return ComposeContainer{}, false
	}
	c := ComposeContainer{Name: e.Name, State: e.State, Health: h}
	if composeServiceRe.MatchString(e.Service) {
		c.Service = e.Service
	}
	if h != "" {
		c.Status = "health: " + h
	}
	var ports []string
	for _, p := range e.Ports {
		if printable(p, 120) {
			ports = append(ports, p)
		}
	}
	c.Ports = text(strings.Join(ports, ", "), 1000)
	c.Image = text(e.RunningReference, 300)
	return c, true
}

// parseComposeUpdateV2 reads a compose-update-v2 result for display.
func parseComposeUpdateV2(result []byte) (ComposeUpdate, error) {
	if len(result) > maxComposeV2Bytes || !utf8.Valid(result) {
		return ComposeUpdate{}, ErrComposeFormat
	}
	var doc composeV2Doc
	dec := json.NewDecoder(bytes.NewReader(result))
	if err := dec.Decode(&doc); err != nil || doc.Format != "compose-update-v2" {
		return ComposeUpdate{}, ErrComposeFormat
	}
	if dec.More() {
		return ComposeUpdate{}, ErrComposeFormat
	}
	c := ComposeUpdate{Format: doc.Format}
	if projectRe.MatchString(doc.Project) {
		c.Project = doc.Project
	}
	reason := ""
	if composeV2ReasonRe.MatchString(doc.Reason) {
		reason = doc.Reason
	} else if doc.Reason != "" {
		reason = "unreadable reason"
	}
	if composeV2Stops[doc.Phase] {
		// Stopped before any recreate (phases 1 to 4): the view shows it as
		// a precheck stop, with the phase named in the reason.
		if reason == "" {
			reason = "no reason given"
		}
		c.Phase, c.Reason, c.Verdict = "precheck", doc.Phase+": "+reason, "FAILED"
		if composeServiceRe.MatchString(doc.Service) {
			c.Reason += " (service " + doc.Service + ")"
		}
		return c, nil
	}
	if doc.Phase != "recreate" && doc.Phase != "after_snapshot" {
		return ComposeUpdate{}, ErrComposeFormat
	}
	c.Phase, c.Reason = doc.Phase, reason
	if doc.UpExit != nil {
		c.UpExit = *doc.UpExit
	} else {
		c.UpExit = -1
	}
	var before, after []composeV2Entry
	if doc.Baseline != nil {
		before = *doc.Baseline
	}
	if doc.After != nil {
		after = *doc.After
	}
	if len(before) > maxComposeV2Containers || len(after) > maxComposeV2Containers {
		return ComposeUpdate{}, ErrComposeFormat
	}
	for _, e := range before {
		if x, ok := displayEntry(e); ok {
			c.Before = append(c.Before, x)
		}
	}
	for _, e := range after {
		if x, ok := displayEntry(e); ok {
			c.After = append(c.After, x)
		}
	}
	c.judgeV2(before, after, doc.Baseline != nil, doc.After != nil, doc.AfterTruncated)
	return c, nil
}

// judgeV2 sets the display verdict of a compose-update-v2 result that
// reached the recreate: FAILED unless up succeeded, the after-snapshot
// exists and is complete, and every replica of the baseline is running
// again with no health regression and the same ports, mounts and
// networks. Unknown is not success.
func (c *ComposeUpdate) judgeV2(before, after []composeV2Entry, haveBefore, haveAfter, afterTruncated bool) {
	failed := func(f string, a ...any) { c.Findings = append(c.Findings, "FAILED: "+fmt.Sprintf(f, a...)) }
	if afterTruncated {
		failed("the after-snapshot was truncated; the recreation cannot be judged in full")
	}
	if c.UpExit != 0 {
		failed("docker compose up -d exited with %d", c.UpExit)
	}
	if c.Reason != "" {
		failed("the update reported %s", c.Reason)
	}
	switch {
	case !haveBefore || len(before) == 0:
		failed("no baseline snapshot; the result cannot be judged")
	case !haveAfter:
		failed("no after-snapshot; the recreation is uncertain")
	default:
		afterBy := map[string]composeV2Entry{}
		for _, e := range after {
			if e.Oversize {
				failed("an after-snapshot entry is too large to judge")
				continue
			}
			afterBy[composeV2Key(e)] = e
		}
		var problems []string
		for _, b := range before {
			if b.Oversize || !composeServiceRe.MatchString(b.Service) || !composeV2ReplicaRe.MatchString(b.Replica) {
				problems = append(problems, "a baseline entry cannot be judged")
				continue
			}
			k := composeV2Key(b)
			a, ok := afterBy[k]
			switch {
			case !ok:
				problems = append(problems, fmt.Sprintf("%s replica %s is missing after the update", b.Service, b.Replica))
				continue
			case b.State == "running" && a.State != "running":
				problems = append(problems, fmt.Sprintf("%s replica %s ran before and is %s now", b.Service, b.Replica, text(a.State, 16)))
			}
			if (b.Health == "healthy" || b.Health == "starting") && a.Health != "healthy" {
				problems = append(problems, fmt.Sprintf("%s replica %s was %s before and is %s now", b.Service, b.Replica, b.Health, text(a.Health, 16)))
			}
			if b.Health == "none" && a.Health != "none" {
				problems = append(problems, fmt.Sprintf("%s replica %s had no health check and has one now", b.Service, b.Replica))
			}
			if !equalStrings(b.Ports, a.Ports) {
				problems = append(problems, fmt.Sprintf("%s replica %s: published ports changed", b.Service, b.Replica))
			}
			if !equalMounts(b.Mounts, a.Mounts) {
				problems = append(problems, fmt.Sprintf("%s replica %s: mounts changed", b.Service, b.Replica))
			}
			if !equalStrings(b.Networks, a.Networks) {
				problems = append(problems, fmt.Sprintf("%s replica %s: networks changed", b.Service, b.Replica))
			}
		}
		sort.Strings(problems)
		for _, p := range problems {
			failed("%s", p)
		}
		if len(after) > len(before) {
			failed("%d containers before, %d after", len(before), len(after))
		}
	}
	c.Verdict = "OK"
	if len(c.Findings) > 0 {
		c.Verdict = "FAILED"
	}
	c.Findings = append(c.Findings, "The executor's own verdict against the approved binding decides the rollout.")
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func equalMounts(a, b []composeV2Mount) bool {
	if len(a) != len(b) {
		return false
	}
	key := func(m composeV2Mount) string {
		return m.Type + "\x00" + m.Source + "\x00" + m.Destination + "\x00" + m.Mode + "\x00" + fmt.Sprint(m.RW)
	}
	x, y := make([]string, len(a)), make([]string, len(b))
	for i := range a {
		x[i], y[i] = key(a[i]), key(b[i])
	}
	return equalStrings(x, y)
}
