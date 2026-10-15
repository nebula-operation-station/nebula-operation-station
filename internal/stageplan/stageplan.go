// SPDX-License-Identifier: AGPL-3.0-or-later

// Package stageplan is the stage plan of a rollout (spec 07): which hosts
// run in which stage, the failure thresholds of each stage and how the
// rollout continues past it. The plan is part of what is approved: its
// RFC 8785 SHA-256 is the request's stage_plan_hash, and the executor
// enforces it (internal/permit).
package stageplan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// Format is the plan document's "plan" member.
const Format = "stages-v1"

// Limits.
const (
	MaxStages  = 20
	MinTimeout = 60
	MaxTimeout = 24 * 60 * 60
)

// Continue modes: how the rollout goes on after a stage has passed.
const (
	ContinueManual = "manual"
	ContinueAuto   = "auto"
)

// Stage is one stage of a plan.
type Stage struct {
	Name           string   `json:"name"`
	Hosts          []string `json:"hosts"`
	MaxFailed      int      `json:"max_failed"`
	MaxUnreachable int      `json:"max_unreachable"`
	// Continue says how the next stage opens once this one has passed:
	// manual (a gate) or auto. It is ignored on the last stage.
	Continue string `json:"continue"`
	// TimeoutS is the planned duration of the stage; the permit's expiry
	// must cover the sum.
	TimeoutS int `json:"timeout_s"`
}

// Plan is a parsed, validated stage plan.
type Plan struct {
	Stages []Stage
	// Hash is the lowercase hex SHA-256 of the plan's canonical form.
	Hash string
}

// ErrInvalid wraps every validation failure.
var ErrInvalid = errors.New("stageplan: invalid plan")

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Parse reads a plan document and checks it against the request's hosts:
// every target is in exactly one stage and no stage names another host.
// Unknown members are refused, so that nothing in the approved bytes goes
// unenforced.
func Parse(raw []byte, targets []string) (Plan, error) {
	_, hash, err := canonical.CanonicalParameters(raw)
	if err != nil {
		return Plan{}, invalid("%v", err)
	}
	var doc struct {
		Plan   string  `json:"plan"`
		Stages []Stage `json:"stages"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return Plan{}, invalid("%v", err)
	}
	if doc.Plan != Format {
		return Plan{}, invalid("plan must be %q", Format)
	}
	// The plan must be exactly what it decodes to: no member in another
	// case, no member left out, nothing the executor would read differently
	// from the approved bytes.
	again, err := Encode(doc.Stages)
	if err != nil {
		return Plan{}, invalid("%v", err)
	}
	if _, h, err := canonical.CanonicalParameters(again); err != nil || h != hash {
		return Plan{}, invalid("the plan is not in its exact form (every member, lowercase names, nothing else)")
	}
	if len(doc.Stages) == 0 || len(doc.Stages) > MaxStages {
		return Plan{}, invalid("a plan has 1 to %d stages", MaxStages)
	}
	want := map[string]bool{}
	for _, t := range targets {
		want[t] = true
	}
	seen := map[string]bool{}
	names := map[string]bool{}
	for i, s := range doc.Stages {
		switch {
		case !nameRe.MatchString(s.Name):
			return Plan{}, invalid("stage %d: name must match %s", i+1, nameRe)
		case names[s.Name]:
			return Plan{}, invalid("stage %d: name %q used twice", i+1, s.Name)
		case len(s.Hosts) == 0:
			return Plan{}, invalid("stage %s has no hosts", s.Name)
		case s.MaxFailed < 0 || s.MaxFailed > len(s.Hosts):
			return Plan{}, invalid("stage %s: max_failed must be 0 to %d", s.Name, len(s.Hosts))
		case s.MaxUnreachable < 0 || s.MaxUnreachable > len(s.Hosts):
			return Plan{}, invalid("stage %s: max_unreachable must be 0 to %d", s.Name, len(s.Hosts))
		case s.Continue != ContinueManual && s.Continue != ContinueAuto:
			return Plan{}, invalid("stage %s: continue must be manual or auto", s.Name)
		case s.TimeoutS < MinTimeout || s.TimeoutS > MaxTimeout:
			return Plan{}, invalid("stage %s: timeout_s must be %d to %d", s.Name, MinTimeout, MaxTimeout)
		}
		names[s.Name] = true
		for _, h := range s.Hosts {
			switch {
			case !want[h]:
				return Plan{}, invalid("stage %s names %q, which is not a target", s.Name, h)
			case seen[h]:
				return Plan{}, invalid("host %q is in two stages", h)
			}
			seen[h] = true
		}
	}
	if len(seen) != len(want) {
		for _, t := range targets {
			if !seen[t] {
				return Plan{}, invalid("target %q is in no stage", t)
			}
		}
	}
	return Plan{Stages: doc.Stages, Hash: hash}, nil
}

// Duration is the planned duration of the whole plan in seconds.
func (p Plan) Duration() int {
	n := 0
	for _, s := range p.Stages {
		n += s.TimeoutS
	}
	return n
}

// AutoContinue reports whether any stage but the last continues
// automatically.
func (p Plan) AutoContinue() bool {
	for _, s := range p.Stages[:len(p.Stages)-1] {
		if s.Continue == ContinueAuto {
			return true
		}
	}
	return false
}

// Encode returns the plan document for stages (the server builds plans
// with it). The bytes hash to the same value as the canonical form.
func Encode(stages []Stage) ([]byte, error) {
	return json.Marshal(struct {
		Plan   string  `json:"plan"`
		Stages []Stage `json:"stages"`
	}{Format, stages})
}

// singleStage is the document of a request without stages: every host
// may run once the request is approved.
var singleStage = []byte(`{"plan":"single-stage-v1"}`)

// SingleStageHash is the stage_plan_hash of a request without stages.
var SingleStageHash = func() string {
	h, _ := canonical.HashParameters(singleStage) // constant, valid input
	return h
}()
