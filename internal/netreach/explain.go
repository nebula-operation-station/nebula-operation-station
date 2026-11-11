// SPDX-License-Identifier: AGPL-3.0-or-later

package netreach

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
)

// StepKind names the kind of one step of an explanation chain.
type StepKind string

// Step kinds, in the order evaluation produces them (ADR 0012 D2
// "Explanation chain").
const (
	StepInput       StepKind = "input"
	StepPlacement   StepKind = "placement"
	StepCrossing    StepKind = "crossing"
	StepNetBird     StepKind = "netbird"
	StepPath        StepKind = "path"
	StepNAT         StepKind = "nat"
	StepReverseNAT  StepKind = "reverse-nat"
	StepRule        StepKind = "rule"
	StepDefaultRule StepKind = "default-rule"
	StepVerdict     StepKind = "verdict"
)

// Step outcomes. They are stable texts; callers may show them and tests
// compare them.
const (
	OutcomeSkippedDisabled = "skipped (disabled)"
	OutcomeNoMatch         = "no match"
	OutcomeMatch           = "match"
	OutcomeConditional     = "conditional match"
	OutcomeUnevaluable     = "unevaluable"
	OutcomeTried           = "tried"
	OutcomeUnknown         = "unknown"
	OutcomePlaced          = "placed"
	OutcomeNotFiltered     = "not filtered"
)

// Step is one step of an explanation chain. Path names the evaluated path
// ("direct", "via NAT rule <name>", "reverse NAT rule <name>", "routing
// peer <name>"); Name is the rule, NAT rule or address the step is about.
// Every text may contain device text and is sanitized; render it as text
// only.
type Step struct {
	Path    string
	Kind    StepKind
	Name    string
	Outcome string
	Detail  string
}

// String renders the step as one line of text.
func (s Step) String() string {
	var b strings.Builder
	if s.Path != "" {
		b.WriteString("[" + s.Path + "] ")
	}
	b.WriteString(string(s.Kind))
	if s.Name != "" {
		b.WriteString(" " + s.Name)
	}
	b.WriteString(": " + s.Outcome)
	if s.Detail != "" {
		b.WriteString(" (" + s.Detail + ")")
	}
	return b.String()
}

// Result is the verdict of one query with its reason and explanation
// chain, the model version and the snapshot hash (ADR 0012 D2).
type Result struct {
	Verdict      Verdict
	Reason       string
	Chain        []Step
	ModelVersion string
	SnapshotHash string
}

// Text renders the result as plain text: the verdict line, then one line
// per chain step.
func (r Result) Text() string {
	var b strings.Builder
	b.WriteString(string(r.Verdict))
	if r.Reason != "" {
		b.WriteString(": " + r.Reason)
	}
	b.WriteString("\nmodel " + r.ModelVersion + ", snapshot " + r.SnapshotHash + "\n")
	for _, s := range r.Chain {
		b.WriteString(s.String())
		b.WriteByte('\n')
	}
	return b.String()
}

// SnapshotHash returns the snapshot hash of ADR 0012 D2: SHA-256 over a
// canonical, length-prefixed encoding of the model version and, for every
// required input in RequiredInputs order, its kind, dataset ID and
// redacted digest. The raw digest is not part of a Snapshot and never
// enters the hash. Same inputs and model version give the same hash.
func SnapshotHash(s *Snapshot) string {
	h := sha256.New()
	write := func(v string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(v)))
		h.Write(n[:])
		h.Write([]byte(v))
	}
	write(ModelVersion)
	for _, k := range RequiredInputs {
		var in Input
		if s != nil {
			in = s.Inputs[k]
		}
		write(string(k))
		write(in.DatasetID)
		write(in.RedactedDigest)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// chain records the steps of one evaluation up to a step limit. When the
// limit is reached further steps are dropped and full is set; the caller
// then turns the verdict into unknown "limit reached".
type chain struct {
	steps []Step
	max   int
	full  bool
}

func (c *chain) add(s Step) {
	if len(c.steps) >= c.max {
		c.full = true
		return
	}
	c.steps = append(c.steps, sanitizeStep(s))
}

// final appends the verdict step even when the chain is full, so every
// chain ends with its verdict.
func (c *chain) final(s Step) {
	c.steps = append(c.steps, sanitizeStep(s))
}

func sanitizeStep(s Step) Step {
	s.Path = sanitizeText(s.Path)
	s.Name = sanitizeText(s.Name)
	s.Outcome = sanitizeText(s.Outcome)
	s.Detail = sanitizeText(s.Detail)
	return s
}
