// SPDX-License-Identifier: AGPL-3.0-or-later

package opsnotes

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

// Kind is the kind of a note.
type Kind string

// The note kinds of ADR 0016 D7.
const (
	// KindFix is a fix suggestion for one finding group: steps and
	// mitigations.
	KindFix Kind = "fix"
	// KindSummary is a summary for one day. It carries text only.
	KindSummary Kind = "summary"
	// KindAnswer is an answer to one question. It carries text only.
	KindAnswer Kind = "answer"
)

// Valid reports whether k is one of the known kinds.
func (k Kind) Valid() bool {
	return k == KindFix || k == KindSummary || k == KindAnswer
}

// StepInput is one step as the model proposed it, after the agent mapped
// the candidate key back to an action and a host. It carries no parameters.
type StepInput struct {
	ActionID string `json:"action_id"`
	HostID   string `json:"host_id"`
	Why      string `json:"why,omitempty"`
}

// Body is the text content of a note. Which fields a note may carry depends
// on its kind; Validate enforces that.
type Body struct {
	// Summary is the summary of a fix note (at most MaxSummaryBytes).
	Summary string `json:"summary,omitempty"`
	// Text is the text of a summary or answer note (at most MaxTextBytes).
	Text string `json:"text,omitempty"`
	// Urgency is the urgency text of a fix note.
	Urgency string `json:"urgency,omitempty"`
	// Steps are the ordered steps of a fix note.
	Steps []StepInput `json:"steps,omitempty"`
	// Mitigations are text-only measures of a fix note.
	Mitigations []string `json:"mitigations,omitempty"`
	// Citations are chunk IDs of the documentation index.
	Citations []string `json:"citations,omitempty"`
}

// Draft is a note as it arrives from the agent, before validation. It has
// no field for the facts snapshot: the snapshot is the caller's, never the
// model's.
type Draft struct {
	Kind   Kind   `json:"kind"`
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
	Body
}

// Step is a validated step of a stored fix note. Index counts from 1 in the
// order of the note. Family is the catalog action family of ActionID.
type Step struct {
	NoteID   int64
	Index    int
	ActionID string
	HostID   string
	Family   string
	Why      string
}

// Candidate is one (action, host) pair the server computed for a ref at a
// given digest.
type Candidate struct {
	ActionID string
	HostID   string
}

// Resolver gives the server's view that a note is checked against. The
// store never reads the inventory or the catalog itself.
type Resolver interface {
	// CurrentDigest returns the current input digest of ref for the kind,
	// and false when the ref does not exist.
	CurrentDigest(kind Kind, ref string) (string, bool)
	// External reports whether the data behind ref is of data class
	// external (ADR 0016 D5).
	External(ref string) bool
	// Candidates returns the (action, host) pairs the server computed for
	// ref at digest. It is not trusted alone: checkSteps also enforces the
	// suggestion allowlist and the group host.
	Candidates(ref, digest string) []Candidate
	// GroupHost returns the managed host of the group ref, and false when
	// ref is not a fix group.
	GroupHost(ref string) (string, bool)
	// HostExists reports whether the managed host exists.
	HostExists(hostID string) bool
	// ActionFamily returns the family of a catalog action, and false when
	// the action is not in the catalog.
	ActionFamily(actionID string) (string, bool)
	// DocChunkExists reports whether the chunk is in the documentation
	// index.
	DocChunkExists(chunkID string) bool
}

// noteKeys lists the keys each object of a note may carry, by its path: ""
// is the note, "steps[]" one step. An object at any other path is refused.
// Keys match exactly; encoding/json would fold case and so is not trusted
// with the key set on its own.
var noteKeys = map[string]map[string]bool{
	"": {
		"kind": true, "ref": true, "digest": true, "summary": true, "text": true,
		"urgency": true, "steps": true, "mitigations": true, "citations": true,
	},
	"steps[]": {"action_id": true, "host_id": true, "why": true},
}

// Fixed error texts. They name no model-supplied field or value: a refused
// note's error may reach logs and HTTP responses.
var (
	errNoteSyntax    = fmt.Errorf("note: not well-formed JSON: %w", ErrDecode)
	errNoteNotObject = fmt.Errorf("note: not a JSON object: %w", ErrDecode)
	errNoteTrailing  = fmt.Errorf("note: trailing data after the object: %w", ErrDecode)
	errNoteKey       = fmt.Errorf("note: field not allowed at this position: %w", ErrDecode)
	errNoteDuplicate = fmt.Errorf("note: duplicate field: %w", ErrDecode)
	errNoteShape     = fmt.Errorf("note: value does not match the note schema: %w", ErrDecode)
)

// Decode parses one strict JSON note: at most MaxNoteBytes, valid UTF-8,
// exactly one object, exact-case keys from noteKeys, no duplicate keys, and
// no unknown fields at any depth. Its errors never echo the input.
func Decode(data []byte) (Draft, error) {
	if len(data) > MaxNoteBytes {
		return Draft{}, fmt.Errorf("note: %d bytes, max %d: %w", len(data), MaxNoteBytes, ErrLimit)
	}
	if !utf8.Valid(data) {
		return Draft{}, fmt.Errorf("note: not valid UTF-8: %w", ErrDecode)
	}
	if err := checkKeys(data); err != nil {
		return Draft{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var d Draft
	if err := dec.Decode(&d); err != nil {
		return Draft{}, errNoteShape
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Draft{}, errNoteTrailing
	}
	return d, nil
}

// checkKeys walks the tokens of one JSON object and refuses any key that is
// not in noteKeys for its position, any repeated key within one object, and
// any other shape at the top level. The walk does not use the decoded values.
func checkKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return errNoteSyntax
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return errNoteNotObject
	}
	if err := walkObject(dec, ""); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errNoteTrailing
	}
	return nil
}

// walkObject checks the members of an object whose '{' was just read. The
// closing '}' is consumed.
func walkObject(dec *json.Decoder, path string) error {
	keys, known := noteKeys[path]
	seen := make(map[string]bool)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return errNoteSyntax
		}
		key, ok := tok.(string)
		if !ok {
			return errNoteSyntax
		}
		if !known || !keys[key] {
			return errNoteKey
		}
		if seen[key] {
			return errNoteDuplicate
		}
		seen[key] = true
		if err := walkValue(dec, childPath(path, key)); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return errNoteSyntax
	}
	return nil
}

// walkValue checks one value at path: an object is checked against noteKeys,
// an array's items are checked at path+"[]", and a scalar is accepted.
func walkValue(dec *json.Decoder, path string) error {
	tok, err := dec.Token()
	if err != nil {
		return errNoteSyntax
	}
	delim, isDelim := tok.(json.Delim)
	switch {
	case isDelim && delim == '{':
		return walkObject(dec, path)
	case isDelim && delim == '[':
		for dec.More() {
			if err := walkValue(dec, path+"[]"); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return errNoteSyntax
		}
	}
	return nil
}

// childPath is the path of the member key of an object at path.
func childPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// Validate checks a draft against the bounds of ADR 0016 D6 and D7 and the
// server's view r. On success it returns the steps with their families,
// numbered from 1. The draft's text is not changed.
func Validate(d Draft, r Resolver) ([]Step, error) {
	if !d.Kind.Valid() {
		return nil, fmt.Errorf("kind %q: %w", d.Kind, ErrInvalidKind)
	}
	if err := checkToken("ref", d.Ref); err != nil {
		return nil, err
	}
	if err := checkToken("digest", d.Digest); err != nil {
		return nil, err
	}
	current, ok := r.CurrentDigest(d.Kind, d.Ref)
	if !ok {
		return nil, fmt.Errorf("ref %s: %w", d.Ref, ErrUnknownRef)
	}
	if d.Digest != current {
		return nil, fmt.Errorf("ref %s: %w", d.Ref, ErrStaleDigest)
	}
	if d.Kind == KindFix && r.External(d.Ref) {
		return nil, fmt.Errorf("ref %s: %w", d.Ref, ErrExternalData)
	}
	if err := checkShape(d); err != nil {
		return nil, err
	}
	for _, c := range d.Citations {
		if err := checkCitation("citation", c); err != nil {
			return nil, err
		}
		if !r.DocChunkExists(c) {
			return nil, fmt.Errorf("citation %s: %w", c, ErrUnknownCitation)
		}
	}
	return checkSteps(d, r)
}

// checkShape enforces which fields each kind carries and their bounds.
func checkShape(d Draft) error {
	if d.Kind != KindFix {
		switch {
		case d.Summary != "":
			return fmt.Errorf("summary: %w", ErrFieldNotAllowed)
		case d.Urgency != "":
			return fmt.Errorf("urgency: %w", ErrFieldNotAllowed)
		case len(d.Steps) > 0:
			return fmt.Errorf("steps: %w", ErrFieldNotAllowed)
		case len(d.Mitigations) > 0:
			return fmt.Errorf("mitigations: %w", ErrFieldNotAllowed)
		case d.Text == "":
			return fmt.Errorf("text: %w", ErrMissing)
		}
		if err := checkFreeText("text", d.Text, MaxTextBytes); err != nil {
			return err
		}
		return checkCitationCount(d)
	}
	if d.Text != "" {
		return fmt.Errorf("text: %w", ErrFieldNotAllowed)
	}
	if d.Summary == "" {
		return fmt.Errorf("summary: %w", ErrMissing)
	}
	if err := checkFreeText("summary", d.Summary, MaxSummaryBytes); err != nil {
		return err
	}
	if err := checkFreeText("urgency", d.Urgency, MaxUrgencyBytes); err != nil {
		return err
	}
	if len(d.Steps) == 0 && len(d.Mitigations) == 0 {
		return fmt.Errorf("steps or mitigations: %w", ErrMissing)
	}
	if len(d.Steps) > MaxStepsPerNote {
		return fmt.Errorf("steps: %d, max %d: %w", len(d.Steps), MaxStepsPerNote, ErrLimit)
	}
	if len(d.Mitigations) > MaxMitigations {
		return fmt.Errorf("mitigations: %d, max %d: %w", len(d.Mitigations), MaxMitigations, ErrLimit)
	}
	for _, m := range d.Mitigations {
		if m == "" {
			return fmt.Errorf("mitigation: %w", ErrMissing)
		}
		if err := checkFreeText("mitigation", m, MaxMitigationBytes); err != nil {
			return err
		}
	}
	return checkCitationCount(d)
}

func checkCitationCount(d Draft) error {
	if len(d.Citations) > MaxCitations {
		return fmt.Errorf("citations: %d, max %d: %w", len(d.Citations), MaxCitations, ErrLimit)
	}
	return nil
}

// suggestionAllowlist is the fixed table of actions a fix note may suggest
// (ADR 0016, suggestion allowlist), with the family of each action. A step
// outside it is refused whatever the candidates say.
var suggestionAllowlist = map[string]string{
	"package.install_security": "os-update",
	"package.install_all":      "os-update",
	"system.reboot":            "reboot",
	"service.restart":          "service-restart",
	"docker.compose_update":    "container-update",
	"docker.update":            "container-update",
	"docker.restart":           "container-restart",
}

// checkSteps checks each step against the catalog, the suggestion allowlist,
// the group's host, the hosts and the candidates of the current digest.
func checkSteps(d Draft, r Resolver) ([]Step, error) {
	if len(d.Steps) == 0 {
		return nil, nil
	}
	groupHost, ok := r.GroupHost(d.Ref)
	if !ok {
		return nil, fmt.Errorf("ref %s: %w", d.Ref, ErrNotGroupHost)
	}
	candidates := r.Candidates(d.Ref, d.Digest)
	seen := make(map[Candidate]bool, len(d.Steps))
	out := make([]Step, 0, len(d.Steps))
	for i, s := range d.Steps {
		if err := checkToken("action_id", s.ActionID); err != nil {
			return nil, err
		}
		if err := checkToken("host_id", s.HostID); err != nil {
			return nil, err
		}
		if err := checkFreeText("why", s.Why, MaxStepWhyBytes); err != nil {
			return nil, err
		}
		family, ok := r.ActionFamily(s.ActionID)
		if !ok {
			return nil, fmt.Errorf("step %d action %s: %w", i+1, s.ActionID, ErrUnknownAction)
		}
		allowed, ok := suggestionAllowlist[s.ActionID]
		if !ok || allowed != family {
			return nil, fmt.Errorf("step %d action %s: %w", i+1, s.ActionID, ErrNotAllowlisted)
		}
		if !r.HostExists(s.HostID) {
			return nil, fmt.Errorf("step %d host %s: %w", i+1, s.HostID, ErrUnknownHost)
		}
		if s.HostID != groupHost {
			return nil, fmt.Errorf("step %d host %s, group host %s: %w", i+1, s.HostID, groupHost, ErrNotGroupHost)
		}
		c := Candidate{ActionID: s.ActionID, HostID: s.HostID}
		if !contains(candidates, c) {
			return nil, fmt.Errorf("step %d (%s on %s): %w", i+1, s.ActionID, s.HostID, ErrNotCandidate)
		}
		if seen[c] {
			return nil, fmt.Errorf("step %d (%s on %s): %w", i+1, s.ActionID, s.HostID, ErrDuplicateStep)
		}
		seen[c] = true
		out = append(out, Step{Index: i + 1, ActionID: s.ActionID, HostID: s.HostID, Family: family, Why: s.Why})
	}
	return out, nil
}

func contains(cs []Candidate, c Candidate) bool {
	for _, x := range cs {
		if x == c {
			return true
		}
	}
	return false
}
