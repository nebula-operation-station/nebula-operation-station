// SPDX-License-Identifier: AGPL-3.0-or-later

// Maintainer decisions on findings (ADR 0011 D5, D6; Q4 decided
// 2026-11-09): accept risk, mark a false positive, confirm or discard a
// held closure, reset a feed's high-water mark. Only the maintainer
// (admin) may submit one, and every submission needs a fresh WebAuthn
// assertion:
//
//  1. POST /vulnerabilities/decide/begin (JSON): the UI checks the
//     maintainer and the input rules, the backend returns a single-use
//     challenge bound to the user and the decision digest; the UI keeps the
//     decision under the challenge ID for the user for a short time.
//  2. POST /vulnerabilities/decide/commit (JSON): the UI re-checks the
//     maintainer, takes the pending decision out (single use, same user)
//     and passes it with the assertion to the backend, which verifies the
//     assertion, applies the decision and audits it.
//
// Both are JSON POSTs: the security middleware rejects a foreign or
// missing Origin (the CSRF defence of every state change here), and a
// cross-site form cannot send application/json.
package ui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnfinding"
	"github.com/nebula-operation-station/nebula-operation-station/internal/vulnstore"
)

// Limits of the decision endpoints.
const (
	// maxVulnDecisionBody bounds a decision request body.
	maxVulnDecisionBody = 16 << 10
	// vulnPendingTTL is how long a begun decision waits for its assertion.
	vulnPendingTTL = 5 * time.Minute
	// maxVulnPending bounds the pending decisions kept in memory.
	maxVulnPending = 64
)

// VulnDecisionKind names a maintainer decision.
type VulnDecisionKind string

// Decision kinds.
const (
	VulnAcceptRisk    VulnDecisionKind = "accept_risk"
	VulnFalsePositive VulnDecisionKind = "false_positive"
	VulnConfirmHold   VulnDecisionKind = "confirm_hold"
	VulnDiscardHold   VulnDecisionKind = "discard_hold"
	VulnMarkReset     VulnDecisionKind = "mark_reset"
)

// VulnDecision is a validated maintainer decision. The backend derives
// the version basis (D6) and, for a mark reset, the reset value from its
// own state; neither comes from the browser.
type VulnDecision struct {
	Kind VulnDecisionKind `json:"kind"`
	// Key is the finding (all kinds but mark_reset).
	Key vulnfinding.Key `json:"-"`
	// Approver (accept_risk) is required.
	Approver string `json:"approver,omitempty"`
	// Reason is required for every kind but discard_hold.
	Reason string `json:"reason,omitempty"`
	// Expires (accept_risk) is required, in the future and at most
	// vulnstore.MaxAcceptExpiry ahead.
	Expires time.Time `json:"expires,omitzero"`
	// Category (false_positive) is one of the D6 categories.
	Category string `json:"category,omitempty"`
	// RunID names the held closure (confirm_hold, discard_hold) or the
	// regressed run whose reported value a mark reset takes (mark_reset).
	RunID string `json:"run_id,omitempty"`
	// SourceID (mark_reset) is the listed feed source.
	SourceID string `json:"source_id,omitempty"`
}

// Digest is the SHA-256 the challenge is bound to: kind, key and every
// field, in a fixed JSON encoding.
func (d VulnDecision) Digest() string {
	b, _ := json.Marshal(struct {
		VulnDecision
		Key string `json:"key"`
	}{d, hex.EncodeToString(d.Key[:])})
	sum := sha256.Sum256(append([]byte("nos-vuln-decision-v1\x00"), b...))
	return hex.EncodeToString(sum[:])
}

// vulnCategories are the D6 false-positive categories.
var vulnCategories = []string{
	vulnstore.CategoryBackportFixed,
	vulnstore.CategoryNotAffectedConfig,
	vulnstore.CategoryComponentNotUsed,
	vulnstore.CategoryVendorDisputed,
	vulnstore.CategoryOther,
}

// vulnActorRe is vulnstore's actor pattern (approver names).
var vulnActorRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._:-]{0,127}$`)

// vulnRunIDRe bounds run IDs as they come back from the browser.
var vulnRunIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// vulnChallengeIDRe bounds challenge IDs.
var vulnChallengeIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

// vulnDecisionInput is the begin request body.
type vulnDecisionInput struct {
	Kind     string `json:"kind"`
	Key      string `json:"key"`
	Approver string `json:"approver"`
	Reason   string `json:"reason"`
	Expires  string `json:"expires"`
	Category string `json:"category"`
	RunID    string `json:"run_id"`
	SourceID string `json:"source_id"`
}

// vulnInputError is a rejection message for the maintainer.
type vulnInputError string

func (e vulnInputError) Error() string { return string(e) }

// checkVulnReason applies the D5/D6 reason rule: required, at most 1 KiB
// of valid UTF-8, no control characters but newline and tab.
func checkVulnReason(s string) error {
	switch {
	case s == "":
		return vulnInputError("a reason is required")
	case len(s) > vulnstore.MaxHumanReason:
		return vulnInputError("the reason is longer than 1 KiB")
	case !utf8.ValidString(s):
		return vulnInputError("the reason is not valid UTF-8")
	}
	for _, r := range s {
		if r == utf8.RuneError || (r < 0x20 && r != '\n' && r != '\t' && r != '\r') || r == 0x7f {
			return vulnInputError("the reason contains control characters")
		}
	}
	return nil
}

// validateVulnDecision turns the begin input into a decision or a
// rejection message.
func validateVulnDecision(in vulnDecisionInput, now time.Time) (VulnDecision, error) {
	d := VulnDecision{Kind: VulnDecisionKind(in.Kind)}
	needKey := true
	switch d.Kind {
	case VulnAcceptRisk:
		if in.Approver == "" {
			return d, vulnInputError("an approver is required")
		}
		if !vulnActorRe.MatchString(in.Approver) {
			return d, vulnInputError("the approver must be 1 to 128 letters, digits or @._:-")
		}
		d.Approver = in.Approver
		if in.Expires == "" {
			return d, vulnInputError("an expiry date is required")
		}
		day, err := time.Parse(vulnDateLayout, in.Expires)
		if err != nil {
			return d, vulnInputError("the expiry must be a date (YYYY-MM-DD)")
		}
		if !day.After(now) {
			return d, vulnInputError("the expiry must be in the future")
		}
		if day.Sub(now) > vulnstore.MaxAcceptExpiry {
			return d, vulnInputError("an expiry more than 365 days ahead is refused")
		}
		d.Expires = day.UTC()
	case VulnFalsePositive:
		ok := false
		for _, c := range vulnCategories {
			ok = ok || c == in.Category
		}
		if !ok {
			return d, vulnInputError("choose a false-positive category")
		}
		d.Category = in.Category
	case VulnConfirmHold, VulnDiscardHold:
		if !vulnRunIDRe.MatchString(in.RunID) {
			return d, vulnInputError("the held closure's run is missing")
		}
		d.RunID = in.RunID
	case VulnMarkReset:
		needKey = false
		if !vulnSourceIDRe.MatchString(in.SourceID) {
			return d, vulnInputError("the feed source is missing")
		}
		if !vulnRunIDRe.MatchString(in.RunID) {
			return d, vulnInputError("there is no regressed run to reset to")
		}
		d.SourceID, d.RunID = in.SourceID, in.RunID
	default:
		return d, vulnInputError("unknown decision")
	}
	if needKey {
		k, ok := parseVulnKey(in.Key)
		if !ok {
			return d, vulnInputError("the finding is missing")
		}
		d.Key = k
	} else if in.Key != "" {
		return d, vulnInputError("a mark reset names no finding")
	}
	if d.Kind != VulnDiscardHold {
		if err := checkVulnReason(in.Reason); err != nil {
			return d, err
		}
		d.Reason = in.Reason
	} else if in.Reason != "" {
		if err := checkVulnReason(in.Reason); err != nil {
			return d, err
		}
		d.Reason = in.Reason
	}
	return d, nil
}

// readVulnJSON reads a bounded JSON body that must be valid UTF-8 as a
// whole (encoding/json would silently replace invalid bytes) and decodes
// it with unknown fields rejected.
func readVulnJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Header.Get("Content-Type") != "application/json" {
		writeJSONError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxVulnDecisionBody))
	if err != nil {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return false
	}
	if !utf8.Valid(body) {
		writeJSONError(w, http.StatusBadRequest, "the request is not valid UTF-8")
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeJSONError(w, http.StatusBadRequest, "request body is not valid JSON")
		return false
	}
	return true
}

// vulnPending is a begun decision awaiting its assertion.
type vulnPending struct {
	user     string
	decision VulnDecision
	expires  time.Time
}

// vulnPendingTable keeps begun decisions by challenge ID.
type vulnPendingTable struct {
	mu sync.Mutex
	m  map[string]vulnPending
}

func newVulnPendingTable() *vulnPendingTable {
	return &vulnPendingTable{m: map[string]vulnPending{}}
}

// put stores a pending decision; false when the table is full of live
// entries.
func (t *vulnPendingTable) put(id string, p vulnPending, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, v := range t.m {
		if !now.Before(v.expires) {
			delete(t.m, k)
		}
	}
	if len(t.m) >= maxVulnPending {
		return false
	}
	t.m[id] = p
	return true
}

// take removes and returns the pending decision of user under id.
func (t *vulnPendingTable) take(id, user string, now time.Time) (VulnDecision, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.m[id]
	if !ok || p.user != user {
		return VulnDecision{}, false
	}
	delete(t.m, id)
	if !now.Before(p.expires) {
		return VulnDecision{}, false
	}
	return p.decision, true
}

// handleVulnDecideBegin serves POST /vulnerabilities/decide/begin.
func (h *Handler) handleVulnDecideBegin(w http.ResponseWriter, r *http.Request) {
	if !h.vulnEnabled(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), vulnCallTimeout)
	defer cancel()
	if !h.vulnMaintainer(ctx, r) {
		writeJSONError(w, http.StatusForbidden, "only the maintainer can change a finding's state")
		return
	}
	var in vulnDecisionInput
	if !readVulnJSON(w, r, &in) {
		return
	}
	now := h.clockNow()
	d, err := validateVulnDecision(in, now)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	user := webUser(r)
	ch, err := h.vuln.BeginVulnDecision(ctx, user, d)
	if err != nil {
		h.vulnDecisionError(w, "begin", err)
		return
	}
	if !vulnChallengeIDRe.MatchString(ch.ID) || !json.Valid(ch.Options) {
		h.log.Error("vulnerabilities: begin decision", "error", "backend returned a malformed challenge")
		writeJSONError(w, http.StatusBadGateway, "security key challenge unavailable")
		return
	}
	if !h.vulnPending.put(ch.ID, vulnPending{user: user, decision: d, expires: now.Add(vulnPendingTTL)}, now) {
		writeJSONError(w, http.StatusTooManyRequests, "too many decisions in progress; try again in a few minutes")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": ch.ID, "options": json.RawMessage(ch.Options)})
}

// handleVulnDecideCommit serves POST /vulnerabilities/decide/commit.
func (h *Handler) handleVulnDecideCommit(w http.ResponseWriter, r *http.Request) {
	if !h.vulnEnabled(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), vulnCallTimeout)
	defer cancel()
	if !h.vulnMaintainer(ctx, r) {
		writeJSONError(w, http.StatusForbidden, "only the maintainer can change a finding's state")
		return
	}
	var in struct {
		ID        string          `json:"id"`
		Assertion json.RawMessage `json:"assertion"`
	}
	if !readVulnJSON(w, r, &in) {
		return
	}
	if len(in.Assertion) == 0 || string(in.Assertion) == "null" {
		writeJSONError(w, http.StatusForbidden, "a fresh security key assertion is required")
		return
	}
	user := webUser(r)
	if !vulnChallengeIDRe.MatchString(in.ID) {
		writeJSONError(w, http.StatusNotFound, "decision not found or expired; start again")
		return
	}
	d, ok := h.vulnPending.take(in.ID, user, h.clockNow())
	if !ok {
		writeJSONError(w, http.StatusNotFound, "decision not found or expired; start again")
		return
	}
	if err := h.vuln.CommitVulnDecision(ctx, user, in.ID, d, in.Assertion); err != nil {
		h.vulnDecisionError(w, "commit", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"done": true})
}

// vulnDecisionError maps a backend error to a fixed message.
func (h *Handler) vulnDecisionError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, ErrVulnAssertionRefused):
		writeJSONError(w, http.StatusForbidden, "the security key assertion was refused")
	case errors.Is(err, vulnstore.ErrInvalidInput):
		writeJSONError(w, http.StatusBadRequest, "the decision was rejected: an input is out of bounds")
	case errors.Is(err, vulnstore.ErrFindingNotFound), errors.Is(err, vulnstore.ErrHoldNotFound):
		writeJSONError(w, http.StatusNotFound, "the finding or held closure no longer exists")
	case errors.Is(err, vulnstore.ErrWrongState):
		writeJSONError(w, http.StatusConflict, "the finding is no longer in a state this decision applies to")
	case errors.Is(err, vulnstore.ErrHoldSuperseded):
		writeJSONError(w, http.StatusConflict, "the held closure was superseded by a newer run and dropped")
	case errors.Is(err, vulnstore.ErrContradicted):
		writeJSONError(w, http.StatusConflict, "NOS inventory contradicts the closure; it cannot become fixed")
	case errors.Is(err, vulnstore.ErrResetRefused):
		writeJSONError(w, http.StatusConflict, "the mark reset was refused: only the value the latest regressed run reported can be taken")
	default:
		h.log.Error("vulnerabilities: "+op+" decision", "error", err)
		writeJSONError(w, http.StatusBadGateway, "the decision could not be applied")
	}
}
