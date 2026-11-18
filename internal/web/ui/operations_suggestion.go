// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/opsnotes"
)

// maxSuggestionRefLen bounds the suggestion reference "<note ID>.<step>"
// read from a URL. Longer input is refused without a lookup.
const maxSuggestionRefLen = 32

// OperationSuggestionStore reads one stored step of an agent suggestion
// (ADR 0016 D8). It reads only; *opsnotes.Store implements it.
type OperationSuggestionStore interface {
	// Step returns step index of note noteID. ok is false for an unknown,
	// expired or dismissed step.
	Step(ctx context.Context, noteID int64, index int) (opsnotes.Step, bool, error)
}

// OperationSuggestions configures the operation form that an agent
// suggestion opens (GET /operations/new?suggestion=). Nil in Options
// answers every such request with 404.
type OperationSuggestions struct {
	// Store is the notes store. Required.
	Store OperationSuggestionStore
	// IsAdmin is the admin role check. Required; a failing check denies.
	IsAdmin func(ctx context.Context, user string) (bool, error)
}

// suggestionForm is the form an agent suggestion opens. Action and host
// come from the stored step only; the form carries no parameter.
type suggestionForm struct {
	// Ref is the reference "<note ID>.<step>" the form sends back.
	Ref      string
	ActionID string
	HostID   string
}

// suggestionNotFound is the fixed text of every refused suggestion page.
const suggestionNotFound = "unknown agent suggestion"

// parseSuggestionRef reads "<note ID>.<step>" strictly: decimal digits on
// both sides of one dot, a positive note ID, and a step without leading
// zeros. Anything else is not a reference.
func parseSuggestionRef(ref string) (noteID int64, index int, ok bool) {
	if ref == "" || len(ref) > maxSuggestionRefLen {
		return 0, 0, false
	}
	note, step, found := strings.Cut(ref, ".")
	if !found || !allDigits(note) || !allDigits(step) || (len(step) > 1 && step[0] == '0') {
		return 0, 0, false
	}
	id, err := strconv.ParseInt(note, 10, 64)
	if err != nil || id <= 0 {
		return 0, 0, false
	}
	idx, err := strconv.Atoi(step)
	if err != nil {
		return 0, 0, false
	}
	return id, idx, true
}

// allDigits reports whether s is a non-empty run of ASCII digits.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// suggestionPrefill resolves a suggestion reference for the request. found
// is false when the request must get the fixed 404: suggestions are not
// configured, the reference is malformed or unknown, or the user is not an
// admin. The reference is resolved here only; nothing is planned or
// approved. An error is a failed read and answers 500.
func (h *Handler) suggestionPrefill(r *http.Request, ref string) (form *suggestionForm, found bool, err error) {
	if h.opSuggest == nil {
		return nil, false, nil
	}
	noteID, index, ok := parseSuggestionRef(ref)
	if !ok {
		return nil, false, nil
	}
	ctx, cancel := context.WithTimeout(r.Context(), operationsCallTimeout)
	defer cancel()
	admin, err := h.opSuggest.IsAdmin(ctx, webUser(r))
	if err != nil {
		return nil, false, fmt.Errorf("suggestion admin check: %w", err)
	}
	if !admin {
		return nil, false, nil
	}
	step, ok, err := h.opSuggest.Store.Step(ctx, noteID, index)
	if err != nil {
		return nil, false, fmt.Errorf("suggestion step: %w", err)
	}
	if !ok {
		return nil, false, nil
	}
	return &suggestionForm{Ref: ref, ActionID: step.ActionID, HostID: step.HostID}, true, nil
}
