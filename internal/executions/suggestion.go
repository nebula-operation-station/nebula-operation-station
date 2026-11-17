// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"errors"
	"strings"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// ErrUnknownSuggestion refuses an execution whose suggestion reference does
// not name a stored suggestion step (malformed, unknown or deleted). The
// server never falls back to an unmarked execution (ADR 0016 D9).
var ErrUnknownSuggestion = errors.New("unknown agent suggestion")

// Origin prefixes recorded in executions.origin (spec 07 v28-07-01).
const (
	originSuggestion      = "suggestion:"
	originSuggestionMatch = "suggestion-match:"
)

// MaxSuggestionRefLen bounds a suggestion reference (a note ID, a dot and a
// step number). Longer input is malformed and refused.
const MaxSuggestionRefLen = 128

// SuggestionIndex resolves agent suggestions from the notes store. The
// implementation lives with the ops notes; executions only reads it. A nil
// index means there are no suggestions: every execution is planned as before.
type SuggestionIndex interface {
	// Step resolves a suggestion reference "<note ID>.<step>" to the action,
	// its family and the host of that step. ok is false for an unknown,
	// expired or deleted reference.
	Step(ref string) (action, family, hostID string, ok bool)
	// Match returns the ID of a stored fix note that holds a step of family
	// on hostID, if any.
	Match(family, hostID string) (noteID string, ok bool)
	// Family returns the action family of an action ID.
	Family(actionID string) (family string, ok bool)
}

// suggestionRefValid reports whether ref has the shape "<note ID>.<step>":
// bounded, printable, without spaces, with a dot before the step number.
func suggestionRefValid(ref string) bool {
	if ref == "" || len(ref) > MaxSuggestionRefLen {
		return false
	}
	i := strings.LastIndexByte(ref, '.')
	if i <= 0 || i == len(ref)-1 {
		return false
	}
	for _, c := range []byte(ref) {
		ok := c == '.' || c == '-' || c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !ok {
			return false
		}
	}
	return true
}

// referenceOrigin returns the origin of a request that carries a suggestion
// reference. A reference that is malformed or unknown is refused; a valid
// one always marks the execution, whatever action or targets the human
// chose in the form.
func referenceOrigin(idx SuggestionIndex, ref string) (string, error) {
	if !suggestionRefValid(ref) || idx == nil {
		return "", ErrUnknownSuggestion
	}
	if _, _, _, ok := idx.Step(ref); !ok {
		return "", ErrUnknownSuggestion
	}
	return originSuggestion + ref, nil
}

// matchOrigin returns the origin attributed to an action on hosts without a
// reference: the first host that a stored fix note covers with the same
// action family. The match never lowers anything; it only raises the class.
func matchOrigin(idx SuggestionIndex, actionID string, hostIDs []string) string {
	if idx == nil {
		return ""
	}
	fam, ok := idx.Family(actionID)
	if !ok {
		return ""
	}
	for _, h := range hostIDs {
		if note, ok := idx.Match(fam, h); ok {
			return originSuggestionMatch + note
		}
	}
	return ""
}

// suggestedRisk raises a declared risk class to at least MEDIUM. HIGH and
// CRITICAL are returned unchanged. The request carries the raised class;
// the executor only accepts a class at or above its own derivation.
func suggestedRisk(r pb.RiskClass) pb.RiskClass {
	if r < pb.RiskClass_RISK_CLASS_MEDIUM {
		return pb.RiskClass_RISK_CLASS_MEDIUM
	}
	return r
}
