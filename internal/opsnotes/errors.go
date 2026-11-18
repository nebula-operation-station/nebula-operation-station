// SPDX-License-Identifier: AGPL-3.0-or-later

// Package opsnotes stores the notes the ops agent writes (ADR 0016 D7 and
// D9): validated suggestions for fixes, summaries and answers, with their
// steps indexed for the security-key rule.
//
// Notes are output of a language model and are untrusted. They are never
// an input to planning, proposals, permits, schedules, leases or the
// executor. The store lives in its own SQLite file, chosen by the caller,
// and its migrations are part of this package, so the server database
// backup does not copy it.
package opsnotes

import "errors"

// Sentinel errors that callers branch on.
var (
	// ErrDecode marks a request that is not one strict JSON object: an
	// unknown field, trailing data, a wrong type or invalid UTF-8.
	ErrDecode = errors.New("opsnotes: malformed note")
	// ErrLimit marks a value over a named bound (size or count).
	ErrLimit = errors.New("opsnotes: over the limit")
	// ErrInvalidText marks text with control, bidi, zero-width or
	// replacement characters, or with invalid UTF-8.
	ErrInvalidText = errors.New("opsnotes: invalid text")
	// ErrURL marks text that contains "://" or "www.".
	ErrURL = errors.New("opsnotes: text contains a URL")
	// ErrInvalidField marks an ID that does not match the token syntax.
	ErrInvalidField = errors.New("opsnotes: invalid field")
	// ErrMissing marks a required field that is empty.
	ErrMissing = errors.New("opsnotes: required field missing")
	// ErrFieldNotAllowed marks a field the note kind does not carry.
	ErrFieldNotAllowed = errors.New("opsnotes: field not allowed for this kind")
	// ErrInvalidKind marks an unknown note kind.
	ErrInvalidKind = errors.New("opsnotes: invalid kind")
	// ErrUnknownRef marks a ref the server does not know.
	ErrUnknownRef = errors.New("opsnotes: unknown ref")
	// ErrStaleDigest marks a digest that is not the current input digest of
	// the ref.
	ErrStaleDigest = errors.New("opsnotes: digest is not current")
	// ErrExternalData marks a fix note for data of class external.
	ErrExternalData = errors.New("opsnotes: fix note for external data")
	// ErrUnknownAction marks a step whose action is not in the catalog.
	ErrUnknownAction = errors.New("opsnotes: unknown action")
	// ErrUnknownHost marks a step whose host does not exist.
	ErrUnknownHost = errors.New("opsnotes: unknown host")
	// ErrNotAllowlisted marks a step whose action is in the catalog but not
	// on the suggestion allowlist (ADR 0016 D4), or whose catalog family
	// differs from the allowlist family.
	ErrNotAllowlisted = errors.New("opsnotes: action is not on the suggestion allowlist")
	// ErrNotGroupHost marks a step on a host that is not the managed host of
	// the note's group (ADR 0016 D7).
	ErrNotGroupHost = errors.New("opsnotes: step is not on the group's host")
	// ErrNotCandidate marks a step that is not among the candidates the
	// server computed for the current digest.
	ErrNotCandidate = errors.New("opsnotes: step is not a candidate")
	// ErrDuplicateStep marks two steps with the same action and host.
	ErrDuplicateStep = errors.New("opsnotes: duplicate step")
	// ErrUnknownCitation marks a citation that is not in the documentation
	// index.
	ErrUnknownCitation = errors.New("opsnotes: unknown citation")
	// ErrConflict marks a note with the same kind, ref and digest as a
	// stored note but a different body (HTTP 409).
	ErrConflict = errors.New("opsnotes: conflicting note for this digest")
	// ErrDailyLimit marks a write over MaxNotesPerDay for the UTC day.
	ErrDailyLimit = errors.New("opsnotes: daily note limit reached")
	// ErrNotFound marks a missing note or question.
	ErrNotFound = errors.New("opsnotes: not found")
	// ErrQuestionsFull marks a new question while MaxOpenQuestions questions
	// are open.
	ErrQuestionsFull = errors.New("opsnotes: too many open questions")
	// ErrNotOpen marks an answer to a question that is answered or expired.
	ErrNotOpen = errors.New("opsnotes: question is not open")
	// ErrInvalidSnapshot marks a facts snapshot that is not valid JSON
	// text.
	ErrInvalidSnapshot = errors.New("opsnotes: invalid facts snapshot")
)
