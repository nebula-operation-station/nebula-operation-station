// SPDX-License-Identifier: AGPL-3.0-or-later

package opsnotes

import "time"

// Retention and count bounds (ADR 0016 D7), next to the code that enforces
// them.
const (
	// Retention is how long a note is kept after it was stored (30 days).
	Retention = 30 * 24 * time.Hour
	// MaxNotes bounds the stored notes; the oldest are pruned first.
	MaxNotes = 500
	// MaxNotesPerDay bounds the notes stored per UTC day.
	MaxNotesPerDay = 100
)

// Field bounds from ADR 0016 D6, applied to the note the model produced.
const (
	// MaxNoteBytes bounds one raw note request before it is parsed.
	MaxNoteBytes = 16 << 10
	// MaxSummaryBytes bounds the summary of a fix note.
	MaxSummaryBytes = 600
	// MaxTextBytes bounds the text of a summary or answer note.
	MaxTextBytes = 2 << 10
	// MaxStepsPerNote bounds the steps of a fix note.
	MaxStepsPerNote = 6
	// MaxStepWhyBytes bounds the reason of one step.
	MaxStepWhyBytes = 300
	// MaxMitigations bounds the mitigation texts of a fix note.
	MaxMitigations = 3
	// MaxMitigationBytes bounds one mitigation text.
	MaxMitigationBytes = 400
	// MaxUrgencyBytes bounds the urgency text of a fix note.
	MaxUrgencyBytes = 300
	// MaxCitations bounds the documentation citations of a note. D6 gives
	// the bound for fix notes only; the same bound is used for the others.
	MaxCitations = 3
	// MaxIDBytes bounds refs, digests, action, host and chunk IDs.
	MaxIDBytes = 128
	// MaxSnapshotBytes bounds the facts snapshot stored with a note.
	MaxSnapshotBytes = 8 << 10
)
