// SPDX-License-Identifier: AGPL-3.0-or-later

package answer

import (
	"errors"
)

// Limits of ADR 0014 D4. They are enforced in decode.go.
const (
	// MaxAnswerBytes is the largest raw answer that is decoded at all.
	MaxAnswerBytes = 8 << 10
	// MaxSteps is the largest number of steps in one answer.
	MaxSteps = 12
	// MaxSummaryBytes bounds the summary text.
	MaxSummaryBytes = 1 << 10
	// MaxStepTextBytes bounds the text of one step.
	MaxStepTextBytes = 1 << 10
	// MaxCommandBytes bounds the command of one step. It is one line.
	MaxCommandBytes = 512
)

// ErrInvalidAnswer is returned by Decode for every answer that does not
// match the schema. Its text is the fixed text of ADR 0014 D4. It never
// contains the answer or part of it.
var ErrInvalidAnswer = errors.New("the assistant returned an invalid answer")

// Language is the language of an answer: "de" or "en" (ADR 0014 D4).
type Language string

// The two languages an answer can be written in.
const (
	LanguageDE Language = "de"
	LanguageEN Language = "en"
)

// Where names the place a step is carried out. It is optional; the empty
// value means that the step does not name one.
type Where string

// The three places of ADR 0014 D4.
const (
	WhereNebulaHost  Where = "nos-host"
	WhereManagedHost Where = "managed-host"
	WhereBrowser     Where = "browser"
)

// Step is one step of an answer. Command is empty when the step has none,
// because an empty command is rejected by Decode; Where is empty when the
// step names no place. Text and Command are still untrusted: render Text with
// CleanText and check Command with helpcmd before it is shown.
type Step struct {
	Text    string
	Command string
	Where   Where
}

// Answer is a decoded model answer. Its fields follow the schema of ADR 0014
// D4. Citations are IDs as the model wrote them; MapCitations decides which
// of them are valid. Summary and step texts are not yet cleaned.
type Answer struct {
	InScope   bool
	Language  Language
	Summary   string
	Steps     []Step
	Citations []string
}
