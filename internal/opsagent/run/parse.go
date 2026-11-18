// SPDX-License-Identifier: AGPL-3.0-or-later

package run

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Output limits for one model answer (ADR 0016 D6), named next to the code.
const (
	// MaxOutputBytes bounds an answer before it is parsed (T8).
	MaxOutputBytes = 8 << 10
	// MaxSteps bounds the steps of a fix answer.
	MaxSteps = 6
	// MaxMitigations bounds the mitigations of a fix answer.
	MaxMitigations = 3
	// MaxCitations bounds the citations of an answer.
	MaxCitations = 3
	// MaxSummaryBytes bounds the summary of a fix answer.
	MaxSummaryBytes = 600
	// MaxUrgencyBytes bounds the urgency text of a fix answer.
	MaxUrgencyBytes = 300
	// MaxWhyBytes bounds the reason of one step.
	MaxWhyBytes = 300
	// MaxMitigationBytes bounds one mitigation text.
	MaxMitigationBytes = 400
	// MaxTextBytes bounds the text of a summary answer.
	MaxTextBytes = 2 << 10
)

// ErrInvalidOutput: the model's answer is not one valid object. The answer
// is discarded; its text never reaches a log or an error.
var ErrInvalidOutput = errors.New("model output invalid")

type fixOut struct {
	Summary     string    `json:"summary"`
	Urgency     string    `json:"urgency"`
	Steps       []stepOut `json:"steps"`
	Mitigations []mitOut  `json:"mitigations"`
	Citations   []string  `json:"citations"`
}

type stepOut struct {
	Candidate string `json:"candidate"`
	Why       string `json:"why"`
}

type mitOut struct {
	Text string `json:"text"`
}

type textOut struct {
	Text      string   `json:"text"`
	Citations []string `json:"citations"`
}

var thinkBlock = regexp.MustCompile(`(?s)<(think|thinking)>.*?</(think|thinking)>`)

// extractObject returns the one JSON object of an answer. Reasoning blocks are
// removed; text before and after the object is dropped. An answer with an
// unclosed reasoning block loses everything from that block on.
func extractObject(content string) ([]byte, error) {
	if len(content) > MaxOutputBytes || !utf8.ValidString(content) {
		return nil, ErrInvalidOutput
	}
	s := thinkBlock.ReplaceAllString(content, "")
	for _, open := range []string{"<think>", "<thinking>"} {
		if i := strings.Index(s, open); i >= 0 {
			s = s[:i]
		}
	}
	i := strings.IndexByte(s, '{')
	j := strings.LastIndexByte(s, '}')
	if i < 0 || j < i {
		return nil, ErrInvalidOutput
	}
	return []byte(s[i : j+1]), nil
}

// decodeStrict decodes exactly one JSON value into out, rejecting unknown
// fields and trailing data.
func decodeStrict(data []byte, out any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return ErrInvalidOutput
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalidOutput
	}
	return nil
}

// plainNote reports whether s is printable text with newlines and tabs, and
// without bidi or zero-width characters or a URL (the server refuses the same).
func plainNote(s string, max int) bool {
	if s == "" || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == '\n' || r == '\t' {
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError {
			return false
		}
	}
	low := strings.ToLower(s)
	return !strings.Contains(low, "://") && !strings.Contains(low, "www.")
}

// fixAnswer is a checked fix answer. Steps keep the candidate key; the caller
// maps it to the action and host of the work item.
type fixAnswer struct {
	Summary     string
	Urgency     string
	Steps       []stepOut
	Mitigations []string
	Citations   []string
	// Discarded counts steps with a key that is not a candidate of the item.
	Discarded int
}

// parseFix checks a fix answer. candidates are the keys of the item; docs maps
// the opaque keys of the prompt to chunk IDs.
func parseFix(content string, candidates map[string]bool, docs map[string]string) (fixAnswer, error) {
	data, err := extractObject(content)
	if err != nil {
		return fixAnswer{}, err
	}
	var in fixOut
	if err := decodeStrict(data, &in); err != nil {
		return fixAnswer{}, err
	}
	if !plainNote(in.Summary, MaxSummaryBytes) {
		return fixAnswer{}, ErrInvalidOutput
	}
	if in.Urgency != "" && !plainNote(in.Urgency, MaxUrgencyBytes) {
		return fixAnswer{}, ErrInvalidOutput
	}
	if len(in.Steps) > MaxSteps || len(in.Mitigations) > MaxMitigations {
		return fixAnswer{}, ErrInvalidOutput
	}
	out := fixAnswer{Summary: in.Summary, Urgency: in.Urgency}
	for _, s := range in.Steps {
		if !candidates[s.Candidate] {
			out.Discarded++
			continue
		}
		if s.Why != "" && !plainNote(s.Why, MaxWhyBytes) {
			return fixAnswer{}, ErrInvalidOutput
		}
		out.Steps = append(out.Steps, s)
	}
	for _, m := range in.Mitigations {
		if !plainNote(m.Text, MaxMitigationBytes) {
			return fixAnswer{}, ErrInvalidOutput
		}
		out.Mitigations = append(out.Mitigations, m.Text)
	}
	if len(out.Steps) == 0 && len(out.Mitigations) == 0 {
		return fixAnswer{}, ErrInvalidOutput
	}
	cites, err := citations(in.Citations, docs)
	if err != nil {
		return fixAnswer{}, err
	}
	out.Citations = cites
	return out, nil
}

// parseText checks a summary answer.
func parseText(content string, docs map[string]string) (string, []string, error) {
	data, err := extractObject(content)
	if err != nil {
		return "", nil, err
	}
	var in textOut
	if err := decodeStrict(data, &in); err != nil {
		return "", nil, err
	}
	if !plainNote(in.Text, MaxTextBytes) {
		return "", nil, ErrInvalidOutput
	}
	cites, err := citations(in.Citations, docs)
	if err != nil {
		return "", nil, err
	}
	return in.Text, cites, nil
}

// citations maps prompt keys to chunk IDs; any other key refuses the answer.
func citations(keys []string, docs map[string]string) ([]string, error) {
	if len(keys) > MaxCitations {
		return nil, ErrInvalidOutput
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		id, ok := docs[k]
		if !ok {
			return nil, fmt.Errorf("citation not in prompt: %w", ErrInvalidOutput)
		}
		out = append(out, id)
	}
	return out, nil
}
