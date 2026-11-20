// SPDX-License-Identifier: AGPL-3.0-or-later

package prompt

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/helpdocs"
	"github.com/nebula-operation-station/nebula-operation-station/internal/helpfacts"
)

// Sentinel errors. Callers branch on them with errors.Is.
var (
	// ErrTooLarge is returned when a prompt, or a configuration, does
	// not fit MaxPromptTokens, or when the facts block exceeds
	// MaxFactsBlockBytes. Build never shortens a prompt silently.
	ErrTooLarge = errors.New("prompt: exceeds the token budget")
	// ErrInvalidQuestion is returned for an empty, non-UTF-8 or
	// over-long question.
	ErrInvalidQuestion = errors.New("prompt: invalid question")
	// ErrInvalidLanguage is returned for a language other than "de" or "en".
	ErrInvalidLanguage = errors.New("prompt: invalid language")
	// ErrInvalidChunk is returned for a chunk with an empty or duplicate
	// ID or with text that is not valid UTF-8.
	ErrInvalidChunk = errors.New("prompt: invalid chunk")
	// ErrInvalidFacts is returned when the encoded facts contain markup
	// characters. encoding/json never produces them; the check guards
	// the block boundary anyway.
	ErrInvalidFacts = errors.New("prompt: invalid facts")
	// ErrNoChunks is returned when no chunk fits the context budget.
	ErrNoChunks = errors.New("prompt: no chunk fits the context budget")
)

// Languages the assistant answers in (ADR 0014 D4).
const (
	langDE = "de"
	langEN = "en"
)

// dataEscaper replaces the markup characters of data. It is a single
// pass, so the replacement is reversible.
var dataEscaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	"[", "&#91;",
	"]", "&#93;",
)

// Input is what Build assembles. The caller has already selected all of it.
type Input struct {
	// Chunks are the ranked chunks, best first. Build takes the longest
	// prefix that fits MaxChunks and MaxContextDocBytes.
	Chunks []helpdocs.Chunk
	// Facts is the projection of the user's inventory question. Nil
	// means the user did not opt in: the prompt has no <facts> block.
	Facts *helpfacts.Result
	// Question is the user's question as typed. It must be valid UTF-8.
	Question string
	// Language is "de" or "en" and is repeated in the prompt.
	Language string
}

// Citation maps one reference shown in the prompt to a chunk.
type Citation struct {
	// Ref is the reference, "c1" … "cN", as it appears in the prompt.
	Ref string
	// ChunkID is helpdocs.Chunk.ID of the chunk the reference names.
	ChunkID string
}

// Prompt is an assembled prompt.
type Prompt struct {
	// System is SystemPrompt.
	System string
	// User is the user message: language line, <docs>, optional <facts>,
	// and <question>.
	User string
	// Citations lists the references in prompt order. They are the only
	// IDs an answer may cite.
	Citations []Citation
}

// Build assembles the prompt for in. It is deterministic: the same input
// always gives the same Prompt. It fails instead of cutting the question,
// the facts or a chunk; it takes whole chunks from the front of the rank
// order and stops at the first chunk that does not fit.
func Build(in Input) (Prompt, error) {
	if in.Language != langDE && in.Language != langEN {
		return Prompt{}, fmt.Errorf("language %q: %w", in.Language, ErrInvalidLanguage)
	}
	question, err := encodeQuestion(in.Question)
	if err != nil {
		return Prompt{}, err
	}
	if err := checkChunks(in.Chunks); err != nil {
		return Prompt{}, err
	}
	docs, cites, err := renderDocs(in.Chunks)
	if err != nil {
		return Prompt{}, err
	}
	var facts string
	if in.Facts != nil {
		if facts, err = encodeFacts(in.Facts); err != nil {
			return Prompt{}, err
		}
		if err := checkFactsBlock(facts); err != nil {
			return Prompt{}, err
		}
	}

	var u strings.Builder
	u.WriteString("Language: " + in.Language + "\n\n")
	u.WriteString("<docs>\n" + docs + "</docs>\n")
	if in.Facts != nil {
		u.WriteString("\n<facts>\n" + facts + "\n</facts>\n")
	}
	u.WriteString("\n<question>\n" + question + "\n</question>\n")

	p := Prompt{System: SystemPrompt, User: u.String(), Citations: cites}
	if err := checkTotal(p, MaxPromptTokens); err != nil {
		return Prompt{}, err
	}
	return p, nil
}

// encodeQuestion validates the question and returns it escaped.
func encodeQuestion(q string) (string, error) {
	if !utf8.ValidString(q) {
		return "", fmt.Errorf("question is not valid UTF-8: %w", ErrInvalidQuestion)
	}
	if strings.TrimSpace(q) == "" {
		return "", fmt.Errorf("question is empty: %w", ErrInvalidQuestion)
	}
	enc := dataEscaper.Replace(q)
	if len(enc) > MaxQuestionBytes {
		return "", fmt.Errorf("question is %d bytes after escaping, limit %d: %w", len(enc), MaxQuestionBytes, ErrInvalidQuestion)
	}
	return enc, nil
}

// checkChunks rejects an empty, duplicate or non-UTF-8 chunk in the
// whole input, not only in the prefix that fits, so the error does not
// depend on the budget.
func checkChunks(chunks []helpdocs.Chunk) error {
	seen := make(map[string]struct{}, len(chunks))
	for _, c := range chunks {
		if c.ID == "" {
			return fmt.Errorf("chunk without ID: %w", ErrInvalidChunk)
		}
		if _, dup := seen[c.ID]; dup {
			return fmt.Errorf("chunk %q twice: %w", c.ID, ErrInvalidChunk)
		}
		seen[c.ID] = struct{}{}
		if !utf8.ValidString(c.Text) {
			return fmt.Errorf("chunk %q text is not valid UTF-8: %w", c.ID, ErrInvalidChunk)
		}
		for _, p := range c.Path {
			if !utf8.ValidString(p) {
				return fmt.Errorf("chunk %q path is not valid UTF-8: %w", c.ID, ErrInvalidChunk)
			}
		}
	}
	return nil
}

// renderDocs writes the docs block body. It takes chunks from the front
// of the list while fewer than MaxChunks are taken and the next chunk
// fits MaxContextDocBytes as a whole; it stops at the first chunk that
// does not fit.
func renderDocs(chunks []helpdocs.Chunk) (string, []Citation, error) {
	var b strings.Builder
	var cites []Citation
	for _, c := range chunks {
		if len(cites) == MaxChunks {
			break
		}
		ref := "c" + strconv.Itoa(len(cites)+1)
		entry := renderEntry(ref, c)
		if b.Len()+len(entry) > MaxContextDocBytes {
			break
		}
		b.WriteString(entry)
		cites = append(cites, Citation{Ref: ref, ChunkID: c.ID})
	}
	if len(cites) == 0 {
		return "", nil, ErrNoChunks
	}
	return b.String(), cites, nil
}

// renderEntry returns one chunk as it appears in the docs block.
func renderEntry(ref string, c helpdocs.Chunk) string {
	path := make([]string, len(c.Path))
	for i, p := range c.Path {
		path[i] = dataEscaper.Replace(p)
	}
	return "[" + ref + "] " + strings.Join(path, " / ") + "\n" +
		dataEscaper.Replace(c.Text) + "\n\n"
}

// encodeFacts returns the facts as JSON. encoding/json escapes < > & in
// strings, so the output holds no markup; the check below is a guard.
func encodeFacts(f *helpfacts.Result) (string, error) {
	b, err := json.Marshal(f)
	if err != nil {
		return "", fmt.Errorf("encode facts: %w", err)
	}
	if strings.ContainsAny(string(b), "<>") {
		return "", fmt.Errorf("facts contain markup characters: %w", ErrInvalidFacts)
	}
	return string(b), nil
}

// checkFactsBlock reports ErrTooLarge when the facts block body, as it
// is sent, exceeds MaxFactsBlockBytes.
func checkFactsBlock(facts string) error {
	if len(facts) > MaxFactsBlockBytes {
		return fmt.Errorf("facts block is %d bytes, limit %d: %w", len(facts), MaxFactsBlockBytes, ErrTooLarge)
	}
	return nil
}

// checkTotal reports ErrTooLarge when the estimate of p's two messages,
// PromptMessageOverheadTokens each included, exceeds maxTokens.
func checkTotal(p Prompt, maxTokens int) error {
	n := EstimateMessageTokens(p.System, p.User)
	if n > maxTokens {
		return fmt.Errorf("prompt estimated at %d tokens, limit %d: %w", n, maxTokens, ErrTooLarge)
	}
	return nil
}
