// SPDX-License-Identifier: AGPL-3.0-or-later

// Package prompt assembles the prompt of the in-app help assistant
// (ADR 0014 D2, D3, D5). It is a pure function of already selected
// inputs: no retrieval, no fact selection, no LLM call, no I/O.
//
// Layout of the user message:
//
//	Language: de
//
//	<docs>
//	[c1] Handbuch / Abschnitt 1
//	…chunk text…
//
//	[c2] …
//	</docs>
//
//	<facts>
//	…JSON of the helpfacts projection…
//	</facts>          (only when facts are given)
//
//	<question>
//	…question…
//	</question>
//
// Escaping. Chunk text, heading paths and the question are data, not
// markup. Before they are written, the characters & < > [ ] are replaced
// by &amp; &lt; &gt; &#91; &#93; (see dataEscaper). Afterwards no data
// contains "<", so no data can open or close <docs>, <facts> or
// <question>, and no data can forge a "[cN]" reference line. The mapping
// is reversible, so the model can still read the text. The facts block
// is JSON from encoding/json, which writes < > & as JSON escapes
// (backslash-u003c, -u003e, -u0026); Build checks that no "<" or ">" is left. [ ] stay as they are
// in the facts block: they are JSON arrays, and a [ ] inside a JSON
// string cannot start a "[cN]" line because encoding/json escapes line
// breaks. System prompt rule 8 therefore names the entity escaping for
// <docs> and <question> only and the JSON escapes for <facts>.
//
// Citations. Chunks are numbered c1…cN in the rank order given by the
// caller. The numbering depends only on that order and on the budget, so
// it is stable for the same input. Prompt.Citations returns the mapping
// to chunk IDs; NOS uses it to render links and never trusts a reference
// the model invents.
//
// Budget. Byte limits apply to the bytes actually sent, after escaping.
// The token estimate is the one spec 01 (D5 "How NOS counts tokens")
// fixes: ⌈bytes ÷ PromptBytesPerToken⌉ with PromptBytesPerToken = 3,
// plus PromptMessageOverheadTokens = 8 per chat message
// (EstimateMessageTokens). CheckFit and Build check MaxPromptTokens
// against it.
package prompt

// Limits of the help assistant prompt. They are the values of ADR 0014
// D2 and D5 and are pinned by TestConstantsMatchADR.
const (
	// MaxPromptTokens is the estimated token limit of system prompt and
	// user message together (ADR 0014 D5), estimated by
	// EstimateMessageTokens. At PromptBytesPerToken it is a budget of
	// 48000 bytes of message content, minus the message overhead.
	MaxPromptTokens = 16000
	// MaxOutputTokens is the output limit requested from the model. It
	// is not part of the prompt budget.
	MaxOutputTokens = 1500
	// MaxContextDocBytes is the byte limit of the docs chunks in the
	// prompt, counted after escaping (ADR 0014 D2).
	MaxContextDocBytes = 24 << 10
	// MaxChunks is the number of chunks in the prompt (ADR 0014 D2, k).
	MaxChunks = 6
	// MaxQuestionBytes is the limit of the question after escaping. It
	// is also the question budget of CheckFit.
	MaxQuestionBytes = 2 << 10
	// FramingBytes is the allowance for the language line, the block
	// markers and the blank lines around them, for CheckFit.
	FramingBytes = 1 << 10
	// MaxFactsBlockBytes is the byte limit of the body of the <facts>
	// block as sent: the encoded, escaped facts (ADR 0014 D5). Build
	// refuses a larger block with ErrTooLarge and never cuts it; CheckFit
	// reserves it in full.
	MaxFactsBlockBytes = 12 << 10
)
