// SPDX-License-Identifier: AGPL-3.0-or-later

package prompt

import "fmt"

// Token estimate of spec 01, D5 "How NOS counts tokens". NOS uses no
// tokenizer: a message counts ⌈UTF-8 bytes ÷ PromptBytesPerToken⌉ plus
// PromptMessageOverheadTokens, summed over every message of the request.
// The bound this enforces is in bytes and the same for every model; it
// is not an upper bound on a model's own count.
const (
	// PromptBytesPerToken is the number of content bytes counted as one
	// token, rounded up (spec 01: PromptBytesPerToken = 3).
	PromptBytesPerToken = 3
	// PromptMessageOverheadTokens is added once per chat message for
	// its role and template (spec 01: PromptMessageOverheadTokens = 8).
	PromptMessageOverheadTokens = 8
)

// buildMessages is the number of chat messages Build produces: the
// system prompt and the user message.
const buildMessages = 2

// EstimateTokens returns the estimated token count of the content of
// one message of the given byte length, rounded up, without the
// per-message overhead. Negative lengths count as zero.
func EstimateTokens(bytes int) int {
	if bytes <= 0 {
		return 0
	}
	return (bytes + PromptBytesPerToken - 1) / PromptBytesPerToken
}

// EstimateMessageTokens returns the estimate of a request with the given
// messages: for each message EstimateTokens of its length plus
// PromptMessageOverheadTokens. This is the number checked against
// MaxPromptTokens.
func EstimateMessageTokens(messages ...string) int {
	n := 0
	for _, m := range messages {
		n += EstimateTokens(len(m)) + PromptMessageOverheadTokens
	}
	return n
}

// CheckFit reports ErrTooLarge when the worst case of the configured
// limits does not fit MaxPromptTokens. The worst case is the system
// prompt as one message and, as the user message, MaxContextDocBytes of
// docs, MaxQuestionBytes of question, FramingBytes and
// MaxFactsBlockBytes of facts, each message with
// PromptMessageOverheadTokens. Every one of these is a byte bound on what
// is sent, after escaping, that Build enforces, so no prompt Build
// accepts is larger. The service calls it at startup and refuses to
// start when it fails.
//
// The facts allowance is the cap on the encoded, escaped facts block,
// not the helpfacts.MaxFactBytes payload: JSON keys, punctuation and
// escaping add to the payload. The largest plain projection
// (helpfacts.MaxFactHosts hosts of helpfacts.MaxEndpoints endpoints at
// helpfacts.MaxFactBytes) fits the cap; a projection that escaping makes
// larger is refused by Build.
func CheckFit() error {
	return checkFit(SystemPrompt, MaxPromptTokens, MaxContextDocBytes, MaxQuestionBytes, MaxFactsBlockBytes)
}

// checkFit is CheckFit with the limits as parameters, so that tests can
// check a budget that does not fit.
func checkFit(system string, maxTokens, docBytes, questionBytes, factsBlockBytes int) error {
	user := FramingBytes + docBytes + questionBytes + factsBlockBytes
	n := EstimateTokens(len(system)) + EstimateTokens(user) + buildMessages*PromptMessageOverheadTokens
	if n > maxTokens {
		return fmt.Errorf("worst case %d tokens, limit %d: %w", n, maxTokens, ErrTooLarge)
	}
	return nil
}
