// SPDX-License-Identifier: AGPL-3.0-or-later

package prompt

import "fmt"

// bytesPerToken is the token estimate used for the budget: one token
// per 3 bytes, rounded up. ASSUMPTION of this package: ADR 0014 D5 asks
// for an estimate "conservatively from bytes" and names no ratio. Typical
// English text is about 4 bytes per token, so 3 is conservative for prose;
// symbol-heavy text (commands, JSON) can be denser. The maintainer must
// confirm the ratio. A smaller value only makes the estimate larger.
const bytesPerToken = 3

// EstimateTokens returns the estimated token count of a text of the
// given byte length, rounded up. Negative lengths count as zero.
func EstimateTokens(bytes int) int {
	if bytes <= 0 {
		return 0
	}
	return (bytes + bytesPerToken - 1) / bytesPerToken
}

// CheckFit reports ErrTooLarge when the worst case of the configured
// limits does not fit MaxPromptTokens. The worst case is the system
// prompt, MaxContextDocBytes of docs, MaxQuestionBytes of question,
// FramingBytes and MaxFactsBlockBytes of facts. Every one of these is
// a byte bound on what is sent, after escaping, that Build enforces, so
// no prompt Build accepts is larger. The service calls it at startup and
// refuses to start when it fails.
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
	worst := len(system) + FramingBytes + docBytes + questionBytes + factsBlockBytes
	if n := EstimateTokens(worst); n > maxTokens {
		return fmt.Errorf("worst case %d tokens, limit %d: %w", n, maxTokens, ErrTooLarge)
	}
	return nil
}
