// SPDX-License-Identifier: AGPL-3.0-or-later

package prompt

import (
	"fmt"

	"github.com/nebula-operation-station/nebula-operation-station/internal/helpfacts"
)

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
// prompt, MaxContextDocBytes of docs, helpfacts.MaxFactBytes of facts,
// MaxQuestionBytes of question and FramingBytes. The service calls it at
// startup and refuses to start when it fails.
//
// The facts allowance is the payload bound of helpfacts. The JSON keys
// and punctuation of the encoded facts are not part of it; Build checks
// the real size of each prompt against MaxPromptTokens.
func CheckFit() error {
	return checkFit(SystemPrompt, MaxPromptTokens, MaxContextDocBytes, helpfacts.MaxFactBytes, MaxQuestionBytes)
}

// checkFit is CheckFit with the limits as parameters, so that tests can
// check a budget that does not fit.
func checkFit(system string, maxTokens, docBytes, factBytes, questionBytes int) error {
	worst := len(system) + FramingBytes + docBytes + factBytes + questionBytes
	if n := EstimateTokens(worst); n > maxTokens {
		return fmt.Errorf("worst case %d tokens, limit %d: %w", n, maxTokens, ErrTooLarge)
	}
	return nil
}
