// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import (
	"errors"
	"fmt"
)

// ErrUnbalancedQuote is returned when a quote is opened and never closed. ADR
// 0014 D4 makes such a command red.
var ErrUnbalancedQuote = errors.New("unbalanced quote")

// Tokenize splits s into shell-like words for the V3 matching (ADR 0014 D4,
// "Matching (V3)"). Runs of spaces outside quotes, and not masked by a
// backslash, separate tokens. Quotes and backslashes stay part of the token
// text; nothing is expanded, unescaped or removed, so every token is a literal
// substring of s. A backslash masks the byte after it, except inside single
// quotes, where it is literal (as in POSIX shells). A quote that is opened and
// not closed returns ErrUnbalancedQuote. Only the space byte separates tokens;
// the caller has already checked that the text is printable ASCII (check V1).
// Input longer than MaxCommandBytes returns ErrTooLong.
func Tokenize(s string) ([]string, error) {
	if len(s) > MaxCommandBytes {
		return nil, fmt.Errorf("tokenize: %w: %d bytes, limit %d", ErrTooLong, len(s), MaxCommandBytes)
	}
	var tokens []string
	var quote byte // 0 outside quotes, '\'' or '"' inside them
	start := -1    // byte offset where the current token starts, -1 between tokens
	for i := 0; i < len(s); i++ {
		c := s[i]
		if start < 0 {
			if c == ' ' {
				continue
			}
			start = i
		}
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case c == '\\':
			// Skip the masked byte, so it can neither separate nor open or
			// close a quote. A trailing backslash is ordinary text.
			if i+1 < len(s) {
				i++
			}
		case quote == '"':
			if c == '"' {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == ' ':
			tokens = append(tokens, s[start:i])
			start = -1
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("%w: %c opened and not closed", ErrUnbalancedQuote, quote)
	}
	if start >= 0 {
		tokens = append(tokens, s[start:])
	}
	return tokens, nil
}
