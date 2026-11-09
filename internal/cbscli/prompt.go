// SPDX-License-Identifier: AGPL-3.0-or-later

package cbscli

import (
	"regexp"
	"strings"
)

// Prompt limits. A CBS prompt is the host name followed by '#'
// (privileged EXEC) or '>' (user EXEC). The host name charset and length
// follow the CBS CLI guides (verify against ND-03 lab output).
const (
	// MaxHostnameBytes bounds the host name part of a prompt.
	MaxHostnameBytes = 58
	// MaxPromptBytes bounds a whole prompt (host name plus '#' or '>').
	MaxPromptBytes = MaxHostnameBytes + 1
)

var promptRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,57}[#>]$`)

// parsePrompt reports whether tail, the unterminated last line the device
// sent, is a recognised EXEC prompt, and returns it without trailing
// blanks. Configuration-mode prompts ("sw(config)#") are not recognised.
func parsePrompt(tail string) (string, bool) {
	p := strings.TrimRight(tail, " ")
	if len(p) > MaxPromptBytes || !promptRE.MatchString(p) {
		return "", false
	}
	return p, true
}

// interactiveMarkers are substrings (lower case) of tails that wait for
// input the driver never gives: pagers, confirmations, in-band logins,
// configuration modes. The driver aborts instead of answering.
var interactiveMarkers = []string{
	"--more--",
	"more:",
	"(y/n)",
	"[y/n]",
	"y/n",
	"[confirm]",
	"user name",
	"username",
	"password",
	"login",
	"(config",
	"press any key",
}

// looksInteractive reports whether tail, the unterminated last line after
// the device went quiet, looks like the device waits for input. Every
// prompt-shaped tail counts, also a well-formed prompt other than the
// session's own (a host name or privilege change).
func looksInteractive(tail string) bool {
	t := strings.TrimSpace(tail)
	if t == "" {
		return false
	}
	lower := strings.ToLower(t)
	for _, m := range interactiveMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return strings.ContainsAny(t[len(t)-1:], ":?#>])")
}
