// SPDX-License-Identifier: AGPL-3.0-or-later

package cbscli

import (
	"strings"
	"testing"
)

// promptSeeds are the seed tails shared by both fuzz targets: the table cases
// of prompt_test.go plus hostile shapes (control bytes, ANSI sequences, bad
// UTF-8, long and embedded-newline lines, pager and password prompts).
func promptSeeds() []string {
	return []string{
		"",
		" ",
		"switch#",
		"switch>",
		"sw-lab-01#",
		"SW1.lab>",
		"sw1#  ",
		"sw1#\t",
		"sw1#\r",
		"sw1#\x00",
		"sw1\x1b[0m#",
		"\x1b[31msw1#",
		"sw1\x1b[K#",
		"sw1#\x1b",
		"\x1b[2J",
		"switch(config)#",
		"switch(config-if)#",
		"--More--",
		" --More-- ",
		"More: <space>,  Quit: q or CTRL+Z, One line: <return>",
		"Overwrite file [startup-config].... (Y/N)[N] ?",
		"Are you sure? [y/n]",
		"Proceed with reload? [confirm]",
		"User Name:",
		"Username: ",
		"Password:",
		"password:",
		"login:",
		"Press any key to continue",
		"Continue? ",
		"sw1\nswitch#",
		"sw1#\nmore",
		"gi1/0/1\n--More--",
		"\xff\xfeswitch#",
		"sw\xc3#",
		"swîtch#",
		"sw​#",
		"sw‮#",
		"switch\x7f#",
		strings.Repeat("h", MaxHostnameBytes) + "#",
		strings.Repeat("h", MaxHostnameBytes+1) + "#",
		strings.Repeat("h", MaxPromptBytes*4),
		strings.Repeat("a", MaxLineBytes+2) + "#",
		strings.Repeat(" ", 1<<12) + "#",
		strings.Repeat("#", 1<<10),
		strings.Repeat("-", 1<<10) + "#",
	}
}

// FuzzParsePrompt checks that parsePrompt never panics and that an accepted
// prompt is a bounded, plain-ASCII host name followed by '#' or '>', and that
// the driver's interactive check also flags it, so an accepted prompt is never
// read as "not a prompt".
func FuzzParsePrompt(f *testing.F) {
	for _, s := range promptSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, tail string) {
		got, ok := parsePrompt(tail)
		if !ok {
			if got != "" {
				t.Fatalf("parsePrompt(%q) rejected but returned %q", tail, got)
			}
			return
		}
		if len(got) > MaxPromptBytes {
			t.Fatalf("parsePrompt(%q) = %q: %d bytes, limit %d", tail, got, len(got), MaxPromptBytes)
		}
		if got != strings.TrimRight(tail, " ") {
			t.Fatalf("parsePrompt(%q) = %q, want the tail without trailing blanks", tail, got)
		}
		if n := len(got); n < 2 || got[n-1] != '#' && got[n-1] != '>' {
			t.Fatalf("parsePrompt(%q) = %q: not a host name plus '#' or '>'", tail, got)
		}
		for i := 0; i < len(got)-1; i++ {
			c := got[i]
			ok := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
				(i > 0 && (c == '.' || c == '_' || c == '-'))
			if !ok {
				t.Fatalf("parsePrompt(%q) = %q: byte %d (%#x) outside the host name charset", tail, got, i, c)
			}
		}
		if !looksInteractive(tail) {
			t.Fatalf("parsePrompt accepted %q but looksInteractive does not flag it", tail)
		}
	})
}

// FuzzLooksInteractive checks that looksInteractive never panics on arbitrary
// bytes and that a blank tail is never reported as waiting for input.
func FuzzLooksInteractive(f *testing.F) {
	for _, s := range promptSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, tail string) {
		if strings.TrimSpace(tail) == "" && looksInteractive(tail) {
			t.Fatalf("looksInteractive(%q) = true for a blank tail", tail)
		}
	})
}
