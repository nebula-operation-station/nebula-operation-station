// SPDX-License-Identifier: AGPL-3.0-or-later

package helpfacts

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// osRe is the charset of an OS family or release: letters, digits, dot,
// underscore, space and hyphen, at most MaxOSBytes bytes.
var osRe = regexp.MustCompile("^[A-Za-z0-9._ -]{1," + strconv.Itoa(MaxOSBytes) + "}$")

// cleanText makes an untrusted text value safe to show as plain text:
// invalid UTF-8 is dropped, control and format characters become spaces,
// whitespace is collapsed, and the value is cut to max bytes at a rune
// boundary. Every change sets Altered. Instruction-like wording is not
// removed; it stays data.
func cleanText(s string, max int) Text {
	var t Text
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
		t.Altered = true
	}
	mapped := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, s)
	norm := strings.Join(strings.Fields(mapped), " ")
	if norm != s {
		t.Altered = true
	}
	if len(norm) > max {
		cut := max
		for cut > 0 && !utf8.RuneStart(norm[cut]) {
			cut--
		}
		norm = strings.TrimRight(norm[:cut], " ")
		t.Altered = true
	}
	t.Value = norm
	return t
}

// cleanOS accepts an OS family or release only from osRe; anything else
// is dropped and marked.
func cleanOS(s string) Text {
	if s == "" {
		return Text{}
	}
	if osRe.MatchString(s) {
		return Text{Value: s}
	}
	return Text{Altered: true}
}
