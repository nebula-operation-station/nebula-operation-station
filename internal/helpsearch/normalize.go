// SPDX-License-Identifier: AGPL-3.0-or-later

package helpsearch

import (
	"strings"
	"unicode"
)

// maxTokenBytes is the longest token kept, after normalisation. Longer
// runs (base64 blobs, hashes) are dropped on both the corpus and the
// query side, so they can neither match nor grow the index.
const maxTokenBytes = 64

// umlauts maps German letters to their ASCII spelling so "Schlüssel"
// and "Schluessel" are the same token.
var umlauts = strings.NewReplacer("ä", "ae", "ö", "oe", "ü", "ue", "ß", "ss")

// stopWords are English and German function words. They carry no
// topic and only add noise to a question; both sides drop them.
var stopWords = setOf(
	// English
	"a", "about", "after", "all", "also", "an", "and", "any", "are", "as", "at",
	"be", "because", "been", "before", "both", "but", "by", "can", "do", "does",
	"each", "for", "from", "get", "has", "have", "how", "i", "if", "in", "into",
	"is", "it", "its", "may", "me", "more", "must", "my", "no", "not", "of", "on",
	"once", "one", "only", "or", "other", "our", "out", "own", "should", "so",
	"some", "such", "than", "that", "the", "their", "them", "then", "there",
	"these", "they", "this", "those", "to", "too", "up", "use", "used", "very",
	"was", "we", "were", "what", "when", "where", "which", "while", "who", "why",
	"will", "with", "would", "you", "your",
	// German (after umlaut mapping)
	"aber", "alle", "als", "am", "an", "auch", "auf", "aus", "bei", "bin", "bis",
	"bitte", "da", "damit", "dann", "das", "dass", "dem", "den", "der", "des",
	"die", "dies", "diese", "dieser", "doch", "du", "durch", "ein", "eine",
	"einem", "einen", "einer", "es", "fuer", "hat", "habe", "ich", "ihr", "im",
	"ist", "ja", "kann", "man", "mein", "meine", "meinem", "meinen", "mich",
	"mir", "mit", "muss", "nach", "nicht", "noch", "nur", "ob", "oder", "sich",
	"sie", "sind", "so", "soll", "ueber", "um", "und", "uns", "unter", "vom",
	"von", "vor", "was", "welche", "wenn", "wie", "will", "wir", "wird", "wo",
	"zu", "zum", "zur",
)

func setOf(words ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(words))
	for _, w := range words {
		m[w] = struct{}{}
	}
	return m
}

// tokenRune reports whether r belongs to a token. '-', '.' and '_' are
// kept inside tokens so commands, flags, file names and addresses
// ("enroll-script", "--from", "enroll.sh", "192.168.22.1") stay whole.
func tokenRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '.' || r == '_'
}

// rawTokens splits s into lower-cased, umlaut-mapped tokens without
// stop-word removal or folding. Sentence punctuation around a token
// (a trailing "." or "-", a leading ".") is trimmed; a leading "-" is
// kept because it marks a flag.
func rawTokens(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return !tokenRune(r) }) {
		t := strings.TrimLeft(strings.TrimRight(f, ".-_"), "._")
		if t == "" || strings.Trim(t, "-") == "" {
			continue
		}
		t = umlauts.Replace(strings.ToLower(t))
		if len(t) > maxTokenBytes {
			continue
		}
		out = append(out, t)
	}
	return out
}

// terms returns the index terms of s: raw tokens without stop words,
// each folded, each followed by its parts (see tokenTerms).
func terms(s string) []string {
	var out []string
	for _, t := range rawTokens(s) {
		out = append(out, tokenTerms(t)...)
	}
	return out
}

// tokenTerms returns the terms of one raw token: the token itself
// (folded, unless it is a stop word) and, for a token joined by '-' or
// '_' ("enroll-script", "--no-sudo", "nos-read"), its parts. The whole
// token is always a term, so a command or flag still matches exactly
// and, being rarer, scores higher than its parts; the parts let
// "enroll-script" meet a section titled "The enrollment script".
// Dots do not split: addresses and versions stay whole.
func tokenTerms(t string) []string {
	whole, parts := splitToken(t)
	if whole == "" {
		return parts
	}
	return append([]string{whole}, parts...)
}

// splitToken returns the folded token ("" for a stop word) and its
// folded parts, as described at tokenTerms.
func splitToken(t string) (whole string, parts []string) {
	if _, stop := stopWords[t]; !stop {
		whole = fold(t)
	}
	if !strings.ContainsAny(strings.TrimLeft(t, "-"), "-_") {
		return whole, nil
	}
	for _, p := range strings.FieldsFunc(t, func(r rune) bool { return r == '-' || r == '_' }) {
		if len(p) < 2 {
			continue
		}
		if _, stop := stopWords[p]; stop {
			continue
		}
		parts = append(parts, fold(p))
	}
	return whole, parts
}

// fold is a small English suffix folding ("enrollment", "enrolling",
// "enrolled" → "enroll"; "pinned", "pins" → "pin"; "updates",
// "updated" → "updat"). It only touches plain lower-case ASCII words;
// commands, flags, numbers and German words keep their form (German is
// matched through the synonym table, not stemmed). The rules are
// deliberately few: the same function runs on corpus and query, so a
// rough stem is fine as long as related forms meet.
func fold(t string) string {
	if len(t) < 4 || !plainWord(t) {
		return t
	}
	switch {
	case strings.HasSuffix(t, "ies") && len(t) > 4:
		t = t[:len(t)-3] + "y"
	case strings.HasSuffix(t, "s") && !strings.HasSuffix(t, "ss") &&
		!strings.HasSuffix(t, "us") && !strings.HasSuffix(t, "is"):
		t = t[:len(t)-1]
	}
	switch {
	case strings.HasSuffix(t, "ment") && len(t)-4 >= 4:
		t = t[:len(t)-4]
	case strings.HasSuffix(t, "ing") && len(t)-3 >= 3:
		t = undouble(t[:len(t)-3])
	case strings.HasSuffix(t, "ed") && len(t)-2 >= 3:
		t = undouble(t[:len(t)-2])
	}
	if strings.HasSuffix(t, "e") && len(t) >= 5 {
		t = t[:len(t)-1]
	}
	return t
}

// undouble turns "pinn" (from "pinning") into "pin". Final "ll", "ss"
// and "zz" stay ("enroll", "access").
func undouble(t string) string {
	n := len(t)
	if n >= 3 && t[n-1] == t[n-2] && !strings.ContainsRune("lsz", rune(t[n-1])) && !strings.ContainsRune("aeiou", rune(t[n-1])) {
		return t[:n-1]
	}
	return t
}

func plainWord(t string) bool {
	for i := 0; i < len(t); i++ {
		if t[i] < 'a' || t[i] > 'z' {
			return false
		}
	}
	return true
}
