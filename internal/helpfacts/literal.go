// SPDX-License-Identifier: AGPL-3.0-or-later

package helpfacts

import (
	"net"
	"regexp"
	"strings"
)

// MaxLiterals bounds the distinct literals taken from one question.
const MaxLiterals = 32

// literalKind is the shape of a literal taken from the question.
type literalKind int

const (
	litAddress literalKind = iota + 1
	litCIDR
	litName
)

// literal is one address, CIDR or name/ID token of the question.
type literal struct {
	kind    literalKind
	ip      net.IP
	network *net.IPNet
	name    string
}

// key identifies a literal for de-duplication.
func (l literal) key() string {
	switch l.kind {
	case litAddress:
		return "a:" + l.ip.String()
	case litCIDR:
		return "c:" + l.network.String()
	default:
		return "n:" + strings.ToLower(l.name)
	}
}

// nameRe matches a host name or host ID token: letters, digits, dot,
// underscore and hyphen, at most 253 bytes, starting and ending with a
// letter or digit.
var nameRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$`)

// parseLiterals returns the distinct literals of question in order of
// appearance. It reports truncated when more than MaxLiterals distinct
// literals were found. Only ASCII tokens count; everything else is a
// separator.
func parseLiterals(question string) ([]literal, bool) {
	var out []literal
	seen := make(map[string]bool)
	for _, tok := range tokenize(question) {
		l, ok := literalOf(tok)
		if !ok {
			continue
		}
		k := l.key()
		if seen[k] {
			continue
		}
		if len(out) == MaxLiterals {
			return out, true
		}
		seen[k] = true
		out = append(out, l)
	}
	return out, false
}

// tokenize splits the question at every byte that cannot be part of an
// address, CIDR or host name.
func tokenize(q string) []string {
	var out []string
	start := -1
	for i := 0; i <= len(q); i++ {
		if i < len(q) && isTokenByte(q[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			out = append(out, q[start:i])
			start = -1
		}
	}
	return out
}

// isTokenByte reports whether c can be part of a literal.
func isTokenByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '.', c == '_', c == '-', c == ':', c == '/':
		return true
	}
	return false
}

// literalOf classifies a token. A trailing sentence punctuation is
// removed when the bare token is not a literal (for example "pve1.").
func literalOf(tok string) (literal, bool) {
	if l, ok := parseOne(tok); ok {
		return l, true
	}
	if t := strings.TrimRight(tok, ".:-_"); t != tok {
		return parseOne(t)
	}
	return literal{}, false
}

// parseOne classifies a bare token as CIDR, IP address or host name.
func parseOne(t string) (literal, bool) {
	if strings.Contains(t, "/") {
		_, n, err := net.ParseCIDR(t)
		if err != nil {
			return literal{}, false
		}
		return literal{kind: litCIDR, network: n}, true
	}
	if ip := net.ParseIP(t); ip != nil {
		return literal{kind: litAddress, ip: ip}, true
	}
	if nameRe.MatchString(t) {
		return literal{kind: litName, name: t}, true
	}
	return literal{}, false
}
