// SPDX-License-Identifier: AGPL-3.0-or-later

package helpfacts

import (
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// MaxLiterals bounds the distinct address and CIDR literals taken from
// one question. Name literals are not counted: they are checked against
// the inventory by lookup, so ordinary words cannot push an address out
// of the budget.
const MaxLiterals = 32

// Smallest CIDR prefixes a question may name. Broader blocks (0.0.0.0/0,
// ::/0, …) would select every visible host, which ADR 0014 D3 forbids
// ("no all-hosts mode"); they are refused and reported as truncated.
const (
	minIPv4CIDRPrefix = 16
	minIPv6CIDRPrefix = 32
)

// tokenSeparators are the characters that, with whitespace, separate
// tokens in the D4 matcher (ADR 0014 D4, V5). Every other byte belongs
// to a token.
const tokenSeparators = ",;()[]{}\"'<>"

// trailingSentenceMarks are the characters one of which is removed from
// the end of a token (ADR 0014 D4). Only one is removed.
const trailingSentenceMarks = ".:?!"

// literalKind is the shape of a literal taken from the question.
type literalKind int

const (
	litAddress literalKind = iota + 1
	litCIDR
	litName
)

// literal is one address, CIDR or name token of the question.
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
		return "n:" + asciiLower(l.name)
	}
}

// nameRe matches a host name or host ID token: letters, digits, dot,
// underscore and hyphen, at most 253 bytes, starting and ending with a
// letter or digit.
var nameRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$`)

// QuestionHostValues is what the D4 matcher takes from a question. The
// same matcher selects the D3 facts and builds the V5 trusted host set,
// so both see the same hosts.
type QuestionHostValues struct {
	// Addresses are IP literals in canonical form, in order of appearance.
	Addresses []string
	// CIDRs are CIDR blocks in canonical form, in order of appearance.
	CIDRs []string
	// Names are DNS-style names and host IDs in lower case.
	Names []string
	// Truncated reports that literals were left out: the address/CIDR
	// budget was full, or a CIDR was broader than the minimum prefix.
	Truncated bool
}

// ParseQuestionHostValues runs the D4 matcher over a question.
func ParseQuestionHostValues(question string) QuestionHostValues {
	lits, truncated := parseLiterals(question)
	out := QuestionHostValues{Truncated: truncated}
	for _, l := range lits {
		switch l.kind {
		case litAddress:
			out.Addresses = append(out.Addresses, l.ip.String())
		case litCIDR:
			out.CIDRs = append(out.CIDRs, l.network.String())
		default:
			out.Names = append(out.Names, asciiLower(l.name))
		}
	}
	return out
}

// parseLiterals returns the distinct literals of question in order of
// appearance. It reports truncated when an address or CIDR was left out
// because MaxLiterals was reached or a CIDR was too broad.
func parseLiterals(question string) ([]literal, bool) {
	var out []literal
	seen := make(map[string]bool)
	truncated := false
	addresses := 0
	for _, tok := range Tokenize(question) {
		l, ok, refused := classify(tok)
		if refused {
			truncated = true
		}
		if !ok {
			continue
		}
		k := l.key()
		if seen[k] {
			continue
		}
		seen[k] = true
		if l.kind != litName {
			if addresses == MaxLiterals {
				truncated = true
				continue
			}
			addresses++
		}
		out = append(out, l)
	}
	return out, truncated
}

// Tokenize splits a question into tokens as ADR 0014 D4 defines them:
// whitespace and the characters ,;()[]{}"'<> separate tokens, and one
// trailing . : ? or ! is removed from each token. Empty tokens are
// dropped. The V5 trusted host set uses this same function.
func Tokenize(question string) []string {
	var out []string
	fields := strings.FieldsFunc(question, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune(tokenSeparators, r)
	})
	for _, f := range fields {
		if n := len(f); n > 0 && strings.IndexByte(trailingSentenceMarks, f[n-1]) >= 0 {
			f = f[:n-1]
		}
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// classify turns one token into a literal. refused reports a CIDR that
// was well-formed but too broad.
//
// A token is, in order: a URL (its host part is the literal), a CIDR,
// an IP address, a host name, or host:port (the host part is the
// literal when the port is valid). Anything else is not a literal.
func classify(tok string) (lit literal, ok bool, refused bool) {
	if strings.Contains(tok, "://") {
		u, err := url.Parse(tok)
		if err != nil {
			return literal{}, false, false
		}
		l, ok := classifyHost(u.Hostname())
		return l, ok, false
	}
	if strings.Contains(tok, "/") {
		return classifyCIDR(tok)
	}
	if l, ok := classifyHost(tok); ok {
		return l, true, false
	}
	if i := strings.LastIndexByte(tok, ':'); i > 0 && strings.IndexByte(tok[:i], ':') < 0 && validPort(tok[i+1:]) {
		l, ok := classifyHost(tok[:i])
		return l, ok, false
	}
	return literal{}, false, false
}

// classifyHost classifies a bare host: an IP address or a name.
func classifyHost(h string) (literal, bool) {
	if ip := net.ParseIP(h); ip != nil {
		return literal{kind: litAddress, ip: ip}, true
	}
	if nameRe.MatchString(h) {
		return literal{kind: litName, name: h}, true
	}
	return literal{}, false
}

// classifyCIDR classifies a CIDR token and refuses blocks broader than
// the minimum prefix of its family.
func classifyCIDR(t string) (literal, bool, bool) {
	_, n, err := net.ParseCIDR(t)
	if err != nil {
		return literal{}, false, false
	}
	ones, bits := n.Mask.Size()
	minPrefix := minIPv6CIDRPrefix
	if bits == 32 {
		minPrefix = minIPv4CIDRPrefix
	}
	if ones < minPrefix {
		return literal{}, false, true
	}
	return literal{kind: litCIDR, network: n}, true, false
}

// validPort reports whether s is a decimal TCP/UDP port, 1 to 65535.
func validPort(s string) bool {
	if s == "" || len(s) > 5 {
		return false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n >= 1 && n <= 65535
}

// asciiLower lowercases ASCII letters only. Non-ASCII bytes are kept, so
// no Unicode folding can make two different names equal.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// asciiName returns the ASCII-lowercased form of s and true, or false
// when s contains any non-ASCII byte. Host-chosen names are compared
// only in this form, so a Unicode look-alike never matches a literal.
func asciiName(s string) (string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return "", false
		}
	}
	return asciiLower(s), true
}
