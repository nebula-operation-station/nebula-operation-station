// SPDX-License-Identifier: AGPL-3.0-or-later
package dockerhost

import (
	"bytes"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// trivyScan walks a JSON document on its raw bytes, without copying any
// value: strings, keys and numbers are returned as sub-slices of the input
// and skipped values are only stepped over. Only values the parser keeps
// are decoded, and only after their raw length was checked against the
// field limit, so one huge string, key or number never reaches memory.
//
// The document must have passed json.Valid; the scanner still checks every
// index and reports errTrivyShape instead of panicking on a malformed one.
type trivyScan struct {
	b []byte
	i int
}

// peek skips whitespace and returns the next byte, 0 at the end.
func (s *trivyScan) peek() byte {
	for s.i < len(s.b) {
		switch c := s.b[s.i]; c {
		case ' ', '\t', '\n', '\r':
			s.i++
		default:
			return c
		}
	}
	return 0
}

// str consumes the string at the cursor and returns its raw content
// between the quotes, escapes not decoded.
func (s *trivyScan) str() ([]byte, error) {
	if s.peek() != '"' {
		return nil, errTrivyShape
	}
	start := s.i + 1
	for j := start; j < len(s.b); {
		q := bytes.IndexByte(s.b[j:], '"')
		if q < 0 {
			break
		}
		end := j + q
		// The quote is escaped when an odd number of backslashes precede it.
		n := 0
		for k := end - 1; k >= start && s.b[k] == '\\'; k-- {
			n++
		}
		if n%2 == 0 {
			s.i = end + 1
			return s.b[start:end], nil
		}
		j = end + 1
	}
	return nil, errTrivyShape
}

// skip consumes one value of any type.
func (s *trivyScan) skip() error {
	switch c := s.peek(); c {
	case 0:
		return errTrivyShape
	case '"':
		_, err := s.str()
		return err
	case '{', '[':
		depth := 0
		for s.i < len(s.b) {
			switch s.b[s.i] {
			case '"':
				if _, err := s.str(); err != nil {
					return err
				}
				continue
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					s.i++
					return nil
				}
			}
			s.i++
		}
		return errTrivyShape
	default: // number, true, false, null
		start := s.i
		for s.i < len(s.b) && !scanDelim(s.b[s.i]) {
			s.i++
		}
		if s.i == start {
			return errTrivyShape
		}
		return nil
	}
}

// span consumes one value and returns its raw bytes.
func (s *trivyScan) span() ([]byte, error) {
	s.peek()
	start := s.i
	if err := s.skip(); err != nil {
		return nil, err
	}
	return s.b[start:s.i], nil
}

func scanDelim(c byte) bool {
	switch c {
	case ',', ']', '}', ':', ' ', '\t', '\n', '\r':
		return true
	}
	return false
}

// open reports whether the value at the cursor is the container d ('{' or
// '['), consuming a null instead (false). Any other value is a shape error.
func (s *trivyScan) open(d byte) (bool, error) {
	switch s.peek() {
	case d:
		return true, nil
	case 'n':
		return false, s.skip()
	}
	return false, errTrivyShape
}

// members walks the object at the cursor. field gets the raw key and must
// consume the member's value.
func (s *trivyScan) members(field func(rawKey []byte) error) error {
	if s.peek() != '{' {
		return errTrivyShape
	}
	s.i++
	if s.peek() == '}' {
		s.i++
		return nil
	}
	for {
		key, err := s.str()
		if err != nil {
			return err
		}
		if s.peek() != ':' {
			return errTrivyShape
		}
		s.i++
		if err := field(key); err != nil {
			return err
		}
		switch s.peek() {
		case ',':
			s.i++
		case '}':
			s.i++
			return nil
		default:
			return errTrivyShape
		}
	}
}

// elements walks the array at the cursor. elem must consume one element.
func (s *trivyScan) elements(elem func() error) error {
	if s.peek() != '[' {
		return errTrivyShape
	}
	s.i++
	if s.peek() == ']' {
		s.i++
		return nil
	}
	for {
		if err := elem(); err != nil {
			return err
		}
		switch s.peek() {
		case ',':
			s.i++
		case ']':
			s.i++
			return nil
		default:
			return errTrivyShape
		}
	}
}

// maxJSONEscapeRatio is the largest number of raw bytes one decoded byte
// can take in a JSON string ("a" is one byte). A raw string longer
// than maxJSONEscapeRatio*limit therefore decodes to more than limit bytes
// and is rejected without decoding.
const maxJSONEscapeRatio = 6

// unescapeJSON appends the decoded content of a raw JSON string to dst,
// as encoding/json does (an unpaired surrogate becomes U+FFFD).
func unescapeJSON(dst, raw []byte) ([]byte, bool) {
	for i := 0; i < len(raw); {
		c := raw[i]
		if c != '\\' {
			dst = append(dst, c)
			i++
			continue
		}
		if i+1 >= len(raw) {
			return dst, false
		}
		switch raw[i+1] {
		case '"', '\\', '/':
			dst = append(dst, raw[i+1])
		case 'b':
			dst = append(dst, '\b')
		case 'f':
			dst = append(dst, '\f')
		case 'n':
			dst = append(dst, '\n')
		case 'r':
			dst = append(dst, '\r')
		case 't':
			dst = append(dst, '\t')
		case 'u':
			r, ok := hex4(raw[i+2:])
			if !ok {
				return dst, false
			}
			i += 6
			if utf16.IsSurrogate(r) {
				if i+6 <= len(raw) && raw[i] == '\\' && raw[i+1] == 'u' {
					if r2, ok := hex4(raw[i+2:]); ok {
						if d := utf16.DecodeRune(r, r2); d != unicode.ReplacementChar {
							dst = utf8.AppendRune(dst, d)
							i += 6
							continue
						}
					}
				}
				r = unicode.ReplacementChar
			}
			dst = utf8.AppendRune(dst, r)
			continue
		default:
			return dst, false
		}
		i += 2
	}
	return dst, true
}

func hex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var r rune
	for _, c := range b[:4] {
		switch {
		case c >= '0' && c <= '9':
			c -= '0'
		case c >= 'a' && c <= 'f':
			c = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			c = c - 'A' + 10
		default:
			return 0, false
		}
		r = r<<4 | rune(c)
	}
	return r, true
}

// maxJSONSmallInt bounds the digits of an integer the parser decodes; an
// epoch or schema version never needs more.
const maxJSONSmallInt = 9

// smallInt parses a raw JSON number that is an integer of at most
// maxJSONSmallInt digits; anything else (fraction, exponent, longer) is not.
func smallInt(b []byte) (int, bool) {
	neg := len(b) > 0 && b[0] == '-'
	if neg {
		b = b[1:]
	}
	if len(b) == 0 || len(b) > maxJSONSmallInt {
		return 0, false
	}
	n := 0
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	if neg {
		n = -n
	}
	return n, true
}
