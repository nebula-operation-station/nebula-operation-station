// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

// maxKeyDepth bounds the nesting of arrays and objects the strict key
// check walks in a parsed section; iproute2 output nests far less.
const maxKeyDepth = 64

// Exact member names of the result document and of a section object.
var (
	documentKeys = map[string]bool{
		"format": true, "phase": true,
		SectionAddr: true, SectionLink: true, SectionRoute: true, SectionRoute6: true,
		SectionNeigh: true, SectionNeigh6: true, SectionBridgeVLAN: true,
		SectionLLDP: true, SectionSockets: true, SectionConntrack: true,
	}
	sectionKeys = map[string]bool{"status": true, "truncated": true, "data": true}
)

// parserFields lists the exact JSON field names the internal/netfacts
// parsers bind (a test keeps it identical to their struct tags).
// encoding/json matches member names to fields case-insensitively, so in
// a parsed section a key that folds to one of them must be spelled
// exactly like it.
var parserFields = []string{
	"addr_info", "address", "dev", "dst", "family", "flags", "gateway", "host",
	"id", "ifname", "info_data", "info_kind", "link", "link_type", "linkinfo",
	"lladdr", "local", "master", "metric", "nexthops", "operstate", "prefixlen",
	"state", "via", "vlan", "vlanEnd", "vlans",
}

// parserFieldFold maps the ASCII-folded form of every parser field to its
// exact spelling.
var parserFieldFold = func() map[string]string {
	m := make(map[string]string, len(parserFields))
	for _, f := range parserFields {
		m[foldKey(f)] = f
	}
	return m
}()

// foldKey returns s with the ASCII letters A-Z mapped to a-z. checkKeys
// rejects every member name with a non-ASCII byte before folding, so on
// the names it folds, foldKey(a) == foldKey(b) exactly when encoding/json
// would treat a and b as the same field name (for ASCII its folding is
// ASCII case folding); non-ASCII folds such as U+212A KELVIN SIGN or
// U+017F LONG S never reach this point.
func foldKey(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// isASCII reports whether s has no byte >= 0x80.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// maxQuotedKey bounds how much of a host-controlled member name an error
// message quotes.
const maxQuotedKey = 64

// quoteKey quotes at most maxQuotedKey bytes of key for an error message.
func quoteKey(key string) string {
	if len(key) > maxQuotedKey {
		return strconv.Quote(key[:maxQuotedKey]) + "..."
	}
	return strconv.Quote(key)
}

// errKeys marks a strict key violation.
var errKeys = errors.New("strict keys")

// checkKeys walks the first JSON value in raw token by token and calls
// rule for every object member name with its nesting depth (1 for the
// members of a top-level object). A member name (after JSON unescaping)
// with a non-ASCII byte is rejected, so no Unicode case folding of the
// decoder can map it to a field. Two member names of one object that are
// equal under ASCII case folding are rejected, so neither a duplicate nor
// a case variant can carry a second value. Nesting deeper than maxDepth
// is rejected. Empty input is accepted; syntax errors are returned. The
// work is linear in len(raw).
func checkKeys(raw []byte, maxDepth int, rule func(depth int, key string) error) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // numbers are not converted, so none is out of range
	type frame struct {
		object  bool
		wantKey bool
		seen    map[string]struct{}
	}
	var stack []frame
	for {
		tok, err := dec.Token()
		if err == io.EOF && len(stack) == 0 {
			return nil
		}
		if err != nil {
			return fmt.Errorf("syntax: %w", err)
		}
		top := len(stack) - 1
		if d, isDelim := tok.(json.Delim); isDelim && (d == '}' || d == ']') {
			stack = stack[:top]
			if len(stack) == 0 {
				return nil
			}
			continue
		}
		if s, isString := tok.(string); isString && top >= 0 && stack[top].object && stack[top].wantKey {
			if !isASCII(s) {
				return fmt.Errorf("%w: non-ASCII member %s", errKeys, quoteKey(s))
			}
			if err := rule(len(stack), s); err != nil {
				return err
			}
			k := foldKey(s)
			if _, dup := stack[top].seen[k]; dup {
				return fmt.Errorf("%w: duplicate or case-variant member %s", errKeys, quoteKey(s))
			}
			if stack[top].seen == nil {
				stack[top].seen = make(map[string]struct{})
			}
			stack[top].seen[k] = struct{}{}
			stack[top].wantKey = false
			continue
		}
		// tok is a value: it completes the pending member of an object.
		if top >= 0 && stack[top].object {
			stack[top].wantKey = true
		}
		if d, isDelim := tok.(json.Delim); isDelim {
			if len(stack) >= maxDepth {
				return fmt.Errorf("%w: nesting deeper than %d", errKeys, maxDepth)
			}
			stack = append(stack, frame{object: d == '{', wantKey: d == '{'})
			continue
		}
		if len(stack) == 0 {
			return nil // a top-level scalar
		}
	}
}

// checkDocumentKeys requires every member name of the result document and
// of its section objects to be spelled exactly as the schema names it,
// (so ASCII only), with no duplicates; nothing nests deeper than a section object.
func checkDocumentKeys(raw []byte) error {
	return checkKeys(raw, 2, func(depth int, key string) error {
		names := documentKeys
		if depth == 2 {
			names = sectionKeys
		}
		if !names[key] {
			return fmt.Errorf("%w: unexpected member %s", errKeys, quoteKey(key))
		}
		return nil
	})
}

// checkSectionKeys checks the JSON data of a parsed section: ASCII member
// names only, no duplicate or case-variant members in any object, no case
// variant of a parser field, nesting at most maxKeyDepth.
func checkSectionKeys(raw []byte) error {
	return checkKeys(raw, maxKeyDepth, func(_ int, key string) error {
		if exact, bound := parserFieldFold[foldKey(key)]; bound && exact != key {
			return fmt.Errorf("%w: member %s is a case variant of %q", errKeys, quoteKey(key), exact)
		}
		return nil
	})
}
