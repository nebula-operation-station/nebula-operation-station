// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
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

// parserFields lists the JSON field names the internal/netfacts parsers
// bind (a test keeps it complete). encoding/json matches them
// case-insensitively, so in a parsed section a key that folds to one of
// them must be spelled exactly like it.
var parserFields = []string{
	"addr_info", "address", "dev", "dst", "family", "flags", "gateway", "host",
	"id", "ifname", "info_data", "info_kind", "link", "link_type", "linkinfo",
	"lladdr", "local", "master", "metric", "nexthops", "operstate", "prefixlen",
	"state", "via", "vlan", "vlanEnd", "vlans",
}

// parserFieldFold maps the folded form of every parser field to its exact
// spelling.
var parserFieldFold = func() map[string]string {
	m := make(map[string]string, len(parserFields))
	for _, f := range parserFields {
		m[foldKey(f)] = f
	}
	return m
}()

// foldKey returns a canonical form of s under Unicode simple case folding:
// foldKey(a) == foldKey(b) exactly when strings.EqualFold(a, b), which is
// how encoding/json matches member names to fields. Each rune is replaced
// by the smallest rune of its fold orbit.
func foldKey(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		low := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			low = min(low, f)
		}
		b.WriteRune(low)
	}
	return b.String()
}

// errKeys marks a strict key violation.
var errKeys = errors.New("strict keys")

// checkKeys walks the first JSON value in raw token by token and calls
// rule for every object member name with its nesting depth (1 for the
// members of a top-level object). Two member names of one object that
// are equal under case folding are rejected, so neither a duplicate nor
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
			if err := rule(len(stack), s); err != nil {
				return err
			}
			k := foldKey(s)
			if _, dup := stack[top].seen[k]; dup {
				return fmt.Errorf("%w: duplicate or case-variant member %q", errKeys, s)
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
// with no duplicates; nothing nests deeper than a section object.
func checkDocumentKeys(raw []byte) error {
	return checkKeys(raw, 2, func(depth int, key string) error {
		names := documentKeys
		if depth == 2 {
			names = sectionKeys
		}
		if !names[key] {
			return fmt.Errorf("%w: unexpected member %q", errKeys, key)
		}
		return nil
	})
}

// checkSectionKeys checks the JSON data of a parsed section: no duplicate
// or case-variant members in any object, no case variant of a parser
// field, nesting at most maxKeyDepth.
func checkSectionKeys(raw []byte) error {
	return checkKeys(raw, maxKeyDepth, func(_ int, key string) error {
		if exact, bound := parserFieldFold[foldKey(key)]; bound && exact != key {
			return fmt.Errorf("%w: member %q is a case variant of %q", errKeys, key, exact)
		}
		return nil
	})
}
