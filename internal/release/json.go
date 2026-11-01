// SPDX-License-Identifier: AGPL-3.0-or-later

package release

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

// maxDocumentDepth is the nesting limit of signed documents: the root
// object is depth 1 (spec 10).
const maxDocumentDepth = 4

// decodeCanonical decodes a signed JSON document that must be exactly its
// RFC 8785 (JCS) form: no BOM, valid UTF-8, an object at the top, no
// duplicate keys, no nulls, at most maxDocumentDepth levels and at most
// maxBytes bytes. Structure and depth are checked iteratively before any
// recursive processing, so hostile nesting cannot exhaust the stack.
// Noncanonical input is rejected, never reserialized.
func decodeCanonical(raw []byte, maxBytes int) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > maxBytes {
		return nil, fmt.Errorf("%w: document must be 1 to %d bytes", ErrFormat, maxBytes)
	}
	if bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}) || !utf8.Valid(raw) {
		return nil, fmt.Errorf("%w: document is not UTF-8 without BOM", ErrFormat)
	}
	if err := checkStructure(raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	canon, err := jcs.Transform(raw)
	if err != nil || !bytes.Equal(canon, raw) {
		return nil, fmt.Errorf("%w: document is not canonical JSON (RFC 8785)", ErrFormat)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	return out, nil
}

// checkStructure walks the token stream without recursion.
func checkStructure(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	type frame struct {
		object bool
		keys   map[string]bool
		expKey bool
	}
	var stack []*frame
	first := true
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			if len(stack) != 0 || first {
				return errors.New("truncated document")
			}
			return nil
		}
		if err != nil {
			return errors.New("invalid JSON")
		}
		if first {
			if d, ok := tok.(json.Delim); !ok || d != '{' {
				return errors.New("document must be an object")
			}
		} else if len(stack) == 0 {
			return errors.New("trailing data after the document")
		}
		first = false
		// A key in an object.
		if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].expKey {
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:n-1]
				continue
			}
			k, ok := tok.(string)
			if !ok {
				return errors.New("invalid object key")
			}
			if stack[n-1].keys[k] {
				return fmt.Errorf("duplicate key %q", k)
			}
			stack[n-1].keys[k] = true
			stack[n-1].expKey = false
			continue
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				if len(stack)+1 > maxDocumentDepth {
					return fmt.Errorf("nesting deeper than %d", maxDocumentDepth)
				}
				if n := len(stack); n > 0 && stack[n-1].object {
					stack[n-1].expKey = true
				}
				stack = append(stack, &frame{object: v == '{', keys: map[string]bool{}, expKey: v == '{'})
				continue
			case ']':
				stack = stack[:len(stack)-1]
			}
		case nil:
			return errors.New("null is not allowed")
		}
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].expKey = true
		}
	}
}

// fields checks that v is an object with exactly the given keys.
func fields(v any, keys ...string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("expected an object")
	}
	if len(m) != len(keys) {
		return nil, fmt.Errorf("object must have exactly the fields %v", keys)
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return nil, fmt.Errorf("missing field %q", k)
		}
	}
	return m, nil
}

func str(m map[string]any, k string) (string, error) {
	s, ok := m[k].(string)
	if !ok {
		return "", fmt.Errorf("field %q must be a string", k)
	}
	return s, nil
}

// integer returns a JSON integer field in [lo, hi]. Fractions and
// exponents are rejected; canonical JSON already forbids other spellings.
func integer(m map[string]any, k string, lo, hi int64) (int64, error) {
	n, ok := m[k].(json.Number)
	if !ok {
		return 0, fmt.Errorf("field %q must be an integer", k)
	}
	i, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil || i < lo || i > hi {
		return 0, fmt.Errorf("field %q must be an integer from %d to %d", k, lo, hi)
	}
	return i, nil
}

func array(m map[string]any, k string, lo, hi int) ([]any, error) {
	a, ok := m[k].([]any)
	if !ok {
		return nil, fmt.Errorf("field %q must be an array", k)
	}
	if len(a) < lo || len(a) > hi {
		return nil, fmt.Errorf("field %q must have %d to %d entries", k, lo, hi)
	}
	return a, nil
}

// sha256Hex returns a field holding exactly 64 lowercase hex digits.
func sha256Hex(m map[string]any, k string) (string, error) {
	s, err := str(m, k)
	if err != nil {
		return "", err
	}
	if !validSHA256(s) {
		return "", fmt.Errorf("field %q must be 64 lowercase hex digits", k)
	}
	return s, nil
}

func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// sortedUnique reports whether ids are strictly increasing (ASCII).
func sortedUnique(ids []string) bool {
	for i := 1; i < len(ids); i++ {
		if ids[i-1] >= ids[i] {
			return false
		}
	}
	return true
}
