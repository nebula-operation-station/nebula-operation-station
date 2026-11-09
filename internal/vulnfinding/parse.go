// SPDX-License-Identifier: AGPL-3.0-or-later

package vulnfinding

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

// jsonKeyRe is the only accepted spelling of an object key. encoding/json
// matches keys case-insensitively (with Unicode folding); allowing only the
// lower-case ASCII spelling of the schema makes that matching exact.
var jsonKeyRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// ParseRecord decodes and validates one finding record and computes its
// key. The body must be a single JSON object of at most MaxRecordBytes in
// strict UTF-8 with no duplicate, non-canonical or unknown keys.
func ParseRecord(data []byte) (Finding, error) {
	if len(data) > MaxRecordBytes {
		return Finding{}, fmt.Errorf("record of %d bytes: %w", len(data), ErrTooLarge)
	}
	if !utf8.Valid(data) {
		return Finding{}, ErrInvalidUTF8
	}
	if err := checkJSONShape(data); err != nil {
		return Finding{}, err
	}
	var r Record
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		if strings.HasPrefix(err.Error(), "json: unknown field ") {
			// The field name is not repeated: it is untrusted input.
			return Finding{}, ErrUnknownField
		}
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			return Finding{}, fmt.Errorf("%s: wrong JSON type: %w", typeErr.Field, ErrMalformed)
		}
		return Finding{}, fmt.Errorf("decode record: %w", ErrMalformed)
	}
	return Validate(r)
}

// checkJSONShape walks the tokens once: a single top-level object, bounded
// depth, keys in canonical spelling and unique per object, and no string
// that decoded to U+FFFD (encoding/json replaces escaped lone surrogates
// with it silently).
func checkJSONShape(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	type frame struct {
		object    bool
		expectKey bool
		keys      map[string]struct{}
	}
	var stack []*frame
	first := true
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			if first || len(stack) != 0 {
				return fmt.Errorf("unexpected end of record: %w", ErrMalformed)
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("record syntax: %w", ErrMalformed)
		}
		if !first && len(stack) == 0 {
			return fmt.Errorf("data after the record: %w", ErrMalformed)
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		isKey := top != nil && top.object && top.expectKey
		if d, ok := tok.(json.Delim); ok && (d == '}' || d == ']') {
			stack = stack[:len(stack)-1]
			if len(stack) > 0 && stack[len(stack)-1].object {
				stack[len(stack)-1].expectKey = true
			}
			continue
		}
		if first {
			if d, ok := tok.(json.Delim); !ok || d != '{' {
				return fmt.Errorf("record is not a JSON object: %w", ErrMalformed)
			}
		}
		first = false
		if isKey {
			k, _ := tok.(string)
			if strings.ContainsRune(k, utf8.RuneError) {
				return ErrInvalidUTF8
			}
			if !jsonKeyRe.MatchString(k) {
				return fmt.Errorf("non-canonical object key: %w", ErrMalformed)
			}
			if _, dup := top.keys[k]; dup {
				return fmt.Errorf("duplicate object key: %w", ErrMalformed)
			}
			top.keys[k] = struct{}{}
			top.expectKey = false
			continue
		}
		switch v := tok.(type) {
		case json.Delim: // '{' or '['
			if len(stack) >= maxJSONDepth {
				return fmt.Errorf("record nested too deep: %w", ErrMalformed)
			}
			f := &frame{object: v == '{', expectKey: v == '{'}
			if f.object {
				f.keys = make(map[string]struct{})
			}
			stack = append(stack, f)
			continue
		case string:
			if strings.ContainsRune(v, utf8.RuneError) {
				return ErrInvalidUTF8
			}
		}
		if top != nil && top.object {
			top.expectKey = true
		}
	}
}
