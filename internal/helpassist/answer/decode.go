// SPDX-License-Identifier: AGPL-3.0-or-later

package answer

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

// errSchema is the internal reason for a rejection. Decode never returns it:
// every rejection is reported as ErrInvalidAnswer, so no reason or fragment
// of the answer can leak into an error.
var errSchema = errors.New("schema")

// Decode decodes one model answer strictly (ADR 0014 D4). raw must be exactly
// one JSON object, surrounded only by JSON whitespace. Decode rejects, with
// ErrInvalidAnswer and nothing repaired:
//   - more than MaxAnswerBytes bytes, or input that is not valid UTF-8;
//   - a lone or malformed surrogate escape, which encoding/json would turn
//     into U+FFFD without a trace;
//   - text before or after the object, a second object, or a Markdown fence;
//   - an unknown field, a duplicate field (also in a step), or a field with a
//     different case;
//   - a wrong type, including null for any field;
//   - a missing required field (in_scope, language, summary, steps, citations)
//     or a missing step text;
//   - a language other than "de" or "en", a where other than the three
//     values of D4, or an empty command;
//   - more than MaxSteps steps, or a text or command over its limit, or a
//     command that spans more than one line.
//
// An empty summary and an empty step text are valid: the schema allows them.
// citations may be empty and may repeat an ID; MapCitations deals with that.
func Decode(raw []byte) (Answer, error) {
	if len(raw) > MaxAnswerBytes || !utf8.Valid(raw) || !escapesWellFormed(raw) {
		return Answer{}, ErrInvalidAnswer
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var a Answer
	if err := decodeAnswer(dec, &a); err != nil {
		return Answer{}, ErrInvalidAnswer
	}
	// Exactly one value: anything after the object is an error, including a
	// second object. io.EOF is the only accepted end.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Answer{}, ErrInvalidAnswer
	}
	return a, nil
}

// decodeAnswer reads the top-level object of D4.
func decodeAnswer(dec *json.Decoder, a *Answer) error {
	seen, err := walkObject(dec, func(key string) error {
		switch key {
		case "in_scope":
			v, err := readBool(dec)
			if err != nil {
				return err
			}
			a.InScope = v
		case "language":
			s, err := readString(dec)
			if err != nil {
				return err
			}
			switch Language(s) {
			case LanguageDE, LanguageEN:
				a.Language = Language(s)
			default:
				return errSchema
			}
		case "summary":
			s, err := readString(dec)
			if err != nil {
				return err
			}
			if len(s) > MaxSummaryBytes {
				return errSchema
			}
			a.Summary = s
		case "steps":
			return decodeSteps(dec, a)
		case "citations":
			return decodeCitations(dec, a)
		default:
			return errSchema
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, key := range []string{"in_scope", "language", "summary", "steps", "citations"} {
		if !seen[key] {
			return errSchema
		}
	}
	return nil
}

// decodeSteps reads the steps array: at most MaxSteps objects.
func decodeSteps(dec *json.Decoder, a *Answer) error {
	a.Steps = []Step{}
	return walkArray(dec, func() error {
		if len(a.Steps) == MaxSteps {
			return errSchema
		}
		var s Step
		seen, err := walkObject(dec, func(key string) error {
			switch key {
			case "text":
				v, err := readString(dec)
				if err != nil {
					return err
				}
				if len(v) > MaxStepTextBytes {
					return errSchema
				}
				s.Text = v
			case "command":
				v, err := readString(dec)
				if err != nil {
					return err
				}
				if err := checkCommand(v); err != nil {
					return err
				}
				s.Command = v
			case "where":
				v, err := readString(dec)
				if err != nil {
					return err
				}
				switch Where(v) {
				case WhereNebulaHost, WhereManagedHost, WhereBrowser:
					s.Where = Where(v)
				default:
					return errSchema
				}
			default:
				return errSchema
			}
			return nil
		})
		if err != nil {
			return err
		}
		if !seen["text"] {
			return errSchema
		}
		a.Steps = append(a.Steps, s)
		return nil
	})
}

// decodeCitations reads the citations array of strings. Duplicates and IDs
// that were not prompted are decoded here; MapCitations removes them.
func decodeCitations(dec *json.Decoder, a *Answer) error {
	a.Citations = []string{}
	return walkArray(dec, func() error {
		v, err := readString(dec)
		if err != nil {
			return err
		}
		a.Citations = append(a.Citations, v)
		return nil
	})
}

// checkCommand applies the limits of D4 to a command: non-empty, at most
// MaxCommandBytes bytes, and no line break. Other characters are checked by
// helpcmd.CheckASCII where the command is shown.
func checkCommand(s string) error {
	if s == "" || len(s) > MaxCommandBytes || strings.ContainsFunc(s, isLineBreak) {
		return errSchema
	}
	return nil
}

// isLineBreak reports whether r ends a line for the one-line rule of a
// command: CR, LF, VT, FF, next line (U+0085), line separator (U+2028) and
// paragraph separator (U+2029). Every one of them starts a new line in some
// renderer, so none may appear in a command.
func isLineBreak(r rune) bool {
	switch r {
	case '\r', '\n', '\v', '\f', 0x85, 0x2028, 0x2029:
		return true
	}
	return false
}

// walkObject reads one JSON object. For every key it calls fn, which reads the
// value or returns errSchema for an unknown key. A key that occurs twice is
// an error. It returns the set of keys that were present.
func walkObject(dec *json.Decoder, fn func(key string) error) (map[string]bool, error) {
	if err := expectDelim(dec, '{'); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, errSchema
		}
		key, ok := tok.(string)
		if !ok || seen[key] {
			return nil, errSchema
		}
		seen[key] = true
		if err := fn(key); err != nil {
			return nil, err
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return nil, err
	}
	return seen, nil
}

// walkArray reads one JSON array and calls fn for every element.
func walkArray(dec *json.Decoder, fn func() error) error {
	if err := expectDelim(dec, '['); err != nil {
		return err
	}
	for dec.More() {
		if err := fn(); err != nil {
			return err
		}
	}
	return expectDelim(dec, ']')
}

// expectDelim reads the next token, which must be the delimiter want.
func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return errSchema
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return errSchema
	}
	return nil
}

// readString reads the next value, which must be a JSON string. null, a
// number, a boolean, an object or an array are errors.
func readString(dec *json.Decoder) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", errSchema
	}
	s, ok := tok.(string)
	if !ok {
		return "", errSchema
	}
	return s, nil
}

// readBool reads the next value, which must be a JSON boolean.
func readBool(dec *json.Decoder) (bool, error) {
	tok, err := dec.Token()
	if err != nil {
		return false, errSchema
	}
	b, ok := tok.(bool)
	if !ok {
		return false, errSchema
	}
	return b, nil
}

// escapesWellFormed reports whether every \u escape inside a JSON string is
// a scalar value or a proper surrogate pair. encoding/json replaces a lone
// surrogate with U+FFFD silently, so the check has to run on the raw bytes.
// The scan does not validate the rest of the syntax; the decoder does that.
func escapesWellFormed(raw []byte) bool {
	inString := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			if i+1 >= len(raw) {
				return false
			}
			if raw[i+1] != 'u' {
				i++
				continue
			}
			v, ok := hex4(raw, i+2)
			if !ok {
				return false
			}
			i += 5 // now at the last hex digit
			switch {
			case v >= 0xDC00 && v <= 0xDFFF:
				return false
			case v >= 0xD800 && v <= 0xDBFF:
				if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
					return false
				}
				w, ok := hex4(raw, i+3)
				if !ok || w < 0xDC00 || w > 0xDFFF {
					return false
				}
				i += 6
			}
		}
	}
	return true
}

// hex4 parses the four hex digits at raw[at:at+4].
func hex4(raw []byte, at int) (rune, bool) {
	if at < 0 || at+4 > len(raw) {
		return 0, false
	}
	var v rune
	for _, c := range raw[at : at+4] {
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, false
		}
		v = v<<4 | rune(d)
	}
	return v, true
}
