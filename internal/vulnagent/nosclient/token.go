// SPDX-License-Identifier: AGPL-3.0-or-later

package nosclient

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// MaxTokenBytes bounds the token; the server refuses longer bearer tokens.
const MaxTokenBytes = 256

// redacted replaces the token wherever it might be printed.
const redacted = "[REDACTED]"

var (
	// ErrTokenFilePermissions: the token file is readable or writable by
	// group or others, or is not a regular file.
	ErrTokenFilePermissions = errors.New("token file must be a regular file with mode 0600 or 0400")
	// ErrTokenMalformed: the token file does not hold exactly one token of
	// printable ASCII without spaces.
	ErrTokenMalformed = errors.New("token file content is malformed")
)

// Token is the agent's API bearer token. Its value is unexported and every
// way of printing, logging or encoding a Token yields a placeholder, so it
// cannot end up in logs, errors or results by accident.
type Token struct {
	value string
}

// String returns a placeholder, never the token.
func (Token) String() string { return redacted }

// GoString returns a placeholder, never the token.
func (Token) GoString() string { return redacted }

// Format prints a placeholder for every verb.
func (Token) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, redacted) }

// LogValue makes log/slog print a placeholder.
func (Token) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalJSON encodes a placeholder.
func (Token) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// MarshalText encodes a placeholder.
func (Token) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// redact replaces every occurrence of the token in s.
func (t Token) redact(s string) string {
	if t.value == "" {
		return s
	}
	return strings.ReplaceAll(s, t.value, redacted)
}

// LoadToken reads the bearer token from path. The file must be a regular
// file that neither group nor others can access (mode 0600 or 0400) and
// hold one token of printable ASCII, optionally followed by a newline.
// Errors name the path but never the content.
func LoadToken(path string) (Token, error) {
	if path == "" {
		return Token{}, errors.New("load token: no token file configured")
	}
	f, err := os.Open(path)
	if err != nil {
		return Token{}, fmt.Errorf("load token: %w", err)
	}
	defer f.Close()
	// Stat the opened file, not the path, so the checked file is the read
	// one.
	fi, err := f.Stat()
	if err != nil {
		return Token{}, fmt.Errorf("load token %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
		return Token{}, fmt.Errorf("load token %s (mode %v): %w", path, fi.Mode(), ErrTokenFilePermissions)
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxTokenBytes+2))
	if err != nil {
		return Token{}, fmt.Errorf("load token %s: %w", path, err)
	}
	s := string(raw)
	s = strings.TrimSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\r")
	if s == "" || len(s) > MaxTokenBytes {
		return Token{}, fmt.Errorf("load token %s: %w", path, ErrTokenMalformed)
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return Token{}, fmt.Errorf("load token %s: %w", path, ErrTokenMalformed)
		}
	}
	return Token{value: s}, nil
}
