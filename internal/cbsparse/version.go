// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cbsparse contains parsers for Cisco CBS CLI output. The
// parsers are pure functions with no I/O: they take raw command output
// bytes and return validated, typed values. Test fixtures are synthetic
// until ND-03 records lab fixtures.
package cbsparse

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// versionMaxLines bounds the lines of a "show version" output. The ADR
// 0010 D3 table names a line limit only for show running-config and show
// startup-config (netdevcontract.MaxConfigLines); a real "show version"
// is a few dozen lines, so this unexported bound sits far above any real
// output and keeps hostile line floods refused by a named limit.
const versionMaxLines = 1000

// ErrInvalidValue reports a recognised field whose value violates the
// netdevcontract text rule (a tab, U+FFFD or a non-printable rune).
var ErrInvalidValue = errors.New("cbsparse: invalid field value text")

// Version is the parsed result of "show version" on a CBS switch.
// Incomplete is true when at least one of Model, Firmware or Serial was
// not present in the output; that is a data gap, not an error.
type Version struct {
	Model    string
	Firmware string
	Serial   string
	// Incomplete reports that at least one field was missing.
	Incomplete bool
}

// versionTarget names the Version field a key fills.
type versionTarget int

const (
	targetModel versionTarget = iota
	targetFirmware
	targetSerial
	numTargets
)

// versionFields lists every recognised "show version" key. A key matches
// only as the complete key of a line (see splitKeyValue), never as a
// prefix of a longer key: "Firmware Date", "Model Number", "Serial No."
// and "ModelX" are unknown keys and ignored.
//
// rank orders keys for the same field by specificity, 0 being the most
// specific. A more specific key always wins over a less specific one,
// regardless of line order, so the generic "Version" fallback never beats
// "Firmware Version". Among occurrences of the same rank the first one
// wins: on CBS output the active image block, with its "Version:" line,
// is printed before the inactive image block. ND-03 checks this order
// against recorded lab output.
var versionFields = []struct {
	key    string
	target versionTarget
	rank   int
}{
	{"Model", targetModel, 0},
	{"Firmware Version", targetFirmware, 0},
	{"Firmware", targetFirmware, 1},
	{"Version", targetFirmware, 2},
	{"Serial Number", targetSerial, 0},
	{"Serial", targetSerial, 1},
}

// ParseVersion parses the output of "show version" on a CBS switch.
//
// The input is untrusted device text (spec 09). It is first checked with
// netdevcontract.CheckLines against the transport byte cap for non-config
// CBS commands, the line limit above and the per-line byte limit; invalid
// UTF-8 and control characters anywhere in the output are refused. Each
// line is then split into a key and a value at the first separator (a
// colon or a column gap of a tab or two or more spaces); unknown keys are
// ignored. A field value longer than netdevcontract.MaxLabelBytes is an
// error matching netdevcontract.ErrOverLimit; a value that violates the
// netdevcontract text rule is an error matching ErrInvalidValue. Fields
// that are absent (or present without a value) leave the corresponding
// Version field empty and set Incomplete; that is not an error. When
// several keys fill the same field, the most specific key wins, and among
// equally specific keys the first occurrence wins (see versionFields).
func ParseVersion(out []byte) (Version, error) {
	if err := netdevcontract.CheckLines(out, netdevcontract.MaxCBSCommandOutputBytes, versionMaxLines); err != nil {
		return Version{}, fmt.Errorf("cbsparse: show version: %w", err)
	}
	var (
		values [numTargets]string
		ranks  [numTargets]int
	)
	for i := range ranks {
		ranks[i] = -1
	}
	for i, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if err := checkLineText(line); err != nil {
			return Version{}, fmt.Errorf("cbsparse: show version line %d: %w", i+1, err)
		}
		key, value := splitKeyValue(strings.TrimSpace(line))
		for _, f := range versionFields {
			if key != f.key {
				continue
			}
			if value == "" {
				// A key without a value counts as missing.
				break
			}
			if err := netdevcontract.CheckCount("version field value bytes", len(value), netdevcontract.MaxLabelBytes); err != nil {
				return Version{}, fmt.Errorf("cbsparse: show version field %q: %w", f.key, err)
			}
			if !validValueText(value) {
				return Version{}, fmt.Errorf("cbsparse: show version field %q line %d: %w", f.key, i+1, ErrInvalidValue)
			}
			if ranks[f.target] < 0 || f.rank < ranks[f.target] {
				values[f.target] = value
				ranks[f.target] = f.rank
			}
			break
		}
	}
	v := Version{
		Model:    values[targetModel],
		Firmware: values[targetFirmware],
		Serial:   values[targetSerial],
	}
	v.Incomplete = v.Model == "" || v.Firmware == "" || v.Serial == ""
	return v, nil
}

// splitKeyValue splits a trimmed line at its first separator: a colon or
// a column gap (a tab, or two or more spaces). The key is the text before
// the separator without trailing spaces; after a column gap an optional
// colon is skipped ("Serial Number    :  X"). A line without a separator
// is all key and has no value. A single space never separates, so
// "Firmware Date : 2020" has the key "Firmware Date".
func splitKeyValue(line string) (key, value string) {
	for i := 0; i < len(line); i++ {
		switch {
		case line[i] == ':':
			return strings.TrimRight(line[:i], " "), strings.TrimSpace(line[i+1:])
		case line[i] == '\t', line[i] == ' ' && i+1 < len(line) && line[i+1] == ' ':
			rest := strings.TrimLeft(line[i:], " \t")
			rest = strings.TrimPrefix(rest, ":")
			return line[:i], strings.TrimSpace(rest)
		}
	}
	return line, ""
}

// validValueText mirrors the unexported netdevcontract validText rule for
// a field value (the length limit is checked separately so that it keeps
// matching ErrOverLimit): valid UTF-8 and every rune printable, which
// excludes tabs and U+FFFD.
func validValueText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// checkLineText rejects control characters and format runes in one line
// of device output. netdevcontract.CheckLines already validated UTF-8 and
// the byte limits; its printable-rune helper is not exported, so the spec
// 09 rule is applied here: every rune must be printable (which includes
// U+0020) or a tab used for spacing.
//
// This check runs on every line, including lines with unknown keys that
// are otherwise ignored. That is a deliberate fail-closed choice: a stray
// control byte anywhere refuses the whole output instead of skipping the
// line, because a terminal escape or injected control sequence means the
// output cannot be trusted as a whole. ND-03 checks this against recorded
// lab output; if real CBS output carries control bytes in ignored lines,
// the choice is revisited there, not loosened silently.
func checkLineText(line string) error {
	for _, r := range line {
		if r != '\t' && !unicode.IsPrint(r) {
			return fmt.Errorf("control character U+%04X in line", r)
		}
	}
	return nil
}
