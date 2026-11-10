// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cbsparse contains parsers for Cisco CBS CLI output. The
// parsers are pure functions with no I/O: they take raw command output
// bytes and return validated, typed values. Test fixtures are synthetic
// until ND-03 records lab fixtures.
package cbsparse

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/nebula-operation-station/nebula-operation-station/internal/netdevcontract"
)

// versionMaxLines bounds the lines of a "show version" output. The ADR
// 0010 D3 table names a line limit only for show running-config and show
// startup-config (netdevcontract.MaxConfigLines); a real "show version"
// is a few dozen lines, so this unexported bound sits far above any real
// output and keeps hostile line floods refused by a named limit.
const versionMaxLines = 1000

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

// versionField maps one known "show version" key to the Version field it
// fills. The order is significant: longer keys come before the shorter
// prefixes they contain ("Serial Number" before "Serial", "Firmware
// Version" before "Firmware"), so the first match is the most specific.
// Every setter only writes an empty field, so when a key occurs more
// than once the first occurrence wins.
var versionFields = []struct {
	key string
	set func(*Version, string)
}{
	{"Serial Number", func(v *Version, s string) {
		if v.Serial == "" {
			v.Serial = s
		}
	}},
	{"Firmware Version", func(v *Version, s string) {
		if v.Firmware == "" {
			v.Firmware = s
		}
	}},
	{"Firmware", func(v *Version, s string) {
		if v.Firmware == "" {
			v.Firmware = s
		}
	}},
	{"Serial", func(v *Version, s string) {
		if v.Serial == "" {
			v.Serial = s
		}
	}},
	{"Model", func(v *Version, s string) {
		if v.Model == "" {
			v.Model = s
		}
	}},
	{"Version", func(v *Version, s string) {
		if v.Firmware == "" {
			v.Firmware = s
		}
	}},
}

// ParseVersion parses the output of "show version" on a CBS switch.
//
// The input is untrusted device text (spec 09). It is first checked with
// netdevcontract.CheckLines against the transport byte cap for non-config
// CBS commands, the line limit above and the per-line byte limit; invalid
// UTF-8 and control characters are refused. The parser then reads
// "key  value" lines tolerant to spacing and an optional colon; unknown
// lines are ignored. A field value longer than the netdevcontract label
// limit is an error. Fields that are absent (or present without a value)
// leave the corresponding Version field empty and set Incomplete; that is
// not an error. If a key occurs more than once, the first occurrence
// wins.
func ParseVersion(out []byte) (Version, error) {
	if err := netdevcontract.CheckLines(out, netdevcontract.MaxCBSCommandOutputBytes, versionMaxLines); err != nil {
		return Version{}, fmt.Errorf("cbsparse: show version: %w", err)
	}
	var v Version
	for i, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if err := checkLineText(line); err != nil {
			return Version{}, fmt.Errorf("cbsparse: show version line %d: %w", i+1, err)
		}
		trimmed := strings.TrimSpace(line)
		for _, f := range versionFields {
			if !strings.HasPrefix(trimmed, f.key) {
				continue
			}
			rest := trimmed[len(f.key):]
			// The key must end at a separator (space, tab or colon) or
			// at the end of the line, so "ModelX" is not "Model".
			if rest != "" && rest[0] != ' ' && rest[0] != '\t' && rest[0] != ':' {
				continue
			}
			rest = strings.TrimLeft(rest, " \t")
			rest = strings.TrimPrefix(rest, ":")
			value := strings.TrimSpace(rest)
			if value == "" {
				// A key without a value counts as missing.
				break
			}
			if err := netdevcontract.CheckCount("version field value bytes", len(value), netdevcontract.MaxLabelBytes); err != nil {
				return Version{}, fmt.Errorf("cbsparse: show version field %q: %w", f.key, err)
			}
			f.set(&v, value)
			break
		}
	}
	v.Incomplete = v.Model == "" || v.Firmware == "" || v.Serial == ""
	return v, nil
}

// checkLineText rejects control characters and format runes in one line
// of device output. netdevcontract.CheckLines already validated UTF-8 and
// the byte limits; its printable-rune helper is not exported, so the spec
// 09 rule is applied here: every rune must be printable (which includes
// U+0020) or a tab used for spacing.
func checkLineText(line string) error {
	for _, r := range line {
		if r != '\t' && !unicode.IsPrint(r) {
			return fmt.Errorf("control character U+%04X in line", r)
		}
	}
	return nil
}
