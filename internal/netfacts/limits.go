// SPDX-License-Identifier: AGPL-3.0-or-later

package netfacts

import (
	"unicode/utf8"
)

// Shared limits for host network facts (ADR 0009 D1, spec 09). Every value
// read from a managed host is untrusted: bounded size, bounded count,
// printable UTF-8 text only.
const (
	// maxInputSize bounds the raw size of one `ip -j ...` JSON document in
	// bytes (1 MiB, spec 09).
	maxInputSize = 1 << 20
	// maxEntries bounds the number of entries a single document may yield.
	maxEntries = 4096
	// maxStringLen bounds any host-provided string field in bytes.
	maxStringLen = 253
	// maxStates bounds the state list of one neighbor entry. iproute2
	// reports at most one of the eight NUD states per entry.
	maxStates = 8
	// maxMetric bounds a route metric (iproute2 uses unsigned 32-bit
	// metrics).
	maxMetric = 1<<32 - 1
)

// printable reports whether s is non-empty printable UTF-8 text within
// limit bytes: valid UTF-8, no control characters, no line breaks, no DEL.
// Host-provided text that fails this check is dropped, never rendered
// (spec 09).
func printable(s string, limit int) bool {
	if s == "" || len(s) > limit {
		return false
	}
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unsafeRune(r) {
			return false
		}
	}
	return true
}

// unsafeRune reports whether r must not appear in host-provided text.
func unsafeRune(r rune) bool {
	switch {
	case r == '\n' || r == '\r' || r == '\t':
		return true
	case r < 0x20 || r == 0x7f:
		return true
	case !utf8.ValidRune(r):
		return true
	}
	return false
}
