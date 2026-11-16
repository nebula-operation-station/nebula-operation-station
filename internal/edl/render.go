// SPDX-License-Identifier: AGPL-3.0-or-later

package edl

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"slices"
)

// ErrTooManyEntries means the input exceeds MaxEntries. Nothing is rendered.
var ErrTooManyEntries = fmt.Errorf("edl: list exceeds %d entries", MaxEntries)

// Result is a rendered list.
type Result struct {
	// Body is the list text: one entry per line, LF line ends, ASCII only.
	// Empty for an empty list.
	Body []byte
	// Count is the number of entries in Body.
	Count int
	// Digest is the lowercase hex SHA-256 of Body.
	Digest string
}

// Render checks every entry against r (ADR 0012 D7: refusals are checked on
// every publish), then returns the sorted, de-duplicated list. Networks are
// written in masked canonical form. A host (/32 or /128) is written as a bare
// address. Output does not depend on input order.
//
// The input may hold at most MaxEntries entries; duplicates count toward this
// limit. Over the limit, or on any refused entry, Render returns an error and
// no partial output. The input slice is not modified.
func Render(entries []netip.Prefix, r Refusals) (Result, error) {
	if len(entries) > MaxEntries {
		return Result{}, fmt.Errorf("%w: got %d", ErrTooManyEntries, len(entries))
	}
	canon := make([]netip.Prefix, 0, len(entries))
	for i, e := range entries {
		if err := Check(e, r); err != nil {
			return Result{}, fmt.Errorf("render entry %d: %w", i, err)
		}
		canon = append(canon, e.Masked())
	}
	slices.SortFunc(canon, comparePrefix)
	canon = slices.Compact(canon)

	var buf bytes.Buffer
	for _, p := range canon {
		buf.WriteString(formatEntry(p))
		buf.WriteByte('\n')
	}
	body := buf.Bytes()
	sum := sha256.Sum256(body)
	return Result{
		Body:   body,
		Count:  len(canon),
		Digest: hex.EncodeToString(sum[:]),
	}, nil
}

// comparePrefix orders by address (IPv4 before IPv6, then numerically), then
// by prefix length.
func comparePrefix(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}

// formatEntry writes a host as a bare address and a network in CIDR form.
// The prefix must be masked.
func formatEntry(p netip.Prefix) string {
	if p.Bits() == p.Addr().BitLen() {
		return p.Addr().String()
	}
	return p.String()
}
