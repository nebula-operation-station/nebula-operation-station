// SPDX-License-Identifier: AGPL-3.0-or-later

// Package reputation validates IP reputation snapshots and matches addresses
// against them (ADR 0012 D6, NS-15 and NS-16 part 1).
//
// The package is a pure library: it holds no store, no API, sends no
// notification, performs no I/O and reads no clock. Snapshot content comes
// from a managed feed and is untrusted (AGENTS.md rule 6); every value is
// checked before it reaches a caller, and every limit is a named constant or
// an explicit parameter.
package reputation

// Prefix-length minimums (ADR 0012 D6, accepted with Q3). A shorter prefix
// is dropped as too broad: one poisoned entry must not mark a large block.
const (
	// MinPrefixV4 is the shortest IPv4 prefix length a snapshot may carry.
	MinPrefixV4 = 16
	// MinPrefixV6 is the shortest IPv6 prefix length a snapshot may carry.
	MinPrefixV6 = 32
	// MaxCategoryBytes caps the length of one feed category label.
	MaxCategoryBytes = 32
)

// Caps are the entry caps for one validation run. ADR 0012 D6 requires
// per-feed and total caps as named constants but does not give their values,
// so the caller supplies them. Both must be positive. An over-cap snapshot is
// refused as a whole, never trimmed.
type Caps struct {
	// PerFeed is the most entries one snapshot may carry.
	PerFeed int
	// Total is the most kept entries across all feeds (see CheckTotal).
	Total int
}
