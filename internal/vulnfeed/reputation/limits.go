// SPDX-License-Identifier: AGPL-3.0-or-later

// Package reputation is the pure parser library for the IP reputation feeds
// of ADR 0012 D6 (NS-14). It turns the bytes of a feed into normalised
// (CIDR, category) entries for upload.
//
// The package performs no network access, reads no configuration and no
// clock, and has no per-address lookup path: it only parses what it is
// given. Feed bytes are untrusted (AGENTS.md rule 6); every limit is a named
// constant below and is enforced before a value reaches a caller.
//
// Only the format-independent core is here. The per-feed file formats of
// Feodo, SSLBL, Spamhaus DROP/EDROP and FireHOL level1 are not documented in
// the repository (ADR 0012 marks them *verify*, and the NS-03 lab note is not
// in this tree), so no per-feed parser exists yet. Each feed is listed as
// open in the implementation report.
package reputation

// Named limits (ADR 0011 D4, ADR 0012 D6). Each is enforced in this package
// and tested at the limit and one past it.
const (
	// MaxFeedBytes caps the bytes read from one feed, checked before any
	// record is parsed. A feed over this size is refused as a whole.
	MaxFeedBytes = 8 << 20
	// MaxLineBytes caps one line of a feed (its raw length, without the
	// line terminator), comment lines included.
	MaxLineBytes = 256
	// MaxEntriesPerFeed caps the distinct entries one feed may yield.
	// Repeats of a stored entry do not count against it.
	MaxEntriesPerFeed = 1 << 18
)

// maxEntryTextBytes caps the text of one entry after blanks are trimmed. It
// is the longest IPv6 address with a prefix length (43 bytes).
const maxEntryTextBytes = 43

// Accepted content-date years. A date outside them is treated as undated.
const (
	minContentYear = 1970
	maxContentYear = 2999
)
