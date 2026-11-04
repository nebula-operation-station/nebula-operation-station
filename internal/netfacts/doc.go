// SPDX-License-Identifier: AGPL-3.0-or-later
// Package netfacts parses host network facts: the JSON output of
// `ip -j neigh` and `ip -j route` (and `ip -6 -j route`) collected by the
// net.facts read action (ADR 0009 D1).
//
// The parsers are pure functions with no I/O and no dependencies beyond the
// standard library. Every byte of input is untrusted data from a managed
// host (spec 09): documents are bounded in size, entry counts are bounded,
// strings are validated as printable UTF-8, unknown JSON fields are
// dropped, and malformed entries are skipped rather than guessed. An
// oversize or non-array document is an error, never an empty result, so
// incomplete data is never presented as a complete empty dataset. A table
// that lost entries or fields carries Incomplete (and a Dropped count), so
// a partial table is never presented as complete. IPv6 zones are accepted
// only as short interface names. The parsers never panic on any input.
package netfacts
