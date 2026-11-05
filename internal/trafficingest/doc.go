// SPDX-License-Identifier: AGPL-3.0-or-later

// Package trafficingest turns net.facts results into traffic map data
// (ADR 0009, TM12): observed endpoints, hourly flow buckets and the hop
// through each host's gateway.
//
// For every managed host the server knows, the Ingester takes the latest
// successful net.facts result from the executions, decodes it with the
// bounded net.facts decoder, diffs its socket table against the host's
// previous snapshot with internal/flowagg and writes endpoints and
// buckets through internal/trafficstore. It never creates assets, hosts
// or placements; endpoints are facts (D2).
//
// Trust rules (spec 09, ADR 0009 "a compromised host can lie"):
//
//   - The reporter label of every endpoint and bucket, and the host of
//     every flowagg report, is the execution's target host as the server
//     recorded it, never a value from the host's output.
//   - The snapshot time is the server's finish time of the execution,
//     not a host clock.
//   - The addresses and MACs a host may speak for (flowagg's own,
//     trafficstore.Identity) come only from the server's own records of
//     that host (Records), with values claimed by more than one host
//     removed (Exclusive). The host's self-reported addresses never widen
//     them.
//   - A result whose socket section is cut, invalid or incomplete does
//     not produce flows: the next complete snapshot starts a fresh
//     baseline, so a socket hidden once cannot count its lifetime
//     counters a second time.
//
// Idempotency: an execution is ingested at most once per host. The
// Ingester remembers the last ingested execution per host; seeing it
// again changes nothing. Bytes are counted only from a diff between two
// consecutive snapshots the Ingester saw itself; the first snapshot after
// a start (or after a gap longer than flowagg.DefaultMaxInterval,
// flowagg.ErrIntervalTooLong) is a baseline that writes endpoints but no
// bytes. A restart therefore never counts a diff twice. The in-memory
// flowagg.Aggregator refuses overlapping reports (ErrDuplicateReport) as
// a second guard before any bucket is written.
//
// Ownership reconciliation (TM11b): Sync calls
// trafficstore.Store.ReconcileIdentities with the current identities
// whenever the server's host records changed and at least once per clock
// hour, together with the hourly Prune.
package trafficingest
