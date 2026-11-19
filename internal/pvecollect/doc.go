// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pvecollect is the PVE collector and its server-side importers
// (ADR 0006, P1-10). It has two sides.
//
// Collector side: it schedules typed read requests over the executor's
// socket (gRPC, internal/rpc/executorv1), assembles sanitized observations
// and hands them to the spool: a bounded, descriptor-relative directory
// handoff (Spool). The live watcher, the poll loop and the SSH telemetry path
// all take this route through the executor. The collector never contacts a
// PVE endpoint itself, opens no network listener and holds no PVE
// credentials. The executor performs the reads and sanitizes the output, but
// the collector still treats executor results as untrusted text. The
// collector side does not touch a database.
//
// Server side: Importer reads observations from the spool and writes them
// into the pveinventory store (ImportOnce, via IngestObservation). The
// server never talks to PVE. GuestNetImporter reads guest NIC records from a
// server-side spool and hands each one to a GuestNetSink. GuestNetStoreSink
// is that sink: it writes the guest NIC snapshots into the trafficstore,
// which is backed by database/sql. So this package performs database writes
// through those two stores, and only on the server side.
package pvecollect
