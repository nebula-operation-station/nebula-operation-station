// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pvecollect is the PVE collector and its server-side importers
// (ADR 0006, P1-10). The package has two sides, and the telemetry paths sit
// on different sides of that split.
//
// Collector side (cmd/nebula-pve-collector). The poll loop (Collector.PollOnce)
// schedules typed read requests over the executor's socket (gRPC,
// internal/rpc/executorv1), assembles sanitized observations and hands them
// to the spool: a bounded, descriptor-relative directory handoff (Spool). The
// LiveWatcher runs here too. It serves the server's live want-list with
// on-demand provider reads through the executor and publishes its samples to
// a LiveHandoff, not to the Spool. The collector opens no network listener,
// holds no PVE credentials (the executor owns the PVE connections) and does
// not touch a database. It still treats executor results as untrusted text.
//
// Server side (cmd/nebula-server). The SSH telemetry path runs here, not on
// the collector: SSHTelemetryReader and TelemetryScheduler are built by the
// live chart. The reader resolves hosts through TelemetryHosts, which
// inventory.Store implements, and issues its reads through the executor
// (RunReadGrant). Nothing on the collector side touches this path.
//
// The server-side importers read the spool and write the results to the
// database. Importer reads observations and ingests them into the
// pveinventory store (ImportOnce, via Store.IngestObservation).
// GuestNetImporter reads guest NIC records and hands each one to a
// GuestNetSink; GuestNetStoreSink is that sink and writes the guest NIC
// snapshots into the trafficstore. The importers never talk to PVE.
//
// So this package performs database writes through server-side paths:
// Importer (Store.IngestObservation into pveinventory), GuestNetStoreSink
// (the trafficstore) and BucketSink, which records telemetry samples into the
// pveinventory metric buckets through MetricRecorder. No production code in
// this tree constructs a BucketSink yet. The collector side never reaches
// these stores.
package pvecollect
