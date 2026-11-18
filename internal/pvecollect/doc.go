// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pvecollect is the PVE collector (ADR 0006, P1-10). It schedules
// typed read requests over the executor's socket (gRPC, internal/rpc/executorv1),
// assembles sanitized observations and hands them to the spool: a bounded,
// descriptor-relative directory handoff (Spool). The live watcher and the SSH
// telemetry path take the same route through the executor.
//
// The package never contacts a PVE endpoint itself, opens no network
// listener, imports no database and holds no PVE credentials. The executor
// performs the reads and sanitizes the output, but the collector still treats
// executor results as untrusted text.
package pvecollect
