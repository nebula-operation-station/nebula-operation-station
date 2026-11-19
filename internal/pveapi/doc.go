// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pveapi is a typed client for the Proxmox VE JSON API (ADR 0006,
// ADR 0008). It has two halves in separate types, so a read path cannot
// issue a mutation by accident:
//
//   - Readers (Client, MetricsClient and the cluster, backup, storage,
//     snapshot, task, inventory, agent and hardware readers) issue GET
//     requests only. Their responses are decoded and reduced to nonsecret
//     evidence.
//   - Writer (write*.go, ADR 0008 PV-02) is the only type in this package
//     that sends POST, PUT or DELETE requests. It exposes a closed set of
//     typed methods: create from image, clone, config set, disk resize,
//     start, shutdown, reboot, stop, reset, migrate, convert to template,
//     backup now, node reboot, snapshot create, delete and rollback,
//     storage download-url, and task status. Callers pass typed request
//     values, not URLs or raw PVE parameters. The one caller-supplied URL is
//     DownloadRequest.SourceURL: it must be an absolute https URL without
//     user info, query or fragment, and it is sent with a SHA-256 checksum.
//     Its consumer is the executor (internal/executor), which builds Writer
//     with the PVE action token for mutations and with the read token for
//     task-status lookups (pve_mutation_client.go).
//
// Untrusted responses: every response from a PVE host is untrusted input.
// Response bodies are size-limited (see the Max* constants next to each
// reader and MaxWriteResponseBytes for Writer), decoded against explicit
// schemas, and range- or UTF-8-checked. Most readers ignore unknown JSON
// fields; the guest-agent file read (agent_file.go) rejects them.
//
// Unavailable versus empty: a dataset that cannot be read is reported in
// one of two ways, and both stay distinct from "empty" (a valid response
// with no entries). A failed Client request returns an error, and
// MetricsClient wraps ErrUnavailable. Backup and storage dataset readers
// return an UnavailableDataset value that carries a reason instead of an
// error. HA status returns an HAStatus with the unavailable part marked and
// a nil error.
//
// Credentials and errors: the package stores no secret values. The caller
// injects a ready *http.Client (TLS trust and certificate pinning are the
// caller's responsibility), the base URL, and token or auth-header
// suppliers (TokenSupplier, AuthHeaderSupplier). The package does not log.
// Errors never contain tokens or auth header values, and they do not quote
// response bodies. They may contain the request path (node, vmid and
// storage ids are part of it), rejected names and ids (for example an
// invalid storage id or snapshot name, quoted), and ErrSnapshotNotFound
// includes the snapshot name.
package pveapi
