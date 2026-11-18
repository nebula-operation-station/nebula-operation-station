// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pveapi is a typed client for the Proxmox VE JSON API (ADR 0006,
// ADR 0008). It has two halves in separate types, so a read path cannot
// issue a mutation by accident:
//
//   - Readers (Client, MetricsClient and the cluster, backup, storage,
//     snapshot, task and hardware readers) issue GET requests only. Their
//     responses are read back by typed readers and reduced to nonsecret
//     evidence.
//   - Writer (write*.go, ADR 0008 PV-02) is the only mutation type in this
//     package. It exposes a closed allowlist of typed provisioning calls
//     (POST, PUT and DELETE requests such as clone, config set, resize,
//     start, snapshot and template conversion) and task status. It has no
//     free-form URL or parameter input. Its consumer is the executor
//     (internal/executor), which constructs it with the PVE action token.
//
// Untrusted responses: every response from a PVE host is untrusted input.
// Response bodies are size-limited (see the Max* constants next to each
// reader and MaxWriteResponseBytes for Writer), decoded against explicit
// schemas, and range- or UTF-8-checked. Unknown fields are ignored.
// "Unavailable" (endpoint missing, unreachable, timeout or HTTP error) is
// reported as an error and kept distinct from "empty" (a valid response
// with no entries).
//
// Credentials and TLS: the package stores no secret values. The caller
// injects a ready *http.Client (TLS trust and certificate pinning are the
// caller's responsibility), the base URL, and token or auth-header
// suppliers (TokenSupplier, AuthHeaderSupplier). Neither Client nor Writer
// logs request headers or response bodies, and errors never contain
// response content, request values or token values.
package pveapi
