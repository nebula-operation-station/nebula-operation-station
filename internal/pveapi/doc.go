// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pveapi is a typed client for the Proxmox VE JSON API (ADR 0006,
// ADR 0008). It has two halves in separate types, so a read path cannot
// issue a mutation by accident:
//
//   - Readers issue GET requests only. Most are methods on *Client: the
//     cluster, backup, storage, snapshot, task, inventory, config, agent and
//     hardware readers, and Client.PlanSnapshotRollback (write_snapshot.go),
//     which reads the snapshot's RAM flag and mutates nothing. MetricsClient
//     (metrics.go) is the one reader with its own type. Responses are decoded
//     and reduced to nonsecret evidence.
//   - Writer (write*.go, ADR 0008 PV-02) is the only type in this package
//     that sends POST, PUT or DELETE requests. It exposes a closed set of
//     typed methods: create from image, clone, config set, disk resize,
//     start, shutdown, reboot, stop, reset, migrate, convert to template,
//     backup now, node reboot, snapshot create, delete and rollback, and
//     storage download-url. Its task-status lookup is a GET sent through the
//     same Writer. Callers pass typed request values, not URLs or raw PVE
//     parameters. The one caller-supplied URL is DownloadRequest.SourceURL:
//     it must be an absolute https URL without user info, query or fragment,
//     and it is sent with a SHA-256 checksum. Its consumer is the executor
//     (internal/executor), which builds each Writer with NewWriter: the PVE
//     action token for mutations, the read token for the task-status lookup.
//
// Untrusted responses: every response from a PVE host is untrusted input.
// Response bodies are size-limited (see the Max* constants next to each
// reader and MaxWriteResponseBytes for Writer), decoded against explicit
// schemas, and checked for valid UTF-8. Most readers ignore unknown JSON
// fields; the guest-agent file read (agent_file.go) rejects them.
//
// Unavailable versus empty: a dataset that cannot be read is never reported
// as empty (a valid response with no entries). How the failure is reported
// depends on the helper the reader uses:
//
//   - Client.get (ListStorages, GetStorage, ListSnapshots): any failed
//     request, including transport, timeout, non-2xx, oversize and invalid
//     JSON or schema, returns a *UnavailableError with a fixed reason;
//     errors.Is(err, ErrUnavailable) matches it.
//   - Client.do (inventory, config, agent and guest-agent file readers):
//     a non-2xx response returns a *StatusError, an oversize body returns
//     ErrResponseTooLarge, and transport or decode failures return wrapped
//     errors. Guest-agent readers turn some "agent not running" responses
//     into a value with Available=false and a Reason, and a nil error.
//   - Client.clusterGet (cluster status, node votes, HA, node tasks, node
//     PCI devices): a transport failure, timeout or non-2xx answer (404
//     included) is a Reason inside the returned value with a nil error.
//     Only token, readiness and malformed-response problems are errors.
//     HAStatus.NotConfigured separates "no HA manager" from "unknown".
//   - Backup readers (ReadBackups) report each unavailable dataset with
//     UnavailableDataset, a value that carries a reason; I/O and schema
//     errors are still returned as errors so the caller can retry.
//   - MetricsClient wraps ErrUnavailable for failed requests and ErrTooLarge
//     for oversize bodies.
//   - Writer reports failed requests as a *WriteError with a reason.
//
// Credentials and errors: the package stores no secret values. The caller
// injects a ready *http.Client (TLS trust and certificate pinning are the
// caller's responsibility), the base URL, and token or auth-header
// suppliers (TokenSupplier, AuthHeaderSupplier). The package does not log.
// Errors and Reason values never contain tokens or auth header values.
// They can contain the request path (node, vmid and storage ids are part
// of it), rejected names and ids (for example an invalid storage id or
// snapshot name, quoted), and ErrSnapshotNotFound includes the snapshot
// name.
//
// PVE response text is the one exception to "no response bodies": for a
// non-2xx response, StatusError.Message carries the "message", "error" or
// first "errors" field text of the body. That text is sanitized before use
// (invalid UTF-8 replaced, control characters removed) and capped at
// MaxErrorMessageBytes. Guest-agent Reason values can copy it too. Callers
// must treat it as untrusted text and render it as text only.
package pveapi
