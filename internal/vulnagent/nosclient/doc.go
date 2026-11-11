// SPDX-License-Identifier: AGPL-3.0-or-later

// Package nosclient is the vulnerability agent's client for the NOS
// vulnerability API (ADR 0011 D3, D5), the counterpart of
// internal/web/api's VulnHandler.
//
// It reads the paginated inventory export (vuln-inventory-v1) bound to one
// snapshot ID and tracks which subjects arrived with all their parts, and it
// drives the run protocol: start, findings batches and complete. Batches
// and complete are retried with the same run ID, batch_seq and body, which
// the server treats as idempotent. The bearer token is read from a file
// that only its owner can access and is never logged or quoted in errors.
// TLS verifies the server against a pinned CA or the system pool; there is
// no way to turn verification off.
package nosclient
