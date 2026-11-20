// SPDX-License-Identifier: AGPL-3.0-or-later

// Package vulninventory stores NOS's versioned reads of each host's installed
// source packages in server.db (table vuln_inventory_reads, migration 0052;
// ADR 0011 D3 and D5).
//
// Every read is immutable: Put only inserts, and an identical read is a new
// row. The newest read of a host is the one with the highest read_at, then
// the highest id; the last complete read is the newest one with complete set.
// The closure classes of ADR 0011 D5 use these two reads.
//
// The store deletes no reads. Retention of package reads (ADR 0011 D6, decision
// E1 in docs/implementation/vuln-inventory-decisions.md) is not decided yet.
//
// Inputs are checked against the named limits in store.go and rejected, never
// truncated. Package names, versions and architectures must match the export's
// ASCII patterns. The package uses database/sql only and has no dependency on
// other NOS packages.
package vulninventory
