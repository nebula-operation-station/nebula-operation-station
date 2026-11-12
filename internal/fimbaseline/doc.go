// SPDX-License-Identifier: AGPL-3.0-or-later

// Package fimbaseline holds the per-host I2 baseline model of ADR 0015 D7
// and compares a parsed fim-scan-v1 result (package fimscan) with it.
//
// It is a pure library: no database, no UI, no clock, no I/O. A Baseline is
// built only from a complete scan and carries a SHA-256 digest over a fixed
// canonical encoding (see Baseline.Digest). Diff returns one Deviation per
// path that differs, sorted by raw path bytes, each with the ADR 0015 D9
// class (critical or normal) decided from executor-side data only.
//
// Not covered here (later IG-06/IG-07/IG-08 parts): the store, approvals and
// proposals, severities, expected-change attribution, findings and the
// derivation of the SSH configuration set (d) from sshd_config.
package fimbaseline
