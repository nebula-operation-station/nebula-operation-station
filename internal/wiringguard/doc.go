// SPDX-License-Identifier: AGPL-3.0-or-later

// Package wiringguard makes "built but not wired" visible.
//
// It reads the import declarations (go/parser, ImportsOnly) of every
// non-test Go file in a module and computes which package directories are
// reachable from the package main programs under cmd/. Every package under
// internal/ (and every package main outside cmd/) that has production code
// but is not reachable is a finding, unless internal/wiringguard/allowlist.txt
// records why it is not wired yet.
//
// Rules:
//   - Reachability follows module-internal imports transitively. Imports in
//     _test.go files do not count, so a package imported only by tests is a
//     finding.
//   - Imports are taken from all non-test files of a package, including
//     generated files and files behind build constraints. This over-approximates
//     reachability, so the guard reports gaps rather than false alarms.
//   - A package made only of generated files is not checked itself, but its
//     imports still count while its package is reachable.
//   - Allowlist entries need a reason and a ticket. An entry whose package is
//     reachable now is reported as informational only. An entry that names no
//     checked package is stale and is reported as a finding.
//
// The package uses only the standard library and reads only the module tree.
package wiringguard
