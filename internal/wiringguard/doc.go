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
//   - A file with the "//go:build ignore" constraint is never compiled. It does
//     not make its directory a package main, and it is not production code, but
//     its imports still count, as those of other constrained files do.
//   - A package made only of generated or ignored files is not checked itself,
//     but its imports still count while its package is reachable.
//   - Allowlist entries need a reason and a ticket. The reason starts with a
//     category (planned, test helper - never wired, developer tool) followed by
//     text. The ticket must be an ID in the project's ticket form (for example
//     "AS-09", "iv02" or "EN-16h") that a Markdown file under docs/ defines in a
//     table row or heading. A ticket that internal/wiringguard/tickets.txt
//     registers must be defined by the tracking document the register names.
//     Words such as "TODO" or "none"
//     are not tickets. An entry whose package is reachable now is reported as
//     informational only. An entry that names no checked package is stale and
//     is reported as a finding.
//   - Directories named testdata, vendor, or starting with "." or "_" are not
//     scanned. A subdirectory with its own go.mod is another module and is not
//     scanned either.
//
// The package uses only the standard library and reads only the module tree.
package wiringguard
