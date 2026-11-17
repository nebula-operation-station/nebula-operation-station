// SPDX-License-Identifier: AGPL-3.0-or-later

// Package fimfinding maps the deviations of an I2 baseline comparison to the
// finding classes and severities of ADR 0015 D9 (table "Severity by class",
// "the highest matching severity wins").
//
// Source: ADR 0015 D9, "Findings"; the class names and the severity table
// are in package integritystore (classes.go). Inputs are the types of
// fimbaseline (Report, Deviation, Change, Kind, Class) and fimscan (Root).
// The package is a pure library: no database, no I/O, no clock.
//
// Covered here, each from the deviation alone:
//   - critical-path-changed (critical): a changed, new or removed path whose
//     fimbaseline Deviation.Class is critical (D9 "critical-class paths").
//   - setid-new (critical): a new setuid or setgid bit on a changed or new
//     record, or a new record that carries such a bit.
//   - owner-mode-changed (high): a changed owner (uid or gid) or mode
//     (permission, setuid, setgid or sticky bits) of a changed record.
//   - etc-changed (high): a changed or new path in /etc or in a literal
//     watched /usr root of the profile (D5). Glob roots are not /usr roots.
//   - scan-partial (medium): the report is not complete (Report.Complete).
//
// A deviation can match several classes; Classes returns all of them and
// Findings reports the one with the highest severity (integritystore.Escalate).
//
// Not covered (the rows need inputs that a deviation does not carry; later
// IG-06/IG-07/IG-08 parts):
//   - pkg-file-mismatch, pkg-content-without-version, pkg-downgraded,
//     pkg-updated-outside-nos: need the signed package references and the
//     reported package versions (D7, D8).
//   - nos-unit-mismatch, nos-key-missing, ssh-key-extra: need the NOS binary,
//     unit and key data (D2, D7).
//   - critical-path-changed-in-job, changed-in-job-unverified,
//     expected-change: need the NOS job records and the expected-change
//     attribution (D9 "Expected changes are attributed automatically").
//     Until attribution exists, every critical-class change is reported as
//     critical-path-changed, which is the fail-closed reading.
//   - reference-conflict: needs the D8 reference builder results.
//   - baseline-digest-mismatch: needs the stored baseline digest, not a
//     deviation.
//   - ssh-login-file-outside-roots: needs the derived SSH set (D9 "SSH login
//     files"), which is not implemented yet.
//   - mount-unexpected and mount-unexpected-critical: fimbaseline emits no
//     mount deviation, and the covered/excluded/skipped sorting of mounts
//     (D5 "Separate mounts below a root") needs the profile's excluded_mounts
//     list, which fimscan.Profile does not carry.
//
// Gap in the ADR table, not in this code: the row "other changed or new
// file" covers only /etc and watched /usr roots. A removed non-critical
// path, and a changed or new non-critical path elsewhere (for example under
// /opt, under /bin on a host without merged /usr, or under /usr/local), has
// no row outside a NOS job. Classes returns ErrNotCovered for such a
// deviation. Findings does not drop the run for it: the deviation becomes its
// own Finding with NotCovered set and no class or severity, and the other
// findings of the report are still returned. The maintainers must decide the
// row.
package fimfinding
