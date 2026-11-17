// SPDX-License-Identifier: AGPL-3.0-or-later

// Package fimsshd derives the SSH login file set of ADR 0015 D7 (d) and D9
// from the sshd_config files that a host sent (D6). It is a pure library: it
// does no I/O, does not resolve Include globs against scan records, and does
// not follow symlinks. Anything it does not understand is reported as
// ErrUnclassifiable, which the caller must treat as critical-class.
//
// Configuration content is never included in errors or in String output.
package fimsshd
