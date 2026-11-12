// SPDX-License-Identifier: AGPL-3.0-or-later

// Package fimscan parses the fim-scan-v1 result of the built-in read-only
// fim.scan action (ADR 0015 D5, D6; spec 09 v26-09-01).
//
// Every byte of the document is untrusted host data. The parser reads the
// document as a stream through a byte-counting reader, validates it token by
// token and record by record against a strict schema and never buffers the
// raw document. It enforces the named limits in limits.go:
//
//   - A document that is not one strict JSON object of the schema (syntax
//     error, unknown or duplicate top-level member, wrong format, profile or
//     mode, data after the document) is rejected as a whole with
//     ErrInvalidResult; nothing from it is used.
//   - A record, mount or roots entry that is well-formed JSON but violates
//     the schema is dropped and counted, and the run is partial.
//   - A run cut at a limit keeps the records validated so far but is partial;
//     it is never presented as complete.
//
// Content hashes leave the parser only in their D6 form: a plain SHA-256
// for the allowlisted package-binary roots, an HMAC-SHA-256 under the
// per-host key for every other path. Plain hashes of keyed paths exist only
// in parser memory.
//
// Errors and results never quote host-supplied bytes; host paths are
// returned as raw bytes and must be shown through EscapePath.
//
// The package also holds the producing side: Script, the embedded
// read-only fim.scan script for the profile DefaultProfile
// (fim-default-v1), and Action, its read-only action contract. The script
// reports plain SHA-256 values only; keying them is the parser's job, so the
// per-host key never reaches the host.
package fimscan
