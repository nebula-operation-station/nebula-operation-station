// SPDX-License-Identifier: AGPL-3.0-or-later

// Package helpcmd holds the deterministic command checks of the in-app help
// assistant. ADR 0014 (docs/adr/0014-help-assistant.md) decides that the
// assistant only shows commands that pass these checks, and never runs them;
// the implementation plan is docs/implementation/help-assistant.md.
//
// This package implements the first part of ticket AS-05:
//
//   - check V1 (ADR 0014, validator table): the command is one line of
//     printable ASCII (0x20–0x7E); see CheckASCII and NonASCIIError;
//   - the units of a command (ADR 0014, "What V6 matches (units)"): split at
//     the separators of the shell syntax, redirections dropped, the wrappers
//     sudo, env, NAME=value, exec, nohup, nice, time, timeout, docker run and
//     exec, docker compose exec and run, and sh/bash/su -c unwrapped; an option
//     the ADR does not name makes the unit indeterminate; see Units. Units
//     only choose the destructive wording; the allowlist does not unwrap;
//   - check V6 (ADR 0014, maintainer decision 2026-11-16): the allowlist of
//     harmless commands (allowlist.go). Assess calls a command harmless only
//     when every simple command of it is an allowlisted program with allowed
//     subcommands and options, without wrapper, redirection, expansion or
//     group; everything else needs confirmation. The reviewed
//     destructive-pattern list, each row with its ADR wording, only chooses
//     the wording of a command that is not harmless.
//
// The package is a pure library. It has no command catalog, reads no docs,
// runs no command, opens no connection and imports only the standard library.
//
// AS-05 part 2 is only partly in this package. The placeholder class table
// (ADR 0014 D4, "Matching (V3)") is in placeholder.go: the fixed names, the
// value shape of each class, and the lookup. The shell-word tokenizer
// (Tokenize, tokens.go) and the token matching of V3 (MatchShape, match.go)
// are in place: a doc shape and a command are split by the same tokenizer,
// token counts and order must agree, each token is byte-identical or holds one
// placeholder whose value matches its class, and a copied placeholder is
// reported as Unchanged. MatchShape only reports the host values; it does not
// check them against the trusted host set. Still open in part 2: the command
// catalog (built from the cmd/nebula command tree, not from the docs), the
// shape builder from the code blocks of cited chunks, and checks V2, V4 and V5
// (V5 needs the trusted host set; the docs cross-check runs at build time).
package helpcmd
