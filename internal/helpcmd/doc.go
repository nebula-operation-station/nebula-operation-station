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
//     the ADR does not name makes the unit indeterminate, which is destructive
//     (fail closed); see Units;
//   - check V6 (ADR 0014): the reviewed destructive-pattern list, each row
//     with its ADR wording, and Assess, which applies the list to every unit.
//
// The package is a pure library. It has no command catalog, reads no docs,
// runs no command, opens no connection and imports only the standard library.
//
// AS-05 part 2 is not in this package yet: the command catalog (built from the
// cmd/nebula command tree, not from the docs), the shape builder from the code
// blocks of cited chunks, the placeholder class table, and checks V2 to V5.
package helpcmd
