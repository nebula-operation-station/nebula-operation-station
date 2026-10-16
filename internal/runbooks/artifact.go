// SPDX-License-Identifier: AGPL-3.0-or-later

package runbooks

import (
	"strconv"
	"strings"
)

// Artifact is what runs on the host: a generated prelude, then the
// author's script as a shell function. It is part of the approved bytes,
// so the approval covers the prelude too.
//
// The prelude reads every parameter from the canonical parameters
// ($NEBULA_PARAMS, one line of RFC 8785 JSON) and checks it with the same
// pattern the server checked, anchored (grep -Ex); a value that does not
// match ends the run as precheck_failed before the author's script starts.
// Values match their type's narrow character set, so they contain no quote
// or backslash and the extraction cannot be confused by JSON escapes. Each
// value is exported as NEBULA_P_<NAME>. For each secret slot the prelude
// checks that the host bootstrap stored its file and exports its path as
// NEBULA_SECRET_<SLOT>; the value itself never appears in the environment.
//
// The script runs in a subshell with stdin from /dev/null and its stdout
// sent to the log (stderr): the result document (stdout) is always the
// prelude's own one line, {"format":"runbook-v1","phase":"done","exit":N},
// and the run's exit status is the script's.
func Artifact(v Version) []byte {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("# Nebula runbook " + v.Slug + " version " + strconv.Itoa(v.Version) + " (runbook-v1).\n")
	b.WriteString("# Generated prelude: checks every parameter, then runs the script below.\n")
	b.WriteString(`set -u
nebula_fail() { printf '{"format":"runbook-v1","phase":"precheck","reason":"%s"}\n' "$1"; exit 10; }
nebula_get() { sed -n 's/.*"'"$1"'":"\([^"\\]*\)".*/\1/p' "$NEBULA_PARAMS" | head -n 1; }
`)
	for _, p := range v.Params {
		up := strings.ToUpper(p.Name)
		b.WriteString("v=$(nebula_get " + p.Name + ")\n")
		b.WriteString("printf '%s\\n' \"$v\" | grep -Eqx '" + p.pattern() + "' || nebula_fail \"parameter " + p.Name + " is not valid\"\n")
		b.WriteString("NEBULA_P_" + up + "=$v; export NEBULA_P_" + up + "\n")
	}
	for _, slot := range v.Secrets {
		up := strings.ToUpper(slot)
		b.WriteString("[ -n \"${NEBULA_SECRETS_DIR:-}\" ] && [ -f \"$NEBULA_SECRETS_DIR/" + slot + "\" ] || nebula_fail \"secret " + slot + " is not available\"\n")
		b.WriteString("NEBULA_SECRET_" + up + "=$NEBULA_SECRETS_DIR/" + slot + "; export NEBULA_SECRET_" + up + "\n")
	}
	b.WriteString("unset v\nset +u\n")
	b.WriteString("nebula_main() {\n:\n")
	b.WriteString("# ---- runbook script ----\n")
	b.WriteString(v.Body)
	if !strings.HasSuffix(v.Body, "\n") {
		b.WriteString("\n")
	}
	b.WriteString("# ---- end of runbook script ----\n")
	b.WriteString(`}
( nebula_main ) </dev/null 1>&2
rc=$?
printf '{"format":"runbook-v1","phase":"done","exit":%d}\n' "$rc"
exit "$rc"
`)
	return []byte(b.String())
}
