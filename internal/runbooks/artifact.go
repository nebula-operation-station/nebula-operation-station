// SPDX-License-Identifier: AGPL-3.0-or-later

package runbooks

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// ShellCheck parses a script with sh -n without running it. It is a
// variable so tests on machines without /bin/sh can replace it.
var ShellCheck = func(script []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-n")
	cmd.Stdin = bytes.NewReader(script)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin"}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if i := strings.IndexByte(msg, '\n'); i >= 0 {
			msg = msg[:i]
		}
		if len(msg) > 200 {
			msg = msg[:200]
		}
		if msg == "" {
			return err
		}
		return errors.New(msg)
	}
	return nil
}

// Artifact is what runs on the host: a generated prelude, then the
// author's script as a shell function. It is part of the approved bytes,
// so the approval covers the prelude too.
//
// The prelude reads every parameter from the canonical parameters
// ($NEBULA_PARAMS, one line of RFC 8785 JSON) and checks it with the same
// pattern the server checked, anchored (grep -Ex, in the C locale so
// bracket ranges match exactly what Go's regexp matches); a value that does not
// match ends the run as precheck_failed before the author's script starts.
// Values match their type's narrow character set, so they contain no quote
// or backslash and the extraction cannot be confused by JSON escapes. Each
// value is exported as NEBULA_P_<NAME>.
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
		b.WriteString("printf '%s\\n' \"$v\" | LC_ALL=C grep -Eqx '" + p.pattern() + "' || nebula_fail \"parameter " + p.Name + " is not valid\"\n")
		b.WriteString("NEBULA_P_" + up + "=$v; export NEBULA_P_" + up + "\n")
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
