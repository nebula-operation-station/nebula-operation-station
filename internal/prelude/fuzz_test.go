// SPDX-License-Identifier: AGPL-3.0-or-later

package prelude

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

// FuzzCheckBuild feeds arbitrary parameter and secret-slot fields through
// Check and, when Check accepts them, through Build. It must not panic;
// an accepted parameter must have a pattern that is a plain ERE (no quote,
// space or line break, so it can sit in a single-quoted grep argument); and
// the generated script must be deterministic and must carry the name only
// in the fixed template forms, with the name matching nameRe.
func FuzzCheckBuild(f *testing.F) {
	f.Add("unit", "Unit", "name", "", "token")
	f.Add("count", "Count", "int", "", "a1")
	f.Add("dir", "Dir", "path", "", "tls_key")
	f.Add("mode", "Mode", "choice", "soft,hard-reset", "x")
	f.Add("mode", "Mode", "choice", "a'b", "x")
	f.Add("mode", "Mode", "choice", "a|b,c)", "")
	f.Add("nebula_x", "L", "name", "", "nebula")
	f.Add("u", "L", "name", "", "u")
	f.Add("unit", "a"+string(rune(0x202e))+"b", "name", "", "")
	f.Add("", "", "", "", "")

	f.Fuzz(func(t *testing.T, name, label, typ, choices, slot string) {
		var cs []string
		if choices != "" {
			cs = strings.Split(choices, ",")
		}
		params := []Param{{Name: name, Label: label, Type: typ, Choices: cs}}
		secrets := []string{slot}

		reason, ok := Check(params, secrets)
		if !ok {
			if reason == "" {
				t.Fatalf("Check refused %q %q %q %q %q without a reason", name, label, typ, choices, slot)
			}
			return
		}

		// Accepted: the parameter pattern is usable in the generated grep.
		pat := params[0].Pattern()
		if pat == "" {
			t.Fatalf("accepted %q (%s): empty pattern", name, typ)
		}
		if strings.ContainsAny(pat, "' \n\r") {
			t.Fatalf("accepted %q (%s): pattern %q has a quote, space or line break", name, typ, pat)
		}
		if _, err := regexp.Compile(pat); err != nil {
			t.Fatalf("accepted %q (%s): pattern %q does not compile: %v", name, typ, pat, err)
		}

		// Accepted: Build is deterministic and has the fixed header.
		out1 := Build("fuzz", params, secrets, "true\n")
		out2 := Build("fuzz", params, secrets, "true\n")
		if !bytes.Equal(out1, out2) {
			t.Fatalf("Build is not deterministic for %q", name)
		}
		script := string(out1)
		if !strings.HasPrefix(script, "#!/bin/sh\n") {
			t.Fatalf("script does not start with the shebang: %q", script[:min(len(script), 20)])
		}

		// Every line that comes from the parameter or the slot uses the
		// name in the template form only, and the name is one nameRe allows.
		if !nameRe.MatchString(name) || !nameRe.MatchString(slot) {
			t.Fatalf("accepted names outside nameRe: %q, %q", name, slot)
		}
		up := strings.ToUpper(name)
		for _, line := range []string{
			"v=$(nebula_get " + name + ")\n",
			"printf '%s\\n' \"$v\" | LC_ALL=C grep -Eqx '" + pat + "' || nebula_fail \"parameter " + name + " is not valid\"\n",
			"NEBULA_P_" + up + "=$v; export NEBULA_P_" + up + "\n",
			"[ -n \"${NEBULA_SECRETS_DIR:-}\" ] && [ -f \"$NEBULA_SECRETS_DIR/" + slot + "\" ] || nebula_fail \"secret " + slot + " is not available\"\n",
			"NEBULA_SECRET_" + strings.ToUpper(slot) + "=$NEBULA_SECRETS_DIR/" + slot + "; export NEBULA_SECRET_" + strings.ToUpper(slot) + "\n",
		} {
			if !strings.Contains(script, line) {
				t.Fatalf("script lacks the expected line %q", line)
			}
		}
	})
}
