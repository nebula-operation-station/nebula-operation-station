// SPDX-License-Identifier: AGPL-3.0-or-later

package prelude

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

// The allowlists below are written out here as literals. They do not reuse
// nameRe, choiceRe or ere, so that widening a pattern in prelude.go makes
// this test fail instead of passing on both sides.
var (
	// allowName is what a parameter name and a secret slot may contain in
	// the generated shell: nothing that the shell would interpret.
	allowName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	// allowChoice is the character set of a choice value.
	allowChoice = regexp.MustCompile(`^[a-z0-9_-]{1,63}$`)
	// allowChoicePattern is the set of characters a choice pattern may use:
	// the value characters plus the group and alternation operators.
	allowChoicePattern = regexp.MustCompile(`^[a-z0-9_|()-]+$`)
)

// wantTypePattern is each non-choice type's pattern, copied as a literal.
var wantTypePattern = map[string]string{
	TypeName: `[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}`,
	TypeInt:  `[0-9]{1,9}`,
	TypePath: `/[A-Za-z0-9._/-]{0,200}`,
}

// FuzzCheckBuild feeds arbitrary parameter and secret-slot fields through
// Check and, when Check accepts them, through Build. It must not panic.
// For each accepted input it checks, against the literal allowlists above,
// that every name, slot and pattern carries only characters the generated
// shell may see; that a choice pattern matches exactly the declared choices;
// and that the script equals the fixed template with only the parameter and
// slot lines inserted, so nothing else in the prelude depends on the input.
//
// The shape byte chooses how many secret slots (0, 1 or 2) and whether a
// second parameter is added, so the interaction between generated lines is
// covered as well.
func FuzzCheckBuild(f *testing.F) {
	f.Add("unit", "Unit", "name", "", "token", uint8(0))
	f.Add("count", "Count", "int", "", "a1", uint8(1))
	f.Add("dir", "Dir", "path", "", "tls_key", uint8(2))
	f.Add("mode", "Mode", "choice", "soft,hard-reset", "x", uint8(3))
	f.Add("mode", "Mode", "choice", "a'b", "x", uint8(4))
	f.Add("mode", "Mode", "choice", "a|b,c)", "token", uint8(0))
	f.Add("mode", "Mode", "choice", "x)|(.*,a", "token", uint8(5))
	f.Add("mode", "Mode", "choice", "a$(id),b`id`", "token", uint8(1))
	f.Add("unit", around(0x202e), "name", "", "token", uint8(1))
	f.Add("nebula_x", "L", "name", "", "nebula", uint8(0))
	f.Add("u", "L", "name", "", "u", uint8(6))
	f.Add("", "", "", "", "", uint8(0))

	f.Fuzz(func(t *testing.T, name, label, typ, choices, slot string, shape uint8) {
		var cs []string
		if choices != "" {
			cs = strings.Split(choices, ",")
		}
		params := []Param{{Name: name, Label: label, Type: typ, Choices: cs}}
		if shape&4 != 0 {
			params = append(params, Param{Name: "other", Label: "Other", Type: TypeInt})
		}
		var secrets []string
		switch shape % 3 {
		case 1:
			secrets = []string{slot}
		case 2:
			secrets = []string{slot, "backup"}
		}

		reason, ok := Check(params, secrets)
		if !ok {
			if reason == "" {
				t.Fatalf("Check refused %q %q %q %q %q without a reason", name, label, typ, choices, slot)
			}
			return
		}

		for _, p := range params {
			checkAcceptedParam(t, p)
		}
		for _, s := range secrets {
			if !allowName.MatchString(s) {
				t.Fatalf("accepted secret slot %q outside the name allowlist", s)
			}
		}

		// Build is deterministic and equals the template plus substitutions.
		out1 := Build("fuzz", params, secrets, "true\n")
		out2 := Build("fuzz", params, secrets, "true\n")
		if !bytes.Equal(out1, out2) {
			t.Fatalf("Build is not deterministic for %q", name)
		}
		if got, want := string(out1), wantScript(t, params, secrets); got != want {
			t.Fatalf("script is not the fixed template plus the parameter and slot lines\ngot:\n%s\nwant:\n%s", got, want)
		}
	})
}

// checkAcceptedParam asserts the properties of one accepted parameter.
func checkAcceptedParam(t *testing.T, p Param) {
	t.Helper()
	if !allowName.MatchString(p.Name) {
		t.Fatalf("accepted parameter name %q outside the name allowlist", p.Name)
	}
	pat := p.Pattern()
	if p.Type != TypeChoice {
		if want := wantTypePattern[p.Type]; pat != want {
			t.Fatalf("accepted %q (%s): pattern %q, want %q", p.Name, p.Type, pat, want)
		}
		return
	}
	if !allowChoicePattern.MatchString(pat) {
		t.Fatalf("accepted choice %q: pattern %q has characters outside the choice allowlist", p.Name, pat)
	}
	for _, c := range p.Choices {
		if !allowChoice.MatchString(c) {
			t.Fatalf("accepted choice %q: value %q outside the choice allowlist", p.Name, c)
		}
	}
	// The anchored pattern must match exactly the declared choices.
	anchored, err := regexp.Compile("^" + pat + "$")
	if err != nil {
		t.Fatalf("accepted choice %q: pattern %q does not compile: %v", p.Name, pat, err)
	}
	declared := map[string]bool{}
	for _, c := range p.Choices {
		declared[c] = true
	}
	probes := append([]string{"", "zz_not_a_choice"}, p.Choices...)
	for _, c := range p.Choices {
		probes = append(probes, c+"_", c[:len(c)-1])
	}
	for _, probe := range probes {
		if got := anchored.MatchString(probe); got != declared[probe] {
			t.Fatalf("accepted choice %q: anchored %q matches %q = %v, want %v", p.Name, pat, probe, got, declared[probe])
		}
	}
}

// wantScript is the script Build must produce: the template Build emits
// with no parameters or slots, with exactly the per-parameter and per-slot
// lines inserted before the "unset v" line. The lines are written out here
// as literals, so a change in Build shows up as a difference.
func wantScript(t *testing.T, params []Param, secrets []string) string {
	t.Helper()
	base := Build("fuzz", nil, nil, "true\n")
	const anchor = "unset v\n"
	i := strings.Index(string(base), anchor)
	if i < 0 || strings.LastIndex(string(base), anchor) != i {
		t.Fatalf("template does not contain %q exactly once", anchor)
	}
	var lines strings.Builder
	for _, p := range params {
		up := strings.ToUpper(p.Name)
		lines.WriteString("v=$(nebula_get " + p.Name + ")\n")
		lines.WriteString(`printf '%s\n' "$v" | LC_ALL=C grep -Eqx '` + p.Pattern() + `' || nebula_fail "parameter ` + p.Name + ` is not valid"` + "\n")
		lines.WriteString("NEBULA_P_" + up + "=$v; export NEBULA_P_" + up + "\n")
	}
	for _, s := range secrets {
		up := strings.ToUpper(s)
		lines.WriteString(`[ -n "${NEBULA_SECRETS_DIR:-}" ] && [ -f "$NEBULA_SECRETS_DIR/` + s + `" ] || nebula_fail "secret ` + s + ` is not available"` + "\n")
		lines.WriteString("NEBULA_SECRET_" + up + "=$NEBULA_SECRETS_DIR/" + s + "; export NEBULA_SECRET_" + up + "\n")
	}
	return string(base[:i]) + lines.String() + string(base[i:])
}
