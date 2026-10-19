// SPDX-License-Identifier: AGPL-3.0-or-later

// Package prelude builds the host script of a runbook or module action:
// a generated prelude that checks typed parameters and secret slots, then
// the author's script. The server and the executor build the same bytes
// from the same inputs (the executor does so for signed modules), so this
// package has no dependencies beyond the standard library.
package prelude

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Parameter types (decision 2 of the M7 plan): no free-form strings.
const (
	TypeName   = "name"
	TypeInt    = "int"
	TypePath   = "path"
	TypeChoice = "choice"
)

// Limits.
const (
	MaxParams  = 10
	MaxSecrets = 8
	MaxChoices = 20
	MaxLabel   = 100
)

// ere is each type's pattern, written so that Go's regexp and POSIX ERE
// (grep -E, used by the prelude on the host) read it the same way.
//
// A path may contain ".." segments: it is an absolute path handed to the
// author's own script, which can name any path anyway, so the pattern only
// keeps quotes, spaces and shell metacharacters out (review m72, note 2).
var ere = map[string]string{
	TypeName: `[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}`,
	TypeInt:  `[0-9]{1,9}`,
	TypePath: `/[A-Za-z0-9._/-]{0,200}`,
}

var (
	nameRe   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	choiceRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
)

// Param is one typed parameter.
type Param struct {
	Name    string   `json:"name"`
	Label   string   `json:"label"`
	Type    string   `json:"type"`
	Choices []string `json:"choices,omitempty"`
}

// Pattern is the parameter's ERE without anchors.
func (p Param) Pattern() string {
	if p.Type == TypeChoice {
		return "(" + strings.Join(p.Choices, "|") + ")"
	}
	return ere[p.Type]
}

// Clean reports whether s is printable text without control, format
// (bidi) or line/paragraph separator characters; newline and tab are
// allowed only where multiline is true.
func Clean(s string, multiline bool) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		switch {
		case multiline && (r == '\n' || r == '\t'):
		case r == '\r':
			return false
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), r == '\u2028', r == '\u2029', r == utf8.RuneError:
			return false
		}
	}
	return true
}

// Check checks parameters and secret slots; the reason is safe to show.
func Check(params []Param, secrets []string) (string, bool) {
	seen := map[string]bool{}
	if len(params) > MaxParams {
		return "at most 10 parameters", false
	}
	if len(secrets) > MaxSecrets {
		return "at most 8 secret slots", false
	}
	for _, slot := range secrets {
		if !nameRe.MatchString(slot) || strings.HasPrefix(slot, "nebula") || seen[slot] {
			return "secret slots are distinct names of 1 to 32 lowercase letters, digits or _, starting with a letter (not nebula…)", false
		}
		seen[slot] = true
	}
	for _, p := range params {
		switch {
		case !nameRe.MatchString(p.Name) || strings.HasPrefix(p.Name, "nebula"):
			return "parameter names are 1 to 32 lowercase letters, digits or _, starting with a letter (not nebula…)", false
		case seen[p.Name]:
			return "parameter " + p.Name + " appears twice or is also a secret slot", false
		case p.Label == "" || len(p.Label) > MaxLabel || !Clean(p.Label, false):
			return "parameter " + p.Name + " needs a label of 1 to 100 characters of plain text", false
		}
		seen[p.Name] = true
		switch p.Type {
		case TypeName, TypeInt, TypePath:
			if len(p.Choices) > 0 {
				return "parameter " + p.Name + ": only a choice has choices", false
			}
		case TypeChoice:
			if len(p.Choices) == 0 || len(p.Choices) > MaxChoices {
				return "parameter " + p.Name + ": a choice has 1 to 20 values", false
			}
			vals := map[string]bool{}
			for _, c := range p.Choices {
				if !choiceRe.MatchString(c) || vals[c] {
					return "parameter " + p.Name + ": choices are distinct lowercase words (letters, digits, _ and -)", false
				}
				vals[c] = true
			}
		default:
			return "parameter " + p.Name + ": the type must be name, int, path or choice", false
		}
	}
	return "", true
}

// Build is what runs on the host: a generated prelude, then the
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
// value is exported as NEBULA_P_<NAME>. For each secret slot the prelude
// checks that the host bootstrap stored its file and exports its path as
// NEBULA_SECRET_<SLOT>; the value itself never appears in the environment.
//
// The script runs in a subshell with stdin from /dev/null and its stdout
// sent to the log (stderr): the result document (stdout) is always the
// prelude's own one line, {"format":"runbook-v1","phase":"done","exit":N},
// and the run's exit status is the script's.
func Build(title string, params []Param, secrets []string, body string) []byte {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("# " + title + "\n")
	b.WriteString("# Generated prelude: checks every parameter, then runs the script below.\n")
	b.WriteString(`set -u
nebula_fail() { printf '{"format":"runbook-v1","phase":"precheck","reason":"%s"}\n' "$1"; exit 10; }
nebula_get() { sed -n 's/.*"'"$1"'":"\([^"\\]*\)".*/\1/p' "$NEBULA_PARAMS" | head -n 1; }
`)
	for _, p := range params {
		up := strings.ToUpper(p.Name)
		b.WriteString("v=$(nebula_get " + p.Name + ")\n")
		b.WriteString("printf '%s\\n' \"$v\" | LC_ALL=C grep -Eqx '" + p.Pattern() + "' || nebula_fail \"parameter " + p.Name + " is not valid\"\n")
		b.WriteString("NEBULA_P_" + up + "=$v; export NEBULA_P_" + up + "\n")
	}
	for _, slot := range secrets {
		up := strings.ToUpper(slot)
		b.WriteString("[ -n \"${NEBULA_SECRETS_DIR:-}\" ] && [ -f \"$NEBULA_SECRETS_DIR/" + slot + "\" ] || nebula_fail \"secret " + slot + " is not available\"\n")
		b.WriteString("NEBULA_SECRET_" + up + "=$NEBULA_SECRETS_DIR/" + slot + "; export NEBULA_SECRET_" + up + "\n")
	}
	b.WriteString("unset v\nset +u\n")
	b.WriteString("nebula_main() {\n:\n")
	b.WriteString("# ---- runbook script ----\n")
	b.WriteString(body)
	if !strings.HasSuffix(body, "\n") {
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
