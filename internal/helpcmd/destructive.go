// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import "strings"

// destructivePattern is one row of the reviewed destructive-pattern list of
// ADR 0014 check V6. Each row has the wording of the ADR as its comment (the
// `adr` field). A row matches a unit when every condition that is set holds.
//
// The list is exactly the ADR list. Rows are not added here on their own
// initiative; a change needs an ADR change and a maintainer review.
type destructivePattern struct {
	// adr is the row text of ADR 0014 V6, copied as written.
	adr string
	// program is the exact program name (last path element), or "".
	program string
	// programPrefix is a prefix of the program name, or "" (used for mkfs*).
	programPrefix string
	// seq lists words that must appear consecutively among the arguments.
	seq []string
	// anyArg lists words of which at least one must be an argument.
	anyArg []string
	// match is an extra condition on the arguments, or nil.
	match func(args []string) bool
}

// matches reports whether the unit u is covered by the row.
func (p destructivePattern) matches(u Unit) bool {
	if p.program != "" && u.Program != p.program {
		return false
	}
	if p.programPrefix != "" && !strings.HasPrefix(u.Program, p.programPrefix) {
		return false
	}
	if len(p.seq) > 0 && !containsSeq(u.Args, p.seq) {
		return false
	}
	if len(p.anyArg) > 0 && !containsAny(u.Args, p.anyArg) {
		return false
	}
	if p.match != nil && !p.match(u.Args) {
		return false
	}
	return true
}

// destructivePatterns is the V6 list of ADR 0014, in the ADR's order.
var destructivePatterns = []destructivePattern{
	{
		// ADR 0014 V6: `rm` with `-r`/`-R`/`-f` (also inside a single-dash
		// cluster such as `-rf`) or `--recursive`/`--force`
		adr:     "`rm` with `-r`/`-R`/`-f` (also inside a single-dash cluster such as `-rf`) or `--recursive`/`--force`",
		program: "rm",
		match:   rmRecursiveOrForce,
	},
	{
		// ADR 0014 V6: `userdel`
		adr:     "`userdel`",
		program: "userdel",
	},
	{
		// ADR 0014 V6: `groupdel`
		adr:     "`groupdel`",
		program: "groupdel",
	},
	{
		// ADR 0014 V6: `shred`
		adr:     "`shred`",
		program: "shred",
	},
	{
		// ADR 0014 V6: `dd`
		adr:     "`dd`",
		program: "dd",
	},
	{
		// ADR 0014 V6: `mkfs*`
		adr:           "`mkfs*`",
		programPrefix: "mkfs",
	},
	{
		// ADR 0014 V6: `wipefs`
		adr:     "`wipefs`",
		program: "wipefs",
	},
	{
		// ADR 0014 V6: `truncate`
		adr:     "`truncate`",
		program: "truncate",
	},
	{
		// ADR 0014 V6: `tar` extracting (see units below)
		adr:     "`tar` extracting (see units below)",
		program: "tar",
		match:   tarExtracts,
	},
	{
		// ADR 0014 V6: `docker compose down -v`
		adr:     "`docker compose down -v`",
		program: "docker",
		match:   composeDownVolumes,
	},
	{
		// ADR 0014 V6: `docker volume rm`
		adr:     "`docker volume rm`",
		program: "docker",
		seq:     []string{"volume", "rm"},
	},
	{
		// ADR 0014 V6: `docker system prune`
		adr:     "`docker system prune`",
		program: "docker",
		seq:     []string{"system", "prune"},
	},
	{
		// ADR 0014 V6: `apt remove`/`purge`
		adr:     "`apt remove`/`purge`",
		program: "apt",
		anyArg:  []string{"remove", "purge"},
	},
	{
		// ADR 0014 V6: `nebula restore`
		adr:     "`nebula restore`",
		program: "nebula",
		seq:     []string{"restore"},
	},
	{
		// ADR 0014 V6: `nebula netdev remove`
		adr:     "`nebula netdev remove`",
		program: "nebula",
		seq:     []string{"netdev", "remove"},
	},
	{
		// ADR 0014 V6: `nebula pve remote remove`
		adr:     "`nebula pve remote remove`",
		program: "nebula",
		seq:     []string{"pve", "remote", "remove"},
	},
	{
		// ADR 0014 V6: `nebula container definition remove`
		adr:     "`nebula container definition remove`",
		program: "nebula",
		seq:     []string{"container", "definition", "remove"},
	},
	{
		// ADR 0014 V6: `nebula webauthn remove`
		adr:     "`nebula webauthn remove`",
		program: "nebula",
		seq:     []string{"webauthn", "remove"},
	},
	{
		// ADR 0014 V6: `nebula totp remove`
		adr:     "`nebula totp remove`",
		program: "nebula",
		seq:     []string{"totp", "remove"},
	},
	{
		// ADR 0014 V6: `nebula signer remove`
		adr:     "`nebula signer remove`",
		program: "nebula",
		seq:     []string{"signer", "remove"},
	},
	{
		// ADR 0014 V6: `nebula secret rm`
		adr:     "`nebula secret rm`",
		program: "nebula",
		seq:     []string{"secret", "rm"},
	},
	{
		// ADR 0014 V6: `nebula host unpin`
		adr:     "`nebula host unpin`",
		program: "nebula",
		seq:     []string{"host", "unpin"},
	},
	{
		// ADR 0014 V6: `nebula host clear`
		adr:     "`nebula host clear`",
		program: "nebula",
		seq:     []string{"host", "clear"},
	},
	{
		// ADR 0014 V6: `nebula artifact unpin`
		adr:     "`nebula artifact unpin`",
		program: "nebula",
		seq:     []string{"artifact", "unpin"},
	},
	{
		// ADR 0014 V6: `nebula read-grant revoke`
		adr:     "`nebula read-grant revoke`",
		program: "nebula",
		seq:     []string{"read-grant", "revoke"},
	},
	{
		// ADR 0014 V6: `nebula schedule revoke`
		adr:     "`nebula schedule revoke`",
		program: "nebula",
		seq:     []string{"schedule", "revoke"},
	},
	{
		// ADR 0014 V6: `nebula netdev repin`
		adr:     "`nebula netdev repin`",
		program: "nebula",
		seq:     []string{"netdev", "repin"},
	},
	{
		// ADR 0014 V6: `nebula pve remote repin`
		adr:     "`nebula pve remote repin`",
		program: "nebula",
		seq:     []string{"pve", "remote", "repin"},
	},
	{
		// ADR 0014 V6: `nebula pve remote rotate-token`
		adr:     "`nebula pve remote rotate-token`",
		program: "nebula",
		seq:     []string{"pve", "remote", "rotate-token"},
	},
}

// Verdict is the V6 result for one command.
type Verdict struct {
	// Destructive is true when the command must be shown at least amber, or
	// red when no cited shape covers it.
	Destructive bool
	// Pattern is the ADR wording of the first matching row. It is empty when
	// the command is destructive only because it could not be checked.
	Pattern string
}

// Assess applies check V6 of ADR 0014 to cmd. Every unit of the command is
// checked, not only the first word. A command that cannot be split into units,
// or a unit with a wrapper option the ADR does not name, is destructive (fail
// closed).
func Assess(cmd string) Verdict {
	units, err := Units(cmd)
	if err != nil {
		return Verdict{Destructive: true}
	}
	indeterminate := false
	for _, u := range units {
		if p := matchingPattern(u); p != nil {
			return Verdict{Destructive: true, Pattern: p.adr}
		}
		if u.Indeterminate {
			indeterminate = true
		}
	}
	if indeterminate {
		return Verdict{Destructive: true}
	}
	return Verdict{}
}

// matchingPattern returns the first row of destructivePatterns that covers u,
// or nil.
func matchingPattern(u Unit) *destructivePattern {
	for i := range destructivePatterns {
		if destructivePatterns[i].matches(u) {
			return &destructivePatterns[i]
		}
	}
	return nil
}

// rmRecursiveOrForce reports whether an rm argument list contains -r, -R or
// -f in a single-dash cluster, or --recursive or --force.
func rmRecursiveOrForce(args []string) bool {
	for _, a := range args {
		if a == "--recursive" || a == "--force" {
			return true
		}
		if strings.HasPrefix(a, "--") || len(a) < 2 || a[0] != '-' {
			continue
		}
		if strings.ContainsAny(a[1:], "rRf") {
			return true
		}
	}
	return false
}

// tarExtracts reports whether tar extracts: a single-dash option word contains
// x, --extract or --get is present, or the first argument has no dash and
// contains x (old-style options such as `tar xzf archive`).
func tarExtracts(args []string) bool {
	for _, a := range args {
		if a == "--extract" || a == "--get" {
			return true
		}
		if strings.HasPrefix(a, "--") || len(a) < 2 || a[0] != '-' {
			continue
		}
		if strings.ContainsRune(a, 'x') {
			return true
		}
	}
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") && strings.ContainsRune(args[0], 'x') {
		return true
	}
	return false
}

// composeDownVolumes reports whether the arguments contain compose, then down,
// then -v in that order (the global options of compose may sit in between).
func composeDownVolumes(args []string) bool {
	for i, a := range args {
		if a != "compose" {
			continue
		}
		for j := i + 1; j < len(args); j++ {
			if args[j] != "down" {
				continue
			}
			for k := j + 1; k < len(args); k++ {
				if args[k] == "-v" {
					return true
				}
			}
		}
	}
	return false
}

// containsSeq reports whether seq occurs as consecutive words in words.
func containsSeq(words, seq []string) bool {
	for i := 0; i+len(seq) <= len(words); i++ {
		match := true
		for j, s := range seq {
			if words[i+j] != s {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// containsAny reports whether one of want is an element of words.
func containsAny(words, want []string) bool {
	for _, w := range words {
		for _, x := range want {
			if w == x {
				return true
			}
		}
	}
	return false
}
