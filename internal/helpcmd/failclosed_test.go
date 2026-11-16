// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import "testing"

// These tests cover the round-2 findings on V6 (PR #596): every construct the
// scanner does not evaluate makes the unit indeterminate, which counts as the
// destructive side. Each named test fails on the round-1 scanner.

// TestSubstitutionMakesEnclosingCommandIndeterminate (HIGH): a $( … ),
// backtick or process substitution replaces a word of the command it sits in,
// so the program that runs is unknown. The enclosing command is indeterminate,
// including the words after the substitution. Inner commands are still checked.
func TestSubstitutionMakesEnclosingCommandIndeterminate(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"rm $(echo -rf) /x",
		"$(echo rm) -rf /x",
		"rm `echo -rf` /x",
		"cat <(echo rm) -rf /x",
		"diff <(ls) x",
		"echo $(echo a)rm -rf /x",
		`rm "$(echo -rf)" /x`,
	} {
		assertIndeterminate(t, in)
	}
	assertDestructiveRow(t, "echo $(rm -rf /x)")
	assertDestructiveRow(t, "echo `rm -rf /x`")
}

// TestUnquotedBraceMakesWordIndeterminate (HIGH): brace expansion rewrites a
// word before it runs, so `{rm,-rf,/x}` is `rm -rf /x`. A word with an
// unquoted brace is indeterminate. Brace-group keywords are not words.
func TestUnquotedBraceMakesWordIndeterminate(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"{rm,-rf,/x}",
		"rm -{r,f} /x",
		"rm {a,b}",
		"rm x}",
		"rm {a..b}",
		"echo {a}",
	} {
		assertIndeterminate(t, in)
	}
	assertUnits(t, "{ echo a; }", []string{"echo a"})
	assertUnits(t, `echo "{a,b}"`, []string{"echo {a,b}"})
	assertDestructiveRow(t, "{ dd of=y; }")
}

// TestEscapedSeparatorMakesCommandIndeterminate (HIGH): in `rm \; -rf /x` bash
// passes `;`, `-rf` and `/x` to rm. An unquoted backslash makes the word
// dynamic, so the escaped character is never a separator.
func TestEscapedSeparatorMakesCommandIndeterminate(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		`rm \; -rf /x`,
		`echo a\;b`,
		`rm -\rf /x`,
		`\rm -rf /x`,
		`r\m -rf /x`,
		`sudo \userdel a`,
		`\\rm x`,
		`echo a\`,
	} {
		assertIndeterminate(t, in)
	}
	assertUnits(t, `echo "a\;b"`, []string{`echo a\;b`})
}

// TestEntrypointOptionMakesUnitIndeterminate (MEDIUM): `--entrypoint` replaces
// the program that runs, so the word after the image is not the program.
// ADR 0014 lists --entrypoint among the skipped options; in doubt the unit is
// indeterminate.
func TestEntrypointOptionMakesUnitIndeterminate(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"docker run --entrypoint rm img -rf /x",
		"docker run --entrypoint=rm img -rf /x",
		"docker container run --rm --entrypoint rm img -rf /x",
		"docker compose run --entrypoint rm web -rf /x",
		"docker compose run --rm --entrypoint=rm web -rf /x",
		"sudo docker run --entrypoint sh img -c 'rm -rf /x'",
	} {
		assertIndeterminate(t, in)
	}
	// Without --entrypoint the image and the program after it still unwrap.
	assertUnits(t, "docker run --rm img rm -rf /x", []string{"rm -rf /x"})
}

// TestImageArgumentWithDashIsIndeterminate (MEDIUM): a unit whose program word
// starts with `-` or is empty cannot be a program name, so it is indeterminate.
func TestImageArgumentWithDashIsIndeterminate(t *testing.T) {
	t.Parallel()
	assertIndeterminate(t, "docker run img -rf /x")
	assertIndeterminate(t, `""`)
}

// TestProgramRunnersAreIndeterminate (MEDIUM): these programs run another
// program that ADR 0014 does not show, so they fail closed.
func TestProgramRunnersAreIndeterminate(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"zsh -c 'rm -rf /x'",
		"dash -c 'rm -rf /x'",
		"ksh -c 'rm -rf /x'",
		"fish -c 'rm -rf /x'",
		"find /x -exec rm -rf +",
		"find /x -execdir rm -f +",
		"find /x -ok rm -f +",
		"find /x -okdir rm -f +",
		"nsenter -t 1 -m rm -rf /x",
		"unshare -m rm -rf /x",
		"systemd-run --wait rm -rf /x",
		"pkexec rm -rf /x",
		"ssh host rm -rf /x",
		"chroot /mnt rm -rf /x",
		"sudo nsenter -t 1 -m sh -c x",
	} {
		assertIndeterminate(t, in)
	}
	// find without an exec form is an ordinary program and is checked as
	// itself.
	assertUnits(t, "find /x -name a", []string{"find /x -name a"})
}

// TestCoprocKeywordIsIndeterminate (MEDIUM): `coproc` starts a command that
// bash runs in the background, so the word after it is not the program.
func TestCoprocKeywordIsIndeterminate(t *testing.T) {
	t.Parallel()
	assertIndeterminate(t, "coproc rm -rf /x")
	assertIndeterminate(t, "coproc NAME { rm -rf /x; }")
}

// TestLongOptionAbbreviationsAreDestructive (MEDIUM): GNU getopt accepts any
// unambiguous prefix of a long option, so `rm --rec` is --recursive.
func TestLongOptionAbbreviationsAreDestructive(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"rm --rec /x",
		"rm --recurs /x",
		"rm --r /x",
		"rm --f /x",
		"rm --forc /x",
		"sudo rm --rec /x",
		"tar --ext -f a.tar",
		"tar --get -f a.tar",
		"tar --extr -f a.tar",
	} {
		assertDestructiveRow(t, in)
	}
	for _, in := range []string{
		"rm --interactive x",
		"rm --i x",
		"rm --verbose x",
		"tar --list -f a.tar",
	} {
		if v := Assess(in); v.Pattern != "" {
			t.Errorf("Assess(%q) = %+v, want no destructive row", in, v)
		}
	}
}
