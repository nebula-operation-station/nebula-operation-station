// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import (
	"reflect"
	"testing"
)

// assertUnits checks Units(in) against want, rendered by unitStrings.
func assertUnits(t *testing.T, in string, want []string) {
	t.Helper()
	us, err := Units(in)
	if err != nil {
		t.Fatalf("Units(%q): %v", in, err)
	}
	if got := unitStrings(us); !reflect.DeepEqual(got, want) {
		t.Errorf("Units(%q) = %q, want %q", in, got, want)
	}
}

// assertDestructiveRow checks that Assess(in) is destructive by a named row.
func assertDestructiveRow(t *testing.T, in string) {
	t.Helper()
	if v := Assess(in); !v.Destructive || v.Pattern == "" {
		t.Errorf("Assess(%q) = %+v, want destructive with a named row", in, v)
	}
}

// assertIndeterminate checks that Assess(in) is destructive without a row,
// which is what an unchecked (indeterminate) unit gives.
func assertIndeterminate(t *testing.T, in string) {
	t.Helper()
	us, err := Units(in)
	if err != nil {
		t.Fatalf("Units(%q): %v", in, err)
	}
	found := false
	for _, u := range us {
		found = found || u.Indeterminate
	}
	if !found {
		t.Errorf("Units(%q) = %q, want an indeterminate unit", in, unitStrings(us))
	}
	if v := Assess(in); !v.Destructive {
		t.Errorf("Assess(%q) = %+v, want destructive", in, v)
	}
}

// TestClusteredCommandOptionCountsAsDashC covers a `c` inside a short option
// cluster (`bash -lc`, `sh -ec`, `su -lc`): it is the -c option, so the
// command string is split again and checked.
func TestClusteredCommandOptionCountsAsDashC(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want []string
	}{
		{"bash -lc 'rm -rf /x'", []string{"rm -rf /x"}},
		{"sh -ec 'userdel a'", []string{"userdel a"}},
		{"su -lc 'userdel a'", []string{"userdel a"}},
		{"bash -cx 'rm -rf /x'", []string{"rm -rf /x"}},
		{"bash -o pipefail -c 'dd of=x'", []string{"dd of=x"}},
		{"bash -oc pipefail 'rm -rf /x'", []string{"!bash"}},
	}
	for _, tc := range cases {
		assertUnits(t, tc.in, tc.want)
	}
	for _, in := range []string{"bash -lc 'rm -rf /x'", "sh -ec 'userdel a'", "su -lc 'userdel a'"} {
		assertDestructiveRow(t, in)
	}
	// An unknown letter in a cluster is an unknown option: fail closed.
	assertIndeterminate(t, "bash -lZc 'echo hi'")
	// `+c` is not the -c option.
	assertIndeterminate(t, "bash +c 'echo hi'")
}

// TestBackslashEscapedProgramNameIsIndeterminate covers the alias bypass idiom
// `\rm` and a backslash inside the program word. The shell runs `rm`, but the
// scanner does not evaluate the escape, so the unit is indeterminate (fail
// closed) rather than matched by name. Still destructive.
func TestBackslashEscapedProgramNameIsIndeterminate(t *testing.T) {
	t.Parallel()
	assertIndeterminate(t, `\rm -rf /x`)
	assertIndeterminate(t, `r\m -rf /x`)
	assertIndeterminate(t, `sudo \userdel a`)
	assertIndeterminate(t, `\\rm x`)
}

// TestExpandedProgramWordIsIndeterminate covers program words that the
// scanner cannot evaluate: ANSI-C quoting, parameter expansion and globs.
// The shell may run rm, so the unit is indeterminate (fail closed).
func TestExpandedProgramWordIsIndeterminate(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		`$'\x72m' -rf /x`,
		`r${E}m -rf /x`,
		`$X -rf /x`,
		`"$X" -rf /x`,
		`r* -rf /x`,
		`r?m -rf /x`,
		`[r]m -rf /x`,
		`sudo $X -rf /x`,
		`bash -c "$X"`,
		`echo $HOME`,
	} {
		assertIndeterminate(t, in)
	}
	// A quoted `$` is literal, so the program is known. An escaped `*` is
	// also literal, but an unquoted backslash is not evaluated (fail closed).
	assertUnits(t, `echo '$X'`, []string{"echo $X"})
	assertIndeterminate(t, `echo \*`)
}

// TestDockerContainerRunAndExecUnwrap covers the `docker container` spelling
// of run and exec, which unwraps like `docker run` and `docker exec`.
func TestDockerContainerRunAndExecUnwrap(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want []string
	}{
		{"docker container exec executor rm -rf /x", []string{"rm -rf /x"}},
		{"docker container run img rm -rf /x", []string{"rm -rf /x"}},
		{"docker container run --rm -i -v v:/v debian:12-slim tar -C /v -xpz",
			[]string{"tar -C /v -xpz"}},
		{"docker -H x container exec -it c rm -f /x", []string{"rm -f /x"}},
	}
	for _, tc := range cases {
		assertUnits(t, tc.in, tc.want)
	}
	assertIndeterminate(t, "docker container run --bogus img rm x")
	assertDestructiveRow(t, "docker container exec executor rm -rf /x")
	assertDestructiveRow(t, "docker container run img rm -rf /x")
	assertDestructiveRow(t, "docker container run --rm -i -v v:/v debian:12-slim tar -C /v -xpz")
	// Other container subcommands are not wrappers and are not destructive.
	assertUnits(t, "docker container ls", []string{"docker container ls"})
}

// TestStdinAndHereStringShellsAreIndeterminate covers a shell that reads its
// script from stdin, a here-string, a redirection or a file. The script is
// unknown, so the unit is indeterminate instead of a plain `sh`.
func TestStdinAndHereStringShellsAreIndeterminate(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"echo 'rm -rf /x' | sh",
		"bash <<< 'rm -rf /x'",
		"cat <<EOF\nrm -rf /x\nEOF",
		"cat <<< 'rm -rf /x'",
		"sh < script.sh",
		"bash ./script.sh",
		"bash -s",
		"bash -- -c x",
		"su - root",
		"sudo bash",
		"bash --bogus -c 'echo hi'",
	} {
		assertIndeterminate(t, in)
	}
}

// TestUnnamedWrappersAreIndeterminate covers programs that run another
// program but are not named in ADR 0014. They fail closed.
func TestUnnamedWrappersAreIndeterminate(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"command rm -rf /x",
		"eval rm -rf /x",
		"xargs rm -rf",
		"doas rm -rf /x",
		"docker-compose exec executor rm -f /x",
		"runuser -u root -- rm -rf /x",
		"setsid rm -rf /x",
		"stdbuf -o0 rm -rf /x",
		"flock /tmp/l rm -rf /x",
		"watch rm -rf /x",
		"ionice -c3 rm -rf /x",
		"chroot /mnt rm -rf /x",
		"busybox rm -rf /x",
	} {
		assertIndeterminate(t, in)
	}
}
