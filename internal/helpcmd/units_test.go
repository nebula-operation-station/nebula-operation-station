// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// unitStrings renders units as "program arg…" with an "!" prefix for
// indeterminate units, so table tests stay readable.
func unitStrings(us []Unit) []string {
	out := make([]string, 0, len(us))
	for _, u := range us {
		s := strings.TrimSpace(u.Program + " " + strings.Join(u.Args, " "))
		if u.Indeterminate {
			s = "!" + s
		}
		out = append(out, s)
	}
	return out
}

func TestUnitsSplitsAtEveryOperator(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"semicolon", "echo a; rm x", []string{"echo a", "rm x"}},
		{"and", "nebula status && sudo nebula netdev remove fw-01",
			[]string{"nebula status", "nebula netdev remove fw-01"}},
		{"or", "false || rm x", []string{"false", "rm x"}},
		{"pipe", "cat k | dd of=x", []string{"cat k", "dd of=x"}},
		{"background", "sleep 1 & rm x", []string{"sleep 1", "rm x"}},
		{"newline is never in V1 input but splits anyway", "a\nrm x", []string{"a", "rm x"}},
		{"no spaces around operators", "a;rm x|dd", []string{"a", "rm x", "dd"}},
		{"subshell and brace group", "(rm x) ; { dd of=y; }", []string{"rm x", "dd of=y"}},
		{"command substitution", "echo $(rm x)", []string{"echo", "rm x"}},
		{"backtick", "echo `rm x`", []string{"echo", "rm x"}},
		{"operator inside double quotes is literal", `echo "a; rm x"`, []string{"echo a; rm x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			us, err := Units(tc.in)
			if err != nil {
				t.Fatalf("Units(%q): %v", tc.in, err)
			}
			if got := unitStrings(us); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Units(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestUnitsDropsRedirections(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"rm x > /dev/null":       "rm x",
		"rm x 2>&1":              "rm x",
		"rm x 2> err.log":        "rm x",
		"cat < in rm x":          "cat rm x",
		"echo a >>log rm -rf /x": "echo a rm -rf /x",
		"rm x >&2":               "rm x",
	}
	for in, want := range cases {
		us, err := Units(in)
		if err != nil {
			t.Fatalf("Units(%q): %v", in, err)
		}
		if got := unitStrings(us); len(got) != 1 || got[0] != want {
			t.Errorf("Units(%q) = %q, want [%q]", in, got, want)
		}
	}
}

func TestUnitsHonoursQuotesAndEscapes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want []string
	}{
		{`echo "rm -rf /x"`, []string{`echo rm -rf /x`}},
		{`echo 'a; rm -rf /x'`, []string{`echo a; rm -rf /x`}},
		{`echo ''`, []string{`echo`}},
		{`echo a\;b`, []string{`echo a\`, `b`}},
		{`echo a\ b`, []string{`echo a b`}},
		{`echo "a\"b"`, []string{`echo a"b`}},
	}
	for _, tc := range cases {
		us, err := Units(tc.in)
		if err != nil {
			t.Fatalf("Units(%q): %v", tc.in, err)
		}
		if got := unitStrings(us); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("Units(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestUnitsRejectsUnbalancedQuoteAndLongInput(t *testing.T) {
	t.Parallel()
	if _, err := Units(`echo 'abc`); !errors.Is(err, ErrUnbalanced) {
		t.Errorf("unbalanced single quote: got %v, want ErrUnbalanced", err)
	}
	if _, err := Units(`echo "abc`); !errors.Is(err, ErrUnbalanced) {
		t.Errorf("unbalanced double quote: got %v, want ErrUnbalanced", err)
	}
	if _, err := Units(`echo "$(rm x"`); !errors.Is(err, ErrUnbalanced) {
		t.Errorf("unclosed substitution: got %v, want ErrUnbalanced", err)
	}
	long := strings.Repeat("a", MaxCommandBytes+1)
	if _, err := Units(long); !errors.Is(err, ErrTooLong) {
		t.Errorf("long input: got %v, want ErrTooLong", err)
	}
	if _, err := Units(strings.Repeat("a", MaxCommandBytes)); err != nil {
		t.Errorf("input of exactly MaxCommandBytes: %v", err)
	}
}

func TestUnitsUnwrapsADRExamples(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"sudo with user option", "sudo -u root shred -u k", []string{"shred -u k"}},
		{"sudo bare", "sudo rm -rf /x", []string{"rm -rf /x"}},
		{"sudo with long option and value", "sudo --user root rm x", []string{"rm x"}},
		{"sudo end of options", "sudo -- rm x", []string{"rm x"}},
		{"env and nice", "env A=1 nice -n 5 dd if=/dev/zero of=x", []string{"dd if=/dev/zero of=x"}},
		{"bare assignments", "A=1 B=2 rm x", []string{"rm x"}},
		{"nice attached value", "nice -n5 rm x", []string{"rm x"}},
		{"nice long option", "nice --adjustment=5 rm x", []string{"rm x"}},
		{"exec nohup time", "exec nohup time rm x", []string{"rm x"}},
		{"timeout with duration", "timeout 5s rm x", []string{"rm x"}},
		{"timeout with signal", "timeout -s KILL 5s rm x", []string{"rm x"}},
		{"program by last path element", "/usr/sbin/userdel a", []string{"userdel a"}},
		{"docker run skips options and image",
			"docker run --rm -v nebula_executor-data:/v debian:12-slim rm -rf /v/x",
			[]string{"rm -rf /v/x"}},
		{"docker run restore pipe ends in tar",
			"cat b.tgz | docker run --rm -i -v nebula_executor-data:/v debian:12-slim tar -C /v -xpz",
			[]string{"cat b.tgz", "tar -C /v -xpz"}},
		{"docker compose exec skips service",
			"docker compose exec executor rm -f /x", []string{"rm -f /x"}},
		{"docker compose run with global option",
			"docker compose -f a.yml run --rm web rm -rf /x", []string{"rm -rf /x"}},
		{"docker exec", "docker exec -it c rm -rf /x", []string{"rm -rf /x"}},
		{"docker volume rm is not unwrapped",
			"docker volume rm v", []string{"docker volume rm v"}},
		{"bash -c string is split again", "bash -c 'rm -rf /x'", []string{"rm -rf /x"}},
		{"sh -c with operators", "sh -c 'echo a; dd of=x'", []string{"echo a", "dd of=x"}},
		{"su -c", "su - root -c 'userdel a'", []string{"userdel a"}},
		{"nested wrapper in sh -c",
			`sh -c 'sudo -u root bash -c "rm -rf /x"'`, []string{"rm -rf /x"}},
		{"keywords before a command", "if rm -rf /x; then echo ok; fi",
			[]string{"rm -rf /x", "echo ok"}},
		{"double quoted command substitution", `echo "$(rm -rf /x)"`,
			[]string{"echo", "rm -rf /x", ""}},
		{"bang negation", "! rm -rf /x", []string{"rm -rf /x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			us, err := Units(tc.in)
			if err != nil {
				t.Fatalf("Units(%q): %v", tc.in, err)
			}
			if got := unitStrings(us); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Units(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestUnitsMarksUnknownWrapperOptionsIndeterminate(t *testing.T) {
	t.Parallel()
	cases := []string{
		"docker run --bogus-option img rm x",
		"sudo --bogus rm x",
		"sudo -Z rm x",
		"env -Z rm x",
		"time -p rm x",
		"nice -5 rm x",
		"exec -a name rm x",
		"docker -Q run img rm x",
		"docker compose --bogus exec s rm x",
		"docker compose exec --bogus s rm x",
		"bash -c",
		"sudo -u",
	}
	for _, in := range cases {
		us, err := Units(in)
		if err != nil {
			t.Fatalf("Units(%q): %v", in, err)
		}
		found := false
		for _, u := range us {
			if u.Indeterminate {
				found = true
			}
		}
		if !found {
			t.Errorf("Units(%q) = %q, want an indeterminate unit", in, unitStrings(us))
		}
	}
}

func TestUnitsOfWrapperOnlyIsEmpty(t *testing.T) {
	t.Parallel()
	// A wrapper with nothing after it runs nothing; the unit list is empty
	// and the verdict cannot be destructive because of it.
	for _, in := range []string{"sudo", "env A=1", "timeout 5s", "docker run img"} {
		us, err := Units(in)
		if err != nil {
			t.Fatalf("Units(%q): %v", in, err)
		}
		if len(us) != 0 {
			t.Errorf("Units(%q) = %q, want no units", in, unitStrings(us))
		}
	}
}

func TestUnitsNestingIsBounded(t *testing.T) {
	t.Parallel()
	in := "rm x"
	escape := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	for i := 0; i < maxNesting+2; i++ {
		in = `sh -c "` + escape.Replace(in) + `"`
	}
	us, err := Units(in)
	if err != nil {
		t.Fatalf("Units: %v", err)
	}
	if len(us) != 1 || !us[0].Indeterminate {
		t.Errorf("deep nesting: got %q, want one indeterminate unit", unitStrings(us))
	}
}
