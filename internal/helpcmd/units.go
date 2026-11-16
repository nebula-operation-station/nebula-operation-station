// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import (
	"errors"
	"fmt"
	"strings"
)

// MaxCommandBytes is the longest command text Units accepts. Longer input is
// rejected with ErrTooLong, and Assess treats it as destructive. The limit is
// an implementation choice of this package; ADR 0014 sets no command length.
const MaxCommandBytes = 4096

// maxNesting bounds how often a `sh -c`, `bash -c` or `su -c` string is split
// again. Deeper nesting makes the unit indeterminate (fail closed).
const maxNesting = 4

// ErrTooLong is returned by Units for input longer than MaxCommandBytes.
var ErrTooLong = errors.New("command is longer than the maximum length")

// ErrUnbalanced is returned by Units when a quote or a $( … ) / backtick
// substitution is not closed, so the command cannot be split reliably.
var ErrUnbalanced = errors.New("unbalanced quote or substitution")

// Unit is one simple command of a shown command after the wrappers of ADR
// 0014 ("What V6 matches (units)") have been removed. Program is the last
// path element of the program word, so /usr/sbin/userdel gives userdel.
type Unit struct {
	// Program is the program word, reduced to its last path element.
	Program string
	// Args are the words after the program word, quotes removed.
	Args []string
	// Indeterminate is set when the unwrapper met an option or wrapper form
	// that the ADR does not name. Such a unit counts as destructive.
	Indeterminate bool
}

// Units splits cmd at ;, &&, ||, |, & and the other shell syntax that starts
// a new command, drops redirections and unwraps the wrappers named in ADR
// 0014. It returns one Unit per simple command that runs something. Input that
// cannot be split reliably yields an error; Assess treats that as destructive.
func Units(cmd string) ([]Unit, error) {
	if len(cmd) > MaxCommandBytes {
		return nil, fmt.Errorf("split command: %w", ErrTooLong)
	}
	return unitsAt(cmd, 0)
}

func unitsAt(cmd string, depth int) ([]Unit, error) {
	simple, err := splitSimple(cmd)
	if err != nil {
		return nil, err
	}
	var out []Unit
	for _, sc := range simple {
		us, err := unwrap(sc, depth)
		if err != nil {
			return nil, err
		}
		out = append(out, us...)
	}
	return out, nil
}

// substitution is an open $( … ) or backtick substitution. Inside it the
// shell reads code again, so separators and whitespace have their unquoted
// meaning until the substitution closes.
type substitution struct {
	savedDouble bool     // double-quote state before the substitution opened
	savedCmd    []string // words of the enclosing command so far
	savedSkip   bool     // the enclosing command had a redirection target pending
	backtick    bool
	depth       int // open parentheses inside a $( … ) substitution
}

// simpleCmd is one simple command: its words, quotes removed, and whether
// some word has an expansion or a glob that the scanner does not evaluate.
type simpleCmd struct {
	words []string
	// dynamic is set when a word contains `$` outside single quotes (a
	// parameter, arithmetic, ANSI-C or locale expansion) or an unquoted glob
	// character. The shell replaces such a word before it runs, so the
	// program and the arguments are unknown.
	dynamic bool
}

// splitSimple splits s into simple commands. Quotes and escapes are removed
// from words the way the shell removes them. Redirections, including their
// target word, are dropped. The scanner errs on the side of splitting: a
// backslash never hides a separator, so a separator always starts a new
// command.
func splitSimple(s string) ([]simpleCmd, error) {
	var (
		cmds     []simpleCmd
		cur      []string
		word     []byte
		inWord   bool
		wordDyn  bool // the current word has an expansion or a glob
		cmdDyn   bool // the current simple command has a dynamic word
		skipWord bool // the next word is a redirection target
		inSingle bool
		inDouble bool
		stack    []substitution
	)
	flush := func() {
		if !inWord {
			return
		}
		if skipWord {
			skipWord = false
		} else {
			cur = append(cur, string(word))
			cmdDyn = cmdDyn || wordDyn
		}
		word = word[:0]
		inWord = false
		wordDyn = false
	}
	// endCommand ends the current simple command. A command whose program or
	// arguments come from a substitution is kept even without words: the
	// output of the substitution may be a program to run.
	endCommand := func() {
		flush()
		if len(cur) > 0 || cmdDyn {
			cmds = append(cmds, simpleCmd{words: cur, dynamic: cmdDyn})
		}
		cur = nil
		cmdDyn = false
		skipWord = false
	}
	// pushSubstitution opens a substitution inside the current command. The
	// words of the enclosing command are saved, so the substitution's own
	// commands are split separately; the enclosing command is marked dynamic
	// when the substitution closes, because its program or argument is the
	// output of the substitution.
	pushSubstitution := func(backtick bool) {
		flush()
		stack = append(stack, substitution{
			savedDouble: inDouble,
			savedCmd:    cur,
			savedSkip:   skipWord,
			backtick:    backtick,
		})
		cur = nil
		cmdDyn = false
		skipWord = false
		inDouble = false
	}
	popSubstitution := func() {
		endCommand()
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		inDouble = top.savedDouble
		cur = top.savedCmd
		cmdDyn = true
		skipWord = top.savedSkip
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		if inSingle {
			if c == '\'' {
				inSingle = false
			} else {
				word = append(word, c)
			}
			continue
		}
		if c == '\\' && inDouble && i+1 < len(s) {
			// Inside double quotes a backslash escapes only these characters;
			// before any other character it is literal.
			if n := s[i+1]; n == '"' || n == '\\' || n == '$' || n == '`' {
				word = append(word, n)
				inWord = true
				i++
				continue
			}
		}
		if c == '\\' && !inDouble {
			// An unquoted backslash escapes the next character, which the
			// scanner does not evaluate: `\rm`, `\;` and `\<newline>` are not
			// split the way the shell reads them. The word is dynamic, so the
			// command is indeterminate (fail closed).
			wordDyn, inWord = true, true
			if i+1 < len(s) {
				word = append(word, s[i+1])
				i++
			} else {
				word = append(word, c)
			}
			continue
		}
		if c == '$' && i+1 < len(s) && s[i+1] == '(' {
			pushSubstitution(false)
			i++
			continue
		}
		if c == '$' {
			// Any other `$` outside single quotes is an expansion ($X, ${X},
			// $'…' ANSI-C, $"…"), so the word is not known before it runs.
			wordDyn, inWord = true, true
		}
		if c == '`' {
			if n := len(stack); n > 0 && stack[n-1].backtick {
				popSubstitution()
			} else {
				pushSubstitution(true)
			}
			continue
		}
		if c == '"' {
			inDouble = !inDouble
			inWord = true
			continue
		}
		if c == '\'' && !inDouble {
			inSingle = true
			inWord = true
			continue
		}
		if inDouble {
			word = append(word, c)
			inWord = true
			continue
		}
		switch c {
		case '(':
			if n := len(stack); n > 0 && !stack[n-1].backtick {
				stack[n-1].depth++
			}
			endCommand()
		case ')':
			endCommand()
			if n := len(stack); n > 0 && !stack[n-1].backtick {
				if stack[n-1].depth == 0 {
					popSubstitution()
				} else {
					stack[n-1].depth--
				}
			}
		case ';', '&', '|', '\n', '\r':
			endCommand()
		case '{', '}':
			// A brace at the start of a command followed by a blank (or, for
			// `}`, by an operator or the end) is the reserved word of a brace
			// group. Anywhere else an unquoted brace may be brace expansion,
			// which rewrites the word, so the word is dynamic.
			if isBraceKeyword(s, i) && !inWord && !skipWord && len(cur) == 0 {
				break
			}
			wordDyn = true
			word = append(word, c)
			inWord = true
		case ' ', '\t':
			flush()
		case '>', '<':
			if i+1 < len(s) && s[i+1] == '(' {
				// Process substitution <(…) or >(…): the enclosing command is
				// indeterminate once the substitution closes.
				pushSubstitution(false)
				i++
				break
			}
			if c == '<' && i+1 < len(s) && s[i+1] == '<' {
				// A here-document or here-string feeds the command text on
				// stdin, which the scanner does not read: indeterminate.
				cmdDyn = true
			}
			if inWord && allDigits(word) {
				word = word[:0]
				inWord = false
				wordDyn = false
			} else {
				flush()
			}
			skipWord = true
			for i+1 < len(s) && strings.IndexByte(">&<|", s[i+1]) >= 0 {
				i++
			}
		case '*', '?', '[':
			// An unquoted glob is expanded by the shell to file names, which
			// may name any program or any option.
			wordDyn = true
			word = append(word, c)
			inWord = true
		default:
			word = append(word, c)
			inWord = true
		}
	}
	if inSingle || inDouble || len(stack) > 0 {
		return nil, ErrUnbalanced
	}
	endCommand()
	return cmds, nil
}

// isBraceKeyword reports whether the brace at s[i] is a brace-group reserved
// word: `{` followed by a blank, or `}` followed by a blank, an operator or
// the end. Callers check that the brace starts a command.
func isBraceKeyword(s string, i int) bool {
	if s[i] == '{' {
		return i+1 < len(s) && strings.IndexByte(" \t\n", s[i+1]) >= 0
	}
	return i+1 >= len(s) || strings.IndexByte(" \t\n;&|)", s[i+1]) >= 0
}

func allDigits(b []byte) bool {
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// programRunners are programs that run another program, a shell command or
// a `-exec` argument, and that ADR 0014 does not unwrap. Their unit is
// indeterminate, so it fails closed: V6 cannot see the program they run. The
// shells sh, bash and su are not here; their `-c` string is unwrapped (see
// unwrap). The env, nice, nohup and timeout wrappers are unwrapped too.
//
// The rule is a closed list of the programs that run something, not a rule
// about what they run: a program that runs another one and is missing here is
// checked as itself. The list therefore names every such program we know of.
var programRunners = map[string]bool{
	"command": true, "eval": true, "xargs": true, "doas": true,
	"docker-compose": true, "runuser": true, "setsid": true, "ionice": true,
	"stdbuf": true, "flock": true, "watch": true, "chroot": true,
	"busybox": true,
	// Other shells: their -c string is not unwrapped, so they fail closed.
	"zsh": true, "dash": true, "ksh": true, "fish": true,
	// Namespace, service and remote runners.
	"nsenter": true, "unshare": true, "systemd-run": true, "pkexec": true,
	"ssh": true,
	// `coproc` is a bash keyword that starts a command in the background; the
	// word after it is not the program. It is listed as a program name.
	"coproc": true,
}

// findExecArgs are the find options that run a command: the word after them
// is a program, so a find unit with one of them is indeterminate.
var findExecArgs = []string{"-exec", "-execdir", "-ok", "-okdir"}

// unwrap removes the wrappers of one simple command until nothing changes and
// returns its units. depth counts nested sh -c strings. A dynamic simple
// command (an expansion or glob in one of its words) is indeterminate.
func unwrap(sc simpleCmd, depth int) ([]Unit, error) {
	words := sc.words
	if sc.dynamic {
		return indeterminate(words), nil
	}
loop:
	for {
		words = dropKeywords(words)
		if len(words) == 0 {
			return nil, nil
		}
		if isAssignment(words[0]) {
			words = words[1:]
			continue
		}
		var (
			rest []string
			ok   = true
		)
		name := base(words[0])
		switch name {
		case "sudo":
			rest, ok = skipOptions(words[1:], sudoSpec)
		case "env":
			rest, ok = skipOptions(words[1:], envSpec)
		case "exec", "nohup", "time":
			rest, ok = skipOptions(words[1:], noOptions)
		case "nice":
			rest, ok = skipOptions(words[1:], niceSpec)
		case "timeout":
			rest, ok = skipOptions(words[1:], timeoutSpec)
			if ok {
				rest = dropFirst(rest) // DURATION
			}
		case "docker":
			var wrapper bool
			rest, ok, wrapper = dockerRest(words)
			if ok && !wrapper {
				break loop
			}
		case "sh", "bash", "su":
			// A shell without -c runs a script from a file, stdin or a
			// here-string, which is unknown: indeterminate.
			sp := shellSpec
			if name == "su" {
				sp = suSpec
			}
			str, found := shellCommandString(words[1:], sp)
			if !found || depth >= maxNesting {
				return indeterminate(words), nil
			}
			return unitsAt(str, depth+1)
		case "find":
			if containsAny(words[1:], findExecArgs) {
				return indeterminate(words), nil
			}
			break loop
		default:
			if programRunners[name] {
				return indeterminate(words), nil
			}
			break loop
		}
		if !ok {
			return indeterminate(words), nil
		}
		words = rest
	}
	// A program word that is empty or starts with `-` is not a program name:
	// the unit is an option or argument that a wrapper or an image passed on,
	// such as the entrypoint of `docker run img -rf /x`. Fail closed.
	if prog := base(words[0]); prog == "" || prog[0] == '-' {
		return indeterminate(words), nil
	}
	return []Unit{{Program: base(words[0]), Args: words[1:]}}, nil
}

// indeterminate is the fail-closed unit for a wrapper form the ADR does not
// name. Its program is the first word, reduced to its last path element.
func indeterminate(words []string) []Unit {
	u := Unit{Indeterminate: true}
	if len(words) > 0 {
		u.Program = base(words[0])
	}
	return []Unit{u}
}

// dropKeywords removes shell reserved words that start a simple command
// (`if`, `then`, `!` and the like). They change no program that runs.
func dropKeywords(words []string) []string {
	for len(words) > 0 && reservedWords[words[0]] {
		words = words[1:]
	}
	return words
}

var reservedWords = map[string]bool{
	"!": true, "if": true, "then": true, "elif": true, "else": true,
	"do": true, "while": true, "until": true, "fi": true, "done": true,
}

// isAssignment reports whether w is a NAME=value word.
func isAssignment(w string) bool {
	i := strings.IndexByte(w, '=')
	if i <= 0 {
		return false
	}
	for j := 0; j < i; j++ {
		c := w[j]
		isLetter := c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !isLetter && !(j > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// base returns the last path element of a program word.
func base(p string) string {
	return p[strings.LastIndexByte(p, '/')+1:]
}

// dropFirst removes the first word of r, or returns nil when r is empty.
func dropFirst(r []string) []string {
	if len(r) == 0 {
		return nil
	}
	return r[1:]
}

// shellCommandString returns the command string of a shell invocation: the
// value of -c or --command, where -c may sit in a short option cluster such as
// -lc or -ec. found is false when the arguments do not give a command string,
// or when an option is unknown, a value is missing or an option is ambiguous.
// The caller treats found=false as indeterminate (fail closed).
func shellCommandString(args []string, sp optionSpec) (str string, found bool) {
	for i := 0; i < len(args); i++ {
		w := args[i]
		switch {
		case w == "--":
			return "", false
		case w == "-" && sp.stopAtOperand:
			return "", false
		case w == "-":
			// su: a bare dash is the login option.
		case w == "--command" && sp.command:
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		case sp.command && strings.HasPrefix(w, "--command="):
			return w[len("--command="):], true
		case strings.HasPrefix(w, "--"):
			name, _, hasValue := strings.Cut(w, "=")
			switch {
			case hasValue && (sp.valueLong[name] || sp.boolLong[name]):
			case !hasValue && sp.valueLong[name]:
				if i+1 >= len(args) {
					return "", false
				}
				i++
			case !hasValue && sp.boolLong[name]:
			default:
				return "", false
			}
		case len(w) > 1 && (w[0] == '-' || w[0] == '+'):
			sawCommand, valueNext := false, false
			for k := 1; k < len(w); k++ {
				ch := w[k]
				switch {
				case sp.command && w[0] == '-' && ch == 'c':
					sawCommand = true
				case strings.IndexByte(sp.valueShort, ch) >= 0:
					// A value option takes the next word; inside a cluster
					// the value would be ambiguous, so it must come last.
					if k != len(w)-1 {
						return "", false
					}
					valueNext = true
				case strings.IndexByte(sp.boolShort, ch) >= 0:
				default:
					return "", false
				}
			}
			if sawCommand && valueNext {
				return "", false
			}
			if valueNext {
				if i+1 >= len(args) {
					return "", false
				}
				i++
				continue
			}
			if sawCommand {
				if i+1 < len(args) {
					return args[i+1], true
				}
				return "", false
			}
		default:
			// An operand. For sh and bash it is the script file, so the
			// options end here. su takes a user name here and still reads
			// options after it.
			if sp.stopAtOperand {
				return "", false
			}
		}
	}
	return "", false
}

// shellSpec lists the options of sh and bash that the unwrapper knows. Any
// other option is unknown and the unit is indeterminate. -c, -o and -O are
// the only ones that change what runs; the rest are accepted as flags.
var shellSpec = optionSpec{
	command:       true,
	stopAtOperand: true,
	valueShort:    "oO",
	boolShort:     "abBCdDeEfhHiklmnpPqrsStTuvVx",
	valueLong:     optSet("--rcfile", "--init-file"),
	boolLong: optSet("--login", "--norc", "--noprofile", "--posix",
		"--restricted", "--verbose", "--version", "--help", "--debugger",
		"--noediting", "--dump-strings", "--dump-po-strings", "--pretty-print"),
}

// suSpec lists the options of su that the unwrapper knows (util-linux).
var suSpec = optionSpec{
	command:    true,
	valueShort: "gGsw",
	boolShort:  "fhlmpPV",
	valueLong: optSet("--shell", "--group", "--supp-group",
		"--whitelist-environment", "--session-command"),
	boolLong: optSet("--login", "--preserve-environment", "--fast", "--pty",
		"--help", "--version"),
}

// dockerRest handles `docker run`, `docker exec`, `docker container run`,
// `docker container exec`, `docker compose exec` and `docker compose run`. It returns the command after the image, container or
// service word. wrapper is false when the unit is not one of these forms; ok
// is false when an option is unknown.
func dockerRest(words []string) (rest []string, ok, wrapper bool) {
	rest, ok = skipOptions(words[1:], dockerGlobalSpec)
	if !ok {
		return nil, false, true
	}
	if len(rest) == 0 {
		return nil, true, false
	}
	switch rest[0] {
	case "run", "exec":
		return dockerRunOrExec(rest)
	case "container":
		// `docker container run|exec` is the same wrapper as `docker run|exec`.
		if len(rest) > 1 && (rest[1] == "run" || rest[1] == "exec") {
			return dockerRunOrExec(rest[1:])
		}
		return nil, true, false
	case "compose":
		r, ok := skipOptions(rest[1:], composeGlobalSpec)
		if !ok {
			return nil, false, true
		}
		if len(r) == 0 {
			return nil, true, false
		}
		var sp optionSpec
		switch r[0] {
		case "exec":
			sp = composeExecSpec
		case "run":
			sp = composeRunSpec
		default:
			return nil, true, false
		}
		r2, ok := skipOptions(r[1:], sp)
		if !ok {
			return nil, false, true
		}
		return dropFirst(r2), true, true
	}
	return nil, true, false
}

// dockerRunOrExec unwraps `docker run` or `docker exec`; args[0] is "run" or
// "exec". It returns the command after the image or container word.
func dockerRunOrExec(args []string) (rest []string, ok, wrapper bool) {
	sp := dockerRunSpec
	if args[0] == "exec" {
		sp = dockerExecSpec
	}
	r, ok := skipOptions(args[1:], sp)
	if !ok {
		return nil, false, true
	}
	return dropFirst(r), true, true
}

// optionSpec lists the options of one wrapper. Options not listed are
// unknown, and an unknown option makes the unit indeterminate.
type optionSpec struct {
	valueShort string // short options that take a value
	boolShort  string // short options without a value
	valueLong  map[string]bool
	boolLong   map[string]bool
	// unsafeLong lists long options that take a value and change the program
	// that runs (`docker run --entrypoint`). They are never skipped: seeing one
	// makes the wrapper form unknown, so the unit is indeterminate.
	unsafeLong map[string]bool
	// command is set for sh, bash and su: -c (or --command) gives the command
	// string, which may sit in a short cluster such as -lc.
	command bool
	// stopAtOperand is set for sh and bash: the first word that is not an
	// option is the script file, so the options end there.
	stopAtOperand bool
}

var noOptions = optionSpec{}

// skipOptions removes the leading options of words that are listed in sp,
// including the values of value-taking options. ok is false when an option is
// not listed or its value is missing.
func skipOptions(words []string, sp optionSpec) (rest []string, ok bool) {
	for len(words) > 0 {
		w := words[0]
		if w == "--" {
			return words[1:], true
		}
		if w == "-" || !strings.HasPrefix(w, "-") {
			return words, true
		}
		if strings.HasPrefix(w, "--") {
			name, _, hasValue := strings.Cut(w, "=")
			switch {
			case sp.unsafeLong[name]:
				return nil, false
			case hasValue && (sp.valueLong[name] || sp.boolLong[name]):
				words = words[1:]
			case !hasValue && sp.valueLong[name]:
				if len(words) < 2 {
					return nil, false
				}
				words = words[2:]
			case !hasValue && sp.boolLong[name]:
				words = words[1:]
			default:
				return nil, false
			}
			continue
		}
		r, ok := skipShortCluster(words, sp)
		if !ok {
			return nil, false
		}
		words = r
	}
	return words, true
}

// skipShortCluster consumes the short option cluster words[0] (for example
// -xpz or -n5) and the value of its last value-taking option, if any.
func skipShortCluster(words []string, sp optionSpec) ([]string, bool) {
	w := words[0]
	for k := 1; k < len(w); k++ {
		ch := w[k]
		if strings.IndexByte(sp.valueShort, ch) >= 0 {
			if k == len(w)-1 {
				if len(words) < 2 {
					return nil, false
				}
				return words[2:], true
			}
			return words[1:], true
		}
		if strings.IndexByte(sp.boolShort, ch) < 0 {
			return nil, false
		}
	}
	return words[1:], true
}

func optSet(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// The option tables below cover the options of the wrappers named in ADR
// 0014 ("What V6 matches (units)"). The ADR lists some of them with "…", so
// they are complete for the common forms; every other option is unknown and
// makes the unit indeterminate, which is the fail-closed reading.

var sudoSpec = optionSpec{
	valueShort: "CDghprtTuU",
	boolShort:  "AbEeHiKklnPSsv",
	valueLong: optSet("--user", "--group", "--host", "--prompt", "--role",
		"--type", "--close-from", "--chdir", "--command-timeout", "--other-user"),
	boolLong: optSet("--login", "--shell", "--preserve-env", "--set-home",
		"--background", "--reset-timeout", "--non-interactive", "--stdin",
		"--askpass", "--validate", "--list", "--remove-timestamp",
		"--reset-timestamp", "--help", "--version", "--preserve-groups"),
}

var envSpec = optionSpec{
	valueShort: "uC",
	boolShort:  "i0",
	valueLong:  optSet("--unset", "--chdir"),
	boolLong:   optSet("--ignore-environment", "--null"),
}

var niceSpec = optionSpec{
	valueShort: "n",
	valueLong:  optSet("--adjustment"),
}

var timeoutSpec = optionSpec{
	valueShort: "sk",
	boolShort:  "v",
	valueLong:  optSet("--signal", "--kill-after"),
	boolLong:   optSet("--foreground", "--preserve-status"),
}

var dockerGlobalSpec = optionSpec{
	valueShort: "Hcl",
	boolShort:  "Dv",
	valueLong: optSet("--config", "--context", "--host", "--log-level",
		"--tlscacert", "--tlscert", "--tlskey"),
	boolLong: optSet("--debug", "--tls", "--tlsverify", "--version", "--help"),
}

var dockerRunSpec = optionSpec{
	valueShort: "acehlmpuvwf",
	boolShort:  "diPtq",
	valueLong: optSet("--add-host", "--attach", "--blkio-weight", "--cap-add",
		"--cap-drop", "--cgroup-parent", "--cidfile", "--cpu-period",
		"--cpu-quota", "--cpu-shares", "--cpus", "--cpuset-cpus", "--cpuset-mems",
		"--detach-keys", "--device", "--device-cgroup-rule", "--device-read-bps",
		"--device-read-iops", "--device-write-bps", "--device-write-iops",
		"--dns", "--dns-option", "--dns-search", "--domainname",
		"--env", "--env-file", "--expose", "--gpus", "--group-add",
		"--health-cmd", "--health-interval", "--health-retries",
		"--health-start-period", "--health-timeout", "--hostname", "--ip",
		"--ip6", "--ipc", "--isolation", "--label", "--label-file", "--link",
		"--link-local-ip", "--log-driver", "--log-opt", "--mac-address",
		"--memory", "--memory-reservation", "--memory-swap",
		"--memory-swappiness", "--mount", "--name", "--network", "--net",
		"--network-alias", "--oom-score-adj", "--pid", "--pids-limit",
		"--platform", "--pull", "--publish", "--restart", "--runtime",
		"--security-opt", "--shm-size", "--stop-signal", "--stop-timeout",
		"--storage-opt", "--sysctl", "--tmpfs", "--ulimit", "--user", "--userns",
		"--uts", "--volume", "--volumes-from", "--workdir", "--annotation",
		"--cgroupns", "--cpu-rt-period", "--cpu-rt-runtime"),
	unsafeLong: optSet("--entrypoint"),
	boolLong: optSet("--detach", "--interactive", "--tty", "--rm", "--privileged",
		"--publish-all", "--read-only", "--init", "--quiet",
		"--no-healthcheck", "--sig-proxy", "--oom-kill-disable", "--help"),
}

var dockerExecSpec = optionSpec{
	valueShort: "euw",
	boolShort:  "dit",
	valueLong:  optSet("--detach-keys", "--env", "--env-file", "--user", "--workdir"),
	boolLong:   optSet("--detach", "--interactive", "--tty", "--privileged"),
}

var composeGlobalSpec = optionSpec{
	valueShort: "fp",
	valueLong: optSet("--file", "--project-name", "--project-directory",
		"--env-file", "--profile", "--ansi", "--parallel", "--progress"),
	boolLong: optSet("--compatibility", "--dry-run", "--verbose",
		"--all-resources", "--help"),
}

var composeExecSpec = optionSpec{
	valueShort: "euw",
	boolShort:  "dT",
	valueLong:  optSet("--env", "--index", "--user", "--workdir"),
	boolLong:   optSet("--detach", "--no-TTY", "--privileged", "--interactive", "--tty"),
}

var composeRunSpec = optionSpec{
	valueShort: "elpuvw",
	boolShort:  "dTit",
	valueLong: optSet("--name", "--env", "--label", "--user",
		"--volume", "--workdir", "--publish", "--cap-add", "--cap-drop",
		"--pull", "--env-from-file"),
	unsafeLong: optSet("--entrypoint"),
	boolLong: optSet("--detach", "--rm", "--no-deps", "--service-ports",
		"--build", "--quiet-pull", "--remove-orphans", "--no-TTY",
		"--interactive", "--tty", "--use-aliases", "--no-log-prefix", "--quiet",
		"--privileged", "--help"),
}
