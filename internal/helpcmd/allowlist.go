// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import "strings"

// This file is the V6 allowlist of ADR 0014 (maintainer decision 2026-11-16,
// Axel): a command is harmless only when every simple command of it is, word
// for word, a program of the allowlist with an allowed subcommand and allowed
// options. Everything else is indeterminate and needs confirmation. The
// harmless check does not unwrap anything: a wrapper (`sudo`, `env`,
// `NAME=value`, `nice`, `taskset`, `xargs`, `sh -c`, an interpreter, …) is not
// on the allowlist, so it never makes its command harmless, whatever it runs.
//
// The table is exactly the ADR table. Entries are not added here on their own
// initiative; a change needs an ADR change and a maintainer review.

// longKind says whether a long option takes a value.
type longKind uint8

const (
	// longFlag is a long option without a value (`--no-pager`).
	longFlag longKind = iota + 1
	// longValue is a long option with a value, as `--x=v` or `--x v`.
	longValue
	// longOptional is a long option whose value, if any, is attached with
	// `=` (`--color`, `--color=auto`).
	longOptional
)

// argSpec lists the options and operands that one allowlist form accepts.
// Options are matched by their exact spelling: an unlisted option, an
// abbreviation of a long option or an unlisted letter in a short cluster is
// not harmless.
type argSpec struct {
	// shortFlags are short options without a value; they may be clustered.
	shortFlags string
	// shortValue are short options with a value: the rest of the cluster
	// (`-n20`) or, when last in the cluster, the next word (`-n 20`).
	shortValue string
	// shortOptional are short options with an optional value (getopt `n::`):
	// the rest of the cluster is the value (`-n20`, `-b-1`). A bare option,
	// last in its cluster, takes the next word only when the form for its
	// letter accepts that word (journalctl `-n 20`); otherwise, and when the
	// form is nil, the next word is checked as an option or operand of its
	// own, as the program reads it (`journalctl -n --rotate`).
	shortOptional map[byte]func(string) bool
	// numericWord accepts a whole word `-NUM` (head and tail `-5`). Digits
	// are never cluster letters: `-5c` is one obsolete count option, not
	// `-5 -c`, and stays indeterminate.
	numericWord bool
	// long maps a long option, with its leading `--`, to its kind.
	long map[string]longKind
	// exact are whole option words accepted as written (`ip -br`).
	exact map[string]bool
	// operands allows words that are not options.
	operands bool
	// anyArgs accepts every option and operand. It is used only for programs
	// that, with any option, only stat files or read /proc (see the ADR
	// table). Their operands are still checked when opensFiles is set, so an
	// anyArgs rule must set it.
	anyArgs bool
	// bareOperandsOpen is set with anyArgs for programs that open their
	// operands as files (ls, df). A word that is neither an option nor an
	// absolute path is then relative to the working directory, which may be
	// under dev, proc or sys, so it is not harmless.
	bareOperandsOpen bool
}

// allowRule is one program of the V6 allowlist.
type allowRule struct {
	// why is the reason of the ADR table that this program is harmless.
	why string
	// spec checks the arguments when the program has no subcommands.
	spec argSpec
	// subcommands maps a subcommand path (words separated by one space) to
	// the spec of the words after it. When set, the path must follow the
	// program right after the options of globals; the longest path wins.
	subcommands map[string]argSpec
	// globals are the options allowed before the subcommand path.
	globals argSpec
	// opensFiles is set for programs that open their operands. An operand
	// path with an element dev, proc or sys is then not harmless.
	opensFiles bool
}

// allowlisted reports whether cmd is harmless under the V6 allowlist: valid
// for V1, no `!`, splittable, at least one simple command, and every simple
// command an allowlisted program without redirection, expansion or group.
func allowlisted(cmd string) bool {
	if len(cmd) > MaxCommandBytes || CheckASCII(cmd) != nil {
		return false
	}
	// Interactive bash expands `!` (history expansion) before it parses the
	// line, so `ls !!` can run any earlier command.
	if strings.IndexByte(cmd, '!') >= 0 {
		return false
	}
	cmds, err := splitSimple(cmd)
	if err != nil || len(cmds) == 0 {
		return false
	}
	for _, c := range cmds {
		if c.dynamic || c.redirected || c.compound || len(c.words) == 0 {
			return false
		}
		r, ok := allowlist[c.words[0]]
		if !ok || !r.harmless(c.words[1:]) {
			return false
		}
	}
	return true
}

// harmless reports whether args (the words after the program) fit the rule.
func (r allowRule) harmless(args []string) bool {
	if r.subcommands == nil {
		return r.spec.accepts(args, r.opensFiles)
	}
	rest, ok := r.globals.scan(args, true, false)
	if !ok {
		return false
	}
	best := -1
	var spec argSpec
	for key, sp := range r.subcommands {
		path := strings.Split(key, " ")
		if len(path) <= best || len(path) > len(rest) {
			continue
		}
		match := true
		for i, w := range path {
			if rest[i] != w {
				match = false
				break
			}
		}
		if match {
			best, spec = len(path), sp
		}
	}
	if best < 0 {
		return false
	}
	return spec.accepts(rest[best:], r.opensFiles)
}

// accepts reports whether every word of args is an allowed option, option
// value or operand.
func (sp argSpec) accepts(args []string, opensFiles bool) bool {
	if sp.anyArgs {
		if !opensFiles {
			return true
		}
		// Every word is checked, options included: an option value can name
		// a special file too, and the program may open it. Words are literal
		// here: an expansion makes the command dynamic before this point.
		for _, w := range args {
			if namesSpecialFile(w) {
				return false
			}
			if sp.bareOperandsOpen && !strings.HasPrefix(w, "-") && !strings.HasPrefix(w, "/") {
				return false
			}
		}
		return true
	}
	_, ok := sp.scan(args, false, opensFiles)
	return ok
}

// scan checks the options of args. With stopAtOperand it stops at the first
// operand and returns the words from there; otherwise every operand is
// checked and rest is nil.
func (sp argSpec) scan(args []string, stopAtOperand, opensFiles bool) (rest []string, ok bool) {
	for i := 0; i < len(args); i++ {
		w := args[i]
		switch {
		case w == "--":
			if stopAtOperand {
				return nil, false
			}
			for _, op := range args[i+1:] {
				if !sp.operandOK(op, opensFiles) {
					return nil, false
				}
			}
			return nil, true
		case sp.exact[w]:
		case strings.HasPrefix(w, "--"):
			name, _, hasValue := strings.Cut(w, "=")
			switch sp.long[name] {
			case longFlag:
				if hasValue {
					return nil, false
				}
			case longValue:
				if !hasValue {
					if i+1 >= len(args) {
						return nil, false
					}
					i++
				}
			case longOptional:
			default:
				return nil, false
			}
		case sp.numericWord && isNumericOption(w):
		case len(w) > 1 && w[0] == '-':
			n, ok := sp.shortCluster(w, args[i+1:])
			if !ok {
				return nil, false
			}
			i += n
		default:
			if stopAtOperand {
				return args[i:], true
			}
			if !sp.operandOK(w, opensFiles) {
				return nil, false
			}
		}
	}
	return nil, true
}

// shortCluster checks the short option cluster w. next are the words after w.
// It returns how many of them are consumed as a value.
func (sp argSpec) shortCluster(w string, next []string) (consumed int, ok bool) {
	for k := 1; k < len(w); k++ {
		ch := w[k]
		if strings.IndexByte(sp.shortFlags, ch) >= 0 {
			continue
		}
		if strings.IndexByte(sp.shortValue, ch) >= 0 {
			if k < len(w)-1 {
				return 0, true // value attached: -n20
			}
			if len(next) < 1 {
				return 0, false
			}
			return 1, true
		}
		if form, isOpt := sp.shortOptional[ch]; isOpt {
			if k < len(w)-1 {
				return 0, true // value attached: -n20
			}
			if form != nil && len(next) > 0 && form(next[0]) {
				return 1, true
			}
			return 0, true
		}
		return 0, false
	}
	return 0, true
}

// maxCountDigits bounds the digits of a count that the check treats as a
// number: nine digits always fit a C int, so the program parses the word as
// a number too and never falls back to reading it as an option or operand.
const maxCountDigits = 9

// isCount reports whether w is a decimal count without a leading zero (or
// "0"), at most maxCountDigits long. Base-0 and base-10 parsers read it the
// same way.
func isCount(w string) bool {
	if w == "0" {
		return true
	}
	if len(w) == 0 || len(w) > maxCountDigits || w[0] == '0' {
		return false
	}
	for i := 0; i < len(w); i++ {
		if w[i] < '0' || w[i] > '9' {
			return false
		}
	}
	return true
}

// isJournalLines reports whether journalctl takes w as the value of a bare
// `-n`: a count, optionally with a leading `+`. `all` and other forms it
// also takes are not needed; they are checked as their own word instead.
func isJournalLines(w string) bool {
	return isCount(strings.TrimPrefix(w, "+"))
}

// isNumericOption reports whether w is `-NUM`, the obsolete line count of
// head and tail.
func isNumericOption(w string) bool {
	return len(w) > 1 && w[0] == '-' && isCount(w[1:])
}

// operandOK reports whether w may be an operand.
func (sp argSpec) operandOK(w string, opensFiles bool) bool {
	if !sp.operands {
		return false
	}
	return !opensFiles || !namesSpecialFile(w)
}

// namesSpecialFile reports whether the path w has an element dev, proc or
// sys. Opening some files there has side effects (`/dev/watchdog` can reboot
// the host, reading `/proc/kmsg` consumes kernel messages).
func namesSpecialFile(w string) bool {
	if strings.IndexByte(w, '/') < 0 {
		return false
	}
	for _, el := range strings.Split(w, "/") {
		if el == "dev" || el == "proc" || el == "sys" {
			return true
		}
	}
	return false
}

// longs builds a long option table from name/kind pairs.
func longs(kind longKind, names ...string) map[string]longKind {
	m := make(map[string]longKind, len(names))
	for _, n := range names {
		m[n] = kind
	}
	return m
}

// merge returns one table with the entries of all tables.
func merge(tables ...map[string]longKind) map[string]longKind {
	m := map[string]longKind{}
	for _, t := range tables {
		for k, v := range t {
			m[k] = v
		}
	}
	return m
}

// systemctlOptions are the display options of systemctl, before or after the
// verb. Not -H/--host, -M/--machine or --root.
var systemctlOptions = argSpec{
	shortFlags: "alqr",
	shortValue: "tpPno",
	long: merge(
		longs(longFlag, "--all", "--full", "--no-pager", "--no-legend", "--plain",
			"--failed", "--value", "--user", "--system", "--quiet", "--recursive",
			"--reverse", "--before", "--after", "--show-types"),
		longs(longValue, "--type", "--state", "--property", "--lines", "--output"),
	),
	operands: true,
}

// pveConfig is the spec of `qm config` and `pct config`; pveStatus of their
// `status`; pveList of their `list`.
var (
	pveList   = argSpec{long: longs(longOptional, "--full")}
	pveConfig = argSpec{
		long:     merge(longs(longFlag, "--current"), longs(longValue, "--snapshot")),
		operands: true,
	}
	pveStatus = argSpec{long: longs(longOptional, "--verbose"), operands: true}
)

// ipShow is the spec after `ip a show`, `ip r list` and the like: selectors
// only, no option.
var ipShow = argSpec{operands: true}

// allowlist is the V6 allowlist of ADR 0014, keyed by the bare program name.
var allowlist = map[string]allowRule{
	"ls": {
		why:        "only stats files; no option writes, deletes or runs anything; operands follow the opens-files rule",
		opensFiles: true,
		spec:       argSpec{anyArgs: true, bareOperandsOpen: true},
	},
	"df": {
		why:        "only reads file system statistics; df opens each operand, so operands follow the opens-files rule",
		opensFiles: true,
		spec:       argSpec{anyArgs: true, bareOperandsOpen: true},
	},
	"du": {
		why: "only stats files; not --files0-from or -X/--exclude-from, which open a file",
		spec: argSpec{
			shortFlags: "abcDhHklLmPsSx0",
			shortValue: "dBt",
			long: merge(
				longs(longFlag, "--all", "--apparent-size", "--bytes", "--total",
					"--dereference-args", "--human-readable", "--si", "--inodes",
					"--dereference", "--count-links", "--no-dereference", "--null",
					"--separate-dirs", "--summarize", "--one-file-system"),
				longs(longValue, "--max-depth", "--block-size", "--threshold",
					"--exclude", "--time-style"),
				longs(longOptional, "--time")),
			operands: true,
		},
	},
	"free": {
		why:        "only reads /proc/meminfo; no option writes or runs anything; operands follow the opens-files rule",
		opensFiles: true,
		spec:       argSpec{anyArgs: true},
	},
	"uptime": {
		why:        "only reads /proc; no option writes or runs anything; operands follow the opens-files rule",
		opensFiles: true,
		spec:       argSpec{anyArgs: true},
	},
	"ps": {
		why:        "only reads /proc; no option writes or runs anything; operands follow the opens-files rule",
		opensFiles: true,
		spec:       argSpec{anyArgs: true},
	},
	"cat": {
		why:        "reads its operands and writes only to stdout",
		opensFiles: true,
		spec: argSpec{
			shortFlags: "AbeEnstTuv",
			long: longs(longFlag, "--show-all", "--number-nonblank", "--show-ends",
				"--number", "--squeeze-blank", "--show-tabs", "--show-nonprinting"),
			operands: true,
		},
	},
	"head": {
		why:        "reads its operands and writes only to stdout",
		opensFiles: true,
		spec: argSpec{
			shortFlags:  "qvz",
			shortValue:  "nc",
			numericWord: true,
			long: merge(longs(longValue, "--lines", "--bytes"),
				longs(longFlag, "--quiet", "--silent", "--verbose", "--zero-terminated")),
			operands: true,
		},
	},
	"tail": {
		why:        "reads its operands and writes only to stdout",
		opensFiles: true,
		spec: argSpec{
			shortFlags:  "fFqvz",
			shortValue:  "ncs",
			numericWord: true,
			long: merge(
				longs(longValue, "--lines", "--bytes", "--sleep-interval", "--pid",
					"--max-unchanged-stats"),
				longs(longOptional, "--follow"),
				longs(longFlag, "--retry", "--quiet", "--silent", "--verbose",
					"--zero-terminated")),
			operands: true,
		},
	},
	"wc": {
		why:        "reads its operands and writes only to stdout (not --files0-from)",
		opensFiles: true,
		spec: argSpec{
			shortFlags: "cmlLw",
			long: merge(longs(longFlag, "--bytes", "--chars", "--lines", "--words",
				"--max-line-length"), longs(longOptional, "--total")),
			operands: true,
		},
	},
	"grep": {
		why:        "reads its operands; not recursive (-r, -R, -d, -D) and no pattern file (-f)",
		opensFiles: true,
		spec: argSpec{
			shortFlags: "EFGPiywxvcLloqsbHhnTZzaIU",
			shortValue: "eABCm",
			long: merge(
				longs(longFlag, "--extended-regexp", "--fixed-strings", "--basic-regexp",
					"--perl-regexp", "--ignore-case", "--no-ignore-case", "--word-regexp",
					"--line-regexp", "--invert-match", "--count", "--files-with-matches",
					"--files-without-match", "--only-matching", "--quiet", "--silent",
					"--no-messages", "--byte-offset", "--with-filename", "--no-filename",
					"--line-number", "--initial-tab", "--null", "--null-data", "--text",
					"--line-buffered"),
				longs(longValue, "--regexp", "--max-count", "--after-context",
					"--before-context", "--context", "--label", "--binary-files"),
				longs(longOptional, "--color", "--colour")),
			operands: true,
		},
	},
	"ip": {
		why: "only `ip a`/`ip r` listings; no -batch, -netns, -force or other verb",
		globals: argSpec{exact: map[string]bool{
			"-4": true, "-6": true, "-br": true, "-brief": true, "-c": true,
			"-color": true, "-j": true, "-json": true, "-p": true, "-pretty": true,
			"-s": true, "-stats": true, "-d": true, "-details": true,
		}},
		subcommands: map[string]argSpec{
			"a": {}, "a show": ipShow, "a list": ipShow,
			"addr": {}, "addr show": ipShow, "addr list": ipShow,
			"address": {}, "address show": ipShow, "address list": ipShow,
			"r": {}, "r show": ipShow, "r list": ipShow,
			"ro": {}, "ro show": ipShow, "ro list": ipShow,
			"route": {}, "route show": ipShow, "route list": ipShow,
		},
	},
	"ss": {
		why: "lists sockets; not -K/--kill, -D/--diag, -F/--filter or -N/--net",
		spec: argSpec{
			shortFlags: "atulnpexmoisrwHO46ZzSdE0",
			shortValue: "Af",
			long: merge(
				longs(longFlag, "--all", "--tcp", "--udp", "--listening", "--numeric",
					"--processes", "--extended", "--memory", "--options", "--info",
					"--summary", "--resolve", "--raw", "--unix", "--no-header",
					"--oneline", "--ipv4", "--ipv6", "--sctp", "--dccp", "--events",
					"--context", "--contexts", "--packet"),
				longs(longValue, "--query", "--socket", "--family")),
			operands: true,
		},
	},
	"journalctl": {
		why: "reads the journal; not --vacuum-*, --rotate, --flush, --sync, --relinquish-var, --setup-keys, --cursor-file, --file, -D or -M",
		spec: argSpec{
			shortFlags: "fearkxqlmNh",
			shortValue: "upotgSUFc",
			// -n and -b take an attached value. A bare -n takes the next
			// word only when it is a count; a bare -b never takes it here
			// (journalctl may read a boot id, which is then checked as an
			// operand or option of its own).
			shortOptional: map[byte]func(string) bool{'n': isJournalLines, 'b': nil},
			long: merge(
				longs(longFlag, "--follow", "--pager-end", "--all", "--reverse",
					"--dmesg", "--catalog", "--quiet", "--full", "--merge", "--no-pager",
					"--no-hostname", "--no-full", "--list-boots", "--disk-usage", "--utc",
					"--system", "--user", "--fields", "--no-tail", "--show-cursor"),
				longs(longValue, "--unit", "--user-unit", "--priority", "--output",
					"--identifier", "--grep", "--since", "--until", "--facility",
					"--output-fields", "--cursor", "--after-cursor", "--field"),
				longs(longOptional, "--boot", "--lines")),
			operands: true,
		},
	},
	"systemctl": {
		why:     "status, show and list verbs only read unit state; no -H/--host, -M or --root",
		globals: systemctlOptions,
		subcommands: map[string]argSpec{
			"status": systemctlOptions, "show": systemctlOptions,
			"list-units": systemctlOptions, "list-unit-files": systemctlOptions,
			"list-sockets": systemctlOptions, "list-timers": systemctlOptions,
			"list-jobs": systemctlOptions, "list-dependencies": systemctlOptions,
			"list-machines": systemctlOptions, "list-automounts": systemctlOptions,
			"list-paths": systemctlOptions,
		},
	},
	"docker": {
		why: "ps, logs and inspect only read container state; no global option, no other subcommand",
		subcommands: map[string]argSpec{
			"ps": {
				shortFlags: "aqls",
				shortValue: "nf",
				long: merge(longs(longFlag, "--all", "--quiet", "--latest", "--size", "--no-trunc"),
					longs(longValue, "--last", "--filter", "--format")),
			},
			"logs": {
				shortFlags: "ft",
				shortValue: "n",
				long: merge(longs(longFlag, "--follow", "--timestamps", "--details"),
					longs(longValue, "--tail", "--since", "--until")),
				operands: true,
			},
			"inspect": {
				shortFlags: "s",
				shortValue: "f",
				long: merge(longs(longFlag, "--size"),
					longs(longValue, "--format", "--type")),
				operands: true,
			},
		},
	},
	"qm": {
		why:         "list, config and status only read VM state; no other subcommand",
		subcommands: map[string]argSpec{"list": pveList, "config": pveConfig, "status": pveStatus},
	},
	"pct": {
		why:         "list, config and status only read container state; no other subcommand",
		subcommands: map[string]argSpec{"list": pveList, "config": pveConfig, "status": pveStatus},
	},
	"zpool": {
		why: "list and status only read pool state; not status -c, which runs scripts",
		subcommands: map[string]argSpec{
			"list":   {shortFlags: "gHLpPv", shortValue: "oT", operands: true},
			"status": {shortFlags: "DegiLpPstvx", shortValue: "T", operands: true},
		},
	},
	"zfs": {
		why: "list only reads data set properties",
		subcommands: map[string]argSpec{
			"list": {shortFlags: "rHp", shortValue: "dotsS", operands: true},
		},
	},
}
