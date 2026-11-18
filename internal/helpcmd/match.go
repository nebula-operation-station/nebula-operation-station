// SPDX-License-Identifier: AGPL-3.0-or-later

package helpcmd

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrNoMatch is returned when a command does not have the shape of a doc
// example (ADR 0014 D4, "Matching (V3)"). It is returned for every rule
// violation: a token count or order mismatch, a byte difference, an unknown
// placeholder name, a second placeholder in one token, and a value outside
// its class. Callers check it with errors.Is.
var ErrNoMatch = errors.New("command does not match the doc shape")

// placeholderRE finds a placeholder `<name>` in a doc token, name = [a-z0-9-]+.
var placeholderRE = regexp.MustCompile(`<([a-z0-9-]+)>`)

// Binding is one placeholder of a doc token that the command token filled.
type Binding struct {
	// Token is the index of the token, the same in the doc shape and the command.
	Token int
	// Name is the placeholder name, without the angle brackets.
	Name string
	// Class is the value class the name has in the fixed table.
	Class PlaceholderClass
	// Value is the part of the command token that stands for the placeholder.
	// For an Unchanged binding it is the placeholder text itself.
	Value string
	// Unchanged reports that the command token is the doc token: the
	// placeholder was copied, not replaced. Such a command is never copyable
	// (ADR 0014 D4).
	Unchanged bool
}

// Match is the result of a successful MatchShape. It holds one Binding per
// placeholder of the doc shape, in token order.
type Match struct {
	// Bindings lists the placeholders of the doc shape, in token order.
	Bindings []Binding
}

// Unchanged reports whether any placeholder was copied unchanged into the
// command. The command must then be shown as amber "replace <…> before
// running" and must not be copyable.
func (m Match) Unchanged() bool {
	for _, b := range m.Bindings {
		if b.Unchanged {
			return true
		}
	}
	return false
}

// HostValues returns the values of the host-class placeholders that the command
// filled in, in token order. V5 checks them against the trusted host set; this
// package does not. Unchanged placeholders are not values and are left out.
func (m Match) HostValues() []string {
	var hosts []string
	for _, b := range m.Bindings {
		if b.Class == ClassHost && !b.Unchanged {
			hosts = append(hosts, b.Value)
		}
	}
	return hosts
}

// HasPlaceholder reports whether s contains a placeholder `<name>` with a name
// of [a-z0-9-]+. It does not look at the name table, so it also finds names
// that match nothing. A command that still has one was not filled in.
func HasPlaceholder(s string) bool {
	return placeholderRE.MatchString(s)
}

// MatchShape checks whether command has the shape of doc, the doc example from
// a code block. Both strings are split with Tokenize. Then:
//
//   - the token counts and the order must be equal;
//   - a token of the doc without a placeholder must be byte-identical to the
//     command token;
//   - a doc token with one placeholder `<name>` must have the text before it,
//     then a value, then the text after it, all literal; the value must match
//     the class of the name in full (IPv6 for class host only when the
//     placeholder is the whole token);
//   - a doc token may hold at most one placeholder, and a name outside the
//     table matches nothing, not even the same text;
//   - a command token that equals the doc token with its placeholder is an
//     Unchanged binding and still matches; the caller reports it.
//
// A tokenizer error (unbalanced quote, too long) is returned as is, wrapped.
// Every other failure wraps ErrNoMatch. The function never rewrites the
// command and never expands it.
func MatchShape(doc, command string) (Match, error) {
	docTokens, err := Tokenize(doc)
	if err != nil {
		return Match{}, fmt.Errorf("doc shape: %w", err)
	}
	cmdTokens, err := Tokenize(command)
	if err != nil {
		return Match{}, fmt.Errorf("command: %w", err)
	}
	if len(docTokens) != len(cmdTokens) {
		return Match{}, fmt.Errorf("%w: %d tokens in the doc shape, %d in the command",
			ErrNoMatch, len(docTokens), len(cmdTokens))
	}
	var m Match
	for i := range docTokens {
		b, ok, err := matchToken(i, docTokens[i], cmdTokens[i])
		if err != nil {
			return Match{}, fmt.Errorf("%w: token %d: %w", ErrNoMatch, i, err)
		}
		if ok {
			m.Bindings = append(m.Bindings, b)
		}
	}
	return m, nil
}

// matchToken compares one doc token with one command token. It returns the
// binding and true when the doc token has a placeholder, false when the tokens
// are identical without one, and an error when they do not match.
func matchToken(index int, doc, cmd string) (Binding, bool, error) {
	locs := placeholderRE.FindAllStringSubmatchIndex(doc, -1)
	switch {
	case len(locs) == 0:
		if doc != cmd {
			return Binding{}, false, fmt.Errorf("%q is not %q", cmd, doc)
		}
		return Binding{}, false, nil
	case len(locs) > 1:
		return Binding{}, false, fmt.Errorf("doc token %q has %d placeholders, at most one is allowed", doc, len(locs))
	}
	loc := locs[0]
	name := doc[loc[2]:loc[3]]
	class, known := LookupPlaceholder(name)
	if !known {
		return Binding{}, false, fmt.Errorf("placeholder <%s> is not in the class table", name)
	}
	if cmd == doc {
		return Binding{Token: index, Name: name, Class: class, Value: doc, Unchanged: true}, true, nil
	}
	prefix := doc[:loc[0]]
	suffix := doc[loc[1]:]
	// The value must be at least one byte, so the prefix and suffix may not
	// overlap or cover the whole command token.
	if len(cmd) < len(prefix)+len(suffix)+1 || !strings.HasPrefix(cmd, prefix) || !strings.HasSuffix(cmd, suffix) {
		return Binding{}, false, fmt.Errorf("%q does not have the text %q before and %q after <%s>", cmd, prefix, suffix, name)
	}
	value := cmd[len(prefix) : len(cmd)-len(suffix)]
	whole := prefix == "" && suffix == ""
	if err := CheckPlaceholderValue(class, value, whole); err != nil {
		return Binding{}, false, fmt.Errorf("<%s>: %w", name, err)
	}
	return Binding{Token: index, Name: name, Class: class, Value: value}, true, nil
}
