// SPDX-License-Identifier: AGPL-3.0-or-later

package fimsshd

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
)

// MaxDerivedValues is the limit of values in one derived set (ADR 0015 D7
// (d), "Derived-set limit"). Every value of the Include, AuthorizedKeysFile,
// AuthorizedPrincipalsFile, TrustedUserCAKeys, RevokedKeys and command
// directives counts once, including the default AuthorizedKeysFile values;
// a value that repeats is counted again (fail closed).
const MaxDerivedValues = 4096

// maxTokenBytes bounds one value token (PATH_MAX).
const maxTokenBytes = 4096

// maxComponents bounds the path components of one value, which bounds the
// work of Match.
const maxComponents = 32

// defaultAuthorizedKeys are the OpenSSH defaults of AuthorizedKeysFile, used
// when no AuthorizedKeysFile directive exists (ADR 0015 D7 (d)).
var defaultAuthorizedKeys = []string{".ssh/authorized_keys", ".ssh/authorized_keys2"}

// sshdConfigDir is the directory that sshd resolves relative Include values
// against (OpenSSH sshd_config(5): "Files without absolute paths are assumed
// to be in /etc/ssh").
const sshdConfigDir = "/etc/ssh/"

// ErrUnclassifiable reports a configuration that the parser does not fully
// understand. The derived set is then unusable and every deviation is
// critical-class (ADR 0015 D7 "Unclassifiable means critical").
var ErrUnclassifiable = errors.New("sshd configuration is unclassifiable")

// ErrOverflow reports a derived set with more than MaxDerivedValues values.
// No usable set exists; the caller marks the set overflowed (ADR 0015 D7).
var ErrOverflow = errors.New("derived SSH set exceeds the value limit")

type directive uint8

const (
	dirInclude directive = iota + 1
	dirAuthorizedKeysFile
	dirAuthorizedPrincipalsFile
	dirTrustedUserCAKeys
	dirRevokedKeys
	dirAuthorizedKeysCommand
	dirAuthorizedPrincipalsCommand
)

// directives maps the lowercase ASCII keyword to its kind (sshd keywords are
// case-insensitive).
var directives = map[string]directive{
	"include":                     dirInclude,
	"authorizedkeysfile":          dirAuthorizedKeysFile,
	"authorizedprincipalsfile":    dirAuthorizedPrincipalsFile,
	"trustedusercakeys":           dirTrustedUserCAKeys,
	"revokedkeys":                 dirRevokedKeys,
	"authorizedkeyscommand":       dirAuthorizedKeysCommand,
	"authorizedprincipalscommand": dirAuthorizedPrincipalsCommand,
}

// Directives are the login-relevant values of one host's sshd configuration,
// as compiled entries. Build the matching set with Set.
type Directives struct {
	entries []entry
}

// Count returns the number of values, the quantity limited by MaxDerivedValues.
func (d Directives) Count() int { return len(d.entries) }

// Set returns the derived set of these directives.
func (d Directives) Set() *Set { return &Set{entries: d.entries} }

// Parse extracts the login directives of ADR 0015 D9 "SSH login files" from
// every configuration file of the host's SSH configuration array. Keywords
// are matched without regard to case, in Match blocks as well. It returns
// ErrUnclassifiable for any value whose syntax is not fixed by the ADR (for
// example a "=" separator or quoting) and ErrOverflow above MaxDerivedValues.
// Errors name the file and the line only, never the content.
func Parse(files []fimscan.SSHConfigFile) (Directives, error) {
	var d Directives
	authKeysSeen := false
	for _, f := range files {
		for n, line := range bytes.Split(f.Content, []byte{'\n'}) {
			seen, err := d.addLine(string(line))
			if err != nil {
				if errors.Is(err, ErrOverflow) {
					return Directives{}, err
				}
				return Directives{}, fmt.Errorf("sshd config %q line %d: %w", f.Path, n+1, err)
			}
			authKeysSeen = authKeysSeen || seen
			if len(d.entries) > MaxDerivedValues {
				return Directives{}, ErrOverflow
			}
		}
	}
	if !authKeysSeen {
		for _, v := range defaultAuthorizedKeys {
			e, err := userEntry(v)
			if err != nil {
				return Directives{}, fmt.Errorf("default AuthorizedKeysFile: %w", err)
			}
			d.entries = append(d.entries, e)
		}
	}
	if len(d.entries) > MaxDerivedValues {
		return Directives{}, ErrOverflow
	}
	return d, nil
}

// addLine parses one line. It reports whether the line is an
// AuthorizedKeysFile directive (so the default must not apply).
func (d *Directives) addLine(line string) (bool, error) {
	s := strings.TrimLeft(line, " \t\r")
	if s == "" || s[0] == '#' {
		return false, nil
	}
	kw, rest := s, ""
	if i := strings.IndexAny(s, " \t\r="); i >= 0 {
		kw, rest = s[:i], s[i:]
	}
	kind, ok := directives[asciiLower(kw)]
	if !ok {
		return false, nil
	}
	rest = strings.TrimLeft(rest, " \t\r")
	if strings.HasPrefix(rest, "=") {
		// The "=" separator is not fixed by the ADR: do not guess.
		return false, ErrUnclassifiable
	}
	toks := strings.FieldsFunc(rest, isSep)
	if len(toks) == 0 {
		return false, ErrUnclassifiable
	}
	for _, t := range toks {
		if !validToken(t) {
			return false, ErrUnclassifiable
		}
	}
	switch kind {
	case dirInclude:
		for _, t := range toks {
			e, err := includeEntry(t)
			if err != nil {
				return false, err
			}
			d.entries = append(d.entries, e)
		}
	case dirAuthorizedKeysFile, dirAuthorizedPrincipalsFile:
		if len(toks) == 1 && toks[0] == "none" {
			return kind == dirAuthorizedKeysFile, nil
		}
		for _, t := range toks {
			if t == "none" {
				return false, ErrUnclassifiable
			}
			e, err := userEntry(t)
			if err != nil {
				return false, err
			}
			d.entries = append(d.entries, e)
		}
		return kind == dirAuthorizedKeysFile, nil
	case dirTrustedUserCAKeys, dirRevokedKeys:
		if len(toks) != 1 {
			return false, ErrUnclassifiable
		}
		e, err := daemonEntry(toks[0])
		if err != nil {
			return false, err
		}
		d.entries = append(d.entries, e)
	case dirAuthorizedKeysCommand, dirAuthorizedPrincipalsCommand:
		if toks[0] == "none" {
			return false, nil
		}
		prog := toks[0]
		if !strings.HasPrefix(prog, "/") || strings.Contains(prog, "%") {
			return false, ErrUnclassifiable
		}
		e, err := literalEntry(prog)
		if err != nil {
			return false, err
		}
		d.entries = append(d.entries, e)
	}
	return false, nil
}

func isSep(r rune) bool { return r == ' ' || r == '\t' || r == '\r' }

// validToken accepts printable ASCII without quotes, backslash, "#" and "=".
// Anything else is not understood (ADR 0015 D7: quoting and escapes fail closed).
func validToken(t string) bool {
	if t == "" || len(t) > maxTokenBytes {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if c < 0x21 || c > 0x7e || strings.IndexByte(`"'\#=`, c) >= 0 {
			return false
		}
	}
	return true
}

// asciiLower lowercases ASCII letters only, so that no non-ASCII byte can
// turn into a keyword.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
