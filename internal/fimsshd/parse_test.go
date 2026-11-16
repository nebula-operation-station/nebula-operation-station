// SPDX-License-Identifier: AGPL-3.0-or-later

package fimsshd

import (
	"errors"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimbaseline"
	"github.com/nebula-operation-station/nebula-operation-station/internal/fimscan"
)

// cfg builds one sshd_config file at /etc/ssh/sshd_config.
func cfg(content string) []fimscan.SSHConfigFile {
	return []fimscan.SSHConfigFile{{Path: []byte("/etc/ssh/sshd_config"), Content: []byte(content)}}
}

// setFor parses content and returns the derived set, failing the test on error.
func setFor(t *testing.T, content string) *Set {
	t.Helper()
	d, err := Parse(cfg(content))
	if err != nil {
		t.Fatalf("Parse(%q): %v", content, err)
	}
	return d.Set()
}

// TestParseRejectsUnclassifiableValues checks that anything the parser does
// not understand fails closed with ErrUnclassifiable (ADR 0015 D7 "Unclassifiable means critical").
func TestParseRejectsUnclassifiableValues(t *testing.T) {
	tests := map[string]string{
		"separator equals":            "AuthorizedKeysFile=.ssh/keys\n",
		"quoted value":                "AuthorizedKeysFile \".ssh/keys\"\n",
		"single quote":                "AuthorizedKeysFile '.ssh/keys'\n",
		"backslash":                   "AuthorizedKeysFile .ssh/a\\b\n",
		"unknown token":               "AuthorizedKeysFile .ssh/%d\n",
		"percent at end":              "AuthorizedKeysFile .ssh/%\n",
		"home token mid component":    "AuthorizedKeysFile x%h/keys\n",
		"dotdot component":            "AuthorizedKeysFile ../keys\n",
		"empty component":             "AuthorizedKeysFile /etc//keys\n",
		"trailing slash":              "AuthorizedKeysFile /etc/keys/\n",
		"missing value":               "AuthorizedKeysFile\n",
		"non ASCII":                   "AuthorizedKeysFile .ssh/ü\n",
		"hash in value":               "AuthorizedKeysFile .ssh/keys # note\n",
		"daemon tilde name":           "TrustedUserCAKeys ~bob/ca.pub\n",
		"daemon two values":           "RevokedKeys /etc/a /etc/b\n",
		"daemon dotdot":               "RevokedKeys ../revoked\n",
		"include percent":             "Include /etc/ssh/%u.conf\n",
		"include tilde":               "Include ~/extra.conf\n",
		"include bad glob":            "Include /etc/ssh/extra/[\n",
		"include negated class bang":  "Include sshd_config.d/[!x]*.conf\n",
		"include negated class caret": "Include sshd_config.d/[^x]*.conf\n",
		"include class range":         "Include sshd_config.d/[a-z]*.conf\n",
		"include class single":        "Include sshd_config.d/[a]*.conf\n",
		"command relative":            "AuthorizedKeysCommand bin/keys\n",
		"command percent":             "AuthorizedKeysCommand /usr/bin/keys%u\n",
		"command quoted":              "AuthorizedKeysCommand \"/usr/bin/keys\"\n",
		"command escaped":             "AuthorizedKeysCommand /usr/bin/a\\ b\n",
		"command principals rel":      "AuthorizedPrincipalsCommand keys\n",
		"principals file with none":   "AuthorizedPrincipalsFile none /etc/x\n",
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(cfg(content))
			if !errors.Is(err, ErrUnclassifiable) {
				t.Fatalf("Parse: err = %v, want ErrUnclassifiable", err)
			}
		})
	}
}

// TestParseErrorsNeverContainConfigContent checks that a rejection names the
// file and the line, never the configuration text (ADR 0015 D6, AGENTS.md rule 7).
func TestParseErrorsNeverContainConfigContent(t *testing.T) {
	const secret = "SECRETVALUE42"
	_, err := Parse(cfg("Port 22\nAuthorizedKeysFile \"" + secret + "\"\n"))
	if err == nil {
		t.Fatal("Parse: no error for quoted value")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaks config content: %v", err)
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("error does not name the line: %v", err)
	}
}

// TestKeywordsAreCaseInsensitiveAndApplyInMatch checks that keywords match
// without regard to case and inside Match blocks (ADR 0015 D7 (d)).
func TestKeywordsAreCaseInsensitiveAndApplyInMatch(t *testing.T) {
	s := setFor(t, "Match User bob\n  authorizedkeysfile /srv/keys/%u\n")
	if got := s.Match([]byte("/srv/keys/bob")); got != fimbaseline.SSHFile {
		t.Fatalf("Match(/srv/keys/bob) = %v, want SSHFile", got)
	}
	// A Match-scoped AuthorizedKeysFile does not replace the default for users
	// the Match block does not cover, so the default stays a login file.
	if got := s.Match([]byte("/root/.ssh/authorized_keys")); got != fimbaseline.SSHFile {
		t.Fatalf("default dropped for users outside the Match block: %v", got)
	}
}

// TestGlobalAuthorizedKeysFileReplacesDefault checks that an AuthorizedKeysFile
// outside any Match block replaces the OpenSSH default for every user.
func TestGlobalAuthorizedKeysFileReplacesDefault(t *testing.T) {
	tests := map[string]string{
		"values":            "AuthorizedKeysFile /srv/k/%u\n",
		"none":              "AuthorizedKeysFile none\n",
		"after other lines": "Port 22\nPasswordAuthentication no\nAuthorizedKeysFile /srv/k/%u\n",
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			s := setFor(t, content)
			if got := s.Match([]byte("/root/.ssh/authorized_keys")); got != fimbaseline.SSHNone {
				t.Fatalf("default applied globally: %v", got)
			}
		})
	}
}

// TestMatchScopeKeepsDefault checks that once a Match block has started, every
// AuthorizedKeysFile after it is scoped (sshd Match blocks run to the next
// Match line or the end of the file), so the default stays for other users,
// also across files of the SSH configuration array.
func TestMatchScopeKeepsDefault(t *testing.T) {
	tests := map[string]string{
		"scoped values": "Match User bob\nAuthorizedKeysFile /srv/k/%u\n",
		"scoped none":   "Match User bob\nAuthorizedKeysFile none\n",
		"match all":     "Match all\nAuthorizedKeysFile /srv/k/%u\n",
		"after match":   "Match User bob\nPort 22\nAuthorizedKeysFile /srv/k/%u\n",
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			s := setFor(t, content)
			if got := s.Match([]byte("/root/.ssh/authorized_keys")); got != fimbaseline.SSHFile {
				t.Fatalf("default dropped: %v", got)
			}
		})
	}
	files := []fimscan.SSHConfigFile{
		{Path: []byte("/etc/ssh/sshd_config"), Content: []byte("Match User bob\n")},
		{Path: []byte("/etc/ssh/sshd_config.d/x.conf"), Content: []byte("AuthorizedKeysFile none\n")},
	}
	d, err := Parse(files)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := d.Set().Match([]byte("/root/.ssh/authorized_keys")); got != fimbaseline.SSHFile {
		t.Fatalf("default dropped across files: %v", got)
	}
}

// TestCommentsAndUnrelatedKeywordsAreIgnored checks that comments and other
// directives do not count as login directives.
func TestCommentsAndUnrelatedKeywordsAreIgnored(t *testing.T) {
	s := setFor(t, "# AuthorizedKeysFile /srv/commented\nPort 22\n\n   # RevokedKeys /x\n")
	if got := s.Match([]byte("/srv/commented")); got == fimbaseline.SSHFile {
		t.Fatalf("commented directive applied: %v", got)
	}
	if got := s.Match([]byte("/x")); got == fimbaseline.SSHFile {
		t.Fatalf("commented RevokedKeys applied: %v", got)
	}
	if got := s.Match([]byte("/root/.ssh/authorized_keys")); got != fimbaseline.SSHFile {
		t.Fatalf("default AuthorizedKeysFile missing: %v", got)
	}
}
