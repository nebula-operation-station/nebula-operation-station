// SPDX-License-Identifier: AGPL-3.0-or-later

package fimsshd

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/fimbaseline"
)

// TestADRExamplesClassifyAsSpecified covers the examples of ADR 0015 D7 (d)
// and D9 "SSH login files".
func TestADRExamplesClassifyAsSpecified(t *testing.T) {
	tests := []struct {
		name   string
		config string
		path   string
		want   fimbaseline.SSHMatch
	}{
		{"home pattern root", "AuthorizedKeysFile %h/.config/keys\n", "/root/.config/keys", fimbaseline.SSHFile},
		{"home pattern deep home", "AuthorizedKeysFile %h/.config/keys\n", "/var/lib/svc/.config/keys", fimbaseline.SSHFile},
		{"home pattern other name is only a position", "AuthorizedKeysFile %h/.config/keys\n", "/root/.config/other", fimbaseline.SSHPosition},
		{"home pattern other file is not a hit", "AuthorizedKeysFile %h/.config/keys\n", "/root/.config/keys.bak", fimbaseline.SSHPosition},
		{"user token covers directory entry", "AuthorizedKeysFile /etc/ssh/authorized_keys/%u\n", "/etc/ssh/authorized_keys/alice", fimbaseline.SSHFile},
		{"user token is one component", "AuthorizedKeysFile /etc/ssh/authorized_keys/%u\n", "/etc/ssh/authorized_keys/a/b", fimbaseline.SSHNone},
		{"daemon CA relative to root", "TrustedUserCAKeys etc/ssh/ca.pub\n", "/etc/ssh/ca.pub", fimbaseline.SSHFile},
		{"daemon CA is not below a home", "AuthorizedKeysFile none\nTrustedUserCAKeys etc/ssh/ca.pub\n", "/root/etc/ssh/ca.pub", fimbaseline.SSHNone},
		{"none names no file", "AuthorizedKeysFile none\n", "/root/.ssh/authorized_keys", fimbaseline.SSHNone},
		{"command program absolute", "AuthorizedKeysFile none\nAuthorizedKeysCommand /usr/sbin/keys-cmd --user %u\n", "/usr/sbin/keys-cmd", fimbaseline.SSHFile},
		{"command args are not files", "AuthorizedKeysFile none\nAuthorizedKeysCommand /usr/sbin/keys-cmd %u\n", "/usr/sbin/keys-cmd/%u", fimbaseline.SSHNone},
		{"command none names no file", "AuthorizedKeysFile none\nAuthorizedKeysCommand none\nAuthorizedPrincipalsCommand none\n", "/usr/sbin/none", fimbaseline.SSHNone},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := setFor(t, tc.config).Match([]byte(tc.path)); got != tc.want {
				t.Fatalf("Match(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

// TestDefaultAuthorizedKeysFileApplies checks the OpenSSH default when no
// AuthorizedKeysFile directive exists (ADR 0015 D7 (d)).
func TestDefaultAuthorizedKeysFileApplies(t *testing.T) {
	s := setFor(t, "Port 22\n")
	for _, p := range []string{"/root/.ssh/authorized_keys", "/home/alice/.ssh/authorized_keys2"} {
		if got := s.Match([]byte(p)); got != fimbaseline.SSHFile {
			t.Errorf("Match(%q) = %v, want SSHFile", p, got)
		}
	}
	// A relative value matches any depth, so /home/alice/.ssh/known could be
	// a directory on the way to a hit: a position, never a file.
	if got := s.Match([]byte("/home/alice/.ssh/known")); got != fimbaseline.SSHPosition {
		t.Errorf("unrelated file: got %v, want SSHPosition", got)
	}
	if got := s.Match([]byte("/etc/motd")); got != fimbaseline.SSHPosition {
		t.Errorf("unrelated absolute path: got %v, want SSHPosition", got)
	}
}

// TestPositionsAboveHitsAreReported checks that directories on or above a
// hit are positions, not files (ADR 0015 D7 (d), D9 "Symlinks at or above SSH positions").
func TestPositionsAboveHitsAreReported(t *testing.T) {
	s := setFor(t, "AuthorizedKeysFile %h/.config/keys /etc/ssh/authorized_keys/%u\n")
	tests := map[string]fimbaseline.SSHMatch{
		"/":                          fimbaseline.SSHPosition,
		"/etc":                       fimbaseline.SSHPosition,
		"/etc/ssh/authorized_keys":   fimbaseline.SSHPosition,
		"/home":                      fimbaseline.SSHPosition,
		"/home/alice/.config":        fimbaseline.SSHPosition,
		"/home/alice/.config/keys":   fimbaseline.SSHFile,
		"/etc/ssh/authorized_keys/x": fimbaseline.SSHFile,
		"/etc/ssh/motd":              fimbaseline.SSHPosition,
		"relative/path":              fimbaseline.SSHNone,
	}
	for p, want := range tests {
		if got := s.Match([]byte(p)); got != want {
			t.Errorf("Match(%q) = %v, want %v", p, got, want)
		}
	}
}

// TestPercentAndTildeForms checks the %% escape, ~ and ~name homes, and
// relative values (ADR 0015 D7 (d)).
func TestPercentAndTildeForms(t *testing.T) {
	s := setFor(t, "AuthorizedKeysFile /etc/a%%b/%U ~/.k1 ~alice/.k2 .k3\n")
	tests := map[string]fimbaseline.SSHMatch{
		"/etc/a%b/carol":   fimbaseline.SSHFile,
		"/etc/a%b/x/carol": fimbaseline.SSHPosition,
		"/etc/a%b/x/a/b/c": fimbaseline.SSHPosition,
		"/root/.k1":        fimbaseline.SSHFile,
		"/home/bob/.k2":    fimbaseline.SSHFile,
		"/home/bob/.k3":    fimbaseline.SSHFile,
	}
	for p, want := range tests {
		if got := s.Match([]byte(p)); got != want {
			t.Errorf("Match(%q) = %v, want %v", p, got, want)
		}
	}
}

// TestDaemonWideValuesDoNotExpandPercent checks that TrustedUserCAKeys and
// RevokedKeys treat % as a literal and resolve ~ to /root (ADR 0015 D7 (d)).
func TestDaemonWideValuesDoNotExpandPercent(t *testing.T) {
	s := setFor(t, "AuthorizedKeysFile none\nRevokedKeys %h/revoked\nTrustedUserCAKeys ~/ca.pub\n")
	tests := map[string]fimbaseline.SSHMatch{
		"/%h/revoked":     fimbaseline.SSHFile,
		"/root/revoked":   fimbaseline.SSHNone,
		"/root/ca.pub":    fimbaseline.SSHFile,
		"/root/revoked/x": fimbaseline.SSHNone,
	}
	for p, want := range tests {
		if got := s.Match([]byte(p)); got != want {
			t.Errorf("Match(%q) = %v, want %v", p, got, want)
		}
	}
}

// TestIncludeGlobsMatchOneComponentEach checks Include globs against paths
// (ADR 0015 D7 (d): Include values and matched files).
func TestIncludeGlobsMatchOneComponentEach(t *testing.T) {
	s := setFor(t, "AuthorizedKeysFile none\nInclude sshd_config.d/*.conf\n")
	tests := map[string]fimbaseline.SSHMatch{
		"/etc/ssh/sshd_config.d":            fimbaseline.SSHPosition,
		"/etc/ssh/sshd_config.d/x.conf":     fimbaseline.SSHFile,
		"/etc/ssh/sshd_config.d/sub/x.conf": fimbaseline.SSHNone,
		"/etc/ssh/sshd_config.d/x.txt":      fimbaseline.SSHNone,
	}
	for p, want := range tests {
		if got := s.Match([]byte(p)); got != want {
			t.Errorf("Match(%q) = %v, want %v", p, got, want)
		}
	}
}

// TestIncludeGlobQuestionMarkMatchesOneCharacter checks the ? wildcard of an
// Include glob: exactly one character, one component (ADR 0015 D7 (d)).
func TestIncludeGlobQuestionMarkMatchesOneCharacter(t *testing.T) {
	s := setFor(t, "AuthorizedKeysFile none\nInclude sshd_config.d/?.conf\n")
	tests := map[string]fimbaseline.SSHMatch{
		"/etc/ssh/sshd_config.d/a.conf":  fimbaseline.SSHFile,
		"/etc/ssh/sshd_config.d/ab.conf": fimbaseline.SSHNone,
		"/etc/ssh/sshd_config.d/.conf":   fimbaseline.SSHNone,
		"/etc/ssh/sshd_config.d/a/conf":  fimbaseline.SSHNone,
	}
	for p, want := range tests {
		if got := s.Match([]byte(p)); got != want {
			t.Errorf("Match(%q) = %v, want %v", p, got, want)
		}
	}
}

// TestIncludeGlobStarMatchesWithinOneComponent checks that a * in an Include
// glob matches characters inside one component only and that a leading * may
// match a leading dot. The second case is conservative: sshd's glob(3) does
// not load ".x.conf" for "*.conf", so classifying it as a file errs toward
// critical, which is the fail-closed direction.
func TestIncludeGlobStarMatchesWithinOneComponent(t *testing.T) {
	s := setFor(t, "AuthorizedKeysFile none\nInclude sshd_config.d/*-keys.conf\n")
	tests := map[string]fimbaseline.SSHMatch{
		"/etc/ssh/sshd_config.d/a-keys.conf":   fimbaseline.SSHFile,
		"/etc/ssh/sshd_config.d/-keys.conf":    fimbaseline.SSHFile,
		"/etc/ssh/sshd_config.d/a/b-keys.conf": fimbaseline.SSHNone,
		"/etc/ssh/sshd_config.d/a-keys.txt":    fimbaseline.SSHNone,
		"/etc/ssh/sshd_config.d/.x-keys.conf":  fimbaseline.SSHFile,
	}
	for p, want := range tests {
		if got := s.Match([]byte(p)); got != want {
			t.Errorf("Match(%q) = %v, want %v", p, got, want)
		}
	}
}

// TestDeepRecordPathsAreNotFiles checks that a legitimate deep path (more than
// the 32 components a value may have) is classified by the set, not treated
// as a login file, and that a path beyond PATH_MAX is still failed closed.
func TestDeepRecordPathsAreNotFiles(t *testing.T) {
	s := setFor(t, "AuthorizedKeysFile /srv/k/%u\n")
	deep := "/opt" + strings.Repeat("/node_modules", 40) + "/x.js"
	if got := s.Match([]byte(deep)); got != fimbaseline.SSHNone {
		t.Errorf("deep unrelated path: got %v, want SSHNone", got)
	}
	tooDeep := "/" + strings.Repeat("a/", maxPathComponents) + "a" // one component more than the limit
	if got := s.Match([]byte(tooDeep)); got != fimbaseline.SSHFile {
		t.Errorf("path beyond the component limit: got %v, want SSHFile (fail closed)", got)
	}
}

// TestCommandProgramIsLiteral checks that a command program matches only its
// own path, that a quoted-free argument with % is allowed, and that a
// command program with % is rejected (ADR 0015 D7 (d), D9).
func TestCommandProgramIsLiteral(t *testing.T) {
	s := setFor(t, "AuthorizedKeysFile none\nAuthorizedPrincipalsCommand /usr/local/sbin/pc %u %h\n")
	if got := s.Match([]byte("/usr/local/sbin/pc")); got != fimbaseline.SSHFile {
		t.Fatalf("program not matched: %v", got)
	}
	if got := s.Match([]byte("/usr/local/sbin/pc2")); got != fimbaseline.SSHNone {
		t.Fatalf("program matched by prefix: %v", got)
	}
	if _, err := Parse(cfg("AuthorizedPrincipalsCommand /usr/local/sbin/pc%u\n")); !errors.Is(err, ErrUnclassifiable) {
		t.Fatalf("program with %% accepted: %v", err)
	}
}

// TestDerivedValueLimit checks the 4,096 value limit and the overflow
// marker (ADR 0015 D7 (d): "Derived-set limit").
func TestDerivedValueLimit(t *testing.T) {
	build := func(n int) string {
		var b strings.Builder
		b.WriteString("AuthorizedKeysFile none\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "Include f%04d.conf\n", i)
		}
		return b.String()
	}
	d, err := Parse(cfg(build(MaxDerivedValues)))
	if err != nil {
		t.Fatalf("at limit: Parse: %v", err)
	}
	if got := d.Count(); got != MaxDerivedValues {
		t.Fatalf("Count = %d, want %d", got, MaxDerivedValues)
	}
	if _, err := Parse(cfg(build(MaxDerivedValues + 1))); !errors.Is(err, ErrOverflow) {
		t.Fatalf("one over limit: err = %v, want ErrOverflow", err)
	}
	// The default AuthorizedKeysFile counts too: 4,095 includes plus the two defaults overflow.
	var b strings.Builder
	for i := 0; i < MaxDerivedValues-1; i++ {
		fmt.Fprintf(&b, "Include f%04d.conf\n", i)
	}
	if _, err := Parse(cfg(b.String())); !errors.Is(err, ErrOverflow) {
		t.Fatalf("defaults not counted: err = %v, want ErrOverflow", err)
	}
	if MaxDerivedValues != 4096 {
		t.Fatalf("MaxDerivedValues = %d, ADR 0015 D7 fixes 4,096", MaxDerivedValues)
	}
}

// TestSetStringHasNoConfigContent checks that the String output carries no
// configuration or path content.
func TestSetStringHasNoConfigContent(t *testing.T) {
	s := setFor(t, "AuthorizedKeysFile /srv/secretkeys/%u\n")
	if got := s.String(); strings.Contains(got, "secret") || strings.Contains(got, "srv") {
		t.Fatalf("String leaks content: %q", got)
	}
}

// TestAdjacentUserTokensCollapse checks that adjacent %u and %U tokens need one
// character each, so %u%u needs at least two, and that a long run of them
// compiles to one piece and still matches (ADR 0015 D7 (d)).
func TestAdjacentUserTokensCollapse(t *testing.T) {
	s := setFor(t, "AuthorizedKeysFile none\nAuthorizedKeysFile /srv/k/%u%U\n")
	tests := map[string]fimbaseline.SSHMatch{
		"/srv/k":     fimbaseline.SSHPosition,
		"/srv/k/x":   fimbaseline.SSHNone,
		"/srv/k/xy":  fimbaseline.SSHFile,
		"/srv/k/xyz": fimbaseline.SSHFile,
	}
	for p, want := range tests {
		if got := s.Match([]byte(p)); got != want {
			t.Errorf("Match(%q) = %v, want %v", p, got, want)
		}
	}
	long := setFor(t, "AuthorizedKeysFile none\nAuthorizedKeysFile /srv/k/"+strings.Repeat("%u", 2000)+"\n")
	if got := long.Match([]byte("/srv/k/" + strings.Repeat("a", 2000))); got != fimbaseline.SSHFile {
		t.Errorf("2000 user tokens: got %v, want SSHFile", got)
	}
	if got := long.Match([]byte("/srv/k/" + strings.Repeat("a", 1999))); got != fimbaseline.SSHNone {
		t.Errorf("2000 user tokens, 1999 chars: got %v, want SSHNone", got)
	}
}

// TestHostileUserPiecesAreRefused checks that a component with more than
// maxPiecesPerComponent pieces is refused as unclassifiable, so the matcher
// work per component stays bounded (ADR 0015 D7 (d)). The values are within
// the 4,096-byte token limit and the 256 KiB config limit.
func TestHostileUserPiecesAreRefused(t *testing.T) {
	hostile := []string{
		"%h/" + strings.Repeat("%u-", 1000),
		"%h/%u" + strings.Repeat("a%u", maxPiecesPerComponent),
	}
	for _, v := range hostile {
		if _, err := Parse(cfg("AuthorizedKeysFile " + v + "\n")); !errors.Is(err, ErrUnclassifiable) {
			t.Errorf("hostile value (%d bytes): err = %v, want ErrUnclassifiable", len(v), err)
		}
	}
	// Right at the cap, the value compiles.
	atCap := "%h/" + strings.Repeat("a%u", maxPiecesPerComponent/2)
	if _, err := Parse(cfg("AuthorizedKeysFile " + atCap + "\n")); err != nil {
		t.Errorf("at cap: Parse: %v", err)
	}
}

// TestHostileTokenMatchesWithinBudget matches a 4,096-byte component against
// many maximal entries. There is no timing assertion: the matcher is linear
// in the piece count times the component length, so the test only needs to
// finish with a fixed answer.
func TestHostileTokenMatchesWithinBudget(t *testing.T) {
	var b strings.Builder
	b.WriteString("AuthorizedKeysFile none\n")
	for i := 0; i < 64; i++ {
		b.WriteString("AuthorizedKeysFile /srv/" + strings.Repeat("a%u", maxPiecesPerComponent/2) + "\n")
	}
	s := setFor(t, b.String())
	name := strings.Repeat("a", 4000)
	if got := s.Match([]byte("/srv/" + name)); got != fimbaseline.SSHFile {
		t.Fatalf("Match of hostile name = %v, want SSHFile", got)
	}
}

// TestMatchPiecesAgreesWithReference compares matchPieces with a naive
// recursive reference on small inputs.
func TestMatchPiecesAgreesWithReference(t *testing.T) {
	var ref func(ps []piece, name string) bool
	ref = func(ps []piece, name string) bool {
		if len(ps) == 0 {
			return name == ""
		}
		p := ps[0]
		if !p.user {
			return strings.HasPrefix(name, p.lit) && ref(ps[1:], name[len(p.lit):])
		}
		for k := p.min; k <= len(name); k++ {
			if ref(ps[1:], name[k:]) {
				return true
			}
		}
		return false
	}
	pieceSets := [][]piece{
		{{lit: "a"}, {user: true, min: 1}},
		{{user: true, min: 2}, {lit: "b"}},
		{{lit: "a"}, {user: true, min: 1}, {lit: "a"}},
		{{user: true, min: 1}, {user: true, min: 1}, {lit: "ab"}},
		{{lit: "ab"}},
		{{user: true, min: 3}},
	}
	names := []string{"", "a", "ab", "aab", "abab", "aaaa", "xbab", "aabba", "abbb"}
	for _, ps := range pieceSets {
		for _, n := range names {
			if got, want := matchPieces(ps, n), ref(ps, n); got != want {
				t.Errorf("matchPieces(%+v, %q) = %v, want %v", ps, n, got, want)
			}
		}
	}
}
