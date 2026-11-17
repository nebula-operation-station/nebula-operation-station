// SPDX-License-Identifier: AGPL-3.0-or-later

package enrollscript

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

// maxAddressBytes bounds an accepted address: the longest IPv6 text with an
// embedded IPv4 part is 45 bytes, plus "/" and a prefix of at most three
// digits (49 bytes). The code has no named limit, so this is derived from
// the net parser's grammar, not from the code.
const maxAddressBytes = 49

var (
	addressCharRe = regexp.MustCompile(`^[0-9A-Fa-f.:/]+$`)
	// prefixLenRe is the prefix length grammar of an accepted CIDR range:
	// 0, or one to three digits without a leading zero.
	prefixLenRe = regexp.MustCompile(`^(0|[1-9][0-9]{0,2})$`)
)

// FuzzValidAddress: an accepted address is only IP/CIDR text (no zone, no
// space, no quote), it is short enough for the parser's grammar, and an
// accepted prefix length has no leading zero and at most three digits.
func FuzzValidAddress(f *testing.F) {
	for _, s := range []string{
		"10.0.0.1", "192.168.0.0/24", "2001:db8::10", "fd00:1:2::/64",
		"fe80::1%eth0/64", "::ffff:255.255.255.255", "10.0.0.1 10.0.0.2",
		"10.0.0.1\n", "10.0.0.0/33", "10.0.0.1'", `10.0.0.1"`, "$(id)",
		"nebula.lan", "*", "", "10.0.0.1:22", "10.0.0.0/0",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !ValidAddress(s) {
			return
		}
		if len(s) > maxAddressBytes {
			t.Fatalf("ValidAddress(%q) accepted %d bytes, limit %d", s, len(s), maxAddressBytes)
		}
		if !addressCharRe.MatchString(s) {
			t.Fatalf("ValidAddress(%q) accepted a character outside IP/CIDR text", s)
		}
		if strings.TrimSpace(s) != s {
			t.Fatalf("ValidAddress(%q) accepted surrounding space", s)
		}
		if i := strings.IndexByte(s, '/'); i >= 0 && !prefixLenRe.MatchString(s[i+1:]) {
			t.Fatalf("ValidAddress(%q) accepted a prefix length with a leading zero or more than three digits", s)
		}
	})
}

// FuzzValidators: the user, key reference and offer ID validators accept
// exactly the documented character set and length; users are never root.
func FuzzValidators(f *testing.F) {
	for _, s := range []string{
		"nebula", "root", "_svc-nos_1", "1nebula", "a'b", "a$(id)",
		"nebula-default", "lab_key-2", "../x", "k" + strings.Repeat("0", 63),
		"k" + strings.Repeat("0", 64), testOfferID, testOfferID + "'",
		testOfferID[:OfferIDMinLen-1], strings.Repeat("a", OfferIDMaxLen),
		strings.Repeat("a", OfferIDMaxLen+1), "",
	} {
		f.Add(s)
	}
	userSet := regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	refSet := regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	idSet := regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	f.Fuzz(func(t *testing.T, s string) {
		if ValidUser(s) {
			if !userSet.MatchString(s) || s == "root" {
				t.Fatalf("ValidUser(%q) accepted a name outside the documented set", s)
			}
		} else if userSet.MatchString(s) && s != "root" {
			t.Fatalf("ValidUser(%q) refused a documented name", s)
		}
		if ValidKeyRef(s) {
			if !refSet.MatchString(s) {
				t.Fatalf("ValidKeyRef(%q) accepted a reference outside the documented set", s)
			}
		} else if refSet.MatchString(s) {
			t.Fatalf("ValidKeyRef(%q) refused a documented reference", s)
		}
		if ValidOfferID(s) {
			if len(s) < OfferIDMinLen || len(s) > OfferIDMaxLen || !idSet.MatchString(s) {
				t.Fatalf("ValidOfferID(%q) accepted an ID outside %d..%d of A-Za-z0-9_-", s, OfferIDMinLen, OfferIDMaxLen)
			}
		} else if len(s) >= OfferIDMinLen && len(s) <= OfferIDMaxLen && idSet.MatchString(s) {
			t.Fatalf("ValidOfferID(%q) refused a documented ID", s)
		}
	})
}

// FuzzRenderCommand: on success Origin and the offer ID each appear exactly
// once, and the origin has no quote, backslash, percent sign, dollar,
// backtick or white space. The offer ID occurs only inside its quotes and
// inside the origin or hash text, never as a bare argument. On failure the
// output is empty, the error wraps ErrInvalidOptions and it does not contain
// the offer ID. No shell runs.
func FuzzRenderCommand(f *testing.F) {
	h := strings.Repeat("ab", 32)
	for _, s := range []struct {
		origin, id string
		curl, root bool
	}{
		{"https://nos.example.lan", testOfferID, true, false},
		{"https://nos.example.lan:8443", testOfferID, false, true},
		{"https://[2001:db8::1]:443", testOfferID, true, true},
		{"https://nos'.lan", testOfferID, true, false},
		{"https://nos.lan%s", testOfferID, false, false},
		{"https://nos.lan/x", testOfferID, true, false},
		{"https://nos.example.lan", testOfferID + "'", false, false},
		{"https://nos.example.lan", "short", true, false},
	} {
		f.Add(s.origin, s.id, h, s.curl, s.root)
	}
	f.Fuzz(func(t *testing.T, origin, id, hash string, curl, root bool) {
		d := DownloaderWget
		if curl {
			d = DownloaderCurl
		}
		c := CommandOptions{Origin: origin, OfferID: id, ScriptSHA256: hash, Downloader: d, Root: root}
		out, err := RenderCommand(c)
		if err != nil {
			if out != "" {
				t.Fatalf("RenderCommand failed with output %q", out)
			}
			if !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("RenderCommand error %v does not wrap ErrInvalidOptions", err)
			}
			// Only a valid-looking ID is checked: the fixed error texts
			// contain spaces, so a charset-only ID cannot match them.
			if offerIDRe.MatchString(id) && len(id) >= OfferIDMinLen && strings.Contains(err.Error(), id) {
				t.Fatalf("error text contains the offer ID: %v", err)
			}
			return
		}
		if n := strings.Count(out, origin); n != 1 {
			t.Fatalf("origin %q appears %d times in output", origin, n)
		}
		if strings.ContainsAny(origin, "'\"\\%$` \t\r\n") {
			t.Fatalf("accepted origin %q contains a forbidden character", origin)
		}
		if n := strings.Count(out, "'"+id+"'"); n != 1 {
			t.Fatalf("quoted offer ID appears %d times in output", n)
		}
		// The ID is a run of A-Za-z0-9_- and so cannot match across the
		// quotes, "https://", "/" or the hex hash around it: every other
		// occurrence lies inside the origin or the hash. An unquoted copy
		// in the argument list would make the count one higher.
		if n, want := strings.Count(out, id), 1+strings.Count(origin, id)+strings.Count(hash, id); n != want {
			t.Fatalf("offer ID appears %d times in output, want %d (one quoted, none bare)", n, want)
		}
		if n := strings.Count(out, "echo '"+hash+"  nos-enroll.sh'"); n != 1 {
			t.Fatalf("quoted script hash line appears %d times in output", n)
		}
	})
}

// FuzzRender: with a fixed key, an accepted option set renders a script
// within MaxScriptBytes that has exactly one from="..." line holding the
// joined addresses, and a user line that carries the user unchanged.
//
// The oracle does not call Validate. On success it requires that the user
// and key reference match their documented sets, that the user is not root,
// that every address is IP/CIDR text, and that the script has exactly the
// quote characters of a reference script rendered from safe values. The
// three inputs are the only source of quotes beyond the fixed template, so
// an input that broke out of its quoting would change the quote count, and
// removing any validation makes one of the seeds below fail.
func FuzzRender(f *testing.F) {
	for _, s := range []struct {
		from, user, ref string
		sudo            bool
	}{
		{"192.168.0.10,10.8.0.0/24", "nebula", "nebula-default", true},
		{"10.0.0.1", "ops", "nebula-default", false},
		{"2001:db8::10,fd00:1:2::/64", "nebula", "lab_key-2", true},
		{"10.0.0.1,10.0.0.2/32,172.16.0.0/12,::1,fe80::/10,192.0.2.255", "_svc-nos_1", "nebula-default", true},
		{"203.0.113.7", "a" + strings.Repeat("b", 31), "k" + strings.Repeat("0", 63), false},
		{"10.0.0.1'", "nebula", "nebula-default", false},
		{"10.0.0.1,", "nebula", "nebula-default", false},
		{"10.0.0.1", "root", "nebula-default", false},
		{"10.0.0.1", "nebula", "a'b", false},
		{"fe80::1%eth0", "nebula", "nebula-default", false},
		{"10.0.0.1\n", "nebula", "nebula-default", true},
		{"10.0.0.1", "nebula\n", "nebula-default", true},
		{"10.0.0.1", "nebula", "nebula-default\n", true},
		{"10.0.0.1", "$(id)", "nebula-default", false},
		{"10.0.0.1", "a'b", "nebula-default", false},
		{"10.0.0.1", "a\"b", "nebula-default", false},
		{"10.0.0.1/000000024", "nebula", "nebula-default", false},
	} {
		f.Add(s.from, s.user, s.ref, s.sudo)
	}
	userSet := regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	refSet := regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	f.Fuzz(func(t *testing.T, from, user, ref string, sudo bool) {
		o := Options{
			From:   strings.Split(from, ","),
			User:   user,
			KeyRef: ref,
			Key:    goldenKey(t),
			Sudo:   sudo,
		}
		script, err := Render(o)
		if err != nil {
			if script != nil {
				t.Fatalf("Render failed with a script: %v", err)
			}
			if !errors.Is(err, ErrInvalidOptions) && !errors.Is(err, ErrTooLarge) {
				t.Fatalf("Render error %v wraps neither ErrInvalidOptions nor ErrTooLarge", err)
			}
			return
		}
		s := string(script)
		if len(s) > MaxScriptBytes {
			t.Fatalf("script has %d bytes, limit %d", len(s), MaxScriptBytes)
		}

		// Oracle, independent of Validate.
		if !userSet.MatchString(user) || user == "root" {
			t.Fatalf("accepted user %q is outside the documented set or root", user)
		}
		if !refSet.MatchString(ref) {
			t.Fatalf("accepted key reference %q is outside the documented set", ref)
		}
		for _, a := range o.From {
			if !addressCharRe.MatchString(a) || len(a) > maxAddressBytes {
				t.Fatalf("accepted address %q is not IP/CIDR text of at most %d bytes", a, maxAddressBytes)
			}
		}
		safe, err := Render(Options{From: []string{"10.0.0.1"}, User: "nebula", KeyRef: "nebula-default", Key: o.Key, Sudo: sudo})
		if err != nil {
			t.Fatalf("reference script: %v", err)
		}
		for _, q := range []string{"'", `"`} {
			if got, want := strings.Count(s, q), strings.Count(string(safe), q); got != want {
				t.Fatalf("script has %d %s characters, reference has %d: input changed the quoting", got, q, want)
			}
		}

		line := `from="` + strings.Join(o.From, ",") + `",no-agent-forwarding`
		if n := strings.Count(s, `from="`); n != 1 {
			t.Fatalf("script has %d from=\"...\" lines, want 1", n)
		}
		if !strings.Contains(s, line) {
			t.Fatalf("script lacks the from line %q", line)
		}
		if n := strings.Count(s, "\nuser='"+user+"'\n"); n != 1 {
			t.Fatalf("script has %d user lines for %q, want 1", n, user)
		}
		if n := strings.Count(s, " nebula-"+ref+"'\n"); n != 1 {
			t.Fatalf("script has %d key lines for reference %q, want 1", n, ref)
		}
	})
}
