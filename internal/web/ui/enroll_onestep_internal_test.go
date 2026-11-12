// SPDX-License-Identifier: AGPL-3.0-or-later

package ui

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// adrCommand is ADR 0013 D1 step 3 verbatim, with the example origin,
// offer ID and hash substituted.
const adrCommand = `( umask 077
  for t in /dev/shm "${XDG_RUNTIME_DIR:-}" "${TMPDIR:-/tmp}"; do
    [ -n "$t" ] && [ -d "$t" ] && [ -w "$t" ] && break; done
  d=$(mktemp -d "$t/nos-enroll.XXXXXXXX") || exit 1
  trap 'rm -rf "$d"' EXIT; trap 'exit 130' HUP INT TERM
  cd "$d" &&
  printf 'url = "https://nos.example.lan/enroll/%s"\noutput = "nos-enroll.sh"\n' \
    'abcdefghijklmnopqrstuvwxyz234567' |
    curl --proto '=https' --tlsv1.2 -fsS -K - &&
  echo '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  nos-enroll.sh' | sha256sum -c - &&
  sudo sh nos-enroll.sh )`

const (
	testOfferID = "abcdefghijklmnopqrstuvwxyz234567"
	testSHA     = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func TestOnestepCommandMatchesADRStep3(t *testing.T) {
	sudo, root, err := onestepCommands("https://nos.example.lan", testOfferID, testSHA)
	if err != nil {
		t.Fatalf("onestepCommands: %v", err)
	}
	if sudo != adrCommand {
		t.Errorf("sudo variant differs from ADR 0013 D1 step 3:\n got: %q\nwant: %q", sudo, adrCommand)
	}
	wantRoot := strings.Replace(adrCommand, "  sudo sh nos-enroll.sh )", "  sh nos-enroll.sh )", 1)
	if root != wantRoot {
		t.Errorf("root variant differs:\n got: %q\nwant: %q", root, wantRoot)
	}
	// The root variant differs in the last line only.
	sl, rl := strings.Split(sudo, "\n"), strings.Split(root, "\n")
	if len(sl) != len(rl) || strings.Join(sl[:len(sl)-1], "\n") != strings.Join(rl[:len(rl)-1], "\n") {
		t.Error("root variant differs before the last line")
	}
	for _, must := range []string{"umask 077", "mktemp -d", "trap 'rm -rf \"$d\"' EXIT", "-K -", "sha256sum -c -"} {
		if !strings.Contains(sudo, must) {
			t.Errorf("command lacks %q", must)
		}
	}
	// Never curl | sh, and the offer ID is never a curl argument.
	if strings.Contains(sudo, "| sh ") || strings.Contains(sudo, "| sudo") || strings.Contains(sudo, "curl https") {
		t.Error("command pipes into sh or passes the URL as an argument")
	}
}

func TestOnestepCommandOriginWithPortAndTrailingSlash(t *testing.T) {
	for _, origin := range []string{"https://nos.example.lan:8443", "https://nos.example.lan:8443/", "https://[fd00::1]:8443"} {
		sudo, _, err := onestepCommands(origin, testOfferID, testSHA)
		if err != nil {
			t.Fatalf("%s: %v", origin, err)
		}
		host := strings.TrimSuffix(strings.TrimPrefix(origin, "https://"), "/")
		if !strings.Contains(sudo, `'url = "https://`+host+`/enroll/%s"\noutput`) {
			t.Errorf("%s: url line wrong:\n%s", origin, sudo)
		}
	}
}

func TestOnestepCommandRefusesUnsafeInput(t *testing.T) {
	cases := []struct {
		name, origin, id, sum string
	}{
		{"http origin", "http://nos.example.lan", testOfferID, testSHA},
		{"quote in origin", "https://nos.example.lan'x", testOfferID, testSHA},
		{"percent in origin", "https://nos%2eexample.lan", testOfferID, testSHA},
		{"path in origin", "https://nos.example.lan/x", testOfferID, testSHA},
		{"userinfo in origin", "https://a@nos.example.lan", testOfferID, testSHA},
		{"query in origin", "https://nos.example.lan?x", testOfferID, testSHA},
		{"empty host", "https://", testOfferID, testSHA},
		{"short id", "https://nos.example.lan", "abc", testSHA},
		{"quote in id", "https://nos.example.lan", "abcdefghijklmnopqrstuvwxyz23456'", testSHA},
		{"upper id", "https://nos.example.lan", strings.ToUpper(testOfferID), testSHA},
		{"short sum", "https://nos.example.lan", testOfferID, "0123"},
		{"upper sum", "https://nos.example.lan", testOfferID, strings.ToUpper(testSHA)},
		{"quote in sum", "https://nos.example.lan", testOfferID, testSHA[:63] + "'"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := onestepCommands(c.origin, c.id, c.sum); !errors.Is(err, errOnestepCommand) {
				t.Fatalf("err = %v, want errOnestepCommand", err)
			}
		})
	}
}

func TestOnestepBindingIsStableAndSized(t *testing.T) {
	a, b := onestepBindingOf("token-a"), onestepBindingOf("token-b")
	if len(a) < 16 || len(a) > 64 {
		t.Fatalf("binding length %d outside 16..64", len(a))
	}
	if string(a) != string(onestepBindingOf("token-a")) {
		t.Error("binding not stable")
	}
	if string(a) == string(b) {
		t.Error("two sessions share a binding")
	}
	if strings.Contains(string(a), "token-a") {
		t.Error("binding contains the session token")
	}
}

func TestOnestepTableBindsSessionAndCaps(t *testing.T) {
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	tb := newOnestepTable()
	bind := onestepBindingOf("s1")
	for i := range maxOnestepOffers {
		o := &onestepOffer{idHash: strings.Repeat("0", 62) + string(rune('a'+i/26)) + string(rune('a'+i%26)), binding: bind, expires: now.Add(onestepOfferTTL)}
		if err := tb.add(o, now); err != nil {
			t.Fatalf("add %d: %v", i, err)
		}
	}
	extra := &onestepOffer{idHash: strings.Repeat("f", 64), binding: bind, expires: now.Add(onestepOfferTTL)}
	if err := tb.add(extra, now); !errors.Is(err, errOnestepTableFull) {
		t.Fatalf("add over cap: %v", err)
	}
	first := strings.Repeat("0", 62) + "aa"
	if _, ok := tb.get(first, onestepBindingOf("s2"), now); ok {
		t.Error("another session found the offer")
	}
	if _, ok := tb.get(first, bind, now); !ok {
		t.Error("creating session did not find the offer")
	}
	// After expiry plus the approval grace every entry is pruned.
	later := now.Add(onestepOfferTTL + onestepApprovalGrace + 1)
	if _, ok := tb.get(first, bind, later); ok {
		t.Error("expired offer still found")
	}
	if err := tb.add(extra, later); err != nil {
		t.Errorf("add after prune: %v", err)
	}
}
