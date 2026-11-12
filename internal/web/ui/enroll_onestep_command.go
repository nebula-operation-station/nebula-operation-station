// SPDX-License-Identifier: AGPL-3.0-or-later

// The command block and the server-side offer table of the one-step
// enrollment dialog (ADR 0013 D1 step 3, EN-10).

package ui

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Limits of the one-step dialog.
const (
	// onestepOfferIDLen is the length of an offer ID: 160 bits as
	// lowercase RFC 4648 base32 without padding (ADR 0013 D2).
	onestepOfferIDLen = 32
	// onestepHashLen is the length of a lowercase hex SHA-256.
	onestepHashLen = 64
	// onestepOriginMaxLen bounds the public origin placed in the command.
	onestepOriginMaxLen = 255
	// maxOnestepOffers bounds the server's offer table; the executor
	// allows at most 10 non-final offers, so this is never the limit in
	// normal use.
	maxOnestepOffers = 32
	// onestepOfferTTL is the executor's offer lifetime (ADR 0013 D2, Q2).
	onestepOfferTTL = 15 * time.Minute
	// onestepApprovalGrace keeps a table entry after the offer's expiry so
	// an approval started before expiry can still be committed within the
	// permit's own lifetime (ADR 0013 D2 "Expiry").
	onestepApprovalGrace = 30 * time.Minute
	// onestepScriptName is the file name the command downloads to.
	onestepScriptName = "nos-enroll.sh"
)

// errOnestepCommand reports an input that must not be placed into the
// command block.
var errOnestepCommand = errors.New("enrollment command: unsafe input")

// errOnestepTableFull reports that the offer table holds its maximum of
// live entries.
var errOnestepTableFull = errors.New("enrollment offers: too many open offers on this server")

// onestepCommands renders the command block of ADR 0013 D1 step 3 for an
// offer: the sudo variant and the root variant, which differs in the last
// line only. Every value is checked against a format that excludes quotes,
// backslashes, percent signs and white space, so nothing can leave its
// single-quoted shell literal or the printf format.
func onestepCommands(publicOrigin, offerID, sum string) (sudo, root string, err error) {
	host, err := onestepOriginHost(publicOrigin)
	if err != nil {
		return "", "", err
	}
	if !onestepValidOfferID(offerID) {
		return "", "", fmt.Errorf("%w: offer ID", errOnestepCommand)
	}
	if !onestepValidHex(sum) {
		return "", "", fmt.Errorf("%w: script hash", errOnestepCommand)
	}
	head := "( umask 077\n" +
		"  for t in /dev/shm \"${XDG_RUNTIME_DIR:-}\" \"${TMPDIR:-/tmp}\"; do\n" +
		"    [ -n \"$t\" ] && [ -d \"$t\" ] && [ -w \"$t\" ] && break; done\n" +
		"  d=$(mktemp -d \"$t/nos-enroll.XXXXXXXX\") || exit 1\n" +
		"  trap 'rm -rf \"$d\"' EXIT; trap 'exit 130' HUP INT TERM\n" +
		"  cd \"$d\" &&\n" +
		"  printf 'url = \"https://" + host + "/enroll/%s\"\\noutput = \"" + onestepScriptName + "\"\\n' \\\n" +
		"    '" + offerID + "' |\n" +
		"    curl --proto '=https' --tlsv1.2 -fsS -K - &&\n" +
		"  echo '" + sum + "  " + onestepScriptName + "' | sha256sum -c - &&\n"
	return head + "  sudo sh " + onestepScriptName + " )", head + "  sh " + onestepScriptName + " )", nil
}

// onestepOriginHost returns the host[:port] of an https origin, or an
// error when the origin is not a plain https origin with a safe host.
func onestepOriginHost(origin string) (string, error) {
	if len(origin) > onestepOriginMaxLen {
		return "", fmt.Errorf("%w: public origin too long", errOnestepCommand)
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Host == "" {
		return "", fmt.Errorf("%w: public origin is not a plain https origin", errOnestepCommand)
	}
	for i := 0; i < len(u.Host); i++ {
		c := u.Host[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == ':', c == '[', c == ']':
		default:
			return "", fmt.Errorf("%w: public origin host", errOnestepCommand)
		}
	}
	return u.Host, nil
}

// onestepValidOfferID checks an offer ID's syntax.
func onestepValidOfferID(id string) bool {
	if len(id) != onestepOfferIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < 'a' || c > 'z') && (c < '2' || c > '7') {
			return false
		}
	}
	return true
}

// onestepValidHex checks a lowercase hex SHA-256.
func onestepValidHex(s string) bool {
	if len(s) != onestepHashLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// onestepBindingDomain separates the session binding from other uses of
// the session token.
const onestepBindingDomain = "nos-enroll-session-v1"

// onestepBindingOf derives the opaque session binding the executor binds
// an offer to (CreateEnrollOfferRequest.session_binding, 16 to 64 bytes)
// from the web session token. The token itself never leaves the server.
func onestepBindingOf(token string) []byte {
	sum := sha256.Sum256([]byte(onestepBindingDomain + "\x00" + token))
	return sum[:]
}

// onestepPaired is the matched pairing an offer waits to approve.
type onestepPaired struct {
	Digest        string
	Endpoint      string
	EndpointToAdd bool
	Fingerprint   string
	KeyType       string
	Code          string
	OptionsJSON   string
	ApprovalUntil time.Time
}

// onestepOffer is the server's record of an offer created by one web
// session. It holds the offer ID, the download capability, in memory only,
// so "Show script" and the browser download can name the offer; the ID is
// never logged, never put into a URL of the UI and dropped with the entry.
type onestepOffer struct {
	idHash     string
	id         string
	binding    []byte
	hostID     string
	hostName   string
	sshUser    string
	credential string
	sudo       bool
	sha256     string
	created    time.Time
	expires    time.Time
	// endpoints are the host's inventory endpoints when the offer was
	// created (host:port).
	endpoints []string
	paired    *onestepPaired
	// final marks an offer that failed, was revoked or enrolled.
	final      bool
	finalState string
}

// onestepTable holds the offers of this server, keyed by the offer ID
// hash. Every lookup needs the creating session's binding.
type onestepTable struct {
	mu sync.Mutex
	m  map[string]*onestepOffer
}

func newOnestepTable() *onestepTable {
	return &onestepTable{m: map[string]*onestepOffer{}}
}

// pruneLocked drops entries past their expiry and approval grace.
func (t *onestepTable) pruneLocked(now time.Time) {
	for k, o := range t.m {
		if now.After(o.expires.Add(onestepApprovalGrace)) {
			delete(t.m, k)
		}
	}
}

// add stores a new offer.
func (t *onestepTable) add(o *onestepOffer, now time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneLocked(now)
	if len(t.m) >= maxOnestepOffers {
		return errOnestepTableFull
	}
	t.m[o.idHash] = o
	return nil
}

// get returns a copy of the offer when binding is the creating session's.
func (t *onestepTable) get(idHash string, binding []byte, now time.Time) (onestepOffer, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pruneLocked(now)
	o, ok := t.m[idHash]
	if !ok || !onestepSameBinding(o.binding, binding) {
		return onestepOffer{}, false
	}
	return *o, true
}

// update applies f to the offer when binding is the creating session's.
func (t *onestepTable) update(idHash string, binding []byte, f func(*onestepOffer)) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	o, ok := t.m[idHash]
	if !ok || !onestepSameBinding(o.binding, binding) {
		return false
	}
	f(o)
	return true
}

// onestepSameBinding compares two bindings in constant time.
func onestepSameBinding(a, b []byte) bool {
	return len(a) > 0 && subtle.ConstantTimeCompare(a, b) == 1
}

// onestepValidOfferHash checks the {offer} path value.
func onestepValidOfferHash(s string) bool { return onestepValidHex(s) }

// onestepTrim bounds operator text placed into an error message.
func onestepTrim(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	return strings.ToValidUTF8(s, "")
}
