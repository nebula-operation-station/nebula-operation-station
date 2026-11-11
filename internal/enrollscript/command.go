// SPDX-License-Identifier: AGPL-3.0-or-later

package enrollscript

import (
	"fmt"
	"regexp"
	"strings"
)

// Offer ID limits for the download command: base64url text of at least 128
// bits (ADR 0013 threat table) and a generous upper bound.
const (
	OfferIDMinLen = 22
	OfferIDMaxLen = 128
)

// Downloader selects the download client of the UI command (ADR 0013 D1
// step 3, D7).
type Downloader int

const (
	// DownloaderCurl reads URL and output file from a `-K -` config on
	// standard input.
	DownloaderCurl Downloader = iota + 1
	// DownloaderWget reads the URL from standard input with `-i -`.
	DownloaderWget
)

// CommandOptions are the inputs of the command the UI shows for a one-step
// offer.
type CommandOptions struct {
	// Origin is the server's public origin, `https://<host>[:port]` with
	// no path; it must satisfy the management URL rules without a path.
	Origin string
	// OfferID is the offer ID, OfferIDMinLen to OfferIDMaxLen characters
	// of `A-Za-z0-9_-`. It reaches the download client only on standard
	// input, never in an argument list.
	OfferID string
	// ScriptSHA256 is the SHA-256 of the script as 64 lowercase hex
	// characters; the command runs the script only if it matches.
	ScriptSHA256 string
	// Downloader is DownloaderCurl or DownloaderWget.
	Downloader Downloader
	// Root renders the variant for a root login without sudo.
	Root bool
}

var (
	offerIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	sha256Re  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidOfferID reports whether id is acceptable in the download command.
func ValidOfferID(id string) bool {
	return len(id) >= OfferIDMinLen && len(id) <= OfferIDMaxLen && offerIDRe.MatchString(id)
}

// Validate checks every field of c.
func (c CommandOptions) Validate() error {
	if !validHTTPSURL(c.Origin, false) {
		return fmt.Errorf("%w: origin is not an https origin without path", ErrInvalidOptions)
	}
	if !ValidOfferID(c.OfferID) {
		// The ID is a bearer secret until consumed: never in the error.
		return fmt.Errorf("%w: offer ID has the wrong format", ErrInvalidOptions)
	}
	if !sha256Re.MatchString(c.ScriptSHA256) {
		return fmt.Errorf("%w: script hash is not 64 lowercase hex characters", ErrInvalidOptions)
	}
	if c.Downloader != DownloaderCurl && c.Downloader != DownloaderWget {
		return fmt.Errorf("%w: unknown download client", ErrInvalidOptions)
	}
	return nil
}

// RenderCommand validates c and returns the command the operator pastes
// into a POSIX shell on the new host (ADR 0013 D1 step 3): a subshell under
// umask 077 that downloads into a fresh mktemp -d directory in /dev/shm,
// $XDG_RUNTIME_DIR or else $TMPDIR//tmp, removed by trap on every exit,
// checks the hash and only then runs the script. The offer ID is printed
// by the printf builtin into the client's standard input. Origin, ID and
// hash are validated and placed only inside single quotes; none of them
// contains a quote, backslash, percent sign or whitespace.
func RenderCommand(c CommandOptions) (string, error) {
	if err := c.Validate(); err != nil {
		return "", fmt.Errorf("render enroll command: %w", err)
	}
	var fetch string
	switch c.Downloader {
	case DownloaderCurl:
		fetch = `  printf 'url = "` + c.Origin + `/enroll/%s"\noutput = "nos-enroll.sh"\n' \
    '` + c.OfferID + `' |
    curl --proto '=https' --tlsv1.2 -fsS -K - &&
`
	default:
		fetch = `  printf '` + c.Origin + `/enroll/%s\n' \
    '` + c.OfferID + `' |
    wget --https-only -i - -O nos-enroll.sh &&
`
	}
	run := "sudo sh nos-enroll.sh )"
	if c.Root {
		run = "sh nos-enroll.sh )"
	}
	var b strings.Builder
	b.WriteString(`( umask 077
  for t in ` + tmpRootShm + ` "${XDG_RUNTIME_DIR:-}" "${TMPDIR:-/tmp}"; do
    [ -n "$t" ] && [ -d "$t" ] && [ -w "$t" ] && break; done
  d=$(mktemp -d "$t/nos-enroll.XXXXXXXX") || exit 1
  trap 'rm -rf "$d"' EXIT; trap 'exit 130' HUP INT TERM
  cd "$d" &&
`)
	b.WriteString(fetch)
	b.WriteString(`  echo '` + c.ScriptSHA256 + `  nos-enroll.sh' | sha256sum -c - &&
  ` + run + "\n")
	return b.String(), nil
}
