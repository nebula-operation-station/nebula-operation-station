// SPDX-License-Identifier: AGPL-3.0-or-later

package enrollscript

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// SetupKeyPlaceholder replaces the NetBird setup key in the "Show script"
// render (ADR 0013 D1 step 3); a script carrying it refuses to join.
const SetupKeyPlaceholder = "<netbird-setup-key-withheld>"

// NetBirdMgmtURLMaxLen is the length limit of the NetBird management URL
// (spec 03 "Render-input format").
const NetBirdMgmtURLMaxLen = 256

// NetBirdClientVersionsMax is the maximum number of entries of the
// key-passing mode table (spec 03 "Render-input format").
const NetBirdClientVersionsMax = 16

// KeyPassing is how the script hands the setup key to a NetBird client
// version (ADR 0013 D5): never as a command-line argument.
type KeyPassing int

const (
	// KeyPassingEnv passes the key in the environment variable NB_SETUP_KEY.
	KeyPassingEnv KeyPassing = iota + 1
	// KeyPassingFile passes the key in a 0600 file under a 0700 temporary
	// directory, named with --setup-key-file.
	KeyPassingFile
)

// NetBirdClient is one row of the key-passing mode table: a supported
// NetBird client version and how it takes the setup key.
type NetBirdClient struct {
	// Version is MAJOR.MINOR.PATCH, each part 1 to 5 decimal digits, as
	// `netbird version` prints it.
	Version string
	// KeyPassing is KeyPassingEnv or KeyPassingFile.
	KeyPassing KeyPassing
}

// NetBirdOptions are the inputs of the optional NetBird join (ADR 0013 D6).
type NetBirdOptions struct {
	// ManagementURL is the NetBird management URL; it must satisfy
	// ValidManagementURL.
	ManagementURL string
	// SetupKey is the one-off setup key (canonical uppercase UUID) or
	// SetupKeyPlaceholder for the "Show script" render.
	SetupKey string
	// Clients is the key-passing mode table; any client version not in it
	// stops the script before any change.
	Clients []NetBirdClient
}

var (
	setupKeyRe  = regexp.MustCompile(`^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$`)
	versionRe   = regexp.MustCompile(`^[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}$`)
	httpsURLRe  = regexp.MustCompile(`^https://[A-Za-z0-9.:\[\]-]+(/[A-Za-z0-9._~/-]*)?$`)
	dnsLabelRe  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	portDigitRe = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)
)

// ValidSetupKey reports whether k is a NetBird setup key in canonical
// uppercase UUID form (spec 09) or exactly SetupKeyPlaceholder.
func ValidSetupKey(k string) bool {
	return k == SetupKeyPlaceholder || setupKeyRe.MatchString(k)
}

// ValidManagementURL reports whether u is an acceptable NetBird management
// URL (spec 03 "Render-input format"): https only, at most
// NetBirdMgmtURLMaxLen bytes, a DNS or IP host, optional port and path, no
// userinfo, query, fragment, percent-encoding, quote or shell
// metacharacter, and equal to its re-encoded form.
func ValidManagementURL(u string) bool {
	return validHTTPSURL(u, true)
}

// validHTTPSURL checks s as described at ValidManagementURL; withPath
// allows a path, otherwise s must be a bare origin.
func validHTTPSURL(s string, withPath bool) bool {
	if len(s) > NetBirdMgmtURLMaxLen || !httpsURLRe.MatchString(s) {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.String() != s {
		return false
	}
	if !withPath && u.Path != "" {
		return false
	}
	if p := u.Port(); p != "" || strings.HasSuffix(u.Host, ":") {
		if !portDigitRe.MatchString(p) {
			return false
		}
		if n, err := strconv.Atoi(p); err != nil || n > 65535 {
			return false
		}
	}
	host := u.Hostname()
	if strings.HasPrefix(u.Host, "[") {
		a, err := netip.ParseAddr(host)
		return err == nil && a.Is6() && a.Zone() == ""
	}
	if strings.ContainsAny(host, "[]:") {
		return false
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Is4()
	}
	return validDNSName(host)
}

// validDNSName reports whether h is a DNS name of LDH labels.
func validDNSName(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if !dnsLabelRe.MatchString(l) {
			return false
		}
	}
	// A name whose last label is all digits would be read as an IPv4
	// address by some resolvers.
	last := labels[len(labels)-1]
	return strings.Trim(last, "0123456789") != ""
}

// Validate checks every field of n.
func (n NetBirdOptions) Validate() error {
	if !ValidManagementURL(n.ManagementURL) {
		return fmt.Errorf("%w: NetBird management URL is not a valid https URL", ErrInvalidOptions)
	}
	if !ValidSetupKey(n.SetupKey) {
		// The value is a secret: never in the error.
		return fmt.Errorf("%w: NetBird setup key has the wrong format", ErrInvalidOptions)
	}
	if len(n.Clients) == 0 || len(n.Clients) > NetBirdClientVersionsMax {
		return fmt.Errorf("%w: NetBird client table needs 1 to %d entries, got %d", ErrInvalidOptions, NetBirdClientVersionsMax, len(n.Clients))
	}
	seen := map[string]bool{}
	for _, c := range n.Clients {
		if !versionRe.MatchString(c.Version) {
			return fmt.Errorf("%w: NetBird client version %q is not MAJOR.MINOR.PATCH", ErrInvalidOptions, c.Version)
		}
		if seen[c.Version] {
			return fmt.Errorf("%w: NetBird client version %q listed twice", ErrInvalidOptions, c.Version)
		}
		seen[c.Version] = true
		if c.KeyPassing != KeyPassingEnv && c.KeyPassing != KeyPassingFile {
			return fmt.Errorf("%w: NetBird client version %q has no valid key-passing mode", ErrInvalidOptions, c.Version)
		}
	}
	return nil
}

// netbirdSelfMarker is the line by which the script recognises its own
// file before deleting it: it deletes only a file that contains it.
const netbirdSelfMarker = "# nos-enroll: this script carries a NetBird setup key and deletes itself when it ends."

// tmpRootShm is the first candidate of the temporary directory rule (ADR
// 0013 D1 step 3), shared by the UI command and the script.
const tmpRootShm = "/dev/shm"

// netbirdEarly returns the NetBird part that runs right after `set -eu`,
// before any change to the host: umask 077, the key and URL literals, the
// cleanup trap on EXIT, HUP, INT and TERM, and the preflight (not the
// review copy, client found, client version in the table). Both literals
// are validated and exclude `'`.
func netbirdEarly(n NetBirdOptions) string {
	var env, file []string
	for _, c := range n.Clients {
		if c.KeyPassing == KeyPassingEnv {
			env = append(env, "'"+c.Version+"'")
		} else {
			file = append(file, "'"+c.Version+"'")
		}
	}
	var arms strings.Builder
	if len(env) > 0 {
		fmt.Fprintf(&arms, "  %s) nb_mode='env' ;;\n", strings.Join(env, "|"))
	}
	if len(file) > 0 {
		fmt.Fprintf(&arms, "  %s) nb_mode='file' ;;\n", strings.Join(file, "|"))
	}
	return `
` + netbirdSelfMarker + `
# The NetBird setup key below is a secret (ADR 0013 D5, D6): it is passed to
# the NetBird client only by environment variable or a 0600 key file, never
# as an argument; the key file's directory is removed on every exit, and this
# script deletes itself when it ends.
umask 077
nb_key='` + n.SetupKey + `'
nb_url='` + n.ManagementURL + `'
nb_self=$0
nb_dir=''
nb_pid=''
nos_nb_cleanup() {
  if [ -n "$nb_pid" ]; then
    kill "$nb_pid" 2>/dev/null || true
  fi
  if [ -n "$nb_dir" ]; then
    rm -rf "$nb_dir"
  fi
  if [ "$nb_key" != '` + SetupKeyPlaceholder + `' ] && [ -f "$nb_self" ] && grep -qxF '` + netbirdSelfMarker + `' "$nb_self" 2>/dev/null; then
    rm -f "$nb_self"
  fi
}
trap nos_nb_cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if [ "$nb_key" = '` + SetupKeyPlaceholder + `' ]; then
  echo "error: this is the review copy of the script; the NetBird setup key is withheld. Run the downloaded script instead." >&2
  exit 1
fi
nb_bin=$(command -v netbird || true)
if [ -z "$nb_bin" ]; then
  echo "error: the NetBird client (netbird) is not installed; install it from the official NetBird package repository and run this script again" >&2
  exit 1
fi
nb_ver=$("$nb_bin" version 2>/dev/null | head -n 1 || true)
nb_mode=''
case $nb_ver in
` + arms.String() + `esac
if [ -z "$nb_mode" ]; then
  echo "error: this NetBird client version is not supported for the join; nothing was changed" >&2
  exit 1
fi
`
}

// netbirdJoin joins NetBird with the key passed by the selected mode and
// waits at most 60 s for the NetBird address. The client runs in the
// background with `wait`, so a TERM reaches the trap at once even while the
// client hangs, and the trap stops the client.
const netbirdJoin = `
# NetBird join (ADR 0013 D6).
if [ "$nb_mode" = file ]; then
  for nb_t in ` + tmpRootShm + ` "${XDG_RUNTIME_DIR:-}" "${TMPDIR:-/tmp}"; do
    [ -n "$nb_t" ] && [ -d "$nb_t" ] && [ -w "$nb_t" ] && break
  done
  if ! nb_dir=$(mktemp -d "$nb_t/nos-netbird.XXXXXXXX"); then
    nb_dir=''
    echo "error: no temporary directory for the NetBird setup key" >&2
    exit 1
  fi
  chmod 0700 "$nb_dir"
  printf '%s\n' "$nb_key" > "$nb_dir/setup-key"
  chmod 0600 "$nb_dir/setup-key"
  "$nb_bin" up --management-url "$nb_url" --setup-key-file "$nb_dir/setup-key" &
  nb_pid=$!
else
  NB_SETUP_KEY=$nb_key "$nb_bin" up --management-url "$nb_url" &
  nb_pid=$!
fi
if ! wait "$nb_pid"; then
  nb_pid=''
  echo "error: netbird up failed" >&2
  exit 1
fi
nb_pid=''
if [ -n "$nb_dir" ]; then
  rm -rf "$nb_dir"
  nb_dir=''
fi
nb_ip=''
nb_i=0
while [ "$nb_i" -lt 60 ]; do
  nb_ip=$("$nb_bin" status 2>/dev/null | sed -n 's/^NetBird IP: *\([0-9.]*\).*/\1/p' | head -n 1 || true)
  [ -n "$nb_ip" ] && break
  sleep 1
  nb_i=$((nb_i + 1))
done
if [ -n "$nb_ip" ]; then
  echo "NetBird address: $nb_ip"
else
  echo "warning: no NetBird address after 60 s; check 'netbird status'" >&2
fi
`
