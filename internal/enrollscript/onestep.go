// SPDX-License-Identifier: AGPL-3.0-or-later

package enrollscript

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/nebula-operation-station/nebula-operation-station/internal/pairing"
)

// OneStepOptions are the inputs of the one-step enrollment script (ADR 0013
// D3, D5): the classic options plus the offer salt the pairing code is
// derived with.
type OneStepOptions struct {
	Options
	// Salt is the offer salt, exactly pairing.SaltSize bytes. It reaches
	// the script only base64-encoded inside one single-quoted literal.
	Salt []byte
}

// Validate checks every field of o.
func (o OneStepOptions) Validate() error {
	if err := o.Options.Validate(); err != nil {
		return err
	}
	if len(o.Salt) != pairing.SaltSize {
		return fmt.Errorf("%w: salt must be %d bytes, got %d", ErrInvalidOptions, pairing.SaltSize, len(o.Salt))
	}
	return nil
}

// RenderOneStep validates o and returns the one-step enrollment script: the
// classic script for o.Options with a 64-bit arithmetic check at the start
// and, at the end, the host's address list and the pairing code computed on
// the host. It refuses invalid options with ErrInvalidOptions and a script
// over MaxScriptBytes with ErrTooLarge.
func RenderOneStep(o OneStepOptions) ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, fmt.Errorf("render one-step enroll script: %w", err)
	}
	s := renderOneStep(o)
	if len(s) > MaxScriptBytes {
		return nil, fmt.Errorf("render one-step enroll script: %w: %d bytes, limit %d", ErrTooLarge, len(s), MaxScriptBytes)
	}
	return []byte(s), nil
}

// renderOneStep writes the one-step script for validated options.
func renderOneStep(o OneStepOptions) string {
	return renderWith(o.Options, "\n"+check64) + "\n" + pairingFuncs(o.Salt, o.From) + pairingMain
}

// check64 stops the script before any change when the shell lacks 64-bit
// arithmetic, which the pairing code needs for its two 60-bit halves.
const check64 = `# The pairing code needs 64-bit shell arithmetic (ADR 0013 D3): check it
# before changing anything.
if [ "$(( 0x7fffffffffffffff ))" != 9223372036854775807 ] || [ "$(( (0xfffffffffffffff >> 55) & 31 ))" != 31 ]; then
  echo "error: this shell has no 64-bit arithmetic; run the script with dash or bash" >&2
  exit 1
fi
`

// pairingMain calls the pairing functions; it follows pairingFuncs at the
// end of the script, where sshd_bin is set by the classic part.
const pairingMain = `nos_pair_addrs
nos_pair_show "$sshd_bin" /etc/ssh/ssh_host_ed25519_key.pub || exit 1
`

// pairingFuncs returns the shell definitions of the pairing part: the salt
// and source address literals and the functions nos_pair_blob_ok,
// nos_pair_code, nos_pair_hostkey, nos_pair_addrs and nos_pair_show. The
// salt is base64 (alphabet A-Za-z0-9+/=) and the addresses are validated
// IPs/CIDRs, so neither can break out of its single quotes.
//
// The code follows ADR 0013 D3 without any 120-bit number: the first 30
// hex digits of the SHA-256 are read as two 60-bit halves of 15 digits each
// with $((0x…)), each half gives twelve base32hex digits by shift-and-mask,
// tr maps them to Crockford, and the check value is
// ((hi % 37) * 10 + lo % 37) % 37 because 2^60 mod 37 = 10.
func pairingFuncs(salt []byte, from []string) string {
	return `
# One-step enrollment (ADR 0013 D3, D5): the pairing code binds this host's
# ed25519 host key to this offer. Type it in the enrollment dialog; Nebula
# pins the key only if the code matches.
pair_salt='` + base64.StdEncoding.EncodeToString(salt) + `'
pair_from='` + strings.Join(from, " ") + `'

# nos_pair_blob_ok B64: B64 is exactly the base64 SSH wire format of an
# ed25519 public key (string "ssh-ed25519", string of 32 bytes).
nos_pair_blob_ok() {
  # 51 bytes are 68 base64 characters without padding.
  case $1 in
    AAAAC3NzaC1lZDI1NTE5AAAAI*) ;;
    *) return 1 ;;
  esac
  case $1 in
    *[!A-Za-z0-9+/]*) return 1 ;;
  esac
  [ "${#1}" -eq 68 ] || return 1
  pair_blob=$(printf '%s' "$1" | base64 -d 2>/dev/null | od -An -tx1 -v | tr -d ' \n')
  [ "${#pair_blob}" -eq 102 ] || return 1
  case $pair_blob in
    0000000b7373682d6564323535313900000020*) return 0 ;;
  esac
  return 1
}

# nos_pair_code B64: print the pairing code XXXXX-XXXXX-XXXXX-XXXXX-XXXXC of
# the ed25519 host key blob B64 for this offer's salt.
nos_pair_code() {
  nos_pair_blob_ok "$1" || return 1
  # SHA-256("nos-enroll-pair-v1" || 0x00 || salt || blob): first 30 hex
  # digits = 120 bits.
  pair_hex=$({ printf 'nos-enroll-pair-v1\000'; printf '%s' "$pair_salt" | base64 -d; printf '%s' "$1" | base64 -d; } | sha256sum | cut -c1-30)
  case $pair_hex in
    *[!0-9a-f]*) return 1 ;;
  esac
  [ "${#pair_hex}" -eq 30 ] || return 1
  # Two 60-bit halves of 15 hex digits each; they fit 64-bit arithmetic
  # with the sign bit clear. No 120-bit number is ever formed.
  pair_h=$(printf '%s' "$pair_hex" | cut -c1-15)
  pair_hi=$((0x$pair_h))
  pair_h=$(printf '%s' "$pair_hex" | cut -c16-30)
  pair_lo=$((0x$pair_h))
  # Twelve 5-bit groups per half, most significant first, as base32hex.
  pair_b32=''
  for pair_x in "$pair_hi" "$pair_lo"; do
    pair_s=55
    while [ "$pair_s" -ge 0 ]; do
      pair_d=$(( (pair_x >> pair_s) & 31 ))
      pair_b32=$pair_b32$(printf '%s' 0123456789ABCDEFGHIJKLMNOPQRSTUV | cut -c$((pair_d + 1)))
      pair_s=$((pair_s - 5))
    done
  done
  pair_code=$(printf '%s' "$pair_b32" | tr 0123456789ABCDEFGHIJKLMNOPQRSTUV 0123456789ABCDEFGHJKMNPQRSTVWXYZ)
  # v mod 37 for v = hi * 2^60 + lo; 10 is 2^60 mod 37. All values < 400.
  pair_c=$(( ((pair_hi % 37) * 10 + pair_lo % 37) % 37 ))
  pair_code=$pair_code$(printf '%s' '0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U' | cut -c$((pair_c + 1)))
  [ "${#pair_code}" -eq 25 ] || return 1
  printf '%s\n' "$pair_code" | sed 's/\(.....\)\(.....\)\(.....\)\(.....\)\(.....\)/\1-\2-\3-\4-\5/'
}

# nos_pair_hostkey SSHD FALLBACK: print the base64 blob of the ed25519 host
# key sshd serves (the hostkey lines of sshd -T); only when sshd -T is not
# available, the one in the public key file FALLBACK.
nos_pair_hostkey() {
  if [ -x "$1" ] && pair_conf=$("$1" -T 2>/dev/null); then
    pair_k=$(printf '%s\n' "$pair_conf" | while read -r pair_n pair_p _; do
      if [ "$pair_n" != hostkey ] || [ ! -r "$pair_p.pub" ]; then
        continue
      fi
      pair_t='' pair_b=''
      # read fails on a last line without newline, but still sets the fields.
      read -r pair_t pair_b _ < "$pair_p.pub" || true
      if [ "$pair_t" = ssh-ed25519 ] && nos_pair_blob_ok "$pair_b"; then
        printf '%s\n' "$pair_b"
        break
      fi
    done)
  else
    pair_k=''
    if [ -r "$2" ]; then
      pair_t='' pair_b=''
      read -r pair_t pair_b _ < "$2" || true
      if [ "$pair_t" = ssh-ed25519 ] && nos_pair_blob_ok "$pair_b"; then
        pair_k=$pair_b
      fi
    fi
  fi
  [ -n "$pair_k" ] || return 1
  printf '%s\n' "$pair_k"
}

# nos_pair_addrs: print the addresses Nebula connects from and this host's
# global addresses, as hints for the endpoint in the enrollment dialog.
nos_pair_addrs() {
  echo
  echo "Nebula connects from: $pair_from"
  echo "Addresses of this host (candidates for the endpoint in the dialog):"
  if command -v ip >/dev/null 2>&1; then
    ip -o addr show scope global 2>/dev/null | awk '{ sub(/\/.*/, "", $4); print "  " $2 "  " $4 }' || true
  else
    echo "  (ip not found)"
  fi
}

# nos_pair_show SSHD FALLBACK: print the pairing code, or explain why there
# is none.
nos_pair_show() {
  if ! pair_key=$(nos_pair_hostkey "$1" "$2"); then
    echo "error: this host has no ed25519 SSH host key that sshd serves, so there is no pairing code. One-step enrollment pins ed25519 keys only; enroll this host the classic way and compare the fingerprints above in 'nebula host pin'." >&2
    return 1
  fi
  if ! pair_out=$(nos_pair_code "$pair_key"); then
    echo "error: the pairing code could not be computed (base64, od, sha256sum, cut, tr and sed are needed); enroll this host the classic way." >&2
    return 1
  fi
  echo
  echo "Pairing code (type it in the enrollment dialog):"
  echo
  printf '    %s\n' "$pair_out"
}
`
}
