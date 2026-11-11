// SPDX-License-Identifier: AGPL-3.0-or-later

// Package enrollscript renders the POSIX shell script that enrolls a new
// host (spec 08): the admin reviews it and runs it as root on the host. The
// script creates a dedicated user, installs Nebula's key for it, restricted
// to Nebula's addresses, optionally grants NOPASSWD sudo, lets the user past
// sshd AllowUsers/AllowGroups and prints the host key fingerprints for
// `nebula host pin`.
//
// Render validates every interpolated value itself, so no caller input can
// break out of the script's quoting.
package enrollscript

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

// MaxScriptBytes is the size limit of a rendered script (ADR 0013 D5,
// docs/spec/03-processes-and-data.md); larger scripts are refused.
const MaxScriptBytes = 64 << 10

var (
	// ErrInvalidOptions reports options that fail validation.
	ErrInvalidOptions = errors.New("invalid enroll script options")
	// ErrTooLarge reports a rendered script over MaxScriptBytes.
	ErrTooLarge = errors.New("enroll script too large")
)

var (
	userRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	refRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

// Options are the inputs of the enrollment script.
type Options struct {
	// From lists the IP addresses or CIDR ranges Nebula connects from, in
	// the order given; each must satisfy ValidAddress.
	From []string
	// User is the user to create on the host; it must satisfy ValidUser.
	User string
	// KeyRef is the keyring reference of the installed key; it must
	// satisfy ValidKeyRef. It becomes the key comment "nebula-<KeyRef>".
	KeyRef string
	// Key is Nebula's public key. Only its re-encoded type and key data
	// reach the script.
	Key ssh.PublicKey
	// Sudo grants the user NOPASSWD sudo, which is effectively root.
	Sudo bool
}

// ValidUser reports whether u is an acceptable, non-root user name.
func ValidUser(u string) bool {
	return userRe.MatchString(u) && u != "root"
}

// ValidKeyRef reports whether r is an acceptable keyring reference.
func ValidKeyRef(r string) bool {
	return refRe.MatchString(r)
}

// ValidAddress reports whether a is an IP address or a CIDR range, exactly
// as given (no surrounding space, no host name, no zone).
func ValidAddress(a string) bool {
	if net.ParseIP(a) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(a)
	return err == nil
}

// Validate checks every field of o.
func (o Options) Validate() error {
	if !ValidUser(o.User) {
		return fmt.Errorf("%w: user %q is not a valid non-root user name", ErrInvalidOptions, o.User)
	}
	if !ValidKeyRef(o.KeyRef) {
		return fmt.Errorf("%w: key reference %q is not valid", ErrInvalidOptions, o.KeyRef)
	}
	if len(o.From) == 0 {
		return fmt.Errorf("%w: no source address", ErrInvalidOptions)
	}
	for _, a := range o.From {
		if !ValidAddress(a) {
			return fmt.Errorf("%w: source %q is neither an IP address nor a CIDR range", ErrInvalidOptions, a)
		}
	}
	if o.Key == nil {
		return fmt.Errorf("%w: no key", ErrInvalidOptions)
	}
	return nil
}

// Render validates o and returns the script. It refuses invalid options
// with ErrInvalidOptions and a script over MaxScriptBytes with ErrTooLarge.
func Render(o Options) ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, fmt.Errorf("render enroll script: %w", err)
	}
	s := render(o)
	if len(s) > MaxScriptBytes {
		return nil, fmt.Errorf("render enroll script: %w: %d bytes, limit %d", ErrTooLarge, len(s), MaxScriptBytes)
	}
	return []byte(s), nil
}

// render writes the classic script for validated options.
func render(o Options) string {
	return renderWith(o, "")
}

// renderWith writes the script for validated options with early, fixed or
// validated template text, inserted right after `set -eu` before any
// change to the host. Every interpolated value is validated (user name,
// IPs/CIDRs, key reference) or re-encoded (key), so none can break out of
// its quoting.
func renderWith(o Options, early string) string {
	keyLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(o.Key))) + " nebula-" + o.KeyRef
	keyFP := ssh.FingerprintSHA256(o.Key)
	var b strings.Builder
	opts := fmt.Sprintf(`from="%s",no-agent-forwarding,no-port-forwarding,no-X11-forwarding`, strings.Join(o.From, ","))
	fmt.Fprintf(&b, `#!/bin/sh
# Nebula Operation Station: enroll this host (spec 08).
# Review, then run as root on the host. Key: %s
set -eu
%s
user='%s'
key_line='%s %s'

# A dedicated group named like the user, also where USERGROUPS_ENAB=no or the
# user existed before: the file ownership below and AllowGroups rely on it.
if ! getent group "$user" >/dev/null 2>&1; then
  groupadd --system "$user"
fi
if ! id "$user" >/dev/null 2>&1; then
  useradd --system --create-home --shell /bin/sh -g "$user" "$user"
fi
if ! id -nG "$user" | tr ' ' '\n' | grep -qx "$user"; then
  usermod -a -G "$user" "$user"
fi
home=$(getent passwd "$user" | cut -d: -f6)
install -d -m 0700 -o "$user" -g "$user" "$home/.ssh"
touch "$home/.ssh/authorized_keys"
if ! grep -qxF "$key_line" "$home/.ssh/authorized_keys"; then
  printf '%%s\n' "$key_line" >> "$home/.ssh/authorized_keys"
fi
chown "$user:$user" "$home/.ssh/authorized_keys"
chmod 0600 "$home/.ssh/authorized_keys"
`, keyFP, early, o.User, opts, keyLine)
	if o.Sudo {
		fmt.Fprintf(&b, `
# NOPASSWD sudo: effectively root on this host (spec 08).
printf '%%s ALL=(ALL) NOPASSWD: ALL\n' "$user" > /etc/sudoers.d/nebula.tmp
chmod 0440 /etc/sudoers.d/nebula.tmp
visudo -cf /etc/sudoers.d/nebula.tmp
mv /etc/sudoers.d/nebula.tmp /etc/sudoers.d/nebula
`)
	}
	var pats, probe []string
	for _, a := range o.From {
		pats = append(pats, o.User+"@"+a)
		// sshd -T -C needs an address: the base address of a range.
		probe = append(probe, strings.SplitN(a, "/", 2)[0])
	}
	fmt.Fprintf(&b, `
# sshd: AllowUsers/AllowGroups (for example from a hardening baseline) would
# refuse the user. Add it in a drop-in for exactly the directives that are
# already in use; sshd merges the lists, so the existing entries stay valid.
# AllowGroups names the user's own group only: nobody else gets in.
sshd_bin=$(command -v sshd || echo /usr/sbin/sshd)
dropin=/etc/ssh/sshd_config.d/10-nebula.conf
probe='%s'
if [ -x "$sshd_bin" ]; then
  rm -f "$dropin.old"
  if [ -f "$dropin" ]; then mv "$dropin" "$dropin.old"; fi
  if conf=$("$sshd_bin" -T 2>/dev/null); then
    want=''
    if printf '%%s\n' "$conf" | grep -q '^allowusers '; then
      want='AllowUsers %s'
    fi
    if printf '%%s\n' "$conf" | grep -q '^allowgroups '; then
      others=$(getent group "$user" | cut -d: -f4 | tr ',' '\n' | grep -vx "$user" || true)
      if [ -n "$others" ]; then
        echo "warning: group $user has other members ($others); not adding AllowGroups $user. Add $user to your AllowUsers/AllowGroups yourself." >&2
      else
        want="${want:+$want
}AllowGroups $user"
      fi
    fi
    if printf '%%s\n' "$conf" | grep -Eq "^deny(users|groups) .*\b$user\b"; then
      echo "warning: DenyUsers/DenyGroups in the sshd configuration names $user; Nebula cannot log in until you change that" >&2
    fi
    if [ -n "$want" ]; then
      install -d -m 0755 /etc/ssh/sshd_config.d
      printf '# Written by the Nebula enrollment script. sshd merges this with the\n# AllowUsers/AllowGroups lines elsewhere. On its own it would let only\n# Nebula log in: delete it if you remove those lines.\n%%s\n' "$want" > "$dropin"
      chmod 0644 "$dropin"
      if "$sshd_bin" -t && "$sshd_bin" -T 2>/dev/null | grep -Eq "^allowusers $user@|^allowgroups $user\$"; then
        rm -f "$dropin.old"
        systemctl try-reload-or-restart ssh 2>/dev/null || systemctl try-reload-or-restart sshd 2>/dev/null || true
        echo "sshd: $dropin lets $user log in (AllowUsers/AllowGroups are in use; applies to new connections)"
      else
        rm -f "$dropin"
        echo "warning: sshd does not read $dropin (no Include of sshd_config.d?); add this to your AllowUsers/AllowGroups yourself:" >&2
        printf '%%s\n' "$want" >&2
      fi
    else
      rm -f "$dropin.old"
    fi
    # Match blocks (for example Match Address) are not in the plain sshd -T
    # output: check the configuration sshd applies to Nebula's connections.
    for a in $probe; do
      mconf=$("$sshd_bin" -T -C "user=$user,host=$a,addr=$a" 2>/dev/null) || continue
      if printf '%%s\n' "$mconf" | grep -q '^allowusers ' && ! printf '%%s\n' "$mconf" | grep -Eq "^allowusers $user(@|\$)"; then
        echo "warning: for connections from $a an AllowUsers (in a Match block?) does not name $user; add $user@$a there" >&2
      fi
      if printf '%%s\n' "$mconf" | grep -q '^allowgroups ' && ! printf '%%s\n' "$mconf" | grep -qx "allowgroups $user"; then
        echo "warning: for connections from $a an AllowGroups (in a Match block?) does not name $user; add $user there" >&2
      fi
    done
  else
    echo "warning: $sshd_bin -T failed, so AllowUsers/AllowGroups were not checked; fix the sshd configuration (sshd -t) and run this script again" >&2
  fi
  if [ -f "$dropin.old" ]; then mv "$dropin.old" "$dropin"; fi
fi
`, strings.Join(probe, " "), strings.Join(pats, " "))
	b.WriteString(`
# Fallback cleanup of job directories older than 14 days (spec 07).
printf 'd /var/lib/nebula/jobs 0700 root root 14d\n' > /etc/tmpfiles.d/nebula.conf

echo
echo "Done. Host key fingerprints of this host, to compare in 'nebula host pin':"
for f in /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ecdsa_key.pub /etc/ssh/ssh_host_rsa_key.pub; do
  [ -r "$f" ] && ssh-keygen -lf "$f"
done
echo "If fail2ban runs here, add Nebula's addresses to its ignoreip."
`)
	return b.String()
}
