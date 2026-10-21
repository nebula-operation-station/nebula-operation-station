// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"

	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Enrollment helper (spec 08). `nebula host enroll-script` prints a POSIX
// shell script that the admin reviews and runs as root on the new host
// (console or an existing admin login). Nebula never logs in with a
// password: the script installs Nebula's key for a dedicated user,
// restricted to Nebula's addresses, and prints the host key fingerprints
// for `nebula host pin`.

const enrollUsage = `usage: nebula host enroll-script --from ADDR[,ADDR...] [--user nebula] [--key nebula-default] [--no-sudo]
ADDR are the IP addresses or CIDR ranges Nebula connects from (they go into
the key's from= option; use IPs, not host names). Without --no-sudo the user
gets NOPASSWD sudo, which is effectively root (spec 08)`

var (
	enrollUserRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	enrollRefRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
)

type enrollOptions struct {
	from    []string // validated IPs / CIDRs
	user    string
	keyLine string // "type base64 nebula-<ref>"
	keyFP   string
	sudo    bool
}

func hostEnrollScript(ctx context.Context, c pb.ExecutorServiceClient, args []string, w io.Writer) error {
	fs := flag.NewFlagSet("host enroll-script", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	from := fs.String("from", "", "comma-separated IP addresses or CIDR ranges Nebula connects from")
	user := fs.String("user", "nebula", "user to create on the host")
	ref := fs.String("key", "nebula-default", "keyring reference of the key to install")
	noSudo := fs.Bool("no-sudo", false, "do not grant sudo (read-only actions only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *from == "" {
		return errors.New(enrollUsage)
	}
	o := enrollOptions{user: *user, sudo: !*noSudo}
	if !enrollUserRe.MatchString(o.user) || o.user == "root" {
		return fmt.Errorf("--user %q is not a valid non-root user name", o.user)
	}
	if !enrollRefRe.MatchString(*ref) {
		return fmt.Errorf("--key %q is not a valid keyring reference", *ref)
	}
	for _, a := range strings.Split(*from, ",") {
		a = strings.TrimSpace(a)
		if net.ParseIP(a) == nil {
			if _, _, err := net.ParseCIDR(a); err != nil {
				return fmt.Errorf("--from %q is neither an IP address nor a CIDR range", a)
			}
		}
		o.from = append(o.from, a)
	}
	resp, err := c.GetSSHPublicKey(ctx, &pb.GetSSHPublicKeyRequest{CredentialRef: *ref})
	if err != nil {
		return err
	}
	// Re-encode from the parsed key: nothing the executor returns besides
	// the key itself reaches the script.
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(resp.GetAuthorizedKey()))
	if err != nil {
		return fmt.Errorf("executor returned an unusable key: %w", err)
	}
	o.keyLine = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " nebula-" + *ref
	o.keyFP = ssh.FingerprintSHA256(pub)
	_, err = io.WriteString(w, enrollScript(o))
	return err
}

// enrollScript renders the script. Every interpolated value was validated
// (user name, IPs/CIDRs, key re-encoded), so none can break out of its
// quoting.
func enrollScript(o enrollOptions) string {
	var b strings.Builder
	opts := fmt.Sprintf(`from="%s",no-agent-forwarding,no-port-forwarding,no-X11-forwarding`, strings.Join(o.from, ","))
	fmt.Fprintf(&b, `#!/bin/sh
# Nebula Operation Station: enroll this host (spec 08).
# Review, then run as root on the host. Key: %s
set -eu

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
`, o.keyFP, o.user, opts, o.keyLine)
	if o.sudo {
		fmt.Fprintf(&b, `
# NOPASSWD sudo: effectively root on this host (spec 08).
printf '%%s ALL=(ALL) NOPASSWD: ALL\n' "$user" > /etc/sudoers.d/nebula.tmp
chmod 0440 /etc/sudoers.d/nebula.tmp
visudo -cf /etc/sudoers.d/nebula.tmp
mv /etc/sudoers.d/nebula.tmp /etc/sudoers.d/nebula
`)
	}
	var pats, probe []string
	for _, a := range o.from {
		pats = append(pats, o.user+"@"+a)
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
