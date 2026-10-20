#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Prepare a managed host (Debian 12, Ubuntu 22.04/24.04, Proxmox VE) for
# Nebula. Run it as root on the host, next to the enroll.sh that
# setup-nebula.sh (or `nebula host enroll-script`) wrote on the Nebula
# machine:
#
#   sudo ./prepare-target.sh --nebula-ip 192.168.0.10 --enroll enroll.sh
#
# It installs what Nebula's actions use (OpenSSH server, sudo, curl), lets
# the Nebula machine past fail2ban if fail2ban is installed, runs the
# enrollment script (a `nebula` user with Nebula's key, limited to the
# Nebula addresses, and a NOPASSWD sudo rule: that user is effectively
# root here) and prints this host's SSH key fingerprints. Compare them
# with what the web UI shows when you pin the host.
#
# Options:
#   --nebula-ip IP[,IP...]  addresses the Nebula machine connects from (required)
#   --enroll FILE           the enrollment script from the Nebula machine
#                           (without it, only the preparation runs)
set -euo pipefail

nebula_ips=""
enroll=""

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
say() { printf '\n==> %s\n' "$*"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --nebula-ip) [[ $# -ge 2 ]] || die "--nebula-ip requires a value"; nebula_ips=$2; shift 2 ;;
    --nebula-ip=*) nebula_ips=${1#*=}; shift ;;
    --enroll) [[ $# -ge 2 ]] || die "--enroll requires a value"; enroll=$2; shift 2 ;;
    --enroll=*) enroll=${1#*=}; shift ;;
    -h|--help) sed -n '3,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ ${EUID} -eq 0 ]] || die "run it as root: sudo $0 --nebula-ip IP --enroll enroll.sh"
[[ -n "$nebula_ips" ]] || die "--nebula-ip is required"
IFS=',' read -r -a ips <<<"$nebula_ips"
valid_ip() {
  local addr=${1%/*} len=""
  [[ "$1" == */* ]] && len=${1#*/}
  if [[ "$addr" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
    for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
    [[ -z "$len" ]] || { [[ "$len" =~ ^[0-9]{1,2}$ ]] && (( 10#$len >= 8 && 10#$len <= 32 )); } || return 1
  elif [[ "$addr" == *:* && "$addr" != "::" && "$addr" =~ ^[0-9a-fA-F:]{2,39}$ && "$addr" != *:::* ]]; then
    [[ -z "$len" ]] || { [[ "$len" =~ ^[0-9]{1,3}$ ]] && (( 10#$len >= 16 && 10#$len <= 128 )); } || return 1
  else
    return 1
  fi
}
for ip in "${ips[@]}"; do
  valid_ip "$ip" || die "--nebula-ip: $ip is not an IP address or a CIDR range of /8 (IPv4) or /16 (IPv6) and narrower; this script will not exempt the whole internet from fail2ban"
done
if [[ -n "$enroll" ]]; then
  [[ -f "$enroll" ]] || die "$enroll not found"
  head -n 2 "$enroll" | grep -q "Nebula Operation Station: enroll this host" \
    || die "$enroll does not look like a Nebula enrollment script"
fi

say "Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q openssh-server sudo curl ca-certificates
systemctl enable --now ssh >/dev/null 2>&1 || systemctl enable --now sshd >/dev/null 2>&1 || true

jail=/etc/fail2ban/jail.d/nebula.local
if systemctl is-active --quiet fail2ban 2>/dev/null; then
  say "fail2ban: ignoring the Nebula machine"
  if [[ -f "$jail" ]] && ! head -n 1 "$jail" | grep -qF '# Written by nebula prepare-target.sh'; then
    echo "  $jail was edited by hand; leaving it alone (add ${ips[*]} to its ignoreip yourself)"
  else
    install -d -m 0755 /etc/fail2ban/jail.d
    printf '# Written by nebula prepare-target.sh\n[DEFAULT]\nignoreip = 127.0.0.1/8 ::1 %s\n' "${ips[*]}" > "$jail"
  fi
  if systemctl reload fail2ban 2>/dev/null; then
    echo "  /etc/fail2ban/jail.d/nebula.local: ${ips[*]}"
  else
    echo "  warning: fail2ban did not reload; check: fail2ban-client -t" >&2
    echo "  Check: systemctl status fail2ban (Debian 12 needs backend = systemd for sshd)" >&2
  fi
  echo "  (if you set ignoreip elsewhere, merge it there: the last definition wins)"
fi

if [[ -n "$enroll" ]]; then
  say "Running the enrollment script"
  echo "  Read it first if you have not: less $enroll"
  sh "$enroll"   # prints this host's SSH key fingerprints at the end
else
  say "SSH host key fingerprints (compare when you pin the host)"
  for f in /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ecdsa_key.pub /etc/ssh/ssh_host_rsa_key.pub; do
    [[ -f "$f" ]] && ssh-keygen -lf "$f"
  done
fi

cat <<EOF

Done. In the Nebula web UI: Inventory -> add this host (endpoint
$(hostname -I | awk '{print $1}')), then Inventory -> Enroll hosts -> Read host keys,
compare with the fingerprints above, and pin. (Or on the Nebula machine:
nebula host pin HOST $(hostname -I | awk '{print $1}'), then nebula host test HOST $(hostname -I | awk '{print $1}').)
EOF
