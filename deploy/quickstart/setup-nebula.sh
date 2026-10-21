#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# One-command setup of a Nebula machine from a git checkout (lab use).
# Run it from your admin account (not a root shell) on Debian 12 or
# Ubuntu 24.04:
#
#   git clone https://github.com/nebula-operation-station/nebula-operation-station.git
#   cd nebula-operation-station
#   sudo ./deploy/quickstart/setup-nebula.sh --rp-id nebula.lab.example.org
#
# It installs the packages Nebula needs (nmap, age, Caddy, make, git), the
# Go toolchain if missing, builds Nebula, runs deploy/install.sh, creates
# the backup key and the SSH key for managed hosts, sets up Caddy with an
# internal CA in front of the web UI, unlocks the executor and prints the
# one-time code for the first security key. Every step is idempotent: run
# it again after `git pull` to upgrade (install.sh backs up first).
#
# Options:
#   --rp-id HOST              hostname the web UI is served under (required)
#   --admin-users U[,U...]    admin accounts (default: the user who ran sudo)
#   --backup-recipient AGE1   use this age public key instead of creating one
#   --no-caddy                do not set up Caddy (bring your own proxy)
#   --no-unlock               stop before unlocking the executor
#
# Secrets are never taken from the command line: the SSH key passphrase is
# asked for by ssh-keygen and nebula unlock.
set -euo pipefail

GO_SERIES=1.26          # module needs go 1.26 (go.mod)
GO_MIN=1.26.0

rp_id=""
admin_users=""
backup_recipient=""
with_caddy=1
with_unlock=1

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() { sed -n '3,27p' "$0" | sed 's/^# \{0,1\}//'; }

need() { [[ $# -ge 2 && -n "$2" ]] || die "$1 requires a value"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rp-id) need "$@"; rp_id=$2; shift 2 ;;
    --rp-id=*) rp_id=${1#*=}; shift ;;
    --admin-users) need "$@"; admin_users=$2; shift 2 ;;
    --admin-users=*) admin_users=${1#*=}; shift ;;
    --backup-recipient) need "$@"; backup_recipient=$2; shift 2 ;;
    --backup-recipient=*) backup_recipient=${1#*=}; shift ;;
    --no-caddy) with_caddy=0; shift ;;
    --no-unlock) with_unlock=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option: $1" ;;
  esac
done

# --- Preconditions -----------------------------------------------------------
[[ ${EUID} -eq 0 ]] || die "run it with sudo: sudo $0 --rp-id HOST"
[[ -n "$rp_id" ]] || die "--rp-id is required (the hostname the web UI is served under)"
[[ "$rp_id" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$ ]] \
  || die "--rp-id must be a lowercase hostname (got: $rp_id)"
if [[ -n "$backup_recipient" && ! "$backup_recipient" =~ ^age1[0-9a-z]{58}$ ]]; then
  die "--backup-recipient must be an age public key (age1...)"
fi

admin="${SUDO_USER:-}"
if [[ -z "$admin_users" ]]; then
  [[ -n "$admin" && "$admin" != root ]] \
    || die "run it with sudo from your admin account, or pass --admin-users"
  admin_users="$admin"
fi
# The first admin runs the build and the CLI steps below.
first_admin=${admin_users%%,*}
[[ -n "$admin" && "$admin" != root ]] || admin="$first_admin"
id "$first_admin" >/dev/null 2>&1 || die "admin user $first_admin does not exist"
admin_home=$(getent passwd "$first_admin" | cut -d: -f6)

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
[[ -f "$repo/go.mod" && -x "$repo/deploy/install.sh" ]] || die "run it from a nebula-operation-station checkout"

[[ -d /run/systemd/system ]] || die "this needs a systemd host"
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}" in
  debian|ubuntu) ;;
  *) die "supported: Debian 12, Ubuntu 22.04/24.04 (found ${PRETTY_NAME:-unknown})" ;;
esac

as_admin() { sudo -u "$first_admin" -H -- "$@"; }

# Changing the RP ID later would leave server.json, the Caddyfile or the
# executor with the old one (and every security key registered for it):
# refuse. The executor's is the one in effect (last -rp-id of the unit).
if [[ -f /etc/nebula/server.json ]] && ! grep -qF "\"https://$rp_id\"" /etc/nebula/server.json; then
  die "/etc/nebula/server.json has another public_origin than https://$rp_id; use the RP ID of the first run (changing it means registering every security key again: see the handbook)"
fi
current_rp=$(systemctl cat nebula-executor 2>/dev/null | grep -oE -- '-rp-id [^ \\]+' | tail -n 1 | cut -d' ' -f2 || true)
if [[ -n "$current_rp" && "$current_rp" != "nebula.example.org" && "$current_rp" != "$rp_id" ]]; then
  die "the executor runs with RP ID $current_rp, not $rp_id; use --rp-id $current_rp (changing it means registering every security key again: see the handbook)"
fi
if [[ "$rp_id" != *.* ]]; then
  warn "--rp-id $rp_id is a short host name: security keys then only work at exactly https://$rp_id/. A full name (for example ops.example.org) is the usual choice, and it cannot be changed later without registering the keys again."
fi

# --- 1. Sizing check (warnings only) ----------------------------------------
say "Checking this machine"
cpus=$(nproc)
mem_mb=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
disk_gb=$(df -Pk / | awk 'NR==2 {print int($4/1048576)}')
echo "  ${cpus} CPU, ${mem_mb} MB RAM, ${disk_gb} GB free on /"
[[ $cpus -ge 2 ]]       || warn "2 CPUs recommended"
[[ $mem_mb -ge 3500 ]]  || warn "4 GB RAM recommended (building Nebula needs it)"
[[ $disk_gb -ge 10 ]]   || warn "at least 10 GB free disk recommended"
if swapon --noheadings --show=NAME 2>/dev/null | grep -q .; then
  warn "swap is active: unlocked keys could be swapped out; use encrypted swap or none (swapoff -a, remove it from /etc/fstab)"
fi

# --- 2. Packages ---------------------------------------------------------------
say "Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
pkgs=(ca-certificates curl git make nmap age openssh-client openssl python3)
[[ $with_caddy -eq 1 ]] && pkgs+=(caddy)
if ! apt-get install -y -q "${pkgs[@]}"; then
  [[ $with_caddy -eq 1 ]] && warn "if caddy is not in your release (Ubuntu 22.04), install it from https://caddyserver.com/docs/install or use --no-caddy"
  die "package installation failed"
fi

# --- 3. Go toolchain -------------------------------------------------------------
go_ok() {
  local v
  v=$("$1" env GOVERSION 2>/dev/null | sed 's/^go//') || return 1
  [[ -n "$v" ]] && [[ "$(printf '%s\n%s\n' "$GO_MIN" "$v" | sort -V | head -1)" == "$GO_MIN" ]]
}
GO=""
for cand in /usr/local/go/bin/go "$(command -v go || true)"; do
  if [[ -n "$cand" && -x "$cand" ]] && go_ok "$cand"; then GO=$cand; break; fi
done
if [[ -z "$GO" ]]; then
  say "Installing Go ${GO_SERIES} (official release, checksum verified)"
  case "$(uname -m)" in
    x86_64) goarch=amd64 ;;
    aarch64|arm64) goarch=arm64 ;;
    *) die "unsupported CPU: $(uname -m)" ;;
  esac
  # include=all: the default list holds only the two newest Go series.
  dl=$(curl -fsSL 'https://go.dev/dl/?mode=json&include=all' | python3 -c '
import json, sys
series, arch = sys.argv[1], sys.argv[2]
for rel in json.load(sys.stdin):
    if rel["stable"] and rel["version"].startswith("go" + series + "."):
        for f in rel["files"]:
            if f["os"] == "linux" and f["arch"] == arch and f["kind"] == "archive":
                print(f["filename"], f["sha256"]); sys.exit(0)
sys.exit(1)' "$GO_SERIES" "$goarch") || die "could not find a Go ${GO_SERIES} release on go.dev"
  read -r go_file go_sum <<<"$dl"
  [[ "$go_file" =~ ^go[0-9][0-9.]*\.linux-(amd64|arm64)\.tar\.gz$ ]] || die "unexpected Go file name from go.dev: $go_file"
  [[ "$go_sum" =~ ^[0-9a-f]{64}$ ]] || die "unexpected Go checksum from go.dev"
  work=$(mktemp -d /var/tmp/nebula-go.XXXXXX)
  curl -fsSL --max-time 1800 -o "$work/$go_file" "https://go.dev/dl/$go_file"
  echo "$go_sum  $work/$go_file" | sha256sum -c --quiet || die "Go download checksum mismatch"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "$work/$go_file"
  rm -rf "$work"
  GO=/usr/local/go/bin/go
fi
echo "  using $("$GO" version)"

# --- 4. Build ----------------------------------------------------------------------
say "Building Nebula"
chown -R "$first_admin": "$repo"
as_admin env PATH="$(dirname "$GO"):/usr/bin:/bin" GOTOOLCHAIN=local make -C "$repo" build
# deploy/install.sh takes the binaries from the directory above deploy/
# (ignored by git there).
for b in nebula nebula-server nebula-executor nebula-discovery; do
  install -m 0755 "$repo/bin/$b" "$repo/$b"
done

# --- 5. Install (users, directories, units, server.json; backup on upgrade) ---
say "Installing Nebula (deploy/install.sh)"
"$repo/deploy/install.sh" --admin-users "$admin_users" --rp-id "$rp_id"

# --- 6. Backup key ------------------------------------------------------------------
say "Backup recipient"
if [[ -s /etc/nebula/backup-recipients ]]; then
  echo "  /etc/nebula/backup-recipients exists; keeping it"
  if [[ -n "$backup_recipient" ]] && ! grep -qxF "$backup_recipient" /etc/nebula/backup-recipients; then
    warn "--backup-recipient is not in /etc/nebula/backup-recipients; add it there yourself (one recipient per line) if you want it"
  fi
else
  if [[ -z "$backup_recipient" ]]; then
    keyfile="$admin_home/nebula-backup.key"
    if [[ ! -e "$keyfile" ]]; then
      # shellcheck disable=SC2016 # $1 expands in the inner shell
      as_admin sh -c 'umask 077 && age-keygen -o "$1"' _ "$keyfile"
      created_backup_key=1
    fi
    backup_recipient=$(as_admin age-keygen -y "$keyfile")
  fi
  printf '%s\n' "$backup_recipient" > /etc/nebula/backup-recipients
  chmod 0644 /etc/nebula/backup-recipients
  echo "  backups are encrypted to $backup_recipient"
fi

# --- 7. SSH key for managed hosts ---------------------------------------------------
say "SSH key for managed hosts"
keydir=/var/lib/nebula/executor/keys
install -d -m 0700 -o nebula-executor -g nebula-executor "$keydir"
if [[ -e "$keydir/nebula-default.key" ]]; then
  echo "  $keydir/nebula-default.key exists; keeping it"
else
  echo "  Choose a long passphrase and store it in your password manager."
  echo "  You type it again after every restart (nebula unlock)."
  sudo -u nebula-executor ssh-keygen -q -t ed25519 -C nebula-default -f "$keydir/nebula-default.key"
fi

# --- 8. Caddy with an internal CA -----------------------------------------------------
if [[ $with_caddy -eq 1 ]]; then
  say "HTTPS with Caddy (internal CA)"
  caddyfile=/etc/caddy/Caddyfile
  marker="# nebula-operation-station (deploy/quickstart)"
  if ! grep -qF "$marker" "$caddyfile" 2>/dev/null; then
    # Only the package's demo site may be replaced; a Caddyfile with your
    # own sites stays: add the Nebula site to it yourself, or --no-caddy.
    if [[ -s "$caddyfile" ]] && ! grep -q '/usr/share/caddy' "$caddyfile"; then
      die "$caddyfile has sites of its own; add this site to it and run again with --no-caddy:
  $rp_id {
      tls internal
      reverse_proxy 127.0.0.1:8080
  }"
    fi
    [[ -f "$caddyfile" ]] && cp -p "$caddyfile" "$caddyfile.before-nebula"
    # The Debian package ships a demo site on :80; Nebula's site replaces it.
    cat > "$caddyfile" <<EOF
$marker
$rp_id {
	tls internal
	reverse_proxy 127.0.0.1:8080
}
EOF
  fi
  systemctl enable caddy >/dev/null 2>&1 || true
  systemctl restart caddy
  root_ca=/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt
  for _ in $(seq 1 30); do [[ -s "$root_ca" ]] && break; sleep 1; done
  if [[ -s "$root_ca" ]]; then
    install -m 0644 -o "$first_admin" "$root_ca" "$admin_home/nebula-root-ca.crt"
    ca_fp=$(openssl x509 -in "$root_ca" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 || true)
  else
    warn "Caddy has not created its root certificate yet: journalctl -u caddy"
  fi
fi

# --- 9. Unlock and first security key ------------------------------------------------
if [[ $with_unlock -eq 1 ]]; then
  say "Unlocking the executor (enter the SSH key passphrase)"
  as_admin /usr/bin/nebula unlock
  as_admin /usr/bin/nebula status || true
  say "Enrollment script for managed hosts"
  from=$(hostname -I | tr ' ' '\n' | { grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || true; } | paste -sd, -)
  if [[ -n "$from" ]]; then
    # shellcheck disable=SC2016 # $1, $2 expand in the inner shell
    as_admin sh -c '/usr/bin/nebula host enroll-script --from "$1" > "$2"' _ "$from" "$admin_home/enroll.sh"
    echo "  written to $admin_home/enroll.sh (for connections from $from)"
  fi
  say "One-time code for your first security key"
  as_admin /usr/bin/nebula webauthn code
fi

# --- Summary ---------------------------------------------------------------------------
ips=$(hostname -I | awk '{print $1}')
cat <<EOF

$(printf '\033[1m')Nebula is installed.$(printf '\033[0m')

Next:
EOF
step=1
if [[ $with_caddy -eq 1 ]]; then
  cat <<EOF
  $step. On the computer with your browser, make $rp_id resolve to this machine
     (DNS, or a hosts entry: "$ips $rp_id").
EOF
  step=$((step+1))
  cat <<EOF
  $step. Import $admin_home/nebula-root-ca.crt as a trusted root certificate
     (operating system or browser), after checking its SHA-256 fingerprint:
       ${ca_fp:-see: openssl x509 -in $admin_home/nebula-root-ca.crt -noout -fingerprint -sha256}
EOF
  step=$((step+1))
fi
cat <<EOF
  $step. Open https://$rp_id/setup and enter the one-time code above
     (new code: nebula webauthn code). Register a second key as backup.
EOF
step=$((step+1))
if [[ -n "${created_backup_key:-}" ]]; then
  cat <<EOF
  $step. Move the backup key $admin_home/nebula-backup.key off this machine
     (password manager), then delete it here: shred -u $admin_home/nebula-backup.key
     Without it, no backup can be restored.
EOF
  step=$((step+1))
fi
[[ -f "$admin_home/enroll.sh" ]] || cat <<EOF
  $step. Unlock (nebula unlock) and create the enrollment script:
       nebula host enroll-script --from $ips > ~/enroll.sh
EOF
[[ -f "$admin_home/enroll.sh" ]] || step=$((step+1))
cat <<EOF
  $step. Prepare each managed host: copy $admin_home/enroll.sh and
     deploy/quickstart/prepare-target.sh to it and run there
       sudo ./prepare-target.sh --nebula-ip $ips --enroll enroll.sh
     then pin it in the web UI (Inventory -> Enroll hosts).

After every reboot of this machine: nebula unlock
Upgrade later: git pull, then run this script again.
Handbook: docs/admin/guide.md
EOF
