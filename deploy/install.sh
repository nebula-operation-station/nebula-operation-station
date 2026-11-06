#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Install Nebula Operation Station from a release tarball on Debian 12
# (also works on Ubuntu 22.04/24.04). Run it from the extracted tarball:
#
#   sudo ./deploy/install.sh --admin-users alice,bob --rp-id nebula.example.org
#
# Both options are required:
#
#   --admin-users  comma-separated OS users allowed to unlock and approve
#                  (each must exist on this system)
#   --rp-id        WebAuthn RP ID: the fixed hostname Nebula is served
#                  under (a lowercase hostname)
#
# The values are written into the systemd drop-in
# /etc/systemd/system/nebula-executor.service.d/10-local.conf, which
# overrides the executor's ExecStart (origin = https://<rp-id>). The
# drop-in is rewritten on every run; the unit file itself is never
# edited. Each admin user is added to the nebula-rpc group (idempotent)
# and must log in again for the membership to take effect.
#
# The server configuration /etc/nebula/server.json (listen address,
# public origin, data dir, executor socket) is written only if it does
# not exist yet; later runs leave it untouched. It contains no secrets.
#
# The script is idempotent: re-running it updates the binaries and
# rewrites the drop-in, but never overwrites unit files you have edited,
# never touches the data directories, and never overwrites an existing
# /etc/nebula/server.json.
#
# Dry run (no root needed, changes nothing):
#
#   NEBULA_INSTALL_DRY_RUN=1 ./deploy/install.sh \
#     --admin-users alice --rp-id nebula.example.org
#
set -euo pipefail

# --- Options ----------------------------------------------------------------
usage() {
  cat <<'EOF'
Usage: install.sh --admin-users USER[,USER...] --rp-id HOST

  --admin-users  comma-separated OS users allowed to unlock and approve
                 (each must exist on this system; not root, not the
                 nebula-server/nebula-executor system users; each entry
                 must match ^[a-z_][a-z0-9_-]{0,31}$)
  --rp-id        WebAuthn RP ID: the fixed hostname Nebula is served
                 under (lowercase hostname)

  --from-package  the .deb installed binaries and units; only configure

Both options are required. They are written into the systemd drop-in
/etc/systemd/system/nebula-executor.service.d/10-local.conf, which
overrides the executor's ExecStart (origin = https://<rp-id>).
EOF
}

admin_users=""
rp_id=""
# --from-package: the .deb installed the binaries (/usr/bin) and the units
# (/lib/systemd/system); configure only users, directories, drop-ins and
# server.json, then enable and start.
from_package=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --admin-users)
      if [[ $# -lt 2 ]]; then
        echo "install.sh: --admin-users requires a value" >&2
        usage >&2
        exit 2
      fi
      admin_users="$2"
      shift 2
      ;;
    --admin-users=*)
      admin_users="${1#*=}"
      shift
      ;;
    --rp-id)
      if [[ $# -lt 2 ]]; then
        echo "install.sh: --rp-id requires a value" >&2
        usage >&2
        exit 2
      fi
      rp_id="$2"
      shift 2
      ;;
    --rp-id=*)
      rp_id="${1#*=}"
      shift
      ;;
    --from-package)
      from_package=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "install.sh: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$admin_users" || -z "$rp_id" ]]; then
  echo "install.sh: --admin-users and --rp-id are required" >&2
  usage >&2
  exit 2
fi

# --- Validate the options (also in dry-run mode) ----------------------------
# rp-id is a WebAuthn RP ID: a lowercase hostname, labels of lowercase
# letters, digits and hyphens, no leading or trailing hyphen.
if [[ ! "$rp_id" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$ ]]; then
  echo "install.sh: --rp-id must be a lowercase hostname (got: $rp_id)" >&2
  exit 1
fi

# Split the admin list, trim whitespace, and validate every entry. The
# executor refuses to start with a missing, root or reserved admin user
# (cmd/nebula-executor), which would crash-loop the service, so reject
# the same set here at install time.
IFS=',' read -r -a raw_users <<< "$admin_users"
admin_list=()
for user in "${raw_users[@]}"; do
  user="${user#"${user%%[![:space:]]*}"}"
  user="${user%"${user##*[![:space:]]}"}"
  if [[ -z "$user" ]]; then
    echo "install.sh: --admin-users contains an empty entry" >&2
    exit 1
  fi
  # Entries must look like OS usernames. The pattern rejects numeric UIDs
  # (getent would resolve them) and '%' (systemd expands it in ExecStart).
  if [[ ! "$user" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
    echo "install.sh: admin user must match ^[a-z_][a-z0-9_-]{0,31}$ (got: $user)" >&2
    exit 1
  fi
  if ! getent passwd "$user" >/dev/null; then
    echo "install.sh: admin user does not exist: $user" >&2
    exit 1
  fi
  case "$user" in
    root|nebula-server|nebula-executor|nebula-discovery|nebula-pve-collector)
      echo "install.sh: $user cannot be an admin user; use a personal account" >&2
      exit 1
      ;;
  esac
  admin_list+=("$user")
done
admin_users_norm=$(IFS=','; printf '%s' "${admin_list[*]}")

# --- Dry run: options parsed and validated, nothing is touched --------------
if [[ "${NEBULA_INSTALL_DRY_RUN:-0}" == "1" ]]; then
  echo "install.sh: dry run: options valid (admin users: ${admin_users_norm}; rp-id: ${rp_id})"
  echo "install.sh: dry run: would install binaries, units, the executor drop-in and the server config; no changes made"
  exit 0
fi

# --- Refuse to run without root ---------------------------------------------
if [[ ${EUID} -ne 0 ]]; then
  echo "install.sh: must be run as root (try: sudo ./deploy/install.sh)" >&2
  exit 1
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
tarball_root=$(dirname -- "$script_dir")

# The binary list is shared with deploy/quickstart (setup-nebula.sh copies
# exactly these before running this script): one file, so the two cannot
# drift (WA-03). The release tarball carries the whole deploy/ tree.
# begin: load binary list
binaries_file="${script_dir}/quickstart/binaries.txt"
if [[ ! -s "$binaries_file" ]]; then
  echo "install.sh: ${binaries_file} not found; is this a release tarball?" >&2
  exit 1
fi
# shellcheck source=deploy/quickstart/binaries_lib.sh
. "${script_dir}/quickstart/binaries_lib.sh"
# read_binaries stops on the first invalid line; the list is the single
# source of truth, so a mangled line must abort, not install a partial set.
if ! binaries_out=$(read_binaries "$binaries_file"); then
  echo "install.sh: ${binaries_file} contains an invalid line (see above)" >&2
  exit 1
fi
binaries=()
if [[ -n "$binaries_out" ]]; then
  mapfile -t binaries <<< "$binaries_out"
fi
if [[ ${#binaries[@]} -eq 0 ]]; then
  echo "install.sh: ${binaries_file} lists no binaries" >&2
  exit 1
fi
# end: load binary list

bin_dir=/usr/bin
systemd_dir=/etc/systemd/system
var_lib=/var/lib/nebula
group_name=nebula-rpc
drop_in_dir="${systemd_dir}/nebula-executor.service.d"
drop_in="${drop_in_dir}/10-local.conf"

# --- Check the tarball layout ---------------------------------------------
# begin: check layout
unit_dir="${systemd_dir}"
if [[ ${from_package} -eq 1 ]]; then
  unit_dir=/lib/systemd/system
  for bin in "${binaries[@]}"; do
    if [[ ! -x "${bin_dir}/${bin}" ]]; then
      echo "install.sh: ${bin_dir}/${bin} not found; is the package installed?" >&2
      exit 1
    fi
  done
else
  for bin in "${binaries[@]}"; do
    if [[ ! -f "${tarball_root}/${bin}" ]]; then
      echo "install.sh: ${tarball_root}/${bin} not found" >&2
      echo "install.sh: run this script from the extracted release tarball" >&2
      exit 1
    fi
  done
fi
if [[ ! -d "${script_dir}/systemd" ]]; then
  echo "install.sh: ${script_dir}/systemd not found; is this a release tarball?" >&2
  exit 1
fi
# end: check layout

# --- Users and group (idempotent) ------------------------------------------
if ! getent group "${group_name}" >/dev/null; then
  groupadd --system "${group_name}"
fi
if ! getent passwd nebula-server >/dev/null; then
  useradd --system --home-dir "${var_lib}/server" \
    --shell /usr/sbin/nologin -G "${group_name}" nebula-server
fi
if ! getent passwd nebula-executor >/dev/null; then
  useradd --system --home-dir "${var_lib}/executor" \
    --shell /usr/sbin/nologin nebula-executor
fi
if ! getent passwd nebula-discovery >/dev/null; then
  useradd --system --home-dir "${var_lib}/discovery" \
    --shell /usr/sbin/nologin nebula-discovery
fi
# PVE collector (ADR 0006, P1-14): its own system user with the pve-collector
# peercred role. It is in nebula-rpc to reach the executor socket; the unit
# gives it no capabilities and no network (nebula-pve-collector.service).
if ! getent passwd nebula-pve-collector >/dev/null; then
  useradd --system --home-dir "${var_lib}/pve" --shell /usr/sbin/nologin -G "${group_name}" nebula-pve-collector
fi

# Admin users need the nebula-rpc group for the CLI socket; usermod -aG
# is a no-op when the membership already exists.
for user in "${admin_list[@]}"; do
  usermod -aG "${group_name}" "${user}"
done

# --- Directories (modes from docs/spec/03) ---------------------------------
# The executor refuses to start unless its data dir is 0700
# (internal/fsguard); the server dir must not be world-readable because
# it will hold the server database.
install -d -m 0755 -o root -g root "${var_lib}"
install -d -m 0750 -o nebula-server -g nebula-server "${var_lib}/server"
install -d -m 0700 -o nebula-executor -g nebula-executor "${var_lib}/executor"
# Discovery spool (spec 12): the server writes jobs/ and only reads
# results/; nebula-discovery reads jobs/ and writes results/.
install -d -m 0755 -o root -g root "${var_lib}/discovery"
# setgid: a file written by one side gets the directory's group, the
# reader's, so the other side can read it (review m105).
install -d -m 2750 -o nebula-server -g nebula-discovery "${var_lib}/discovery/jobs"
install -d -m 2750 -o nebula-discovery -g nebula-server "${var_lib}/discovery/results"
# PVE spool (ADR 0006, P1-14): the collector owns the root and writes the
# results; the server group (nebula-rpc) lists, reads and, once imported,
# unlinks them (internal/pvecollect/spool.go; the server drop-in below opens
# results/ and guestnet/ for that). setgid so a file written by the collector
# inherits the shared group, which the server can read. The root is 0750 (not
# world-readable) because it holds PVE data.
install -d -m 2750 -o nebula-pve-collector -g nebula-rpc "${var_lib}/pve"
install -d -m 2770 -o nebula-pve-collector -g nebula-rpc "${var_lib}/pve/results"
# Guest NIC records (same handoff as results). Created here with its final
# mode: the collector unit (RestrictSUIDSGID=yes) cannot set setgid itself.
install -d -m 2770 -o nebula-pve-collector -g nebula-rpc "${var_lib}/pve/guestnet"
# Live handoff (ADR 0006 P1-37): the server writes the want-list to requests/
# (group-writable, made writable by the server drop-in below) and reads the
# collector's samples from live/ (group read-only). The server never reads
# Proxmox itself.
install -d -m 2770 -o nebula-pve-collector -g nebula-rpc "${var_lib}/pve/requests"
install -d -m 2750 -o nebula-pve-collector -g nebula-rpc "${var_lib}/pve/live"

# --- Pre-upgrade backup (spec 15) --------------------------------------------
# Before an existing install is replaced, the new CLI makes a backup (as
# the admin who ran sudo, to ~/nebula-backups). Without a backup the
# upgrade stops: when it cannot make one (exit 3: no backup recipients, no
# sudo from an admin, an executor older than backups) or when it fails.
# Set NEBULA_SKIP_BACKUP=1 to upgrade without one. Package upgrades never
# restart the services (deploy/deb/postinst).
if [[ ${from_package} -eq 0 && -x "${bin_dir}/nebula-executor" && "${NEBULA_SKIP_BACKUP:-0}" != "1" ]]; then
  rc=0
  "${tarball_root}/nebula" backup --pre-upgrade || rc=$?
  if [[ ${rc} -eq 3 ]]; then
    echo "install.sh: no pre-upgrade backup was made (see above); nothing was changed." >&2
    echo "install.sh: fix that, or run again with NEBULA_SKIP_BACKUP=1 to upgrade without a backup" >&2
    exit 1
  elif [[ ${rc} -ne 0 ]]; then
    echo "install.sh: the pre-upgrade backup failed; fix it or run again with NEBULA_SKIP_BACKUP=1" >&2
    exit 1
  fi
fi

# --- Binaries (replaced on every run; detect real changes) ------------------
# begin: install binaries
bin_changed=0
[[ ${from_package} -eq 1 ]] || for bin in "${binaries[@]}"; do
  old_sum=""
  if [[ -f "${bin_dir}/${bin}" ]]; then
    old_sum=$(sha256sum "${bin_dir}/${bin}" | cut -d' ' -f1)
  fi
  install -m 0755 -o root -g root "${tarball_root}/${bin}" "${bin_dir}/${bin}"
  new_sum=$(sha256sum "${bin_dir}/${bin}" | cut -d' ' -f1)
  if [[ "${old_sum}" != "${new_sum}" ]]; then
    bin_changed=1
  fi
done
# end: install binaries

# --- Units (installed only if absent: never clobber admin edits) -----------
# The units this install provisions are listed explicitly (WA-04). The
# iconfetch units (nebula-iconfetch.service/.path/.timer and
# nebula-iconfetch-firewall.service) are deliberately left out: the icon
# service is not wired into the server yet, and
# nebula-iconfetch-firewall.service's ExecStart needs
# /etc/nebula/nebula-iconfetch.nft, which nothing provisions. Enabling one
# of them under set -e could abort the install before nebula-server, the
# collector or the executor are enabled. Re-add them here once the icon
# service is provisioned.
#
# In both lists, nebula-server, nebula-executor and nebula-pve-collector
# come before the discovery units, and the enable loop below enables the
# executor within that loop (before the discovery units, not after it), so
# a failing discovery unit cannot abort the install (set -e) before the
# server, the executor or the collector are enabled.
#
# tarball_units is the set of unit files this install provisions; it
# includes nebula-discovery.service, which has no [Install] section and is
# therefore installed but never enabled. package_units is the set the
# package enables: the installable subset (no nebula-discovery.service).
tarball_units=(
  nebula-server.service
  nebula-executor.service
  nebula-pve-collector.service
  nebula-discovery.path
  nebula-discovery.service
  nebula-discovery.timer
)
package_units=(
  nebula-server.service
  nebula-executor.service
  nebula-pve-collector.service
  nebula-discovery.path
  nebula-discovery.timer
)

# enable_units is the list the enable loop below walks, in the order above.
# In tarball mode every provisioned unit is enabled whether or not it was
# just installed, so a re-run after an aborted install still enables the
# units even when their files are already present. In package mode only the
# units the package has not enabled yet are listed.
enable_units=()
if [[ ${from_package} -eq 1 ]]; then
  # The package ships the units; enable the ones not enabled yet.
  for name in "${package_units[@]}"; do
    if ! systemctl is-enabled --quiet "${name}" 2>/dev/null; then
      enable_units+=("${name}")
    fi
  done
else
  for name in "${tarball_units[@]}"; do
    if [[ -e "${systemd_dir}/${name}" ]]; then
      echo "install.sh: ${systemd_dir}/${name} already exists; leaving it untouched"
    else
      install -m 0644 -o root -g root "${script_dir}/systemd/${name}" "${systemd_dir}/${name}"
    fi
    # Enable it whether or not it was just installed: a re-run after an
    # aborted install must still enable the units, not only the ones whose
    # file is absent.
    enable_units+=("${name}")
  done
fi

# Remove iconfetch units left behind by an earlier install (WA-04): the
# lists above no longer install them, but a host upgraded from an earlier
# install still has them in /etc/systemd/system, possibly enabled. Disable
# and remove them so they do not run at boot.
for name in nebula-iconfetch.service nebula-iconfetch.path nebula-iconfetch.timer nebula-iconfetch-firewall.service; do
  if [[ -e "${systemd_dir}/${name}" ]]; then
    echo "install.sh: removing leftover ${name} from an earlier install"
    systemctl disable --now "${name}" 2>/dev/null || true
    rm -f "${systemd_dir}/${name}"
  fi
done

# --- Executor drop-in (rewritten on every run; never edit the unit) --------
# The reference unit ships a placeholder ExecStart that would crash-loop
# the executor; the drop-in clears it (empty ExecStart=) and sets the
# real one with this host's admin users and rp-id.
drop_in_changed=1
install -d -m 0755 -o root -g root "${drop_in_dir}"
tmp_drop_in=$(mktemp)
trap 'rm -f "${tmp_drop_in}"' EXIT
cat > "${tmp_drop_in}" <<EOF
# Written by deploy/install.sh on every run; do not edit by hand.
# Overrides the placeholder ExecStart in nebula-executor.service.
[Service]
ExecStart=
ExecStart=/usr/bin/nebula-executor \\
  -data-dir /var/lib/nebula/executor \\
  -socket /run/nebula/executor.sock \\
  -socket-group nebula-rpc \\
  -server-user nebula-server \\
  -admin-users ${admin_users_norm} \\
  -rp-id ${rp_id} \\
  -origin https://${rp_id}
EOF
if [[ -f "${drop_in}" ]] && cmp -s "${tmp_drop_in}" "${drop_in}"; then
  drop_in_changed=0
fi
install -m 0644 -o root -g root "${tmp_drop_in}" "${drop_in}"
rm -f "${tmp_drop_in}"

# --- Server drop-in (rewritten on every run) -----------------------------
# The server unit uses ProtectSystem=strict; it may write the discovery
# job spool, the PVE live want-list (pve/requests) and the two directories
# it consumes (pve/results, pve/guestnet), and nothing else outside its
# state directory. The pve root and pve/live stay read-only.
server_drop_in_dir="${systemd_dir}/nebula-server.service.d"
server_drop_in="${server_drop_in_dir}/20-discovery.conf"
server_drop_in_changed=1
install -d -m 0755 -o root -g root "${server_drop_in_dir}"
tmp_server_drop_in=$(mktemp)
cat > "${tmp_server_drop_in}" <<EOF
# Written by deploy/install.sh on every run; do not edit by hand.
# nebula-server queues discovery scans here (spec 12).
[Service]
ReadWritePaths=${var_lib}/discovery/jobs
# nebula-server writes the live want-list for nebula-pve-collector here
# (ADR 0006 P1-37); it never reads Proxmox itself.
ReadWritePaths=${var_lib}/pve/requests
# nebula-server unlinks the observations and guest NIC records it imported
# (ADR 0006 P1-10); without this the spool only grows.
ReadWritePaths=${var_lib}/pve/results
ReadWritePaths=${var_lib}/pve/guestnet
EOF
if [[ -f "${server_drop_in}" ]] && cmp -s "${tmp_server_drop_in}" "${server_drop_in}"; then
  server_drop_in_changed=0
fi
install -m 0644 -o root -g root "${tmp_server_drop_in}" "${server_drop_in}"
rm -f "${tmp_server_drop_in}"

# --- Server config (created only if absent: never clobber admin edits) -----
# /etc/nebula/server.json is the nebula-server configuration. It contains
# no secrets. Re-runs never overwrite it: edit it by hand and restart
# nebula-server after changing it.
install -d -m 0755 -o root -g root /etc/nebula
if [[ -e /etc/nebula/server.json ]]; then
  echo "install.sh: /etc/nebula/server.json already exists; leaving it untouched"
else
  tmp_server_json=$(mktemp)
  cat > "${tmp_server_json}" <<EOF
{
  "listen": "127.0.0.1:8080",
  "public_origin": "https://${rp_id}",
  "data_dir": "/var/lib/nebula/server",
  "executor_socket": "/run/nebula/executor.sock",
  "executor_user": "nebula-executor",
  "discovery_dir": "/var/lib/nebula/discovery"
}
EOF
  install -m 0640 -o root -g nebula-server "${tmp_server_json}" /etc/nebula/server.json
  rm -f "${tmp_server_json}"
fi

# --- Start/restart (only after the drop-in is in place) ---------------------
systemctl daemon-reload

for name in "${enable_units[@]}"; do
  # The executor is enabled here (before the discovery units) so its boot
  # start does not depend on the server's Wants=, but it is started or
  # restarted below, where the drop-in-aware handling lives.
  # nebula-discovery.service is started by its path unit and timer and has
  # no [Install] section, so it is not enabled.
  if [[ "${name}" == "nebula-executor.service" ]]; then
    systemctl enable "${name}"
  elif [[ "${name}" != "nebula-discovery.service" ]]; then
    systemctl enable --now "${name}"
  fi
done

if systemctl is-active --quiet nebula-server.service && [[ ${bin_changed} -eq 1 || ${server_drop_in_changed} -eq 1 ]]; then
  systemctl restart nebula-server.service
  echo "install.sh: restarted nebula-server (binaries or drop-in changed)"
fi

if systemctl is-active --quiet nebula-executor.service; then
  if [[ ${bin_changed} -eq 1 || ${drop_in_changed} -eq 1 ]]; then
    # Running with old binaries or an old drop-in: apply the new ones.
    systemctl restart nebula-executor.service
    echo "install.sh: restarted nebula-executor (binaries or drop-in changed)"
  fi
else
  # Not active: a fresh install (the server's Wants= did not start it, or
  # it is a new host) or an earlier install whose executor did not start.
  # It is already enabled (in the loop above, or from a previous run);
  # start it now that the drop-in is in place.
  systemctl restart nebula-executor.service
  echo "install.sh: started nebula-executor (was not active)"
fi

# --- Next steps --------------------------------------------------------------
cat <<EOF

Nebula Operation Station installed.

Admin users (group ${group_name}): ${admin_users_norm}
They must log out and log in again for the group membership to take
effect.

Next steps:

  1. Put a TLS reverse proxy in front of the server (it listens on
     127.0.0.1:8080 by default) and serve it under https://${rp_id}.

  2. Make sure both services are enabled and running:
       systemctl enable --now nebula-executor nebula-server

  3. Create the SSH key for the managed hosts (passphrase from your
     password manager):
       sudo -u nebula-executor mkdir -p ${var_lib}/executor/keys
       sudo -u nebula-executor ssh-keygen -t ed25519 -C nebula-default \\
         -f ${var_lib}/executor/keys/nebula-default.key

  4. Unlock the executor (it starts locked after every restart):
       nebula unlock

  5. Register the first security key: open https://${rp_id}/setup and
     enter the one-time code from
       nebula webauthn code

  6. Check the status:
       nebula status

Further changes to the executor flags go into a separate drop-in
${drop_in_dir}/20-local.conf, because ${drop_in} is rewritten by
install.sh on every run. After editing it:
  systemctl daemon-reload && systemctl restart nebula-executor
EOF
