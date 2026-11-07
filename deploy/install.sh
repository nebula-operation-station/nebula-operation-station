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
# /etc/nebula/server.json. Unit files you did not edit follow the shipped
# version; /var/lib/nebula/units.sha256 records what was installed, so
# that an edit can be told from an older shipped version.
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

# --- Units (refreshed only if unedited: never clobber admin edits) ---------
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

# begin: unit refresh
# units_manifest records, per unit, the checksum of the shipped version this
# script last installed: never the checksum of an edited file. A unit that
# still has that checksum was not edited and may follow the shipped version;
# any other content is the admin's and stays (WA-09).
units_manifest="${var_lib}/units.sha256"

# units_pending is the write-ahead record of a run: the checksum of a shipped
# version goes in before that version is written to its unit file, and the
# file goes away once the restart steps are through. What a stopped run leaves
# behind tells the next run what units_manifest cannot: a unit with one of
# these checksums is unedited even if the tarball has moved on, and its restart
# may still be due. Like units_manifest it holds shipped checksums only.
units_pending="${var_lib}/units.pending"

# Every version shipped before units_manifest existed. Hosts installed then
# have no recorded checksum, and without this list their units would all
# count as edited, so no shipped fix would ever reach them. It applies only
# to a unit with no recorded checksum. Frozen: a unit changed from now on is
# covered by units_manifest and does not belong here.
legacy_unit_sums=(
  "e7a42fc29dc5aeae3e854001f06cd0efeaef8458dd273e7a4ff74607a73de8c4  nebula-server.service"
  "fbce1de5c0888db5927d5a34333214f57e6239c987b9c7be41f21e7c761a1beb  nebula-executor.service"
  "cd452ec9eb40017e6ae6da044ef04034d8031f5137c7ed7b757c7039cde34f42  nebula-pve-collector.service"
  "60c0ef3dc3f3fc0ca54e528fd9b41d82571fbb0bb5637e1779a78e4ad8f0c2b7  nebula-pve-collector.service"
  "4ad18a7e6a7270588e6dbe6a04d2f6fd7a7ccd0730b2ff6989da4136d8acbf11  nebula-discovery.path"
  "be046e71c5f0585c7b0abe93d41a5e698dc47a69affd939761b4c968996a8a50  nebula-discovery.service"
  "2a88aab97acc72e9752b2c259c2f6f2dfccb9804d751cee77d138a0563df2c61  nebula-discovery.timer"
)

# Units whose new version a running service may not have yet, so that the
# restart step can apply it: the ones refresh_units replaced, and the ones a
# stopped run left pending. A unit installed for the first time in this run is
# not listed: the enable step starts it.
refreshed_units=()

# stored_unit_sum NAME prints the recorded checksum of NAME, nothing if there
# is none. Malformed lines count as no record, so damage to the file can only
# make a unit look edited, which keeps it.
stored_unit_sum() {
  local sum entry
  [[ -f "${units_manifest}" ]] || return 0
  while read -r sum entry; do
    if [[ "${entry}" == "$1" && "${sum}" =~ ^[0-9a-f]{64}$ ]]; then
      printf '%s\n' "${sum}"
      return 0
    fi
  done < "${units_manifest}"
}

# is_legacy_unit NAME SUM succeeds if SUM is a version of NAME shipped before
# units_manifest existed.
is_legacy_unit() {
  local entry
  for entry in "${legacy_unit_sums[@]}"; do
    if [[ "${entry}" == "$2  $1" ]]; then
      return 0
    fi
  done
  return 1
}

# unit_pending NAME [SUM] succeeds if a stopped run left NAME on record, with
# the checksum SUM if one is given. Malformed lines do not count, so damage to
# the file can only make a unit look edited, which keeps it.
unit_pending() {
  local sum entry
  [[ -f "${units_pending}" ]] || return 1
  while read -r sum entry; do
    if [[ "${entry}" == "$1" && "${sum}" =~ ^[0-9a-f]{64}$ ]] \
      && [[ $# -lt 2 || "${sum}" == "$2" ]]; then
      return 0
    fi
  done < "${units_pending}"
  return 1
}

# install_unit NAME SUM installs the shipped NAME, whose checksum is SUM. The
# record comes first: at no point is a shipped version in place unrecorded.
install_unit() {
  printf '%s  %s\n' "$2" "$1" >> "${units_pending}"
  install -m 0644 -o root -g root "${script_dir}/systemd/$1" "${systemd_dir}/$1"
}

# clear_pending_units forgets the record once nothing of it is due any more.
clear_pending_units() {
  rm -f "${units_pending}"
}

# warn_kept_unit NAME REASON says that a unit was kept and how to look at it.
warn_kept_unit() {
  local shipped="${script_dir}/systemd/$1" target="${systemd_dir}/$1"
  echo "install.sh: warning: ${target} $2; keeping it, shipped changes to it do not apply" >&2
  echo "install.sh:   compare: diff -u ${shipped} ${target}" >&2
  echo "install.sh:   to take the shipped version, remove the file and run install.sh again" >&2
}

# refresh_units installs what is absent and replaces what is unedited, then
# rewrites units_manifest. A kept unit keeps its old record (or none): were
# its current checksum recorded, the next upgrade would overwrite the edit.
# An install that stops at any point is safe: units_pending names the versions
# it wrote, so the next run takes them for unedited, whichever tarball it uses,
# and makes the restarts that are still due.
refresh_units() {
  local name shipped target shipped_sum stored_sum current_sum record manifest_lines=""
  for name in "${tarball_units[@]}"; do
    shipped="${script_dir}/systemd/${name}"
    target="${systemd_dir}/${name}"
    shipped_sum=$(sha256sum "${shipped}" | cut -d' ' -f1)
    stored_sum=$(stored_unit_sum "${name}")
    record="${shipped_sum}"
    if [[ -e "${target}" || -L "${target}" ]]; then
      if [[ -L "${target}" || ! -f "${target}" ]]; then
        # A symlink (systemctl mask, a unit kept elsewhere) or something
        # stranger is a decision, whatever it points at.
        warn_kept_unit "${name}" "is not a regular file"
        record="${stored_sum}"
      else
        current_sum=$(sha256sum "${target}" | cut -d' ' -f1)
        if [[ "${current_sum}" == "${shipped_sum}" ]]; then
          # Up to date; recording it also adopts it on a pre-manifest host. A
          # stopped run may have left the restart for it to this one.
          if unit_pending "${name}"; then
            refreshed_units+=("${name}")
          fi
        elif [[ "${current_sum}" == "${stored_sum}" ]] \
          || { [[ -z "${stored_sum}" ]] && is_legacy_unit "${name}" "${current_sum}"; } \
          || unit_pending "${name}" "${current_sum}"; then
          install_unit "${name}" "${shipped_sum}"
          refreshed_units+=("${name}")
          echo "install.sh: updated ${target} to the shipped version"
        else
          warn_kept_unit "${name}" "differs from the version Nebula installed"
          record="${stored_sum}"
        fi
      fi
    else
      install_unit "${name}" "${shipped_sum}"
    fi
    if [[ -n "${record}" ]]; then
      manifest_lines+="${record}  ${name}"$'\n'
    fi
    # Enable it whether or not it was just installed: a re-run after an
    # aborted install must still enable the units, not only the ones whose
    # file is absent.
    enable_units+=("${name}")
  done
  # Same directory, so the rename is atomic; root-owned, so nobody else can
  # plant a file here.
  tmp_units_manifest=$(mktemp "${units_manifest}.XXXXXX")
  trap 'rm -f "${tmp_units_manifest}"' EXIT
  printf '%s' "${manifest_lines}" > "${tmp_units_manifest}"
  chmod 0644 "${tmp_units_manifest}"
  mv -fT "${tmp_units_manifest}" "${units_manifest}"
  trap - EXIT
}

# unit_refreshed NAME succeeds if refresh_units replaced NAME.
unit_refreshed() {
  local name
  for name in "${refreshed_units[@]}"; do
    if [[ "${name}" == "$1" ]]; then
      return 0
    fi
  done
  return 1
}
# end: unit refresh

# begin: select units
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
  refresh_units
fi
# end: select units

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
# begin: start units
systemctl daemon-reload

# unit_masked NAME succeeds if systemd reports NAME as masked: a link to
# /dev/null or an empty file, in /etc or under /run. Masking is the admin's
# decision, and systemctl enable and restart both fail on such a unit, which
# under set -e would abort the install before the steps that are still due.
unit_masked() {
  local state
  state=$(systemctl is-enabled "$1" 2>/dev/null) || true
  [[ "${state}" == "masked" || "${state}" == "masked-runtime" ]]
}

# masked_target NAME prints the unit that the path or timer unit NAME starts
# if that unit is masked, nothing otherwise. systemd refuses to start such a
# trigger, and to restart it once stopped, so it is treated like a masked unit.
# Triggers is what systemd resolved, so Unit= in a drop-in counts as well.
masked_target() {
  local target
  [[ "$1" == *.path || "$1" == *.timer ]] || return 0
  for target in $(systemctl show --property=Triggers --value "$1" 2>/dev/null); do
    if unit_masked "${target}"; then
      printf '%s\n' "${target}"
      return 0
    fi
  done
}

for name in "${enable_units[@]}"; do
  # nebula-discovery.service is started by its path unit and timer and has
  # no [Install] section, so it is not enabled.
  if [[ "${name}" == "nebula-discovery.service" ]]; then
    continue
  fi
  if unit_masked "${name}"; then
    echo "install.sh: warning: ${name} is masked; not enabling or starting it (undo: systemctl unmask ${name})" >&2
    continue
  fi
  masked=$(masked_target "${name}")
  if [[ -n "${masked}" ]]; then
    echo "install.sh: warning: ${name} starts ${masked}, which is masked; not enabling or starting it (undo: systemctl unmask ${masked}, then run install.sh again)" >&2
    continue
  fi
  # The executor is enabled here (before the discovery units) so its boot
  # start does not depend on the server's Wants=, but it is started or
  # restarted below, where the drop-in-aware handling lives.
  if [[ "${name}" == "nebula-executor.service" ]]; then
    systemctl enable "${name}"
  else
    systemctl enable --now "${name}"
  fi
done

if ! unit_masked nebula-server.service \
  && systemctl is-active --quiet nebula-server.service \
  && { [[ ${bin_changed} -eq 1 || ${server_drop_in_changed} -eq 1 ]] || unit_refreshed nebula-server.service; }; then
  systemctl restart nebula-server.service
  echo "install.sh: restarted nebula-server (binaries, unit or drop-in changed)"
fi

if unit_masked nebula-executor.service; then
  : # Warned about above: a masked unit is neither started nor restarted.
elif systemctl is-active --quiet nebula-executor.service; then
  if [[ ${bin_changed} -eq 1 || ${drop_in_changed} -eq 1 ]] || unit_refreshed nebula-executor.service; then
    # Running with old binaries or an old drop-in: apply the new ones.
    systemctl restart nebula-executor.service
    echo "install.sh: restarted nebula-executor (binaries, unit or drop-in changed)"
  fi
else
  # Not active: a fresh install (the server's Wants= did not start it, or
  # it is a new host) or an earlier install whose executor did not start.
  # It is already enabled (in the loop above, or from a previous run);
  # start it now that the drop-in is in place.
  systemctl restart nebula-executor.service
  echo "install.sh: started nebula-executor (was not active)"
fi

# The other replaced units: try-restart touches only what is running. The
# server and the executor were handled above. nebula-discovery.service is a
# oneshot: its next run uses the new unit, and a restart would kill a scan.
# The install itself is done by now, so a failure here warns.
for name in "${refreshed_units[@]}"; do
  case "${name}" in
    nebula-server.service|nebula-executor.service|nebula-discovery.service) ;;
    *)
      # Warned about above: the stop would work, the start would be refused.
      if [[ -n "$(masked_target "${name}")" ]]; then
        continue
      fi
      systemctl try-restart "${name}" \
        || echo "install.sh: warning: could not restart ${name}; check: systemctl status ${name}" >&2
      ;;
  esac
done

# Everything a stopped run left is done. A package run looked at no unit.
if [[ ${from_package} -eq 0 ]]; then
  clear_pending_units
fi
# end: start units

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
