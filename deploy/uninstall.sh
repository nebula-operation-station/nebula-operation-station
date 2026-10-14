#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Remove the Nebula Operation Station binaries and units installed by
# deploy/install.sh. Run it from the extracted release tarball:
#
#   sudo ./deploy/uninstall.sh
#
# Deliberately conservative: it stops and removes the units and the
# binaries, but leaves the system users, group, the data directories
# (/var/lib/nebula) and the server configuration (/etc/nebula) in
# place. Back up the databases and keys first if you want to keep them
# (docs/spec/15); remove them manually afterwards if you really want a
# clean slate:
#
#   sudo rm -rf /var/lib/nebula /etc/nebula
#   sudo userdel nebula-server
#   sudo userdel nebula-executor
#   sudo groupdel nebula-rpc

set -euo pipefail

# --- Refuse to run without root -------------------------------------------
if [[ ${EUID} -ne 0 ]]; then
  echo "uninstall.sh: must be run as root (try: sudo ./deploy/uninstall.sh)" >&2
  exit 1
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
systemd_dir=/etc/systemd/system
bin_dir=/usr/bin

# --- Stop and remove the units ----------------------------------------------
shopt -s nullglob
removed_units=0
for unit in "${script_dir}"/systemd/*.service; do
  name=$(basename -- "${unit}")
  if [[ -e "${systemd_dir}/${name}" ]]; then
    systemctl stop "${name}" 2>/dev/null || true
    systemctl disable "${name}" 2>/dev/null || true
    rm -f -- "${systemd_dir}/${name}"
    removed_units=1
  fi
done
shopt -u nullglob

# Remove only the drop-in written by install.sh. Other drop-ins in the
# directory (for example a 20-local.conf with local flag changes) are
# left in place, and the directory is removed only if it is then empty.
drop_in_removed=0
drop_in_dir="${systemd_dir}/nebula-executor.service.d"
if [[ -f "${drop_in_dir}/10-local.conf" ]]; then
  rm -f -- "${drop_in_dir}/10-local.conf"
  drop_in_removed=1
fi
if [[ -d "${drop_in_dir}" && -z "$(ls -A -- "${drop_in_dir}")" ]]; then
  rmdir -- "${drop_in_dir}"
fi

if [[ ${removed_units} -eq 1 || ${drop_in_removed} -eq 1 ]]; then
  systemctl daemon-reload
fi

# --- Remove the binaries ------------------------------------------------------
for bin in nebula nebula-server nebula-executor; do
  if [[ -e "${bin_dir}/${bin}" ]]; then
    rm -f -- "${bin_dir}/${bin}"
  fi
done

echo "Nebula Operation Station binaries and units removed."
echo "The users (nebula-server, nebula-executor), the group (nebula-rpc),"
echo "the data directories under /var/lib/nebula and the server"
echo "configuration under /etc/nebula were left in place."
echo "See the header of this script for manual cleanup."
