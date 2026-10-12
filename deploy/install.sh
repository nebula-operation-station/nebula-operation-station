#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Install Nebula Operation Station from a release tarball on Debian 12
# (also works on Ubuntu 22.04/24.04). Run it from the extracted tarball:
#
#   sudo ./deploy/install.sh
#
# The script is idempotent: re-running it updates the binaries but never
# overwrites unit files you have edited, and never touches the data
# directories. New units are enabled and started; the executor comes up
# locked and must be reviewed (see the next steps it prints) before it
# is useful.

set -euo pipefail

# --- Refuse to run without root -------------------------------------------
if [[ ${EUID} -ne 0 ]]; then
  echo "install.sh: must be run as root (try: sudo ./deploy/install.sh)" >&2
  exit 1
fi

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
tarball_root=$(dirname -- "$script_dir")

bin_dir=/usr/bin
systemd_dir=/etc/systemd/system
var_lib=/var/lib/nebula
group_name=nebula-rpc

# --- Check the tarball layout ---------------------------------------------
for bin in nebula nebula-server nebula-executor; do
  if [[ ! -f "${tarball_root}/${bin}" ]]; then
    echo "install.sh: ${tarball_root}/${bin} not found" >&2
    echo "install.sh: run this script from the extracted release tarball" >&2
    exit 1
  fi
done
if [[ ! -d "${script_dir}/systemd" ]]; then
  echo "install.sh: ${script_dir}/systemd not found; is this a release tarball?" >&2
  exit 1
fi

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

# --- Directories (modes from docs/spec/03) ---------------------------------
# The executor refuses to start unless its data dir is 0700
# (internal/fsguard); the server dir must not be world-readable because
# it will hold the server database.
install -d -m 0755 -o root -g root "${var_lib}"
install -d -m 0750 -o nebula-server -g nebula-server "${var_lib}/server"
install -d -m 0700 -o nebula-executor -g nebula-executor "${var_lib}/executor"

# --- Binaries (idempotent: replaced on every run) --------------------------
for bin in nebula nebula-server nebula-executor; do
  install -m 0755 -o root -g root "${tarball_root}/${bin}" "${bin_dir}/${bin}"
done

# --- Units (installed only if absent: never clobber admin edits) -----------
shopt -s nullglob
installed_units=()
for unit in "${script_dir}"/systemd/*.service; do
  name=$(basename -- "${unit}")
  if [[ -e "${systemd_dir}/${name}" ]]; then
    echo "install.sh: ${systemd_dir}/${name} already exists; leaving it untouched"
  else
    install -m 0644 -o root -g root "${unit}" "${systemd_dir}/${name}"
    installed_units+=("${name}")
  fi
done
shopt -u nullglob

if [[ ${#installed_units[@]} -gt 0 ]]; then
  systemctl daemon-reload
  for name in "${installed_units[@]}"; do
    systemctl enable --now "${name}"
  done
fi

# --- Next steps --------------------------------------------------------------
cat <<EOF

Nebula Operation Station installed. Next steps:

  1. Review the executor unit before relying on it:
       sudoedit ${systemd_dir}/nebula-executor.service
     Set -admin-users (your admin account(s), comma separated), -rp-id
     (your public hostname) and -origin (https://<your public hostname>).
     Then: systemctl daemon-reload && systemctl restart nebula-executor

  2. Create the SSH key for the managed hosts (passphrase from your
     password manager):
       sudo -u nebula-executor mkdir -p ${var_lib}/executor/keys
       sudo -u nebula-executor ssh-keygen -t ed25519 -C nebula-default \\
         -f ${var_lib}/executor/keys/nebula-default.key

  3. Unlock the executor (it starts locked after every restart):
       nebula unlock

  4. Check the status:
       nebula status
EOF
