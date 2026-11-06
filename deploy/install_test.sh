#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Argument-parsing and validation tests for deploy/install.sh.
#
# Every case runs install.sh in dry-run mode (NEBULA_INSTALL_DRY_RUN=1),
# which parses and validates the options and exits before touching the
# system, so no root is needed. Run it from anywhere:
#
#   ./deploy/install_test.sh
#
# The last cases run the real scripts (unit recovery and server.json
# handling on install, drop-in handling on uninstall) and are therefore
# gated on root plus a running systemd; they are skipped with a message
# everywhere else.
#
# Exit status: 0 if all cases pass, 1 otherwise.

set -u

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
install_sh="${script_dir}/install.sh"

if [[ ! -f "$install_sh" ]]; then
  echo "install_test.sh: ${install_sh} not found" >&2
  exit 1
fi

pass=0
fail=0

# run_rc <want_rc> <name> -- <args...>
# Runs install.sh in dry-run mode and checks the exit status.
run_rc() {
  local want="$1" name="$2"
  shift 2
  if [[ "${1:-}" == "--" ]]; then
    shift
  fi
  local out rc
  out=$(NEBULA_INSTALL_DRY_RUN=1 bash "$install_sh" "$@" 2>&1)
  rc=$?
  if [[ "$rc" -eq "$want" ]]; then
    echo "ok   ${name}"
    pass=$((pass + 1))
  else
    echo "FAIL ${name}: exit ${rc}, want ${want}"
    printf '%s\n' "$out" | sed 's/^/     /'
    fail=$((fail + 1))
  fi
}

# run_msg <want_rc> <name> <substring> -- <args...>
# Like run_rc, but also requires the output to contain <substring>. Used to
# prove which check rejected an input (pattern vs. unknown user).
run_msg() {
  local want="$1" name="$2" want_msg="$3"
  shift 3
  if [[ "${1:-}" == "--" ]]; then
    shift
  fi
  local out rc
  out=$(NEBULA_INSTALL_DRY_RUN=1 bash "$install_sh" "$@" 2>&1)
  rc=$?
  if [[ "$rc" -eq "$want" && "$out" == *"$want_msg"* ]]; then
    echo "ok   ${name}"
    pass=$((pass + 1))
  else
    echo "FAIL ${name}: exit ${rc}, want ${want} with message containing ${want_msg}"
    printf '%s\n' "$out" | sed 's/^/     /'
    fail=$((fail + 1))
  fi
}

# A real, non-reserved local user for the valid cases.
test_user=""
for u in "${SUDO_USER:-}" "${USER:-}" daemon nobody; do
  if [[ -n "$u" && "$u" != "root" ]] && getent passwd "$u" >/dev/null; then
    case "$u" in
      nebula-server|nebula-executor) ;;
      *) test_user="$u"; break ;;
    esac
  fi
done
if [[ -z "$test_user" ]]; then
  echo "install_test.sh: no suitable non-root local user found" >&2
  exit 1
fi
echo "# using local user: ${test_user}"

# --- Argument parsing: missing or unknown options exit 2 with usage --------
out=$(NEBULA_INSTALL_DRY_RUN=1 bash "$install_sh" 2>&1)
rc=$?
if [[ "$rc" -eq 2 && "$out" == *"Usage:"* ]]; then
  echo "ok   no options: exit 2 with usage"
  pass=$((pass + 1))
else
  echo "FAIL no options: exit ${rc}, want 2 with usage"
  printf '%s\n' "$out" | sed 's/^/     /'
  fail=$((fail + 1))
fi

run_rc 2 "only --admin-users" -- --admin-users "$test_user"
run_rc 2 "only --rp-id" -- --rp-id nebula.example.org
run_rc 2 "unknown option" -- --admin-users "$test_user" --rp-id nebula.example.org --bogus
run_rc 2 "--admin-users without value" -- --admin-users
run_rc 2 "--rp-id without value" -- --rp-id
run_rc 0 "--help" -- --help

# --- Validation: bad values exit 1 (after parsing, before any change) ------
run_rc 1 "uppercase rp-id rejected" -- --admin-users "$test_user" --rp-id Nebula.example.org
run_rc 1 "underscore in rp-id rejected" -- --admin-users "$test_user" --rp-id nebula_example.org
run_rc 1 "leading hyphen in rp-id rejected" -- --admin-users "$test_user" --rp-id -bad.example.org
run_rc 1 "empty label in rp-id rejected" -- --admin-users "$test_user" --rp-id a..b
run_rc 1 "nonexistent admin user rejected" -- --admin-users definitely-not-a-user-12345 --rp-id nebula.example.org
run_rc 1 "root rejected as admin user" -- --admin-users root --rp-id nebula.example.org
run_rc 1 "nebula-server rejected as admin user" -- --admin-users nebula-server --rp-id nebula.example.org
run_rc 1 "nebula-pve-collector rejected as admin user" -- --admin-users nebula-pve-collector --rp-id nebula.example.org
run_rc 1 "empty entry in admin list rejected" -- --admin-users "${test_user},,${test_user}" --rp-id nebula.example.org
run_rc 1 "second of two users missing" -- --admin-users "$test_user,definitely-not-a-user-12345" --rp-id nebula.example.org

# Admin entries must match ^[a-z_][a-z0-9_-]{0,31}$: no numeric UIDs (which
# getent would resolve), no '%' (which systemd expands in ExecStart), no
# uppercase, at most 32 characters.
run_msg 1 "numeric UID rejected by the pattern" "must match" -- --admin-users 1000 --rp-id nebula.example.org
run_msg 1 "root UID 0 rejected by the pattern" "must match" -- --admin-users 0 --rp-id nebula.example.org
run_msg 1 "percent sign rejected by the pattern" "must match" -- --admin-users '%' --rp-id nebula.example.org
run_msg 1 "uppercase admin user rejected by the pattern" "must match" -- --admin-users Alice --rp-id nebula.example.org
run_msg 1 "33-char admin user rejected by the pattern" "must match" -- --admin-users "$(printf 'a%.0s' {1..33})" --rp-id nebula.example.org
# A 32-char name passes the pattern and is rejected only because it does
# not exist: this pins the boundary at 32 characters.
run_msg 1 "32-char admin user passes the pattern" "does not exist" -- --admin-users "$(printf 'a%.0s' {1..32})" --rp-id nebula.example.org

# --- Valid options pass in dry-run mode -------------------------------------
run_rc 0 "valid single user" -- --admin-users "$test_user" --rp-id nebula.example.org
run_rc 0 "valid multi-label rp-id" -- --admin-users "$test_user" --rp-id sub.domain.example.org
run_rc 0 "valid single-label rp-id" -- --admin-users "$test_user" --rp-id nebula
run_rc 0 "equals-form options" -- "--admin-users=${test_user}" "--rp-id=nebula.example.org"

# --- Dry run changes nothing --------------------------------------------------
drop_in=/etc/systemd/system/nebula-executor.service.d/10-local.conf
before=""
if [[ -f "$drop_in" ]]; then
  before=$(sha256sum "$drop_in" | cut -d' ' -f1)
fi
NEBULA_INSTALL_DRY_RUN=1 bash "$install_sh" --admin-users "$test_user" --rp-id nebula.example.org >/dev/null 2>&1
after=""
if [[ -f "$drop_in" ]]; then
  after=$(sha256sum "$drop_in" | cut -d' ' -f1)
fi
if [[ "$before" == "$after" ]]; then
  echo "ok   dry run leaves the drop-in untouched"
  pass=$((pass + 1))
else
  echo "FAIL dry run changed the drop-in (before: ${before:-absent}, after: ${after:-absent})"
  fail=$((fail + 1))
fi

# --- Live handoff provisioning (static) ---------------------------------------
# The server writes only requests/ and reads only live/; the collector owns
# both. The modes match internal/pvecollect/live_spool.go.
# check_line <name> <file> <exact line>
check_line() {
  if grep -qxF -- "$3" "$2"; then
    echo "ok   $1"
    pass=$((pass + 1))
  else
    echo "FAIL $1: line not found in $2: $3"
    fail=$((fail + 1))
  fi
}
check_line "install.sh provisions pve/requests 2770" "$install_sh" \
  'install -d -m 2770 -o nebula-pve-collector -g nebula-rpc "${var_lib}/pve/requests"'
check_line "install.sh provisions pve/live 2750" "$install_sh" \
  'install -d -m 2750 -o nebula-pve-collector -g nebula-rpc "${var_lib}/pve/live"'
check_line "install.sh provisions pve/guestnet 2770" "$install_sh" \
  'install -d -m 2770 -o nebula-pve-collector -g nebula-rpc "${var_lib}/pve/guestnet"'
# The server drop-in grants exactly the discovery jobs and pve/requests;
# the server unit itself grants no write path.
rw=$(grep '^ReadWritePaths=' "$install_sh" | tr '\n' ' ')
if [[ "$rw" == 'ReadWritePaths=${var_lib}/discovery/jobs ReadWritePaths=${var_lib}/pve/requests ' ]]; then
  echo "ok   server drop-in may write only discovery/jobs and pve/requests"
  pass=$((pass + 1))
else
  echo "FAIL server drop-in ReadWritePaths: ${rw:-none}"
  fail=$((fail + 1))
fi
if ! grep -q '^ReadWritePaths=' "${script_dir}/systemd/nebula-server.service"; then
  echo "ok   server unit grants no write path itself"
  pass=$((pass + 1))
else
  echo "FAIL server unit has a ReadWritePaths line"
  fail=$((fail + 1))
fi

# --- Explicit unit list (WA-04) ----------------------------------------------
# install.sh must install and enable an explicit list of units, not a glob of
# deploy/systemd/. The iconfetch units are not provisioned by this install:
# the icon service is not wired into the server yet, and
# nebula-iconfetch-firewall.service's ExecStart needs
# /etc/nebula/nebula-iconfetch.nft, which nothing creates. Enabling one of
# them under set -e could abort install.sh before nebula-server, the
# collector or the executor are enabled. So the list must be explicit, must
# contain no iconfetch unit, and must match exactly the units the install
# provisions (the non-iconfetch units in deploy/systemd/).
if grep -q 'systemd/\*\.service' "$install_sh"; then
  echo "FAIL install.sh still globs the systemd directory"
  fail=$((fail + 1))
else
  echo "ok   install.sh does not glob the systemd directory"
  pass=$((pass + 1))
fi
# Extract the explicit tarball unit list (one unit per line between the
# 'tarball_units=(' line and the closing ')').
tarball_list=$(awk '/^tarball_units=\(/{f=1;next} f&&/^\)/{exit} f{gsub(/^[[:space:]]+/,"");gsub(/[[:space:]]+$/,"");if(length($0))print}' "$install_sh")
if printf '%s\n' "$tarball_list" | grep -q iconfetch; then
  echo "FAIL the explicit unit list contains an iconfetch unit"
  fail=$((fail + 1))
else
  echo "ok   the explicit unit list has no iconfetch unit"
  pass=$((pass + 1))
fi
# The list must be exactly the set of non-iconfetch units shipped in
# deploy/systemd/ (order-insensitive). This fails if a provisioned unit is
# missing from the list or an unprovisioned (iconfetch) unit is added.
dir_units=$(find "${script_dir}/systemd" -maxdepth 1 -type f \( -name '*.service' -o -name '*.path' -o -name '*.timer' \) ! -name '*iconfetch*' -printf '%f\n' | sort)
list_units=$(printf '%s\n' "$tarball_list" | sort)
if [[ -n "$tarball_list" && "$dir_units" == "$list_units" ]]; then
  echo "ok   the explicit unit list matches the provisioned units (no iconfetch)"
  pass=$((pass + 1))
else
  echo "FAIL the explicit unit list does not match the provisioned units"
  echo "     list:";      printf '%s\n' "$list_units" | sed 's/^/       /'
  echo "     directory (non-iconfetch):"; printf '%s\n' "$dir_units" | sed 's/^/       /'
  fail=$((fail + 1))
fi

# --- Root-gated: real runs of install.sh and uninstall.sh -------------------
# These two cases exercise the systemd handling, which the dry-run mode
# exits before reaching. They need root and a running systemd; the first
# also needs the release-tarball layout (binaries next to deploy/). They
# are skipped with a message everywhere else.
uninstall_sh="${script_dir}/uninstall.sh"
systemd_root=0
if [[ ${EUID} -eq 0 ]] && [[ -d /run/systemd/system ]]; then
  systemd_root=1
fi

if [[ ${systemd_root} -eq 1 ]] && [[ -f "$(dirname -- "$script_dir")/nebula-executor" ]]; then
  # Leave the unit in place, as an earlier install would have, but not
  # active, so install.sh must take the recovery branch.
  if [[ ! -e /etc/systemd/system/nebula-executor.service ]]; then
    install -m 0644 "${script_dir}/systemd/nebula-executor.service" /etc/systemd/system/
  fi
  systemctl stop nebula-executor 2>/dev/null || true
  # Reuse the rp-id the host already has, so the test does not change the
  # origin of a live install.
  rp="lab.local"
  if [[ -f /etc/systemd/system/nebula-executor.service.d/10-local.conf ]]; then
    rp=$(sed -n 's/.*-rp-id \([^ ]*\).*/\1/p' /etc/systemd/system/nebula-executor.service.d/10-local.conf | head -n 1)
  fi
  rp="${rp:-lab.local}"
  out=$(bash "$install_sh" --admin-users "$test_user" --rp-id "$rp" 2>&1)
  rc=$?
  for _ in 1 2 3 4 5; do
    systemctl is-active --quiet nebula-executor.service && break
    sleep 1
  done
  if [[ $rc -eq 0 && "$out" == *"enabled and restarted nebula-executor (was not active)"* ]] \
     && systemctl is-active --quiet nebula-executor.service; then
    echo "ok   inactive unit enabled and restarted"
    pass=$((pass + 1))
  else
    echo "FAIL inactive unit recovery: exit ${rc}"
    printf '%s\n' "$out" | sed 's/^/     /'
    fail=$((fail + 1))
  fi
else
  echo "skip inactive-unit recovery (needs root, systemd and the tarball layout)"
fi

# --- Root-gated: server.json handling ----------------------------------------
# install.sh writes /etc/nebula/server.json only if it does not exist yet
# (valid JSON, this host's public origin, mode 0640) and never overwrites
# it afterwards.
server_json=/etc/nebula/server.json
if [[ ${systemd_root} -eq 1 ]] && [[ -f "$(dirname -- "$script_dir")/nebula-executor" ]]; then
  # Reuse the rp-id the host already has, so the test does not change the
  # origin of a live install.
  rp="lab.local"
  if [[ -f /etc/systemd/system/nebula-executor.service.d/10-local.conf ]]; then
    rp=$(sed -n 's/.*-rp-id \([^ ]*\).*/\1/p' /etc/systemd/system/nebula-executor.service.d/10-local.conf | head -n 1)
  fi
  rp="${rp:-lab.local}"
  had_server_json=0
  if [[ -f "$server_json" ]]; then
    had_server_json=1
  fi
  bash "$install_sh" --admin-users "$test_user" --rp-id "$rp" >/dev/null 2>&1
  if [[ ${had_server_json} -eq 0 ]]; then
    # First install: the file must be created, valid, with the right
    # origin and mode.
    ok_case=1
    if [[ ! -f "$server_json" ]]; then
      echo "FAIL install did not create ${server_json}"
      ok_case=0
    elif ! python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$server_json" 2>/dev/null; then
      echo "FAIL ${server_json} is not valid JSON"
      ok_case=0
    elif ! grep -q "\"public_origin\": \"https://${rp}\"" "$server_json"; then
      echo "FAIL server.json public_origin is not https://${rp}"
      ok_case=0
    elif [[ $(stat -c '%a' "$server_json") != "640" ]]; then
      echo "FAIL server.json mode is $(stat -c '%a' "$server_json"), want 640"
      ok_case=0
    fi
    if [[ ${ok_case} -eq 1 ]]; then
      echo "ok   install creates a valid server.json (0640, right origin)"
      pass=$((pass + 1))
    else
      fail=$((fail + 1))
    fi
  fi
  # An existing server.json (for example one an admin edited by hand)
  # must survive a re-run: put a sentinel in place and re-run.
  if [[ -f "$server_json" ]]; then
    saved=$(mktemp)
    cp "$server_json" "$saved"
    printf 'SENTINEL\n' > "$server_json"
    bash "$install_sh" --admin-users "$test_user" --rp-id "$rp" >/dev/null 2>&1
    if grep -q SENTINEL "$server_json"; then
      echo "ok   install does not overwrite an existing server.json"
      pass=$((pass + 1))
    else
      echo "FAIL install overwrote the existing server.json"
      fail=$((fail + 1))
    fi
    cp "$saved" "$server_json"
    rm -f "$saved"
  fi
else
  echo "skip server.json cases (needs root, systemd and the tarball layout)"
fi

if [[ ${systemd_root} -eq 1 ]]; then
  # uninstall.sh also removes the units and binaries; on a test machine
  # that is the intended end state.
  drop_dir=/etc/systemd/system/nebula-executor.service.d
  mkdir -p "$drop_dir"
  printf '[Service]\nEnvironment=INSTALL_TEST=1\n' > "$drop_dir/10-local.conf"
  printf '[Service]\nEnvironment=KEEP=1\n' > "$drop_dir/20-local.conf"
  bash "$uninstall_sh" >/dev/null 2>&1
  if [[ ! -f "$drop_dir/10-local.conf" && -f "$drop_dir/20-local.conf" && -d "$drop_dir" ]]; then
    echo "ok   uninstall preserves other drop-ins"
    pass=$((pass + 1))
  else
    echo "FAIL uninstall did not preserve other drop-ins"
    fail=$((fail + 1))
  fi
  # With only the install.sh drop-in left, the directory must go away.
  rm -f "$drop_dir/20-local.conf"
  printf '[Service]\nEnvironment=INSTALL_TEST=1\n' > "$drop_dir/10-local.conf"
  bash "$uninstall_sh" >/dev/null 2>&1
  if [[ ! -d "$drop_dir" ]]; then
    echo "ok   uninstall removes an empty drop-in directory"
    pass=$((pass + 1))
  else
    echo "FAIL drop-in directory not removed when empty"
    fail=$((fail + 1))
  fi
else
  echo "skip uninstall drop-in cases (needs root and systemd)"
fi

echo
echo "install_test.sh: ${pass} passed, ${fail} failed"
if [[ "$fail" -gt 0 ]]; then
  exit 1
fi
