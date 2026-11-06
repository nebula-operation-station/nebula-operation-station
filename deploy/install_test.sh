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
# The unit refresh cases run the real refresh block of install.sh in a
# temporary directory, which needs no root either. The last cases run the
# real scripts (unit recovery and server.json handling on install, drop-in
# handling on uninstall) and are therefore gated on root plus a running
# systemd; they are skipped with a message everywhere else.
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
# collector or the executor are enabled.
#
# The checks are order-sensitive and cover both the tarball list and the
# --from-package list, and that the install/enable loops actually use them,
# so a *.path/*.timer glob, a discovery-first ordering, or an iconfetch
# unit in either list all fail.
if grep -Eq 'systemd/\*\.(service|path|timer)' "$install_sh"; then
  echo "FAIL install.sh still globs the systemd directory"
  fail=$((fail + 1))
else
  echo "ok   install.sh does not glob the systemd directory"
  pass=$((pass + 1))
fi
# Extract an explicit unit list (one unit per line between the '<name>=('
# line and the closing ')').
tarball_list=$(awk '/^tarball_units=\(/{f=1;next} f&&/^\)/{exit} f{gsub(/^[[:space:]]+/,"");gsub(/[[:space:]]+$/,"");if(length($0))print}' "$install_sh")
package_list=$(awk '/^package_units=\(/{f=1;next} f&&/^\)/{exit} f{gsub(/^[[:space:]]+/,"");gsub(/[[:space:]]+$/,"");if(length($0))print}' "$install_sh")
# The tarball list must be exactly the provisioned units, in this order:
# the server, executor and collector come before the discovery units so a
# failing discovery unit cannot abort the install before they are enabled.
expected_tarball=$'nebula-server.service\nnebula-executor.service\nnebula-pve-collector.service\nnebula-discovery.path\nnebula-discovery.service\nnebula-discovery.timer'
if [[ "$tarball_list" == "$expected_tarball" ]]; then
  echo "ok   tarball unit list is exact and ordered (server/executor/collector before discovery)"
  pass=$((pass + 1))
else
  echo "FAIL the tarball unit list is not the expected ordered list"
  echo "     got:";      printf '%s\n' "$tarball_list" | sed 's/^/       /'
  echo "     expected:"; printf '%s\n' "$expected_tarball" | sed 's/^/       /'
  fail=$((fail + 1))
fi
# The --from-package list must be exactly the installable units (no
# nebula-discovery.service, which has no [Install] section), with the
# collector before the discovery units.
expected_package=$'nebula-server.service\nnebula-executor.service\nnebula-pve-collector.service\nnebula-discovery.path\nnebula-discovery.timer'
if [[ "$package_list" == "$expected_package" ]]; then
  echo "ok   package unit list is exact and ordered (collector before discovery, no discovery.service)"
  pass=$((pass + 1))
else
  echo "FAIL the --from-package unit list is not the expected ordered list"
  echo "     got:";      printf '%s\n' "$package_list" | sed 's/^/       /'
  echo "     expected:"; printf '%s\n' "$expected_package" | sed 's/^/       /'
  fail=$((fail + 1))
fi
# Neither list may contain an iconfetch unit.
if printf '%s\n%s\n' "$tarball_list" "$package_list" | grep -q iconfetch; then
  echo "FAIL a unit list contains an iconfetch unit"
  fail=$((fail + 1))
else
  echo "ok   neither unit list contains an iconfetch unit"
  pass=$((pass + 1))
fi
# The install loops must actually use the explicit lists, not a hardcoded
# word list or a glob.
if grep -qF 'for name in "${tarball_units[@]}"; do' "$install_sh"; then
  echo "ok   the tarball install loop uses tarball_units"
  pass=$((pass + 1))
else
  echo "FAIL the tarball install loop does not iterate over tarball_units"
  fail=$((fail + 1))
fi
if grep -qF 'for name in "${package_units[@]}"; do' "$install_sh"; then
  echo "ok   the package install loop uses package_units"
  pass=$((pass + 1))
else
  echo "FAIL the --from-package install loop does not iterate over package_units"
  fail=$((fail + 1))
fi
# The enable loop must enable the executor (not skip it), so that a failing
# discovery unit later in the list cannot abort the install before the
# executor is enabled. The old code skipped the executor in the loop and
# enabled it only after the loop.
enable_loop=$(awk '/for name in/ && /enable_units/{f=1} f{print} f&&/^done$/{exit}' "$install_sh")
if printf '%s\n' "$enable_loop" | grep -qF '!= "nebula-executor.service"'; then
  echo "FAIL the enable loop still skips nebula-executor.service"
  fail=$((fail + 1))
else
  echo "ok   the enable loop does not skip nebula-executor.service"
  pass=$((pass + 1))
fi
# The tarball branch must enable every provisioned unit whether or not it was
# just installed: a re-run after an aborted install (which copies all the
# units first) must still enable them, not only the ones whose file is
# absent. The append to enable_units must sit at the loop-body level (same
# indent as the 'if [[ -e' line), not inside the install if/else.
tu_if_indent=$(awk '/for name in "\$\{tarball_units\[@\]\}"; do/{f=1} f&&/if \[\[ -e/{match($0,/^ */);print RLENGTH;exit} f&&/^  done$/{exit}' "$install_sh")
tu_append_indent=$(awk '/for name in "\$\{tarball_units\[@\]\}"; do/{f=1} f&&/enable_units\+=/{match($0,/^ */);print RLENGTH;exit} f&&/^  done$/{exit}' "$install_sh")
if [[ -n "$tu_append_indent" && -n "$tu_if_indent" && "$tu_append_indent" -le "$tu_if_indent" ]]; then
  echo "ok   the tarball branch enables every provisioned unit (re-run safe)"
  pass=$((pass + 1))
else
  echo "FAIL the tarball branch only enables units it just installed (re-run enables nothing)"
  fail=$((fail + 1))
fi
# A host upgraded from an earlier install still has the iconfetch units in
# /etc/systemd/system (possibly enabled). install.sh must disable and remove
# them, not just stop installing them.
if grep -qF 'for name in nebula-iconfetch.service nebula-iconfetch.path nebula-iconfetch.timer nebula-iconfetch-firewall.service' "$install_sh" \
   && grep -q 'systemctl disable --now' "$install_sh" \
   && grep -qE 'rm -f "\$\{systemd_dir\}/\$\{name\}"' "$install_sh"; then
  echo "ok   leftover iconfetch units are disabled and removed on upgrade"
  pass=$((pass + 1))
else
  echo "FAIL leftover iconfetch units are not disabled and removed on upgrade"
  fail=$((fail + 1))
fi

# --- Unit refresh (WA-09), functional, no root needed -------------------------
# Runs the real refresh block of install.sh against a sandbox: the paths point
# into a temporary directory and the only stub is `install`, which drops the
# -o/-g options so that no root is needed. Three cases carry the design: a
# unit nobody edited follows the shipped version, an edited one is never
# replaced, and a new one is installed.
refresh_block=$(sed -n '/^# begin: unit refresh/,/^# end: unit refresh/p' "$install_sh")
refresh_sb=$(mktemp -d)
trap 'rm -rf "$refresh_sb"' EXIT
mkdir -p "$refresh_sb/deploy/systemd" "$refresh_sb/etc" "$refresh_sb/var"

# ship <unit> <content>: this "tarball" now ships <content> for <unit>.
ship() {
  printf '%s\n' "$2" > "$refresh_sb/deploy/systemd/$1"
}
# sum_of <file>: the sha256 of a file.
sum_of() {
  sha256sum "$1" | cut -d' ' -f1
}
# text_sum <content>: the sha256 of ship's or an admin's file with <content>.
text_sum() {
  printf '%s\n' "$1" | sha256sum | cut -d' ' -f1
}
# reset_refresh: an empty host and an empty tarball.
reset_refresh() {
  rm -rf "$refresh_sb/etc" "$refresh_sb/var" "$refresh_sb/deploy/systemd"
  mkdir -p "$refresh_sb/deploy/systemd" "$refresh_sb/etc" "$refresh_sb/var"
}
# run_refresh [legacy line]: one install.sh unit step for the units in
# refresh_units_list, under set -e like the real script. The output (with
# stderr) lands in $refresh_out, the exit status in $refresh_rc. A legacy
# line replaces the embedded list of pre-manifest checksums.
refresh_units_list=(a.service b.service)
run_refresh() {
  local legacy="${1:-}"
  refresh_out=$(
    exec 2>&1
    set -euo pipefail
    install() { command install -m 0644 "${@: -2:1}" "${@: -1}"; }
    script_dir="$refresh_sb/deploy"
    systemd_dir="$refresh_sb/etc"
    var_lib="$refresh_sb/var"
    tarball_units=("${refresh_units_list[@]}")
    enable_units=()
    eval "$refresh_block"
    if [[ -n "$legacy" ]]; then
      legacy_unit_sums=("$legacy")
    fi
    refresh_units
    echo "ENABLE=${enable_units[*]}"
    echo "REFRESHED=${refreshed_units[*]:-}"
    echo "END"
  )
  refresh_rc=$?
}
# expect <name> <shell condition...>: pass if the condition holds.
expect() {
  local name="$1"
  shift
  if "$@"; then
    echo "ok   ${name}"
    pass=$((pass + 1))
  else
    echo "FAIL ${name}"
    printf '%s\n' "$refresh_out" | sed 's/^/     /'
    fail=$((fail + 1))
  fi
}
has_content() { [[ "$(cat "$1")" == "$2" ]]; }
out_has() { [[ "$refresh_out" == *"$1"* ]]; }
out_lacks() { [[ "$refresh_out" != *"$1"* ]]; }
manifest_has() { grep -qxF "$1  $2" "$refresh_sb/var/units.sha256"; }
manifest_lacks_unit() { ! grep -q " $1\$" "$refresh_sb/var/units.sha256"; }
manifest_lacks_sum() { ! grep -q "^$1 " "$refresh_sb/var/units.sha256"; }
rc_is() { [[ "$refresh_rc" -eq "$1" ]]; }

if [[ -z "$refresh_block" ]]; then
  echo "FAIL install.sh has no unit refresh block"
  fail=$((fail + 1))
else
  # Case 1: new units are installed and recorded.
  reset_refresh
  ship a.service 'A v1'
  ship b.service 'B v1'
  run_refresh
  expect "fresh install succeeds" rc_is 0
  expect "fresh install: a new unit is installed" has_content "$refresh_sb/etc/a.service" 'A v1'
  expect "fresh install: every unit is recorded" manifest_has "$(text_sum 'A v1')" a.service
  expect "fresh install: every unit is recorded (second)" manifest_has "$(text_sum 'B v1')" b.service
  expect "fresh install: every unit is enabled" out_has 'ENABLE=a.service b.service'
  if [[ $(stat -c '%a' "$refresh_sb/var/units.sha256") == "644" ]]; then
    echo "ok   the checksum file has mode 0644"
    pass=$((pass + 1))
  else
    echo "FAIL the checksum file has mode $(stat -c '%a' "$refresh_sb/var/units.sha256"), want 0644"
    fail=$((fail + 1))
  fi
  if [[ $(find "$refresh_sb/var" -type f | wc -l) -eq 1 ]]; then
    echo "ok   no temporary file is left next to the checksum file"
    pass=$((pass + 1))
  else
    echo "FAIL a temporary file was left next to the checksum file"
    fail=$((fail + 1))
  fi

  # Case 2: a re-run with nothing new changes nothing.
  run_refresh
  expect "unchanged unit: nothing is reported refreshed" out_has $'REFRESHED=\nEND'
  expect "unchanged unit: no warning" out_lacks 'warning'

  # Case 3: a shipped fix replaces a unit nobody edited.
  ship a.service 'A v2'
  run_refresh
  expect "unedited unit: the shipped fix arrives" has_content "$refresh_sb/etc/a.service" 'A v2'
  expect "unedited unit: reported as refreshed" out_has 'REFRESHED=a.service'
  expect "unedited unit: the new checksum is recorded" manifest_has "$(text_sum 'A v2')" a.service
  expect "unedited unit: the old checksum is gone" manifest_lacks_sum "$(text_sum 'A v1')"
  expect "unedited unit: still enabled" out_has 'ENABLE=a.service b.service'

  # Case 4: an edited unit is kept, the warning says how to compare, and
  # its checksum stays the shipped one: recording the edit would make the
  # next upgrade take it for an unedited unit and overwrite it.
  printf 'A admin edit\n' > "$refresh_sb/etc/a.service"
  ship a.service 'A v3'
  run_refresh
  expect "edited unit: the run succeeds" rc_is 0
  expect "edited unit: the admin's content is kept" has_content "$refresh_sb/etc/a.service" 'A admin edit'
  expect "edited unit: warned about" out_has "warning: $refresh_sb/etc/a.service"
  expect "edited unit: the warning has a diff hint" out_has "diff -u $refresh_sb/deploy/systemd/a.service $refresh_sb/etc/a.service"
  expect "edited unit: not reported as refreshed" out_has $'REFRESHED=\nEND'
  expect "edited unit: the edit is not recorded" manifest_lacks_sum "$(text_sum 'A admin edit')"
  expect "edited unit: the shipped baseline stays recorded" manifest_has "$(text_sum 'A v2')" a.service
  expect "edited unit: still enabled" out_has 'ENABLE=a.service b.service'
  # The same on every later upgrade, not only the first.
  ship a.service 'A v4'
  run_refresh
  expect "edited unit: kept again on the next upgrade" has_content "$refresh_sb/etc/a.service" 'A admin edit'
  # Back on the recorded version, the unit counts as unedited again.
  printf 'A v2\n' > "$refresh_sb/etc/a.service"
  run_refresh
  expect "reverted unit: the shipped version arrives again" has_content "$refresh_sb/etc/a.service" 'A v4'
  expect "reverted unit: the new checksum is recorded" manifest_has "$(text_sum 'A v4')" a.service

  # Case 5: a unit that is new in this version is installed on an upgrade.
  refresh_units_list=(a.service b.service c.service)
  ship c.service 'C v1'
  run_refresh
  expect "new unit on upgrade: installed" has_content "$refresh_sb/etc/c.service" 'C v1'
  expect "new unit on upgrade: recorded" manifest_has "$(text_sum 'C v1')" c.service
  refresh_units_list=(a.service b.service)

  # An admin who copied the shipped version in by hand made it unedited.
  printf 'A v9\n' > "$refresh_sb/etc/a.service"
  ship a.service 'A v9'
  run_refresh
  expect "unit already equal to the shipped one: recorded" manifest_has "$(text_sum 'A v9')" a.service

  # An install that stopped after replacing a unit, before writing the
  # checksum file, recovers on the next run.
  reset_refresh
  ship a.service 'A v1'
  ship b.service 'B v1'
  run_refresh
  ship a.service 'A v2'
  printf 'A v2\n' > "$refresh_sb/etc/a.service"
  run_refresh
  expect "interrupted upgrade: the checksum catches up" manifest_has "$(text_sum 'A v2')" a.service
  printf 'A later edit\n' > "$refresh_sb/etc/a.service"
  ship a.service 'A v3'
  run_refresh
  expect "interrupted upgrade: a later edit is still protected" has_content "$refresh_sb/etc/a.service" 'A later edit'

  # A host installed before the checksum file existed. Identical units are
  # adopted, a known older version is replaced, anything else counts as
  # edited and must never become a recorded baseline.
  reset_refresh
  ship a.service 'A v2'
  ship b.service 'B v2'
  printf 'A v2\n' > "$refresh_sb/etc/a.service"
  printf 'B v1\n' > "$refresh_sb/etc/b.service"
  run_refresh "$(text_sum 'B v1')  b.service"
  expect "pre-manifest host: an identical unit is adopted" manifest_has "$(text_sum 'A v2')" a.service
  expect "pre-manifest host: a known old version gets the shipped fix" has_content "$refresh_sb/etc/b.service" 'B v2'
  expect "pre-manifest host: the refreshed unit is recorded" manifest_has "$(text_sum 'B v2')" b.service

  reset_refresh
  ship a.service 'A v2'
  ship b.service 'B v2'
  printf 'A v2\n' > "$refresh_sb/etc/a.service"
  printf 'B admin edit\n' > "$refresh_sb/etc/b.service"
  run_refresh "$(text_sum 'B v1')  b.service"
  expect "pre-manifest host: an unknown unit is kept" has_content "$refresh_sb/etc/b.service" 'B admin edit'
  expect "pre-manifest host: an unknown unit is warned about" out_has "warning: $refresh_sb/etc/b.service"
  expect "pre-manifest host: an unknown unit is not recorded" manifest_lacks_unit b.service
  ship b.service 'B v3'
  run_refresh "$(text_sum 'B v1')  b.service"
  expect "pre-manifest host: still kept on the next upgrade" has_content "$refresh_sb/etc/b.service" 'B admin edit'
  expect "pre-manifest host: still not recorded" manifest_lacks_unit b.service

  # A known old version in another unit's name proves nothing.
  reset_refresh
  ship a.service 'A v2'
  ship b.service 'B v2'
  printf 'B v1\n' > "$refresh_sb/etc/a.service"
  run_refresh "$(text_sum 'B v1')  b.service"
  expect "legacy checksum of another unit does not match" has_content "$refresh_sb/etc/a.service" 'B v1'

  # Once a unit has a recorded baseline, the list of old versions no longer
  # applies: going back to one of them is an edit.
  reset_refresh
  ship a.service 'A v2'
  ship b.service 'B v1'
  run_refresh
  printf 'A v1\n' > "$refresh_sb/etc/a.service"
  ship a.service 'A v3'
  run_refresh "$(text_sum 'A v1')  a.service"
  expect "recorded baseline wins over the legacy list" has_content "$refresh_sb/etc/a.service" 'A v1'

  # A symlink is an admin's decision (systemctl mask, a unit kept elsewhere).
  # It is not followed and not replaced, even if the target looks unedited.
  reset_refresh
  ship a.service 'A v1'
  ship b.service 'B v1'
  run_refresh
  printf 'A v1\n' > "$refresh_sb/target"
  ln -sf "$refresh_sb/target" "$refresh_sb/etc/a.service"
  ln -sf /nonexistent/unit "$refresh_sb/etc/b.service"
  ship a.service 'A v2'
  ship b.service 'B v2'
  run_refresh
  if [[ -L "$refresh_sb/etc/a.service" ]] && has_content "$refresh_sb/target" 'A v1' && [[ -L "$refresh_sb/etc/b.service" ]]; then
    echo "ok   symlinked units are left in place"
    pass=$((pass + 1))
  else
    echo "FAIL a symlinked unit was replaced or followed"
    printf '%s\n' "$refresh_out" | sed 's/^/     /'
    fail=$((fail + 1))
  fi
  expect "symlinked unit: warned about" out_has "warning: $refresh_sb/etc/a.service"
  expect "symlinked unit: the recorded baseline stays" manifest_has "$(text_sum 'A v1')" a.service

  # A damaged checksum file cannot turn an edited unit into an unedited one.
  reset_refresh
  ship a.service 'A v1'
  ship b.service 'B v1'
  printf 'A admin edit\n' > "$refresh_sb/etc/a.service"
  printf 'not-a-checksum  a.service\n\nx\n' > "$refresh_sb/var/units.sha256"
  run_refresh
  expect "damaged checksum file: the run succeeds" rc_is 0
  expect "damaged checksum file: the unit is kept" has_content "$refresh_sb/etc/a.service" 'A admin edit'

  # An entry only counts for exactly the unit it names.
  reset_refresh
  ship a.service 'A v2'
  ship b.service 'B v1'
  printf 'A admin edit\n' > "$refresh_sb/etc/a.service"
  printf '%s  xa.service\n' "$(text_sum 'A admin edit')" > "$refresh_sb/var/units.sha256"
  run_refresh
  expect "checksum of a similarly named unit does not match" has_content "$refresh_sb/etc/a.service" 'A admin edit'

  # A tarball that lacks a listed unit stops the install.
  reset_refresh
  ship a.service 'A v1'
  run_refresh
  expect "missing shipped unit: the run fails" rc_is 1

  # The real list of pre-manifest checksums: the collector version without
  # RestartSec is in it, and the entries are well formed.
  legacy_list=$(awk '/^legacy_unit_sums=\(/{f=1;next} f&&/^\)/{exit} f{print}' "$install_sh")
  if printf '%s\n' "$legacy_list" | grep -qF '"cd452ec9eb40017e6ae6da044ef04034d8031f5137c7ed7b757c7039cde34f42  nebula-pve-collector.service"'; then
    echo "ok   the collector unit from before RestartSec is a known old version"
    pass=$((pass + 1))
  else
    echo "FAIL the collector unit from before RestartSec is not in legacy_unit_sums"
    fail=$((fail + 1))
  fi
  if [[ $(printf '%s\n' "$legacy_list" | wc -l) -ge 7 ]] \
     && ! printf '%s\n' "$legacy_list" | grep -qvE '^  "[0-9a-f]{64}  nebula-[a-z-]+\.(service|path|timer)"$'; then
    echo "ok   legacy_unit_sums holds well-formed entries for the shipped versions"
    pass=$((pass + 1))
  else
    echo "FAIL legacy_unit_sums is malformed"
    fail=$((fail + 1))
  fi
fi

# --- Unit refresh wiring in install.sh (static) -------------------------------
# refresh_units runs for tarball installs only: under --from-package the
# package manager owns the units in /lib/systemd/system. It runs before the
# daemon-reload, and a replaced unit reaches the services that are running.
call_line=$(grep -n '^  refresh_units$' "$install_sh" | cut -d: -f1)
package_branch=$(grep -n '^if \[\[ \${from_package} -eq 1 \]\]; then$' "$install_sh" | tail -n 1 | cut -d: -f1)
else_line=$(awk -v s="${package_branch:-0}" 'NR>s && /^else$/{print NR; exit}' "$install_sh")
reload_line=$(grep -n '^systemctl daemon-reload$' "$install_sh" | cut -d: -f1)
if [[ -n "$call_line" && -n "$else_line" && -n "$reload_line" && "$call_line" -gt "$else_line" && "$call_line" -lt "$reload_line" ]]; then
  echo "ok   refresh_units runs in the tarball branch, before the daemon-reload"
  pass=$((pass + 1))
else
  echo "FAIL refresh_units must run in the tarball branch, before the daemon-reload"
  fail=$((fail + 1))
fi
restart_block=$(awk '/^# --- Start\/restart/{f=1} /^# --- Next steps/{f=0} f{print}' "$install_sh")
for want in 'unit_refreshed nebula-server.service' 'unit_refreshed nebula-executor.service' 'systemctl try-restart'; do
  if printf '%s\n' "$restart_block" | grep -qF -- "$want"; then
    echo "ok   the restart step uses: ${want}"
    pass=$((pass + 1))
  else
    echo "FAIL the restart step does not use: ${want}"
    fail=$((fail + 1))
  fi
done

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
  if [[ $rc -eq 0 && "$out" == *"started nebula-executor (was not active)"* ]] \
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
