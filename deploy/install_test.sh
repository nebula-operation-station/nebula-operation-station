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

# WA-07: rootless provisioning tests shared with the quickstart checks.
if python3 "${script_dir}/quickstart/release_bundle_test.py"; then
  pass=$((pass + 1))
else
  fail=$((fail + 1))
fi

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

# Explicit bundle source options must parse before any system changes.
run_rc 0 "release bundle source option" --admin-users "$test_user" --rp-id nebula.test --release-bundle-dir /tmp/attachments
run_rc 0 "release bundle source equals option" --admin-users "$test_user" --rp-id nebula.test --release-bundle-dir=/tmp/attachments
run_rc 2 "release bundle source missing value" --admin-users "$test_user" --rp-id nebula.test --release-bundle-dir
run_rc 2 "release bundle source empty value" --admin-users "$test_user" --rp-id nebula.test --release-bundle-dir=

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
run_rc 1 "nebula-netdev-collector rejected as admin user" -- --admin-users nebula-netdev-collector --rp-id nebula.example.org
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

# --- Admin users must be in /etc/passwd (WA-12) --------------------------------
# The executor is built CGO_ENABLED=0, so Go's user.Lookup reads /etc/passwd
# only: an NSS-only admin (LDAP, SSSD) would pass getent but crash-loop the
# executor. NEBULA_PASSWD_FILE points the check at a temporary file; a getent
# stub on PATH simulates an NSS-only user.
wa12_tmp=$(mktemp -d)
wa12_passwd="${wa12_tmp}/passwd"
getent passwd "$test_user" > "$wa12_passwd"
real_getent=$(command -v getent)
cat > "${wa12_tmp}/getent" <<EOF
#!/usr/bin/env bash
if [[ "\${1:-}" == "passwd" && "\${2:-}" == "nssonly" ]]; then
  printf 'nssonly:x:12345:12345:NSS only user:/home/nssonly:/bin/bash\n'
  exit 0
fi
exec ${real_getent} "\$@"
EOF
chmod +x "${wa12_tmp}/getent"

# NSS-only admin: getent resolves it, but the passwd file has no line for it.
out=$(PATH="${wa12_tmp}:${PATH}" NEBULA_PASSWD_FILE="$wa12_passwd" \
  NEBULA_INSTALL_DRY_RUN=1 bash "$install_sh" \
  --admin-users nssonly --rp-id nebula.example.org 2>&1)
rc=$?
if [[ "$rc" -eq 1 && "$out" == *"nssonly"* && "$out" == *"NSS-only"* ]]; then
  echo "ok   NSS-only admin user rejected"
  pass=$((pass + 1))
else
  echo "FAIL NSS-only admin user rejected: exit ${rc}, want 1 naming the user and NSS-only"
  printf '%s\n' "$out" | sed 's/^/     /'
  fail=$((fail + 1))
fi

# A user with a line in the passwd file is accepted (dry run).
out=$(NEBULA_PASSWD_FILE="$wa12_passwd" NEBULA_INSTALL_DRY_RUN=1 \
  bash "$install_sh" --admin-users "$test_user" --rp-id nebula.example.org 2>&1)
rc=$?
if [[ "$rc" -eq 0 ]]; then
  echo "ok   admin user with a passwd-file line accepted"
  pass=$((pass + 1))
else
  echo "FAIL admin user with a passwd-file line accepted: exit ${rc}, want 0"
  printf '%s\n' "$out" | sed 's/^/     /'
  fail=$((fail + 1))
fi
rm -rf "$wa12_tmp"

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
# both. It lists, reads and unlinks in results/ and guestnet/. The modes match
# internal/pvecollect/live_spool.go and spool.go.
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
check_line "install.sh provisions the pve spool paths with their modes" "$install_sh" \
  'for entry in results:2770 guestnet:2770 requests:2770 live:2750; do'
# The spool paths sit below the collector-owned pve root, so a link can be
# swapped in after the guard: they must never get a root install -d (which
# follows it), only chown --no-dereference and an install -d as the collector.
check_line "install.sh fixes spool owner/group without following a link" "$install_sh" \
  '    chown --no-dereference nebula-pve-collector:nebula-rpc "$pve_dir"'
check_line "install.sh applies the spool mode as the collector" "$install_sh" \
  '  setpriv --reuid=nebula-pve-collector --regid=nebula-rpc --clear-groups \'
# Any root install -d with an owner (-o) on a spool path, at any indent and
# also through the loop variable, would follow a swapped-in link.
if grep -qE '^[[:space:]]*install -d .*-o .*("\$\{var_lib\}/pve/|\$pve_dir)' "$install_sh"; then
  echo "FAIL install.sh runs a root install -d on a pve spool path (follows a swapped-in link)"
  fail=$((fail + 1))
else
  echo "ok   install.sh runs no root install -d on a pve spool path"
  pass=$((pass + 1))
fi
# The server drop-in grants exactly the discovery jobs, pve/requests, the
# two pve directories the importers unlink in and the netdev spool (optional,
# "-": the netdev import, ND-16, unlinks there); the server unit itself
# grants no write path.
rw=$(grep '^ReadWritePaths=' "$install_sh" | tr '\n' ' ')
if [[ "$rw" == 'ReadWritePaths=${var_lib}/discovery/jobs ReadWritePaths=${var_lib}/pve/requests ReadWritePaths=${var_lib}/pve/results ReadWritePaths=${var_lib}/pve/guestnet ReadWritePaths=-${var_lib}/netdev ' ]]; then
  echo "ok   server drop-in may write only discovery/jobs, pve/requests, pve/results, pve/guestnet and netdev"
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
# Compose gives the server the same rights: it shares the collector's results
# and guestnet volumes writable, and never the spool root.
compose_yaml="${script_dir}/container/compose.yaml"
if [[ $(grep -cxF '      - pve-results:/var/lib/nebula/pve/results' "$compose_yaml") == 2 &&
      $(grep -cxF '      - pve-guestnet:/var/lib/nebula/pve/guestnet' "$compose_yaml") == 2 &&
      $(grep -c 'pve-spool:/var/lib/nebula/pve$' "$compose_yaml") == 1 &&
      $(grep -cxF '    network_mode: none' "$compose_yaml") == 2 &&
      $(awk '/^  pve-collector:$/{f=1;next} f&&/^  [a-z]/{exit} f{print}' "$compose_yaml" | grep -cxF '    network_mode: none') == 1 ]]; then
  echo "ok   compose mounts results and guestnet in both services, the root only in the collector, and the collector has no network"
  pass=$((pass + 1))
else
  echo "FAIL compose PVE spool mounts differ from server and collector sharing, or the collector has a network"
  fail=$((fail + 1))
fi
# The server shares the netdev spool volume writable (the ND-16 import
# unlinks there), like pve/results, so that import needs no compose change.
server_compose=$(awk '/^  server:$/{f=1;next} f&&/^  [a-z]/{exit} f{print}' "$compose_yaml")
if printf '%s\n' "$server_compose" | grep -qxF '      - netdev-spool:/var/lib/nebula/netdev' &&
   [[ $(grep -cxF '      - netdev-spool:/var/lib/nebula/netdev' "$compose_yaml") == 2 ]]; then
  echo "ok   compose mounts the netdev spool writable in the server and the collector"
  pass=$((pass + 1))
else
  echo "FAIL compose netdev spool is not shared writable by the server and the collector"
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
expected_tarball=$'nebula-server.service\nnebula-executor.service\nnebula-pve-collector.service\nnebula-netdev-collector.service\nnebula-discovery.path\nnebula-discovery.service\nnebula-discovery.timer'
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

# --- Restart on upgrade (WA-08) ----------------------------------------------
# install.sh must restart nebula-pve-collector only when the unit is active,
# not masked, and the binaries or its unit changed, and only after the
# executor answers on its socket. The executor is Type=simple, so its restart
# above returns before it listens, and the collector's startup probe
# (ListPVERemotes) exits fatally without it: on a tarball upgrade that keeps
# an edited collector unit without RestartSec=5s, an early restart can hit
# the start limit and leave the collector failed while install.sh still
# prints "restarted" and exits 0. The socket file alone proves nothing: a
# crashed or SIGKILLed executor leaves it behind, and nobody answers on it
# until the new executor has replaced it. The collector has no drop-in of
# its own, so bin_changed and a refreshed unit are its only triggers.
#
# The restart therefore sits in a block delimited by the
# '# begin: collector restart on upgrade' and '# end: ...' markers, which
# the checks below extract. The static checks pin the structure (the
# condition, exactly one restart inside the block, after the binaries are
# installed and after the last executor restart); the behaviour cases run
# the block with a stubbed systemctl and runuser and a real Unix socket for
# bin_changed 0 and 1, a refreshed, an active, an inactive and a masked unit,
# and a socket that listens, listens late, is stale, is stale and then
# replaced, accepts and hangs, or never appears. A restart while nothing
# answers on the socket fails every case. The restart step cases further down
# run the whole step, which the block alone cannot show: the collector
# restarts once, whatever else the step does with a refreshed unit.
collector_block=$(awk '/^# begin: collector restart on upgrade$/{f=1;next} /^# end: collector restart on upgrade$/{f=0} f' "$install_sh")
if [[ -n "$collector_block" ]]; then
  echo "ok   collector restart block is delimited by markers"
  pass=$((pass + 1))
else
  echo "FAIL collector restart block: the begin/end markers are missing in $install_sh"
  fail=$((fail + 1))
fi
# The condition must be inside the block, and the restart must be inside it
# too: exactly one restart in the whole file, and it must be the one in the
# block. A restart anywhere else — before the binaries are installed, or
# unconditionally after an empty if-block — would add a second occurrence
# or leave the block without one. Any form counts (try-restart,
# reload-or-restart, flags before the verb); a loop that names the unit only
# through a variable is the case of the restart step tests below.
if printf '%s\n' "$collector_block" | grep -qxF 'if { [[ ${bin_changed} -eq 1 ]] || unit_refreshed nebula-pve-collector.service; } \' \
  && printf '%s\n' "$collector_block" | grep -qxF '  && systemctl is-active --quiet nebula-pve-collector.service; then'; then
  echo "ok   the collector restart is conditional on active and on new binaries or a refreshed unit"
  pass=$((pass + 1))
else
  echo "FAIL the active and changed condition is not inside the collector restart block"
  fail=$((fail + 1))
fi
if printf '%s\n' "$collector_block" | grep -qxF '  if unit_masked nebula-pve-collector.service; then'; then
  echo "ok   the collector restart looks for a mask"
  pass=$((pass + 1))
else
  echo "FAIL the masked guard is not inside the collector restart block"
  fail=$((fail + 1))
fi
# count_collector_restarts counts the lines on stdin that restart the collector
# in any form. Comment lines say what the code does and do not count.
count_collector_restarts() {
  grep -v '^[[:space:]]*#' | grep -E 'systemctl.*[a-z-]*restart.*nebula-pve-collector' | grep -c . || true
}
restarts_in_block=$(printf '%s\n' "$collector_block" | count_collector_restarts)
restarts_in_file=$(count_collector_restarts < "$install_sh")
if [[ "$restarts_in_block" -eq 1 && "$restarts_in_file" -eq 1 ]]; then
  echo "ok   exactly one collector restart, inside the conditional block"
  pass=$((pass + 1))
else
  echo "FAIL collector restart count: ${restarts_in_block} in the block, ${restarts_in_file} in the file (want 1 and 1)"
  fail=$((fail + 1))
fi
# collector_order_error <file> prints why the collector restart block of
# <file> is in the wrong place, nothing if it is in the right one. It must
# run after the binaries are installed (bin_changed is set in that loop)
# and after the last executor restart: above it, the wait is answered by
# the old executor, and the collector restarts before the executor does.
collector_order_error() {
  local file="$1" binaries_line block_line executor_line
  binaries_line=$(grep -nF '# end: install binaries' "$file" | cut -d: -f1)
  block_line=$(grep -nF '# begin: collector restart on upgrade' "$file" | cut -d: -f1)
  executor_line=$(grep -nE '^[[:space:]]*systemctl restart nebula-executor\.service$' "$file" | tail -n 1 | cut -d: -f1)
  if [[ -z "$binaries_line" || -z "$block_line" || -z "$executor_line" ]]; then
    echo "a landmark is missing (binaries ${binaries_line:-?}, block ${block_line:-?}, executor restart ${executor_line:-?})"
  elif [[ "$block_line" -le "$binaries_line" ]]; then
    echo "block (line ${block_line}) is not after the binary install (line ${binaries_line})"
  elif [[ "$block_line" -le "$executor_line" ]]; then
    echo "block (line ${block_line}) is not after the last executor restart (line ${executor_line})"
  fi
}
order_error=$(collector_order_error "$install_sh")
if [[ -z "$order_error" ]]; then
  echo "ok   the collector restart runs after the binaries and the executor restart"
  pass=$((pass + 1))
else
  echo "FAIL collector restart order: ${order_error}"
  fail=$((fail + 1))
fi
# The check above must catch the whole block moved above the executor
# restart, which is still after the binary install.
order_mutant=$(mktemp)
COLLECTOR_BLOCK="$collector_block" awk '
  /^# begin: collector restart on upgrade$/ { skip=1 }
  skip { if ($0 == "# end: collector restart on upgrade") skip=0; next }
  !moved && /^[[:space:]]*systemctl restart nebula-executor\.service$/ {
    print "# begin: collector restart on upgrade"
    print ENVIRON["COLLECTOR_BLOCK"]
    print "# end: collector restart on upgrade"
    moved=1
  }
  { print }' "$install_sh" > "$order_mutant"
order_error=$(collector_order_error "$order_mutant")
if [[ "$order_error" == *"last executor restart"* ]]; then
  echo "ok   the order check rejects the block above the executor restart"
  pass=$((pass + 1))
else
  echo "FAIL the order check accepts the block above the executor restart: ${order_error:-no error}"
  fail=$((fail + 1))
fi
rm -f "$order_mutant"
# [collector_refreshed=1] [collector_masked=1] [collector_wait_s=V] run_collector_block <name> <bin_changed> <is_active_rc> <socket_mode> <want> [want_msg]
# Runs the extracted collector restart block under install.sh's shell
# options, with a stubbed systemctl and runuser and a real Unix socket, and
# checks the restart decision.
#   collector_refreshed  1: refresh_units replaced the collector unit
#   collector_masked     1: the unit is masked, and restart fails as on a host
#   collector_wait_s     NEBULA_COLLECTOR_RESTART_WAIT_S (default 3)
#   bin_changed   0 or 1, as install.sh sets it
#   is_active_rc  exit code the stubbed 'systemctl is-active' returns
#   socket_mode   live (listens and answers) | late (the same 0.5 s later) |
#                 stale (file left by a dead process, nobody listens) |
#                 stale-late (stale, replaced by a listener 0.5 s later) |
#                 hang (accepts, never answers) | absent
#   want          none | restart
#   want_msg      optional output substring (empty: no message check)
# The stubbed runuser and systemctl really connect to the socket and wait for
# a reply, so a stale file and a silent listener fail as they would on a host.
# systemctl records the outcome at restart time: a restart while nothing
# answers fails the case whatever <want> says. runuser insists on the probe's
# exact command line and logs each call: whenever a restart is due, the wait
# must have run that probe, and a restart must follow an answer to it, so a
# wait that only connects to the socket fails. The probe waits up to
# collector_probe_block_s for a reply, as nebula status blocks on its context,
# and collector_block_limit_s bounds the whole block: it passes with the
# 3 s wait of these cases plus one 5 s probe timeout, not without that timeout.
collector_probe_block_s=20
collector_block_limit_s=14
run_collector_block() {
  local name="$1" bin_changed="$2" is_active_rc="$3" socket_mode="$4" want="$5" want_msg="${6:-}"
  local refreshed="${collector_refreshed:-0}" masked="${collector_masked:-0}"
  local dir sock calls block_file driver connect_py listen_py out rc listener_pid="" restarts probes elapsed started ok=1 reason=""
  dir=$(mktemp -d)
  sock="${dir}/executor.sock"
  calls="${dir}/calls"
  block_file="${dir}/block.sh"
  driver="${dir}/driver.sh"
  connect_py="${dir}/connect.py"
  listen_py="${dir}/listen.py"
  : > "$calls"
  printf '%s\n' "$collector_block" > "$block_file"
  cat > "$connect_py" <<'EOF'
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(float(sys.argv[2]))
s.connect(sys.argv[1])
sys.exit(0 if s.recv(1) else 1)
EOF
  cat > "$listen_py" <<'EOF'
import os, socket, sys, time
time.sleep(float(sys.argv[2]))
try:
    os.unlink(sys.argv[1])
except FileNotFoundError:
    pass
s = socket.socket(socket.AF_UNIX)
s.bind(sys.argv[1])
s.listen(8)
held = []
while True:
    conn, _ = s.accept()
    held.append(conn)
    if sys.argv[3] == "answer":
        conn.send(b"k")
EOF
  mkdir "${dir}/bin"
  cat > "${dir}/bin/runuser" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" != "-u nebula-server -- ${bin_dir}/nebula status" || "${NEBULA_EXECUTOR_SOCKET:-}" != "$NEBULA_EXECUTOR_SOCK" ]]; then
  printf 'runuser:unexpected %s\n' "$*" >> "$CALLS_FILE"
  exit 2
fi
printf 'runuser:probe\n' >> "$CALLS_FILE"
if python3 "$CONNECT_PY" "$NEBULA_EXECUTOR_SOCKET" "$PROBE_BLOCK_S" 2>/dev/null; then
  printf 'runuser:answered\n' >> "$CALLS_FILE"
  exit 0
fi
exit 1
EOF
  chmod 0755 "${dir}/bin/runuser"
  cat > "$driver" <<'EOF'
set -euo pipefail
calls_file="$CALLS_FILE"
is_active_rc="$IS_ACTIVE_RC"
sock="$NEBULA_EXECUTOR_SOCK"
unit_refreshed() { [[ "$1" == nebula-pve-collector.service && "$COLLECTOR_REFRESHED" -eq 1 ]]; }
unit_masked() { [[ "$1" == nebula-pve-collector.service && "$COLLECTOR_MASKED" -eq 1 ]]; }
systemctl() {
  printf '%s\n' "$*" >> "$calls_file"
  if [[ "$1" == "is-active" ]]; then
    return "$is_active_rc"
  fi
  if [[ "$1" == "restart" ]]; then
    if [[ "$COLLECTOR_MASKED" -eq 1 ]]; then
      echo "stub: Unit $2 is masked." >&2
      return 1
    fi
    if python3 "$CONNECT_PY" "$sock" 1 2>/dev/null; then
      printf 'restart:executor-answers\n' >> "$calls_file"
    else
      printf 'restart:executor-silent\n' >> "$calls_file"
    fi
  fi
  return 0
}
. "$BLOCK_FILE"
EOF
  if [[ "$socket_mode" == "stale" || "$socket_mode" == "stale-late" ]]; then
    python3 -c 'import socket,sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$sock"
  fi
  case "$socket_mode" in
    live) python3 "$listen_py" "$sock" 0 answer & listener_pid=$! ;;
    late|stale-late) python3 "$listen_py" "$sock" 0.5 answer & listener_pid=$! ;;
    hang) python3 "$listen_py" "$sock" 0 hang & listener_pid=$! ;;
  esac
  started=$SECONDS
  out=$(bin_changed="$bin_changed" bin_dir=/usr/bin IS_ACTIVE_RC="$is_active_rc" CALLS_FILE="$calls" BLOCK_FILE="$block_file" \
        COLLECTOR_REFRESHED="$refreshed" COLLECTOR_MASKED="$masked" \
        CONNECT_PY="$connect_py" PROBE_BLOCK_S="$collector_probe_block_s" NEBULA_EXECUTOR_SOCK="$sock" NEBULA_COLLECTOR_RESTART_WAIT_S="${collector_wait_s:-3}" \
        PATH="${dir}/bin:${PATH}" bash "$driver" 2>&1)
  rc=$?
  elapsed=$((SECONDS - started))
  if [[ -n "$listener_pid" ]]; then
    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true
  fi
  if [[ $rc -ne 0 ]]; then
    ok=0; reason="the block exited ${rc}"
  fi
  if grep -q 'restart:executor-silent' "$calls"; then
    ok=0; reason="restarted while nothing answered on the executor socket"
  fi
  if grep -q '^runuser:unexpected' "$calls"; then
    ok=0; reason="${reason:+${reason}; }the probe is not 'nebula status' as nebula-server on the socket"
  fi
  probes=$(grep -c '^runuser:probe$' "$calls")
  if [[ "$is_active_rc" -eq 0 && "$masked" -eq 0 ]] && [[ "$bin_changed" -eq 1 || "$refreshed" -eq 1 ]]; then
    if [[ "$probes" -eq 0 ]]; then
      ok=0; reason="${reason:+${reason}; }a restart was due and the wait never ran nebula status"
    fi
  elif [[ "$probes" -ne 0 ]]; then
    ok=0; reason="${reason:+${reason}; }no restart was due and the wait still ran ${probes} probes"
  fi
  # The call right before the restart is the answer it waited for.
  if awk '$0 == "restart nebula-pve-collector.service" && prev != "runuser:answered" { found=1 } { prev=$0 } END { exit !found }' "$calls"; then
    ok=0; reason="${reason:+${reason}; }the restart does not follow an answer to the probe"
  fi
  if [[ "$elapsed" -gt "$collector_block_limit_s" ]]; then
    ok=0; reason="${reason:+${reason}; }the block took ${elapsed}s, limit ${collector_block_limit_s}s: a hanging probe is not bounded"
  fi
  restarts=$(grep -c '^restart nebula-pve-collector.service$' "$calls")
  if [[ "$want" == "restart" && "$restarts" -ne 1 ]]; then
    ok=0; reason="${reason:+${reason}; }restart calls: ${restarts}, want 1"
  elif [[ "$want" == "none" && "$restarts" -ne 0 ]]; then
    ok=0; reason="${reason:+${reason}; }restart calls: ${restarts}, want 0"
  fi
  if [[ -n "$want_msg" && "$out" != *"$want_msg"* ]]; then
    ok=0; reason="${reason:+${reason}; }output does not contain ${want_msg}"
  fi
  if [[ "$ok" -eq 1 ]]; then
    echo "ok   ${name}"
    pass=$((pass + 1))
  else
    echo "FAIL ${name}: ${reason}"
    printf '%s\n' "$out" | sed 's/^/     /'
    fail=$((fail + 1))
  fi
  rm -rf "$dir"
}
# bin_changed 0 (a re-run without new binaries): the active collector keeps
# the binary it is already running; no restart, no socket wait.
run_collector_block "bin_changed 0: active collector is not restarted" 0 0 live none
# bin_changed 1, the executor already answers: exactly one restart.
run_collector_block "bin_changed 1: active collector restarted once the executor answers" 1 0 live restart "restarted nebula-pve-collector (binaries or unit changed)"
# bin_changed 1, unit not active: nothing to restart.
run_collector_block "bin_changed 1: inactive collector is not restarted" 1 3 live none
# bin_changed 1, the executor (Type=simple) is still coming up: the block
# must wait for it, not restart before it listens.
run_collector_block "bin_changed 1: waits for a late executor socket" 1 0 late restart
# bin_changed 1, a crashed executor left its socket file and the new one has
# not replaced it yet: the file must not pass, the listener must.
run_collector_block "bin_changed 1: waits past a stale socket for the new executor" 1 0 stale-late restart
# bin_changed 1, the stale file is all there is: no restart, and a warning
# instead of "restarted".
run_collector_block "bin_changed 1: a stale socket is not restarted on and warns" 1 0 stale none "not answering"
# bin_changed 1, the socket never appears (broken executor): leave the
# collector on the old binary (it retries inside its poll loop) and warn.
run_collector_block "bin_changed 1: no socket in time is not restarted and warns" 1 0 absent none "not answering"
# bin_changed 1, a listener that accepts and never answers: a connect is no
# answer, and nebula status would block for its whole context on each attempt,
# so the probe has to give up on its own.
run_collector_block "bin_changed 1: a listener that hangs is not restarted on, in bounded time" 1 0 hang none "not answering"
# The refreshed unit is a trigger of its own, with the same wait.
collector_refreshed=1 run_collector_block "refreshed unit: active collector restarted once the executor answers" 0 0 live restart "restarted nebula-pve-collector (binaries or unit changed)"
collector_refreshed=1 run_collector_block "refreshed unit: waits past a stale socket for the new executor" 0 0 stale-late restart
collector_refreshed=1 run_collector_block "refreshed unit: inactive collector is not restarted" 0 3 live none
collector_refreshed=1 run_collector_block "refreshed unit and new binaries: restarted once" 1 0 live restart
# A masked collector that still runs: systemctl restart would fail, and under
# set -e end the install. It stays as it is, and the executor is not asked.
collector_masked=1 run_collector_block "masked: new binaries are skipped with a warning" 1 0 live none "is masked; not restarting it"
collector_masked=1 collector_refreshed=1 run_collector_block "masked: a refreshed unit is skipped with a warning" 0 0 live none "is masked; not restarting it"
collector_masked=1 run_collector_block "masked and stopped: nothing to say" 1 3 live none
# The wait goes into bash arithmetic, which evaluates what it is given: a value
# that is not a plain non-negative integer falls back to the default with a
# warning, and is never evaluated (the subscript would create the marker).
wait_marker=$(mktemp -u)
for bad_wait in "x[\$(touch ${wait_marker})]" -1 08 1.5 abc 1234567; do
  collector_wait_s="$bad_wait" run_collector_block "wait '${bad_wait}': the default is used, with a warning" 1 0 live restart "NEBULA_COLLECTOR_RESTART_WAIT_S is not a non-negative integer"
done
if [[ ! -e "$wait_marker" ]]; then
  echo "ok   wait values are never evaluated"
  pass=$((pass + 1))
else
  echo "FAIL a wait value was evaluated as an expression"
  rm -f "$wait_marker"
  fail=$((fail + 1))
fi
postinst="${script_dir}/deb/postinst"
check_line "postinst hint names the collector" "$postinst" \
  'nebula:   sudo nebula backup && sudo systemctl restart nebula-executor nebula-server nebula-pve-collector'
# --- Unit refresh (WA-09), functional, no root needed -------------------------
# Runs the real refresh block of install.sh against a sandbox: the paths point
# into a temporary directory and the only stub is `install`, which drops the
# -o/-g options so that no root is needed. Three cases carry the design: a
# unit nobody edited follows the shipped version, an edited one is never
# replaced, and a new one is installed.
refresh_block=$(sed -n '/^# begin: unit refresh/,/^# end: unit refresh/p' "$install_sh")
# The pending record is defined above the binary install, which writes to it.
pending_block=$(sed -n '/^# begin: pending record/,/^# end: pending record/p' "$install_sh")
refresh_sb=$(mktemp -d)
trap 'rm -rf "$refresh_sb"' EXIT
mkdir -p "$refresh_sb/deploy/systemd" "$refresh_sb/etc" "$refresh_sb/var"
# The real units, for the cases that run more than the refresh block.
install_units=(
  nebula-server.service
  nebula-executor.service
  nebula-pve-collector.service
  nebula-discovery.path
  nebula-discovery.service
  nebula-discovery.timer
)
# The binaries of the sandbox tarball, for the cases that run the binary
# install: one per unit whose restart new binaries make due, and the CLI. The
# collector's comes last, so a stop at it finds the others replaced.
sandbox_binaries=(nebula nebula-server nebula-executor nebula-pve-collector)
# bin_build counts the builds run_install has shipped (inst_bin_changed=1).
bin_build=0

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
# reset_refresh: an empty host and an empty tarball, whose binaries (for the
# cases that run the binary install) are the ones the host already has.
reset_refresh() {
  local bin
  rm -rf "$refresh_sb/etc" "$refresh_sb/var" "$refresh_sb/deploy/systemd" "$refresh_sb/bin" "$refresh_sb/tarball"
  mkdir -p "$refresh_sb/deploy/systemd" "$refresh_sb/etc" "$refresh_sb/var" "$refresh_sb/bin" "$refresh_sb/tarball"
  for bin in "${sandbox_binaries[@]}"; do
    printf '%s build 0\n' "$bin" > "$refresh_sb/bin/$bin"
    cp "$refresh_sb/bin/$bin" "$refresh_sb/tarball/$bin"
  done
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
    eval "$pending_block"
    eval "$refresh_block"
    if [[ -n "$legacy" ]]; then
      legacy_unit_sums=("$legacy")
    fi
    refresh_units
    clear_pending_units # a run that reached its end
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
  # The list is frozen, entry for entry. A wrong checksum would make that
  # unit count as edited on a pre-manifest host as soon as it changes.
  expected_legacy='  "e7a42fc29dc5aeae3e854001f06cd0efeaef8458dd273e7a4ff74607a73de8c4  nebula-server.service"
  "fbce1de5c0888db5927d5a34333214f57e6239c987b9c7be41f21e7c761a1beb  nebula-executor.service"
  "cd452ec9eb40017e6ae6da044ef04034d8031f5137c7ed7b757c7039cde34f42  nebula-pve-collector.service"
  "60c0ef3dc3f3fc0ca54e528fd9b41d82571fbb0bb5637e1779a78e4ad8f0c2b7  nebula-pve-collector.service"
  "4ad18a7e6a7270588e6dbe6a04d2f6fd7a7ccd0730b2ff6989da4136d8acbf11  nebula-discovery.path"
  "be046e71c5f0585c7b0abe93d41a5e698dc47a69affd939761b4c968996a8a50  nebula-discovery.service"
  "2a88aab97acc72e9752b2c259c2f6f2dfccb9804d751cee77d138a0563df2c61  nebula-discovery.timer"'
  if [[ "$legacy_list" == "$expected_legacy" ]]; then
    echo "ok   legacy_unit_sums is unchanged, entry for entry"
    pass=$((pass + 1))
  else
    echo "FAIL legacy_unit_sums differs from the frozen list"
    fail=$((fail + 1))
  fi
  # The source of truth for that list is the repository: at the last commit
  # before units.sha256 existed, it must name every committed version of every
  # unit and nothing else. CI's test job has a shallow checkout and the release
  # tarball no history at all, so this runs in full clones only; the frozen
  # copy above keeps the list from drifting everywhere else.
  freeze_commit=bdb6998
  repo_root=$(dirname -- "$script_dir")
  if [[ "$(git -C "$repo_root" rev-parse --is-shallow-repository 2>/dev/null)" == "false" ]] \
     && git -C "$repo_root" cat-file -e "${freeze_commit}^{commit}" 2>/dev/null; then
    history_list=""
    for unit in "${install_units[@]}"; do
      while read -r commit; do
        blob=$(git -C "$repo_root" rev-parse -q --verify "${commit}:deploy/systemd/${unit}") || continue
        history_list+="  \"$(git -C "$repo_root" cat-file blob "$blob" | sha256sum | cut -d' ' -f1)  ${unit}\""$'\n'
      done < <(git -C "$repo_root" log --format=%H "$freeze_commit" -- "deploy/systemd/${unit}")
    done
    if [[ "$(printf '%s' "$history_list" | sort -u)" == "$(printf '%s\n' "$legacy_list" | sort -u)" ]]; then
      echo "ok   legacy_unit_sums is exactly the unit versions committed before the freeze"
      pass=$((pass + 1))
    else
      echo "FAIL legacy_unit_sums does not match the committed unit versions"
      diff <(printf '%s' "$history_list" | sort -u) <(printf '%s\n' "$legacy_list" | sort -u) | sed 's/^/     /'
      fail=$((fail + 1))
    fi
  else
    echo "skip legacy_unit_sums against the unit history (needs a full clone)"
  fi
fi

# --- PVE spool guard, functional, no root needed ------------------------------
# Runs the real guard block of install.sh against a sandbox var_lib: a file
# or symlink swapped in at the pve root or a spool path must stop the
# install before install -d -o -g follows it as root. The guard is the
# install-side twin of the postinst's check (deploy/deb/postinst), which
# refuses the same objects and points the admin to install.sh.
pve_guard_block=$(sed -n '/^# begin: pve spool guard/,/^# end: pve spool guard/p' "$install_sh")
pve_sb=$(mktemp -d)
trap 'rm -rf "$refresh_sb" "$pve_sb"' EXIT

# run_pve_guard: the real guard block against pve_sb/var, under set -e like
# the real script. The output (with stderr) lands in pve_out, the exit
# status in pve_rc.
run_pve_guard() {
  pve_out=$(
    exec 2>&1
    set -euo pipefail
    var_lib="$pve_sb/var"
    eval "$pve_guard_block"
    echo "END"
  )
  pve_rc=$?
  refresh_out="$pve_out" # expect prints it on a failure
}
pve_reset() {
  rm -rf "$pve_sb/var"
  mkdir -p "$pve_sb/var"
}
pve_rc_is() { [[ "$pve_rc" -eq "$1" ]]; }
pve_out_has() { [[ "$pve_out" == *"$1"* ]]; }
pve_out_lacks() { [[ "$pve_out" != *"$1"* ]]; }

if [[ -z "$pve_guard_block" ]]; then
  echo "FAIL install.sh has no pve spool guard block"
  fail=$((fail + 1))
else
  # The guard must use the postinst's directory/link check, on every pve
  # path, before install -d runs on the pve root.
  if printf '%s\n' "$pve_guard_block" | grep -qF 'if [[ -L "$pve_path" ]] || { [[ -e "$pve_path" ]] && [[ ! -d "$pve_path" ]]; }; then'; then
    echo "ok   the pve spool guard uses the postinst's directory/link check"
    pass=$((pass + 1))
  else
    echo "FAIL the pve spool guard does not use the postinst's directory/link check"
    fail=$((fail + 1))
  fi
  guard_paths=$(printf '%s\n' "$pve_guard_block" | grep -o '"\${var_lib}/pve[^"]*"')
  expected_pve_paths=$(printf '"%s"\n' '${var_lib}/pve' '${var_lib}/pve/results' '${var_lib}/pve/guestnet' '${var_lib}/pve/requests' '${var_lib}/pve/live')
  if [[ "$guard_paths" == "$expected_pve_paths" ]]; then
    echo "ok   the pve spool guard covers the pve root and every spool path"
    pass=$((pass + 1))
  else
    echo "FAIL the pve spool guard does not cover the pve root and every spool path"
    printf '%s\n' "$guard_paths" | sed 's/^/     got: /'
    fail=$((fail + 1))
  fi
  guard_end_line=$(grep -n '^# end: pve spool guard$' "$install_sh" | cut -d: -f1)
  pve_install_line=$(grep -n '^install -d -m 2750 -o nebula-pve-collector -g nebula-rpc "\${var_lib}/pve"$' "$install_sh" | cut -d: -f1)
  if [[ -n "$guard_end_line" && -n "$pve_install_line" && "$guard_end_line" -lt "$pve_install_line" ]]; then
    echo "ok   the pve spool guard runs before install -d on the pve root"
    pass=$((pass + 1))
  else
    echo "FAIL the pve spool guard must run before install -d on the pve root"
    fail=$((fail + 1))
  fi

  # A fresh host: nothing at the pve paths, the guard passes.
  pve_reset
  run_pve_guard
  expect "pve guard: a fresh host passes" pve_rc_is 0
  expect "pve guard: a fresh host reaches the end" pve_out_has 'END'

  # Real directories at every pve path: the guard passes.
  pve_reset
  mkdir -p "$pve_sb/var/pve/results" "$pve_sb/var/pve/guestnet" "$pve_sb/var/pve/requests" "$pve_sb/var/pve/live"
  run_pve_guard
  expect "pve guard: real directories pass" pve_rc_is 0

  # A symlink or a file at the pve root or a spool path stops the install
  # before install -d follows it. <path relative to var_lib> <how>
  while read -r rel how; do
    pve_reset
    parent=$(dirname "$pve_sb/var/$rel")
    mkdir -p "$parent"
    case "$how" in
      link)
        mkdir -p "$pve_sb/target"
        ln -s "$pve_sb/target" "$pve_sb/var/$rel"
        ;;
      file)
        printf 'swapped in\n' > "$pve_sb/var/$rel"
        ;;
    esac
    run_pve_guard
    expect "pve guard: ${how} at ${rel} is refused" pve_rc_is 1
    expect "pve guard: ${how} at ${rel} names the path" pve_out_has "$pve_sb/var/$rel"
    expect "pve guard: ${how} at ${rel} does not reach the end" pve_out_lacks 'END'
  done <<'CASES'
pve link
pve file
pve/results link
pve/results file
pve/guestnet link
pve/guestnet file
pve/requests link
pve/requests file
pve/live link
pve/live file
CASES
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

# --- Enable and restart steps, functional, no root needed ---------------------
# Runs the real unit selection and the real enable and restart steps of
# install.sh after the refresh block, against the sandbox above, with a
# systemctl stub that logs every call and refuses masked units like the real
# one: `enable` and `restart` fail, which under set -e aborts the script. It
# also refuses to start a path or timer unit whose target is masked, as
# systemd does, while `enable` alone and a start of a running unit succeed.
# The status probe of the collector restart goes through a stubbed runuser,
# which logs to the same file, so that a run shows the order of the two.
binaries_block=$(sed -n '/^# begin: install binaries/,/^# end: install binaries/p' "$install_sh")
select_block=$(sed -n '/^# begin: select units/,/^# end: select units/p' "$install_sh")
start_block=$(sed -n '/^# begin: start units/,/^# end: start units/p' "$install_sh")
systemctl_log="$refresh_sb/systemctl.log"
both_services="nebula-server.service nebula-executor.service"
all_services="$both_services nebula-pve-collector.service"
mkdir -p "$refresh_sb/stub-bin"
cat > "$refresh_sb/stub-bin/runuser" <<'EOF'
#!/usr/bin/env bash
printf 'probe %s\n' "$*" >> "$STUB_SYSTEMCTL_LOG"
exit "$STUB_PROBE_RC"
EOF
chmod 0755 "$refresh_sb/stub-bin/runuser"

# What the next run_install sees; reset_install restores the defaults.
reset_install() {
  inst_bin_changed=0
  inst_probe_rc=0              # what the status probe exits with
  inst_drop_in_changed=0
  inst_server_drop_in_changed=0
  inst_from_package=0
  stub_active="$both_services" # units that are running
  stub_runtime_masked=""       # units masked under /run
  stub_fail=""                 # the one systemctl call that fails
  stub_stop_at_manifest=0      # 1: the run stops before units_manifest moves
  stub_stop_at_unit=""         # the unit file whose write stops the run
  stub_stop_after_copy=0       # 1: that write copies the file, then fails
  inst_new_bins="nebula-server nebula-pve-collector" # what inst_bin_changed=1 rebuilds
  inst_legacy=""               # replaces the list of pre-manifest checksums
}

# stub_unit_state <unit>: what systemctl is-enabled prints. Masked means what
# it means to systemd: a link to /dev/null or an empty file.
stub_unit_state() {
  local file="$refresh_sb/etc/$1"
  if [[ " $stub_runtime_masked " == *" $1 "* ]]; then
    echo masked-runtime
  elif [[ -L "$file" && "$(readlink "$file")" == /dev/null ]] || [[ -f "$file" && ! -s "$file" ]]; then
    echo masked
  else
    echo disabled
  fi
}
# stub_trigger_target <unit>: what a path or timer unit starts: its Unit= line
# or the service of the same name, nothing for any other unit.
stub_trigger_target() {
  local line target="${1%.*}.service"
  if [[ "$1" != *.path && "$1" != *.timer ]]; then
    return 0
  fi
  if [[ -f "$refresh_sb/etc/$1" ]]; then
    while IFS= read -r line; do
      if [[ "$line" == Unit=* ]]; then
        target="${line#Unit=}"
      fi
    done < "$refresh_sb/etc/$1"
  fi
  printf '%s\n' "$target"
}
# stub_start_refused <systemctl call...>: succeeds if the call has to start a
# trigger whose target is masked. A start of a running unit changes nothing,
# `enable` alone starts nothing, and try-restart touches only a running unit.
stub_start_refused() {
  local unit="${*: -1}" target running=0
  target=$(stub_trigger_target "$unit")
  if [[ -z "$target" || "$(stub_unit_state "$target")" != masked* ]]; then
    return 1
  fi
  if [[ " $stub_active " == *" $unit "* ]]; then
    running=1
  fi
  case "$1 $running" in
    "enable 0") [[ "$2" == --now ]] ;;
    "restart "*|"try-restart 1") return 0 ;;
    *) return 1 ;;
  esac
}
stub_systemctl() {
  local unit="${*: -1}" state
  printf '%s\n' "$*" >> "$systemctl_log"
  if [[ -n "$stub_fail" && "$*" == "$stub_fail" ]]; then
    echo "stub: $* failed" >&2
    return 1
  fi
  state=$(stub_unit_state "$unit")
  case "$1" in
    is-enabled)
      if [[ "$2" != --quiet ]]; then
        printf '%s\n' "$state"
      fi
      return 1
      ;;
    is-active)
      [[ " $stub_active " == *" $unit "* ]]
      ;;
    show)
      stub_trigger_target "$unit"
      ;;
    enable|restart|try-restart)
      if [[ "$state" == masked* ]]; then
        echo "stub: Unit ${unit} is masked." >&2
        return 1
      fi
      if stub_start_refused "$@"; then
        echo "stub: Refusing to start ${unit}, the unit it triggers is not loaded." >&2
        return 1
      fi
      ;;
  esac
}
# run_install: the unit, enable and restart steps of one install.sh run, under
# set -e like the real script. refresh_out and refresh_rc as in run_refresh.
run_install() {
  : > "$systemctl_log"
  # New binaries are a new build of each of inst_new_bins in the tarball; the
  # binary install of the run below finds them, and sets bin_changed as
  # install.sh does.
  local bin
  if [[ "$inst_bin_changed" -eq 1 ]]; then
    bin_build=$((bin_build + 1))
    for bin in $inst_new_bins; do
      printf '%s build %s\n' "$bin" "$bin_build" > "$refresh_sb/tarball/$bin"
    done
  fi
  refresh_out=$(
    exec 2>&1
    set -euo pipefail
    install() {
      if [[ -n "$stub_stop_at_unit" && "${@: -1}" == *"/$stub_stop_at_unit" ]]; then
        # install -o/-g copies, then sets the owner: a stop there leaves the
        # new file in place.
        if [[ "$stub_stop_after_copy" -eq 1 ]]; then
          command install -m 0644 "${@: -2:1}" "${@: -1}"
        fi
        return 1
      fi
      command install -m 0644 "${@: -2:1}" "${@: -1}"
    }
    if [[ "$stub_stop_at_manifest" -eq 1 ]]; then
      mv() { return 1; }
    fi
    systemctl() { stub_systemctl "$@"; }
    export PATH="$refresh_sb/stub-bin:$PATH"
    export STUB_SYSTEMCTL_LOG="$systemctl_log" STUB_PROBE_RC="$inst_probe_rc"
    export NEBULA_COLLECTOR_RESTART_WAIT_S=1
    script_dir="$refresh_sb/deploy"
    systemd_dir="$refresh_sb/etc"
    var_lib="$refresh_sb/var"
    bin_dir="$refresh_sb/bin"
    tarball_root="$refresh_sb/tarball"
    binaries=("${sandbox_binaries[@]}")
    from_package="$inst_from_package"
    drop_in_changed="$inst_drop_in_changed"
    server_drop_in_changed="$inst_server_drop_in_changed"
    tarball_units=("${install_units[@]}")
    package_units=(
      nebula-server.service
      nebula-executor.service
      nebula-pve-collector.service
      nebula-discovery.path
      nebula-discovery.timer
    )
    eval "$pending_block"
    eval "$binaries_block"
    eval "$refresh_block"
    if [[ -n "$inst_legacy" ]]; then
      legacy_unit_sums=("$inst_legacy")
    fi
    eval "$select_block"
    eval "$start_block"
    echo "END"
  )
  refresh_rc=$?
}
# installed_host: a host that went through one complete install of v1.
installed_host() {
  local unit
  reset_refresh
  reset_install
  for unit in "${install_units[@]}"; do
    ship "$unit" "$unit v1"
  done
  run_install
}
called() { grep -qxF -- "$1" "$systemctl_log"; }
not_called() { ! called "$1"; }
restarts_are() { [[ "$(grep -E '^(restart|try-restart) ' "$systemctl_log")" == "$1" ]]; }
# collector_restarts_are <n>: the run restarted the collector <n> times, in
# any form: a verb ending in restart, with or without flags.
collector_restarts_are() {
  [[ "$(grep -E '(^| )[a-z-]*restart( |$)' "$systemctl_log" | grep -c 'nebula-pve-collector')" -eq "$1" ]]
}
# The runuser stub logs each status probe as "probe <its arguments>".
probed() { grep -qxF "probe -u nebula-server -- $refresh_sb/bin/nebula status" "$systemctl_log"; }
not_probed() { ! grep -q '^probe ' "$systemctl_log"; }
# log_order <line...>: each line occurs, each after the one before it.
log_order() {
  local want="$1" line
  shift
  while IFS= read -r line; do
    if [[ "$line" == "$want" ]]; then
      if [[ $# -eq 0 ]]; then
        return 0
      fi
      want="$1"
      shift
    fi
  done < "$systemctl_log"
  return 1
}
probe_precedes_collector_restart() {
  log_order "probe -u nebula-server -- $refresh_sb/bin/nebula status" 'restart nebula-pve-collector.service'
}
collector_restarts_after_probe() {
  log_order 'restart nebula-executor.service' "probe -u nebula-server -- $refresh_sb/bin/nebula status" 'restart nebula-pve-collector.service'
}
is_mask_link() { [[ -L "$1" && "$(readlink "$1")" == /dev/null ]]; }
rc_not_zero() { [[ "$refresh_rc" -ne 0 ]]; }
stub_accepts() { stub_systemctl "$@" 2>/dev/null; }
stub_refuses() { ! stub_accepts "$@"; }
nothing_pending() { [[ ! -e "$refresh_sb/var/units.pending" ]]; }
pending_has() { grep -qxF "$1  $2" "$refresh_sb/var/units.pending"; }
# pending_is <sum or "restart"> <unit>: that line is all the record holds.
pending_is() { [[ "$(cat "$refresh_sb/var/units.pending" 2>/dev/null)" == "$1  $2" ]]; }
# bins_current: every installed binary is the tarball's, so the next run of
# the same tarball replaces none and has bin_changed 0.
bins_current() {
  local bin
  for bin in "${sandbox_binaries[@]}"; do
    cmp -s "$refresh_sb/tarball/$bin" "$refresh_sb/bin/$bin" || return 1
  done
}
# all_restarts: the restarts new binaries make due, in the step's order.
all_restarts=$'restart nebula-server.service\nrestart nebula-executor.service\nrestart nebula-pve-collector.service'

if [[ -z "$select_block" || -z "$start_block" ]]; then
  echo "FAIL install.sh has no unit selection or start block"
  fail=$((fail + 1))
else
  installed_host
  expect "install: a complete run succeeds" rc_is 0
  expect "install: the server is enabled and started" called 'enable --now nebula-server.service'
  expect "install: the executor is enabled" called 'enable nebula-executor.service'
  expect "install: the discovery timer is enabled and started" called 'enable --now nebula-discovery.timer'
  expect "install: the discovery service is never enabled" not_called 'enable --now nebula-discovery.service'

  # Which restarts a run makes, exactly: a broken unit_refreshed, an inverted
  # condition or a loop that restarts too much all change this list.
  run_install
  expect "nothing changed: nothing is restarted" restarts_are ''
  # <unit> <the only restart that may follow when a shipped fix replaces it>
  while read -r unit want_restart; do
    installed_host
    ship "$unit" "$unit v2"
    stub_active="$all_services"
    run_install
    expect "refreshed ${unit}: the run succeeds" rc_is 0
    expect "refreshed ${unit}: exactly '${want_restart}' follows" restarts_are "$want_restart"
  done <<'CASES'
nebula-server.service restart nebula-server.service
nebula-executor.service restart nebula-executor.service
nebula-pve-collector.service restart nebula-pve-collector.service
nebula-discovery.path try-restart nebula-discovery.path
nebula-discovery.timer try-restart nebula-discovery.timer
nebula-discovery.service
CASES

  installed_host
  ship nebula-server.service 'nebula-server.service v2'
  stub_active=nebula-executor.service
  run_install
  expect "refreshed but stopped server: not restarted" restarts_are ''

  installed_host
  printf 'admin edit\n' > "$refresh_sb/etc/nebula-server.service"
  ship nebula-server.service 'nebula-server.service v2'
  run_install
  expect "edited server unit: not restarted" restarts_are ''

  installed_host
  inst_bin_changed=1
  run_install
  expect "new binaries: both services restart" restarts_are $'restart nebula-server.service\nrestart nebula-executor.service'

  # The collector restart belongs to one block, also with new binaries and a
  # refreshed unit at once, when two steps of the run have a reason for it. It
  # follows the executor restart and an answer, or nothing would come up.
  installed_host
  ship nebula-pve-collector.service 'nebula-pve-collector.service v2'
  stub_active="$all_services"
  inst_bin_changed=1
  run_install
  expect "new binaries and collector unit: the run succeeds" rc_is 0
  expect "new binaries and collector unit: each service restarts once" restarts_are $'restart nebula-server.service\nrestart nebula-executor.service\nrestart nebula-pve-collector.service'
  expect "new binaries and collector unit: one collector restart in any form" collector_restarts_are 1
  expect "new binaries and collector unit: executor, answer, collector" collector_restarts_after_probe

  # No new binaries: the refreshed unit alone asks for the same waited restart.
  installed_host
  ship nebula-pve-collector.service 'nebula-pve-collector.service v2'
  stub_active="$all_services"
  run_install
  expect "collector unit only: one collector restart in any form" collector_restarts_are 1
  expect "collector unit only: the probe comes first" probe_precedes_collector_restart

  installed_host
  ship nebula-pve-collector.service 'nebula-pve-collector.service v2'
  run_install
  expect "refreshed but stopped collector: not restarted" collector_restarts_are 0
  expect "refreshed but stopped collector: nothing asked" not_probed

  # A first install is not an upgrade: the enable step starts the collector,
  # although the unit went on record in this run.
  reset_refresh
  reset_install
  for unit in "${install_units[@]}"; do
    ship "$unit" "$unit v1"
  done
  stub_active="$all_services"
  run_install
  expect "first install, running collector: not restarted" collector_restarts_are 0
  expect "first install, running collector: nothing asked" not_probed

  # Nobody answers: no restart in any form, a warning, and the install ends.
  # The restart is still due, so it stays on record, and only that: the server
  # restarted, so its line goes. The run after that asks again, and warns again
  # or restarts, once, with the same tarball and nothing changed.
  collector=nebula-pve-collector.service
  installed_host
  ship nebula-server.service 'nebula-server.service v2'
  ship "$collector" "$collector v2"
  stub_active="$all_services"
  inst_bin_changed=1
  inst_probe_rc=1
  run_install
  expect "silent executor: the install runs to its end" rc_is 0
  expect "silent executor: the end is reached" out_has $'\nEND'
  expect "silent executor: the collector is not restarted" collector_restarts_are 0
  expect "silent executor: it was asked" probed
  expect "silent executor: the warning says so" out_has 'not answering'
  expect "silent executor: only the collector stays pending" pending_is restart "$collector"
  inst_bin_changed=0
  run_install
  expect "silent again: the run succeeds" rc_is 0
  expect "silent again: nothing is restarted" restarts_are ''
  expect "silent again: it was asked" probed
  expect "silent again: the warning comes again" out_has 'not answering'
  expect "silent again: the collector stays pending" pending_is restart "$collector"
  inst_probe_rc=0
  run_install
  expect "answering after a skip: the run succeeds" rc_is 0
  expect "answering after a skip: the collector alone restarts, once" restarts_are "restart $collector"
  expect "answering after a skip: the probe comes first" probe_precedes_collector_restart
  expect "answering after a skip: no warning" out_lacks 'not answering'
  expect "answering after a skip: nothing stays pending" nothing_pending
  run_install
  expect "after the retry: nothing is restarted" restarts_are ''

  # New binaries alone: the run replaced no unit and wrote no record, so the
  # skipped restart has to go on record by itself.
  installed_host
  stub_active="$all_services"
  inst_bin_changed=1
  inst_probe_rc=1
  run_install
  expect "silent, binaries only: the collector goes on record" pending_is restart "$collector"
  inst_bin_changed=0
  inst_probe_rc=0
  run_install
  expect "silent, binaries only: the next run restarts it, once" restarts_are "restart $collector"
  expect "silent, binaries only: nothing stays pending" nothing_pending

  # An edited unit keeps the restart it is owed. The record holds a restart
  # line, no checksum: never the edit's, which would make the edit look
  # unedited.
  installed_host
  printf 'admin edit\n' > "$refresh_sb/etc/$collector"
  stub_active="$all_services"
  inst_bin_changed=1
  inst_probe_rc=1
  run_install
  expect "silent, edited unit: the restart goes on record" pending_is restart "$collector"
  inst_bin_changed=0
  inst_probe_rc=0
  ship "$collector" "$collector v2"
  run_install
  expect "silent, edited unit: the edit is kept" has_content "$refresh_sb/etc/$collector" 'admin edit'
  expect "silent, edited unit: the next run restarts it, once" restarts_are "restart $collector"
  expect "silent, edited unit: nothing stays pending" nothing_pending

  # Stopped by the next run: nothing runs the old binary, nothing is left due.
  installed_host
  stub_active="$all_services"
  inst_bin_changed=1
  inst_probe_rc=1
  run_install
  inst_bin_changed=0
  inst_probe_rc=0
  stub_active="$both_services"
  run_install
  expect "stopped after a skip: not restarted" collector_restarts_are 0
  expect "stopped after a skip: nothing asked" not_probed
  expect "stopped after a skip: nothing stays pending" nothing_pending

  # New binaries alone, and the run stops after they are in place but before
  # the restarts. bin_changed is gone with the run, and the re-run of the same
  # tarball finds no binary changed (bins_current), so only the record written
  # before the binaries were replaced still makes the restarts due: the
  # server's and the executor's as well as the collector's, or the collector
  # would come up on the new binary against the old executor. One case
  # rebuilds the server binary alone, so a record step that looked at the
  # collector binary only would fail it; another rebuilds only the CLI
  # (nebula), which belongs to none of the three units and still makes all
  # three restarts due.
  # <the failing systemctl call>
  for new_bins in "nebula" "nebula-server" "nebula-server nebula-pve-collector"; do
    first_new_bin="${new_bins%% *}"
    while read -r failing; do
      name="binaries only (new: ${new_bins}), stopped at '${failing}'"
      installed_host
      stub_active="$all_services"
      inst_bin_changed=1
      inst_new_bins="$new_bins"
      stub_fail="$failing"
      run_install
      expect "${name}: the run fails" rc_not_zero
      expect "${name}: the new ${first_new_bin} binary is in place" has_content "$refresh_sb/bin/$first_new_bin" "$first_new_bin build $bin_build"
      expect "${name}: the next run of this tarball changes no binary" bins_current
      expect "${name}: the collector is not restarted yet" collector_restarts_are 0
      expect "${name}: the server restart is on record" pending_has restart nebula-server.service
      expect "${name}: the executor restart is on record" pending_has restart nebula-executor.service
      expect "${name}: the collector restart is on record" pending_has restart "$collector"
      inst_bin_changed=0
      stub_fail=""
      run_install
      expect "${name}: the re-run succeeds" rc_is 0
      expect "${name}: the re-run restarts server, executor, collector, once each" restarts_are "$all_restarts"
      expect "${name}: the re-run asks the new executor first" collector_restarts_after_probe
      expect "${name}: nothing stays pending" nothing_pending
      run_install
      expect "${name}: the run after that restarts nothing" restarts_are ''
    done <<'CASES'
enable --now nebula-discovery.timer
restart nebula-server.service
restart nebula-executor.service
CASES
  done

  # A stop while the binaries are replaced: the record came first. The stop
  # comes after the last binary (the collector's) was copied, so the re-run
  # sees bin_changed 0 and the record alone makes the restarts due.
  installed_host
  stub_active="$all_services"
  inst_bin_changed=1
  stub_stop_at_unit=nebula-pve-collector # the binary, not the unit
  stub_stop_after_copy=1
  run_install
  expect "stopped installing the collector binary: the run fails" rc_not_zero
  expect "stopped installing the collector binary: nothing is restarted" restarts_are ''
  expect "stopped installing the collector binary: the server restart is on record" pending_has restart nebula-server.service
  expect "stopped installing the collector binary: the executor restart is on record" pending_has restart nebula-executor.service
  expect "stopped installing the collector binary: the collector restart is on record" pending_has restart "$collector"
  expect "stopped installing the collector binary: the new collector binary is in place" has_content "$refresh_sb/bin/nebula-pve-collector" "nebula-pve-collector build $bin_build"
  expect "stopped installing the collector binary: the re-run changes no binary" bins_current
  stub_stop_at_unit=""
  stub_stop_after_copy=0
  inst_bin_changed=0
  run_install
  expect "stopped installing the collector binary: the re-run succeeds" rc_is 0
  expect "stopped installing the collector binary: the re-run restarts server, executor, collector, once each" restarts_are "$all_restarts"
  expect "stopped installing the collector binary: nothing stays pending" nothing_pending

  # A first install has no binary in place: nothing goes on record, even
  # though every binary is new.
  reset_refresh
  reset_install
  rm -f "$refresh_sb/bin/"*
  for unit in "${install_units[@]}"; do
    ship "$unit" "$unit v1"
  done
  stub_stop_at_unit=nebula-pve-collector # the binary, not the unit
  run_install
  expect "first install, stopped at the collector binary: nothing on record" nothing_pending
  stub_stop_at_unit=""

  # Same binaries: nothing goes on record, so nothing is restarted.
  installed_host
  stub_active="$all_services"
  stub_fail='enable --now nebula-discovery.timer'
  run_install
  expect "same binaries, stopped: nothing on record" nothing_pending
  stub_fail=""
  run_install
  expect "same binaries, re-run: no collector restart" collector_restarts_are 0

  installed_host
  inst_drop_in_changed=1
  run_install
  expect "executor drop-in changed: only the executor restarts" restarts_are 'restart nebula-executor.service'

  installed_host
  inst_server_drop_in_changed=1
  run_install
  expect "server drop-in changed: only the server restarts" restarts_are 'restart nebula-server.service'

  installed_host
  stub_active=nebula-server.service
  run_install
  expect "stopped executor: started" restarts_are 'restart nebula-executor.service'
  expect "stopped executor: reported as started" out_has 'started nebula-executor (was not active)'

  # A masked unit is the admin's decision: it is kept, not enabled, not
  # started, and the install runs to its end, so that the other units still
  # get their restart. Masking a running unit does not stop it, hence the
  # stubbed services stay active.
  for unit in "${install_units[@]}"; do
    installed_host
    ln -sf /dev/null "$refresh_sb/etc/$unit"
    ship "$unit" "$unit v2"
    inst_bin_changed=1
    run_install
    expect "masked ${unit}: the install runs to its end" rc_is 0
    expect "masked ${unit}: the end is reached" out_has $'\nEND'
    expect "masked ${unit}: the mask is kept" is_mask_link "$refresh_sb/etc/$unit"
    expect "masked ${unit}: the shipped baseline stays recorded" manifest_has "$(text_sum "$unit v1")" "$unit"
    expect "masked ${unit}: not enabled" not_called "enable --now $unit"
    expect "masked ${unit}: not enabled (executor form)" not_called "enable $unit"
    expect "masked ${unit}: not restarted" not_called "restart $unit"
    expect "masked ${unit}: not try-restarted" not_called "try-restart $unit"
  done

  installed_host
  ln -sf /dev/null "$refresh_sb/etc/nebula-discovery.timer"
  inst_bin_changed=1
  run_install
  expect "masked timer: the warning names the unit" out_has 'warning: nebula-discovery.timer is masked'
  expect "masked timer: the warning says how to undo it" out_has 'systemctl unmask nebula-discovery.timer'
  expect "masked timer: the other units are still enabled" called 'enable --now nebula-discovery.path'
  expect "masked timer: the services still restart" restarts_are $'restart nebula-server.service\nrestart nebula-executor.service'

  # The stub must refuse what systemd refuses, or the cases below prove nothing.
  discovery=nebula-discovery.service
  installed_host
  ln -sf /dev/null "$refresh_sb/etc/$discovery"
  for trigger in nebula-discovery.path nebula-discovery.timer; do
    stub_active="$both_services"
    expect "stub: refuses enable --now on stopped ${trigger}, target masked" stub_refuses enable --now "$trigger"
    expect "stub: refuses restart of stopped ${trigger}, target masked" stub_refuses restart "$trigger"
    expect "stub: enable alone starts nothing on ${trigger}" stub_accepts enable "$trigger"
    expect "stub: try-restart leaves stopped ${trigger} alone" stub_accepts try-restart "$trigger"
    stub_active="$both_services $trigger"
    expect "stub: enable --now on running ${trigger} starts nothing" stub_accepts enable --now "$trigger"
    expect "stub: refuses try-restart of running ${trigger}, target masked" stub_refuses try-restart "$trigger"
  done
  rm -f "$refresh_sb/etc/$discovery"
  stub_active="$both_services"
  expect "stub: accepts enable --now without a mask" stub_accepts enable --now nebula-discovery.path

  # systemd refuses to start a stopped path or timer unit whose target is
  # masked, so both stay as they are and the run reaches the executor restart
  # and the pending cleanup. <how> names one way to mask nebula-discovery.service.
  while read -r how; do
    installed_host
    ship nebula-server.service 'nebula-server.service v2'
    case "$how" in
      link) ln -sf /dev/null "$refresh_sb/etc/$discovery" ;;
      empty) : > "$refresh_sb/etc/$discovery" ;;
      runtime) stub_runtime_masked="$discovery" ;;
    esac
    inst_bin_changed=1
    run_install
    expect "masked target (${how}): the install runs to its end" rc_is 0
    expect "masked target (${how}): the end is reached" out_has $'\nEND'
    expect "masked target (${how}): the path unit is not enabled" not_called 'enable --now nebula-discovery.path'
    expect "masked target (${how}): the timer is not enabled" not_called 'enable --now nebula-discovery.timer'
    expect "masked target (${how}): the warning names the path unit" out_has "warning: nebula-discovery.path starts $discovery, which is masked"
    expect "masked target (${how}): the warning names the timer" out_has "warning: nebula-discovery.timer starts $discovery, which is masked"
    expect "masked target (${how}): the warning says how to undo it" out_has "systemctl unmask $discovery"
    expect "masked target (${how}): the services still restart" restarts_are $'restart nebula-server.service\nrestart nebula-executor.service'
    expect "masked target (${how}): nothing stays pending" nothing_pending
  done <<'CASES'
link
empty
runtime
CASES

  # What counts is the Unit= systemd reports, not the name of the trigger.
  installed_host
  printf 'Unit=nebula-pve-collector.service\n' > "$refresh_sb/etc/nebula-discovery.path"
  ln -sf /dev/null "$refresh_sb/etc/nebula-pve-collector.service"
  run_install
  expect "other Unit= masked: the install runs to its end" rc_is 0
  expect "other Unit= masked: the trigger is not enabled" not_called 'enable --now nebula-discovery.path'
  expect "other Unit= masked: the warning names the target" out_has 'nebula-discovery.path starts nebula-pve-collector.service, which is masked'
  expect "other Unit= masked: the timer of an unmasked target is enabled" called 'enable --now nebula-discovery.timer'

  # A running trigger stays running: a restart would stop it for good.
  installed_host
  ln -sf /dev/null "$refresh_sb/etc/$discovery"
  ship nebula-discovery.path 'nebula-discovery.path v2'
  stub_active="$both_services nebula-discovery.path"
  run_install
  expect "running trigger, masked target: the install runs to its end" rc_is 0
  expect "running trigger, masked target: not try-restarted" not_called 'try-restart nebula-discovery.path'
  expect "running trigger, masked target: no failed restart reported" out_lacks 'could not restart'

  # Package mode walks the same loop, and unmasking brings the triggers back.
  installed_host
  ln -sf /dev/null "$refresh_sb/etc/$discovery"
  inst_from_package=1
  run_install
  expect "package mode, masked target: the install runs to its end" rc_is 0
  expect "package mode, masked target: the path unit is not enabled" not_called 'enable --now nebula-discovery.path'
  expect "package mode, masked target: the timer is not enabled" not_called 'enable --now nebula-discovery.timer'
  expect "package mode, masked target: the others are enabled" called 'enable --now nebula-server.service'
  inst_from_package=0
  rm -f "$refresh_sb/etc/$discovery"
  run_install
  expect "unmasked target: the path unit is enabled again" called 'enable --now nebula-discovery.path'
  expect "unmasked target: the timer is enabled again" called 'enable --now nebula-discovery.timer'

  installed_host
  ln -sf /dev/null "$refresh_sb/etc/nebula-executor.service"
  stub_active=nebula-server.service
  run_install
  expect "masked, stopped executor: the install runs to its end" rc_is 0
  expect "masked, stopped executor: not started" not_called 'restart nebula-executor.service'

  # systemd also takes an empty file for a mask, and a mask under /run leaves
  # the file in /etc as it is.
  installed_host
  : > "$refresh_sb/etc/nebula-discovery.path"
  run_install
  expect "empty unit file: the install runs to its end" rc_is 0
  expect "empty unit file: not enabled" not_called 'enable --now nebula-discovery.path'
  expect "empty unit file: kept" has_content "$refresh_sb/etc/nebula-discovery.path" ''

  installed_host
  stub_runtime_masked=nebula-server.service
  inst_bin_changed=1
  run_install
  expect "runtime-masked server: the install runs to its end" rc_is 0
  expect "runtime-masked server: not enabled" not_called 'enable --now nebula-server.service'
  expect "runtime-masked server: not restarted" not_called 'restart nebula-server.service'
  expect "runtime-masked server: the executor still restarts" called 'restart nebula-executor.service'

  # A masked collector that still runs: the restart is due and systemd would
  # refuse it, which under set -e would end the run before the pending record
  # is cleared. The skipped restart stays on record as a restart line, like the
  # server's and the executor's, and nothing else does, so
  # the next run warns again, and restarts it once the mask is gone. <how> names
  # one way to mask it, <inputs> what makes it due.
  for how in link runtime; do
    for inputs in bin unit; do
      name="masked running collector (${how}, ${inputs})"
      installed_host
      ship nebula-server.service 'nebula-server.service v2'
      if [[ "$inputs" == unit ]]; then
        ship nebula-pve-collector.service 'nebula-pve-collector.service v2'
      else
        inst_bin_changed=1
      fi
      case "$how" in
        link) ln -sf /dev/null "$refresh_sb/etc/nebula-pve-collector.service" ;;
        runtime) stub_runtime_masked=nebula-pve-collector.service ;;
      esac
      stub_active="$all_services"
      run_install
      expect "${name}: the install runs to its end" rc_is 0
      expect "${name}: the end is reached" out_has $'\nEND'
      expect "${name}: not restarted in any form" collector_restarts_are 0
      expect "${name}: the executor is not asked for it" not_probed
      expect "${name}: the server still restarts" called 'restart nebula-server.service'
      if [[ "$how" == link && "$inputs" == unit ]]; then
        # The link keeps the unit, so nothing makes the restart due.
        expect "${name}: nothing stays pending" nothing_pending
        expect "${name}: nothing was due, nothing to warn about" out_lacks 'not restarting it'
      else
        expect "${name}: the warning says it was not restarted" out_has 'nebula-pve-collector.service is masked; not restarting it'
        expect "${name}: only the collector stays pending" pending_is restart nebula-pve-collector.service
        inst_bin_changed=0
        run_install
        expect "${name}: the next run warns again" out_has 'nebula-pve-collector.service is masked; not restarting it'
        expect "${name}: the next run restarts nothing" restarts_are ''
        expect "${name}: it stays pending" pending_is restart nebula-pve-collector.service
        if [[ "$how" == runtime ]]; then
          stub_runtime_masked=""
          run_install
          expect "${name}: unmasked, it restarts once" restarts_are 'restart nebula-pve-collector.service'
          expect "${name}: unmasked, nothing stays pending" nothing_pending
        fi
      fi
    done
  done

  # The same in package mode, where the units are not looked at otherwise.
  installed_host
  ln -sf /dev/null "$refresh_sb/etc/nebula-pve-collector.service"
  ln -sf /dev/null "$refresh_sb/etc/nebula-executor.service"
  inst_from_package=1
  run_install
  expect "package mode, masked units: the install runs to its end" rc_is 0
  expect "package mode, masked units: not enabled" not_called 'enable --now nebula-pve-collector.service'
  expect "package mode, masked executor: not enabled" not_called 'enable nebula-executor.service'
  expect "package mode, masked units: the others are enabled" called 'enable --now nebula-server.service'

  # A run that stops after units_manifest moved must not lose the restart it
  # owes: the next run finds the unit up to date, and nothing else says that
  # the running service still has the old unit.
  # <replaced unit> <the failing call> <the restart the next run must make>
  while IFS='|' read -r unit failing want_restart; do
    installed_host
    ship "$unit" "$unit v2"
    stub_active="$all_services"
    stub_fail="$failing"
    run_install
    expect "stopped at '${failing}': the run fails" rc_not_zero
    expect "stopped at '${failing}': the checksum file moved on" manifest_has "$(text_sum "$unit v2")" "$unit"
    expect "stopped at '${failing}': the restart stays pending" pending_has "$(text_sum "$unit v2")" "$unit"
    stub_fail=""
    run_install
    expect "stopped at '${failing}': the next run succeeds" rc_is 0
    expect "stopped at '${failing}': the next run restarts ${unit}" restarts_are "$want_restart"
    expect "stopped at '${failing}': nothing stays pending" nothing_pending
    run_install
    expect "stopped at '${failing}': the run after that restarts nothing" restarts_are ''
  done <<'CASES'
nebula-server.service|restart nebula-server.service|restart nebula-server.service
nebula-executor.service|restart nebula-executor.service|restart nebula-executor.service
nebula-pve-collector.service|enable --now nebula-discovery.timer|restart nebula-pve-collector.service
CASES

  # A complete run leaves nothing behind.
  installed_host
  ship nebula-server.service 'nebula-server.service v2'
  run_install
  expect "complete run: nothing stays pending" nothing_pending

  # A package run does not look at the units, so it leaves the record alone.
  installed_host
  ship nebula-server.service 'nebula-server.service v2'
  stub_fail='restart nebula-server.service'
  run_install
  stub_fail=""
  inst_from_package=1
  run_install
  expect "package run: a pending restart stays recorded" pending_has "$(text_sum 'nebula-server.service v2')" nebula-server.service
  inst_from_package=0
  run_install
  expect "package run: the next tarball run still restarts" restarts_are 'restart nebula-server.service'

  # A unit a run stopped on is masked before the next run: no restart then.
  installed_host
  ship nebula-server.service 'nebula-server.service v2'
  stub_fail='restart nebula-server.service'
  run_install
  stub_fail=""
  ln -sf /dev/null "$refresh_sb/etc/nebula-server.service"
  run_install
  expect "masked after a stop: the install runs to its end" rc_is 0
  expect "masked after a stop: not restarted" restarts_are ''
  expect "masked after a stop: nothing stays pending" nothing_pending

  # A run that stops between replacing a unit and rewriting units_manifest
  # leaves a shipped version that the record does not know. A newer tarball
  # must still replace it: it was never edited.
  installed_host
  server=nebula-server.service
  ship "$server" "$server v2"
  stub_stop_at_manifest=1
  run_install
  expect "stopped before the rewrite: the run fails" rc_not_zero
  expect "stopped before the rewrite: the unit was replaced" has_content "$refresh_sb/etc/$server" "$server v2"
  expect "stopped before the rewrite: the checksum file is old" manifest_has "$(text_sum "$server v1")" "$server"
  stub_stop_at_manifest=0
  ship "$server" "$server v3"
  run_install
  expect "newer tarball after a stop: the run succeeds" rc_is 0
  expect "newer tarball after a stop: the shipped fix arrives" has_content "$refresh_sb/etc/$server" "$server v3"
  expect "newer tarball after a stop: no warning" out_lacks 'warning'
  expect "newer tarball after a stop: the new checksum is recorded" manifest_has "$(text_sum "$server v3")" "$server"
  expect "newer tarball after a stop: the service restarts" restarts_are "restart $server"
  expect "newer tarball after a stop: nothing stays pending" nothing_pending

  # The record does not protect less than before: an edit made after the stop
  # is the admin's, and it does not become a baseline.
  installed_host
  ship "$server" "$server v2"
  stub_stop_at_manifest=1
  run_install
  stub_stop_at_manifest=0
  printf 'admin edit\n' > "$refresh_sb/etc/$server"
  ship "$server" "$server v3"
  run_install
  expect "edit after a stop: kept" has_content "$refresh_sb/etc/$server" 'admin edit'
  expect "edit after a stop: warned about" out_has "warning: $refresh_sb/etc/$server"
  expect "edit after a stop: the old baseline stays recorded" manifest_has "$(text_sum "$server v1")" "$server"
  expect "edit after a stop: the edit is not recorded" manifest_lacks_sum "$(text_sum 'admin edit')"
  expect "edit after a stop: not restarted" restarts_are ''

  # The same for the collector: a first install that stopped after the
  # collector was enabled and started leaves its unit version on record, which
  # is no restart. An edit made after that stop is kept and owes no restart.
  reset_refresh
  reset_install
  for unit in "${install_units[@]}"; do
    ship "$unit" "$unit v1"
  done
  stub_active="$all_services"
  stub_fail='enable --now nebula-discovery.timer'
  run_install
  expect "collector edit after a first-install stop: the run fails" rc_not_zero
  expect "collector edit after a first-install stop: the collector was started" called "enable --now $collector"
  expect "collector edit after a first-install stop: its unit version is on record" pending_has "$(text_sum "$collector v1")" "$collector"
  stub_fail=""
  printf 'admin edit\n' > "$refresh_sb/etc/$collector"
  run_install
  expect "collector edit after a first-install stop: the re-run succeeds" rc_is 0
  expect "collector edit after a first-install stop: kept" has_content "$refresh_sb/etc/$collector" 'admin edit'
  expect "collector edit after a first-install stop: not restarted in any form" collector_restarts_are 0
  expect "collector edit after a first-install stop: nothing asked" not_probed
  expect "collector edit after a first-install stop: nothing stays pending" nothing_pending

  # The same for a unit installed for the first time, which has no record at
  # all, and on a pre-manifest host, where the old version came from the list.
  reset_refresh
  reset_install
  for unit in "${install_units[@]}"; do
    ship "$unit" "$unit v1"
  done
  stub_stop_at_manifest=1
  run_install
  stub_stop_at_manifest=0
  ship "$server" "$server v2"
  run_install
  expect "first install after a stop: the shipped fix arrives" has_content "$refresh_sb/etc/$server" "$server v2"
  expect "first install after a stop: no warning" out_lacks 'warning'

  installed_host
  rm -f "$refresh_sb/var/units.sha256"
  inst_legacy="$(text_sum "$server v1")  $server"
  ship "$server" "$server v2"
  stub_stop_at_manifest=1
  run_install
  stub_stop_at_manifest=0
  ship "$server" "$server v3"
  run_install
  expect "pre-manifest host after a stop: the shipped fix arrives" has_content "$refresh_sb/etc/$server" "$server v3"
  expect "pre-manifest host after a stop: the unit is recorded" manifest_has "$(text_sum "$server v3")" "$server"

  # The checksum goes on record before the file is written, not after.
  installed_host
  ship "$server" "$server v2"
  stub_stop_at_unit="$server"
  run_install
  stub_stop_at_unit=""
  expect "stopped while writing a unit: the run fails" rc_not_zero
  expect "stopped while writing a unit: the file is unchanged" has_content "$refresh_sb/etc/$server" "$server v1"
  expect "stopped while writing a unit: the version is on record" pending_has "$(text_sum "$server v2")" "$server"
  run_install
  expect "stopped while writing a unit: the next run finishes it" has_content "$refresh_sb/etc/$server" "$server v2"

  # Damage to the record can only make a unit look edited.
  installed_host
  printf 'admin edit\n' > "$refresh_sb/etc/$server"
  ship "$server" "$server v2"
  printf 'not-a-checksum  %s\n\nx\n%s  x%s\n' "$server" "$(text_sum 'admin edit')" "$server" > "$refresh_sb/var/units.pending"
  run_install
  expect "damaged pending file: the run succeeds" rc_is 0
  expect "damaged pending file: the unit is kept" has_content "$refresh_sb/etc/$server" 'admin edit'

  # A restart that new binaries left due says nothing about the unit file: an
  # edited unit stays, and still gets its restart.
  installed_host
  printf 'admin edit\n' > "$refresh_sb/etc/$server"
  ship "$server" "$server v2"
  printf 'restart  %s\n' "$server" > "$refresh_sb/var/units.pending"
  run_install
  expect "restart on record, edited unit: the run succeeds" rc_is 0
  expect "restart on record, edited unit: the edit is kept" has_content "$refresh_sb/etc/$server" 'admin edit'
  expect "restart on record, edited unit: it restarts, once" restarts_are "restart $server"
  expect "restart on record, edited unit: nothing stays pending" nothing_pending
fi

# --- Network device collector deployment (ADR 0010 ND-15) --------------------
# The netdev collector runs like the PVE collector: its own system user in
# nebula-rpc, no capabilities, no network (AF_UNIX only), and the spool as
# its only writable path. Its spool is one flat directory that
# internal/netdevcollect/spool.go expects owned by the collector and the
# shared nebula-rpc group, mode 2770 (the server unlinks what it imported).
# install.sh installs the unit but never enables it: devices are registered
# in the executor after the install, so the admin enables the collector.
netdev_unit="${script_dir}/systemd/nebula-netdev-collector.service"
pve_unit="${script_dir}/systemd/nebula-pve-collector.service"
netdev_spool_go="${script_dir}/../internal/netdevcollect/spool.go"
if [[ ! -f "$netdev_unit" ]]; then
  echo "FAIL ${netdev_unit} is missing"
  fail=$((fail + 1))
else
  # The sandbox block of the unit (from "# Hardening" to [Install]) equals
  # the PVE collector's, apart from the one spool path it may write.
  hardening_of() {
    sed -n '/^# Hardening$/,/^\[Install\]$/p' "$1" | grep -v '^#' | grep -v '^ReadWritePaths='
  }
  netdev_hardening=$(hardening_of "$netdev_unit")
  if [[ -n "$netdev_hardening" && "$netdev_hardening" == "$(hardening_of "$pve_unit")" ]]; then
    echo "ok   netdev unit: sandbox options identical to the pve collector's"
    pass=$((pass + 1))
  else
    echo "FAIL netdev unit: sandbox options differ from the pve collector's"
    diff <(hardening_of "$pve_unit") <(printf '%s\n' "$netdev_hardening") | sed 's/^/     /'
    fail=$((fail + 1))
  fi
  for line in \
    'User=nebula-netdev-collector' \
    'Group=nebula-netdev-collector' \
    'SupplementaryGroups=nebula-rpc' \
    'NoNewPrivileges=yes' \
    'CapabilityBoundingSet=' \
    'AmbientCapabilities=' \
    'RestrictAddressFamilies=AF_UNIX' \
    'ProtectSystem=strict' \
    'ProtectHome=yes' \
    'PrivateDevices=yes' \
    'RestrictSUIDSGID=yes' \
    'UMask=0077' \
    'ReadWritePaths=/var/lib/nebula/netdev' \
    '  -spool /var/lib/nebula/netdev \' \
    '  -socket /run/nebula/executor.sock \' \
    '  -executor-user nebula-executor \' \
    'ExecStart=/usr/bin/nebula-netdev-collector \'; do
    check_line "netdev unit has: ${line}" "$netdev_unit" "$line"
  done
  # Exactly one write path and one address family; no other grant.
  if [[ $(grep -c '^ReadWritePaths=' "$netdev_unit") == 1 &&
        $(grep -c '^RestrictAddressFamilies=' "$netdev_unit") == 1 &&
        $(grep -cE '^(AmbientCapabilities|CapabilityBoundingSet)=.' "$netdev_unit") == 0 &&
        $(grep -cE '^(PrivateNetwork=no|User=root|PermissionsStartOnly|ReadOnlyPaths|BindPaths|SupplementaryGroups=.*[[:space:]])' "$netdev_unit") == 0 ]]; then
    echo "ok   netdev unit: one write path, AF_UNIX only, no capabilities, no extra grants"
    pass=$((pass + 1))
  else
    echo "FAIL netdev unit grants more than the spool, AF_UNIX and nebula-rpc"
    fail=$((fail + 1))
  fi
  # The spool, user and executor flags match the collector's defaults.
  if grep -qxF '	defaultSpool        = "/var/lib/nebula/netdev"' "${script_dir}/../cmd/nebula-netdev-collector/main.go" &&
     grep -qF 'RoleNetDevCollector: {Flag: "netdev-collector-user", DefaultUser: "nebula-netdev-collector"}' "${script_dir}/../internal/peercred/collector.go"; then
    echo "ok   netdev unit: spool path and user match the collector and executor defaults"
    pass=$((pass + 1))
  else
    echo "FAIL netdev unit: spool path or user no longer match cmd/nebula-netdev-collector or internal/peercred"
    fail=$((fail + 1))
  fi
  # Nothing imports the spool before ND-16: the unit must not claim the
  # server imports it, and must say to enable it only once that import is in.
  if ! grep -qi 'server imports' "$netdev_unit" &&
     grep -qF '# Off by default' "$netdev_unit" &&
     grep -qF '# shares with the executor database. Enable it only once the server import' "$netdev_unit"; then
    echo "ok   netdev unit: off by default, enable only once the server import (ND-16) is installed"
    pass=$((pass + 1))
  else
    echo "FAIL netdev unit: must say it is off by default until the server import (ND-16), and not claim an import"
    fail=$((fail + 1))
  fi
fi
check_line "install.sh: next steps keep the netdev collector off until ND-16" "$install_sh" \
  '     but off. Leave it off until the server import of its spool (ND-16)'
# The provisioned spool state is what the collector's spool code checks.
if grep -qF 'spoolDirMode = os.FileMode(0o770) | os.ModeSetgid' "$netdev_spool_go" &&
   grep -qF 'const spoolGroupName = "nebula-rpc"' "$netdev_spool_go"; then
  echo "ok   netdevcollect still expects mode 2770 and group nebula-rpc"
  pass=$((pass + 1))
else
  echo "FAIL internal/netdevcollect/spool.go changed its spool mode or group; update install.sh, the postinst and the Dockerfile"
  fail=$((fail + 1))
fi
check_line "install.sh creates the netdev collector user" "$install_sh" \
  '  useradd --system --home-dir "${var_lib}/netdev" --shell /usr/sbin/nologin -G "${group_name}" nebula-netdev-collector'
check_line "install.sh provisions the netdev spool 2770 collector:nebula-rpc" "$install_sh" \
  'install -d -m 2770 -o nebula-netdev-collector -g nebula-rpc "${var_lib}/netdev"'
check_line "install.sh rejects the netdev collector as an admin user" "$install_sh" \
  '    root|nebula-server|nebula-executor|nebula-discovery|nebula-pve-collector|nebula-netdev-collector)'
# The unit is installed (tarball list) but never enabled: not in the
# package list, and the enable loop skips it.
if printf '%s\n' "$tarball_list" | grep -qxF nebula-netdev-collector.service &&
   ! printf '%s\n' "$package_list" | grep -qxF nebula-netdev-collector.service; then
  echo "ok   netdev unit is installed from the tarball and not in the package enable list"
  pass=$((pass + 1))
else
  echo "FAIL netdev unit: must be in tarball_units and not in package_units"
  fail=$((fail + 1))
fi
check_line "install.sh: the enable loop skips the netdev collector" "$install_sh" \
  '  if [[ "${name}" == "nebula-netdev-collector.service" ]]; then'
# Compose: the netdev collector has no network, no capabilities, its own
# UID, the rpc volume and its own spool volume, and starts only with the
# netdev profile.
netdev_compose=$(awk '/^  netdev-collector:$/{f=1;print;next} f&&/^  [a-z]/{exit} f&&/^[a-z]/{exit} f{print}' "$compose_yaml")
netdev_compose_ok=1
for line in \
  '    <<: *hardening' \
  '    user: "10005:10005"' \
  '    group_add: ["10010"]' \
  '    network_mode: none' \
  '    profiles: [netdev]' \
  '      - nebula-netdev-collector' \
  '      - -spool=/var/lib/nebula/netdev' \
  '      - rpc:/run/nebula' \
  '      - netdev-spool:/var/lib/nebula/netdev'; do
  if ! printf '%s\n' "$netdev_compose" | grep -qxF -- "$line"; then
    echo "FAIL compose netdev-collector lacks: ${line}"
    netdev_compose_ok=0
  fi
done
if printf '%s\n' "$netdev_compose" | grep -qE 'cap_add|network_mode: host|ports:|privileged|executor-data'; then
  echo "FAIL compose netdev-collector gets capabilities, a network, ports or the executor data"
  netdev_compose_ok=0
fi
if [[ $(printf '%s\n' "$netdev_compose" | grep -c '^      - [a-z-]*:/') != 2 ]]; then
  echo "FAIL compose netdev-collector mounts more than the rpc and spool volumes"
  netdev_compose_ok=0
fi
if [[ $netdev_compose_ok -eq 1 ]]; then
  echo "ok   compose netdev-collector: own UID, no network, no capabilities, rpc and spool volumes only, netdev profile"
  pass=$((pass + 1))
else
  fail=$((fail + 1))
fi
dockerfile="${script_dir}/container/Dockerfile"
check_line "Dockerfile creates the netdev collector user (UID 10005, nebula-rpc)" "$dockerfile" \
  ' && useradd --system --uid 10005 --gid 10005 --groups nebula-rpc --home-dir /var/lib/nebula/netdev --shell /usr/sbin/nologin nebula-netdev-collector \'
check_line "Dockerfile provisions the netdev spool 2770 collector:nebula-rpc" "$dockerfile" \
  ' && install -d -m 2770 -o nebula-netdev-collector -g nebula-rpc /var/lib/nebula/netdev \'
if grep -qE '^COPY .* nebula-netdev-collector .*/usr/bin/$' "$dockerfile"; then
  echo "ok   Dockerfile copies the netdev collector binary"
  pass=$((pass + 1))
else
  echo "FAIL Dockerfile does not copy nebula-netdev-collector"
  fail=$((fail + 1))
fi

# Functional, no root needed: the real netdev provisioning block of
# install.sh with stubbed getent, useradd and install, run twice. The first
# run creates the user and the spool; the second creates no user again and
# re-applies the same spool state. A file or symlink at the spool path stops
# the install before install -d follows it.
netdev_block=$(sed -n '/^# begin: netdev collector provisioning/,/^# end: netdev collector provisioning/p' "$install_sh")
netdev_sb=$(mktemp -d)
trap 'rm -rf "$refresh_sb" "$pve_sb" "$netdev_sb"' EXIT
run_netdev_block() {
  netdev_out=$(
    exec 2>&1
    set -euo pipefail
    getent() { grep -qxF "$2" "$netdev_sb/users"; }
    useradd() {
      printf 'useradd %s\n' "$*" >> "$netdev_sb/calls"
      printf '%s\n' "${*: -1}" >> "$netdev_sb/users"
    }
    install() {
      printf 'install %s\n' "$*" >> "$netdev_sb/calls"
      mkdir -p "${*: -1}"
      chmod "$3" "${*: -1}"
    }
    var_lib="$netdev_sb/var"
    group_name=nebula-rpc
    eval "$netdev_block"
    echo "END"
  )
  netdev_rc=$?
  refresh_out="$netdev_out" # expect prints it on a failure
}
netdev_reset() {
  rm -rf "$netdev_sb/var" "$netdev_sb/calls" "$netdev_sb/target"
  mkdir -p "$netdev_sb/var"
  : > "$netdev_sb/users"
  : > "$netdev_sb/calls"
}
netdev_rc_is() { [[ "$netdev_rc" -eq "$1" ]]; }
netdev_calls_are() { [[ "$(cat "$netdev_sb/calls")" == "$1" ]]; }
netdev_spool_mode_is() { [[ "$(stat -c '%a' "$netdev_sb/var/netdev")" == "$1" ]]; }
netdev_out_has() { [[ "$netdev_out" == *"$1"* ]]; }
if [[ -z "$netdev_block" ]]; then
  echo "FAIL install.sh has no netdev collector provisioning block"
  fail=$((fail + 1))
else
  netdev_useradd="useradd --system --home-dir $netdev_sb/var/netdev --shell /usr/sbin/nologin -G nebula-rpc nebula-netdev-collector"
  netdev_install="install -d -m 2770 -o nebula-netdev-collector -g nebula-rpc $netdev_sb/var/netdev"
  netdev_reset
  run_netdev_block
  expect "netdev provisioning: a fresh host succeeds" netdev_rc_is 0
  expect "netdev provisioning: user created, then the spool 2770 collector:nebula-rpc" \
    netdev_calls_are "$netdev_useradd"$'\n'"$netdev_install"
  expect "netdev provisioning: the spool has mode 2770" netdev_spool_mode_is 2770
  : > "$netdev_sb/calls"
  chmod 0700 "$netdev_sb/var/netdev"
  run_netdev_block
  expect "netdev provisioning re-run: succeeds" netdev_rc_is 0
  expect "netdev provisioning re-run: no second user, the same spool state re-applied" \
    netdev_calls_are "$netdev_install"
  expect "netdev provisioning re-run: a drifted spool mode is repaired to 2770" netdev_spool_mode_is 2770
  # The link case runs last, so its target is still there for the check below.
  for how in file link; do
    netdev_reset
    if [[ "$how" == link ]]; then
      mkdir -p "$netdev_sb/target"
      ln -s "$netdev_sb/target" "$netdev_sb/var/netdev"
    else
      printf 'swapped in\n' > "$netdev_sb/var/netdev"
    fi
    run_netdev_block
    expect "netdev provisioning: a ${how} at the spool path is refused" netdev_rc_is 1
    expect "netdev provisioning: a ${how} at the spool path is named" netdev_out_has "$netdev_sb/var/netdev"
    expect "netdev provisioning: a ${how} at the spool path gets no install -d" \
      eval '! grep -q "^install " "$netdev_sb/calls"'
  done
  if [[ -d "$netdev_sb/target" && -z "$(ls -A "$netdev_sb/target")" && "$(stat -c '%a' "$netdev_sb/target")" != 2770 ]]; then
    echo "ok   netdev provisioning: the symlink target is left alone"
    pass=$((pass + 1))
  else
    echo "FAIL netdev provisioning: the symlink target was touched"
    fail=$((fail + 1))
  fi
fi

# Functional: the enable and restart steps with the netdev unit in the
# tarball list. A first install puts the unit file in place but enables
# nothing for it; once the admin runs it, a changed unit is applied with
# try-restart, which touches only a running unit.
if [[ -n "$start_block" ]]; then
  saved_install_units=("${install_units[@]}")
  install_units+=(nebula-netdev-collector.service)
  netdev_svc=nebula-netdev-collector.service
  installed_host
  expect "netdev install: the run succeeds" rc_is 0
  expect "netdev install: the unit file is installed" has_content "$refresh_sb/etc/$netdev_svc" "$netdev_svc v1"
  expect "netdev install: the unit is not enabled" not_called "enable --now $netdev_svc"
  expect "netdev install: the unit is not enabled (without --now)" not_called "enable $netdev_svc"
  expect "netdev install: the unit is not started" eval '! grep -qE "(^| )(start|restart|try-restart) '"$netdev_svc"'$" "$systemctl_log"'
  expect "netdev install: the server is still enabled" called 'enable --now nebula-server.service'
  # Running (the admin enabled it) and the unit changed: try-restart.
  reset_install
  stub_active="$both_services $netdev_svc"
  ship "$netdev_svc" "$netdev_svc v2"
  run_install
  expect "netdev upgrade: the run succeeds" rc_is 0
  expect "netdev upgrade: the changed unit is applied" has_content "$refresh_sb/etc/$netdev_svc" "$netdev_svc v2"
  expect "netdev upgrade: a running collector gets try-restart" called "try-restart $netdev_svc"
  expect "netdev upgrade: the unit is still not enabled by the install" not_called "enable --now $netdev_svc"
  # New binaries and a changed unit in one run: the restart on the pending
  # record and the replaced unit name the collector twice, but it gets one
  # try-restart.
  saved_sandbox_binaries=("${sandbox_binaries[@]}")
  sandbox_binaries+=(nebula-netdev-collector)
  installed_host
  reset_install
  stub_active="$both_services $netdev_svc"
  inst_bin_changed=1
  inst_new_bins="nebula-server nebula-netdev-collector"
  ship "$netdev_svc" "$netdev_svc v2"
  run_install
  expect "netdev binaries and unit changed: the run succeeds" rc_is 0
  expect "netdev binaries and unit changed: the changed unit is applied" has_content "$refresh_sb/etc/$netdev_svc" "$netdev_svc v2"
  expect "netdev binaries and unit changed: one try-restart of the collector" \
    eval '[[ $(grep -cxF "try-restart $netdev_svc" "$systemctl_log") -eq 1 ]]'
  sandbox_binaries=("${saved_sandbox_binaries[@]}")
  # Package mode never enables it either.
  reset_install
  inst_from_package=1
  run_install
  expect "netdev package mode: the unit is not enabled" not_called "enable --now $netdev_svc"
  install_units=("${saved_install_units[@]}")
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
