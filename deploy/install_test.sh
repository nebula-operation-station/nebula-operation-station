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
run_rc 1 "empty entry in admin list rejected" -- --admin-users "${test_user},,${test_user}" --rp-id nebula.example.org
run_rc 1 "second of two users missing" -- --admin-users "$test_user,definitely-not-a-user-12345" --rp-id nebula.example.org

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

echo
echo "install_test.sh: ${pass} passed, ${fail} failed"
if [[ "$fail" -gt 0 ]]; then
  exit 1
fi
