# Idempotent: re-running reconciles the component to the module's state.
set -eu

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

json_escape() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\\"/g'
}

emit() {
  {
    printf '{"ok":%s' "$1"
    shift
    while [ "$#" -ge 2 ]; do
      printf ',"%s":"%s"' "$(json_escape "$1")" "$(json_escape "$2")"
      shift 2
    done
    printf '}\n'
  } > "$NEBULA_RESULT"
}
dropin=/etc/ssh/sshd_config.d/90-nebula-hardening.conf

render_config() {
  printf '# Managed by the Nebula ssh-hardening module. Do not edit.\n'
  printf 'Port %s\n' "$1"
  printf 'PermitRootLogin no\n'
  if [ "$4" = password ]; then
    printf 'PasswordAuthentication yes\n'
  else
    printf 'PasswordAuthentication no\n'
  fi
  printf 'KbdInteractiveAuthentication no\n'
  printf 'X11Forwarding no\n'
  printf 'MaxAuthTries 4\n'
  printf 'AllowUsers %s\n' "$(printf '%s' "$2" | tr ':' ' ')"
  printf 'AllowGroups %s\n' "$(printf '%s' "$3" | tr ':' ' ')"
}

port=$NEBULA_P_PORT
users=$NEBULA_P_ALLOW_USERS
groups=$NEBULA_P_ALLOW_GROUPS
auth=$NEBULA_P_AUTH

[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || fail "port out of range"
list=$users
what=allow_users
[ -n "$list" ] || fail "$what is empty"
old_ifs=$IFS
IFS=:
set -- $list
IFS=$old_ifs
for w in "$@"; do
  printf '%s\n' "$w" | grep -Eqx '[a-z][a-z0-9_-]{0,29}' || fail "$what: invalid entry $w"
done

list=$groups
what=allow_groups
[ -n "$list" ] || fail "$what is empty"
old_ifs=$IFS
IFS=:
set -- $list
IFS=$old_ifs
for w in "$@"; do
  printf '%s\n' "$w" | grep -Eqx '[a-z][a-z0-9_-]{0,29}' || fail "$what: invalid entry $w"
done

run_dir=${NEBULA_RUN_DIR:-/tmp}
candidate=$(mktemp "$run_dir/nebula-sshd-candidate.XXXXXX")
testconf=$(mktemp "$run_dir/nebula-sshd-testconf.XXXXXX")
render_config "$port" "$users" "$groups" "$auth" > "$candidate"
{
  cat /etc/ssh/sshd_config
  printf 'Include %s\n' "$candidate"
} > "$testconf"
if ! sshd -t -f "$testconf" 2>"$run_dir/nebula-sshd-err"; then
  cat "$run_dir/nebula-sshd-err" >&2
  rm -f "$candidate" "$testconf"
  fail "sshd -t rejects the new configuration"
fi
rm -f "$testconf"
install -d -m 0755 /etc/ssh/sshd_config.d
install -m 0644 "$candidate" "$dropin"
rm -f "$candidate"
systemctl reload-or-restart ssh
emit true action update port "$port" auth "$auth"
