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

problems=
[ -f "$dropin" ] || problems="drop-in missing"
if [ -f "$dropin" ]; then
  run_dir=${NEBULA_RUN_DIR:-/tmp}
  expected=$(mktemp "$run_dir/nebula-sshd-expected.XXXXXX")
  render_config "$port" "$users" "$groups" "$auth" > "$expected"
  cmp -s "$expected" "$dropin" || problems="$problems drop-in differs"
  rm -f "$expected"
fi
if ! sshd -t 2>/dev/null; then
  problems="$problems sshd -t fails"
fi
effective=$(sshd -T 2>/dev/null || true)
printf '%s\n' "$effective" | grep -Eq "^port $port$" || problems="$problems port"
printf '%s\n' "$effective" | grep -Eq '^permitrootlogin no$' || problems="$problems root login"
if [ "$auth" = password ]; then
  printf '%s\n' "$effective" | grep -Eq '^passwordauthentication yes$' || problems="$problems password auth"
else
  printf '%s\n' "$effective" | grep -Eq '^passwordauthentication no$' || problems="$problems password auth"
fi
if [ -n "$problems" ]; then
  emit false action verify problems "$problems"
  exit 1
fi
emit true action verify port "$port" auth "$auth"
