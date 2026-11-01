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

user=$NEBULA_P_NAME
home=$NEBULA_P_HOME
case $NEBULA_P_SHELL in
  bash) shell=/bin/bash ;;
  sh) shell=/bin/sh ;;
  nologin) shell=/usr/sbin/nologin ;;
esac

printf '%s\n' "$user" | grep -Eqx '[a-z][a-z0-9_-]{0,30}' || fail "name is not a valid login name"
list=$NEBULA_P_GROUPS
what=groups
[ -n "$list" ] || fail "$what is empty"
old_ifs=$IFS
IFS=:
set -- $list
IFS=$old_ifs
for w in "$@"; do
  printf '%s\n' "$w" | grep -Eqx '[a-z][a-z0-9_-]{0,29}' || fail "$what: invalid entry $w"
done

if ! id -u "$user" >/dev/null 2>&1; then
  emit false action verify user "$user" problem "user does not exist"
  exit 1
fi
problems=
actual_shell=$(getent passwd "$user" | cut -d: -f7)
actual_home=$(getent passwd "$user" | cut -d: -f6)
[ "$actual_shell" = "$shell" ] || problems="$problems shell"
[ "$actual_home" = "$home" ] || problems="$problems home"
for g in "$@"; do
  id -nG "$user" | tr ' ' '\n' | grep -qx "$g" || problems="$problems group:$g"
done
if [ -n "$problems" ]; then
  emit false action verify user "$user" problems "${problems# }"
  exit 1
fi
emit true action verify user "$user"
