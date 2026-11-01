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

printf '%s\n' "$user" | grep -Eqx '[a-z][a-z0-9_-]{0,30}' || fail "name is not a valid login name"
removed=no
if id -u "$user" >/dev/null 2>&1; then
  userdel --remove "$user" 2>/dev/null || userdel "$user"
  removed=yes
fi
emit true action uninstall user "$user" removed "$removed"
