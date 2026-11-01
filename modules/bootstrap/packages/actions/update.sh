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

list=$NEBULA_P_PACKAGES
what=packages
[ -n "$list" ] || fail "$what is empty"
old_ifs=$IFS
IFS=:
set -- $list
IFS=$old_ifs
for w in "$@"; do
  printf '%s\n' "$w" | grep -Eqx '[a-z][a-z0-9_-]{0,29}' || fail "$what: invalid entry $w"
done

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# shellcheck disable=SC2086
apt-get install --only-upgrade -y -qq $*
emit true action update
