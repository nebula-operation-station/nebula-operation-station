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

zone=${NEBULA_P_ZONE#/}
[ -f "/usr/share/zoneinfo/$zone" ] || fail "no such IANA zone: $zone"
ln -sf "/usr/share/zoneinfo/$zone" /etc/localtime
printf '%s\n' "$zone" > /etc/timezone
emit true action install zone "$zone"
