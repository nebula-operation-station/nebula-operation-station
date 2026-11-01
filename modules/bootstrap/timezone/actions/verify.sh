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
problems=
link=$(readlink /etc/localtime)
[ "$link" = "/usr/share/zoneinfo/$zone" ] || problems="localtime"
file_zone=
[ -r /etc/timezone ] && file_zone=$(head -n 1 /etc/timezone | tr -d '[:space:]')
[ -n "$file_zone" ] && [ "$file_zone" = "$zone" ] || problems="$problems timezone file"
if [ -n "$problems" ]; then
  emit false action verify zone "$zone" problems "$problems"
  exit 1
fi
emit true action verify zone "$zone"
