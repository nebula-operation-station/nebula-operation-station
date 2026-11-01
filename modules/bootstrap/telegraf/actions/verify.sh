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

problems=
systemctl is-active telegraf >/dev/null 2>&1 || problems="service"
[ -f /etc/telegraf/telegraf.d/nebula.conf ] || problems="$problems config"
if [ -f /etc/telegraf/telegraf.d/nebula.token ]; then
  [ "$(stat -c %a /etc/telegraf/telegraf.d/nebula.token)" = 600 ] || problems="$problems token permissions"
else
  problems="$problems token"
fi
if [ -n "$problems" ]; then
  emit false action verify problems "$problems"
  exit 1
fi
emit true action verify
