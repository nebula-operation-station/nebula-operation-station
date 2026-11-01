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
dpkg-query -W -f='${Status}' qemu-guest-agent 2>/dev/null | grep -q 'install ok installed' || problems="package"
systemctl is-active qemu-guest-agent >/dev/null 2>&1 || problems="$problems service"
if [ -n "$problems" ]; then
  emit false action verify problems "$problems"
  exit 1
fi
emit true action verify
