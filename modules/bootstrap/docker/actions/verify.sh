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

version=$NEBULA_P_VERSION
printf '%s\n' "$version" | grep -Eqx '[0-9]+(\.[0-9]+)?' || fail "version must be a major or minor number"
problems=
command -v docker >/dev/null 2>&1 || problems="engine"
systemctl is-active docker >/dev/null 2>&1 || problems="$problems service"
if command -v docker >/dev/null 2>&1; then
  actual=$(docker --version 2>/dev/null | sed -n 's/.*Docker version \([0-9]*\).*/\1/p')
  [ "$actual" = "${version%%.*}" ] || problems="$problems version"
fi
if [ -n "$problems" ]; then
  emit false action verify problems "$problems"
  exit 1
fi
emit true action verify version "$version"
