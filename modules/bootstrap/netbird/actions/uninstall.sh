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

export DEBIAN_FRONTEND=noninteractive
removed=no
if command -v netbird >/dev/null 2>&1; then
  netbird down 2>/dev/null || true
  apt-get purge -y -qq netbird 2>/dev/null || true
  rm -f /etc/apt/sources.list.d/netbird.list /etc/apt/keyrings/netbird.gpg
  removed=yes
fi
emit true action uninstall removed "$removed"
