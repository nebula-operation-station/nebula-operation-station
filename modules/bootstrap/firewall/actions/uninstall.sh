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
if command -v ufw >/dev/null 2>&1; then
  ufw --force disable 2>/dev/null || true
  rm -f /etc/fail2ban/jail.d/nebula.conf
  apt-get purge -y -qq ufw fail2ban 2>/dev/null || true
  removed=yes
fi
emit true action uninstall removed "$removed"
