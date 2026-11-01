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
if command -v telegraf >/dev/null 2>&1; then
  systemctl disable --now telegraf 2>/dev/null || true
  rm -f /etc/telegraf/telegraf.d/nebula.conf /etc/telegraf/telegraf.d/nebula.token
  apt-get purge -y -qq telegraf 2>/dev/null || true
  rm -f /etc/apt/sources.list.d/influxdata.list /usr/share/keyrings/influxdata-archive-keyring.gpg
  removed=yes
fi
emit true action uninstall removed "$removed"
