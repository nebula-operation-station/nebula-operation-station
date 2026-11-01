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

port=$NEBULA_P_SSH_PORT
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || fail "ssh_port out of range"
problems=
ufw status 2>/dev/null | grep -q '^Status: active' || problems="ufw"
ufw status 2>/dev/null | grep -Eq "^$port/tcp" || problems="$problems ssh port"
fail2ban-client status sshd >/dev/null 2>&1 || problems="$problems sshd jail"
if [ -n "$problems" ]; then
  emit false action verify problems "$problems"
  exit 1
fi
emit true action verify ssh_port "$port"
