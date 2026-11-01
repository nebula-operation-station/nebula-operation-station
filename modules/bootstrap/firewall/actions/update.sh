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
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install --only-upgrade -y -qq ufw fail2ban
ufw allow "$port"/tcp comment 'ssh'
printf '[sshd]\nenabled = true\nport = %s\nmode = aggressive\n' "$port" > /etc/fail2ban/jail.d/nebula.conf
systemctl restart fail2ban
emit true action update ssh_port "$port"
