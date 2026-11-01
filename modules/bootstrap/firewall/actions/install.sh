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
apt-get install -y -qq ufw fail2ban
ufw default deny incoming
ufw default allow outgoing
ufw allow "$port"/tcp comment 'ssh'
ufw --force enable
install -d -m 0755 /etc/fail2ban/jail.d
printf '[sshd]\nenabled = true\nport = %s\nmode = aggressive\n' "$port" > /etc/fail2ban/jail.d/nebula.conf
systemctl enable fail2ban
systemctl restart fail2ban
emit true action install ssh_port "$port"
