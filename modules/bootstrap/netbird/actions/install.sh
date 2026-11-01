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

server=$NEBULA_P_SERVER
hostname=$NEBULA_P_HOSTNAME
printf '%s\n' "$server" | grep -Eqx '[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?' || fail "server must be host or host:port"
printf '%s\n' "$hostname" | grep -Eqx '[a-z0-9]([a-z0-9-]*[a-z0-9])?' || fail "hostname must be a lowercase name"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg
install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://pkgs.netbird.io/key.asc | gpg --dearmor > /etc/apt/keyrings/netbird.gpg
chmod a+r /etc/apt/keyrings/netbird.gpg
printf 'deb [arch=%s signed-by=/etc/apt/keyrings/netbird.gpg] https://pkgs.netbird.io/ stable main\n' "$(dpkg --print-architecture)" > /etc/apt/sources.list.d/netbird.list
apt-get update -qq
apt-get install -y -qq netbird
if netbird status 2>/dev/null | grep -q 'connected'; then
  netbird up
  joined=no
else
  # The setup key is one-time and is read from the vault file at the
  # last moment; it never appears in a log or result. It is passed in the
  # environment (NB_SETUP_KEY, readable only by root via /proc/<pid>/environ),
  # never on the command line, where every local user could see it in ps.
  NB_SETUP_KEY=$(head -n 1 "$NEBULA_SECRET_SETUP_KEY") \
    netbird up --server "$server" --hostname "$hostname"
  joined=yes
fi
emit true action install joined "$joined"
