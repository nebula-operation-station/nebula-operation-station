# Idempotent: re-running reconciles the component to the module's state.
set -eu

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

# nebula_check_repo_key FILE EXPECTED_FPR
# Fails the run unless the GPG key in FILE has primary fingerprint
# EXPECTED_FPR. The fingerprint is pinned from the vendor's documentation
# (cited at the call site); a mismatch means the downloaded key is not the
# vendor's, so we stop before installing anything.
nebula_check_repo_key() {
  fpr=$(gpg --show-keys --with-colons "$1" 2>/dev/null | awk -F: '$1=="fpr" {print $10; exit}')
  [ "$fpr" = "$2" ] || fail "repository key fingerprint mismatch: got ${fpr:-<none>}, want $2"
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
[ -n "${NEBULA_RUN_DIR:-}" ] || fail "NEBULA_RUN_DIR is not set"
key="$NEBULA_RUN_DIR/nebula-netbird-key"
curl -fsSL "https://pkgs.netbird.io/debian/public.key" -o "$key"
# Pin the full primary-key fingerprint of the NetBird apt signing key so a
# substituted key is rejected before anything is installed. The key is the
# "Wiretrustee <dev@wiretrustee.com>" key, published in the vendor's
# public-keys repository (https://github.com/netbirdio/public-keys,
# packages/deb.gpg) and served at https://pkgs.netbird.io/debian/public.key
# (https://docs.netbird.io/get-started/install/linux).
nebula_check_repo_key "$key" EFE37DF047DF7CCDF1FC54FA83F79AD029778355
gpg --dearmor -o /etc/apt/keyrings/netbird.gpg "$key"
rm -f "$key"
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
