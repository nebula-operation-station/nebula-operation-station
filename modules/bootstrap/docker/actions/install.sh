# Idempotent: re-running reconciles the component to the module's state.
set -eu

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

# nebula_check_repo_key FILE EXPECTED_FPR
# Fails the run unless FILE holds exactly one GPG key and its primary
# fingerprint is EXPECTED_FPR. The fingerprint is pinned from the vendor
# (cited at the call site); a mismatch means the downloaded key is not the
# vendor's, so we stop before installing anything. A second key in the file
# is rejected too: the whole file becomes the signed-by keyring, and apt
# trusts every key in it.
nebula_check_repo_key() {
  keys=$(gpg --show-keys --with-colons "$1" 2>/dev/null) || fail "cannot read repository key"
  n=$(printf '%s\n' "$keys" | grep -c '^pub:') || true
  [ "$n" = 1 ] || fail "repository key file must hold exactly one key, has ${n:-0}"
  fpr=$(printf '%s\n' "$keys" | awk -F: '$1=="pub" {p=1; next} p && $1=="fpr" {print $10; exit}')
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

version=$NEBULA_P_VERSION
printf '%s\n' "$version" | grep -Eqx '[0-9]+(\.[0-9]+)?' || fail "version must be a major or minor number"
export DEBIAN_FRONTEND=noninteractive
. /etc/os-release
distro=$ID
codename=$VERSION_CODENAME
case $distro in
  debian|ubuntu) ;;
  *) fail "unsupported distribution: $distro" ;;
esac
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg
install -d -m 0755 /etc/apt/keyrings
[ -n "${NEBULA_RUN_DIR:-}" ] || fail "NEBULA_RUN_DIR is not set"
key="$NEBULA_RUN_DIR/nebula-docker-key"
curl -fsSL "https://download.docker.com/linux/$distro/gpg" -o "$key"
# Pin the full primary-key fingerprint of the Docker apt signing key so a
# substituted key is rejected before anything is installed. The key is the
# "Docker Release (CE deb)" key, served at
# https://download.docker.com/linux/debian/gpg and documented in Docker's
# install docs (https://docs.docker.com/engine/install/debian/).
nebula_check_repo_key "$key" 9DC858229FC7DD38854AE2D88D81803C0EBFCD88
gpg --dearmor -o /etc/apt/keyrings/docker.gpg "$key"
rm -f "$key"
chmod a+r /etc/apt/keyrings/docker.gpg
printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/%s %s stable\n' "$(dpkg --print-architecture)" "$distro" "$codename" > /etc/apt/sources.list.d/docker.list
apt-get update -qq
# shellcheck disable=SC2086
apt-get install -y -qq "docker-ce=$version"* containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable docker
systemctl restart docker
emit true action install version "$version"
