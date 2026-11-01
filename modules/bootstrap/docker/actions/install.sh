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
curl -fsSL "https://download.docker.com/linux/$distro/gpg" -o "${NEBULA_RUN_DIR:-/tmp}/nebula-docker.gpg"
gpg --dearmor -o /etc/apt/keyrings/docker.gpg "${NEBULA_RUN_DIR:-/tmp}/nebula-docker.gpg"
rm -f "${NEBULA_RUN_DIR:-/tmp}/nebula-docker.gpg"
chmod a+r /etc/apt/keyrings/docker.gpg
printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/%s %s stable\n' "$(dpkg --print-architecture)" "$distro" "$codename" > /etc/apt/sources.list.d/docker.list
apt-get update -qq
# shellcheck disable=SC2086
apt-get install -y -qq "docker-ce=$version"* containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable docker
systemctl restart docker
emit true action install version "$version"
