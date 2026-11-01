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

scheme=$NEBULA_P_INFLUX_SCHEME
host=$NEBULA_P_INFLUX_HOST
org=$NEBULA_P_INFLUX_ORG
bucket=$NEBULA_P_INFLUX_BUCKET
printf '%s\n' "$host" | grep -Eqx '[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?' || fail "influx_host must be host or host:port"
printf '%s\n' "$org" | grep -Eqx '[a-z][a-z0-9_-]{0,63}' || fail "influx_org is not a valid organization name"
printf '%s\n' "$bucket" | grep -Eqx '[a-z][a-z0-9_-]{0,63}' || fail "influx_bucket is not a valid bucket name"
export DEBIAN_FRONTEND=noninteractive
. /etc/os-release
codename=$VERSION_CODENAME
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg
[ -n "${NEBULA_RUN_DIR:-}" ] || fail "NEBULA_RUN_DIR is not set"
key="$NEBULA_RUN_DIR/nebula-influxdata-key"
curl -fsSL "https://repos.influxdata.com/influxdata-archive.key" -o "$key"
# Pin the full primary-key fingerprint of the InfluxData apt signing key so a
# substituted key is rejected before anything is installed. The key is the
# "InfluxData Package Signing Key", documented in InfluxData's install docs
# (https://docs.influxdata.com/influxdb/v1/introduction/install/) and served
# at https://repos.influxdata.com/influxdata-archive.key.
nebula_check_repo_key "$key" 24C975CBA61A024EE1B631787C3D57159FC2F927
gpg --dearmor -o /usr/share/keyrings/influxdata-archive-keyring.gpg "$key"
rm -f "$key"
printf 'deb [signed-by=/usr/share/keyrings/influxdata-archive-keyring.gpg] https://repos.influxdata.com/debian %s main\n' "$codename" > /etc/apt/sources.list.d/influxdata.list
apt-get update -qq
apt-get install -y -qq telegraf
install -d -m 0755 /etc/telegraf/telegraf.d
printf '[[outputs.influxdb_v2]]\n  urls = ["%s://%s"]\n  token_file = "/etc/telegraf/telegraf.d/nebula.token"\n  organization = "%s"\n  bucket = "%s"\n' "$scheme" "$host" "$org" "$bucket" > /etc/telegraf/telegraf.d/nebula.conf
install -m 0600 "$NEBULA_SECRET_INFLUX_TOKEN" /etc/telegraf/telegraf.d/nebula.token
systemctl restart telegraf
emit true action install
