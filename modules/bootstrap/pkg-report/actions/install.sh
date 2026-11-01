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

install -d -m 0755 /usr/local/lib/nebula /var/log/nebula
cat > /usr/local/lib/nebula/pkg-report.sh <<'EOF'
#!/bin/sh
# Nebula pkg-report: refresh the apt lists and log the upgradable
# packages. Runs daily from /etc/cron.d/nebula-pkg-report.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
{
  printf '%s pkg-report\n' "$(date -Is)"
  apt list --upgradable 2>/dev/null | tail -n +2 | sed 's/^/  /'
} >> /var/log/nebula/pkg-report.log
EOF
chmod 0755 /usr/local/lib/nebula/pkg-report.sh
printf '15 4 * * * root /usr/local/lib/nebula/pkg-report.sh\n' > /etc/cron.d/nebula-pkg-report
chown root:root /etc/cron.d/nebula-pkg-report
chmod 0644 /etc/cron.d/nebula-pkg-report
emit true action install
