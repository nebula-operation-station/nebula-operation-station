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

dropin=/etc/ssh/sshd_config.d/90-nebula-hardening.conf
removed=no
if [ -f "$dropin" ]; then
  rm -f "$dropin"
  sshd -t || fail "sshd -t fails after removing the drop-in"
  systemctl reload-or-restart ssh
  removed=yes
fi
emit true action uninstall removed "$removed"
