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

user=$NEBULA_P_NAME
home=$NEBULA_P_HOME
case $NEBULA_P_SHELL in
  bash) shell=/bin/bash ;;
  sh) shell=/bin/sh ;;
  nologin) shell=/usr/sbin/nologin ;;
esac

printf '%s\n' "$user" | grep -Eqx '[a-z][a-z0-9_-]{0,30}' || fail "name is not a valid login name"
case $user in
  *-|*.) fail "name must not end with - or ." ;;
esac
case $home in
  /home/*) ;;
  *) fail "home must be under /home" ;;
esac
list=$NEBULA_P_GROUPS
what=groups
[ -n "$list" ] || fail "$what is empty"
old_ifs=$IFS
IFS=:
set -- $list
IFS=$old_ifs
for w in "$@"; do
  printf '%s\n' "$w" | grep -Eqx '[a-z][a-z0-9_-]{0,29}' || fail "$what: invalid entry $w"
done

if ! id -u "$user" >/dev/null 2>&1; then
  fail "user $user does not exist; run install first"
fi
usermod --shell "$shell" --home "$home" "$user"
for g in "$@"; do
  getent group "$g" >/dev/null || fail "group $g does not exist"
  usermod -aG "$g" "$user"
done
key_file=$NEBULA_SECRET_SSH_PUBLIC_KEY
key=$(head -n 1 "$key_file")
printf '%s\n' "$key" | grep -Eq '^(ssh-ed25519|sk-ssh-ed25519@openssh.com|ecdsa-[0-9]+|ssh-rsa) [A-Za-z0-9+/=]+' || fail "ssh_public_key is not a valid OpenSSH public key"
ssh_dir="$home/.ssh"
install -d -m 0700 -o "$user" -g "$user" "$ssh_dir"
authz="$ssh_dir/authorized_keys"
touch "$authz"
chmod 0600 "$authz"
chown "$user:$user" "$authz"
if ! grep -qxF "$key" "$authz"; then
  printf '%s\n' "$key" >> "$authz"
fi
emit true action update user "$user"
