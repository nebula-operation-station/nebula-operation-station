#!/bin/sh
# package.refresh 1.0.0 (Nebula built-in, os-debian): apt-get update.
# Needs root: uses sudo -n (the nebula user's NOPASSWD sudo, spec 08).
set -u
command -v apt-get >/dev/null 2>&1 || { echo "no apt-get: not a Debian or Ubuntu host" >&2; exit 3; }
if [ "$(id -u)" -eq 0 ]; then s=""; else s="sudo -n"; fi
# Wait for the dpkg/apt lock up to 8 minutes (an attached run ends at 10).
$s env LC_ALL=C DEBIAN_FRONTEND=noninteractive apt-get -q -o DPkg::Lock::Timeout=480 update >&2
rc=$?
lists=$(stat -c %Y /var/lib/apt/lists 2>/dev/null || echo 0)
case "$lists" in ''|*[!0-9]*) lists=0 ;; esac
printf '{"refreshed":%s,"exit":%d,"lists_mtime":%s}\n' "$([ $rc -eq 0 ] && echo true || echo false)" "$rc" "$lists"
exit "$rc"
