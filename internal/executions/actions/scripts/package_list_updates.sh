#!/bin/sh
# package.list_updates 1.0.0 (Nebula built-in, os-debian, read-only).
# Lists pending updates with an apt simulation (no root, no lock), plus
# reboot-required and the age of the package lists. Raw apt output is
# base64-wrapped; the server parses it as untrusted text.
set -u
b64() { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }
command -v apt-get >/dev/null 2>&1 || { echo "no apt-get: not a Debian or Ubuntu host" >&2; exit 3; }
proxmox=false
[ -d /etc/pve ] && proxmox=true
mode=upgrade
[ "$proxmox" = true ] && mode=dist-upgrade
sim=$(LC_ALL=C apt-get -s -o Debug::NoLocking=1 "$mode" 2>/dev/null | grep '^Inst ' | head -n 20000 | b64)
reboot=false
[ -e /var/run/reboot-required ] && reboot=true
pkgs=""
[ -r /var/run/reboot-required.pkgs ] && pkgs=$(head -c 65536 /var/run/reboot-required.pkgs | b64)
lists=$(stat -c %Y /var/lib/apt/lists 2>/dev/null || echo 0)
case "$lists" in ''|*[!0-9]*) lists=0 ;; esac
printf '{"format":"apt-simulate-v1","mode":"%s","simulate":"%s","reboot_required":%s,"reboot_pkgs":"%s","lists_mtime":%s,"proxmox":%s}\n' \
  "$mode" "$sim" "$reboot" "$pkgs" "$lists" "$proxmox"
