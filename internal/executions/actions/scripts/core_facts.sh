#!/bin/sh
# core.facts 1.0.0 (Nebula built-in, read-only): facts for the inventory.
# Values are base64 so that host text can never break the JSON document.
set -u
b64() { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }
os=""
[ -r /etc/os-release ] && os=$(b64 < /etc/os-release)
kernel=$(uname -srm | b64)
name=$(hostname 2>/dev/null | b64)
uptime=$(cut -d' ' -f1 /proc/uptime 2>/dev/null | b64)
proxmox=false
[ -d /etc/pve ] && proxmox=true
printf '{"os_release":"%s","uname":"%s","hostname":"%s","uptime":"%s","proxmox":%s}\n' "$os" "$kernel" "$name" "$uptime" "$proxmox"
