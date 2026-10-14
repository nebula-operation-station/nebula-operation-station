#!/bin/sh
# service.list 1.0.0 (Nebula built-in, systemd, read-only): all service units.
set -u
b64() { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }
command -v systemctl >/dev/null 2>&1 || { echo "no systemctl: not a systemd host" >&2; exit 3; }
units=$(systemctl list-units --type=service --all --no-legend --plain --no-pager 2>/dev/null | head -n 3000 | b64)
printf '{"format":"systemd-units-v1","units":"%s"}\n' "$units"
