#!/bin/sh
# service.status 1.0.0 (Nebula built-in, systemd, read-only): one unit's
# state and its last 50 journal lines. Parameter: {"unit": "<name>"}.
set -u
b64() { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }
pre() { printf '{"format":"systemd-status-v1","phase":"precheck","reason":"%s"}\n' "$1"; exit 10; }
u=$(sed -n 's/^{"unit":"\([A-Za-z0-9][A-Za-z0-9@._:-]*\)"}$/\1/p' "$NEBULA_PARAMS")
[ -n "$u" ] || pre "the unit parameter is missing or invalid"
command -v systemctl >/dev/null 2>&1 || pre "no systemctl"
show=$(systemctl show -p Id,Description,LoadState,ActiveState,SubState,UnitFileState,ActiveEnterTimestamp,MainPID --no-pager -- "$u" 2>/dev/null | b64)
if [ "$(id -u)" -eq 0 ]; then s=""; else s="sudo -n"; fi
journal=$($s journalctl -u "$u" -n 50 --no-pager -o short-iso 2>/dev/null | tail -n 50 | b64)
printf '{"format":"systemd-status-v1","phase":"done","show":"%s","journal":"%s"}\n' "$show" "$journal"
