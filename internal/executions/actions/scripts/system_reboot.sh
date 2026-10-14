#!/bin/sh
# system.reboot 1.0.0 (Nebula built-in, os-debian, durable job, runs as root).
# Schedules a reboot 15 seconds after the job ends and asks the executor to
# wait until the host is back with a new boot ID (spec 11).
set -u
pre() { printf '{"format":"reboot-v1","phase":"precheck","reason":"%s"}\n' "$1"; exit 10; }
[ "$(id -u)" -eq 0 ] || pre "not running as root"
command -v systemd-run >/dev/null 2>&1 || pre "no systemd-run"
b=$(head -c 64 /proc/sys/kernel/random/boot_id 2>/dev/null)
case "$b" in ????????-????-????-????-????????????) ;; *) pre "unreadable boot ID" ;; esac
case "${NEBULA_EXECUTION_ID:-}" in ????????-????-????-????-????????????) ;; *) pre "no execution ID" ;; esac
systemd-run --quiet --on-active=15s --unit="nebula-reboot-$NEBULA_EXECUTION_ID" /bin/systemctl reboot >&2 || pre "could not schedule the reboot"
printf '{"format":"reboot-v1","phase":"scheduled","await_reboot":true,"boot_id":"%s"}\n' "$b"
