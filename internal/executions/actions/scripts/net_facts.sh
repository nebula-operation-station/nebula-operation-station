#!/bin/sh
# net.facts 1.0.0 (Nebula built-in, read-only): network facts for the
# traffic map (ADR 0009 D1). Every section is the unchanged stdout of one
# fixed read-only command, base64 so that host text can never break the
# JSON document. Nothing is changed on the host and nothing runs with sudo:
# `ss` runs without -p, so process names stay empty (ADR 0009 Q3).
#
# Bounds: each section keeps at most section_max bytes, and all sections
# together at most total_max bytes, so the base64 document stays below the
# executor's 1 MiB result limit. A cut section says "truncated":true; a
# section the total budget no longer covers is not run ("skipped"). An
# optional tool that is not installed is "absent"; a command that exits
# non-zero (e.g. conntrack without CAP_NET_ADMIN) is "failed" with no data.
set -u
LC_ALL=C
export LC_ALL
b64() { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }
section_max=262144
total_max=737280
budget=$total_max
pre() { printf '{"format":"net-facts-v1","phase":"precheck","reason":"%s"}\n' "$1"; exit 10; }
status_file=$(mktemp) || pre "cannot create a temporary status file"
trap 'rm -f -- "$status_file"' 0
emit() { printf ',"%s":{"status":"%s","truncated":%s,"data":"%s"}' "$1" "$2" "$3" "$4"; }
# section NAME COMMAND ARGS...: run one fixed command and emit its section.
section() {
	name=$1
	shift
	if ! command -v "$1" >/dev/null 2>&1; then
		emit "$name" absent false ""
		return
	fi
	lim=$section_max
	[ "$budget" -lt "$lim" ] && lim=$budget
	if [ "$lim" -le 0 ]; then
		emit "$name" skipped true ""
		return
	fi
	: >"$status_file"
	# Read at most lim+1 bytes (one more than kept, to detect a cut) and
	# drain the rest, so the exit status is the command's own and never a
	# SIGPIPE caused by the cut.
	data=$({ "$@" </dev/null 2>/dev/null; printf '%s\n' "$?" >"$status_file"; } |
		{ head -c "$((lim + 1))" | b64; cat >/dev/null; })
	if [ "$(cat "$status_file")" != 0 ]; then
		emit "$name" failed false ""
		return
	fi
	pad=0
	case $data in *==) pad=2 ;; *=) pad=1 ;; esac
	len=$((${#data} / 4 * 3 - pad))
	trunc=false
	if [ "$len" -gt "$lim" ]; then
		data=$(printf '%s' "$data" | base64 -d | head -c "$lim" | b64)
		len=$lim
		trunc=true
	fi
	budget=$((budget - len))
	emit "$name" ok "$trunc" "$data"
}
printf '{"format":"net-facts-v1","phase":"done"'
section addr ip -j addr
section link ip -j -d link
section route ip -j route
section route6 ip -j -6 route
section neigh ip -j neigh
section neigh6 ip -j -6 neigh
section bridge_vlan bridge -j vlan
section lldp lldpcli -f json show neighbors
section sockets ss -tinuaH
section conntrack conntrack -L
printf '}\n'
