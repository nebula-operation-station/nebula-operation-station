#!/bin/sh
# docker.logs 1.0.0 (Nebula built-in, Docker, read-only): state and the
# last 100 log lines (stdout and stderr, with timestamps) of one container.
# Parameter: {"container": "<name or ID>"}.
set -u
b64() { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }
pre() { printf '{"format":"docker-logs-v1","phase":"precheck","reason":"%s"}\n' "$1"; exit 10; }
c=$(sed -n 's/^{"container":"\([A-Za-z0-9][A-Za-z0-9_.-]*\)"}$/\1/p' "$NEBULA_PARAMS")
[ -n "$c" ] || pre "the container parameter is missing or invalid"
command -v docker >/dev/null 2>&1 || pre "Docker is not installed"
# Same access as docker.list: the docker group, else sudo -n (spec 08).
d="docker"
if [ "$(id -u)" -ne 0 ] && ! docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
	d="sudo -n docker"
fi
$d version --format '{{.Server.Version}}' >/dev/null 2>&1 ||
	pre "the Docker daemon is not reachable, or the SSH user may not use it (docker group or sudo)"
state=$($d inspect --type container --format '{{.State.Status}}' -- "$c" 2>/dev/null) || pre "no such container"
state=$(printf '%s' "$state" | head -c 100 | b64)
logs=$($d logs --tail 100 --timestamps -- "$c" 2>&1 | tail -n 100 | head -c 262144 | b64)
printf '{"format":"docker-logs-v1","phase":"done","container":"%s","state":"%s","logs":"%s"}\n' "$c" "$state" "$logs"
