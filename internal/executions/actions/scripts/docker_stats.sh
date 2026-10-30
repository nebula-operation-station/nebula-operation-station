#!/bin/sh
# docker.stats 1.0.0 (Nebula built-in, Docker, read-only): one bounded,
# non-streaming CPU/RAM snapshot of the running containers, keyed by full
# container ID. A host without Docker is a successful result with
# "present":false. Only ID, name, CPU %, memory and memory % are read;
# never the environment, labels or command line.
set -u
b64() { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }
pre() { printf '{"format":"docker-stats-v1","phase":"precheck","reason":"%s"}\n' "$1"; exit 10; }
if ! command -v docker >/dev/null 2>&1; then
	printf '{"format":"docker-stats-v1","phase":"done","present":false}\n'
	exit 0
fi
# Access to the Docker socket is root-equivalent like NOPASSWD sudo
# (spec 08): use the docker group if the SSH user has it, else sudo -n.
d="docker"
if [ "$(id -u)" -ne 0 ] && ! docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
	d="sudo -n docker"
fi
ver=$($d version --format '{{.Server.Version}}' 2>/dev/null) ||
pre "the Docker daemon is not reachable, or the SSH user may not use it (docker group or sudo)"
# One non-streaming snapshot. --no-trunc keeps the full 64-hex container
# ID, the key a container is matched by (a recreated container has a new ID
# even when it keeps its name). The template reads only the statistics
# fields; never the environment, labels or command line.
fmt='{"id":{{json .ID}},"name":{{json .Name}},"cpu":{{json .CPUPerc}},"mem":{{json .MemUsage}},"memp":{{json .MemPerc}}}'
st=$($d stats --no-stream --no-trunc --format "$fmt" 2>/dev/null) || pre "docker stats failed"
st=$(printf '%s\n' "$st" | head -n 2000 | b64)
ver=$(printf '%s' "$ver" | head -c 100 | b64)
printf '{"format":"docker-stats-v1","phase":"done","present":true,"version":"%s","stats":"%s"}\n' "$ver" "$st"
