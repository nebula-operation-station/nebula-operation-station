#!/bin/sh
# docker.list 1.0.0 (Nebula built-in, Docker, read-only): all containers
# with image, state, health, ports and Compose project. A host without
# Docker is a successful result with "present":false.
set -u
b64() { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }
pre() { printf '{"format":"docker-ps-v1","phase":"precheck","reason":"%s"}\n' "$1"; exit 10; }
if ! command -v docker >/dev/null 2>&1; then
	printf '{"format":"docker-ps-v1","phase":"done","present":false}\n'
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
t='{{"\t"}}'
fmt="{{.ID}}$t{{.Names}}$t{{.Image}}$t{{.State}}$t{{.Status}}$t{{.Ports}}$t"
fmt="$fmt{{.Label \"com.docker.compose.project\"}}$t{{.Label \"com.docker.compose.service\"}}$t"
# Creation time is the 10th column; older parsers ignore it, this one keeps it.
fmt="$fmt{{.Label \"com.docker.compose.project.working_dir\"}}$t{{.CreatedAt}}"
ps=$($d ps -a --no-trunc --format "$fmt" 2>/dev/null) || pre "docker ps failed"
# Bound the rows, never the bytes: one label can be arbitrarily large, and a
# byte cut can split a row (or a UTF-8 character, which the parser refuses
# as a whole). awk with LC_ALL=C counts bytes and keeps only whole rows that
# fit in 512 KiB raw (about 700 KiB encoded, under hostrun.MaxResult), at
# most 2000 rows. A row that does not fit is skipped with "next", not "exit":
# docker ps lists the newest containers first, so stopping at one oversized
# row would hide every container after it. Skipped rows still count toward
# the row limit.
ps=$(printf '%s\n' "$ps" | LC_ALL=C awk -v max=524288 -v rows=2000 '
{ if (NR > rows) exit; if (n + length($0) + 1 > max) next; n += length($0) + 1; print }' | b64)
ver=$(printf '%s' "$ver" | head -c 100 | b64)
printf '{"format":"docker-ps-v1","phase":"done","present":true,"version":"%s","containers":"%s"}\n' "$ver" "$ps"
