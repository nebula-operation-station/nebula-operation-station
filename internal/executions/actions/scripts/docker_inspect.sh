#!/bin/sh
# docker.inspect 1.0.0 (Nebula built-in, Docker, read-only): image and
# digest, state, restart policy, health, mounts, ports and networks of one
# container. Environment, command line and labels are never read: they
# often hold secrets. Parameter: {"container": "<name or ID>"}.
set -u
b64() { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }
pre() { printf '{"format":"docker-inspect-v1","phase":"precheck","reason":"%s"}\n' "$1"; exit 10; }
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
f='{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Config.Image}},"image_id":{{json .Image}},'
# .State as a whole: docker's template fails on .State.Health when the
# container has no health check.
f="$f"'"state":{{json .State}},"restarts":{{json .RestartCount}},"restart_policy":{{json .HostConfig.RestartPolicy.Name}},'
f="$f"'"mounts":{{json .Mounts}},"ports":{{json .NetworkSettings.Ports}},"networks":{{json .NetworkSettings.Networks}}}'
$d inspect --type container --format '{{.Id}}' -- "$c" >/dev/null 2>&1 || pre "no such container"
info=$($d inspect --type container --format "$f" -- "$c" 2>/dev/null) || pre "docker inspect failed"
img=$($d inspect --type container --format '{{.Image}}' -- "$c" 2>/dev/null)
digests=$($d image inspect --format '{{json .RepoDigests}}' -- "$img" 2>/dev/null | head -c 65536 | b64)
info=$(printf '%s' "$info" | head -c 524288 | b64)
printf '{"format":"docker-inspect-v1","phase":"done","container":"%s","inspect":"%s","digests":"%s"}\n' "$c" "$info" "$digests"
