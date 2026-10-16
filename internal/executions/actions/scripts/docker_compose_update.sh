#!/bin/sh
# docker.compose_update 1.0.0 (Nebula built-in, Docker, durable job, runs
# as root): the manual update of one Compose project (spec 11). The project
# is found by its labels; its containers are listed before, then
# `docker compose pull` and `docker compose up -d` run, health checks get
# up to 60 seconds, and the containers are listed again. The server
# compares both lists (postflight). Parameter: {"project": "<name>"}.
set -u
set -f
b64() { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }
pre() { printf '{"format":"compose-update-v1","phase":"precheck","reason":"%s"}\n' "$1"; exit 10; }
[ "$(id -u)" -eq 0 ] || pre "not running as root"
p=$(sed -n 's/^{"project":"\([a-z0-9][a-z0-9_-]*\)"}$/\1/p' "$NEBULA_PARAMS")
[ -n "$p" ] || pre "the project parameter is missing or invalid"
command -v docker >/dev/null 2>&1 || pre "Docker is not installed"
docker compose version >/dev/null 2>&1 || pre "the docker compose plugin is not installed"
ids=$(docker ps -a -q --filter "label=com.docker.compose.project=$p" 2>/dev/null)
[ -n "$ids" ] || pre "no containers of this Compose project"
first=$(printf '%s\n' "$ids" | head -n 1)
dir=$(docker inspect --type container --format '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' -- "$first" 2>/dev/null)
files=$(docker inspect --type container --format '{{index .Config.Labels "com.docker.compose.project.config_files"}}' -- "$first" 2>/dev/null)
case "$dir" in /*) ;; *) pre "the working directory label is not an absolute path" ;; esac
[ -d "$dir" ] || pre "the working directory of the project is gone"
# Config files: a comma-separated label of absolute paths. Each becomes
# one argument after -f; none can start with "-".
set --
oldifs=$IFS
IFS=,
for f in $files; do
	case "$f" in /*) ;; *) IFS=$oldifs; pre "a config file label is not an absolute path" ;; esac
	[ -f "$f" ] || { IFS=$oldifs; pre "a config file of the project is gone"; }
	set -- "$@" -f "$f"
done
IFS=$oldifs
[ $# -gt 0 ] || pre "the project has no config file label"
t='{{"\t"}}'
snap() {
	docker ps -a --filter "label=com.docker.compose.project=$p" \
		--format "{{.Label \"com.docker.compose.service\"}}$t{{.Names}}$t{{.State}}$t{{.Status}}$t{{.Ports}}$t{{.Image}}" 2>/dev/null |
		sort | head -n 200
}
before=$(snap)
cd "$dir" || pre "cannot enter the working directory"
docker compose -p "$p" --project-directory "$dir" "$@" pull >&2
pullrc=$?
uprc=-1
if [ "$pullrc" -eq 0 ]; then
	docker compose -p "$p" --project-directory "$dir" "$@" up -d >&2
	uprc=$?
fi
i=0
while [ "$i" -lt 12 ]; do
	case "$(snap)" in
	*"(health: starting)"*) sleep 5; i=$((i + 1)) ;;
	*) break ;;
	esac
done
after=$(snap)
printf '{"format":"compose-update-v1","phase":"done","project":"%s","pull_exit":%d,"up_exit":%d,"before":"%s","after":"%s"}\n' \
	"$p" "$pullrc" "$uprc" "$(printf '%s' "$before" | b64)" "$(printf '%s' "$after" | b64)"
[ "$pullrc" -eq 0 ] && [ "$uprc" -eq 0 ]
