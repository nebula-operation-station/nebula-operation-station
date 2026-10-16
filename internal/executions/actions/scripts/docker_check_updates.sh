#!/bin/sh
# docker.check_updates 1.0.0 (Nebula built-in, Docker, read-only): for the
# image of every running container, compare the local repository digest
# with the registry's current digest for its tag, using a manifest HEAD
# request (spec 11: does not count against pull limits, pulls nothing).
# Anonymous access only; a registry that wants credentials reports
# "unknown". Needs curl on the host.
set -u
set -f
b64() { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }
pre() { printf '{"format":"docker-updates-v1","phase":"precheck","reason":"%s"}\n' "$1"; exit 10; }
command -v docker >/dev/null 2>&1 || pre "Docker is not installed"
command -v curl >/dev/null 2>&1 || pre "curl is not installed"
d="docker"
if [ "$(id -u)" -ne 0 ] && ! docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
	d="sudo -n docker"
fi
$d version --format '{{.Server.Version}}' >/dev/null 2>&1 ||
	pre "the Docker daemon is not reachable, or the SSH user may not use it (docker group or sudo)"

accept="application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json"
accept="$accept,application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json"
# HTTPS only, no redirects, short timeouts, no credentials ever sent.
fetch() { curl --proto '=https' --max-redirs 0 --connect-timeout 5 --max-time 10 -s "$@"; }

# Header value of name ($2, lower case) from headers ($1), first match.
header() {
	printf '%s\n' "$1" | tr -d '\r' | awk -v n="$2" 'tolower(substr($0, 1, length(n) + 1)) == n ":" { sub(/^[^:]*: */, ""); print; exit }'
}

# remote_digest REGISTRY REPO TAG: prints the digest or "unknown <why>".
remote_digest() {
	url="https://$1/v2/$2/manifests/$3"
	h=$(fetch -I -H "Accept: $accept" "$url") || { echo "unknown registry not reachable"; return; }
	code=$(printf '%s\n' "$h" | head -n 1 | tr -d '\r' | awk '{print $2}')
	if [ "$code" = "401" ]; then
		chal=$(header "$h" "www-authenticate")
		realm=$(printf '%s' "$chal" | sed -n 's/.*realm="\(https:\/\/[^"]*\)".*/\1/p')
		service=$(printf '%s' "$chal" | sed -n 's/.*service="\([^"]*\)".*/\1/p')
		[ -n "$realm" ] || { echo "unknown authentication required"; return; }
		tok=$(fetch -G --data-urlencode "service=$service" --data-urlencode "scope=repository:$2:pull" "$realm" |
			head -c 20000 | sed -n 's/.*"\(access_\)\{0,1\}token" *: *"\([A-Za-z0-9._~+\/=-]*\)".*/\2/p' | head -n 1)
		[ -n "$tok" ] || { echo "unknown authentication required"; return; }
		h=$(fetch -I -H "Accept: $accept" -H "Authorization: Bearer $tok" "$url") || { echo "unknown registry not reachable"; return; }
		code=$(printf '%s\n' "$h" | head -n 1 | tr -d '\r' | awk '{print $2}')
	fi
	[ "$code" = "200" ] || { echo "unknown registry answered $code"; return; }
	dg=$(header "$h" "docker-content-digest")
	case "$dg" in
	sha256:*) echo "$dg" ;;
	*) echo "unknown no digest in the answer" ;;
	esac
}

out=""
n=0
# emit IMAGE STATUS DIGEST NOTE: one tab-separated line of the result.
emit() { out="$out$(printf '%s\t%s\t%s\t%s' "$1" "$2" "$3" "$4")
"; }
for img in $($d ps --format '{{.Image}}' 2>/dev/null | sort -u | head -n 50); do
	n=$((n + 1))
	ref="$img"
	case "$ref" in
	*@sha256:*) emit "$img" pinned "" "the image is pinned by digest"; continue ;;
	sha256:* | *[!A-Za-z0-9._:/-]*) emit "$img" unknown "" "not a tag reference"; continue ;;
	esac
	# [registry/]repository[:tag]
	first=${ref%%/*}
	case "$ref" in
	*/*) case "$first" in *.* | *:* | localhost) reg=$first; rest=${ref#*/} ;; *) reg=registry-1.docker.io; rest=$ref ;; esac ;;
	*) reg=registry-1.docker.io; rest="library/$ref" ;;
	esac
	tag=latest
	case "${rest##*/}" in *:*) tag=${rest##*:}; rest=${rest%:*} ;; esac
	locals=$($d image inspect --format '{{range .RepoDigests}}{{.}} {{end}}' "$img" 2>/dev/null)
	remote=$(remote_digest "$reg" "$rest" "$tag")
	case "$remote" in
	unknown*) emit "$img" unknown "" "${remote#unknown }"; continue ;;
	esac
	ld=""
	for x in $locals; do
		ld="${x#*@}"
		[ "$ld" = "$remote" ] && break
	done
	if [ -n "$ld" ] && [ "$ld" = "$remote" ]; then
		emit "$img" current "$remote" ""
	else
		emit "$img" update "$remote" "local ${ld:-none}"
	fi
done
lines=$(printf '%s' "$out" | head -c 65536 | b64)
printf '{"format":"docker-updates-v1","phase":"done","images":%d,"lines":"%s"}\n' "$n" "$lines"
