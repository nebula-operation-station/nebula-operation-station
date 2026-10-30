#!/bin/sh
# image.vulnerabilities 1.0.0 (Nebula built-in, Docker + Trivy, read-only):
# optional CVE observation of one local image by digest via the host's own
# Trivy. Local-only scan profile: --offline-scan --skip-db-update
# --scanners vuln; NOS never installs a scanner, pulls an image or refreshes
# the database (operator-managed). One concurrent scan per host (flock),
# bounded output, and the raw scanner output never leaves the host: it is
# reduced on the host to unique CVE counts by severity, the top 25 CVEs with
# fixed versions, the target count (coverage) and the database age. Cached
# by digest + platform + DB version for at most 24 h. Absent, stale, busy,
# failed or unsupported scans report their status, never "0 CVEs".
# Parameter: {"image": "<repo>@sha256:<64 hex digest>"}.
set -u
set -f
b64() { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }
pre() { printf '{"format":"image-vulns-v1","phase":"precheck","reason":"%s"}\n' "$1"; exit 10; }

img=$(sed -n 's|^{\"image\":\"\([a-z0-9][a-z0-9._/:-]\{0,254\}@sha256:[0-9a-f]\{64\}\)\"}$|\1|p' "$NEBULA_PARAMS")
[ -n "$img" ] || pre "the image parameter is missing or invalid"
command -v docker >/dev/null 2>&1 || pre "Docker is not installed"
# Same access as docker.list: the docker group, else sudo -n (spec 08).
d="docker"
if [ "$(id -u)" -ne 0 ] && ! docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
	d="sudo -n docker"
fi
$d version --format '{{.Server.Version}}' >/dev/null 2>&1 ||
pre "the Docker daemon is not reachable, or the SSH user may not use it (docker group or sudo)"

# Work directory: per-user and private, so another local user cannot plant
# a cached summary.
w="${TMPDIR:-/tmp}/nebula-image-vulns.$(id -u)"
mkdir -p "$w" 2>/dev/null && chmod 700 "$w" 2>/dev/null || pre "cannot create the scan work directory"
trap 'rm -f "$w/scan.json" "$w/reduced" "$w/scan.err"' EXIT

# emit STATUS: result document from the globals. Every status but ok leaves
# the finding fields empty: the observation is unknown, never zero.
emit() {
	doc="{\"format\":\"image-vulns-v1\",\"phase\":\"done\",\"status\":\"$1\",\"image\":\"$img\""
	[ -n "$present" ] && doc="$doc,\"present\":$present"
	[ -n "$trivyv" ] && doc="$doc,\"trivy\":\"$(printf '%s' "$trivyv" | b64)\""
	[ -n "$dbv" ] && doc="$doc,\"dbver\":\"$(printf '%s' "$dbv" | b64)\""
	[ -n "$dba" ] && doc="$doc,\"dbage\":$dba"
	[ -n "$plat" ] && doc="$doc,\"platform\":\"$(printf '%s' "$plat" | b64)\""
	[ -n "$cached" ] && doc="$doc,\"cached\":true"
	[ -n "$summary" ] && doc="$doc,\"summary\":\"$(printf '%s' "$summary" | b64)\""
	printf '%s}\n' "$doc"
	exit 0
}
present=""; trivyv=""; dbv=""; dba=""; plat=""; cached=""; summary=""

# The image must already be local (never pulled). One call gives presence
# and the platform os/arch[/variant].
plat=$($d image inspect --format '{{.Os}}/{{.Architecture}}{{if .Variant}}/{{.Variant}}{{end}}' -- "$img" 2>/dev/null) || emit notlocal
[ -n "$plat" ] || emit notlocal

# Trivy follows the same access as docker: the user's own binary, or the
# root one via sudo -n (same daemon access). It is only ever used, never
# installed.
t="trivy"
if [ "$d" = "sudo -n docker" ]; then
	t="sudo -n trivy"
	$t --version >/dev/null 2>&1 || { present=false; emit absent; }
else
	command -v trivy >/dev/null 2>&1 || { present=false; emit absent; }
fi
present=true
trivyv=$($t --version 2>/dev/null | sed -n 's/^Version: *//p' | head -n 1 | head -c 100)

# Database: operator-managed. Only its version (file mtime) and age are
# read; it is never downloaded or refreshed. Missing or older than 24 h is
# stale, not "0 CVEs".
if [ "$d" = "sudo -n docker" ]; then
	dbfile="/root/.cache/trivy/db/vuln-list.json"
	dbmtime=$(sudo -n stat -c %Y "$dbfile" 2>/dev/null)
else
	dbfile="${TRIVY_CACHE_DIR:-$HOME/.cache/trivy}/db/vuln-list.json"
	dbmtime=$(stat -c %Y "$dbfile" 2>/dev/null)
fi
if [ -n "$dbmtime" ]; then
	dbv=$(printf '%s' "$dbmtime" | head -c 20)
	now=$(date +%s)
	dba=$(( (now - dbmtime) / 3600 ))
	[ "$dba" -lt 0 ] && dba=0
	[ "$dba" -le 24 ] || emit stale
else
	emit stale
fi

# One concurrent scan per host: an fd lock, released when this process
# dies. Without flock, a directory lock; a stale one from a dead scan is
# taken over after 15 min (the action timeout is 10 min).
if command -v flock >/dev/null 2>&1; then
	exec 9>"$w/scan.lock"
	flock -n 9 || emit busy
else
	if [ -d "$w/scan.lock.d" ] && [ -n "$(find "$w/scan.lock.d" -maxdepth 0 -mmin +15 2>/dev/null)" ]; then
		rmdir "$w/scan.lock.d" 2>/dev/null
	fi
	mkdir "$w/scan.lock.d" 2>/dev/null || emit busy
	trap 'rmdir "$w/scan.lock.d" 2>/dev/null; rm -f "$w/scan.json" "$w/reduced" "$w/scan.err"' EXIT
fi

# Cache by digest + platform + DB version, at most 24 h.
key=$(printf '%s|%s|%s' "$img" "$plat" "$dbv" | sha256sum 2>/dev/null | cut -d ' ' -f 1)
if [ -n "$key" ] && [ -f "$w/c-$key" ] && [ -n "$(find "$w/c-$key" -maxdepth 0 -mmin -1440 2>/dev/null)" ]; then
	summary=$(head -c 1048576 "$w/c-$key")
	case "$summary" in
	*'"severity"'*'"total"'*'"top"'*)
		cached=true
		emit ok
		;;
	esac
fi

# The local-only scan profile: offline, no database update, vuln scanner
# only. Output is bounded; the raw JSON never leaves the host.
$t image --offline-scan --skip-db-update --scanners vuln --quiet --format json -- "$img" >"$w/scan.json" 2>"$w/scan.err"
rc=$?
[ $rc -eq 0 ] || emit failed
size=$(wc -c < "$w/scan.json" 2>/dev/null) || size=0
[ "$size" -le 16777216 ] || emit truncated
[ "$size" -gt 0 ] || emit unsupported
# The output must be the expected pretty-printed JSON skeleton.
head -c 1 "$w/scan.json" | grep -q '^{' || emit unsupported
grep -q '"SchemaVersion"' "$w/scan.json" || emit unsupported
grep -q '"Results"' "$w/scan.json" || emit unsupported

# Reduce on the host: unique CVEs (highest severity wins, first fixed
# version kept), counts by severity, target count, top 25 by severity then
# id. A vulnerability id that is not a plain identifier is dropped, never
# interpreted. No "Vulnerabilities" key at all means the output is not a
# vulnerability scan (U).
awk '
function rank(s) {
	if (s == "CRITICAL") return 5
	if (s == "HIGH") return 4
	if (s == "MEDIUM") return 3
	if (s == "LOW") return 2
	return 1
}
function flush(	r) {
	if (id != "") {
		r = rank(sev)
		if (id in seen) {
			if (r > rank(seen[id])) seen[id] = sev
			if (fix[id] == "" && fixed != "") fix[id] = fixed
		} else {
			seen[id] = sev
			fix[id] = fixed
		}
	}
	id = ""; sev = ""; fixed = ""
}
{
	if ($0 ~ /"Vulnerabilities"[ \t]*:/) have = 1
	if ($0 ~ /"Target"[ \t]*:/) targets++
	if ($0 ~ /"VulnerabilityID"[ \t]*:[ \t]*"/) {
		flush()
		s = $0
		sub(/^.*"VulnerabilityID"[ \t]*:[ \t]*"/, "", s)
		sub(/".*$/, "", s)
		if (s ~ /^[A-Za-z0-9][A-Za-z0-9-]{1,63}$/) id = s
	} else if (id != "" && $0 ~ /"FixedVersion"[ \t]*:[ \t]*"/) {
		if (fixed == "") {
			s = $0
			sub(/^.*"FixedVersion"[ \t]*:[ \t]*"/, "", s)
			sub(/".*$/, "", s)
			gsub(/["\\]/, "", s)
			if (length(s) > 200) s = substr(s, 1, 200)
			fixed = s
		}
	} else if (id != "" && $0 ~ /"Severity"[ \t]*:[ \t]*"/) {
		s = $0
		sub(/^.*"Severity"[ \t]*:[ \t]*"/, "", s)
		sub(/".*$/, "", s)
		if (s == "CRITICAL" || s == "HIGH" || s == "MEDIUM" || s == "LOW" || s == "UNKNOWN") sev = s
	}
}
END {
	flush()
	if (!have) { print "U"; exit }
	print "T\t" targets + 0
	for (id in seen) {
		s = seen[id]
		if (s == "") s = "UNKNOWN"
		count[s]++
		print "R\t" rank(s) "\t" id "\t" s "\t" fix[id]
	}
	n = split("CRITICAL HIGH MEDIUM LOW UNKNOWN", names, " ")
	for (i = 1; i <= n; i++) print "C\t" names[i] "\t" (names[i] in count ? count[names[i]] : 0)
}
' "$w/scan.json" >"$w/reduced" || emit unsupported
grep -q '^U$' "$w/reduced" && emit unsupported

tab=$(printf '\t')
targets=$(awk -F '\t' '$1 == "T" { print $2 }' "$w/reduced" | head -n 1)
[ -n "$targets" ] || targets=0
total=$(awk -F '\t' '$1 == "C" { s += $3 } END { print s + 0 }' "$w/reduced")
sevjson=$(awk -F '\t' '$1 == "C" { printf "%s\"%s\":%s", (n++ ? "," : ""), $2, $3 }' "$w/reduced")
topjson=$(awk -F '\t' '$1 == "R"' "$w/reduced" | sort -t "$tab" -k2,2nr -k3,3 | head -n 25 |
	awk -F '\t' '{ printf "%s{\"id\":\"%s\",\"severity\":\"%s\",\"fixed\":\"%s\"}", (NR > 1 ? "," : ""), $3, $4, $5 }')
summary=$(printf '{"severity":{%s},"total":%s,"targets":%s,"top":[%s]}' "$sevjson" "$total" "$targets" "$topjson")

# Cache the summary for the next 24 h (atomic replace).
if [ -n "$key" ]; then
	printf '%s' "$summary" >"$w/.c-$key.tmp" 2>/dev/null && mv "$w/.c-$key.tmp" "$w/c-$key" 2>/dev/null
fi
emit ok
