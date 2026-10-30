#!/bin/sh
# backup.status 1.0.0 (Nebula built-in, backup, read-only): bounded local
# Veeam Agent for Linux evidence. Fixed allowlisted commands only:
#   veeamconfig session list
#   veeamconfig session info --id <session-id>
# A host without veeamconfig is a successful result with "present":false
# (no evidence, never ok). A failed or denied query is a precheck failure
# with a fixed reason; host text is never echoed.
set -u
b64() { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }
pre() { printf '{"format":"backup-status-v1","phase":"precheck","reason":"%s"}\n' "$1"; exit 10; }
if ! command -v veeamconfig >/dev/null 2>&1; then
	printf '{"format":"backup-status-v1","phase":"done","present":false}\n'
	exit 0
fi
# Bound the stream before shell capture, with one overflow byte and a
# four-byte exit-status trailer. Base64 preserves NULs and trailing newlines
# until after the byte count is checked.
max_output_bytes=262144
max_sessions=32
max_session_bytes=8192
max_total_bytes=524288
guid_re='\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}'
# query takes a diagnostic-capture flag and runs one fixed command
# with a bounded capture and a 3-digit exit-status trailer. It prints the decoded text and the status as the
# last line (??? when the capture exceeded the byte limit); the caller
# splits them off again.
query() {
	capture_diagnostics=$1
	shift
	cap=$({
		if [ "$capture_diagnostics" = 1 ]; then
			"$@" 2>&1
		else
			"$@" 2>/dev/null
		fi
		printf '\n%03d' "$?"
	} | head -c "$((max_output_bytes + 5))" | b64)
	captured_bytes=$((${#cap} / 4 * 3))
	case "$cap" in
	*==) captured_bytes=$((captured_bytes - 2)) ;;
	*=) captured_bytes=$((captured_bytes - 1)) ;;
	esac
	if [ "$captured_bytes" -gt "$((max_output_bytes + 4))" ]; then
		printf '\n???'
		return
	fi
	cap=$(printf '%s' "$cap" | base64 -d; printf '.')
	cap=${cap%.}
	status=${cap##*'
'}
	cap=${cap%????}
	printf '%s\n%s' "$cap" "$status"
}
# 1) the session list: the session identities, nothing else is used.
res=$(query 1 veeamconfig session list)
status=${res##*'
'}
list_out=${res%????}
if [ "$status" = '???' ]; then
	pre "command output exceeds byte limit"
fi
if [ "$status" != 000 ]; then
	# The host's own text is not echoed back: only a fixed reason.
	case "$list_out" in
	*'permission denied'*|*'Permission denied'*|*'not permitted'*|*'insufficient privileges'*|*'EACCES'*)
		pre "the host denies access to the Veeam Agent metadata" ;;
	esac
	pre "veeamconfig session list failed"
fi
ids=$(printf '%s\n' "$list_out" | grep -oE "$guid_re" 2>/dev/null | sort -u)
truncated=0
if [ -n "$ids" ]; then
	n=$(printf '%s\n' "$ids" | wc -l)
	if [ "$n" -gt "$max_sessions" ]; then
		truncated=1
	fi
fi
ids=$(printf '%s\n' "$ids" | head -n "$max_sessions")
# 2) per session: the allowlisted session info; the parser checks the
# identity of each block against the list.
doc=""
total=0
count=0
for id in $ids; do
	count=$((count + 1))
	res=$(query 0 veeamconfig session info --id "$id")
	status=${res##*'
'}
	info=${res%????}
	if [ "$status" != 000 ]; then
		# The session evidence is incomplete; the document is partial.
		truncated=1
		continue
	fi
	if [ "${#info}" -gt "$max_session_bytes" ]; then
		truncated=1
		continue
	fi
	# Only approved metadata from stdout enters the result. Diagnostics
	# and other fields are discarded before constructing session blocks.
	info=$(printf '%s\n' "$info" | LC_ALL=C grep -aE '^(ID|Job name|State|Start time|End time):')
	block="[${count}] ${id}
${info}
"
	total=$((total + ${#block}))
	if [ "$total" -gt "$max_total_bytes" ]; then
		truncated=1
		break
	fi
	doc="${doc}${block}
"
done
if [ "$truncated" = 1 ]; then
	printf '{"format":"backup-status-v1","phase":"done","present":true,"truncated":true}\n'
	exit 0
fi
out=$(printf '%s' "$doc" | b64)
printf '{"format":"backup-status-v1","phase":"done","present":true,"sessions":"%s"}\n' "$out"
