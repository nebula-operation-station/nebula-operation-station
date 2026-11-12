#!/bin/sh
# fim.scan 1.0.0 (Nebula built-in, read-only): integrity scan of the fixed
# profile fim-default-v1 (ADR 0015 D5, D6; spec 10 v26-10-02, spec 09
# v26-09-01). Parameters: {"mode":"full|incremental","profile":"fim-default-v1"}.
#
# Read-only: the script writes nothing but stdout (and discards stderr of
# the tools it runs). No temporary files, no here-documents, no package
# database, no network. find runs with -P -xdev and never follows a
# symlink; its only -exec is the hash tool (sha256sum). The path list is
# fixed here; no parameter names a path.
#
# Output: one fim-scan-v1 JSON document. Every host byte (paths, symlink
# targets, mount points) leaves base64-encoded; the JSON is assembled by the
# awk program at the end from a hex dump (od) of a NUL-separated stream, so
# no file name can break the document. Content hashes are plain SHA-256;
# the executor replaces every hash outside the D6 allowlist with its keyed
# form (the per-host key never leaves the executor).
#
# Incremental runs hash the files whose ctime or mtime lies in the profile's
# 26-hour look-back window and are at most 512 MiB, plus every file under
# /etc/ssh, every SSH configuration file and the whole /boot/efi root; other
# files appear by metadata only. Full runs hash every file. Hashing stops
# after 30 minutes; a run hashes at most 8 GiB (the rest is metadata only).
# A run cut at any of these limits says "truncated":true.
#
# NEBULA_FIM_TEST_ROOT is for tests only: it prefixes every path the script
# reads (the reported paths stay host paths) and suppresses the sudo
# re-execution. It does not widen what is read.
set -u
LC_ALL=C
export LC_ALL
P=${NEBULA_FIM_TEST_ROOT:-}
fail() { printf 'fim.scan: %s\n' "$1" >&2; exit 2; }

# The mode comes from the canonical parameters, or from $1 after the sudo
# re-execution below (sudo resets the environment).
if [ $# -ge 1 ]; then
	MODE=$1
else
	[ -n "${NEBULA_PARAMS:-}" ] || fail "no parameters"
	MODE=$(sed -n 's/^{"mode":"\([a-z]*\)","profile":"fim-default-v1"}$/\1/p' "$NEBULA_PARAMS")
fi
case $MODE in
full | incremental) ;;
*) fail "the mode or profile parameter is missing or invalid" ;;
esac

# Root is needed for /root/.ssh, /etc/sudoers.d and the crontab spool. Without
# usable sudo the scan runs as the SSH user and is partial where it cannot read.
if [ -z "$P" ] && [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
	exec sudo -n /bin/sh "$0" "$MODE"
fi

WIN=1560                # look-back window of fim-default-v1 in minutes (26 h)
MAXSIZE_INC=536870913   # find -size -Nc: at most 512 MiB in incremental runs
HASH_SECONDS=1800       # hashing stops after 30 minutes
SSH_MAX_FILES=64        # spec 09: at most 64 SSH configuration files
SSH_MAX_BYTES=262144    # spec 09: at most 256 KiB decoded in total
MOUNTINFO="$P/proc/self/mountinfo"

LOW=""
command -v nice >/dev/null 2>&1 && LOW="nice -n 19"
command -v ionice >/dev/null 2>&1 && LOW="$LOW ionice -c3 -t"
TIMEOUT=""
command -v timeout >/dev/null 2>&1 && TIMEOUT=timeout

# Profile roots in profile order. Nested roots lie inside an earlier root:
# they are scanned by that root unless they are mount points, in which case
# the parent prunes them and they are scanned as their own root.
LITERAL_ROOTS="/etc /etc/systemd/system /etc/systemd/user /boot /boot/efi /bin /sbin /lib /usr/bin /usr/sbin /usr/lib /usr/lib/systemd/system /usr/libexec /usr/local/bin /usr/local/sbin /usr/local/lib /opt /var/spool/cron/crontabs"
NESTED_ROOTS="/etc/systemd/system /etc/systemd/user /boot/efi /usr/lib/systemd/system"
# Home-relative SSH access files, below /root and every /home/* directory.
HOME_FILES=".ssh/authorized_keys* .shosts .rhosts .k5login .ssh/known_hosts .ssh/known_hosts2"

is_mount() {
	[ -r "$MOUNTINFO" ] || return 1
	awk -v p="$1" '$5 == p { f = 1 } END { exit !f }' "$MOUNTINFO"
}
NESTED_MOUNTS=""
for n in $NESTED_ROOTS; do
	is_mount "$n" && NESTED_MOUNTS="$NESTED_MOUNTS $n"
done

exists() { [ -e "$P$1" ] || [ -L "$P$1" ]; }

nested() {
	for n in $NESTED_ROOTS; do [ "$n" = "$1" ] && return 0; done
	return 1
}

nested_mount() {
	for n in $NESTED_MOUNTS; do [ "$n" = "$1" ] && return 0; done
	return 1
}

# scan START KIND ALL: walk one start point. KIND hash runs sha256sum on the
# files to hash, KIND meta prints one metadata entry per path ("M1" for a
# file that should have a hash, "M0" otherwise). ALL=1 hashes every file.
scan() {
	start=$1
	kind=$2
	all=$3
	set -- -P "$P$start" -xdev "(" -path "$P/etc/pve" -o -path "$P/usr/lib/python3*/__pycache__" -o -path "$P/usr/local/lib/python3*/__pycache__"
	for n in $NESTED_MOUNTS; do
		case $n in "$start"/*) set -- "$@" -o -path "$P$n" ;; esac
	done
	set -- "$@" ")" -prune -o "(" -path "$P/etc/ld.so.cache" \
		-o -path "$P/usr/lib/modules/*/modules.*" ! -path "$P/usr/lib/modules/*/*/*" \
		-o -path "$P/lib/modules/*/modules.*" ! -path "$P/lib/modules/*/*/*" ")" -o
	if [ "$all" = 1 ] || [ "$MODE" = full ]; then
		set -- "$@" "(" -type f
	else
		set -- "$@" "(" -type f -size "-${MAXSIZE_INC}c" "(" -cmin "-$WIN" -o -mmin "-$WIN" -o -path "$P/etc/ssh/*" ")"
	fi
	if [ "$kind" = hash ]; then
		set -- "$@" -exec sha256sum -z -- "{}" + ")"
		now=$(date +%s)
		left=$((DEADLINE - now))
		# Every T of the hash pass has a leading NUL: a killed pass may end in
		# a record cut mid-path, and the NUL ends that fragment as a field of
		# its own (the awk program drops the hash just before a T).
		if [ "$left" -le 0 ]; then
			printf '\0T\0'
			return
		fi
		if [ -n "$TIMEOUT" ]; then
			# shellcheck disable=SC2086 # LOW is a word list
			$TIMEOUT "$left" $LOW find "$@" 2>/dev/null
		else
			# shellcheck disable=SC2086
			$LOW find "$@" 2>/dev/null
		fi
		[ $? -eq 124 ] && printf '\0T\0'
	else
		set -- "$@" -printf 'M1 %y %s %m %U %G %i %T@ %C@\0%p\0%l\0' ")" -o -printf 'M0 %y %s %m %U %G %i %T@ %C@\0%p\0%l\0'
		# shellcheck disable=SC2086
		$LOW find "$@" 2>/dev/null || printf 'U\0'
	fi
}

# homes CALLBACK: call CALLBACK with every home directory (/root, /home/*)
# that is a real directory. Symlinked homes are never followed.
homes() {
	for h in "$P/root" "$P"/home/*; do
		if [ -L "$h" ] || [ ! -d "$h" ]; then
			continue
		fi
		h=${h#"$P"}
		case $h in *"
"*) continue ;; esac
		"$1" "$h"
	done
}

# report_links: every symlinked home or .ssh directory, and every home whose
# name holds a newline, counts as unreadable: the files behind it are not
# scanned, so the run is partial.
report_links() {
	for h in "$P/root" "$P"/home/*; do
		[ -e "$h" ] || [ -L "$h" ] || continue
		case $h in *"
"*)
			printf 'U\0'
			continue
			;;
		esac
		if [ -L "$h" ] || [ -L "$h/.ssh" ]; then
			printf 'U\0'
		fi
	done
}

# each_home_file BASE REL CALLBACK: call CALLBACK for every existing BASE/REL
# with BASE /root or /home (meaning /home/*), never through a symlinked home
# or .ssh directory. REL may end in a glob.
each_home_file() {
	BASE=$1
	REL=$2
	FILE_CB=$3
	homes home_file
}

home_file() {
	case $BASE in
	/root) [ "$1" = /root ] || return 0 ;;
	*) [ "$1" = /root ] && return 0 ;;
	esac
	case $REL in .ssh/*) [ -L "$P$1/.ssh" ] && return 0 ;; esac
	for f in "$P$1"/$REL; do
		[ -e "$f" ] || [ -L "$f" ] || continue
		f=${f#"$P"}
		case $f in *"
"*) continue ;; esac
		"$FILE_CB" "$f"
	done
}

FOUND=0
found() { FOUND=1; }
scan_hash() { scan "$1" hash 0; }
scan_meta() { scan "$1" meta 0; }

# walk KIND: every start point of the profile.
walk() {
	for r in $LITERAL_ROOTS; do
		if nested "$r" && ! nested_mount "$r"; then
			continue
		fi
		exists "$r" || continue
		all=0
		[ "$r" = /boot/efi ] && all=1
		scan "$r" "$1" "$all"
	done
	for base in /root /home; do
		for rel in $HOME_FILES; do
			each_home_file "$base" "$rel" "scan_$1"
		done
	done
}

# SSH configuration: /etc/ssh/sshd_config and every regular file under /etc
# its Include lines name (relative paths are relative to /etc/ssh, as for
# sshd). Values are split on blanks and globbed; nothing is evaluated.
SSH_FILES=""
ssh_known() {
	for k in $SSH_FILES; do [ "$k" = "$1" ] && return 0; done
	return 1
}
ssh_collect() {
	SSH_FILES=""
	SSH_N=0
	SSH_BYTES=0
	SSH_CUT=0
	queue=/etc/ssh/sshd_config
	while [ -n "$queue" ]; do
		f=${queue%% *}
		case $queue in *" "*) queue=${queue#* } ;; *) queue="" ;; esac
		ssh_known "$f" && continue
		if [ -L "$P$f" ] || [ ! -f "$P$f" ] || [ ! -r "$P$f" ]; then
			continue
		fi
		size=$(wc -c <"$P$f" 2>/dev/null) || continue
		if [ "$SSH_N" -ge "$SSH_MAX_FILES" ] || [ $((SSH_BYTES + size)) -gt "$SSH_MAX_BYTES" ]; then
			SSH_CUT=1
			break
		fi
		SSH_N=$((SSH_N + 1))
		SSH_BYTES=$((SSH_BYTES + size))
		SSH_FILES="$SSH_FILES $f"
		# The values are split with globbing off, then each one is globbed
		# under the read root; nothing in them is evaluated.
		set -f
		# shellcheck disable=SC2013 # Include takes blank-separated words
		for w in $(sed -n 's/^[[:space:]]*[Ii][Nn][Cc][Ll][Uu][Dd][Ee][[:space:]=][[:space:]=]*//p' "$P$f" 2>/dev/null); do
			case $w in
			/*) pat=$w ;;
			*) pat=/etc/ssh/$w ;;
			esac
			set +f
			for m in "$P"$pat; do
				m=${m#"$P"}
				case $m in /etc/*) ;; *) continue ;; esac
				case $m in *[[:space:]]* | *[\*\?\[]* | */./* | */../* | */.. | */. | *//*) continue ;; esac
				queue="$queue $m"
				queue=${queue# }
			done
			set -f
		done
		set +f
	done
}

produce() {
	printf 'B%s\0' "$(date +%s)"
	[ -n "$P" ] && printf 'P\0%s\0' "$P"

	# Roots summary.
	for r in $LITERAL_ROOTS; do
		if exists "$r"; then printf 'R%s %s\0' scanned "$r"; else printf 'R%s %s\0' missing "$r"; fi
	done
	for base in /root /home; do
		for rel in $HOME_FILES; do
			FOUND=0
			each_home_file "$base" "$rel" found
			if [ "$base" = /root ]; then pat="/root/$rel"; else pat="/home/*/$rel"; fi
			if [ "$FOUND" = 1 ]; then printf 'R%s %s\0' scanned "$pat"; else printf 'R%s %s\0' missing "$pat"; fi
		done
	done
	report_links

	# Hashes first, then metadata: the awk program needs each hash before
	# the record it belongs to.
	ssh_collect
	DEADLINE=$(($(date +%s) + HASH_SECONDS))
	walk hash
	for f in $SSH_FILES; do
		sha256sum -z -- "$P$f" 2>/dev/null
	done
	walk meta

	printf 'I\0'
	[ -r "$MOUNTINFO" ] && cat "$MOUNTINFO" 2>/dev/null
	printf '\0'

	[ "$SSH_CUT" = 1 ] && printf 'T\0'
	for f in $SSH_FILES; do
		c=$(base64 -w0 <"$P$f" 2>/dev/null) || {
			printf 'U\0'
			continue
		}
		printf 'C\0%s\0%s\0' "$P$f" "$c"
	done
	printf 'E%s\0' "$(date +%s)"
}

produce | od -An -v -tx1 | awk -v mode="$MODE" '
BEGIN {
	for (i = 0; i < 256; i++) HX[sprintf("%02x", i)] = i
	for (i = 32; i < 127; i++) CH[i] = sprintf("%c", i)
	A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for (i = 0; i < 64; i++) E[i] = substr(A, i + 1, 1)
	MAXREC = 300000              # spec 09 records per run
	RECBUDGET = 125829120        # 120 MiB of records, below the 128 MiB document limit
	HASHBUDGET = 8589934592      # 8 GiB hashed per run
	MAXMOUNTS = 256
	MAXPATH = 4096
	MAXDEPTH = 64
	n = 0; st = "tag"; plen = 0; nroots = 0; nrec = 0; recbytes = 0; hashed = 0
	nmnt = 0; nssh = 0; unread = 0; trunc = 0; opened = 0; started = 0; ended = -1
}
{
	for (i = 1; i <= NF; i++) {
		if ($i == "00") { field(); n = 0 } else B[++n] = HX[$i]
	}
}
function asc(from, to,   s, k) {
	s = ""
	for (k = from; k <= to; k++) s = s ((B[k] >= 32 && B[k] < 127) ? CH[B[k]] : "\001")
	return s
}
function b64(from, to,   out, k, a, b, c, rem) {
	out = ""
	for (k = from; k + 2 <= to; k += 3) {
		a = B[k]; b = B[k + 1]; c = B[k + 2]
		out = out E[int(a / 4)] E[(a % 4) * 16 + int(b / 16)] E[(b % 16) * 4 + int(c / 64)] E[c % 64]
	}
	rem = to - k + 1
	if (rem == 1) { a = B[k]; out = out E[int(a / 4)] E[(a % 4) * 16] "==" }
	else if (rem == 2) { a = B[k]; b = B[k + 1]; out = out E[int(a / 4)] E[(a % 4) * 16 + int(b / 16)] E[(b % 16) * 4] "=" }
	return out
}
# strip: index of the first byte after the test prefix, or 0 if the field
# does not start with it.
function strip(from,   k) {
	if (n - from + 1 <= plen) return 0
	for (k = 1; k <= plen; k++) if (B[from + k - 1] != PB[k]) return 0
	return from + plen
}
function pathok(from, to,   k, depth) {
	if (to - from + 1 > MAXPATH || B[from] != 47) return 0
	depth = 0
	for (k = from; k <= to; k++) if (B[k] == 47) depth++
	return depth <= MAXDEPTH
}
function uint(s) { return s ~ /^[0-9]+$/ && length(s) <= 20 }
function etime(s,   ip, fr, neg) {
	if (s !~ /^-?[0-9]+(\.[0-9]+)?$/) return ""
	ip = s; fr = ""
	if (index(s, ".") > 0) { ip = substr(s, 1, index(s, ".") - 1); fr = substr(s, index(s, ".") + 1) }
	neg = substr(ip, 1, 1) == "-"
	if (neg && fr ~ /[1-9]/) ip = sprintf("%d", ip - 1)
	if (ip == "-0") ip = "0"
	if (length(ip) > 13) return ""
	return ip
}
function oct(s,   k, v) {
	if (s !~ /^[0-7]+$/ || length(s) > 5) return -1
	v = 0
	for (k = 1; k <= length(s); k++) v = v * 8 + substr(s, k, 1)
	return v
}
function open_records(   k) {
	if (opened) return
	opened = 1
	printf "{\"format\":\"fim-scan-v1\",\"profile\":\"fim-default-v1\",\"mode\":\"%s\",\"started\":%s,\"roots\":[", mode, started
	for (k = 1; k <= nroots; k++) printf "%s{\"root\":\"%s\",\"status\":\"%s\"}", (k > 1 ? "," : ""), ROOTN[k], ROOTS[k]
	printf "],\"records\":["
}
function field(   s, c, k, from, ph) {
	ph = LASTH; LASTH = ""
	if (st == "tag") {
		if (n == 0) { trunc = 1; return }
		c = B[1]
		if ((c >= 48 && c <= 57) || (c >= 97 && c <= 102)) { hashline(); return }
		s = asc(1, n)
		c = substr(s, 1, 1)
		if (c == "B") { started = etime(substr(s, 2)); if (started == "") started = 0 }
		else if (c == "E") { ended = etime(substr(s, 2)) }
		else if (c == "P") st = "prefix"
		else if (c == "R") {
			k = index(s, " ")
			ROOTS[++nroots] = substr(s, 2, k - 2); ROOTN[nroots] = substr(s, k + 1)
			if (ROOTN[nroots] !~ /\*/) LIT[ROOTN[nroots]] = 1
		}
		else if (c == "M") { open_records(); META = s; st = "mpath" }
		else if (c == "U") unread++
		else if (c == "T") {
			# The field before a T may be a hash record cut by a killed
			# hash pass, its path a prefix of another path: drop it.
			trunc = 1
			if (ph != "") { if (LASTHAD) HS[ph] = LASTOLD; else delete HS[ph] }
		}
		else if (c == "I") st = "mountinfo"
		else if (c == "C") st = "cpath"
		else trunc = 1
		return
	}
	if (st == "prefix") { plen = n; for (k = 1; k <= n; k++) PB[k] = B[k]; st = "tag"; return }
	if (st == "mpath") {
		from = strip(1)
		if (from == 0 || !pathok(from, n)) { MPATH = ""; } else MPATH = b64(from, n)
		st = "mlink"; return
	}
	if (st == "mlink") {
		MLINK = (n > 0 && n <= MAXPATH) ? b64(1, n) : ""
		MLINKBAD = n > MAXPATH
		record(); st = "tag"; return
	}
	if (st == "mountinfo") { mountinfo(); st = "tag"; return }
	if (st == "cpath") {
		from = strip(1)
		CPATH = (from > 0 && pathok(from, n)) ? b64(from, n) : ""
		st = "ccontent"; return
	}
	if (st == "ccontent") {
		s = asc(1, n)
		if (CPATH == "" || s !~ /^[A-Za-z0-9+\/=]*$/) unread++
		else { SSHP[++nssh] = CPATH; SSHC[nssh] = s }
		st = "tag"; return
	}
}
function hashline(   k, from, hex) {
	if (n < 67 || B[65] != 32 || (B[66] != 32 && B[66] != 42)) return
	hex = asc(1, 64)
	if (hex !~ /^[0-9a-f]+$/ || length(hex) != 64) return
	from = strip(67)
	if (from == 0 || !pathok(from, n)) return
	LASTH = b64(from, n)
	LASTHAD = LASTH in HS
	if (LASTHAD) LASTOLD = HS[LASTH]
	HS[LASTH] = hex
}
function record(   f, t, rec, m, mt, ct, hash) {
	if (split(META, f, " ") != 9 || MPATH == "" || MLINKBAD) { unread++; return }
	t = f[2] == "f" ? "file" : f[2] == "d" ? "dir" : f[2] == "l" ? "symlink" : "other"
	m = oct(f[4]); mt = etime(f[8]); ct = etime(f[9])
	if (!uint(f[3]) || m < 0 || m > 4095 || !uint(f[5]) || !uint(f[6]) || !uint(f[7]) || mt == "" || ct == "" || (t == "symlink" && MLINK == "")) { unread++; return }
	hash = ""
	if (t == "file" && (MPATH in HS)) {
		if (hashed + f[3] > HASHBUDGET) trunc = 1
		else { hashed += f[3]; hash = HS[MPATH] }
		delete HS[MPATH]
	} else if (t == "file" && f[1] == "M1") unread++
	if (nrec >= MAXREC || recbytes > RECBUDGET) { trunc = 1; return }
	rec = "{\"path\":\"" MPATH "\",\"type\":\"" t "\",\"size\":" f[3] ",\"mode\":" m ",\"uid\":" f[5] ",\"gid\":" f[6] ",\"inode\":" f[7] ",\"mtime\":" mt ",\"ctime\":" ct
	if (hash != "") rec = rec ",\"sha256\":\"" hash "\""
	if (t == "symlink") rec = rec ",\"link\":\"" MLINK "\""
	rec = rec "}"
	printf "%s%s", (nrec > 0 ? "," : ""), rec
	nrec++
	recbytes += length(rec) + 1
}
# mountinfo: report every mount point at or below a literal profile root
# (field 5, with the kernel octal escapes decoded) and its fstype (the
# field after the "-" separator).
function mountinfo(   k, lstart, fno, fstart, mpf, mpt, sep, fsf, fst, j) {
	lstart = 1
	for (k = 1; k <= n + 1; k++) {
		if (k <= n && B[k] != 10) continue
		fno = 0; fstart = lstart; sep = 0; mpf = 0; fsf = 0
		for (j = lstart; j <= k; j++) {
			if (j < k && B[j] != 32) continue
			fno++
			if (fno == 5) { mpf = fstart; mpt = j - 1 }
			if (fno > 6 && !sep && j - fstart == 1 && B[fstart] == 45) sep = fno
			else if (sep && fno == sep + 1) { fsf = fstart; fst = j - 1 }
			fstart = j + 1
		}
		if (mpf && fsf) mount(mpf, mpt, fsf, fst)
		lstart = k + 1
	}
}
function mount(mpf, mpt, fsf, fst,   k, m, s, fs, r, key, save, sn) {
	m = 0
	for (k = mpf; k <= mpt; k++) {
		if (B[k] == 92 && k + 3 <= mpt && B[k+1] >= 48 && B[k+1] <= 55 && B[k+2] >= 48 && B[k+2] <= 55 && B[k+3] >= 48 && B[k+3] <= 55) {
			MB[++m] = (B[k+1] - 48) * 64 + (B[k+2] - 48) * 8 + (B[k+3] - 48); k += 3
		} else MB[++m] = B[k]
	}
	if (m == 0 || m > MAXPATH) return
	s = ""
	for (k = 1; k <= m; k++) s = s ((MB[k] >= 32 && MB[k] < 127) ? CH[MB[k]] : "\001")
	sn = 0
	for (r in LIT) if (s == r || substr(s, 1, length(r) + 1) == r "/") sn = 1
	if (!sn) return
	fs = asc(fsf, fst)
	if (fs !~ /^[a-z0-9._-]+$/ || length(fs) > 64) fs = "invalid"
	# b64 works on B; encode the decoded mount point from a saved copy.
	sn = n
	for (k = 1; k <= m; k++) { save[k] = B[k]; B[k] = MB[k] }
	key = b64(1, m)
	for (k = 1; k <= m; k++) B[k] = save[k]
	if ((key SUBSEP fs) in MSEEN) return
	MSEEN[key SUBSEP fs] = 1
	if (nmnt >= MAXMOUNTS) { trunc = 1; return }
	MP[++nmnt] = key; MF[nmnt] = fs
}
END {
	if (st != "tag" || n > 0) trunc = 1
	open_records()
	printf "],\"mounts\":["
	for (k = 1; k <= nmnt; k++) printf "%s{\"path\":\"%s\",\"fstype\":\"%s\"}", (k > 1 ? "," : ""), MP[k], MF[k]
	printf "],\"ssh_config\":["
	for (k = 1; k <= nssh; k++) printf "%s{\"path\":\"%s\",\"content\":\"%s\"}", (k > 1 ? "," : ""), SSHP[k], SSHC[k]
	if (ended == "" || ended == -1) ended = started
	printf "],\"truncated\":%s,\"ended\":%s,\"counters\":{\"records\":%d,\"mounts\":%d,\"ssh_config\":%d,\"unreadable\":%d}}\n", (trunc ? "true" : "false"), ended, nrec, nmnt, nssh, unread
}'
