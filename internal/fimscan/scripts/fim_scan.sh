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
# after 30 minutes (timeout, or a watchdog without it); a run hashes at most
# 8 GiB: before a start point is read, the sizes of its files are summed and
# larger files are left out (metadata only) once the budget would be passed.
# A run cut at any of these limits says "truncated":true. Paths are never
# opened through a symlink in any component. The SSH files below /root and
# /home/* lie in directories their users own and can change at any time:
# each is scanned from inside its directory, entered once and checked by
# its physical path, as a single entry (a directory there is reported, not
# walked); it is opened and hashed only by a holder process dropped to the
# owner of the directory (root never opens it, by name or through the
# holder's descriptor), bounded in time, through one descriptor checked to
# be the regular file find saw, before and after the read. Its hash
# carries that device:inode:ctime and is kept only for a record of the
# same whose ctime and mtime are older than the hash start by more than
# the timestamp granularity (a racy timestamp cannot prove the content
# unchanged). At most 16 authorized_keys* files per home are scanned.
#
# NEBULA_FIM_TEST_ROOT is for tests only: it prefixes every path the script
# reads (the reported paths stay host paths), suppresses the sudo
# re-execution and enables the NEBULA_FIM_TEST_* window, deadline and budget
# settings. It does not widen what is read.
set -u
LC_ALL=C
export LC_ALL
unset CDPATH
P=${NEBULA_FIM_TEST_ROOT:-}
# PREAL: the physical path of the read root, for the pwd -P check of
# home_cd ("" on a host).
PREAL=""
if [ -n "$P" ]; then
	PREAL=$(cd -P "$P" && pwd -P) || exit 2
fi
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
HASH_BUDGET=8589934592  # a run hashes at most 8 GiB
SSH_MAX_FILES=64        # spec 09: at most 64 SSH configuration files
SSH_MAX_BYTES=262144    # spec 09: at most 256 KiB decoded in total
SSH_MAX_QUEUE=256       # Include matches waiting to be read
SSH_MAX_SEEN=1024       # Include matches looked at in total
HOME_MAX_MATCHES=16     # start points per home and glob (.ssh/authorized_keys*)
HOME_OPEN_SECONDS=5     # a home SSH file not opened (and checked) within this is not hashed
# A home SSH hash is kept only if the file's ctime and mtime (whole
# seconds) lie more than RACY_SECONDS before the second the hash started.
# File timestamps are coarse (the kernel's tick-based clock, whole seconds
# on some file systems, two on FAT), so a write during or after the read
# can leave dev:inode:ctime unchanged; such a write still gets a timestamp
# no earlier than RACY_SECONDS before the hash start, so its record keeps
# no hash (unknown, as git treats a racily clean index entry).
RACY_SECONDS=2
MOUNTINFO="$P/proc/self/mountinfo"
AM_ROOT=0
[ "$(id -u)" = 0 ] && AM_ROOT=1
# Tests only (with NEBULA_FIM_TEST_ROOT): shorter window, deadline, budget;
# a smaller (or negative) timestamp margin for trees written just before.
if [ -n "$P" ]; then
	for v in "${NEBULA_FIM_TEST_WINDOW:-}" "${NEBULA_FIM_TEST_HASH_SECONDS:-}" "${NEBULA_FIM_TEST_HASH_BUDGET:-}"; do
		case $v in *[!0-9]*) fail "invalid test setting" ;; esac
	done
	case ${NEBULA_FIM_TEST_RACY_SECONDS:-0} in
	- | -*[!0-9]* | [!-]*[!0-9]* | [!-0-9]) fail "invalid test setting" ;;
	esac
	WIN=${NEBULA_FIM_TEST_WINDOW:-$WIN}
	HASH_SECONDS=${NEBULA_FIM_TEST_HASH_SECONDS:-$HASH_SECONDS}
	HASH_BUDGET=${NEBULA_FIM_TEST_HASH_BUDGET:-$HASH_BUDGET}
	RACY_SECONDS=${NEBULA_FIM_TEST_RACY_SECONDS:-$RACY_SECONDS}
fi

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

# nolink PATH: true if no component of the host path PATH (below the read
# root) is a symlink. Every path the script opens by name is checked with
# it first, so no symlinked directory anywhere in a path is followed.
nolink() {
	nl_rest=${1#/}
	nl_cur=""
	while [ -n "$nl_rest" ]; do
		nl_cur="$nl_cur/${nl_rest%%/*}"
		case $nl_rest in */*) nl_rest=${nl_rest#*/} ;; *) nl_rest="" ;; esac
		[ -L "$P$nl_cur" ] && return 1
	done
	return 0
}

# root_state ROOT: scanned; error when a directory above the root is a
# symlink (find would resolve it; the root is not scanned) or when the
# nearest existing directory above it cannot be searched (EACCES: whether
# the root exists is unknown, so it is unreadable, never missing); else
# missing.
root_state() {
	if ! nolink "${1%/*}"; then
		echo error
		return
	fi
	if exists "$1"; then
		echo scanned
		return
	fi
	rs_d=${1%/*}
	while [ -n "$rs_d" ] && ! exists "$rs_d"; do
		rs_d=${rs_d%/*}
	done
	if [ -d "$P${rs_d:-/}" ] && [ ! -x "$P${rs_d:-/}" ]; then
		echo error
	else
		echo missing
	fi
}

nested() {
	for n in $NESTED_ROOTS; do [ "$n" = "$1" ] && return 0; done
	return 1
}

nested_mount() {
	for n in $NESTED_MOUNTS; do [ "$n" = "$1" ] && return 0; done
	return 1
}

# SIZE_AWK reads the sizes of the files a start point would hash and the
# budget left, and prints the bytes it will hash and the size cap: "-" when
# all fit, else the largest power of two such that all files below it fit.
# shellcheck disable=SC2016 # an awk program, not shell
SIZE_AWK='{ s = $1 + 0; t += s; k = 0; c = 1; while (c <= s) { c += c; k++ } B[k] += s }
END {
	if (t <= left) { printf "%.0f -\n", t; exit }
	u = 0; best = 0
	for (k = 0; k <= 64; k++) { if (left < u + B[k]) break; u += B[k]; best = k }
	c = 1
	for (k = 0; k < best; k++) c += c
	printf "%.0f %.0f\n", u, c
}'

# watchdog SECONDS PID: without the timeout tool, stop find (PID) and the
# hash tool it runs once SECONDS have passed.
watchdog() {
	ws=""
	trap '[ -n "$ws" ] && kill "$ws" 2>/dev/null; exit 0' TERM
	sleep "$1" &
	ws=$!
	wait "$ws"
	kids=$(cat "/proc/$2/task/$2/children" 2>/dev/null)
	kill -TERM "$2" 2>/dev/null
	# shellcheck disable=SC2086 # a list of process ids
	[ -n "$kids" ] && kill -TERM $kids 2>/dev/null
}

# scan START KIND ALL CAP [HOME]: walk one start point. KIND size prints
# the bytes and cap of the files to hash (SIZE_AWK), KIND hash runs
# sha256sum on the files to hash, KIND meta prints one metadata entry per
# path ("M1" for a file that should have a hash, "M0" otherwise). ALL=1
# hashes every file; CAP ("-" for none) leaves files of CAP bytes or more
# unhashed. HOME=1 marks a home SSH file (home_scan). Status 3: the
# deadline cut the hash pass of this start point.
scan() {
	start=$1
	kind=$2
	all=$3
	cap=$4
	if [ "${5:-0}" = 1 ]; then
		home_scan
		return
	fi
	find_scan "$P$start" '%p' 0
}

# home_scan: scan the home SSH file $start. Its user owns the home (and
# .ssh) directory and can swap any entry in it for a symlink at any time,
# so after the check the path is never resolved by name again: the
# subshell enters the directory once (cd -P) and goes on only if it is the
# directory at exactly this physical path, i.e. no component was a
# symlink. Everything after is relative to that working directory, which
# a later swap cannot move. find -P looks at the single entry (-maxdepth
# 0) without following it, and HASH_FD hashes it through one descriptor
# checked to be that same regular file. A directory swapped for a symlink
# in time makes the file unreadable for this run.
home_scan() {
	(
		home_cd "${start%/*}" || {
			[ "$kind" = meta ] && printf 'U\0'
			exit 0
		}
		find_scan "./${start##*/}" "$(fmt_path "$P$start")" 1
	)
}

# home_cd DIR: enter DIR (a host path below the read root); true only if
# the working directory is now the directory at exactly that physical path.
home_cd() {
	cd -P "$P$1" 2>/dev/null || return 1
	[ "$(pwd -P)" = "$PREAL$1" ]
}

# fmt_path PATH: PATH as literal text in a find -printf format.
fmt_path() {
	printf '%s' "$1" | sed 's/\\/\\\\/g; s/%/%%/g'
}

# HOLD runs as /bin/sh -c "$HOLD" sh NAME ID SECONDS in the checked home
# directory, as the user the open drops to (HASH_FD). It opens NAME as
# descriptor 3, killed by its own watchdog if the open takes more than
# SECONDS (a FIFO swapped in cannot stall the run; no timeout tool is
# needed). It goes on only if the descriptor is the regular file ID
# (device:inode:ctime) find saw at NAME, hashes through it, checks the
# descriptor again (a file changed or replaced while it was read keeps no
# hash) and prints the hash. A symlink or FIFO swapped in fails a check
# before a byte is read. The holder runs with group 65534, which no
# process of the user has, so the user cannot ptrace it (or read its
# memory) to change what it opens or prints.
# shellcheck disable=SC2016 # expanded by the inner shell
HOLD='exec 2>/dev/null
n=$1 id=$2 s=$3
(sleep "$s"; kill -TERM $$) >/dev/null </dev/null &
w=$!
exec 3<"$n" || exit 1
kill "$w"
c() { find -H /proc/self/fd/3 -maxdepth 0 -type f -printf "%D:%i:%C@\n"; }
[ "$(c)" = "$id" ] || exit 1
h=$(sha256sum <&3) || exit 1
[ "$(c)" = "$id" ] || exit 1
printf "%s\n" "$h"'

# HASH_FD runs as /bin/sh -c "$HASH_FD" sh NAME ID HOLD USER SECONDS in the
# checked home directory. The user owning that directory can swap NAME for
# a symlink, a FIFO or another file after find looked at it, so root
# never opens NAME, nor anything a process of the user holds (no
# /proc/PID/fd): HOLD opens, checks and hashes it, dropped to USER
# (setpriv; "" when the scan does not run as root or no one but root can
# change the directory), and only its printed hash comes back. A symlink
# there is followed with the rights of USER only.
# shellcheck disable=SC2016 # expanded by the inner shell
HASH_FD='exec 2>/dev/null
n=$1 id=$2 hold=$3 u=$4 s=$5
set -- /bin/sh -c "$hold" sh "$n" "$id" "$s"
[ -n "$u" ] && set -- setpriv --reuid="$u" --regid=65534 --clear-groups -- "$@"
exec "$@" </dev/null'

# open_user: the user HOLD drops to for the working directory (a checked
# home or .ssh directory), in OPEN_USER: none ("") when the scan does not
# run as root, or the directory is root's and only root can change it;
# its owner when that is another user; nobody (65534) for a root-owned
# directory others can write. False when the open would need to drop but
# cannot (no setpriv): the file is not hashed.
open_user() {
	OPEN_USER=""
	[ "$AM_ROOT" = 1 ] || return 0
	ou=$(find . -maxdepth 0 -printf '%U %m\n' 2>/dev/null)
	case $ou in
	"" | *[!0-9\ ]* | *" "*" "* | " "* | *" ") return 1 ;;
	"0 "*) [ $((0${ou#* } & 18)) -eq 0 ] || OPEN_USER=65534 ;;
	*) OPEN_USER=${ou%% *} ;;
	esac
	[ -z "$OPEN_USER" ] || command -v setpriv >/dev/null 2>&1
}

# bounded SECONDS CMD...: run CMD and stop it, and a tool it runs, after
# SECONDS (the watchdog, for hosts without the timeout tool).
bounded() {
	b_s=$1
	shift
	"$@" &
	b_p=$!
	watchdog "$b_s" "$b_p" >/dev/null 2>&1 &
	b_w=$!
	wait "$b_p"
	b_r=$?
	kill "$b_w" 2>/dev/null
	return "$b_r"
}

# find_scan SP PF ONE: the find run of scan for the start path SP. PF is
# the -printf text of the reported path (%p, or the escaped host path when
# SP is relative); ONE=1 looks at SP alone (a home SSH file).
find_scan() {
	sp=$1
	pf=$2
	one=$3
	set -- -P "$sp"
	[ "$one" = 1 ] && set -- "$@" -maxdepth 0
	set -- "$@" -xdev "(" -path "$P/etc/pve" -o -path "$P/usr/lib/python3*/__pycache__" -o -path "$P/usr/local/lib/python3*/__pycache__"
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
	[ "$cap" = - ] || set -- "$@" -size "-${cap}c"
	case $kind in
	size)
		set -- "$@" -printf '%s\n' ")"
		# shellcheck disable=SC2086 # LOW is a word list
		$LOW find "$@" 2>/dev/null | awk -v left="$HASH_LEFT" "$SIZE_AWK"
		;;
	hash)
		left=$((DEADLINE - $(date +%s)))
		# Every T of the hash pass has a leading NUL: a killed pass may end in
		# a record cut mid-path, and the NUL ends that fragment as a field of
		# its own (the awk program drops the hash just before a T). Status 3
		# tells visit that the deadline cut this start point.
		if [ "$left" -le 0 ]; then
			printf '\0T\0'
			return 3
		fi
		if [ "$one" = 1 ]; then
			set -- "$@" -printf '%D:%i:%C@\n' ")"
			id=$(find "$@" 2>/dev/null)
			if [ -n "$id" ] && open_user; then
				# Taken before the holder opens the file: any write the
				# hash may have missed has a later timestamp than
				# this less RACY_SECONDS.
				cut=$(($(date +%s) - RACY_SECONDS))
				if [ -n "$TIMEOUT" ]; then
					h=$($TIMEOUT "$left" /bin/sh -c "$HASH_FD" sh "$sp" "$id" "$HOLD" "$OPEN_USER" "$HOME_OPEN_SECONDS")
				else
					h=$(bounded "$left" /bin/sh -c "$HASH_FD" sh "$sp" "$id" "$HOLD" "$OPEN_USER" "$HOME_OPEN_SECONDS")
				fi
				# Written whole, only for a complete hash.
				hx=${h%% *}
				if [ "${#hx}" -eq 64 ]; then
					case $hx in
					*[!0-9a-f]*) ;;
					# After the device:inode:ctime it was read from
					# and the cutoff second: the meta pass keeps it
					# only for a record with the same id whose ctime
					# and mtime lie before the cutoff.
					*) printf 'H%s %s\0%s  %s\0' "$id" "$cut" "$hx" "$P$start" ;;
					esac
				fi
			fi
		else
			set -- "$@" -exec sha256sum -z -- "{}" + ")"
			hash_pass "$@"
		fi
		# The clock, not an exit status, says whether the deadline stopped
		# the pass: GNU timeout exits 124, BusyBox timeout 143.
		if [ "$(date +%s)" -ge "$DEADLINE" ]; then
			printf '\0T\0'
			return 3
		fi
		;;
	meta)
		set -- "$@" -printf 'M1 %y %s %m %U %G %i %T@ %C@ %D\0'"$pf"'\0%l\0' ")" -o -printf 'M0 %y %s %m %U %G %i %T@ %C@ %D\0'"$pf"'\0%l\0'
		# shellcheck disable=SC2086
		$LOW find "$@" 2>/dev/null || printf 'U\0'
		;;
	esac
}

# hash_pass FIND-ARGS...: run find and its sha256sum until the deadline
# (left seconds).
hash_pass() {
	# cat ends only when find and every sha256sum it ran have closed the
	# pipe, so the marker is never written between hash records.
	if [ -n "$TIMEOUT" ]; then
		# GNU timeout signals its process group (find and sha256sum);
		# BusyBox timeout signals find only, and the running sha256sum
		# batch ends on its own before cat does.
		{
			# shellcheck disable=SC2086
			$TIMEOUT "$left" $LOW find "$@" 2>/dev/null
		} | cat
	else
		# The watchdog stops find and its sha256sum at the deadline.
		{
			# shellcheck disable=SC2086
			$LOW find "$@" 2>/dev/null &
			fp=$!
			watchdog "$left" "$fp" >/dev/null 2>&1 &
			wp=$!
			wait "$fp"
			kill "$wp" 2>/dev/null
		} | cat
	fi
}

# homes CALLBACK: call CALLBACK with every home directory (/root, /home/*)
# that is a real directory. Symlinked homes, and /home when it is a
# symlink or cannot be listed, are never followed (report_links counts
# them as unreadable); each one not looked into calls home_skip, so that
# the patterns that could match behind it are unknown, never missing.
homes() {
	if [ -L "$P/home" ] || [ ! -d "$P/home" ] || [ ! -r "$P/home" ] || [ ! -x "$P/home" ]; then
		if [ -e "$P/home" ] || [ -L "$P/home" ]; then
			home_skip /home
		fi
		set -- "$1" "$P/root"
	else
		set -- "$1" "$P/root" "$P"/home/*
	fi
	cb=$1
	shift
	for h; do
		if [ -L "$h" ]; then
			home_skip "${h#"$P"}"
			continue
		fi
		[ -d "$h" ] || continue
		h=${h#"$P"}
		case $h in *"
"*)
			home_skip "$h"
			continue
			;;
		esac
		"$cb" "$h"
	done
}

# home_skip HOME: HOME (or all of /home) was not looked into; the patterns
# of BASE that could match there are unknown (SKIP=1). report_links counts
# it as unreadable once.
home_skip() {
	case $1 in
	/root) [ "$BASE" = /root ] && SKIP=1 ;;
	*) [ "$BASE" = /root ] || SKIP=1 ;;
	esac
	return 0
}

# report_links: a symlinked or unlistable /home, every symlinked home or
# .ssh directory, and every home whose name holds a newline, counts as
# unreadable: the files behind it are not scanned, so the run is partial.
report_links() {
	if [ -L "$P/home" ] || { [ -e "$P/home" ] && { [ ! -d "$P/home" ] || [ ! -r "$P/home" ] || [ ! -x "$P/home" ]; }; }; then
		printf 'U\0'
		set -- "$P/root"
	else
		set -- "$P/root" "$P"/home/*
	fi
	for h; do
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
# or .ssh directory. REL may end in a glob. A directory that cannot be
# searched (or, for a glob, listed) sets UNL=1: whether files are behind it
# is unknown, so they are unreadable, never missing.
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
	hd="$P$1"
	if [ ! -x "$hd" ]; then
		UNL=1
		return 0
	fi
	case $REL in .ssh/*)
		if [ -L "$hd/.ssh" ]; then
			SKIP=1
			return 0
		fi
		[ -d "$hd/.ssh" ] || return 0
		hd="$hd/.ssh"
		if [ ! -x "$hd" ]; then
			UNL=1
			return 0
		fi
		;;
	esac
	case $REL in *[\*\?\[]*)
		if [ ! -r "$hd" ]; then
			UNL=1
			return 0
		fi
		;;
	esac
	# The user owning the home chooses how many files match a glob: at
	# most HOME_MAX_MATCHES of them (in glob order) are start points, the
	# others make the run truncated.
	hf_n=0
	for f in "$P$1"/$REL; do
		[ -e "$f" ] || [ -L "$f" ] || continue
		hf_n=$((hf_n + 1))
		if [ "$hf_n" -gt "$HOME_MAX_MATCHES" ]; then
			HOME_CUT=1
			break
		fi
		f=${f#"$P"}
		case $f in *"
"*)
			# Not scanned: its name cannot be a start point.
			UNL=1
			continue
			;;
		esac
		"$FILE_CB" "$f"
	done
}

HOME_CUT=0
FOUND=0
found() { FOUND=1; }

# each_pattern CALLBACK: call CALLBACK BASE REL for every home pattern. The
# list is split with globbing off: a .ssh directory in the working
# directory must not expand .ssh/authorized_keys*.
each_pattern() {
	for base in /root /home; do
		set -f
		for rel in $HOME_FILES; do
			set +f
			"$1" "$base" "$rel"
		done
		set +f
	done
}

# visit KIND START ALL [HOME]: the hash or meta pass of one start point. Before the
# hash pass reads a byte, the sizes of the files it would hash are summed
# (metadata only) and, when they exceed the budget left, the file size is
# capped so the run hashes at most HASH_BUDGET bytes. The cap is kept for
# the meta pass: a file left out by it, or by the deadline before its start
# point, is truncated, not unreadable.
CAPS=""
BUDGET_CUT=0
visit() {
	if [ "$1" = meta ]; then
		CAPS=${CAPS# }
		vcap=${CAPS%% *}
		CAPS=${CAPS#"$vcap"}
		scan "$2" meta "$3" "${vcap:--}" "${4:-0}"
		return
	fi
	if [ "$(date +%s)" -ge "$DEADLINE" ]; then
		CAPS="$CAPS 0"
		printf '\0T\0'
		return
	fi
	vstart=$2
	vall=$3
	vhome=${4:-0}
	# shellcheck disable=SC2046 # two numbers
	set -- $(scan "$vstart" size "$vall" - "$vhome")
	vcap=${2:--}
	[ "$vcap" = - ] || BUDGET_CUT=1
	HASH_LEFT=$((HASH_LEFT - ${1:-0}))
	# A start point the deadline cut is truncated, not unreadable: cap 0
	# marks none of its files as expected to have a hash (M0), and the
	# hashes written before the cut still reach their files by path.
	scan "$vstart" hash "$vall" "$vcap" "$vhome"
	[ $? -eq 3 ] && vcap=0
	CAPS="$CAPS $vcap"
}

# starts: collect every start point of the profile once, as lines "ALL
# HOME PATH", so that the hash and the meta pass visit the same start
# points in the same order (CAPS is matched by position).
STARTS=""
starts() {
	for r in $LITERAL_ROOTS; do
		if nested "$r" && ! nested_mount "$r"; then
			continue
		fi
		[ "$(root_state "$r")" = scanned ] || continue
		all=0
		[ "$r" = /boot/efi ] && all=1
		STARTS="$STARTS$all 0 $r
"
	done
	HOME_LIST=""
	each_pattern each_home_add
	STARTS="$STARTS$HOME_LIST"
}
each_home_add() {
	each_home_file "$1" "$2" home_add
}
home_add() {
	HOME_LIST="${HOME_LIST}0 1 $1
"
}

# walk KIND: visit every start point.
walk() {
	set -f
	w_ifs=$IFS
	IFS='
'
	for w_s in $STARTS; do
		IFS=$w_ifs
		w_rest=${w_s#* }
		visit "$1" "${w_rest#* }" "${w_s%% *}" "${w_rest%% *}"
	done
	IFS=$w_ifs
	set +f
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
	ssh_qn=1
	ssh_seen=0
	while [ -n "$queue" ]; do
		f=${queue%% *}
		case $queue in *" "*) queue=${queue#* } ;; *) queue="" ;; esac
		ssh_qn=$((ssh_qn - 1))
		ssh_seen=$((ssh_seen + 1))
		if [ "$ssh_seen" -gt "$SSH_MAX_SEEN" ]; then
			SSH_CUT=1
			break
		fi
		ssh_known "$f" && continue
		# A symlink anywhere in the path (a symlinked /etc/ssh, drop-in or
		# Include directory) is never followed; the file is unreadable.
		if ! nolink "$f"; then
			printf 'U\0'
			continue
		fi
		if [ ! -f "$P$f" ] || [ ! -r "$P$f" ]; then
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
				ssh_known "$m" && continue
				# The queue is bounded: wide globs cannot grow it without
				# limit; a cut queue makes the SSH configuration truncated.
				if [ "$ssh_qn" -ge "$SSH_MAX_QUEUE" ]; then
					SSH_CUT=1
					break
				fi
				ssh_qn=$((ssh_qn + 1))
				queue="$queue $m"
				queue=${queue# }
			done
			set -f
		done
		set +f
	done
}

# pattern_state BASE REL: the roots summary entry of one home pattern.
# UNL=1 (a directory that cannot be searched) counts as unreadable here;
# SKIP=1 (a symlinked or newline-named home, /home or .ssh directory) is
# counted once by report_links. Both make the pattern unknown, never
# missing.
pattern_state() {
	FOUND=0
	UNL=0
	SKIP=0
	each_home_file "$1" "$2" found
	if [ "$1" = /root ]; then pat="/root/$2"; else pat="/home/*/$2"; fi
	if [ "$FOUND" = 1 ]; then
		printf 'R%s %s\0' scanned "$pat"
	elif [ "$UNL" = 1 ] || [ "$SKIP" = 1 ]; then
		printf 'R%s %s\0' error "$pat"
	else
		printf 'R%s %s\0' missing "$pat"
	fi
	[ "$UNL" = 1 ] && printf 'U\0'
}

produce() {
	printf 'B%s\0' "$(date +%s)"
	[ -n "$P" ] && printf 'P\0%s\0' "$P"

	# Roots summary.
	for r in $LITERAL_ROOTS; do
		s=$(root_state "$r")
		printf 'R%s %s\0' "$s" "$r"
		[ "$s" = error ] && printf 'U\0'
	done
	# A home pattern is missing only when every place it could match was
	# looked at; a directory that cannot be searched makes it unreadable
	# (and "error" when nothing else matched), never missing.
	each_pattern pattern_state
	report_links

	# Hashes first, then metadata: the awk program needs each hash before
	# the record it belongs to.
	ssh_collect
	starts
	DEADLINE=$(($(date +%s) + HASH_SECONDS))
	HASH_LEFT=$HASH_BUDGET
	walk hash
	[ "$BUDGET_CUT" = 1 ] && printf '\0T\0'
	[ "$HOME_CUT" = 1 ] && printf '\0T\0'
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
function field(   s, c, k, from, ph, hid) {
	ph = LASTH; LASTH = ""
	hid = HID1; HID1 = ""
	if (st == "tag") {
		if (n == 0) { trunc = 1; return }
		c = B[1]
		if ((c >= 48 && c <= 57) || (c >= 97 && c <= 102)) { hashline(hid); return }
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
		# H: the device:inode:ctime the next hash (a home SSH file) was
		# read from and the cutoff second its ctime and mtime must lie
		# before; an H of another form never matches a record.
		else if (c == "H") {
			HID1 = substr(s, 2)
			if (HID1 !~ /^[0-9]+:[0-9]+:[0-9]+(\.[0-9]+)? -?[0-9]+$/ || length(HID1) > 80) HID1 = "- 0"
		}
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
function hashline(id,   k, from, hex) {
	if (n < 67 || B[65] != 32 || (B[66] != 32 && B[66] != 42)) return
	hex = asc(1, 64)
	if (hex !~ /^[0-9a-f]+$/ || length(hex) != 64) return
	from = strip(67)
	if (from == 0 || !pathok(from, n)) return
	LASTH = b64(from, n)
	LASTHAD = LASTH in HS
	if (LASTHAD) LASTOLD = HS[LASTH]
	HS[LASTH] = hex
	if (id != "") HID[LASTH] = id; else delete HID[LASTH]
}
function record(   f, t, rec, m, mt, ct, hash, moved, k, cut) {
	if (split(META, f, " ") != 10 || MPATH == "" || MLINKBAD) { unread++; return }
	t = f[2] == "f" ? "file" : f[2] == "d" ? "dir" : f[2] == "l" ? "symlink" : "other"
	m = oct(f[4]); mt = etime(f[8]); ct = etime(f[9])
	if (!uint(f[3]) || m < 0 || m > 4095 || !uint(f[5]) || !uint(f[6]) || !uint(f[7]) || mt == "" || ct == "" || (t == "symlink" && MLINK == "")) { unread++; return }
	hash = ""
	# A hash bound to a device:inode:ctime (a home SSH file) belongs to this
	# record only if the meta pass saw the same: a file swapped or changed
	# between the passes keeps no hash (unknown; the run is truncated), so
	# the hash of the old content never stands for the new file. An equal
	# ctime proves nothing for a file whose ctime or mtime is not older
	# than the cutoff (coarse timestamps: a write in the same tick keeps
	# them): no hash either.
	moved = 0
	if (MPATH in HID) {
		k = index(HID[MPATH], " ")
		cut = substr(HID[MPATH], k + 1) + 0
		if (substr(HID[MPATH], 1, k - 1) != f[10] ":" f[7] ":" f[9] || !(ct + 0 < cut && mt + 0 < cut)) { delete HS[MPATH]; moved = 1; trunc = 1 }
		delete HID[MPATH]
	}
	if (t == "file" && (MPATH in HS)) {
		if (hashed + f[3] > HASHBUDGET) trunc = 1
		else { hashed += f[3]; hash = HS[MPATH] }
		delete HS[MPATH]
	} else if (t == "file" && f[1] == "M1" && !moved) unread++
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
