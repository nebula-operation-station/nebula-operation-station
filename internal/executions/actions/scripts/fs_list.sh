#!/bin/sh
# filesystem.list 1.0.0 (Nebula built-in, read-only): real mounts.
# Every mount df reports, as fstype, mount point, size and used bytes.
# Virtual kernel filesystems are not filtered here: the parser drops them
# with its explicit list, so an empty result stays distinct from a host
# whose only mounts are virtual. Values are base64 so that host text can
# never break the JSON document.
set -u
b64() { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }
mounts=$(df -B1 -P -T 2>/dev/null | awk '
  NR > 1 {
    fstype=$2; size=$3; used=$4;
    m = $7; for (i = 8; i <= NF; i++) m = m " " $i;
    printf "%s\t%s\t%s\t%s\n", fstype, m, size, used
  }')
printf '{"format":"fs-list-v1","phase":"done","mounts":"%s"}\n' \
  "$(printf '%s' "$mounts" | b64)"
