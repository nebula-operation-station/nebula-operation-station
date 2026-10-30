#!/bin/sh
# host.metrics 1.0.0 (Nebula built-in, read-only): machine metrics.
# CPU usage over a short sample, load average, RAM used/total and the
# fullest real filesystem. Values are base64 so that host text can never
# break the JSON document; an empty value means the reading is unavailable
# (never a successful zero).
set -u
b64() { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }

# --- CPU usage over a short sample (/proc/stat) ---
cpu_sample() { awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8+$9, $5+$6}' /proc/stat 2>/dev/null; }
s1=$(cpu_sample)
sleep 0.5
s2=$(cpu_sample)
cpu=$(printf '%s %s\n' "$s1" "$s2" | awk '{
  dt = $3 - $1; di = $4 - $2;
  if (dt > 0) { p = 100 * (dt - di) / dt; if (p < 0) p = 0; if (p > 100) p = 100; printf "%.1f", p }
}')

# --- Load average, 1/5/15 minutes (/proc/loadavg) ---
load=$(awk '{print $1, $2, $3}' /proc/loadavg 2>/dev/null)

# --- RAM used/total in bytes (/proc/meminfo) ---
mem=$(awk '
  /^MemTotal:/{t=$2}
  /^MemAvailable:/{a=$2; have=1}
  /^MemFree:/{f=$2}
  /^Buffers:/{b=$2}
  /^Cached:/{c=$2}
  END{
    if (t > 0) {
      if (have && a > 0 && a <= t) u = t - a;
      else if (f > 0) u = t - (f + b + c);
      else u = "";
      if (u != "" && u >= 0 && u <= t) printf "%d %d", u*1024, t*1024
    }
  }' /proc/meminfo 2>/dev/null)

# --- Fullest real filesystem (virtual kernel filesystems excluded) ---
disk=$(df -B1 -P -T 2>/dev/null | awk '
  NR > 1 {
    fstype=$2; size=$3+0; used=$4+0;
    if (size <= 0) next;
    if (fstype ~ /^(proc|sysfs|devtmpfs|devpts|cgroup|cgroup2|pstore|securityfs|debugfs|tracefs|fusectl|configfs|mqueue|hugetlbfs|bpf|autofs|binfmt_misc|rpc_pipefs|nsfs|selinuxfs|efivarfs|ramfs|tmpfs|swap|shm)$/) next;
    p = 100*used/size;
    if (p > best) { best = p; m = $7; for (i = 8; i <= NF; i++) m = m " " $i; u = used; s = size }
  }
  END { if (best != "") printf "%s\t%d\t%d", m, u, s }')

printf '{"format":"host-metrics-v1","phase":"done","cpu":"%s","load":"%s","mem":"%s","disk":"%s"}\n' \
  "$(printf '%s' "$cpu" | b64)" "$(printf '%s' "$load" | b64)" "$(printf '%s' "$mem" | b64)" "$(printf '%s' "$disk" | b64)"
