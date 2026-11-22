#!/bin/sh
# package.list_updates 1.0.0 (Nebula built-in, os-debian, read-only).
# Lists pending updates with an apt simulation (no root, no lock), plus
# reboot-required and the age of the package lists. Raw apt output is
# base64-wrapped; the server parses it as untrusted text.
set -u
export LC_ALL=C
# hostrun.MaxResult: a larger result is discarded as a whole.
max_result=1048576
# Line cap of the candidates section (MaxCandidateStanzas lines of 4).
max_cand_lines=160000
# osdebian.MaxPackages: a simulation with more Inst lines cannot be listed.
max_sim_lines=20000
b64() { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }
command -v apt-get >/dev/null 2>&1 || { echo "no apt-get: not a Debian or Ubuntu host" >&2; exit 3; }
proxmox=false
[ -d /etc/pve ] && proxmox=true
mode=upgrade
[ "$proxmox" = true ] && mode=dist-upgrade
reboot=false
[ -e /var/run/reboot-required ] && reboot=true
pkgs=""
[ -r /var/run/reboot-required.pkgs ] && pkgs=$(head -c 65536 /var/run/reboot-required.pkgs | b64)
lists=$(stat -c %Y /var/lib/apt/lists 2>/dev/null || echo 0)
case "$lists" in ''|*[!0-9]*) lists=0 ;; esac
doc() {
  printf '{"format":"apt-simulate-v1","mode":"%s","simulate":"%s","reboot_required":%s,"reboot_pkgs":"%s","lists_mtime":%s,"proxmox":%s,"candidates":"%s","candidates_truncated":%s}\n' \
    "$mode" "$sim" "$reboot" "$pkgs" "$lists" "$proxmox" "$1" "$2"
}
# Simulation: the Inst lines stream from apt-get through grep and awk into
# the stream variable; the raw apt output is never stored. apt-get's exit
# status and the cut flag follow the lines as token lines that apt does not
# print. The awk keeps whole Inst lines up to max_sim_lines and up to
# sim_budget bytes: what fits next to the rest of the document, base64 turns
# 3 bytes into 4. A simulation that does not fit is not listed at all: a
# partial list would read as "only these updates", so the run fails with
# exit 5. A failed simulation is a failed run too, never an empty update list.
sim=""
skel=$(doc "" false)
sim_budget=$(( (max_result - ${#skel} - 64) / 4 * 3 ))
stream=$({ apt-get -s -o Debug::NoLocking=1 "$mode" 2>/dev/null; echo "nebula-apt-rc=$?"; } \
  | grep -E '^(Inst |nebula-apt-rc=)' \
  | awk -v max="$sim_budget" -v cap="$max_sim_lines" '
      /^nebula-apt-rc=/ { rc = $0; sub(/^nebula-apt-rc=/, "", rc); next }
      cut { next }
      { line = $0 "\n" }
      count == cap || n + length(line) > max { cut = 1; next }
      { printf "%s", line; n += length(line); count++ }
      END { if (cut) print "nebula-apt-cut=1"; print "nebula-apt-rc=" rc }')
simrc=${stream##*nebula-apt-rc=}
[ "$simrc" = 0 ] || { echo "apt-get simulation failed" >&2; exit 4; }
# The cut marker is the whole line awk appends before the final rc line. Only
# awk prints a line that is exactly that text (Inst lines start with "Inst ",
# and the rc line is the last one), so repository text such as an Inst line
# that contains "nebula-apt-cut=1" never matches. The leading newline lets a
# marker on the first line match too.
case "
$stream" in
  *"
nebula-apt-cut=1
nebula-apt-rc="*)
    echo "apt-get simulation exceeds the result size limit: the upgrade cannot be listed completely" >&2
    exit 5 ;;
esac
raw=${stream%nebula-apt-rc=*}
[ -n "$raw" ] && sim=$(printf '%s' "$raw" | b64)

# Candidate source versions (ADR 0011 D8): the simulation shows binary
# versions only, a binNMU's source version is in the candidate's apt-cache
# "Source:" field. Only strictly shaped name[:arch]=version specs reach
# xargs. The section is optional (without it every source stays unknown,
# "fix not verified") and gets only the bytes the rest of the result
# leaves under max_result, so it can never cost the update list. awk
# passes whole stanzas only (closed by their blank line) and stops at the
# budget or the line cap; a cut section is marked candidates_truncated.
cands=""
truncated=false
if [ -n "$raw" ] && command -v apt-cache >/dev/null 2>&1; then
  base=$(doc "" false)
  # Bytes left after the document without candidates (and its newline),
  # with a margin; base64 turns 3 raw bytes into 4.
  avail=$((max_result - ${#base} - 1 - 64))
  budget=$((avail / 4 * 3))
  if [ "$budget" -le 0 ]; then
    truncated=true
  else
    # "; echo ." keeps the trailing blank line that $() would strip.
    sect=$(printf '%s\n' "$raw" \
      | sed -n 's/^Inst \([^ ]*\) \(\[[^]]*\] \)\{0,1\}(\([^ ]*\) .*/\1=\3/p' \
      | grep -E '^[a-z0-9][a-z0-9+.-]*(:[a-z0-9-]+)?=[A-Za-z0-9.+~:-]+$' \
      | xargs -r env apt-cache show 2>/dev/null \
      | grep -E '^(Package|Version|Source):|^$' \
      | awk -v max="$budget" -v lines="$max_cand_lines" '
          NR > lines { cut = 1; exit }
          { buf = buf $0 "\n" }
          length(buf) > max - n { cut = 1; exit }
          $0 == "" { printf "%s", buf; n += length(buf); buf = "" }
          END { if (cut) print "TRUNCATED" }'
      echo .)
    sect=${sect%.}
    # Only Package/Version/Source and blank lines pass grep, so the
    # marker line can only come from awk.
    marker="TRUNCATED
"
    case "$sect" in
      *"$marker") truncated=true; sect=${sect%"$marker"} ;;
    esac
    [ -n "$sect" ] && cands=$(printf '%s' "$sect" | b64)
  fi
fi
doc "$cands" "$truncated"
