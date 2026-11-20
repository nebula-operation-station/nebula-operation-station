#!/bin/sh
# package.list_installed 1.1.0 (Nebula built-in, os-debian, read-only).
# Lists the installed binary packages with their source package and source
# version from the dpkg database (dpkg-query -W), plus the running kernel
# (uname -r, uname -v). No root, no apt, no network, nothing written.
# Output: exactly one JSON document (the executor accepts nothing else)
#   {"format":"nos-installed-v1","text":"...","truncated":false}
# where text is osdebian.InstalledFormat (nos-installed-v1) unchanged,
# JSON-escaped; the server parses it as untrusted text. Built-Using is kept
# for linux-image-* binaries only. The END record is written only after
# dpkg-query succeeded and counts the P records, so a failed or cut read is
# visible to the parser.
# Escaping: '"' and '\' are escaped, TAB is \t, the line end is \n, other
# control bytes are \u00XX, and every byte above 0x7e becomes �, so the
# document is ASCII and valid UTF-8 whatever the dpkg database holds (dpkg
# names, versions and Built-Using are ASCII; such a line stays malformed).
# The document stays below max_result (hostrun.MaxResult): P records that
# do not fit are left out, the document says "truncated":true and has no
# END record, and a message goes to stderr.
set -u
export LC_ALL=C
# hostrun.MaxResult: a larger result is discarded as a whole.
max_result=1048576
command -v dpkg-query >/dev/null 2>&1 || { echo "no dpkg-query: not a Debian or Ubuntu host" >&2; exit 3; }
pkgs=$(dpkg-query -W --showformat='P\t${db:Status-Status}\t${Package}\t${Architecture}\t${Version}\t${source:Package}\t${source:Version}\t${Built-Using}\t.\n' 2>/dev/null)
rc=$?
{ [ -z "$pkgs" ] || printf '%s\n' "$pkgs"; } |
NOS_KREL=$(uname -r 2>/dev/null) NOS_KBUILD=$(uname -v 2>/dev/null) NOS_RC=$rc awk -F'\t' -v max="$max_result" '
function esc(s,   out, c) {
  out = ""
  while (match(s, /["\\]|[^ -~]/)) {
    c = substr(s, RSTART, 1)
    out = out substr(s, 1, RSTART - 1) ((c in tbl) ? tbl[c] : "\\ufffd")
    s = substr(s, RSTART + 1)
  }
  return out s
}
function emit(line,   e) {
  e = esc(line) "\\n"
  printf "%s", e
  size += length(e)
}
BEGIN {
  OFS = "\t"; n = 0; cut = 0
  for (i = 1; i < 32; i++) tbl[sprintf("%c", i)] = sprintf("\\u%04x", i)
  tbl[sprintf("%c", 127)] = "\\u007f"
  tbl["\t"] = "\\t"; tbl["\""] = "\\\""; tbl["\\"] = "\\\\"
  head = "{\"format\":\"nos-installed-v1\",\"text\":\""
  printf "%s", head
  size = length(head)
  # Room kept for the K and END records and the document end: each value
  # of the K record is at most 1024 bytes and escapes to at most 6 bytes
  # per byte.
  reserve = 16384
  emit("nos-installed-v1")
}
{
  if (cut) next
  isp = substr($0, 1, 2) == "P\t"
  if (isp && NF == 9 && substr($3, 1, 12) != "linux-image-") $8 = ""
  # Worst case: every byte escapes to 6.
  if (max - reserve < size + 6 * length($0) + 2) { cut = 1; next }
  if (isp) n++
  emit($0)
}
END {
  krel = ENVIRON["NOS_KREL"]; kbuild = ENVIRON["NOS_KBUILD"]
  # An over-long value is not cut to a shorter, valid looking one: the K
  # record is then malformed and the kernel stays unknown.
  if (1024 < length(krel) || 1024 < length(kbuild)) emit("K")
  else emit("K" OFS krel OFS kbuild)
  if (ENVIRON["NOS_RC"] == "0" && !cut) emit("END" OFS n)
  printf "\",\"truncated\":%s}\n", (cut ? "true" : "false")
  if (cut) exit 4
}'
ac=$?
if [ "$ac" -eq 4 ]; then
  echo "package.list_installed: the result limit of $max_result bytes was reached; the inventory is partial (truncated)" >&2
elif [ "$ac" -ne 0 ]; then
  exit 1
fi
[ "$rc" -eq 0 ] || exit 1
