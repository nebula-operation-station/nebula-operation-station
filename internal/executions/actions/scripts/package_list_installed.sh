#!/bin/sh
# package.list_installed 1.0.0 (Nebula built-in, os-debian, read-only).
# Lists the installed binary packages with their source package and source
# version from the dpkg database (dpkg-query -W), plus the running kernel
# (uname -r, uname -v). No root, no apt, no network, nothing written.
# Output: osdebian.InstalledFormat (nos-installed-v1); the server parses it
# as untrusted text. Built-Using is kept for linux-image-* binaries only.
# The END record is written only after dpkg-query succeeded and counts the
# P records, so a failed or cut read is visible to the parser.
set -u
export LC_ALL=C
command -v dpkg-query >/dev/null 2>&1 || { echo "no dpkg-query: not a Debian or Ubuntu host" >&2; exit 3; }
pkgs=$(dpkg-query -W --showformat='P\t${db:Status-Status}\t${Package}\t${Architecture}\t${Version}\t${source:Package}\t${source:Version}\t${Built-Using}\t.\n' 2>/dev/null)
rc=$?
{ [ -z "$pkgs" ] || printf '%s\n' "$pkgs"; } |
NOS_KREL=$(uname -r 2>/dev/null) NOS_KBUILD=$(uname -v 2>/dev/null) NOS_RC=$rc awk -F'\t' '
BEGIN { OFS = "\t"; n = 0; print "nos-installed-v1" }
substr($0, 1, 2) == "P\t" {
  n++
  if (NF == 9 && substr($3, 1, 12) != "linux-image-") $8 = ""
}
{ print }
END {
  print "K", ENVIRON["NOS_KREL"], ENVIRON["NOS_KBUILD"]
  if (ENVIRON["NOS_RC"] == "0") print "END", n
}'
[ "$rc" -eq 0 ] || exit 1
