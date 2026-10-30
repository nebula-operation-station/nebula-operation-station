#!/bin/sh
# pci.inventory 1.0.0 (Nebula built-in, PCI, read-only): the host's
# NVIDIA display and 3D controllers, from lspci. A host without lspci
# is a successful result with "present":false.
set -u
b64() { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }
pre() { printf '{"format":"pci-inventory-v1","phase":"precheck","reason":"%s"}\n' "$1"; exit 10; }
if ! command -v lspci >/dev/null 2>&1; then
	printf '{"format":"pci-inventory-v1","phase":"done","present":false}\n'
	exit 0
fi
# Bound the stream before shell capture, with one overflow byte and a
# four-byte exit-status trailer. Base64 preserves NULs and trailing newlines
# until after the byte count is checked.
max_output_bytes=1048576
out=$({ lspci -mm -nn -D 2>/dev/null; printf '\n%03d' "$?"; } | head -c "$((max_output_bytes + 5))" | b64)
captured_bytes=$((${#out} / 4 * 3))
case "$out" in
*==) captured_bytes=$((captured_bytes - 2)) ;;
*=) captured_bytes=$((captured_bytes - 1)) ;;
esac
[ "$captured_bytes" -le "$((max_output_bytes + 4))" ] || pre "command output exceeds byte limit"
# The sentinel preserves newlines while decoding the bounded capture.
out=$(printf '%s' "$out" | base64 -d; printf '.')
out=${out%.}
status=${out##*'
'}
out=${out%????}
[ "$status" = 000 ] || pre "lspci failed"
# lspci -mm -nn -D has an unquoted slot followed by quoted fields.
# Normalize numeric class suffixes to the parser's class names.
# Only NVIDIA display and 3D controllers pass; the parser re-checks the
# schema of every line.
out=$(printf '%s\n' "$out" | awk '
  $2 ~ /^(3D controller \[0302\]|VGA compatible controller \[0300\])$/ && ($4 ~ /^NVIDIA/ || $4 ~ /\[10de\]/) {
    slot = $1
    sub(/[[:space:]]+$/, "", slot)
    class = $2
    sub(/ \[[0-9a-f]+\]$/, "", class)
    print slot "\t" class "\t" $4 "\t" $6
  }' FS='"' | head -n 512)
out=$(printf '%s\n' "$out" | b64)
printf '{"format":"pci-inventory-v1","phase":"done","present":true,"devices":"%s"}\n' "$out"
