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
out=$(lspci -mm -nn -D 2>/dev/null) || pre "lspci failed"
# lspci -mm quotes every field; unquote to slot, class, vendor, device.
# Only NVIDIA display and 3D controllers pass; the parser re-checks the
# schema of every line.
out=$(printf '%s\n' "$out" | awk '
  $4 ~ /^(3D controller|VGA compatible controller)$/ && ($6 ~ /^NVIDIA/ || $6 ~ /\[10de\]/) {
    print $2 "\t" $4 "\t" $6 "\t" $8
  }' FS='"' | head -n 512)
out=$(printf '%s\n' "$out" | b64)
printf '{"format":"pci-inventory-v1","phase":"done","present":true,"devices":"%s"}\n' "$out"
