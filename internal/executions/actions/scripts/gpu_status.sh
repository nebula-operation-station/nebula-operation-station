#!/bin/sh
# gpu.status 1.0.0 (Nebula built-in, GPU, read-only): per-GPU status from
# nvidia-smi with a fixed query. A host without nvidia-smi is a
# successful result with "present":false; a missing driver is a precheck
# failure, never an empty GPU list.
set -u
b64() { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }
pre() { printf '{"format":"gpu-status-v1","phase":"precheck","reason":"%s"}\n' "$1"; exit 10; }
if ! command -v nvidia-smi >/dev/null 2>&1; then
	printf '{"format":"gpu-status-v1","phase":"done","present":false}\n'
	exit 0
fi
# Bound the stream before shell capture, with one overflow byte and a
# four-byte exit-status trailer. Base64 preserves NULs and trailing newlines
# until after the byte count is checked.
max_output_bytes=1048576
out=$({ nvidia-smi --query-gpu=index,uuid,pci.bus_id,name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw --format=csv,noheader,nounits 2>&1; printf '\n%03d' "$?"; } | head -c "$((max_output_bytes + 5))" | b64)
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
[ "$status" = 000 ] || {
	# The host's own text is not echoed back: only a fixed reason.
	case "$out" in
	*driver*) pre "the NVIDIA driver is not loaded or not working" ;;
	*) pre "nvidia-smi failed" ;;
	esac
}
out=$(printf '%s\n' "$out" | head -n 64 | b64)
printf '{"format":"gpu-status-v1","phase":"done","present":true,"gpus":"%s"}\n' "$out"
