#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Browser test of the web login (make test-browser). Needs Node.js and
# Playwright with Chromium; set PLAYWRIGHT_MODULE to the playwright package
# path if it is not resolvable as "playwright".
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
chmod 700 "$work"
trap 'kill "${pid:-0}" 2>/dev/null || true; rm -rf "$work"' EXIT
go build -o "$work/harness" "$root/test/browser/harness"
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
mkdir "$work/data" && chmod 700 "$work/data"
"$work/harness" "$port" "$work/data" 2>"$work/harness.log" &
pid=$!
for _ in $(seq 50); do curl -fs "http://127.0.0.1:$port/login" >/dev/null 2>&1 && break; sleep 0.1; done
if ! node "$root/test/browser/login.spec.js" "$port"; then
  echo "--- harness log" >&2; cat "$work/harness.log" >&2; exit 1
fi
