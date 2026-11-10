#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Browser tests of the web login, the traffic map, the vulnerabilities and
# the attack-path pages (make test-browser).
# Needs Node.js and Playwright with Chromium; set PLAYWRIGHT_MODULE to the
# playwright package path if it is not resolvable as "playwright". Every
# spec gets a fresh harness (each registers its own first security key).
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
chmod 700 "$work"
pid=
# Kill only a harness that is still running: an empty pid must never reach
# kill, since "kill 0" signals the whole process group (this script and
# the calling make). The trap keeps the script's exit status.
cleanup() {
  local rc=$?
  if [ -n "${pid:-}" ]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf "$work"
  exit "$rc"
}
trap cleanup EXIT
go build -o "$work/harness" "$root/test/browser/harness"

run_spec() {
  local spec=$1 data port
  data=$(mktemp -d "$work/data.XXXXXX")
  chmod 700 "$data"
  port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
  "$work/harness" "$port" "$data" 2>"$work/harness.log" &
  pid=$!
  for _ in $(seq 50); do curl -fs "http://127.0.0.1:$port/login" >/dev/null 2>&1 && break; sleep 0.1; done
  if ! node "$root/test/browser/$spec" "$port"; then
    echo "--- harness log ($spec)" >&2; cat "$work/harness.log" >&2; exit 1
  fi
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  pid=
}

run_spec login.spec.js
run_spec trafficmap.spec.js
run_spec vuln.spec.js
run_spec attackpath.spec.js
