#!/usr/bin/env bash
# Reads changed file paths on stdin (one per line) and fails if any of them
# is protected according to .github/protected-paths.txt (or the file named in
# PROTECTED_PATHS_FILE; CI passes the base branch's copy so that a change
# cannot edit the list it is checked against).
#
# Always produce the input with --no-renames, so a move lists both paths:
#   git diff --cached --name-only --no-renames | scripts/check-protected-paths.sh
#   git diff --name-only --no-renames origin/main...HEAD | scripts/check-protected-paths.sh
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
list="${PROTECTED_PATHS_FILE:-$root/.github/protected-paths.txt}"
[[ -f "$list" ]] || { echo "protected-paths: $list missing" >&2; exit 2; }

mapfile -t rules < <(grep -v -E '^\s*(#|$)' "$list")

hits=()
while IFS= read -r path; do
  [[ -z "$path" ]] && continue
  for rule in "${rules[@]}"; do
    if [[ "$path" == "$rule" ]] || { [[ "$rule" == */ ]] && [[ "$path" == "$rule"* ]]; }; then
      hits+=("$path")
      break
    fi
  done
done

if (( ${#hits[@]} > 0 )); then
  echo "Protected paths changed (human review required, see AGENTS.md):" >&2
  printf '  %s\n' "${hits[@]}" >&2
  exit 1
fi
