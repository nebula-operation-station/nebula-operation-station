#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Shared parsing of deploy/quickstart/binaries.txt, the single source of
# truth for the binary list. Sourced (not executed) by deploy/install.sh,
# deploy/uninstall.sh and deploy/quickstart/setup-nebula.sh, and by
# deploy/quickstart/quickstart_test.sh: one parser, so the list format
# cannot drift between the scripts.
#
# Format: one binary name per line; blank lines and lines starting with
# # are ignored. A name is [A-Za-z0-9][A-Za-z0-9._-]*: no whitespace, no
# path separators, no inline comments. The names are used by root
# install(1) and rm -f, so anything else is rejected, not guessed at.

# read_binaries <file>: print the binary names from <file>, one per line.
# Returns non-zero (with a message on stderr) on the first invalid line,
# so the caller can stop instead of acting on a partial or mangled list.
read_binaries() {
  local b
  # `|| [[ -n "$b" ]]`: read returns non-zero on a last line without a
  # trailing newline; without the guard that line would be dropped.
  while IFS= read -r b || [[ -n "$b" ]]; do
    b="${b%$'\r'}"
    if [[ -z "${b//[[:space:]]/}" || "$b" =~ ^[[:space:]]*# ]]; then
      continue
    fi
    if [[ ! "$b" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
      echo "binaries_lib: invalid binary name in $1: ${b@Q}" >&2
      return 1
    fi
    printf '%s\n' "$b"
  done < "$1"
}
