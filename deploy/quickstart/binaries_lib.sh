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
# # are ignored.

# read_binaries <file>: print the binary names from <file>, one per line.
read_binaries() {
  local b
  while IFS= read -r b; do
    b="${b%%#*}"
    if [[ -n "$b" ]]; then
      printf '%s\n' "$b"
    fi
  done < "$1"
}
