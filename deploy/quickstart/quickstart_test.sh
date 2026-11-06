#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Tests for the shared binary list (deploy/quickstart/binaries.txt) that
# deploy/install.sh, deploy/uninstall.sh and
# deploy/quickstart/setup-nebula.sh all use (one parser,
# deploy/quickstart/binaries_lib.sh), so the scripts cannot drift
# (WA-03: a quickstart run stopped at step 5 because setup-nebula.sh
# copied four binaries but install.sh required five).
#
# No root needed. Run it from anywhere:
#
#   bash deploy/quickstart/quickstart_test.sh
#
# Exit status: 0 if all cases pass, 1 otherwise.

set -u

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "${script_dir}/../.." && pwd)
# Cases below reuse `repo` for their sandbox; keep the real one.
real_repo="$repo"
list_file="${script_dir}/binaries.txt"
install_sh="${repo}/deploy/install.sh"
uninstall_sh="${repo}/deploy/uninstall.sh"
setup_sh="${script_dir}/setup-nebula.sh"

pass=0
fail=0
ok()  { echo "ok   $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; fail=$((fail + 1)); }

expected=(nebula nebula-server nebula-executor nebula-discovery nebula-pve-collector)

# The same parser the scripts use (one copy, sourced here and there).
# shellcheck source=binaries_lib.sh
. "$script_dir/binaries_lib.sh"

# --- 1. The list file names exactly the five binaries ----------------------
if [[ -f "$list_file" ]]; then
  mapfile -t got < <(read_binaries "$list_file")
  if [[ "${got[*]}" == "${expected[*]}" ]]; then
    ok "binaries.txt lists exactly the five binaries"
  else
    bad "binaries.txt lists exactly the five binaries (got: ${got[*]})"
  fi
else
  bad "binaries.txt exists"
fi

# --- 2. All three scripts load the list from that one file -------------------
for s in "$setup_sh" "$install_sh" "$uninstall_sh"; do
  if grep -q 'binaries\.txt' "$s"; then
    ok "$(basename -- "$s") loads the list from binaries.txt"
  else
    bad "$(basename -- "$s") loads the list from binaries.txt"
  fi
done

# --- 3. No hardcoded second copy of the list remains ------------------------
# A loop over a literal list of binary names is the drift this guards
# against; the loops must iterate the loaded array instead.
if grep -nE '^[[:space:]]*for (b|bin) in nebula( |$)' "$setup_sh" "$install_sh" "$uninstall_sh"; then
  bad "no hardcoded binary list loop remains in the scripts"
else
  ok "no hardcoded binary list loop remains in the scripts"
fi

# --- 4. Functional: the copy block of setup-nebula.sh copies all five -------
# Extract the real copy block from the script (between the begin/end
# markers) and run it against a sandbox checkout: bin/ holds the five
# built binaries, and the block must copy all of them next to deploy/.
sandbox=$(mktemp -d)
trap 'rm -rf "$sandbox"' EXIT
mkdir -p "$sandbox/bin" "$sandbox/deploy/quickstart"
cp "$list_file" "$sandbox/deploy/quickstart/binaries.txt"
cp "$script_dir/binaries_lib.sh" "$sandbox/deploy/quickstart/binaries_lib.sh"
for b in "${expected[@]}"; do
  printf '#!/bin/sh\n' > "$sandbox/bin/$b"
done
die()  { echo "sandbox die: $*" >&2; exit 1; }
repo="$sandbox"
mapfile -t copy_block < <(sed -n '/^# begin: copy binaries/,/^# end: copy binaries/p' "$setup_sh" | grep -v '^# \(begin\|end\): copy binaries$')
if [[ ${#copy_block[@]} -gt 0 ]] && eval "$(printf '%s\n' "${copy_block[@]}")"; then
  missing=()
  for b in "${expected[@]}"; do
    [[ -f "$sandbox/$b" ]] || missing+=("$b")
  done
  if [[ ${#missing[@]} -eq 0 ]]; then
    ok "setup-nebula.sh copy block copies all five binaries next to deploy/"
  else
    bad "setup-nebula.sh copy block copies all five binaries next to deploy/ (missing: ${missing[*]})"
  fi
else
  bad "setup-nebula.sh copy block copies all five binaries next to deploy/ (block missing or failed)"
fi

# --- 5. Functional: the load block of install.sh yields the five names ------
# Same idea for install.sh: run its real load block with a sandbox
# script_dir and check the array it produces.
mkdir -p "$sandbox/deploy/quickstart"
script_dir="$sandbox/deploy"
mapfile -t load_block < <(sed -n '/^# begin: load binary list/,/^# end: load binary list/p' "$install_sh" | grep -v '^# \(begin\|end\): load binary list$')
if [[ ${#load_block[@]} -gt 0 ]]; then
  eval "$(printf '%s\n' "${load_block[@]}")"
  # shellcheck disable=SC2154 # assigned inside the eval'd block
  if [[ "${binaries[*]}" == "${expected[*]}" ]]; then
    ok "install.sh load block yields exactly the five binaries"
  else
    bad "install.sh load block yields exactly the five binaries (got: ${binaries[*]})"
  fi
else
  bad "install.sh load block yields exactly the five binaries (block missing)"
fi

# --- 6. Functional: the remove block of uninstall.sh removes all five -------
# The block must remove every binary from the shared list, not a
# hardcoded copy (the old copy lacked nebula-pve-collector).
mkdir -p "$sandbox/usrbin"
for b in "${expected[@]}"; do
  printf '#!/bin/sh\n' > "$sandbox/usrbin/$b"
done
script_dir="$sandbox/deploy"
bin_dir="$sandbox/usrbin"
mapfile -t remove_block < <(sed -n '/^# begin: remove binaries/,/^# end: remove binaries/p' "$uninstall_sh" | grep -v '^# \(begin\|end\): remove binaries$')
if [[ ${#remove_block[@]} -gt 0 ]] && ( eval "$(printf '%s\n' "${remove_block[@]}")" ); then
  left=()
  for b in "${expected[@]}"; do
    [[ -e "$sandbox/usrbin/$b" ]] && left+=("$b")
  done
  if [[ ${#left[@]} -eq 0 ]]; then
    ok "uninstall.sh remove block removes all five binaries"
  else
    bad "uninstall.sh remove block removes all five binaries (left: ${left[*]})"
  fi
else
  bad "uninstall.sh remove block removes all five binaries (block missing or failed)"
fi

# --- 7. The .deb ships every file install.sh reads ---------------------------
# On a packaged install install.sh runs from /usr/share/nebula/deploy
# (--from-package), so every file it reads under ${script_dir} must be in
# the nfpm contents of .goreleaser.yaml (the tarball carries the whole
# deploy/ tree, so only the package can lose a file).
goreleaser="${real_repo}/.goreleaser.yaml"
if [[ -f "$goreleaser" ]]; then
  mapfile -t install_reads < <(grep -oE '\$\{script_dir\}/[A-Za-z0-9_./-]+' "$install_sh" | sed 's|.*script_dir}/||' | sort -u)
  install_dst=$(grep -oE 'dst: [^ ]+/install\.sh$' "$goreleaser" | head -1 | awk '{print $2}')
  if [[ -n "$install_dst" && ${#install_reads[@]} -gt 0 ]]; then
    base="${install_dst%/*}"
    mapfile -t nfpm_dsts < <(grep -oE 'dst: [^ ]+' "$goreleaser" | awk '{print $2}')
    missing=()
    for rel in "${install_reads[@]}"; do
      covered=0
      for dst in "${nfpm_dsts[@]}"; do
        if [[ "$dst" == "${base}/${rel}" || "$dst" == "${base}/${rel}/" ]]; then
          covered=1
          break
        fi
      done
      [[ $covered -eq 1 ]] || missing+=("$rel")
    done
    if [[ ${#missing[@]} -eq 0 ]]; then
      ok ".deb nfpm contents include every file install.sh reads"
    else
      bad ".deb nfpm contents include every file install.sh reads (missing under ${base}: ${missing[*]})"
    fi
  else
    bad ".deb nfpm contents include every file install.sh reads (could not derive the install.sh dst or the read paths)"
  fi
else
  bad ".goreleaser.yaml exists"
fi

# --- 8. Syntax of the scripts ------------------------------------------------
for s in "$setup_sh" "$install_sh" "$uninstall_sh" "$real_repo/deploy/quickstart/binaries_lib.sh"; do
  if bash -n "$s" 2>/dev/null; then
    ok "bash -n $(basename -- "$s")"
  else
    bad "bash -n $(basename -- "$s")"
  fi
done

echo
echo "quickstart_test: ${pass} passed, ${fail} failed"
[[ $fail -eq 0 ]]
