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
libtmp=""
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
# The reference must be in working code, not a comment: a script that only
# mentions binaries.txt in a comment loads nothing.
for s in "$setup_sh" "$install_sh" "$uninstall_sh"; do
  if grep -vE '^[[:space:]]*#' "$s" | grep -q 'binaries\.txt' \
     && grep -vE '^[[:space:]]*#' "$s" | grep -q 'binaries_lib\.sh'; then
    ok "$(basename -- "$s") loads the list from binaries.txt"
  else
    bad "$(basename -- "$s") loads the list from binaries.txt"
  fi
done

# --- 3. No hardcoded second copy of the list remains ------------------------
# A for-loop over literal binary names, or a literal array of them, is the
# drift this guards against: the scripts must iterate the loaded array.
# find_hardcoded prints one line per hardcoded list it finds:
#   - a for-loop (quoted or unquoted) whose word list names a binary,
#   - an array literal (single- or multi-line) holding two or more names.
# Message lines may name binaries in prose; only loops and arrays count.
find_hardcoded() {
  local s="$1" line rest tok name n
  local -a block=()
  while IFS= read -r line; do
    if [[ ${#block[@]} -gt 0 ]]; then
      block+=("$line")
      if [[ "$line" == *")"* ]]; then
        n=0
        for name in "${expected[@]}"; do
          for l in "${block[@]}"; do
            [[ " $l " == *" $name "* ]] && n=$((n + 1))
          done
        done
        if [[ $n -ge 2 ]]; then
          printf '%s: %s\n' "$(basename -- "$s")" "${block[0]}"
        fi
        block=()
      fi
      continue
    fi
    if [[ "$line" =~ ^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=\( ]]; then
      block=("$line")
      if [[ "$line" == *")"* ]]; then
        n=0
        for name in "${expected[@]}"; do
          [[ " $line " == *" $name "* ]] && n=$((n + 1))
        done
        if [[ $n -ge 2 ]]; then
          printf '%s: %s\n' "$(basename -- "$s")" "$line"
        fi
        block=()
      fi
      continue
    fi
    if [[ "$line" =~ ^[[:space:]]*for[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]+in[[:space:]]+(.*)$ ]]; then
      rest=${BASH_REMATCH[1]//\"/}
      rest=${rest//\'/}
      n=0
      for tok in $rest; do
        for name in "${expected[@]}"; do
          [[ "$tok" == "$name" ]] && n=1
        done
      done
      if [[ $n -eq 1 ]]; then
        printf '%s: %s\n' "$(basename -- "$s")" "$line"
      fi
    fi
  done < <(grep -vE '^[[:space:]]*#' "$s")
}
hardcoded=()
for s in "$setup_sh" "$install_sh" "$uninstall_sh"; do
  while IFS= read -r hit; do
    [[ -n "$hit" ]] && hardcoded+=("$hit")
  done < <(find_hardcoded "$s")
done
if [[ ${#hardcoded[@]} -eq 0 ]]; then
  ok "no hardcoded binary list loop remains in the scripts"
else
  bad "no hardcoded binary list loop remains in the scripts (${hardcoded[*]})"
fi
# The guard must catch the variants it exists for: unquoted and quoted
# loops, single-line and multi-line array literals.
fixture=$(mktemp)
cat > "$fixture" <<'FIX'
for bin in nebula nebula-server nebula-executor nebula-discovery nebula-pve-collector; do
  rm -f /usr/bin/$bin
done
for bin in "nebula" "nebula-server" "nebula-executor" "nebula-discovery" "nebula-pve-collector"; do
  rm -f /usr/bin/$bin
done
binaries=(nebula nebula-server nebula-executor nebula-discovery nebula-pve-collector)
units=(
  nebula
  nebula-server
)
FIX
hits=$(find_hardcoded "$fixture")
rm -f "$fixture"
if [[ $(printf '%s\n' "$hits" | grep -c .) -eq 4 ]]; then
  ok "case 3 guard catches all four hardcoded variants"
else
  bad "case 3 guard catches all four hardcoded variants (got: ${hits@Q})"
fi

# --- 4. Functional: the copy block of setup-nebula.sh copies all five -------
# Extract the real copy block from the script (between the begin/end
# markers) and run it against a sandbox checkout: bin/ holds the five
# built binaries, and the block must copy all of them next to deploy/.
sandbox=$(mktemp -d)
trap 'rm -rf "$sandbox" "$libtmp"' EXIT
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
# A comments-only list is not a list: the block must stop instead of
# copying nothing (install.sh would then fail on a list it cannot see).
printf '# only comments\n\n' > "$sandbox/deploy/quickstart/binaries.txt"
if ( eval "$(printf '%s\n' "${copy_block[@]}")" ); then
  bad "setup-nebula.sh copy block fails on a comments-only list"
else
  ok "setup-nebula.sh copy block fails on a comments-only list"
fi
# An invalid line must stop the block too (the parser rejects it).
printf 'bad/name\n' > "$sandbox/deploy/quickstart/binaries.txt"
if ( eval "$(printf '%s\n' "${copy_block[@]}")" ); then
  bad "setup-nebula.sh copy block fails on an invalid line"
else
  ok "setup-nebula.sh copy block fails on an invalid line"
fi
cp "$list_file" "$sandbox/deploy/quickstart/binaries.txt"

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
mapfile -t binaries < <(read_binaries "$sandbox/deploy/quickstart/binaries.txt")
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

# --- 6b. Functional: the list check of uninstall.sh runs before removal -----
# The check must pass on the valid list, fail on a missing, comments-only or
# invalid list, and it must be placed before the first removal in the script:
# a missing list must not leave the system half uninstalled (units stopped,
# binaries still to go).
mapfile -t ucheck_block < <(sed -n '/^# begin: check binary list/,/^# end: check binary list/p' "$uninstall_sh" | grep -v '^# \(begin\|end\): check binary list$')
script_dir="$sandbox/deploy"
if [[ ${#ucheck_block[@]} -gt 0 ]] && ( eval "$(printf '%s\n' "${ucheck_block[@]}")" ); then
  ok "uninstall.sh list check passes on the valid list"
else
  bad "uninstall.sh list check passes on the valid list (block missing or failed)"
fi
mv "$sandbox/deploy/quickstart/binaries.txt" "$sandbox/blist.bak"
if ( eval "$(printf '%s\n' "${ucheck_block[@]}")" ); then
  bad "uninstall.sh list check fails when the list is missing"
else
  ok "uninstall.sh list check fails when the list is missing"
fi
mv "$sandbox/blist.bak" "$sandbox/deploy/quickstart/binaries.txt"
printf '# only comments\n\n' > "$sandbox/deploy/quickstart/binaries.txt"
if ( eval "$(printf '%s\n' "${ucheck_block[@]}")" ); then
  bad "uninstall.sh list check fails on a comments-only list"
else
  ok "uninstall.sh list check fails on a comments-only list"
fi
printf 'bad/name\n' > "$sandbox/deploy/quickstart/binaries.txt"
if ( eval "$(printf '%s\n' "${ucheck_block[@]}")" ); then
  bad "uninstall.sh list check fails on an invalid line"
else
  ok "uninstall.sh list check fails on an invalid line"
fi
cp "$list_file" "$sandbox/deploy/quickstart/binaries.txt"
check_ln=$(grep -n '^# begin: check binary list' "$uninstall_sh" | head -1 | cut -d: -f1)
first_rm_ln=$(grep -nE '^[[:space:]]*(systemctl (stop|disable)|rm -f --|rmdir --)' "$uninstall_sh" | head -1 | cut -d: -f1)
if [[ -n "${check_ln:-}" && -n "${first_rm_ln:-}" && $check_ln -lt $first_rm_ln ]]; then
  ok "uninstall.sh checks the list before the first removal"
else
  bad "uninstall.sh checks the list before the first removal (check at ${check_ln:-?}, first removal at ${first_rm_ln:-?})"
fi

# --- 7. Functional: the layout check of install.sh (both paths) -------------
# from-package: the five binaries must exist in bin_dir; a missing one must
# stop the script. tarball: the five binaries must exist at tarball_root.
mkdir -p "$sandbox/pkgbin" "$sandbox/deploy/systemd" "$sandbox/tarball"
for b in "${expected[@]}"; do
  printf '#!/bin/sh\n' > "$sandbox/pkgbin/$b"
  chmod +x "$sandbox/pkgbin/$b"
  printf '#!/bin/sh\n' > "$sandbox/tarball/$b"
done
mapfile -t binaries < <(read_binaries "$sandbox/deploy/quickstart/binaries.txt")
from_package=1
bin_dir="$sandbox/pkgbin"
systemd_dir="$sandbox/etc/systemd/system"
script_dir="$sandbox/deploy"
mapfile -t check_block < <(sed -n '/^# begin: check layout/,/^# end: check layout/p' "$install_sh" | grep -v '^# \(begin\|end\): check layout$')
if [[ ${#check_block[@]} -gt 0 ]] && ( eval "$(printf '%s\n' "${check_block[@]}")" ); then
  ok "install.sh layout check passes with all five binaries (from-package)"
else
  bad "install.sh layout check passes with all five binaries (from-package)"
fi
mv "$sandbox/pkgbin/nebula-pve-collector" "$sandbox/gone"
if ( eval "$(printf '%s\n' "${check_block[@]}")" ); then
  bad "install.sh layout check fails when a binary is missing (from-package)"
else
  ok "install.sh layout check fails when a binary is missing (from-package)"
fi
mv "$sandbox/gone" "$sandbox/pkgbin/nebula-pve-collector"
from_package=0
tarball_root="$sandbox/tarball"
if ( eval "$(printf '%s\n' "${check_block[@]}")" ); then
  ok "install.sh layout check passes with all five binaries (tarball)"
else
  bad "install.sh layout check passes with all five binaries (tarball)"
fi
# Negative: a tarball missing one binary must fail the layout check. This is
# the case a truncated list (the original four-of-five bug) or a disabled
# check would pass and stay green: the check must see all five, not a subset.
mv "$sandbox/tarball/nebula-pve-collector" "$sandbox/gone-tarball"
if ( eval "$(printf '%s\n' "${check_block[@]}")" ); then
  bad "install.sh layout check fails when a binary is missing (tarball)"
else
  ok "install.sh layout check fails when a binary is missing (tarball)"
fi
mv "$sandbox/gone-tarball" "$sandbox/tarball/nebula-pve-collector"

# --- 8. Functional: the binary install loop of install.sh -------------------
# Runs the real loop with a fake `install` (no root): all five binaries
# must land in bin_dir and the change must be detected.
mkdir -p "$sandbox/fakebin" "$sandbox/usrbin"
cat > "$sandbox/fakebin/install" <<'FAKE'
#!/bin/sh
# fake install(1): skip -m/-o/-g pairs, copy the last two arguments
while [ $# -gt 0 ]; do
  case $1 in
    -m|-o|-g) shift 2 ;;
    *) break ;;
  esac
done
cp -f "$1" "$2"
FAKE
chmod +x "$sandbox/fakebin/install"
from_package=0
bin_dir="$sandbox/usrbin"
tarball_root="$sandbox/tarball"
mapfile -t install_block < <(sed -n '/^# begin: install binaries/,/^# end: install binaries/p' "$install_sh" | grep -v '^# \(begin\|end\): install binaries$')
out=$( (
  PATH="$sandbox/fakebin:$PATH"
  eval "$(printf '%s\n' "${install_block[@]}")"
  missing=()
  for b in "${expected[@]}"; do
    [[ -f "$sandbox/usrbin/$b" ]] || missing+=("$b")
  done
  if [[ ${#missing[@]} -eq 0 && ${bin_changed} -eq 1 ]]; then
    echo ok
  else
    echo "missing: ${missing[*]:-none}; bin_changed=${bin_changed}"
    exit 1
  fi
) 2>&1 )
if [[ "$out" == ok ]]; then
  ok "install.sh install loop installs all five binaries"
else
  bad "install.sh install loop installs all five binaries ($out)"
fi

# --- 9. The .deb ships every file install.sh reads ---------------------------
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

# --- 10. Syntax of the scripts ------------------------------------------------
for s in "$setup_sh" "$install_sh" "$uninstall_sh" "$real_repo/deploy/quickstart/binaries_lib.sh"; do
  if bash -n "$s" 2>/dev/null; then
    ok "bash -n $(basename -- "$s")"
  else
    bad "bash -n $(basename -- "$s")"
  fi
done

# --- 11. read_binaries: the format edge cases --------------------------------
# The parser is the only gate between the list file and root install(1) and
# rm -f, so every malformed line must be handled deterministically: a valid
# name is [A-Za-z0-9][A-Za-z0-9._-]*, anything else is an error, not a guess.
libtmp=$(mktemp -d)
# A last line without a trailing newline must not be dropped (read returns
# non-zero before the loop body runs without the guard).
printf 'nebula\nnebula-server' > "$libtmp/no-trailing-nl.txt"
out=$(read_binaries "$libtmp/no-trailing-nl.txt")
if [[ "$out" == $'nebula\nnebula-server' ]]; then
  ok "read_binaries keeps a last line without a trailing newline"
else
  bad "read_binaries keeps a last line without a trailing newline (got: ${out@Q})"
fi
# CRLF endings: the CR must not survive into the name.
printf 'nebula\r\nnebula-server\r\n' > "$libtmp/crlf.txt"
out=$(read_binaries "$libtmp/crlf.txt")
if [[ "$out" == $'nebula\nnebula-server' ]]; then
  ok "read_binaries strips CR from CRLF lines"
else
  bad "read_binaries strips CR from CRLF lines (got: ${out@Q})"
fi
# Inline comments are not part of the format: the line is invalid and the
# parser must stop, not silently truncate it to the name.
printf 'nebula # inline\n' > "$libtmp/inline.txt"
if out=$(read_binaries "$libtmp/inline.txt" 2>/dev/null); then
  bad "read_binaries rejects an inline comment (got: ${out@Q})"
else
  ok "read_binaries rejects an inline comment"
fi
# Path separators and whitespace are not binary names (they would reach
# root install and rm -f).
printf 'bad/name\n' > "$libtmp/path.txt"
if read_binaries "$libtmp/path.txt" >/dev/null 2>&1; then
  bad "read_binaries rejects a path separator in a name"
else
  ok "read_binaries rejects a path separator in a name"
fi
printf 'nebula \n' > "$libtmp/trail.txt"
if read_binaries "$libtmp/trail.txt" >/dev/null 2>&1; then
  bad "read_binaries rejects trailing whitespace in a name"
else
  ok "read_binaries rejects trailing whitespace in a name"
fi
# Blank, whitespace-only and comment lines are ignored; the result may be
# empty (the callers then fail the zero-entries check).
printf '   \n\n# only comments\n' > "$libtmp/empty.txt"
out=$(read_binaries "$libtmp/empty.txt")
if [[ -z "$out" ]]; then
  ok "read_binaries ignores blank, whitespace-only and comment lines"
else
  bad "read_binaries ignores blank, whitespace-only and comment lines (got: ${out@Q})"
fi
# A valid list still parses, with or without a trailing newline.
printf 'nebula\nnebula-server\nnebula-executor\nnebula-discovery\nnebula-pve-collector' > "$libtmp/valid.txt"
out=$(read_binaries "$libtmp/valid.txt")
if [[ "$out" == "$(printf '%s\n' "${expected[@]}")" ]]; then
  ok "read_binaries parses a valid five-name list"
else
  bad "read_binaries parses a valid five-name list (got: ${out@Q})"
fi

echo
echo "quickstart_test: ${pass} passed, ${fail} failed"
[[ $fail -eq 0 ]]
