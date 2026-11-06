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
#
# count_names prints how many of the expected binary names appear as whole
# tokens in the given text. Names are extracted as runs of [A-Za-z0-9.-], so
# quoted names, names at the start or end of an array, and backslash-
# continued word lists all match; keeping the dot inside the token means a
# unit file like nebula-server.service does not match the binary nebula-server.
count_names() {
  local text="$1" name tok found
  local -a toks=()
  mapfile -t toks < <(printf '%s' "$text" | grep -oE '[A-Za-z0-9.-]+' || true)
  local n=0
  for name in "${expected[@]}"; do
    found=0
    for tok in "${toks[@]}"; do
      if [[ "$tok" == "$name" ]]; then found=1; break; fi
    done
    (( found )) && n=$((n + 1))
  done
  printf '%s' "$n"
}
# find_hardcoded prints one line per hardcoded list it finds:
#   - a for-loop (quoted or unquoted, backslash-continued) whose word list
#     names at least one binary,
#   - an array literal (plain name=(, name+=(, or declare -a name=,
#     single- or multi-line) holding two or more names.
# Message lines may name binaries in prose; only loops and arrays count.
find_hardcoded() {
  local s="$1" line rest n
  local -a lines=() block=()
  mapfile -t lines < <(grep -vE '^[[:space:]]*#' "$s")
  local i=0
  while (( i < ${#lines[@]} )); do
    line="${lines[i]}"
    i=$((i + 1))
    # array literal: name=(, name+=(, or declare -a name=(
    if [[ "$line" =~ ^[[:space:]]*(declare[[:space:]]+(-[aA][[:space:]]+)?[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*)[+]?=\( ]]; then
      block=("$line")
      if [[ "$line" != *")"* ]]; then
        while (( i < ${#lines[@]} )); do
          line="${lines[i]}"
          i=$((i + 1))
          block+=("$line")
          [[ "$line" == *")"* ]] && break
        done
      fi
      n=$(count_names "$(printf '%s\n' "${block[@]}")")
      if (( n >= 2 )); then
        printf '%s: %s\n' "$(basename -- "$s")" "${block[0]}"
      fi
      continue
    fi
    # for-loop over literal names (possibly backslash-continued)
    if [[ "$line" =~ ^[[:space:]]*for[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]+in[[:space:]]+(.*)$ ]]; then
      rest="${BASH_REMATCH[1]}"
      while [[ "$rest" == *"\\" ]] && (( i < ${#lines[@]} )); do
        rest="$rest ${lines[i]}"
        i=$((i + 1))
      done
      n=$(count_names "$rest")
      if (( n >= 1 )); then
        printf '%s: %s\n' "$(basename -- "$s")" "$line"
      fi
    fi
  done
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
# loops (including a backslash-continued one), single-line and multi-line
# array literals (plain, fully-quoted, declare -a, and += forms).
fixture=$(mktemp)
cat > "$fixture" <<'FIX'
for bin in nebula nebula-server nebula-executor nebula-discovery nebula-pve-collector; do
  rm -f /usr/bin/$bin
done
for bin in "nebula" "nebula-server" "nebula-executor" "nebula-discovery" "nebula-pve-collector"; do
  rm -f /usr/bin/$bin
done
for bin in \
  nebula \
  nebula-server; do
  rm -f /usr/bin/$bin
done
binaries=(nebula nebula-server nebula-executor nebula-discovery nebula-pve-collector)
binaries=("nebula" "nebula-server" "nebula-executor" "nebula-discovery" "nebula-pve-collector")
units=(
  nebula
  nebula-server
)
declare -a units2=(nebula nebula-server)
units3=()
units3+=(nebula nebula-server)
FIX
hits=$(find_hardcoded "$fixture")
rm -f "$fixture"
if [[ $(printf '%s\n' "$hits" | grep -c .) -eq 8 ]]; then
  ok "case 3 guard catches all eight hardcoded variants"
else
  bad "case 3 guard catches all eight hardcoded variants (got: ${hits@Q})"
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
# The remove block must remove every binary from the array the CHECK block
# produces (not a list the test fills itself): the check block is the real
# code path from the list file to the remove loop, so a truncation inside it
# (binaries=("${binaries[@]:0:4}")) or an omission (the block no longer
# setting binaries) must leave a binary behind here.
mkdir -p "$sandbox/usrbin"
for b in "${expected[@]}"; do
  printf '#!/bin/sh\n' > "$sandbox/usrbin/$b"
done
script_dir="$sandbox/deploy"
bin_dir="$sandbox/usrbin"
# the check block of uninstall.sh, without its begin/end markers
mapfile -t ucheck_block < <(sed -n '/^# begin: check binary list/,/^# end: check binary list/p' "$uninstall_sh" | grep -v '^# \(begin\|end\): check binary list$')
# run the check block in a subshell (binaries unset) and print the array it
# sets: the end-to-end link from the list file to the remove loop
ucheck_yield() { ( unset binaries; eval "$(printf '%s\n' "${ucheck_block[@]}")"; if [[ ${#binaries[@]} -gt 0 ]]; then printf '%s\n' "${binaries[@]}"; fi ); }
mapfile -t binaries < <(ucheck_yield)
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
# The check must yield exactly the five names on the valid list (the
# end-to-end link from the list file to the remove block), fail on a
# missing, comments-only or invalid list, and it must be placed before the
# first removal in the script: a missing list must not leave the system half
# uninstalled (units stopped, binaries still to go).
mapfile -t ucheck_block < <(sed -n '/^# begin: check binary list/,/^# end: check binary list/p' "$uninstall_sh" | grep -v '^# \(begin\|end\): check binary list$')
script_dir="$sandbox/deploy"
ucheck_out=$(ucheck_yield 2>/dev/null)
if [[ "$ucheck_out" == "$(printf '%s\n' "${expected[@]}")" ]]; then
  ok "uninstall.sh list check yields exactly the five binaries"
else
  bad "uninstall.sh list check yields exactly the five binaries (got: ${ucheck_out@Q})"
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

# --- 9. The .deb and the image ship exactly the list ------------------------
# binaries.txt is the single source of truth (its own header says so), so
# every consumer must agree with it exactly; a drift breaks the packaged or
# container install while the tarball install still works:
#   9a  every file install.sh reads under ${script_dir} is in the nfpm
#       contents, with the src paired to the dst (a commented-out entry or a
#       dst with the wrong src must not count as shipped);
#   9b  the nfpm ids (the binaries the .deb puts in bindir) match the list;
#   9c  the Dockerfile COPY list (the binaries the image ships) matches it.
goreleaser="${real_repo}/.goreleaser.yaml"
dockerfile="${real_repo}/deploy/container/Dockerfile"
if [[ -f "$goreleaser" && -f "$dockerfile" ]]; then
  # The nfpms block: from 'nfpms:' to the next top-level key.
  nfpms_block=$(awk '/^nfpms:/{f=1;next} f&&/^[a-z]/{f=0} f' "$goreleaser")
  # 9a: every file install.sh reads is in the nfpm contents (src/dst paired).
  install_dst=$(grep -oE 'dst: [^ ]+/install\.sh$' <<< "$nfpms_block" | head -1 | awk '{print $2}')
  mapfile -t install_reads < <(grep -oE '\$\{script_dir\}/[A-Za-z0-9_./-]+' "$install_sh" | sed 's|.*script_dir}/||' | sort -u)
  contents_block=$(awk '/^[[:space:]]*contents:/{f=1;next} f&&/^[[:space:]]*scripts:/{f=0} f' <<< "$nfpms_block")
  if [[ -n "$install_dst" && ${#install_reads[@]} -gt 0 ]]; then
    base="${install_dst%/*}"
    missing=()
    for rel in "${install_reads[@]}"; do
      rel_n="${rel%/}"
      cur_src=""
      hit=0
      while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        if [[ "$line" =~ -[[:space:]]*src:[[:space:]]*(.*)$ ]]; then
          cur_src="${BASH_REMATCH[1]%%[[:space:]]*}"
        elif [[ "$line" =~ dst:[[:space:]]*(.*)$ ]]; then
          dst="${BASH_REMATCH[1]%%[[:space:]]*}"
          if [[ "$dst" == "${base}/${rel_n}" && "$cur_src" == "deploy/${rel_n}" ]]; then
            hit=1; break
          elif [[ "$dst" == "${base}/${rel_n}/" && "$cur_src" == "deploy/${rel_n}/*" ]]; then
            hit=1; break
          elif [[ "$dst" == */ && "$cur_src" == deploy/* ]]; then
            cdir="${cur_src#deploy/}"; cdir="${cdir%/*}"
            if [[ "$rel_n" == "${cdir}"/* && "$dst" == "${base}/${cdir}/" ]]; then
              hit=1; break
            fi
          fi
        fi
      done <<< "$contents_block"
      [[ $hit -eq 1 ]] || missing+=("$rel")
    done
    if [[ ${#missing[@]} -eq 0 ]]; then
      ok ".deb nfpm contents include every file install.sh reads (src/dst paired)"
    else
      bad ".deb nfpm contents include every file install.sh reads (missing under ${base}: ${missing[*]})"
    fi
  else
    bad ".deb nfpm contents include every file install.sh reads (could not derive the install.sh dst or the read paths)"
  fi
  # 9b: the nfpm ids (binaries the .deb puts in bindir) match the list.
  nfpm_ids_line=$(grep -E '^[[:space:]]*ids:' <<< "$nfpms_block" | head -1)
  nfpm_ids=$(sed -E 's/^[[:space:]]*ids:[[:space:]]*\[//; s/\][[:space:]]*$//' <<< "$nfpm_ids_line" | tr ',' '\n' | tr -d ' \t' | grep -v '^$' | sort)
  list_sorted=$(printf '%s\n' "${expected[@]}" | sort)
  if [[ -n "$nfpm_ids" && "$nfpm_ids" == "$list_sorted" ]]; then
    ok ".deb nfpm ids match binaries.txt exactly"
  else
    bad ".deb nfpm ids match binaries.txt exactly (nfpm: ${nfpm_ids:-<none>}; list: ${expected[*]})"
  fi
  # 9c: the Dockerfile COPY list (binaries the image ships) matches the list.
  copy_line=$(grep -E '^[[:space:]]*COPY[[:space:]]' "$dockerfile" | head -1)
  read -r -a copy_words <<< "$copy_line"
  copy_files=()
  if [[ ${#copy_words[@]} -ge 3 ]]; then
    for ((i = 1; i < ${#copy_words[@]} - 1; i++)); do
      copy_files+=("${copy_words[i]}")
    done
  fi
  copy_sorted=$(printf '%s\n' "${copy_files[@]}" | sort)
  if [[ ${#copy_files[@]} -gt 0 && "$copy_sorted" == "$list_sorted" ]]; then
    ok "Dockerfile COPY list matches binaries.txt exactly"
  else
    bad "Dockerfile COPY list matches binaries.txt exactly (copy: ${copy_files[*]:-<none>}; list: ${expected[*]})"
  fi
else
  bad ".goreleaser.yaml and the Dockerfile exist"
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
