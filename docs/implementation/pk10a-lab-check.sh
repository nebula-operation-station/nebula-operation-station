#!/usr/bin/env bash
# PK-10a lab check (docs/implementation/preset-host-key.md, ADR 0008 amendment 1).
#
# Run as root on ONE Proxmox VE node (lab: ProxmoxBAI). Everything the script creates lives
# in its own pool "nos-pk10a" and is removed again on exit (also on error / Ctrl-C):
#   - one throw-away VM without any disk (only a cloud-init drive), never with network
#   - four snippet files on a storage with content "snippets"
#   - test users nos-pk10a-pN@pve with one API token each, roles NOSPK10A-*, their ACLs
# Nothing else on the node is changed: no storage config, no existing VM, no existing user.
#
# Output: /root/pk10a-<host>-<time>.txt (no secrets; token secrets stay in shell variables).
#
# Optional environment:
#   SNIP_STORAGE=<id>   storage with content "snippets" (default: first one found)
#   CI_STORAGE=<id>     storage for the cloud-init drive (default: local-lvm, local-zfs or first "images")
#   START_VM=0          do not start the VM (skips the M1 check)
#   KEEP=1              do not clean up (only for debugging; then run the script with CLEANUP_ONLY=1)
#   CLEANUP_ONLY=1      only remove leftovers of an earlier run
set -u
umask 077

POOL=nos-pk10a
PREFIX=nos-pk10a
ROLEPFX=NOSPK10A
API=https://127.0.0.1:8006/api2/json
NODE=$(hostname)
TS=$(date +%Y%m%d-%H%M%S)
OUT=/root/pk10a-${NODE}-${TS}.txt
STATE=/root/.pk10a-state

die() { echo "ABBRUCH: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "bitte als root ausführen"
for c in pvesh pveum qm pvesm pveversion curl python3; do command -v "$c" >/dev/null || die "$c fehlt"; done

log() { printf '%s\n' "$*" | tee -a "$OUT"; }

# ---------- cleanup ----------
cleanup() {
  [ "${KEEP:-0}" = 1 ] && { echo "KEEP=1: nichts aufgeräumt (später CLEANUP_ONLY=1)"; return; }
  echo "Aufräumen ..."
  if [ -f "$STATE" ]; then
    # shellcheck disable=SC1090
    . "$STATE"
    if [ -n "${S_VMID:-}" ] && qm config "$S_VMID" >/dev/null 2>&1; then
      if qm config "$S_VMID" | grep -q "^name: ${PREFIX}-test$"; then
        qm stop "$S_VMID" --skiplock 1 >/dev/null 2>&1 || true
        qm destroy "$S_VMID" --purge 1 --destroy-unreferenced-disks 1 >/dev/null 2>&1 || qm destroy "$S_VMID" >/dev/null 2>&1 || true
      else
        echo "WARNUNG: VM $S_VMID heißt nicht ${PREFIX}-test – nicht gelöscht"
      fi
    fi
    for f in ${S_FILES:-}; do rm -f -- "$f"; done
  fi
  for u in $(pveum user list --output-format json 2>/dev/null | python3 -c 'import json,sys
for x in json.load(sys.stdin):
    if x["userid"].startswith("nos-pk10a-"): print(x["userid"])' 2>/dev/null); do
    pveum user delete "$u" >/dev/null 2>&1 || true
  done
  for r in $(pveum role list --output-format json 2>/dev/null | python3 -c 'import json,sys
for x in json.load(sys.stdin):
    if x["roleid"].startswith("NOSPK10A-"): print(x["roleid"])' 2>/dev/null); do
    pveum role delete "$r" >/dev/null 2>&1 || true
  done
  pveum pool delete "$POOL" >/dev/null 2>&1 || true
  rm -f "$STATE"
  echo "Aufgeräumt."
}

if [ "${CLEANUP_ONLY:-0}" = 1 ]; then cleanup; exit 0; fi
[ -f "$STATE" ] && die "Reste eines früheren Laufs gefunden: erst CLEANUP_ONLY=1 $0"
if pveum pool list --output-format json 2>/dev/null | grep -q "\"$POOL\""; then
  die "Pool $POOL existiert schon: erst CLEANUP_ONLY=1 $0"
fi
trap cleanup EXIT
trap 'exit 130' INT TERM

: > "$OUT"
log "# PK-10a lab check  node=$NODE  time=$TS"
log "# $(pveversion)"
pveversion -v 2>/dev/null | grep -E '^(proxmox-ve|pve-manager|qemu-server|pve-access-control|libpve-storage-perl|pve-qemu-kvm):' | sed 's/^/#   /' | tee -a "$OUT"

# ---------- storages ----------
first_storage() { pvesm status --content "$1" 2>/dev/null | awk 'NR>1 && $3=="active"{print $1}'; }
SNIP=${SNIP_STORAGE:-$(first_storage snippets | head -1)}
[ -n "$SNIP" ] || die "kein Storage mit Inhalt 'snippets' aktiv. Einmalig z. B.: pvesm set local --content <bisherige Liste>,snippets  (oder SNIP_STORAGE=<id> setzen)"
if [ -z "${CI_STORAGE:-}" ]; then
  IMG=$(first_storage images)
  for s in local-lvm local-zfs; do printf '%s\n' "$IMG" | grep -qx "$s" && CI_STORAGE=$s && break; done
  CI_STORAGE=${CI_STORAGE:-$(printf '%s\n' "$IMG" | head -1)}
fi
CI=$CI_STORAGE
[ -n "$CI" ] || die "kein Storage mit Inhalt 'images' gefunden (CI_STORAGE=<id> setzen)"
log "# snippets storage=$SNIP  cloud-init storage=$CI"

# ---------- privileges (question 3) ----------
DSPRIVS=$(pveum role list --output-format json | python3 -c 'import json,sys
privs=set()
for r in json.load(sys.stdin):
    p=r.get("privs","")
    if isinstance(p,dict): p=",".join(p)
    for x in p.split(","):
        if x.startswith("Datastore."): privs.add(x.strip())
print(" ".join(sorted(privs)))')
log "Q3 Datastore privileges defined by this version: $DSPRIVS"
[ -n "$DSPRIVS" ] || die "keine Datastore.*-Privilegien gefunden"

# ---------- test objects ----------
VMID=$(pvesh get /cluster/nextid)
M=$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')
MK="pk10a${M}"
pveum pool add "$POOL" --comment "NOS PK-10a lab check, temporary" >/dev/null || die "Pool anlegen fehlgeschlagen"
printf 'S_VMID=%s\n' "$VMID" > "$STATE"

FILES=""
for t in user vendor network meta; do
  f=$(pvesm path "$SNIP:snippets/${PREFIX}-$t.yaml") || die "pvesm path für Snippet fehlgeschlagen"
  mkdir -p "$(dirname "$f")"
  case $t in
    user)    printf '#cloud-config\n# %s-user\nhostname: %suser\n' "$MK" "$MK" > "$f" ;;
    vendor)  printf '#cloud-config\n# %s-vendor\nbootcmd:\n  - echo %svendor\n' "$MK" "$MK" > "$f" ;;
    network) printf 'version: 1\n# %s-network\nconfig:\n  - type: nameserver\n    address: [192.0.2.53]\n    search: [%snetwork.invalid]\n' "$MK" "$MK" > "$f" ;;
    meta)    printf 'instance-id: %smeta\n# %s-meta\n' "$MK" "$MK" > "$f" ;;
  esac
  chmod 0644 "$f"
  FILES="$FILES $f"
done
printf 'S_FILES="%s"\n' "$FILES" >> "$STATE"

qm create "$VMID" --name "${PREFIX}-test" --pool "$POOL" --memory 64 --cores 1 --ostype l26 \
  --ide2 "$CI:cloudinit" \
  --cicustom "user=$SNIP:snippets/${PREFIX}-user.yaml,vendor=$SNIP:snippets/${PREFIX}-vendor.yaml,network=$SNIP:snippets/${PREFIX}-network.yaml,meta=$SNIP:snippets/${PREFIX}-meta.yaml" \
  >/dev/null || die "qm create fehlgeschlagen"
CIVOL=$(qm config "$VMID" | sed -n 's/^ide2: \([^,]*\),.*/\1/p')
log "# test VM $VMID (pool $POOL), cloud-init volume $CIVOL, marker prefix $MK"

# ---------- profiles ----------
# name|path:priv,priv;path:priv
PROFILES=()
PROFILES+=("none|")
PROFILES+=("vmaudit-vm|/vms/$VMID:VM.Audit")
PROFILES+=("vmaudit-pool|/pool/$POOL:VM.Audit")
PROFILES+=("sysaudit|/:Sys.Audit")
PROFILES+=("nosread|/:Sys.Audit;/vms:VM.Audit;/storage:Datastore.Audit;/pool:Pool.Audit")
for d in $DSPRIVS; do
  PROFILES+=("ds:$d|/storage/$SNIP:$d;/storage/$CI:$d")
  PROFILES+=("vm+ds:$d|/vms/$VMID:VM.Audit;/storage/$SNIP:$d;/storage/$CI:$d")
done

declare -A TOK
i=0
for p in "${PROFILES[@]}"; do
  i=$((i+1)); name=${p%%|*}; acls=${p#*|}
  u="${PREFIX}-p$i@pve"
  pveum user add "$u" --comment "PK-10a $name (temporary)" >/dev/null || die "user add $u"
  j=0
  IFS=';' read -r -a entries <<< "$acls"
  for e in "${entries[@]}"; do
    [ -n "$e" ] || continue
    j=$((j+1)); path=${e%%:*}; privs=${e#*:}
    r="${ROLEPFX}-p$i-$j"
    pveum role add "$r" --privs "$privs" >/dev/null || die "role add $r ($privs)"
    pveum acl modify "$path" --users "$u" --roles "$r" --propagate 1 >/dev/null || die "acl $path $u"
  done
  sec=$(pveum user token add "$u" t --privsep 0 --output-format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["value"])') || die "token $u"
  TOK[$name]="$u!t=$sec"
done
log "# profiles: $(for p in "${PROFILES[@]}"; do printf '%s  ' "${p%%|*}"; done)"

# ---------- helpers ----------
enc() { python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }
BODY=$(mktemp)
# call <profile> <path-with-query>  -> sets CODE, prints nothing
call() {
  CODE=$(curl -sk -o "$BODY" -w '%{http_code}' --max-time 20 \
    -H "Authorization: PVEAPIToken=${TOK[$1]}" "$API$2" 2>/dev/null) || CODE=ERR
}
hits() { grep -a -o "${MK}[a-z]*" "$BODY" 2>/dev/null | sort -u | tr '\n' ' '; }
row() { log "$(printf '%-28s %-58s %-4s %s' "$1" "$2" "$3" "$4")"; }

drive_marker() {
  local p; p=$(pvesm path "$CIVOL" 2>/dev/null) || { echo "path?"; return; }
  if [ -r "$p" ]; then
    local h; h=$(grep -a -o "${MK}[a-z]*" "$p" 2>/dev/null | sort -u | tr '\n' ' ')
    echo "md5=$(md5sum < "$p" | cut -c1-12) marker=[${h:-none}]"
  else echo "not readable ($p)"; fi
}

# ---------- start VM (drive gets generated) ----------
STARTED=0
log ""
log "## drive before start: $(drive_marker)"
if [ "${START_VM:-1}" = 1 ]; then
  if qm start "$VMID" >/dev/null 2>&1; then STARTED=1; sleep 5; log "## drive after start:  $(drive_marker)"
  else log "## VM start failed (M1 skipped)"; fi
fi

# ---------- per-profile API tests (questions 1, 2, 4) ----------
SNIPVOL="$SNIP:snippets/${PREFIX}-user.yaml"
STEPS=$(pvesh ls "/nodes/$NODE/storage/$SNIP" 2>/dev/null | awk '{print $2}' | tr '\n' ' ')
log ""
log "## storage sub-endpoints (pvesh ls as root): $STEPS"
log ""
log "$(printf '%-28s %-58s %-4s %s' PROFILE REQUEST HTTP 'MARKER/RESULT')"
for p in "${PROFILES[@]}"; do
  n=${p%%|*}
  for t in user network meta vendor; do
    call "$n" "/nodes/$NODE/qemu/$VMID/cloudinit/dump?type=$t"; row "$n" "dump type=$t" "$CODE" "[$(hits)]"
  done
  call "$n" "/nodes/$NODE/qemu/$VMID/config"; row "$n" "qemu config (cicustom visible?)" "$CODE" "$(grep -q cicustom "$BODY" && echo cicustom-visible || echo -)"
  call "$n" "/nodes/$NODE/storage/$SNIP/content"; row "$n" "list $SNIP" "$CODE" "$(grep -q "${PREFIX}-" "$BODY" && echo snippet-listed || echo -)"
  call "$n" "/nodes/$NODE/storage/$CI/content"; row "$n" "list $CI" "$CODE" "$(grep -q "$VMID-cloudinit" "$BODY" && echo cloudinit-listed || echo -)"
  call "$n" "/nodes/$NODE/storage/$SNIP/content/$(enc "$SNIPVOL")"; row "$n" "volume $SNIPVOL" "$CODE" "[$(hits)]"
  call "$n" "/nodes/$NODE/storage/$CI/content/$(enc "$CIVOL")"; row "$n" "volume $CIVOL" "$CODE" "[$(hits)]"
  for s in $STEPS; do
    case $s in content|status|rrd|rrddata) continue ;; esac
    call "$n" "/nodes/$NODE/storage/$SNIP/$s?volume=$(enc "$SNIPVOL")"; row "$n" "storage/$SNIP/$s?volume=snippet" "$CODE" "[$(hits)]"
  done
  call "$n" "/access/acl"; row "$n" "access/acl" "$CODE" "entries=$(python3 -c 'import json,sys
try: print(len(json.load(open(sys.argv[1])).get("data") or []))
except Exception: print("?")' "$BODY") foreign-test-users=$(grep -o "${PREFIX}-p[0-9]*@pve" "$BODY" | sort -u | wc -l)"
  call "$n" "/access/roles"; row "$n" "access/roles" "$CODE" "$(grep -q "${ROLEPFX}-" "$BODY" && echo test-roles-visible || echo -)"
  call "$n" "/pools/$POOL"; row "$n" "pools/$POOL" "$CODE" "$(grep -q "\"vmid\":$VMID" "$BODY" && echo vm-member-visible || echo -)"
done

# ---------- M1 (question 5) ----------
log ""
if [ "$STARTED" = 1 ]; then
  log "## M1: clear cicustom on the running guest"
  qm set "$VMID" --delete cicustom >/dev/null 2>&1; rc=$?
  log "qm set --delete cicustom rc=$rc"
  log "config cicustom (current): $(qm config "$VMID" --current 1 2>/dev/null | grep -c '^cicustom') ; pending: $(qm pending "$VMID" 2>/dev/null | grep -i cicustom | tr -s ' ' | tr '\n' ' ')"
  log "drive right after delete: $(drive_marker)"
  sleep 20
  log "drive 20 s after delete:  $(drive_marker)"
  pvesh get "/nodes/$NODE/qemu/$VMID/cloudinit/dump" --type user > "$BODY" 2>&1; log "dump user (root) after delete: [$(hits)]"
  if qm cloudinit update "$VMID" >/dev/null 2>&1; then log "drive after 'qm cloudinit update': $(drive_marker)"
  else log "'qm cloudinit update' not available or failed"; fi
  qm stop "$VMID" >/dev/null 2>&1
else
  log "## M1 skipped (VM not started)"
fi
rm -f "$BODY"

log ""
log "# done. Bitte diese Datei an Claude geben: $OUT"
