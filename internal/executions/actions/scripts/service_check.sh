#!/bin/sh
# service.check 1.0.0 (Nebula built-in, read-only): one bounded HTTP(S) or
# TCP probe to an operator-approved destination and port. No redirects, no
# arbitrary URLs, no response bodies: a fixed status and the latency only.
# Reserved (internal) IP literals need the explicit internal=yes approval.
# Parameters:
# {"destination":"...","port":"...","protocol":"http|https|tcp","internal":"no|yes"}
set -u
pre() { printf '{"format":"service-check-v1","phase":"precheck","reason":"%s"}\n' "$1"; exit 10; }
res() { printf '{"format":"service-check-v1","phase":"done","status":"%s","latency_ms":%s,"http_status":%s}\n' "$1" "$2" "$3"; }

d=$(sed -n 's/.*"destination":"\([A-Za-z0-9][A-Za-z0-9.-]*\)".*/\1/p' "$NEBULA_PARAMS" | head -n 1)
p=$(sed -n 's/.*"port":"\([0-9][0-9]*\)".*/\1/p' "$NEBULA_PARAMS" | head -n 1)
pr=$(sed -n 's/.*"protocol":"\(http\|https\|tcp\)".*/\1/p' "$NEBULA_PARAMS" | head -n 1)
i=$(sed -n 's/.*"internal":"\(no\|yes\)".*/\1/p' "$NEBULA_PARAMS" | head -n 1)
[ -n "$d" ] && [ -n "$p" ] && [ -n "$pr" ] && [ -n "$i" ] || pre "the service check parameters are missing or invalid"
case "$p" in
  *[!0-9]*|'') pre "the port parameter is missing or invalid" ;;
esac
[ "$p" -ge 1 ] && [ "$p" -le 65535 ] || pre "the port is outside 1-65535"

# A destination is a hostname or an IP literal. Reserved IP literals
# (this network, private, loopback, link-local incl. the 169.254.169.254
# metadata address, CGNAT, multicast/reserved, and every IPv6 literal)
# need the explicit approval.
ipv4_octet() {
  case "$1" in
    0|[1-9]|[1-9][0-9]|[1-9][0-9][0-9]) [ "$1" -le 255 ] ;;
    *) return 1 ;;
  esac
}
reserved() {
  case "$1" in
    *:*|*%*) return 0 ;;  # any IPv6 literal
  esac
  case "$1" in
    *[!0-9.]*|*..*|.*|*.) return 1 ;;  # hostname (not a bare IPv4 literal)
  esac
  old_ifs=$IFS
  IFS=.
  set -- $1
  IFS=$old_ifs
  [ "$#" -eq 4 ] || return 1
  for o in "$@"; do ipv4_octet "$o" || return 1; done
  case "$1" in
    0|10|127) return 0 ;;
    169) [ "$2" = 254 ] && return 0 ;;
    100) [ "$2" -ge 64 ] && [ "$2" -le 127 ] && return 0 ;;
    172) [ "$2" -ge 16 ] && [ "$2" -le 31 ] && return 0 ;;
    192) [ "$2" = 168 ] && return 0 ;;
  esac
  [ "$1" -ge 224 ] && return 0
  return 1
}
if [ "$i" = no ] && reserved "$d"; then
  pre "the destination is an internal address and is not explicitly approved"
fi

command -v curl >/dev/null 2>&1 || pre "no curl"

# Fixed timeouts: 3 s to connect, 5 s total. curl is never given -L, so a
# redirect is reported, not followed; the body goes to /dev/null and is
# never stored.
code=0
t=0
if [ "$pr" = tcp ]; then
  url="telnet://$d:$p/"
  w='%{time_connect}'
else
  case "$pr" in
    http) url="http://$d:$p/" ;;
    https) url="https://$d:$p/" ;;
  esac
  w='%{http_code} %{time_total}'
fi
out=$(curl -s -o /dev/null --connect-timeout 3 --max-time 5 -w "$w" "$url" </dev/null 2>/dev/null)
rc=$?
if [ "$pr" = tcp ]; then
  t=${out:-0}
else
  code=${out%% *}
  t=${out#* }
  [ "$t" = "$out" ] && t=0
fi
case "$t" in
  ''|*[!0-9.]*) t=0 ;;
esac
ms=$(printf '%s\n' "$t" | awk '{ if ($1 + 0 > 0) printf "%d", $1 * 1000; else printf "0" }')
case "$ms" in
  ''|*[!0-9]*) ms=0 ;;
esac

st=error
hs=0
case "$rc" in
  0)
    if [ "$pr" = tcp ]; then
      st=ok
    else
      case "$code" in
        2*) st=ok; hs=$code ;;
        3*) st=redirect; hs=$code ;;
        4*|5*) st=http-error; hs=$code ;;
        *) st=error ;;
      esac
    fi
    ;;
  6) st=unresolved ;;
  7) st=refused ;;
  28) st=timeout ;;
  35|36|51|58|59|60) st=tls-error ;;
  *) st=error ;;
esac
res "$st" "$ms" "$hs"
