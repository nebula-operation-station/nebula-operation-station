#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# service.check: isolated Python stdlib, no proxy/curl configuration or bodies.
command -v python3 >/dev/null 2>&1 || {
    printf '%s\n' '{"format":"service-check-v1","phase":"precheck","reason":"python3 unavailable"}'
    exit 10
}
exec python3 -I - "$NEBULA_PARAMS" <<'PY_SERVICE_CHECK'
import ipaddress
import json
import queue
import re
import socket
import ssl
import sys
import threading
import time

MAX_PARAMS = 1024
MAX_DESTINATION = 253
MAX_DNS_ANSWERS = 16
MAX_STATUS_LINE = 1024
CONNECT_TIMEOUT = 3
TOTAL_TIMEOUT = 5
RESERVED = tuple(ipaddress.ip_network(cidr) for cidr in (
    '0.0.0.0/8', '10.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16',
    '100.64.0.0/10', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/3'))
HOSTNAME = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*', re.I | re.ASCII)
NUMERIC = re.compile(r'(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*', re.I | re.ASCII)


def precheck():
    return {'format': 'service-check-v1', 'phase': 'precheck',
            'reason': 'invalid or unapproved destination parameters'}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def internal(addr):
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.version == 6 or any(addr in network for network in RESERVED)


def read_params():
    with open(sys.argv[1], 'rb') as params_file:
        data = params_file.read(MAX_PARAMS + 1)
    if len(data) > MAX_PARAMS:
        raise ValueError()
    params = json.loads(data.decode('utf-8'), object_pairs_hook=unique_object)
    if not isinstance(params, dict) or set(params) != {'destination', 'port', 'protocol', 'internal'}:
        raise ValueError()
    if not all(isinstance(value, str) for value in params.values()):
        raise ValueError()
    d = params['destination']
    if not 1 <= len(d) <= MAX_DESTINATION or '%' in d:
        raise ValueError()
    if not re.fullmatch(r'[0-9]{1,5}', params['port']):
        raise ValueError()
    p = int(params['port'])
    if not 1 <= p <= 65535 or params['protocol'] not in ('http', 'https', 'tcp') or params['internal'] not in ('no', 'yes'):
        raise ValueError()
    try:
        addr = ipaddress.ip_address(d)
    except ValueError:
        if not HOSTNAME.fullmatch(d) or NUMERIC.fullmatch(d):
            raise ValueError()
    else:
        if params['internal'] != 'yes' and internal(addr):
            raise ValueError()
    return d, p, params['protocol'], params['internal'] == 'yes'


def probe(d, p, protocol, approved):
    # Resolve once, check the entire answer set, and connect to a numeric
    # sockaddr. No subsequent resolver, proxy, redirect, or alternate port.
    answers = socket.getaddrinfo(d, p, socket.AF_UNSPEC, socket.SOCK_STREAM)
    if not answers or len(answers) > MAX_DNS_ANSWERS:
        return precheck()
    for family, socktype, proto, _, address in answers:
        if family not in (socket.AF_INET, socket.AF_INET6) or socktype != socket.SOCK_STREAM or address[1] != p:
            return precheck()
        addr = ipaddress.ip_address(address[0])
        if not approved and internal(addr):
            return precheck()
    family, socktype, proto, _, address = answers[0]
    with socket.socket(family, socktype, proto) as conn:
        conn.settimeout(CONNECT_TIMEOUT)
        conn.connect(address)
        if protocol == 'tcp':
            return ('ok', 0)
        if protocol == 'https':
            # Uses system CAs and verifies the original approved hostname.
            conn = ssl.create_default_context().wrap_socket(conn, server_hostname=d)
        with conn:
            conn.settimeout(TOTAL_TIMEOUT)
            host = '[' + d + ']' if ':' in d else d
            conn.sendall(('HEAD / HTTP/1.1\r\nHost: ' + host + ':' + str(p) +
                          '\r\nConnection: close\r\n\r\n').encode('ascii'))
            # Read the status line only. Never read headers or body, and never
            # expose even the status text (which can contain arbitrary data).
            line = bytearray()
            while len(line) < MAX_STATUS_LINE:
                char = conn.recv(1)
                if not char:
                    break
                line.extend(char)
                if line.endswith(b'\r\n'):
                    break
            match = re.fullmatch(rb'HTTP/1\.[01] ([2-5][0-9]{2})(?: [\x20-\x7e]*)?\r\n', line)
            if not match:
                return ('error', 0)
            code = int(match[1])
            return ('ok' if code < 300 else 'redirect' if code < 400 else 'http-error', code)


def main():
    try:
        params = read_params()
    except (OSError, ValueError, TypeError):
        print(json.dumps(precheck()))
        return 10
    results = queue.Queue(maxsize=1)
    start = time.monotonic()

    def worker():
        try:
            result = probe(*params)
        except socket.gaierror:
            result = ('unresolved', 0)
        except (socket.timeout, TimeoutError):
            result = ('timeout', 0)
        except ssl.SSLError:
            result = ('tls-error', 0)
        except ConnectionRefusedError:
            result = ('refused', 0)
        except Exception:
            # No remote exception text, addresses, headers, or bodies in output.
            result = ('error', 0)
        results.put(result)

    # A daemon worker bounds even an unresponsive system resolver and slow
    # byte-at-a-time replies. Process exit never waits for DNS or a peer.
    threading.Thread(target=worker, daemon=True).start()
    try:
        result = results.get(timeout=TOTAL_TIMEOUT)
    except queue.Empty:
        result = ('timeout', 0)
    if isinstance(result, dict):
        print(json.dumps(result))
        return 10
    status, code = result
    latency = min(TOTAL_TIMEOUT * 1000, max(0, int((time.monotonic() - start) * 1000)))
    print(json.dumps({'format': 'service-check-v1', 'phase': 'done',
                      'status': status, 'latency_ms': latency, 'http_status': code}))
    return 0


sys.exit(main())
PY_SERVICE_CHECK
