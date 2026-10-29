<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# SSH transport and host identity

The executor speaks SSH through Go `x/crypto/ssh`, never through the `ssh` binary, so every failure maps to one error class and host-key trust is decided in code.

**Endpoints.** A host has an ordered list of endpoints (for example LAN, VPN, management network), each with an optional port; the default is 22. The order is set by the admin and never changes because of temporary failures. The precheck is a TCP connect to the configured port; ICMP is only a hint.

| Failure | Behaviour |
| --- | --- |
| TCP timeout or refused | Try the next endpoint |
| SSH handshake failure before authentication | Try the next endpoint once |
| Host-key mismatch | Hard stop for this host, security event, notification |
| Authentication failure | Hard stop; no other endpoint is tried with the same key, which keeps fail2ban quiet and the problem visible |

**Host keys are pinned per host, not per address.** Every endpoint must present the pinned key. To keep negotiation deterministic, the client prefers `ssh-ed25519`, then ECDSA, then `rsa-sha2-512`, and after pinning it offers only the pinned key type for that host.

**Enrollment.** Connect, complete the handshake, show the fingerprint, and send credentials only after the admin confirms it. Bulk enrollment shows a table of address and fingerprint for confirmation. Two ways avoid blind trust: importing existing `known_hosts` lines, or comparing with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` run on the host console. Re-pinning a changed key is a HIGH action with user verification.

**Privileges on the host.** Recommended: a dedicated `nebula` user with Nebula's key and NOPASSWD sudo, documented as effectively root. Also supported: unprivileged (read-only actions) and direct root. The enrollment helper writes the key with `from="<Nebula addresses>",no-agent-forwarding,no-port-forwarding,no-X11-forwarding` and the docs recommend adding Nebula's addresses to fail2ban `ignoreip` as IPs, not hostnames.

**Timeouts.** Connect 10 s, keepalive every 15 s, session dropped after 4 missed keepalives; action timeouts come from the module manifest.

<a id="v23-08-01"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-08-01 -->
**PVE remote identity.** The built-in HTTPS provider supplements SSH; it does not turn provider guests into enrolled SSH hosts. A remote is one cluster with ordered node API endpoints, or one standalone host with one API endpoint; VPN routing creates no extra remote, and standalone endpoint aliases are deferred. Assign immutable local `remote_id`; nodes use `(remote_id, node)`, guests `(remote_id, vmid)` plus QEMU/LXC kind and local generation. Intra-cluster moves preserve identity but change placement; cross-remote moves require explicit relinking. Keep deletion tombstones and compare available UUID, creation/config metadata and MACs to detect VMID reuse. Never inherit links, criticality or approvals across reuse; ambiguity suspends actions for review. The executor owns endpoints, pins, credential references, criticality and generations. Reject duplicate registration of the same trust identity under another remote ID; names and server copies cannot authenticate or lower risk.

<a id="v23-08-02"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-08-02 -->
**PVE TLS enrollment.** Pin the cluster CA's SHA-256 DER fingerprint as the exclusive root; verify every leaf's chain, validity and configured DNS/IP SAN. Standalone remotes pin the served leaf and still check validity/SAN. Never fall back to system roots or accept-any TLS. Custom/ACME proxy certificates need an explicitly compatible reviewed trust choice. Only the local admin CLI adds remotes: probe without credentials, display each endpoint/leaf/CA fingerprint, import a cluster CA from a trusted local file, compare out of band and require typed `yes` before storing trust or sending either token. Server-supplied CAs and unauthenticated API data cannot establish trust.

<a id="v23-08-03"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-08-03 -->
**PVE transport failures and re-pin.** Admin-approved HTTPS origins normally use port 8006; disable redirects and environment proxies. Discovery never adds dial targets, and credentials never follow API URLs. Only connection failures/timeouts allow ordered read failover; authentication failure stops the request. Changed pin, invalid chain or SAN mismatch persistently blocks the whole remote, stops failover and emits an executor event and notification. Re-pin is an explicit admin operation with old/new fingerprints and HIGH user-verified approval; increment trust generation and revoke affected grants/permits. CA-preserving leaf renewal needs no re-pin. An uncertain mutation is reconciled, never repeated at another endpoint. Same-CA endpoint membership and exact supported certificate profiles remain [open questions](17-frozen-decisions.md).
