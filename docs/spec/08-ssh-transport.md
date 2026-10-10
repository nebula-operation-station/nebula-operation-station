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
