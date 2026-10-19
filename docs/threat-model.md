# Threat model

Nebula Operation Station holds the keys that give root on a whole homelab. This document states what it protects against and what it does not, so that nobody relies on a protection that does not exist. This is the version for Release 0.9 (beta); every "Protected" line has its tests in `docs/implementation/security-tests.md`.

## Assets

- SSH private keys and vault secrets (held only by `nebula-executor`).
- Authority to execute on managed hosts (permits, schedule grants, trust in artifacts and module signers).
- Integrity of what runs: artifact, targets, parameters, credentials, secret mappings.
- The record of what happened: the executor's signed events and the server's audit lines.
- Inventory, network and audit data (they reveal the lab's layout), and the backups that hold them.

## Trust boundaries

| Component | Runs as | Trusted with |
| --- | --- | --- |
| `nebula-executor` | `nebula-executor` | Keys, vault, permits, risk floor, host-key pins, event key. No network listener. |
| `nebula-server` | `nebula-server` | Web UI, inventory, IPAM, planning, audit view. Proposes only; never authorizes. |
| `nebula-discovery` | `nebula-discovery` | Raw sockets (`CAP_NET_RAW`) for Nmap. No credentials, no database, no listener. |
| `nebula` CLI | an admin user (backup and restore: root via sudo) | Unlock, hardened approval, trust, signers, backup and restore. |
| Managed hosts, scanned networks, module authors | — | Nothing: everything they produce is untrusted input. |

## Protected

| Threat | Defence | Where |
| --- | --- | --- |
| Compromised web process (`nebula-server`) | Separate OS user; cannot read executor files; can only propose; every permit bound to the executor-computed digest; no RPC returns a secret; backups, trust, signers and risk data are admin-only | `internal/fsguard`, `internal/peercred`, `internal/permit`, `internal/executor/roles.go` |
| Script, host list or parameters swapped after approval | Executor hashes artifact and parameters at run time; host and host-key fingerprint must be in the permit; each host once; the stage plan and the secret mapping are part of the approved digest | `internal/permit`, `internal/canonical` |
| Replayed WebAuthn assertion | Challenge = SHA-256(digest, nonce, expiry), single-use; sign counter checked | `internal/permit`, `internal/webauthnverify` |
| Risk mislabelling by a compromised server | Executor derives the minimum risk from its own data: artifacts trusted by an admin or by a trusted module signer, host criticality bound to the pinned key, the Safety Scanner's findings (it only raises; whatever it cannot read counts HIGH), secrets (at least MEDIUM); untrusted artifacts and unrecorded hosts count as HIGH; re-checked per host run | `internal/riskpolicy`, `internal/scanner`, `internal/permit` |
| Unauthenticated or replayed WebAuthn registration | Every registration needs a one-time code from the executor host, further ones also a user-verified assertion of a registered credential; executor verifies the attestation (origin, RP ID, UV, challenge, key), registrations are single-use | `internal/webauthnreg` |
| Another local user talking to the executor | `SO_PEERCRED` UID check per method; deny by default | `internal/peercred`, `internal/executor/roles.go` |
| Malicious managed host | Host output is untrusted: one bounded JSON document (no duplicate top-level members), schemas and size limits per parser, text-only rendering without control or bidi characters; fuzzed | `internal/hostrun`, `internal/executions/*`, `internal/web/ui` |
| Silent host-key change, man in the middle | Pinned per host on the executor host after fingerprint confirmation; every endpoint must present the pin; a mismatch stops before authentication, blocks the host until re-pinned, is logged and notified | `internal/sshtransport`, `internal/executor/hostkeys.go`, `internal/notify` |
| Key spraying across endpoints, fail2ban lockout | One key per host (IdentitiesOnly); an authentication failure stops, no other endpoint is tried | `internal/sshtransport` |
| Secrets leaking on the way to a host | Vault secrets travel only on the SSH channel into a private tmpfs file removed after the run; never in jobs, results, logs or events; known values are also redacted from output | `internal/executor/secrets.go`, `internal/hostrun` |
| A module or update from an untrusted author | SSH signatures (namespace `nebula-module`) checked by the executor over the exact canonical lock; adding a signer is CRITICAL with a typed fingerprint; a module whose signer changes is refused until an admin confirms the change against the signer shown | `internal/sshsig`, `internal/modulelock`, `internal/executor/modules.go` |
| A module UI injecting script | Declarative UI only: text bound to result fields, rendered by core templates; no module HTML, URLs or JavaScript | `internal/modulelock`, `internal/web/ui/hosts.go` |
| A compromised server misusing discovery | Jobs are validated again by `nebula-discovery`: fixed Nmap arguments per mode, never free-form options; targets are addresses or prefixes of at most a /16; each side writes only its own spool directory; results are cleaned on both sides | `internal/discoveryjob`, `cmd/nebula-discovery`, `deploy/` |
| Hostile scan results | Addresses parsed, MACs normalized, hostnames kept only when valid, other text cleaned and cut; nothing reaches the assets without an import, and a conflict is never imported | `internal/discoveryjob`, `internal/discovery` |
| Forged, changed or hidden history | Every executor audit line is a signed, hash-chained event in append-only storage; `nebula events verify` checks the whole chain on the Nebula machine, the History page the newest part | `internal/events`, `internal/executordb` |
| A backup leaking secrets, or a tampered restore | Backups hold no passphrase, no decrypted key, no plaintext secret and no event key, and are age-encrypted by default; restore is CRITICAL, checks the manifest, every checksum and the schema versions before anything changes, and keeps the old data | `internal/backup`, `cmd/nebula/backup.go`, `internal/executor/backup.go` |

## Not protected

- **Root or kernel compromise of the Nebula machine.** Root can read executor memory and files, take the event key and rewrite the event chain. Offsite copies of the events (`nebula events list --json`) and backups make such a rewrite visible afterwards.
- **A malicious admin.** Admins can approve anything.
- **A compromised authenticator** or a stolen, unlocked device with a registered passkey.
- **Registration through a fully compromised server.** The admin types the one-time code into a page the server controls; the server can use it (and the confirming gesture of that ceremony) for its own key. The admin's own registration then fails, and `nebula webauthn list` shows the extra key.
- **UI deception by a fully compromised server.** WebAuthn signs a challenge, not the text shown. Defence: `nebula approve` (hardened mode). The same holds for the History page: it verifies the events with the key the executor reports; compare the fingerprint with `nebula events key`.
- **Memory remanence.** Go cannot reliably wipe memory; unlocked keys live in the executor's heap. Core dumps are disabled and the process is non-dumpable; use encrypted or no swap.
- **An admin trusting the wrong script, level or signer.** Trust and signers say who vouches for the bytes, not what they do. The Safety Scanner is advisory; it can raise the risk of a script it recognises, but a script it does not recognise can still be harmful.
- **The server's own audit lines.** They are not signed (a compromised server could write any); the optional hash chain shows accidental or offline edits only.
- **The networks Nebula scans.** A scan is visible to the scanned hosts and their IDS; discovery results can be spoofed by anything on the network, which is why they are only ever proposals.
- **Whoever holds a backup identity.** The age identity decrypts every backup made to it: the inventory, the audit data and the still passphrase-encrypted keys. Keep it off the Nebula machine.
