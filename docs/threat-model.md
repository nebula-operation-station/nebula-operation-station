# Threat model (draft)

Nebula Operation Station holds the keys that give root on a whole homelab. This document states what it protects against and what it does not, so that nobody relies on a protection that does not exist. It is a living draft; the final version ships with release 0.9.

## Assets

- SSH private keys and vault secrets (held only by `nebula-executor`).
- Authority to execute on managed hosts (permits).
- Integrity of what runs: artifact, targets, parameters, credentials.
- Inventory and audit data (they reveal the lab's layout).

## Protected

| Threat | Defence | Where |
| --- | --- | --- |
| Compromised web process (`nebula-server`) | Separate OS user; cannot read executor files; can only propose; every permit bound to the executor-computed digest | `internal/fsguard`, `internal/peercred`, `internal/permit` |
| Script, host list or parameters swapped after approval | Executor hashes artifact and parameters at run time; host and host-key fingerprint must be in the permit; each host once | `internal/permit` |
| Replayed WebAuthn assertion | Challenge = SHA-256(digest, nonce, expiry), single-use; sign counter checked | `internal/permit`, `internal/webauthnverify` |
| Risk mislabelling by a compromised server (a dangerous action proposed as LOW) | Executor derives the minimum risk from its own data (artifacts trusted by an admin on the executor host, host criticality bound to the pinned key); untrusted artifacts and unrecorded hosts count as HIGH; re-checked per host run | `internal/riskpolicy`, `internal/permit` |
| Unauthenticated or replayed WebAuthn registration | Every registration needs a one-time code from the executor host, further ones also a user-verified assertion of a registered credential; executor verifies the attestation (origin, RP ID, UV, challenge, key), registrations are single-use | `internal/webauthnreg` |
| Another local user talking to the executor | `SO_PEERCRED` UID check per method; deny by default | `internal/peercred`, `internal/executor/roles.go` |
| Malicious managed host | Host output is untrusted: schemas, size limits, text-only rendering | Milestones 4 and 10 |
| Silent host-key change, man in the middle | Pinned per host on the executor host after fingerprint confirmation; every endpoint must present the pin (only its key type is offered); a mismatch stops before authentication, blocks the host until re-pinned and is logged (notification: later milestone) | `internal/sshtransport`, `internal/executor/hostkeys.go` |
| Key spraying across endpoints, fail2ban lockout | One key per host (IdentitiesOnly); an authentication failure stops, no other endpoint is tried | `internal/sshtransport` |

## Not protected

- **Root or kernel compromise of the Nebula machine.** Root can read executor memory and files.
- **A malicious admin.** Admins can approve anything.
- **A compromised authenticator** or a stolen, unlocked device with a registered passkey.
- **Registration through a fully compromised server.** The admin types the one-time code into a page the server controls; the server can use it (and the confirming gesture of that ceremony) for its own key. The admin's own registration then fails, and `nebula webauthn list` shows the extra key.
- **UI deception by a fully compromised server.** WebAuthn signs a challenge, not the text shown. Defence: `nebula approve` (hardened mode).
- **Memory remanence.** Go cannot reliably wipe memory; unlocked keys live in the executor's heap. Core dumps are disabled and the process is non-dumpable; use encrypted or no swap.
- **An admin trusting the wrong script or level.** `nebula artifact trust` shows the hash and the declared risk and warns that LOW scripts run with server-chosen parameters; what the script does is the admin's judgement until the Safety Scanner and signed manifests arrive (Milestone 7).
