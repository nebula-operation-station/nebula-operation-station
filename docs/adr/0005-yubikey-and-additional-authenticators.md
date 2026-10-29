# ADR 0005: YubiKey and additional authenticators

Status: proposed, 2026-10-27 (needs a maintainer decision; nothing here is implemented yet)

Issue #74. Related: spec 05 (authentication), spec 06 (credentials), m0.md decisions 10, 25, 28, 35–42, issue #72 (security keys in Settings).

## Context

The maintainer wants to use a YubiKey "for everything" and to manage authenticators from Settings after logging in.

What a FIDO2 key (YubiKey or passkey) can already do today:

| Step | Today | Where it is verified |
| --- | --- | --- |
| Web login | WebAuthn assertion with user verification | executor (`FinishLogin`) |
| Privileged session, approvals MEDIUM/HIGH/CRITICAL | WebAuthn assertion per operation or stage | executor (`webauthnverify`) |
| Registering a further key | one-time code from the executor host + assertion by an existing key | executor (decision 25) |
| `nebula unlock` (keyring and vault) | **passphrase only** (Argon2id) | CLI on the Nebula machine |
| `nebula approve` (hardened path) | **admin UID only** (SO_PEERCRED) | executor |
| Recovery | TOTP (CLI setup, decision 39/42) | executor |

So the gaps are the two CLI paths (unlock and approve) and the management UI (handled in #72, which changes no security rule).

Constraints: no CGO and no shelling out from Go production code (AGENTS.md rules 3–5), no new dependency without an explicit decision, the Nebula machine is usually a VM reached over SSH (a key plugged into the admin's laptop is not attached to it), and the web server must stay unable to authorize anything on its own.

## Options

### A. Web unlock with the WebAuthn PRF extension (hmac-secret)

The browser asks the YubiKey for a PRF output over a salt chosen by the executor; that output wraps a copy of the keyring/vault master key. The browser encrypts the PRF output to an ephemeral X25519 key of the executor (HPKE), the server only relays the ciphertext, the executor unwraps and unlocks.

- Pro: one tap unlocks after a reboot without SSH; works with any key that supports `prf` (YubiKey 5 series, most passkeys).
- Con: the page's JavaScript sees the PRF output before encrypting it; a compromised server that serves modified JavaScript can capture it. With that value alone it gains nothing (the wrapped master key lives in `executor.db`, readable only by the executor user), but together with a later copy of `executor.db` it can decrypt the vault offline. This is the "web unlock (opt-in, weaker)" item already listed for after 1.0 in m0.md.
- Needs: proto (new RPCs), keyring/vault (second wrapping of the master key), webauthnverify (PRF support), UI. All protected paths.

### B. YubiKey through the forwarded SSH agent (ed25519-sk / ecdsa-sk) for the CLI

The admin registers an SSH security-key public key (`ssh-keygen -t ed25519-sk`) with the executor. `nebula unlock` and `nebula approve` ask the forwarded agent (`ssh -A`) for a signature over an executor challenge; the executor verifies it with `internal/sshsig` (already used for module signatures) and checks the user-presence flag.

- Pro: uses the existing SSH workflow and the existing signature code; no browser involved; works when the Nebula machine is a VM; the key never leaves the laptop and every signature needs a touch.
- Con: a signature authorizes but cannot derive a decryption key, so for unlock it is a **second factor next to the passphrase**, not a replacement. Agent forwarding exposes the agent to root on the Nebula machine while connected (mitigated: sk keys need a touch per signature).
- Needs: proto (challenge RPCs), executor (sk key registry, checks), `cmd/nebula` (agent client from `golang.org/x/crypto/ssh/agent`, already in the module), docs. Protected paths, no new dependency.

### C. YubiKey attached to the Nebula machine (FIDO2 hmac-secret or PIV via age plugin)

- Con: needs libfido2/pcsc (CGO) or an external plugin binary called from Go, and physical USB passthrough to the VM. Rejected for the default install; possible as a documented manual setup (age-plugin-yubikey for the backup identity) without code changes.

### D. Register keys from Settings without the one-time code

- Con: reverses decision 25 ("the browser alone can never add a key"): a compromised server could turn one hijacked tap into a permanent key of its own. Rejected.

## Proposal

1. **For 1.0:** #72 only — Settings shows keys, adds keys with the unchanged rules (code + confirmation), shows removal and TOTP as CLI commands. Document YubiKey and passkeys as the recommended authenticators (two keys).
2. **After 1.0 (target 1.1):** option **B** — SSH security keys as a second factor for `nebula unlock` and as an approval method for `nebula approve`, opt-in per admin, with a policy switch "require sk signature for unlock/approve".
3. **Later, opt-in:** option **A** — web unlock with PRF, off by default, with the limits above stated in the threat model and the guide.
4. Not planned: C (only as a manual backup recipe), D.

## Decision needed

- Accept the order 1 → 2 → 3, or change it (e.g. A before B)?
- For B: may an sk signature *replace* the passphrase for `nebula approve` only (approve has no secret to unwrap), while unlock always keeps the passphrase?
- Should "require an sk signature" become the default once B exists?
