<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Authentication, sessions and approval

WebAuthn is the primary login and the only way to approve privileged work in the browser. TOTP exists for account recovery only.

**Login.** WebAuthn with several credentials per admin (security key, platform passkey). The RP ID is the fixed hostname under which Nebula is served, with TLS the browser trusts; an IP address cannot be an RP ID. After a TOTP recovery the admin must register a new WebAuthn credential before any privileged action.

**Sessions.**

- Web session for reading (dashboard, inventory, history): long-lived, revocable.
- Privileged session, held by the executor: 60 minutes by default, opened with a user-verified assertion, ended by “Lock executor” in the UI or `nebula lock`.

**Approval flow.**

1. The server sends the canonical execution request to the executor. Canonical encoding is RFC 8785 (JSON Canonicalization Scheme), so both sides hash the same bytes.
2. The executor computes `execution_digest` itself, stores a pending permit and returns a challenge = SHA-256(`execution_digest` ‖ 32-byte nonce ‖ expiry).
3. The browser signs that challenge; the assertion travels through the server to the executor.
4. The executor checks: credential known in `executor.db`, rpIdHash, origin on the allowlist, user-verified flag where required, signCount increased (if the authenticator counts), challenge matches the pending permit, not expired, not used before.
5. The executor issues a single-use permit.

| Effective risk | Required approval |
| --- | --- |
| LOW | Active privileged session; the permit is issued automatically and logged |
| MEDIUM | Per-execution assertion (user presence) |
| HIGH | Per-execution assertion with user verification |
| CRITICAL | Per-execution assertion with user verification plus typing the number of targets; in hardened mode only `nebula approve` |

**Limit, stated in the docs.** An authenticator signs a challenge, not the human-readable request. A fully compromised server can show one request and propose another. `nebula approve <id>` shows action, artifact hash, targets, parameter summary and risk from the executor itself and is the defence; hardened mode makes it mandatory for HIGH and CRITICAL.

**Default approval mode.** V1 defaults to **Standard mode**: browser-based approval is permitted according to the risk table above, while the independent CLI approval path remains available. Hardened mode can be enabled to require CLI approval for HIGH and CRITICAL operations.
