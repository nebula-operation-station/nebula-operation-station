<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Authentication, sessions and approval

WebAuthn is the primary login and the only way to approve privileged work in the browser. TOTP exists for account recovery only.

**Login.** WebAuthn with several credentials per admin (security key, platform passkey). The RP ID is the fixed hostname under which Nebula is served, with TLS the browser trusts; an IP address cannot be an RP ID. After a TOTP recovery the admin must register a new WebAuthn credential before any privileged action.

**Sessions.**

<a id="v23-05-01"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-05-01 -->
- Web session for reading (dashboard, inventory, history): long-lived, revocable.
- Privileged session, held by the executor in memory: 60 minutes by default, configurable to 15–240 minutes only in executor-local configuration validated at startup. A user-verified assertion opens it; lock/restart ends it. The server displays executor-reported expiry and remaining time and cannot choose the duration.

**Approval flow.**

1. The server sends the canonical execution request to the executor. Canonical encoding is RFC 8785 (JSON Canonicalization Scheme), so both sides hash the same bytes.
2. The executor computes `execution_digest` itself, stores a pending permit and returns a challenge = SHA-256(`execution_digest` ‖ 32-byte nonce ‖ expiry).
3. The browser signs that challenge; the assertion travels through the server to the executor.
4. The executor checks: credential known in `executor.db`, rpIdHash, origin on the allowlist, user-verified flag where required, signCount increased (if the authenticator counts), challenge matches the pending permit, not expired, not used before.
5. The executor issues a single-use permit.

<a id="v23-05-02"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-05-02 -->
| Effective risk | Required approval |
| --- | --- |
| LOW | Active privileged session for an interactive permit; the permit is issued automatically and logged. An exact approved read lease instead uses the separate grant path below |
| MEDIUM | Per-execution assertion (user presence), or one presence assertion for an exact batch; browser mutation approval also needs an active privileged session |
| HIGH | Per-execution assertion with user verification, or one user-verified assertion for an exact batch; browser mutation approval also needs an active privileged session; hardened mode uses the local CLI |
| CRITICAL | Per-execution assertion with user verification plus typing the number of targets; in hardened mode only `nebula approve`; reject the entire batch if any member is CRITICAL |

**Limit, stated in the docs.** An authenticator signs a challenge, not the human-readable request. A fully compromised server can show one request and propose another. `nebula approve <id>` shows action, artifact hash, targets, parameter summary and risk from the executor itself and is the defence; hardened mode makes it mandatory for HIGH and CRITICAL.

**Default approval mode.** V1 defaults to **Standard mode**: browser-based approval is permitted according to the risk table above, while the independent CLI approval path remains available. Hardened mode can be enabled to require CLI approval for HIGH and CRITICAL operations.

<a id="v23-05-03"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-05-03 -->
**Session extension.** One fresh user-verified assertion binds the session-extension operation and configured duration. Set expiry to approval time plus that duration; never accumulate extensions. An expired session uses the same single assertion to open a new one. Browsing, leased reads and mutation approval never silently extend it. Extension neither renews read grants nor resurrects permits. Read leases do not require a privileged session, and session expiry alone does not pause them. Audit session open/extension, configured duration/expiry, denials and lock/restart termination without secrets.

<a id="v23-05-04"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-05-04 -->
**Read-grant approval.** In Standard mode one fresh user-verified assertion approves the complete versioned grant digest, including frozen targets, exact actions/parameters, duration and budgets. Neither proposal nor approval requires opening a privileged session first. Use a grant-specific domain separator, nonce, five-minute challenge expiry and single-use verification with the normal RP/origin/counter checks. Recovery mode cannot create grants. Hardened mode requires executor-local admin CLI approval of the complete grant. New grants and renewals default to 7 days and last at most 30 days; renewal needs new approval. UI/CLI revocation needs no assertion. Execution, pause/recovery and audit rules are in [07-execution-model.md](07-execution-model.md).

<a id="v23-05-05"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-05-05 -->
**Batch approval.** The executor validates and holds the complete ordered `batch-v1` plan: 1–100 expanded action-target members, at most 1 MiB canonical bytes and 20 stages. The strictest member sets initial approval: LOW-only uses a privileged session, MEDIUM requires presence, any HIGH requires user verification. A batch-domain challenge binds its digest, nonce and five-minute approval window; execution expiry is at most 24 h. Reject CRITICAL members together with the entire proposal, displaying their identities; the admin must explicitly remove them and approve them separately. Never silently omit or automatically chunk members. Browser mutation approval retains the privileged-session prerequisite.

<a id="v23-05-06"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-05-06 -->
**Review and hardened batches.** Before confirmation, show every member, exact parameters, action/version/hash, target, effective risk, dependency, gate and total count; a summary or truncated list is insufficient. Escape all labels as text. Hardened HIGH approval uses `nebula approve <batch digest>`: only the local admin UID retrieves the executor's complete frozen plan and scanner findings and confirms it once, without a browser session. MEDIUM browser approval remains available. Fresh HIGH stage-gate UV (CLI in hardened mode) and LOW/MEDIUM privileged-session gate clicks remain required; initial batch approval does not remove gates. Audit the approver, complete plan digest, member permits/outcomes, gate releases, skips, denials and revocation. Lock/restart revokes pending and approved batch authority; running tasks may still finish.

<a id="v23-05-07"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-05-07 -->
**Approval deception.** Batch binding prevents substitution, replay and expansion at the executor but cannot prove what a compromised server showed the human. An authenticator signs the challenge, not the displayed plan. The independent executor-local CLI view remains the mitigation, mandatory for hardened HIGH/CRITICAL approval. Read leases deliberately allow bounded reads and budget consumption by a compromised server; a LOW label or clean scanner result is not proof that a root script is harmless.
