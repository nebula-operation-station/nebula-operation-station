# Threat model

Nebula Operation Station holds the keys that give root on a whole homelab. This document states what it protects against and what it does not, so that nobody relies on a protection that does not exist. This is the version for Release 0.9 (beta); every "Protected" line has its tests in `docs/implementation/security-tests.md`.

## Assets

- SSH private keys and vault secrets (held only by `nebula-executor`).
- Authority to execute on managed hosts (permits, schedule grants, trust in artifacts and module signers).
- Integrity of what runs: artifact, targets, parameters, credentials, secret mappings.
- The record of what happened: the executor's signed events and the server's audit lines.
- Inventory, network and audit data (they reveal the lab's layout), and the backups that hold them.
- Vulnerability findings and attack paths (ADR 0011): the package inventory and the paths to the crown jewels are a map of the lab's attack surface; a hidden finding is a false sense of safety.

## Trust boundaries

| Component | Runs as | Trusted with |
| --- | --- | --- |
| `nebula-executor` | `nebula-executor` | Keys, vault, permits, risk floor, host-key pins, event key. No network listener. |
| `nebula-server` | `nebula-server` | Web UI, inventory, IPAM, planning, audit view. Proposes only; never authorizes. |
| `nebula-discovery` | `nebula-discovery` | Raw sockets (`CAP_NET_RAW`) for Nmap. No credentials, no database, no listener. |
| `nebula` CLI | an admin user (backup and restore: root via sudo) | Unlock, hardened approval, trust, signers, backup and restore. |
| Managed hosts, scanned networks, module authors | — | Nothing: everything they produce is untrusted input. |
| Hermes agent (VM `hermes`, outside NOS) and the CVE feeds it fetches | its own VM; talks to `nebula-server` only with the `hermes-vuln` API token | Reading the bounded package export (`vuln.inventory.read`) and writing runs and findings into the findings store (`vuln.findings.write`). No SSH keys, vault, permits, proposals, leases or human states. Everything it sends, and every feed value, is untrusted input (ADR 0011). |

### The container deployment

`deploy/container/compose.yaml` runs the same three services as three
containers from one image. The boundaries above hold with these
differences:

| Container | Runs as | Differences from a host install |
| --- | --- | --- |
| `executor` | UID 10001 | Host network namespace (`network_mode: host`); still no TCP listener, only the Unix socket on a shared volume. Its data volume is mounted by no other container. |
| `server` | UID 10002 | Listens on `0.0.0.0:8080` inside its own network namespace; only the compose port mapping (`127.0.0.1:8080`) keeps it off the network. Changing that mapping publishes the UI. |
| `discovery` | UID 10003 | Host network namespace and `NET_RAW` (the only capability left); mounts only the two spool volumes. |
| admin CLI | `nebula-admin`, UID 10100, in the executor container | A container-local admin identity, distinct from the host's admin users; whoever can `docker compose exec` into the executor container can act as it. |

- **The image is a new trust.** Whoever builds or can replace
  `ghcr.io/nebula-operation-station/nebula` (or the image named by
  `NEBULA_IMAGE`) controls all three services. Pull it by digest and
  check the digest against the release before you run it; build it
  yourself from a tagged release if you cannot.
- **Docker is root.** Anyone in the `docker` group, or with access to the
  Docker socket, can read the executor's volume, start a shell as any
  container user and take the keys: treat Docker access like root on the
  Nebula machine (see "Not protected").

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
| A compromised server misusing discovery | Jobs are validated again by `nebula-discovery`: fixed Nmap arguments per mode, never free-form options; targets are addresses or prefixes of at most a /16 (IPv4) or /112 (IPv6); each side writes only its own spool directory; results are cleaned on both sides | `internal/discoveryjob`, `cmd/nebula-discovery`, `deploy/` |
| Hostile scan results | Addresses parsed, MACs normalized, hostnames kept only when valid, other text cleaned and cut; nothing reaches the assets without an import, and a conflict is never imported | `internal/discoveryjob`, `internal/discovery` |
| Forged, changed or hidden history | Every executor audit line is a signed, hash-chained event in append-only storage; `nebula events verify` checks the whole chain on the Nebula machine, the History page the newest part | `internal/events`, `internal/executordb` |
| Hostile Hermes assessment text or feed values (prompt injection through feed descriptions, script, links, control or bidi characters, oversized text) | Assessment ≤ 4 KiB, strict UTF-8, unknown fields and URLs rejected, IDs and versions by pattern; rendered as escaped text under the strict CSP, labelled "Hermes assessment (LLM, unverified)"; links only from NOS templates; priority, tier and path numbers computed by NOS, never from text; the text is never sent in notifications, logged or put in CSV by default; CSV cells prefixed against formula injection. Prompt injection can change only that text | `internal/vulnfinding`, `internal/web/api/vuln*.go`, `internal/web/ui/vuln.go` |
| Findings turned into actions | Findings, scores, paths and assessment are advisory: no code path from the findings store to proposals, permits, leases or schedules; "fix with" links only prefill the existing approval flows | `internal/vulnstore`, `internal/web/ui/vuln.go` |
| `hermes-vuln` token scope escape (stolen token or compromised Hermes reaching beyond its two scopes) | The vuln scopes live on exactly one token that holds no other scope (configuration refused otherwise); so it holds none of the read-only scopes and no read-only token reaches the vuln API; optional source-address allowlist; `vuln.findings.write` writes only runs and findings: it cannot set `accepted_risk` or `false_positive`, confirm a held closure or reset a high-water mark (maintainer only, fresh WebAuthn assertion); `finding_key` computed by NOS; size and rate limits; export without addresses, host names, host labels, secrets, logs or topology | `internal/serverconfig`, `internal/web/api/vuln*.go`, `internal/vulnstore` |
| Bulk closure of findings by a manipulated Hermes (omission or `not_affected` records) | Closures only through the fixed closure paths: complete runs ordered by `run_seq` and serialized per subject, every basis source named, accepted, dated and fresh, no rejected record of the key; closures NOS's own inventory contradicts are always held; episode KEV and critical findings held even after Hermes first drops the KEV flag or lowers the scores (episode high-water marks); run guard and cumulative 24 h window guard (> 50 % and ≥ 20 overall, ≥ 10 per subject) hold all unevidenced closures; every other unevidenced closure stays visible as "closed by Hermes, not confirmed by NOS"; audited | `internal/vulnstore` |
| Poisoned, replayed or frozen feed (older signed document or bundle, a source rolled back or relabelled, a future content date) | Signatures mandatory and fail closed on Hermes where a source defines them; on NOS a per-source high-water mark of the newest content date and bundle `sequence` ever accepted, also across runs that omit the source; a regressed or future-dated source is frozen **only for that source** and that run: it closes nothing while findings on it, including KEV, still open; regressed, invalid, unknown, undated and on-probation sources are **raise-only** (never lower a fixed version, KEV flag, score, tier or text); source IDs from a fixed NOS list, so relabelled data is unknown and closes nothing; a source past its maximum snapshot age (72 h daily, 30 days CSAF and bundles) is stale and closes nothing; mark reset only by the maintainer with assertion, reason and audit, followed by probation; NOS re-checks `source:Version` and `installed < fixed` itself | `internal/vulnstore`, `internal/vulnver`, `internal/web/api/vuln*.go` |
| Stale or replayed Hermes run | `run_seq` ordering, monotonic inventory generations, `state_run_seq` per finding, subject watermarks, 6 h run timeout without closures, inventory snapshot older than 24 h rejected, idempotent batches (a changed body for a used `batch_seq` is `409` and audited) | `internal/vulnstore`, `internal/web/api/vuln*.go` |
| Attack-path topology handed to an attacker through Hermes or the API | Attack paths are admin-only and not served by the read-only API or the vuln agent API; Hermes may not read attack-path steps or topology and writes no path narratives (Q6, decided 2026-11-09); the export carries no addresses, host names, host labels or topology | `internal/attackpath`, `internal/web/api/vuln_export.go` |
| A backup leaking secrets, or a tampered restore | Backups hold no passphrase, no decrypted key, no plaintext secret and no event key, and are age-encrypted by default; restore is CRITICAL, checks the manifest, every checksum and the schema versions before anything changes, and keeps the old data | `internal/backup`, `cmd/nebula/backup.go`, `internal/executor/backup.go` |

The vulnerability rows (ADR 0011) state the accepted contract. Not all of it is merged yet: the inventory reads `package.list_installed` and `image.packages` (VU-05, VU-06), notifications and the findings export with its CSV prefixing (VU-14), and their security and browser tests (VU-16) are still open in `docs/implementation/vulnerability-management.md`; until VU-16 lands these rows have unit tests in the packages named, not entries in `docs/implementation/security-tests.md`.

## Not protected

- **Root or kernel compromise of the Nebula machine.** Root can read executor memory and files, take the event key and rewrite the event chain. Offsite copies of the events (`nebula events list --json`) and backups make such a rewrite visible afterwards.
- **A malicious admin.** Admins can approve anything.
- **A compromised authenticator** or a stolen, unlocked device with a registered passkey.
- **Registration through a fully compromised server.** The admin types the one-time code into a page the server controls; the server can use it (and the confirming gesture of that ceremony) for its own key. The admin's own registration then fails, and `nebula webauthn list` shows the extra key.
- **UI deception by a fully compromised server.** WebAuthn signs a challenge, not the text shown. Defence: `nebula approve` (hardened mode). The same holds for the History page: it verifies the events with the key the executor reports; compare the fingerprint with `nebula events key`.
- **Memory remanence.** Go cannot reliably wipe memory; unlocked keys live in the executor's heap. Core dumps are disabled and the process is non-dumpable; use encrypted or no swap.
- **An admin trusting the wrong script, level or signer.** Trust and signers say who vouches for the bytes, not what they do. The Safety Scanner is advisory; it can raise the risk of a script it recognises, but a script it does not recognise can still be harmful.
- **The server's own audit lines.** They are not signed (a compromised server could write any); the optional hash chain shows accidental or offline edits only.
- **Which networks get scanned, against a compromised server.** The rule that only known networks are scanned is the server's check; `nebula-discovery` enforces only the fixed arguments and the size limits, so a compromised server can have any network scanned (at most a /16 or an IPv6 /112 per target).
- **The networks Nebula scans.** A scan is visible to the scanned hosts and their IDS; discovery results can be spoofed by anything on the network, which is why they are only ever proposals.
- **A compromised Hermes that lies consistently.** NOS cannot check feed content dates or snapshot IDs against the data; they are Hermes assertions. A Hermes that pairs old data with a fresh date, or withholds a finding NOS cannot re-check, is bounded only by the closure rules: contradicted, KEV and critical closures held, the run and 24 h window guards, and the "closed by Hermes, not confirmed by NOS" label. It can also add false findings (noise). It never reaches keys, permits or proposals.
- **Replay of the proxy-dated Debian tracker JSON.** The tracker JSON is dated by its DSA/DLA companion (Q5, decided 2026-11-09). A Hermes that freezes the tracker JSON while the lists move is not detected, and a replay of old tracker JSON beside fresh lists can lower current values (fixed version, KEV flag, scores, tier, text); it never lowers the episode marks, so closure checks and the KEV and critical holds are unaffected.
- **Small labs and the guard floors.** Up to 19 unevidenced closures a day (fewer than 10 per subject) never trip the bulk-closure guards; in a lab with fewer than 20 open findings one run can close every non-KEV, non-critical unconfirmed finding. They stay labelled "closed by Hermes, not confirmed by NOS".
- **The package inventory given to Hermes.** Whoever controls Hermes or its token reads the lab's installed packages (the attack surface), though not addresses, host names, labels or topology. Keep the token source-bound to `hermes` and rotate it on suspicion.
- **A maintainer who accepts the wrong risk or resets a mark for a replayed feed.** Bounded by the 365-day maximum, re-opening on a version change or KEV listing, probation and raise-only updates after a reset, and the audit log.
- **The host-local Trivy database (P1-30).** It is fetched outside Hermes and its rules; it is kept out of the finding store and labelled "host Trivy, partial".
- **Whoever holds a backup identity.** The age identity decrypts every backup made to it: the inventory, the audit data and the still passphrase-encrypted keys. Keep it off the Nebula machine.
