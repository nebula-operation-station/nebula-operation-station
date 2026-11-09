<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Notifications and integrations

Nebula tells the admin when something needs attention, because nobody keeps an operations UI open all day. Notifications and the API can never trigger an execution. The API is read-only except for the vulnerability agent API below, whose one write scope writes only into the findings store (previously: "Notifications and the API are read-only paths").

**Notification events.**

- Ops State gets worse or recovers (transitions only, never repeats).
- Execution or stage finished with WARNING or FAILED.
- Stage gate waiting for manual continue.
- Host-key mismatch (always sent, cannot be muted).
- Executor locked after a restart, so scheduled checks are paused.
- Optional daily digest of open updates, reboots pending and hosts not READY.

Per-host mute with expiry. Messages carry host, state, reason and execution ID, not log content; including the last log lines is opt-in, because logs are untrusted and may be sensitive.

**Providers in V1.** Generic webhook (JSON, HMAC-signed), ntfy, Telegram. Provider tokens are low-privilege, so they live in the server configuration (owner `nebula-server`, mode 0600), not in the executor vault; the docs say so.

**Read-only API.** `/api/v1`, disabled by default. When enabled: token authentication, scopes `inventory.read`, `operations.read`, `execution_logs.read` (separate, because logs can be sensitive), no anonymous access. This is how Home Assistant, a status page or a script reads Ops State.

<a id="v24-13-01"></a>
<!-- Spec revision (ADR 0011, VU-02): v24-13-01 -->
**Vulnerability agent API (ADR 0011 D3, D5).** Under `/api/v1/vuln/`, separate from the read-only API, two scopes exist for one dedicated agent token (default name `hermes-vuln`, used by the Hermes agent on VM `hermes`):

| Scope | Endpoints | Writes |
| --- | --- | --- |
| `vuln.inventory.read` | `GET /api/v1/vuln/inventory` (`vuln-inventory-v1` export, cursor-paginated, bound to one snapshot ID and generation) | Nothing |
| `vuln.findings.write` | `POST /api/v1/vuln/runs` (run start), `POST /api/v1/vuln/runs/{id}/findings` (batches), `POST /api/v1/vuln/runs/{id}/complete` | Only the findings store: runs, batches and findings with state `open` or a closure through the closure paths of [12-inventory.md](12-inventory.md#v24-12-02) |

- **Exclusive token.** Both scopes live only on that one token, and that token carries no other scope: it can never hold `inventory.read`, `operations.read` or `execution_logs.read`, and no other token can hold a vuln scope. A configuration that breaks this is refused at start. The token is server-side like the other API tokens: it is not an executor credential and confers no SSH, vault, permit, proposal or host access. An optional source-address allowlist (at most 16 addresses or prefixes, allowed only on this token) binds it to the address of `hermes`.
- **`vuln.findings.write` is the first write scope of `/api/v1`** (previously: no scope changed state). It writes nothing outside the findings store: no inventory, host labels, criticality, crown jewels, read leases, proposals, permits, schedules or notification settings. It can never set `accepted_risk` or `false_positive`, confirm or discard a held closure, or reset a feed high-water mark; those are maintainer actions in the UI (Q4). A finding never authorizes, proposes, schedules or approves anything.
- **Export content.** Opaque subject IDs, OS release, running kernel and per subject the component list (source package, `source:Version`, binaries with versions; image packages with source names and versions). No IP addresses, host names, host labels (Q6, decided 2026-11-09: most restrictive, the maintainer may revisit; previously: labels only if the maintainer allowed it), secrets, environment variables, logs, topology or attack-path steps. The export reuses stored observations and never triggers a read.
- **Export limits.** 20,000 packages per host, 5,000 per image, 1,000 subjects and 4 MiB per page, 60 requests per hour per token. A subject that does not fit continues on the next page as parts (`part`, `last_part`); a run that names a subject without all its parts is rejected at `complete`.
- **Write limits.** Run start body 64 KiB, batch 1 MiB and 1,000 findings, 200,000 findings and 10,000 covered subjects per run, 4 KiB assessment, 16 aliases, 60 write requests per minute and two running runs per token; a run not completed within 6 h is aborted (no closures), and a run whose inventory snapshot is more than 24 h older than the current generation is rejected. Unknown JSON fields, invalid UTF-8, URLs and a client-supplied `finding_key` are rejected; batches are idempotent by `(run_id, batch_seq)` (same body hash: no-op; different hash: `409`, audited).
- **Run start and feed sources.** The start names the inventory snapshot, matcher version and per feed source its ID, snapshot ID, integrity mode, content date with kind (`data`, `proxy:<companion>`, `none`) and bundle `sequence` where present. Source IDs come from a fixed NOS-side list; regressed, future-dated and unknown sources are reported in the start response and run report, never the whole start rejected (rules in [12-inventory.md](12-inventory.md#v24-12-03)).
- **Audit.** Every run, batch rejection, held closure and human state change is audited with token ID, counts and hashes; assessment text is never logged.

<a id="v24-13-02"></a>
<!-- Spec revision (ADR 0011, VU-02): v24-13-02 -->
**Vulnerability notification events (ADR 0011 D9).** Sent through the existing webhook, ntfy and Telegram senders:

- `vuln.kev_new`: an open finding is KEV-listed (new with KEV, or an open finding that becomes KEV-listed).
- `vuln.critical_new`: an open finding enters the critical tier (new, or escalated by a score, KEV or exposure change).
- `vuln.hermes_stale`: no complete Hermes run for more than 48 h (Q5); one message.
- `vuln.feed_stale`: a feed source passed its maximum snapshot age; one message per source and stale episode.
- `vuln.feed_regressed`: a run named a listed source below its high-water mark or dated in the future; one message per source and regression episode (until a run accepts the source again); unknown source IDs raise none.
- `vuln.feed_mark_reset`: the maintainer lowered a source's high-water mark; every reset.

Dedupe per `(finding_key, event type)`; a re-opened finding starts a new episode and may notify again, tier flapping inside one episode does not. At most 10 vulnerability messages per hour, the rest in one hourly digest with counts. Messages carry structured fields only (vulnerability ID, subject label, tier, KEV), never the Hermes assessment text.

**Later (1.1).** An OpenMetrics endpoint behind the same scopes, so Prometheus or Telegraf can scrape Ops State and update counts into an existing monitoring stack.
