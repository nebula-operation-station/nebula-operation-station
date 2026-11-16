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

- **Exclusive token.** Both scopes live only on that one token, and that token carries no other scope: it can never hold `inventory.read`, `operations.read` or `execution_logs.read`, and no other token can hold a vuln scope (ADR 0011 D3, D5). The token is server-side like the other API tokens: it is not an executor credential and confers no SSH, vault, permit, proposal or host access. An optional source-address allowlist binds it to the address of `hermes` (D3). *Implementation choices* (not ADR 0011 decisions; `internal/serverconfig` token validation): a configuration that breaks the exclusive-token rule is refused when the configuration is loaded at start, and the allowlist holds at most 16 addresses or prefixes (`serverconfig.MaxSourceAddresses`) and is allowed only on this token.
- **`vuln.findings.write` is the first write scope of `/api/v1`** (previously: no scope changed state). It writes nothing outside the findings store: no inventory, host labels, criticality, crown jewels, read leases, proposals, permits, schedules or notification settings. It can never set `accepted_risk` or `false_positive`, confirm or discard a held closure, or reset a feed high-water mark; those are maintainer actions in the UI (Q4). A finding never authorizes, proposes, schedules or approves anything.
- **Export content.** Opaque subject IDs, OS release, running kernel and per subject the component list (source package, `source:Version`, binaries with versions; image packages with source names and versions). No IP addresses, host names, host labels (Q6, decided 2026-11-09: most restrictive, the maintainer may revisit; previously: labels only if the maintainer allowed it), secrets, environment variables, logs, topology or attack-path steps. The export reuses stored observations and never triggers a read.
- **Export limits.** 20,000 packages per host, 5,000 per image, 1,000 subjects and 4 MiB per page, 60 requests per hour per token. A subject that does not fit continues on the next page as parts (`part`, `last_part`); a run that names a subject without all its parts is rejected at `complete`.
- **Write limits (ADR 0011 D5).** Batch 1 MiB and 1,000 findings, 200,000 findings per run, 4 KiB assessment, 16 aliases, 60 requests per minute and two concurrent runs per token; a run not completed within 6 h is aborted (no closures), and a run whose inventory snapshot is more than 24 h older than the current generation is rejected. Unknown JSON fields, invalid UTF-8, URLs and a client-supplied `finding_key` are rejected; batches are idempotent by `(run_id, batch_seq)` (same body hash: no-op; different hash: `409`, audited).
- **Write limits that are implementation choices** (not ADR 0011 numbers; each is the merged constant named): run-start body 64 KiB (`maxStartBytes`, `internal/web/api/vuln.go`); at most 10,000 covered subjects per run (`vulnstore.MaxCoveredPerRun`), which also caps the subjects of one export snapshot (`api.MaxExportSubjects`); the further per-record bounds in [09-untrusted-host-data.md](09-untrusted-host-data.md#v24-09-02).
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

Dedupe per `(finding_key, event type)`; a re-opened finding starts a new episode and may notify again, tier flapping inside one episode does not. At most 10 vulnerability messages per hour, the rest in one hourly digest with counts. Messages carry structured fields only (vulnerability ID, subject, tier, KEV), never the Hermes assessment text. The subject is the subject kind and its opaque subject ID shortened to 40 characters (an image subject also carries its full platform digest), never a host label or host name. ADR 0011 D9 names a "subject label"; the kind-and-ID form and the 40 characters are an *implementation choice* of `internal/vulnnotify` (`maxSubjectID`).

<a id="v26-13-01"></a>
<!-- Spec revision (ADR 0015, IG-01): v26-13-01 -->
**Integrity notification events (ADR 0015 D9).** Sent through the existing webhook, ntfy and Telegram senders (previously: no integrity events):

- `integrity.nos_mismatch`: an I1 finding on the NOS machine (code, unit, built-in module, root key, web asset or configuration differs from its reference).
- `integrity.host_change`: an I2 finding on a managed host.
- `integrity.scan_incomplete`: an I1 check or an I2 run that could not complete (partial or stale scan).
- `integrity.baseline_tamper`: the server's I2 baseline list does not match the executor-stored digest.
- `integrity.reference_conflict`: the executor rejected a package reference that differs from the one admitted for the same `(package, version, arch)` ([10-modules.md](10-modules.md#v26-10-03)).

Messages carry **structured fields only**: host label, class, severity, count and a NOS link. **No host-supplied path or content is put into a notification**, because chat clients render Markdown and links; the path is shown only in the NOS UI under the rules of [09-untrusted-host-data.md](09-untrusted-host-data.md#v26-09-01). Dedupe per `(subject, class, path)`; at most 10 integrity messages per hour, then an hourly digest. A notification never triggers an execution, a restore or any other mutation.

<a id="v27-13-01"></a>
<!-- Spec revision (ADR 0014, AS-02): v27-13-01 -->
**Help assistant settings event (ADR 0014 D5, D6 T3).** Sent through the existing webhook, ntfy and Telegram senders (previously: no assistant events):

- `assistant.settings_changed`: an admin changed an assistant setting: the LLM base URL, the model name, the credential reference, `allow_plain_http`, `assistant.enabled`, the NOS source addresses (Q6) or the lab networks ([01-product.md](01-product.md#v27-01-01), [02-architecture.md](02-architecture.md#v27-02-01)). One message per change: a changed URL is how an attacker with an admin session would redirect questions and inventory facts to their own endpoint (T3), and a changed source address is how they would make the assistant offer a copyable `--from <attacker-address>` (T1, T4), and a widened lab network is how they would let the dialer reach an endpoint in `100.64.0.0/10` outside the former lab set, never a public one ([02-architecture.md](02-architecture.md#v27-02-01); previously: "an endpoint outside the former lab set", which overstated the widening) (T3, T10) (previously: a change of the NOS source addresses raised no event, and the lab networks had no owner).

The message carries structured fields only: the admin, the time, which settings changed, the old and new URL in full (scheme, host, port and path; the URL can hold no user info, query or fragment), the old and new model name, the old and new credential reference name (a name only, never the credential), the old and new value of `allow_plain_http`, the old and new NOS source addresses, the old and new lab networks, the replaced and the new settings version, and the old and new enabled state (previously: only the old and new URL **host**, so a change of scheme, port or path on the same host was not visible). It never carries the credential, a question, an answer or any inventory fact. The same fields go into the audit entry, which is written for every change. The event is informational: it triggers nothing, and the assistant has no API scope (it is reachable only from the web UI panel).

**Findings export (ADR 0011 D9).** Findings can be exported as CSV or JSON with structured fields only; admin only, and every export is audited before any data is written. CSV cells are prefixed against formula injection ([09-untrusted-host-data.md](09-untrusted-host-data.md#v24-09-02)). D9 excludes the assessment text from CSV by default; the merged export (`internal/vulnnotify`) carries no assessment text, admin reasons, host labels or addresses in either format (implementation choice).

**Later (1.1).** An OpenMetrics endpoint behind the same scopes, so Prometheus or Telegraf can scrape Ops State and update counts into an existing monitoring stack.
