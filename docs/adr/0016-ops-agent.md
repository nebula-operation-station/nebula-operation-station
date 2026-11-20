# ADR 0016: Ops agent (`nebula-ops-agent`): vulnerability fix suggestions, never executes

Status: **Accepted, 2026-11-17** (previously: proposed, awaiting the
maintainer's answers to the open questions). The maintainer decided on
2026-11-17; see "Maintainer decisions 2026-11-17". Nothing here is
implemented; every path, unit name and package below is to be *verified*
in the ticket that implements it.

History:

- 2026-11-17: first draft (`nebula-agent`, ten model tools including
  `draft_operation` and `notify`, Telegram token in the agent, event
  subscription, "ask ops" in the help panel).
- 2026-11-17 (review): no tool loop, no drafts, no notification sending
  and no Telegram token in the agent, no question trigger; one exclusive
  API token; the server keeps all deterministic notifications. Binary
  renamed `nebula-ops-agent` (previously `nebula-agent`).
- 2026-11-17 (accepted): main purpose is now **fix suggestions for
  vulnerability findings** (previously: digest, event and operation
  explanations). Suggestion card with prefilled forms and a mandatory
  security-key assertion (previously: no prefilled form). Host names and
  vulnerability IDs in the prompt when the lab-only dialer is enforced
  (previously: counts only). Admin questions in the "Ops" tab
  (previously: no questions). The agent feed of notification events and
  the note kinds `digest`, `event` and `operation` are dropped.

## Context

The maintainer wants a slim operations assistant made for NOS instead of a
general-purpose agent. Its first job: work through the vulnerability
findings of ADR 0011 and tell the admin, per host, what is affected and
how to fix it with the actions NOS already has. It never executes.

What exists on `main` (checked 2026-11-17):

- Findings, tiers and scores (`vu-prio-v1`) are computed by NOS (ADR 0011
  D7; `internal/vulnstore`, `internal/vulnprio`). "Fix with" links open an
  existing form, prefilled, and never submit (ADR 0011 D8;
  `internal/web/ui/vuln_fix.go`, `GET /operations/new?action=&host=`).
- Notifications (spec 13): webhook, ntfy and Telegram senders in
  `internal/notify`, plain text, send-only; hourly limits and digests for
  vulnerability and integrity events. Spec 13 names an optional daily
  digest; it is not built. No lease-expiry event and no stored
  notification list exist.
- `/api/v1` (`internal/web/api`): bearer tokens from `server.json`, every
  access audited. The vulnerability agent has one exclusive token
  (`vulnTokenProblems` in `internal/serverconfig`).
- The signed event chain belongs to the executor and is readable only over
  the executor socket. The server has no event stream.
- `nebula-vuln-agent` (ADR 0011 Amendment 1): own UID, hardened unit,
  OpenAI-compatible LLM client and lab-only dialer in
  `internal/vulnagent/`. A shared `internal/llmclient` is planned (help
  assistant plan, AS-07) but not on `main`.
- The help assistant (ADR 0014) is advisory, has no tools, reads no
  findings, and never prefills a form.
- Approval (spec 05, ADR 0007): the executor derives a minimum risk class
  and rejects a lower one, but it accepts a **higher** class from the
  server and then requires the stricter approval
  (`internal/permit/permit.go`: "The server's risk_class may raise the
  approval strength, never lower it"). The same holds for batch members
  (`internal/permit/batch/batch.go`, `MaxRisk`).

Spec 13 states that notifications and the API can never trigger an
execution; spec 01 excludes an LLM that decides, executes or authorises
anything. This ADR keeps both.

## Guard rails

These come from the review of the first draft and bind every decision
below and every ticket.

| # | Guard rail |
| --- | --- |
| G1 | **No execution through the API.** No scope of `/api/v1` creates a proposal, plan, permit, lease, schedule, approval or batch. The agent writes notes only |
| G2 | **No event stream over the executor socket.** The agent is not in `nebula-rpc` and never talks to the executor. It polls a server-built work list |
| G3 | **The server sends notifications.** The agent holds no provider token and sends nothing. Message text is a fixed server template, never model output |
| G4 | **No tool loop.** One LLM call per work item with a strict JSON schema. The trigger decides what data is fetched; the model chooses nothing |
| G5 | **ADR 0014 D1 stays.** The help assistant keeps its scope and data limits. The ops agent is a separate backend for admins only |

## Decisions

### D1: Purpose and role

- The ops agent turns open findings into **fix notes**: one note per host
  and finding group (D3) with three parts:
  - **What:** package and version, tier, KEV, exposure. Rendered by NOS
    from its own store, not from model text.
  - **How to fix:** ordered steps (patch run, container update, service
    restart, reboot). Each step is a catalog action on the group's host.
    When no update exists: an interim measure as text (for example
    "restrict the port at the firewall").
  - **Priority:** the tier and score NOS computed (`vu-prio-v1`, spec 12:
    "The LLM supplies text only"), plus one sentence of model text.
- The model orders, explains and words. NOS computes every fact, offers
  the step candidates and validates the result.
- Two further note kinds: `summary` (fleet counts per tier, D5) and
  `answer` (reply to an admin question in the Ops tab, D11).
- The feature is optional and **off by default**.

### D2: Process, identity and scopes

- New binary `cmd/nebula-ops-agent`, a oneshot under its own system user
  `nebula-ops-agent` on the NOS host (D13). It is not in `nebula-rpc` and
  holds no SSH key, vault material or notification provider token.
- It holds exactly: its NOS API token and, optionally, the LLM
  credential, each in a file readable only by its user. Its only state is
  a small run-state file (daily call counter).
- **Import boundary (allowlist, fails closed):** standard library,
  `internal/opsagent/`, `internal/llmclient/`, `internal/helpdocs/`,
  `internal/helpsearch/` and what these import. A test like
  `TestVulnAgentImportsOnlyAllowlist` enforces it.
- One dedicated API token (default name `ops-agent`) with exactly two new
  scopes, served under `/api/v1/ops/`:

  | Scope | Endpoints | Writes |
  | --- | --- | --- |
  | `ops.read` | `GET /api/v1/ops/agent-config`, `GET /api/v1/ops/work` | Nothing |
  | `ops.notes.write` | `POST /api/v1/ops/notes`, `POST /api/v1/ops/status` | Only the notes store and the agent's last-run status |

- **Exclusive token**, same rule as the vulnerability token: both scopes
  live only on this token, the token carries no other scope (never
  `execution_logs.read`, never a vuln scope), at most one such token, and
  a configuration that breaks the rule is refused at start. A
  source-address allowlist is allowed on this token; on the NOS host it
  is set to loopback.
- Revoking the token means removing it from `server.json`.

### D3: Work items and finding groups

- **Group:** one inventory host and one remediation path:
  - `os`: open host package findings of that host (kernel included);
  - `image:<image subject ID>`: open findings of one image that runs on
    that host.
  Device findings get no fix notes in this ADR (NOS has no device patch
  action).
- **Eligible:** the group has at least one open finding in tier
  `critical` or `high`. Findings in state `accepted_risk` or
  `false_positive` are left out. Medium and low findings of the group are
  given as counts.
- **Input digest:** SHA-256 over the canonical JSON of the group's
  projection (D4). A group is **due** when no stored note carries its
  current digest.
- **Work list:** `GET /api/v1/ops/work` returns at most 20 due items,
  ordered by tier, KEV, score. Each item is complete: the agent needs no
  second read. Open admin questions (D11) come first; a `summary` item is
  due once per day.
- **Triggers:**
  - `nebula-ops-agent.timer`, every 30 minutes.
  - `nebula-ops-agent.path`: the server touches a trigger file when a
    finding newly enters tier `critical` or `high` (new, or escalated) or
    when an admin asks a question. Only systemd reads that path; the
    agent cannot see it (D13). The file is
    `/var/lib/nebula/server/ops-trigger` (amendment 2026-11-19). The pattern is that of
    `nebula-discovery.path`.
  A trigger carries no data. A run that finds no due item ends.

### D4: Projection: what the agent reads

The server builds every work item from a fixed struct in a projector
package (`internal/opsfacts`, import-boundary test like
`internal/helpfacts`). The projection, not the agent, is the security
boundary.

| Field | Data class `lab` | Data class `external` |
| --- | --- | --- |
| Host | Inventory host ID, label (≤ 64 bytes), environment, criticality | Never |
| Exposure | The `vu-prio-v1` exposure level; listening ports as number and protocol, ≤ 32 (*verify* the source, ADR 0009 listeners) | Never |
| Findings (≤ 40 per group by score, the rest as counts) | Vulnerability ID, source package, installed version, fixed version or fix state, tier, score, KEV flag | Never |
| Fix status per finding | The ADR 0011 D8 result: fix verified, update not verified, no candidate, no fix yet, reboot required | Never |
| Step candidates | Opaque key (`c1`…), action ID, host ID, fixed NOS label | Never |
| Counts | Per tier and KEV for the group | Per tier and KEV for the whole fleet |
| Documentation | ≤ 3 chunks from `internal/helpsearch`, picked by the agent | Same |

- **Step candidates** are computed by the server with the same logic as
  the "Fix with" links (D8 of ADR 0011), moved into a shared package.
  Actions come only from the **suggestion allowlist**, a fixed table in
  code, each entry with a family:

  | Family | Actions |
  | --- | --- |
  | `os-update` | `package.install_security`, `package.install_all` |
  | `reboot` | `system.reboot` (offered only for "reboot required") |
  | `service-restart` | `service.restart` |
  | `container-update` | the container update flow of the host (`docker.compose_update`, `docker.update`; batch-only) |
  | `container-restart` | `docker.restart` |

  Read-only actions are not on the list. An action that is no longer in
  the catalog drops out.
- **Never in any item:** addresses, endpoints, fingerprints, credentials
  or their references, user names, execution output or logs, audit
  attributes, the vulnerability agent's assessment text, flows, topology,
  attack-path steps, notification targets.
- Bounds (named constants): item ≤ 32 KiB, page ≤ 20 items, 60 requests
  per hour per token.

### D5: Data class (revises ADR 0011 Q6 for this agent)

ADR 0011 Q6 (2026-11-09, "most restrictive, maintainer may revisit")
keeps host labels out of the export to the vulnerability agent. The
maintainer revisited it **for the ops agent only**:

- The settings (D12) carry a **data class**, `lab` (default) or
  `external`, chosen by the admin and stored with the LLM URL.
- **`lab`:** host labels and vulnerability IDs may enter the prompt. The
  agent then **always** builds its LLM client with the lab-only dialer of
  ADR 0011 A1.4 (address check after DNS resolution, no redirects, proxy
  variables ignored, plain `http` only with `allow_plain_http` and never
  with a credential). No flag, setting or environment variable disables
  the dialer in this class. A URL that does not resolve into the lab
  networks gets no call: the run reports `llm_refused_lab_rule` and
  writes no note. There is no fallback to `external` inside a run.
- **`external`:** the LLM URL may point outside the lab. The server then
  serves only `summary` items with counts per tier (D4, right column) and
  no `fix` item. Answers (D11) get the question, documentation chunks and
  the same counts.
- The **server** decides what it serves from the stored class; the agent
  cannot ask for more. The agent decides which dialer it builds from the
  same class. Both are tested.
- ADR 0011 Q6 is unchanged for the vulnerability agent export
  (`vuln-inventory-v1` carries no labels).

### D6: LLM use

- **One call per item, no tool loop** (G4). Reason: the default model is
  a 9B model; a free tool choice over lab data is unreliable and is the
  widest injection surface.
- **Prompt:** fixed core prompt in code, operator instructions (≤ 4 KiB)
  after it, then delimited data blocks marked as data, never
  instructions. Language from the settings (`de` default, `en`).
- **Output for a `fix` item**, one JSON object:

  | Field | Bound |
  | --- | --- |
  | `summary` | ≤ 600 bytes |
  | `steps` | ≤ 6 entries in order; each `candidate` (a key from the prompt) and `why` (≤ 300 bytes) |
  | `mitigations` | ≤ 3 entries of `text` (≤ 400 bytes); expected when no candidate fixes a finding |
  | `urgency` | ≤ 300 bytes |
  | `citations` | ≤ 3 chunk IDs that were in the prompt |

  The model never writes an action ID or host ID. The agent maps each
  candidate key back to the action and host of the work item.
  `summary` and `answer` items return `text` (≤ 2 KiB) and `citations`.
- The agent validates the object, then NOS validates it again (D7).
  Anything else is discarded and counted; one retry at most.
- **Limits (named constants):** prompt ≤ 12,000 tokens (estimated from
  bytes), output ≤ 1,024 tokens, call timeout 90 s, ≤ 20 LLM calls per
  run, ≤ 200 per day.
- **Endpoint:** OpenAI-compatible chat API through `internal/llmclient`.
  All projected data is untrusted input (labels and package names can
  carry instructions). The model's only channel is the note.

### D7: Notes: store and validation

`POST /api/v1/ops/notes`, one JSON object, checked strictly (unknown
fields and invalid UTF-8 rejected):

| Field | Rule |
| --- | --- |
| `kind` | `fix`, `summary` or `answer` |
| `ref` | Group key (`fix`), day (`summary`) or question ID (`answer`); must exist |
| `digest` | Must equal the server's **current** input digest for `ref`; a stale digest is refused |
| Text fields | Bounds of D6; printable UTF-8 with newlines; control, bidi and zero-width characters rejected; a text that contains `://` or `www.` is rejected |
| `steps` | Each `(action_id, host_id)` must be in the suggestion allowlist, in the catalog, on an existing host that is the group's host, **and** among the candidates the server computes for that digest. No parameters |
| `citations` | Chunk IDs of the embedded documentation index |

- A `fix` note in data class `external` is refused.
- On acceptance the server stores, with the note, its own snapshot of
  the group's facts. The "What" part of the card is rendered from that
  snapshot, never from model text.
- Idempotent by `(kind, ref, digest)`: the same body is a no-op, a
  different one is `409` and audited. A newer note for the same `ref`
  supersedes the older one.
- At most 100 notes per day. **Retention: 30 days or 500 notes**,
  whichever is reached first, pruned with injected time.
- **Visible to admins only.** Every other user gets `404`.
- **Not in backups:** notes and questions live in their own SQLite file
  (`/var/lib/nebula/opsnotes/notes.db`, *verify*) that `nebula backup`
  does not copy. If the backup code copies it without a change in
  `cmd/nebula/` (protected), the ticket stops and reports.
- A note is never an input to planning, proposals, permits, schedules,
  leases or the executor. Its only effect outside the notes store is the
  origin rule of D9, which can only make an approval stricter.

### D8: Suggestion card

- NOS renders a `fix` note as a card in the Ops tab (D10): the "What"
  facts from the snapshot, the model text escaped, the label "Generated
  by an LLM – unverified. NOS checked only that each step is a catalog
  action on this host." (German in the German UI), citations as links
  built by NOS. A card whose digest is no longer current is marked
  "outdated: findings changed".
- **One button per step.** It opens the normal NOS form, prefilled with
  the action and the target host, in the "Fix with" pattern of ADR 0011
  D8: a plain GET link, **never submitted**.
  - Single actions: `GET /operations/new?suggestion=<note ID>.<step>`.
    The server reads action and host from the stored note; `action=` and
    `host=` in the same URL are ignored.
  - Container updates: the container update page of that host with the
    same `suggestion` parameter.
- **The human fills in every parameter** (unit name, container, stage
  plan) and **submits**. The note supplies no parameter and no secret.
- Mitigations are text. They have no button and are never turned into a
  form, a firewall rule or a command.
- The form shows a banner: "Opened from an agent suggestion. This
  execution needs a security-key touch."
- A step whose action left the catalog or whose host left the inventory
  shows no button.
- An admin can dismiss a card. Dismissing hides it and changes nothing
  else (see D9).

### D9: Agent-suggested executions always need a security-key assertion

Decision: every execution whose form was opened from an agent suggestion
needs a WebAuthn assertion, also when the action is LOW.

**Mechanism (no change to proto, permit or executor).** For such an
execution the server proposes `risk_class = max(executor-derived risk,
MEDIUM)`. The executor already accepts a class above its own minimum and
then applies the row of that class in the spec 05 table: a per-execution
assertion with user presence, plus an open privileged session for browser
approval. The raised class is part of the canonical request, so it is
bound into the execution digest and the challenge. For a batch, the
matching members are proposed as at least MEDIUM; the strictest-member
rule of ADR 0007 then requires one presence assertion for the batch.
HIGH and CRITICAL keep their own, stricter rows; hardened mode is
unchanged.

**How the server knows the origin.** The client cannot lower it:

1. **Reference.** The prefilled form carries the suggestion reference
   (`<note ID>.<step>`), and the create request sends it back. The server
   looks it up in the notes store. An unknown, expired or malformed
   reference is **refused** (`400`); it never falls back to an unmarked
   execution. A valid reference always marks the execution, also when the
   human changed action or targets in the form.
2. **Match (omission-proof).** For every interactively created execution
   and batch member, with or without a reference, the server checks its
   own notes store: if a stored `fix` note (not yet pruned, dismissed or
   not, outdated or not) has a step with the same **action family** on
   the same host, the execution is marked. Removing the reference from
   the request therefore changes nothing.

So a forged or added reference can only make the approval stricter, and
an omitted one is caught by the match. The cost is deliberate: while a
fix note for a host is stored (at most 30 days), an admin who starts the
same kind of action on that host by hand also touches the key.

**Scope and record.**

- Applies to executions and batches created in the web UI. It does not
  apply to leased reads (no read action is on the suggestion allowlist)
  and adds nothing to schedule or read-grant approval, which already
  need user verification. The suggestion form offers no "schedule this".
- The execution stores its origin (`suggestion:<note ID>.<step>` or
  `suggestion-match:<note ID>`); the audit entry `execution_proposed`
  carries it, and the operation page shows "From an agent suggestion"
  and "Risk MEDIUM (raised; the action declares LOW)".
- If the batch path cannot carry a raised member class without a change
  in a protected path, the ticket stops and reports; container update
  buttons are then not shipped until the maintainer decides.

**Limit, stated in the docs.** The server decides the marking; the
executor enforces the approval once the class is raised. A compromised
server can leave the class at LOW, but it can already propose LOW work
inside an open privileged session (spec 05, `v23-05-07`), so nothing is
lost. The rule defends against a model-written, plausible suggestion and
a routine click, not against a compromised server. As for every browser
approval, the authenticator signs the challenge, not the displayed form.

### D10: Notifications: server only, outbound only

- The agent sends nothing (G3). All messages come from `internal/notify`
  with its existing providers, limits and plain-text rule.
- **Outbound only.** NOS sends to Telegram, ntfy and the webhook and
  **never reads** from a provider: no `getUpdates`, no incoming webhook
  endpoint, no bot commands, no free text. The only Telegram API method
  NOS calls is `sendMessage`; a test fixes that. Questions are asked
  only in the NOS UI (D11).
- **No model text in any message.** Every message is a deterministic
  server template with structured fields.
- **Notification log and inbox (new, server).** Every event the server
  sends, holds back (rate limit, mute) or fails to deliver is stored
  with its structured fields and outcome (30 days, at most 5,000
  entries). The web UI shows it as the "Notifications" list. It works
  without the agent.
- **New deterministic events (server, spec 13).** They need no agent and
  no LLM and are delivered first:

  | Event | Rule |
  | --- | --- |
  | `lease.expiring` | A read lease or schedule grant expires within 7 days, and again within 1 day; once per grant and threshold |
  | `lease.run_failed` | A leased run failed; once per grant, action and host until the next success |
  | Daily digest | Spec 13 already names it. Optional, at a configured time: open updates, reboots pending, hosts not READY, grants expiring within 7 days, open findings per tier and KEV count, failed executions of the last 24 h. Counts only |
  | `opsagent.suggestion_new` | A `fix` note was accepted for a group whose top tier is `critical` or `high`. Text: "Neuer Fix-Vorschlag für <host label>, Tier <tier>" (English: "New fix suggestion for <host label>, tier <tier>") plus a link into the NOS UI. Once per group and tier episode, inside the existing hourly limit and digest |
  | `opsagent.settings_changed` | D12 |

- If the agent or the LLM is down, every notification is unchanged; the
  Ops tab shows "no suggestion yet" and the agent's last-run status.

### D11: One panel "Assistant", two tabs

- The panel of ADR 0014 D1 (on `/help` and as side panel) gets two tabs:

  | Tab | Who | Content | Backend |
  | --- | --- | --- | --- |
  | **Help** ("Hilfe") | Every logged-in user | The help assistant of ADR 0014, handbook only | `internal/helpassist` in the server (ADR 0014) |
  | **Ops** | Admins only | Fix cards, summary, agent status, questions | Notes store in the server; text from `nebula-ops-agent` |

- **Separate backends.** The tabs share no handler, store, prompt,
  settings row or rate limit. Shared code is only `internal/llmclient`,
  `internal/helpdocs` and `internal/helpsearch`. The Help backend never
  reads notes, findings or questions; an import-boundary test fixes
  that. A non-admin does not get the Ops tab in the markup, and its
  endpoints answer `404`.
- **Questions (Ops tab, admins only).** An admin types a question
  (≤ 2 KiB). The server stores it (at most 20 open, 50 per day, 30 days)
  and touches the trigger path. The next agent run gets it as a work
  item with a fixed context: the question, documentation chunks, and in
  class `lab` the group facts of the hosts the question names (≤ 5). One
  LLM call, no tools. The reply is a note of kind `answer`: text and
  citations, **no steps and no buttons**. The UI polls; there is no
  listener in the agent and no stream.

### D12: Settings

Same model as ADR 0011 A1.8 and ADR 0014 Q1: one row in `server.db` with
enabled (default **off**), LLM base URL, model, `allow_plain_http`, data
class (D5), operator instructions, language (`de` default, `en`). A "copy
from vulnerability agent" action copies only URL and model into the form
and saves nothing by itself. Admin only, one fresh user-verified
assertion per change in the flow of spec 05 `v27-05-01` (own domain
separator `nebula-opsagent-settings-v1`), audited, and the event
`opsagent.settings_changed` with old and new URL, model and data class.
The core prompt is shown read-only. The server never stores the LLM
credential. The agent re-validates what it reads against its own rules.

### D13: Deployment and hardening

- Runs on the NOS host under its own UID (previously: "own VM
  possible"; not planned).
- Unit derived from `nebula-vuln-agent.service`: `Type=oneshot`, no
  capabilities, `ProtectSystem=strict`, `NoNewPrivileges`,
  `ProtectProc=invisible`, `ProcSubset=pid`,
  `InaccessiblePaths=-/var/lib/nebula -/etc/nebula -/run/nebula`, state
  directory as the only writable path, `RestrictAddressFamilies=AF_INET
  AF_INET6 AF_UNIX`, `IPAddressDeny=any` with `IPAddressAllow=localhost`
  in the unit and the LLM address in an admin-written drop-in.
- The agent's own dialers connect only to the two configured
  destinations: the NOS API and the LLM endpoint.
- Timer and path unit are not enabled by default.

### D14: Audit

- Server: every API access (existing `api_read`); every accepted or
  rejected note with token, kind, ref, digest, length and SHA-256, never
  the text; every question with user and length, never the text; every
  settings change; the origin of every marked execution (D9).
- Agent: per run to journald and `POST /api/v1/ops/status`: items seen,
  LLM calls, token counts, discarded outputs, refusal reasons. Never
  prompt or answer text, never the token.

## Non-goals

- Executing, proposing, drafting, approving or scheduling anything;
  filling in parameters; submitting a form.
- A tool-using loop, plugins, shell or file access.
- Any intake from Telegram, ntfy or a webhook.
- Model text in a notification.
- Reading logs, audit text, flows or attack paths.
- Fix notes for network devices; explanations of failed operations or of
  single notification events (each needs its own amendment).

## Threats

| # | Threat | Mitigation |
| --- | --- | --- |
| T1 | Prompt injection through host labels, package names or finding data | Data delimited and bounded; no tools; the model picks only candidate keys; output validated twice; nothing executes |
| T2 | Social engineering through a note (a wrong step, a hostile mitigation text) | Label on every card; facts rendered by NOS; steps only from server-computed candidates; no parameters; text escaped, no links, URL-like text refused; **every execution from a suggestion needs a security-key touch (D9)** |
| T3 | Origin marker removed or forged by the client | Reference resolved in the server's store, unknown reference refused; server-side match on action family and host; the marker can only raise the approval |
| T4 | Stolen agent token | Exclusive token, two scopes, loopback source allowlist; reads only the projection; writes only notes |
| T5 | Host names and vulnerability IDs leave the lab | Data class decided by the server; class `lab` forces the lab-only dialer; unit destination filter; `opsagent.settings_changed` on every change; class `external` gets counts only |
| T6 | Note or question flooding | Idempotency per `(kind, ref, digest)`, daily caps, size limits, retention |
| T7 | Compromised agent process on the NOS host | Own UID, hidden NOS paths, no socket, destination filter, no secret beyond its token |
| T8 | Hostile LLM response | Size limit before parsing, strict schema, character rules, validation again in NOS |
| T9 | Telegram as a command channel | NOS never reads from a provider; messages are fixed templates with a NOS link |

Residual risk: an admin follows a plausible but wrong suggestion, fills
in the parameters and approves it with the key. The card reduces reading,
not responsibility; the finding page and the cited section stay the
authority.

## Required specification changes (ag01, protected)

New revision `v28` (2026-11-17), recorded in spec 04.

- **Spec 01** (`v28-01-01`): the ops agent as an optional, default-off,
  advisory feature; the sentence on the help assistant ("never …
  prefills a form that does") stays and applies to the Help tab only.
- **Spec 02, 03** (`v28-02-01`, `v28-03-01`): the process, its user and
  files, its two destinations, the trigger path; the notification log,
  the settings row and the notes file.
- **Spec 05** (`v28-05-01`), new paragraph, proposed text:

  > **Agent-suggested executions (ADR 0016 D9).** An execution or batch
  > member that the server attributes to an ops-agent suggestion is
  > proposed with a risk class of at least MEDIUM, so it always needs a
  > per-execution (or per-batch) assertion with user presence and an
  > open privileged session, also when the action declares LOW. The
  > server attributes an execution when the create request carries a
  > suggestion reference that exists in the notes store, or when a
  > stored fix note holds a step of the same action family on the same
  > host. An unknown reference is refused. The executor enforces the
  > raised class like any other and binds it into the digest; it never
  > lowers it. HIGH, CRITICAL and hardened mode are unchanged. Limit: the
  > attribution is made by `nebula-server`; a compromised server can
  > omit it and gains only what [v23-05-07](#v23-05-07) already states.

- **Spec 07** (`v28-07-01`): the execution origin field in the server
  record and audit entry.
- **Spec 12** (`v28-12-01`): next to "Fix with": suggestion cards open
  the same forms, prefilled with action and target only, never
  submitted; priority stays `vu-prio-v1`.
- **Spec 13** (`v28-13-01`, `v28-13-02`): scopes `ops.read` and
  `ops.notes.write` with the exclusive token rule and `/api/v1/ops/`;
  "the API is read-only except the findings store and the notes store";
  events `lease.expiring`, `lease.run_failed`, `opsagent.suggestion_new`,
  `opsagent.settings_changed`; the daily digest content; the notification
  log; the sentence "NOS never reads from a notification provider".
- **Spec 15** (`v28-15-01`): the notes file is not part of any backup.
- **Threat model:** section "LLM output (ops agent, ADR 0016)" with
  T1–T9 and the residual risk; the row "Findings turned into actions"
  names the suggestion card beside "fix with".
- **ADR 0007**, amendment note: "ADR 0016 D9 uses the existing rule that
  a server-proposed class above the executor minimum raises the
  approval; no new approval type."
- **ADR 0011**, two notes: at Q6, "revised 2026-11-17 for the ops agent
  only (ADR 0016 D5)"; at A1.2, `internal/llmclient/` added to the
  vulnerability agent's import allowlist.
- **ADR 0014**, note at D1: the panel gets the tabs "Help" and "Ops"
  (ADR 0016 D11); D1 itself is unchanged.

## Maintainer decisions 2026-11-17

Axel decided on 2026-11-17. The guard rails G1–G5 stay as written.

| # | Decision | Where |
| --- | --- | --- |
| 1 | **Main purpose: automatic fix suggestions for vulnerabilities.** The agent runs as a oneshot by timer and on new critical or high findings, works through the ADR 0011 findings (`vu-prio-v1`) and writes one validated note per host and finding group: what, how to fix in order, priority; an interim measure as text when no update exists. One LLM call per group, strict JSON schema; steps name only catalog actions and existing hosts; the server validates | D1, D3, D4, D6, D7 |
| 2 | **Suggestion card instead of a draft.** One button per step opens the normal form, prefilled with action and targets, never submitted. The human enters parameters and submits. Every execution opened from a suggestion always needs a security-key assertion, also LOW | D8, D9, spec 05 |
| 3 | **Host names and vulnerability IDs in the prompt only with the lab-only dialer enforced;** otherwise counts per tier only. Revises ADR 0011 Q6 for this agent | D5 |
| 4 | **Runs on the NOS host** under its own UID with the hardening of D13 | D13 |
| 5 | **Telegram outbound only.** NOS never reads from Telegram. No model text in Telegram; for fix suggestions only "Neuer Fix-Vorschlag für <Host>, Tier X" and a NOS link. Questions only in the NOS UI | D10, D11 |
| 6 | **One panel "Assistant" with the tabs "Help" (all users, handbook only) and "Ops" (admins).** Separate backends; shared are only `internal/llmclient`, `internal/helpdocs`, `internal/helpsearch` | D11 |
| 7 | **Deterministic server parts first:** notification log and inbox, `lease.expiring` (7 d, 1 d), `lease.run_failed`, daily digest | D10 |
| 8 | Notes visible to admins only; retention 30 days or 500 notes, not in backups; own LLM settings row with "copy from vulnerability agent"; default language `de` | D7, D12 |

Answers to the open questions of the proposed version: Q1 NOS host.
Q2 no model text in notifications. Q3 host names and vulnerability IDs
under the lab rule (previously recommended: counts only). Q4 and Q5 as
recommended. Q6 suggestions with buttons and the D9 rule (previously
recommended: text only). Q7 one panel, two tabs, separate backends, and
admin questions in the Ops tab (previously recommended: no merge, no
questions). Q8 no Telegram intake.

## Amendment (2026-11-19): trigger file in the server state directory

Maintainer decision (Axel, 2026-11-19, finding B4 of the review). The
trigger file of D3 was `/var/lib/nebula/opsagent/trigger`. nebula-server
runs with `ProtectSystem=strict` and may write only its own
`StateDirectory`, so it could not write that path and the path unit was
inert. The trigger moves (previously `/var/lib/nebula/opsagent/trigger`):

- **Path:** `/var/lib/nebula/server/ops-trigger`, directly in the
  server's `StateDirectory=nebula/server`.
- **Server writes only its own state directory.** `nebula-server.service`
  gets **no new write paths**: no `ReadWritePaths=`, no further
  `*Directory=`; `ProtectSystem=strict` stays.
- **Write:** the server creates an empty temporary file with mode `0600`
  in the same directory and renames it over the trigger (atomic). The
  content is empty and has no meaning; a symlink or other file at the
  path is replaced, never written through. Rate and conditions stay as
  in D3 (at most once per minute, only while the agent is enabled).
- **Watch:** `nebula-ops-agent.path` watches the file with
  `PathChanged=` (`PathModified=` would be equivalent here). Path units
  are watched by systemd itself (PID 1, root); the path unit runs no
  process and names no user, so no account gains access to the server's
  directory. It starts the oneshot `nebula-ops-agent.service`.
- **Agent stays locked out.** `nebula-ops-agent.service` keeps
  `InaccessiblePaths=-/var/lib/nebula -/etc/nebula -/run/nebula` (D13),
  which covers `/var/lib/nebula/server`. The agent never reads the
  trigger; a trigger carries no data (D3).

## Tickets

The plan is `plan-ag.tickets` (IDs `ag01`–`ag26`); the rules every ticket
keeps go into `docs/implementation/ops-agent.md` (ag01).

| Phase | Tickets | Content |
| --- | --- | --- |
| A | ag01 | This ADR, spec revision `v28`, threat model, amendments (protected) |
| B (no agent, no LLM) | ag02–ag07 | Notification log, inbox, lease events, daily digest |
| C | ag08–ag15 | Token class, shared LLM client, fix logic package, projector, notes store, settings store, execution origin, ops API |
| D | ag16–ag21 | Agent binary, panel and cards, prefilled forms with origin, settings UI, suggestion event, units |
| E | ag22–ag23 | Questions in the Ops tab |
| F | ag24–ag26 | Security tests, browser tests, operator documentation |

## Consequences

- NOS gains a second write scope on `/api/v1`, limited to an advisory
  notes store, and one more small process with two destinations.
- The server gains a notification list, lease-expiry messages and the
  daily digest. They are useful without the agent and ship first.
- Suggested work costs one key touch more than the same work started
  from a page without a stored suggestion. That is intended.
- While a fix note for a host is stored, the same action family on that
  host is MEDIUM for everyone. Admins will notice it for LOW restarts.
- The LLM client and lab dialer become one shared package for the
  vulnerability agent, the help assistant and the ops agent.
- No new dependency. No change to `proto/`, `internal/permit/` or
  `nebula-executor`.
