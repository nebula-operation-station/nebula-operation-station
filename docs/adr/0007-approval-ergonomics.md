# ADR 0007: Bounded read leases and batch approval

Status: proposed, 2026-10-29

## Context

Working across several hosts currently repeats confirmations for facts, update
lists and container status as well as changes. Spec [05](../spec/05-authentication.md)
requires a 60-minute privileged session for LOW and assertions for MEDIUM/HIGH.
Untrusted built-ins become HIGH, including reads. The [handbook, sections 8.1
and 9.4](../admin/guide.md) documents artifact trust and schedules, but no common
on-demand read authority.

[Spec 07](../spec/07-execution-model.md) already freezes targets and supports
staged multi-host execution of one action. This proposal also groups different
actions into one reviewed plan. The executor still decides risk, holds keys,
verifies assertions and issues exact-target authority; the server proposes work.
Hardened mode retains independent CLI approval for HIGH/CRITICAL; no generic
command, unattended change or CRITICAL batch is introduced. Acceptance needs
a reviewed spec revision before implementation.

The baseline is `internal/permit/schedule.go` and `internal/schedgrant`:
approved grants persist in `executor.db`, bind action/version/artifact/parameters
and pinned hosts, recheck LOW trust per run, and atomically claim intervals.
They currently require a privileged session to propose/browser-approve, allow
up to 90 days and have a 15-minute minimum interval. Pending grants disappear
on lock/restart; approved grants survive but cannot run with locked keys.
ADR 0006 (`docs/adr/0006-proxmox-integration.md`), inspected from branch
`docs/adr-0006-proxmox`, proposes provider grants (P1-07), SSH telemetry leases
(P1-36), and 30-second live-view requests. That ADR is not yet on this branch.

## Decisions

### One standing read-grant mechanism

Extend schedule grants with a versioned canonical read-grant document; “read
lease” is its user-facing name. Scheduled and on-demand execution use the same
executor authorization path, registry, revocation API and budget accounting.
ADR 0006 P1-07/P1-36 become provider/telemetry profiles of this mechanism,
not independent stores of authority. Preserve typed provider targets and
credential restrictions rather than pretending that a PVE resource is an SSH host.

In Standard mode one fresh user-verified assertion approves the complete grant
digest, including its targets, actions, parameters, duration and budget. Grant
creation does not additionally require opening a privileged session: this is
an explicit change to the existing schedule proposal/commit precondition.
The challenge has its own domain separator, nonce, five-minute expiry and
single-use verification with the existing RP/origin/counter checks. Recovery
mode cannot create grants. Hardened mode keeps executor-local CLI approval,
as existing schedule grants do; the CLI displays the complete grant first.

| Field | Binding and limit |
| --- | --- |
| Identity | Versioned document, grant ID, issuer, creation and absolute expiry; default 7 days, maximum 30 days; renewal requires new approval |
| Actions | Explicit list, at most 32 entries: action ID, module/adapter version, trusted artifact SHA-256 and exact canonical parameters hash |
| SSH targets | Explicit host IDs and pinned SSH fingerprints, at most 1,000; credential references/versions where applicable |
| Provider targets | Exact approved remote/resource scope, trust generation/pin, credential version and typed methods; child-resource validation as in ADR 0006 |
| Rate policy | Named ordinary/telemetry/provider profile, minimum intervals, per-target rolling-hour run budget and provider request budget; all included in the digest |
| Trigger | Scheduled, on demand, or both; a trigger never changes the authorized request |

“All managed hosts”, tag and environment are selection conveniences. Resolve
them before approval and show every host/key; store that frozen snapshot.
New enrollment, changed tag membership or a replacement key never joins a lease
automatically. Removing a host disables it immediately; expansion needs a new
grant. Server-owned tags cannot become live executor authorization predicates.
Provider enumeration may discover children only within an explicitly approved
remote/method scope; it never authorizes SSH or provider mutations on them.

The initial allowlist is `core.facts`, `package.list_updates`, `docker.list`,
`docker.inspect`, `docker.check_updates`, `service.list` and `service.status`.
Parameterized inspection/status binds the exact approved container incarnation
or unit; enumeration does not confer arbitrary follow-up command authority.
`package.refresh` writes package metadata and is excluded even if declared LOW;
`docker.logs` and secret-bearing actions are excluded. Effective LOW alone is
insufficient: the executor also requires an approved read-only action contract.
Later reviewed additions include ADR 0006 `host.metrics`, `filesystem.list`,
`pci.inventory`, `gpu.status`, `docker.stats`, `service.check`, `backup.status`
and optional `image.vulnerabilities`, each with its own cost/parameter limits.
Service checks bind approved destinations; no generic URL, shell or API path.

Ordinary reads default to 24 runs per host per rolling hour, maximum 240,
aggregated across actions and both triggers, retaining the 15-minute per-action
floor. “Refresh now” on one host, a selection or all uses that same allowance;
show cached age and next eligible time when throttled. Failed/disconnected
attempts consume budget once claimed; no catch-up burst or free retries.
Reserve the grant budget and executor-wide target ceiling atomically before
dispatch, durably across restart. Overlapping grants cannot multiply the local
ceiling. Storage errors deny reads; clock rollback must not replenish budgets.

Telemetry is a separately approved profile: five-minute history, ten-second
live reads, explicit aggregate budget up to 4,096 runs/host/rolling hour and
bounded concurrency. Costly scans retain their much slower action-specific
limits. ADR 0006 provider limits (including one metrics request/s and four live
targets per remote) additionally apply. Its 30-second visible-target requests
only select work inside the standing grant and budget; they grant no authority.
Viewers coalesce; hiding/disconnecting stops renewal. These short intervals
require the spec revision, never a bypass of today's ordinary schedule floor.

Before every run the executor rechecks expiry, revocation, exact parameters,
artifact bytes/version, read-only contract, effective LOW risk, pin/block state
and credential version. Untrusted or newly HIGH actions are not covered; no
automatic fallback to an interactive assertion or replacement artifact occurs.
Trusting new built-in versions does not amend a lease: approve a replacement
grant for those exact versions. An unchanged trusted version remains covered
only while installed, available and permitted by current policy.

Read runs need unlocked execution credentials, but no privileged session and
no per-run approval. Expiring a privileged session alone leaves leases usable.
`nebula lock` wipes keys, pauses grants and cancels queued dispatch; restart
starts locked, with approved grants and spent budgets preserved, pending
proposals discarded. Explicit local unlock resumes still-valid leases without
a browser session; elapsed time continues to count toward expiry while paused.
Revoke via UI or CLI needs no assertion and blocks all future claims; serialize
revocation/lock with dispatch so queued work cannot escape. Already dispatched
work may finish; neither lock nor revocation undoes a remote operation.
Re-pin, removal, credential rotation, trust withdrawal or a raised risk floor
blocks affected scope; identity/version changes require a replacement grant.
Credential removal/recovery pauses grants until local review and unlock.

Audit proposals, approver, approved digest/scope/budget, renewal, pause/resume,
revocation and denials. Every run has a fresh execution ID linked to grant ID,
action/version, exact target, trigger, budget claim and outcome. Keep sanitized
results in existing execution history; never log credentials or secret values.
The UI shows expiry, remaining budget, blocked reasons and a prominent Revoke.

Legacy `read-schedule-v1` approvals keep their original schedule-only scope and
expiry (including existing 90-day grants); never reinterpret their signatures
as on-demand permission. New grants/renewals use the 7/30-day policy, replacing
ADR 0006's proposed 90-day provider maximum too. Migrate storage and accounting
without duplicating authority; legacy grants share the executor target ceiling.
List legacy grants together; offer revoke or explicitly approved replacement.

### One approval for an exact change plan

A batch contains 1–100 expanded action-target members, at most 1 MiB of canonical
plan bytes and at most 20 stages. Updating 12 hosts and restarting 3 containers
is 15 members; no compressed wildcard or implicit descendants. Oversize plans
require separately reviewed batches, never invisible automatic approval chunks.
CRITICAL members reject the entire batch proposal, with their identities shown;
the admin must explicitly remove them and approve them separately with the
existing UV/target-count flow (CLI in hardened mode). Do not silently omit them.

The executor validates and computes SHA-256 over RFC 8785 canonical `batch-v1`:
batch ID, expiry, stage/dependency graph and its hash, and an ordered list of
member IDs and complete existing canonical execution requests. Each member
binds action ID, module/adapter version, artifact hash, exact target/key (or
ADR 0006 provider identity/generation/pin), credential references/versions,
canonical parameter hash, precondition hashes and executor-derived risk.
Supply bounded parameter documents and artifact bytes for executor validation;
secret parameters remain opaque references, with values held by the executor.
Container actions bind full ID, configuration and old/new image digests.
Reject duplicate member IDs, duplicate action-target-parameter tuples, malformed
UTF-8, unknown/duplicate keys, cycles, missing dependencies and excessive sizes.
Order is significant; reorder, insertion, removal or edits create a new digest.

The requirement is the strictest member: MEDIUM needs presence; any HIGH needs
UV; LOW-only batches keep privileged-session authorization. Browser mutation
approval still requires a privileged session. One assertion signs an executor
challenge domain-separated for the batch digest, nonce and five-minute approval
window. Execution expiry covers the frozen rollout plus margin, at most 24 h.
The UI shows every member, parameters, version/hash, exact target, effective
risk, dependencies, gates and total counts before confirmation; an aggregate
summary or truncated list is insufficient. Escape all labels as untrusted text.

In hardened mode HIGH batches require `nebula approve <batch digest>` locally.
The admin UID retrieves the executor's complete frozen plan; the CLI shows every
member and scanner findings before one confirmation, without a browser session.
MEDIUM browser approval remains available under the existing rules.

After approval, derive an internal single-use permit for each member, bound to
the parent digest, member index/ID, exact request and parent expiry. No bearer
batch token authorizes arbitrary child requests. Claim member execution IDs
atomically using the existing spent-ID discipline before dispatch; concurrently
submitted/replayed members cannot execute twice. Recheck all normal per-run
trust, risk, pin, parameter, credential and stage checks. A raised risk invalidates
remaining batch authority and requires a fresh plan; never downgrade it.
Approval/child permits and gate state remain memory-only: lock/restart revokes
them. Persist intent/outcomes for reconciliation, never resumable mutation rights.

A batch is not a transaction. Show per-member success, failure, skipped,
not-executed and unknown outcomes; no automatic rollback, unapproved retry or
redispatch after an uncertain mutation. Dependencies enforce order and required
postchecks; default failure policy stops all undispatched work. Explicitly
approved stage thresholds may allow independent members to continue. Reconcile
running jobs first; retries or rollback need fresh exact-target approval.
Reuse the stage engine, extending its unit from host to member so several
actions on one host cannot bypass ordering or reuse one another's permit.
Manual LOW/MEDIUM gates retain a privileged-session click. HIGH gates retain
fresh UV bound to batch digest and stage number (CLI in hardened mode); no
automatic HIGH continuation. “One approval” covers initial plan authorization,
not removal of stage gates. Skips are audited and never open unmet dependencies.

### Trust built-ins together after an upgrade

Add executor-local `nebula artifact trust-builtins`. Read a bounded built-in
bundle from the locally verified NOS release, using the existing release trust
root; a server-exported directory alone is not proof of built-in provenance.
The executor hashes exact candidate bytes and retains the previously trusted
built-in bytes/manifest for comparison. Show action-by-action old/new versions,
hashes, risk/contracts, full script diff and executor scanner findings; display
new actions in full and removed actions explicitly. On first use show all bytes;
missing previous bytes require full review, never “unchanged”. Unchanged actions
need no confirmation. Reject same-version changed bytes or invalid provenance.

One local confirmation commits all displayed additions/changes atomically,
bound to the reviewed manifest digest; rehash and compare the trust-store
generation before commit to reject file substitution or concurrent changes.
This convenience flow is CLI-only in both modes; it creates no browser bulk
trust endpoint. Existing individual trust operations remain available. Scanner
and host floors still apply; record the admin UID and each old/new trust tuple.
Old versions are explicitly retained or retired; retirement revokes affected
authority, never retargets it to new bytes.

Show an executor-verdict banner: “Built-ins are untrusted: every operation using
them needs UV until you trust them.” Include the local CLI command and affected
versions; distinguish unreachable from untrusted and explain lease replacement.
Trust may restore declared risks; it never approves a mutation.

### Visible, configurable privileged sessions

Keep 60 minutes as default; allow 15–240 minutes in executor-local configuration,
validated at startup. The server cannot choose or extend the duration. Show
executor-reported expiry and remaining time with an Extend action. One fresh
UV assertion binds the session-extension operation and configured duration;
set expiry to approval time plus that duration, never accumulate extensions.
An expired session uses the same single assertion to open a new one. Browsing,
read leases and mutation approval do not silently extend it. Lock/restart still
ends the session; extending it does not renew grants or resurrect permits.

## Threat analysis and consequences

A compromised server can request leased reads, consume budgets and see sanitized
results without the admin present. This disclosure/load authority binds methods, targets,
trusted versions, expiry and durable rate limits. It cannot add hosts, secrets,
commands, network destinations or mutations. Trust withdrawal, pin mismatch and
lock fail closed. Read-only root scripts still need review: a LOW label or
clean scanner result is not proof of harmlessness; output limits/redaction,
schema/UTF-8 checks and text-only rendering remain mandatory.

Batch substitution, member injection, target expansion, reordered dependencies
and replay fail because the executor hashes the complete canonical plan and
checks every derived member against it. Atomic claims and dispatch checks close
double-use and approval-to-run races. However, WebAuthn signs a challenge, not
the displayed plan: a compromised server can still show a benign batch while
requesting another batch's valid challenge. The independent executor-local CLI
view mitigates this deception; hardened HIGH/CRITICAL approval retains it.
Large batches increase blast radius and review fatigue; bounded full-member
views, stage gates and conservative stop defaults limit that cost. Longer
sessions increase exposure, so configuration remains a deliberate local choice.

## Required specification changes

- `docs/spec/05-authentication.md`: grant-bound UV without a prior session,
  batch approval/risk table, hardened CLI, session range and extension semantics.
- `docs/spec/07-execution-model.md`: versioned read/batch documents, exact
  binding, limits, derived permits, budgets, member gates and crash semantics.
- `docs/spec/01-product.md`, `03-processes-and-data.md`, `06-credentials.md`:
  standing read scope, durable grants/budgets versus volatile permits, lock and
  recovery; coordinate provider custody/scheduling changes with ADR 0006.
- `docs/spec/10-modules.md`, `11-operations.md`, `12-inventory.md`: local bulk
  built-in trust, read-only allowlist, refresh budgets and frozen selections.
- `docs/spec/04-revision-history.md`, `17-frozen-decisions.md`: record reviewed
  changes; align ADR 0006 P1-01/P1-07/P1-36 before shipping either grant profile.
  Update handbook 8.1/9.4 and implementation/security documentation afterwards.

## Implementation tickets

Each row is one agent job, tests first and `make check`; no new dependencies.
**P** marks protected paths requiring explicit authorization in that ticket.
Generate RPC files with `make generate` after approved proto edits. E01 precedes
authority changes; E04/E05 precede E06; E09–E12 precede E13. Each E19 adapter
precedes its feature's UI/CLI integration; local authority tests need no RPC.

| Ticket | Scope / paths | Acceptance tests or review |
| --- | --- | --- |
| E01: approve spec revision | Listed `docs/spec/` files **P** | Map every changed authority, numerical limit and ADR 0006 overlap |
| E02: read document v2 | `internal/schedgrant/` | Exact schema, frozen scopes, allowlist, 7/30 days, malformed/oversize rejection |
| E03: grant-bound approval | `internal/permit/schedule.go` **P** | One UV without session, recovery refusal, hardened CLI, expiry/replay/domain separation |
| E04: durable read budgets | `internal/executordb/` migration/store **P** | Rolling-hour claims, concurrency, overlapping grants, rollback clock and restart; legacy scope unchanged |
| E05: shared read authorization | `internal/permit/`, executor read dispatch **P** | On-demand/schedule parity, trust/version/pin checks, revoke/lock races, no secrets/mutations |
| E06: refresh and lease pages | `internal/executions/schedules.go`, `internal/web/ui/`, templates | Frozen all/tag/environment previews, refresh selection, throttling, expiry/revoke and legacy display |
| E07: SSH telemetry profile | `internal/schedgrant/`, executor profile dispatch **P** | Replace ADR 0006 P1-36; 10-s/5-min bounds, costly-action limits, no arbitrary commands |
| E08: provider profile adapter | ADR 0006 provider reader, executor **P** | Replace P1-07 authority store; exact remote/trust/credentials, request caps, 30-s requests confer no rights |
| E09: canonical batch contract | `internal/canonical/` **P** | Complete digest, order, duplicates/cycles, 100-member/1-MiB/20-stage limits, substitution rejection |
| E10: batch approval | `internal/permit/` **P** | Strictest risk, CRITICAL rejection, one assertion, hardened CLI, trust/risk changes |
| E11: derived member dispatch | `internal/permit/`, executor dispatch **P** | Single-use concurrent claims, parent/child substitution, crash revocation, uncertain outcome never redispatched |
| E12: member stage gates | `internal/permit/` **P**, `internal/stageplan/` | Same-host ordering, dependencies/postchecks, stop/skip rules, HIGH fresh gate UV |
| E13: batch planning and outcomes | `internal/executions/`, server migration, UI/templates | 12 updates + 3 restarts fully listed, partial failure, no implicit retry/rollback |
| E14: local batch CLI | `cmd/nebula/`, executor admin methods **P** | Admin UID only, full executor view, HIGH hardened refusal from browser, stage gates |
| E15: built-in review manifest | Local release catalog, executor trust storage **P** | Verified provenance, exact previous bytes/diffs, same-version substitution, bounded input |
| E16: bulk built-in trust CLI | `cmd/nebula/`, executor trust transaction **P** | One digest-bound confirmation, atomic commit, race rejection, scanner floors and retirement audit |
| E17: trust-status banner | `internal/web/ui/`, templates | Affected versions, escaped text, unreachable distinct, lease-renewal guidance |
| E18: session policy | `internal/permit/`, `cmd/nebula-executor/` **P** | Default/range, one UV extend/reopen, no accumulated time, expiry/lock races |
| E19a: read-grant RPC | `proto/` **P**, generated RPC, executor roles **P**, client | Narrow propose/approve/read/revoke permissions; scheduled/on-demand parity |
| E19b: batch RPC | `proto/` **P**, generated RPC, executor roles **P**, client | Bounded complete plans, parent/member linkage, server/admin approval separation |
| E19c: built-in trust RPC | `proto/` **P**, generated RPC, executor roles **P**, client | Local admin-only review/commit, read-only trust status for server; no server bulk trust |
| E19d: session RPC | `proto/` **P**, generated RPC, executor roles **P**, client | Executor duration/expiry authoritative, operation-bound extension challenge |
| E20: session display | `internal/web/ui/`, existing WebAuthn assets | Remaining time, extend once, expired state, no activity-based renewal |
| E21: security acceptance | `test/security/` **P** | Compromised-server reads bounded; substitution/replay, revoke/lock races, crash reconciliation |
| E22: operator documentation | `docs/admin/guide.md`, implementation guides | Upgrade trust, 90-day legacy migration, refresh/gates, lock/restart and hardened CLI walkthroughs |
