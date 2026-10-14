# Milestone 6 plan: stage engine (draft for discussion)

Status: **draft, not approved.** Nothing here is implemented. It turns
spec 07 (stage engine) and spec 16 (Milestone 6) into a concrete plan and
lists the decisions that need the maintainer before work starts.

## What the spec asks for

- Spec 07: one engine for everything; DEV → QA → PROD, canary and waves are
  presets. Each stage may set a failure threshold, an unreachable threshold,
  required postchecks, and manual or automatic continue. **One permit covers
  the whole rollout**; its expiry is the planned duration plus margin, at
  most 24 h. Continuing past a gate needs a click in the privileged session
  for LOW and MEDIUM, and a **fresh user-verified assertion bound to digest
  and stage number** for HIGH and CRITICAL. A host still unreachable at stage
  timeout offers Retry, Skip or Abort stage; Skip is audited.
- Spec 16, Milestone 6 (Release 0.2): presets, gates, thresholds, permit
  scope across stages, Retry, Skip, Abort. Accept: *a failing canary stops
  the rollout; a HIGH gate demands a fresh assertion.*
- Spec 13: notify "stage finished with WARNING or FAILED" and "stage gate
  waiting for manual continue".

## What exists that the plan builds on

- The canonical request already carries `stage_plan_hash` (today a fixed
  single-stage value) and `resolved_targets` (every host with its pinned key).
- Permits authorize each host once (`AuthorizeGrant`), keep the canonical
  parameters, and expire.
- The server runs host runs in parallel (at most 4), follows durable jobs,
  stores per-host results and derives Ops State; notifications exist.

## Proposed design

### Stage plan in the approval

A stage plan is part of what is approved, so it is hashed into
`stage_plan_hash`:

```json
{"plan": "stages-v1",
 "stages": [
   {"name": "canary", "hosts": ["web-01"], "max_failed": 0, "max_unreachable": 0,
    "continue": "manual", "timeout_s": 3600},
   {"name": "rest", "hosts": ["web-02", "web-03"], "max_failed": 1, "max_unreachable": 1,
    "continue": "manual", "timeout_s": 3600}
 ]}
```

- Every host of `resolved_targets` appears in exactly one stage; the
  executor checks this at proposal (a host outside the plan, or in two
  stages, is refused).
- The executor keeps the plan with the permit (like the parameters today)
  and tracks the **current stage**: `AuthorizeGrant` refuses a host whose
  stage is not open yet. This is the executor-side enforcement that "a
  failing canary stops the rollout" — the server cannot run stage 2 hosts
  early even if compromised.
- Presets are server-side helpers that produce a plan (single stage;
  canary + rest; DEV → QA → PROD by inventory environment; waves of N). The
  executor only sees the resulting plan.

### Gates

- New RPC `OpenStage(digest, stage)` (server role). LOW/MEDIUM: allowed
  with an active privileged session (the click). HIGH/CRITICAL: needs a
  fresh assertion whose challenge is bound to `digest || stage number`
  (`BeginStage`/`OpenStage` with the assertion), so an assertion for stage 2
  cannot open stage 3. Hardened mode: `nebula approve <digest> --stage N`.
- Stage 1 opens with the initial approval.
- Automatic continue: the executor opens the next stage itself when the
  previous one finished within its thresholds (the thresholds are in the
  approved plan, so this is not a new decision by the server). The server
  reports the per-host outcomes to the executor? **No** — the executor
  already knows them for its own runs (attached responses, durable results),
  so it evaluates thresholds from its own records.

### Thresholds, Retry, Skip, Abort

- A stage is *failed* when more hosts failed than `max_failed` or were
  unreachable than `max_unreachable`; the rollout stops there (no further
  stage can open) and notifies.
- **Retry** an unreachable host: re-authorize the same host in the same
  stage (needs the "unused for this host" rule of #23 — a run that never
  reached the host releases it).
- **Skip** a host: the executor marks it skipped (audited); it counts
  neither as failed nor as done; it needs the same approval level as a
  gate.
- **Abort**: revokes the permit for all remaining hosts.

### Server and UI

- Operation page shows stages, thresholds, per-stage progress and the gate
  button ("Continue to stage 2 — needs your security key").
- Planning page offers the presets; the preview shows which host lands in
  which stage before approval.
- Notifications: stage finished WARNING/FAILED, gate waiting.

### Tests (acceptance from spec 16)

- Canary fails → `AuthorizeGrant` refuses every stage-2 host, even when the
  server asks; notification sent.
- HIGH rollout: opening stage 2 without a fresh assertion bound to stage 2
  is refused; an assertion for another stage or digest is refused.
- Thresholds: `max_failed: 1` lets one failure through, the second stops.
- Retry/Skip/Abort audited; Skip needs the gate approval level.
- Permit expiry: planned duration + margin, never above 24 h.

## Decisions needed from the maintainer

1. **#23 first?** Retry of an unreachable host inside a stage relies on the
   "unused for this host" rule proposed in #23. Without it, Retry means a
   new approval.
2. **Automatic continue for HIGH/CRITICAL rollouts:** spec 07 requires a
   fresh assertion for HIGH gates. Should `continue: "auto"` be refused for
   HIGH/CRITICAL plans (proposal: yes, auto only for LOW/MEDIUM)?
3. **Who evaluates thresholds:** proposed is the executor, from its own run
   records (server cannot fake success to open the next stage). This adds
   state to the executor (`executor.db` migration for stage progress).
4. **Skip approval level:** proposed is the same as a gate.
5. **Scheduled read-only checks** (spec 01: the scheduler may run update
   checks, facts): independent of stages, but also open. Spec 05 requires an
   active privileged session for LOW. Options: (a) a standing, executor-held
   "read-only schedule" grant created with a security key for a fixed set
   of trusted read-only actions and hosts, with an expiry (e.g. 30 days),
   revocable, audited; (b) no scheduling until the user opens a session;
   (c) scheduling only on the executor host via `nebula` (cron). Proposal:
   (a), limited to artifacts trusted as LOW and marked read-only.

## Rough order of work

1. Executor: plan validation, stage tracking in permits, `OpenStage` with
   stage-bound assertions, thresholds from own records (+ `executor.db`
   migration). Security tests first.
2. Server: presets, planning preview, gate UI, notifications.
3. Browser test: canary + gate with the virtual authenticator.
4. Hermes reviews per step (executor part separately).
