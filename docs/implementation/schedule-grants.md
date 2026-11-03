# Scheduled read-only checks: schedule grants

Decision 5 of the M6 plan (option a, 2026-10-15): scheduled read-only
work (update checks, facts) runs under a **standing, executor-held grant**
that the admin creates with the security key, for a fixed set of actions
and hosts, with an expiry, revocable and audited, limited to actions the
executor itself rates LOW.

> **ADR 0007 (merged):** the schedule grant below is now the **legacy**
> mechanism (`read-schedule-v1`, 90-day ceiling). The current mechanism is
> the **read grant** (`read-grant-v2`), documented at the end of this file,
> which adds on-demand runs, per-target run budgets and a 30-day ceiling.
> The operator-facing behaviour and the 90-day migration path are in the
> admin guide, section 9.4.

## Grant

The server proposes a grant document; the executor canonicalizes it
(RFC 8785) and the approval binds its SHA-256:

```json
{"grant": "read-schedule-v1",
 "id": "<uuid>",
 "actions": [{"action_id": "package.list_updates", "module_version": "1.0.0",
              "artifact_sha256": "<hex>", "parameters_hash": "<hex>"}],
 "targets": [{"host_id": "web-01", "host_key_fingerprint": "SHA256:..."}],
 "min_interval_s": 3600,
 "expiry_unix": 1790000000}
```

At proposal the executor checks, from its own data only:

- 1 to 10 actions, 1 to 100 targets, no duplicates;
- every target is pinned with exactly that fingerprint and not blocked;
- every action's artifact is trusted for exactly that action and version,
  and the executor's minimum risk for it on every target is LOW (an
  artifact trusted as LOW is read-only by the admin's declaration, see
  `internal/riskpolicy`);
- `min_interval_s` is 15 minutes to 7 days, the expiry at most 90 days
  ahead (the UI proposes 30).

Approval: a user-verified WebAuthn assertion over
SHA-256("nebula-schedule-grant-v1" 0 ‖ digest ‖ nonce ‖ expiry) inside
the privileged session, or `nebula schedule approve` in hardened mode.
The approved grant is stored in `executor.db`; unlike a permit it survives
a restart (runs still need `nebula unlock`). Revoking needs no approval.

## Runs

`RunScheduled` (server role) names the grant and one host run. The
executor runs it only if the grant is approved, not revoked or expired,
the action, version, artifact bytes and parameters hash to one entry, the
host and its pinned key are a target, the minimum risk for this host is
still LOW (trust withdrawn or criticality raised stops it), and the last
run of this action on this host under this grant is at least
`min_interval_s` ago (recorded before the run). The run is attached, with a
fresh execution ID, and audited like any run.

What a compromised server can do with a grant: run the approved LOW,
read-only actions on the approved hosts, at most once per interval. It
cannot add actions, hosts, parameters or frequency, and cannot extend the
expiry.

## Server

The server's scheduler and the `/schedules` page are decision 62 in
`m0.md`.

## Read grants (ADR 0007): `read-grant-v2`

The current mechanism is the **read grant** (`read-grant-v2`,
`internal/permit/lease.go`), a standing executor-held grant for read-only
runs. One approval binds an explicit action allowlist, an explicit frozen
target list, an absolute expiry and a per-target run budget.
`internal/executordb` persists approved grants and their spent budgets; the
executor enforces both before every run.

A read grant document:

- **Actions** — up to 32 (`MaxReadGrantActions`), each pinned to an action
  ID, version, artifact SHA-256 and parameters hash. Only actions on the
  read-only allowlist are accepted (`core.facts`, `package.list_updates`,
  `docker.list`, `docker.inspect`, `docker.check_updates`, `service.list`,
  `service.status`, plus the reviewed SSH telemetry actions). A built-in
  trusted as LOW is read-only by the admin's declaration; effective LOW
  alone is not sufficient (e.g. `package.refresh`, `docker.logs` and
  secret-bearing actions are excluded even when rated LOW).
- **Targets** — up to 1000 (`MaxReadGrantTargets` = `canonical.MaxTargets`),
  each a pinned host with its exact host-key fingerprint and, for SSH, its
  exact credential version.
- **Lifetime** — 1 hour to 30 days after creation
  (`ReadGrantMinLifetime` / `ReadGrantMaxLifetime`); the default is 7 days
  (`DefaultReadGrantLifetime`).
- **Trigger** — `scheduled` (a fixed interval, floor 15 minutes) and/or
  `on_demand` (runs requested outside the schedule, through
  `RunReadGrant`). Leases proposed from the Read leases page carry both
  (`internal/executions/readgrants_propose.go`), with `min_interval_s`
  fixed to `schedgrant.MinInterval` (15 minutes; the form has no interval
  field) and durations of 7 or 30 days. The only `RunReadGrant` caller
  today is the telemetry collector (`internal/pvecollect`, scheduled
  history and the on-demand live view), and it skips `ordinary`-profile
  leases; the server scheduler (`internal/executions/schedules.go`) runs
  only legacy `read-schedule-v1` grants. Ordinary leases from the Read
  leases page are therefore not run by anything yet. The trigger only
  selects which runs are allowed; it grants no other rights. The "Refresh"
  link on the Read leases page is unrelated: it is renewal, opening the
  new-lease form pre-filled with the lease's scope
  (`internal/web/ui/leases_new.go`), and never runs anything.
- **Run budget** — a per-target rolling-hour ceiling: default 24
  (`DefaultRunBudget`), max 240 (`MaxRunBudget`); telemetry grants may use
  the higher `schedgrant.MaxTelemetryRunBudget` ceiling. Spent budgets are
  persisted and survive a restart.

Approval is a user-verified WebAuthn assertion, or `nebula read-grant
approve <digest>` in hardened mode (full 64-hex digest). The hardened
proposal page currently prints `nebula lease approve <digest>`
(`leaseCLICommand` in `internal/web/ui/leases_new.go`), a command the CLI
does not have. Revoking needs no
approval. While the executor is locked, read grants are paused (not
deleted); unlocking resumes any still-valid grant, but elapsed time counts
toward the expiry.

## Legacy migration (`read-schedule-v1`)

Existing M6 schedule grants keep their format, scope and expiry and are
revoked one by one; they are **never** converted to on-demand and stay
bounded by the 90-day ceiling in `internal/schedgrant`. New grants are
created as `read-grant-v2`. The operator-facing behaviour and the 90-day
migration path are in the admin guide, section 9.4.
