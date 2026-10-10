<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Execution model: permits, stages, durable jobs, reconciliation

Every privileged execution runs only under a permit the executor issued for one exact request; anything that changes after approval invalidates it.

**Canonical request.** `execution_id`, `action_id`, `module_version`, `artifact_sha256`, `parameters_hash`, `credential_refs[]`, `risk_class`, `stage_plan_hash`, `expiry` and `resolved_targets[]`, where each target is host ID plus the host's pinned key fingerprint. Dynamic selections (“group Docker, environment PROD”) are resolved and frozen before approval; a changed membership needs a new approval.

**Executor checks before each host run.** Permit valid and unused for this host; artifact bytes hash to `artifact_sha256`; module and action match; host and its key fingerprint are in `resolved_targets`; parameters hash matches; only permitted credentials are used; not expired; risk authorization satisfied; signature trust satisfied where the module requires it.

**Stage engine.** One engine for everything; DEV → QA → PROD, canary and waves are presets. Each stage may set a failure threshold, an unreachable threshold, required postchecks, and manual or automatic continue. One permit covers the whole rollout; its expiry is the planned duration plus margin, at most 24 h. Continuing past a gate needs a click in the privileged session for LOW and MEDIUM, and a fresh user-verified assertion bound to digest and stage number for HIGH and CRITICAL. A host still unreachable at stage timeout offers Retry, Skip or Abort stage; Skip is audited.

**Attached and durable runs.** Short read-only actions (facts, service status, update listing) run attached to the SSH session. Mutating or long actions run as durable jobs started by the OS adapter (Debian adapter: transient systemd units) in `/var/lib/nebula/jobs/<execution-id>/` with only `action.sh`, `state.json`, `result.json`, `execution.log`. Results are written atomically: write `.tmp`, fsync, rename.

**Job states.** queued, prechecking, dispatching, running, reconciling, success, warning, failed, not\_executed, cancelled, interrupted, unknown.

**Reconciliation.** After a Nebula restart the executor finds unfinished executions, reconnects, reads remote state, collects log and result, runs postchecks and updates central state. It never re-runs a mutating action whose outcome is unknown.

**Retry classes.** `safe` (facts, update checks), `reconcile-first` (package installs, reboot), `never` (restore).

**Remote cleanup.** The executor deletes a job directory once it has stored the result. As a fallback, enrollment installs `/etc/tmpfiles.d/nebula.conf`, which removes job directories older than 14 days without any Nebula daemon.

**Error classes.** network\_unreachable, connection\_timeout, connection\_refused, authentication\_failed, host\_key\_mismatch, credential\_unavailable, vault\_locked, precheck\_failed, policy\_blocked, insufficient\_privileges, execution\_timeout, script\_failed, script\_interrupted, result\_missing, postcheck\_failed, host\_rebooting, host\_not\_returned, unknown.
