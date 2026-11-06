# Container update and rollback plan (ADR 0006 P2-03 to P2-05)

Status: **plan, not started** (2026-11-06). No code exists for it yet.
It turns ADR 0006, section "Phase 2 actions, permits and reconciliation", the
rows P2-03, P2-04 and P2-05, and spec 11 (markers v23-11-02 and v23-11-12)
into PR-sized steps. P2-01 (provider actions, px01 to px04) and P2-02 (tree
staged OS updates, ou02, #218) are done.

Each step below uses the recommended default. Anything that needs a
maintainer decision is in [Open questions for Axel](#open-questions-for-axel);
those are not settled by this plan.

## What the ADR asks for

The numbers R1 to R14 are used by every step. The source is ADR 0006 unless
noted.

| # | Rule | ADR lines |
| --- | --- | --- |
| R1 | Pull the approved immutable digest, keep the old image, recreate with the same complete configuration; never just restart | 434, 456-457 |
| R2 | Compose: extend the versioned action; validate labels against approved project and config-file identities; freeze every affected service, replica and dependency; no implicit project-wide update; reviewed digest override | 457-464 |
| R3 | Standalone: only an operator-supplied complete reproducible definition; never reconstruct from `docker inspect`; incomplete means disabled | 465-467 |
| R4 | Secret-bearing configuration stays executor- or host-side, never in the tree or results | 468 |
| R5 | Bind host ID and key, full container ID **and** name, repository, platform, old and new tag, digest from and to (index and platform manifest), configuration digest, exact affected set, credential version, stage plan; for a tag change also the policy and its version. A Compose member binds all of this per image | 372, 435, 470-473; spec v23-11-09 |
| R6 | The executor rechecks identity, configuration and current digest before dispatch and verifies the pulled digest; changed targets are refused; a moved tag needs a new proposal | 473-476 |
| R7 | Private pulls are executor-mediated over SSH to the target engine; credentials stay in the executor, never in host Docker login files; the transfer/load profile is reviewed before it is enabled | 476-478 |
| R8 | Same-tag refresh MEDIUM base, tag change HIGH base with bound policy and version, explicit version selection and no implicit major upgrade; normal trust, scanner and host floors apply; **no CRITICAL variant**, refuse and never downgrade | 372-373, 434-435, 437-443, 479-480; spec v23-11-09 |
| R9 | Keep the previous image by digest and the recreation definition through a rollback window (default 7 days); no automatic prune; cleanup must not delete a retained image | 482-483, 489 |
| R10 | Rollback is a separately approved exact-target recreation (same-tag MEDIUM, tag reversal HIGH) with health, ports, mounts/network and service/replica-count postchecks | 484-486 |
| R11 | A failed update stops its rollout; uncertain recreation is reconciled before any retry or rollback | 486-487, P2-04 row |
| R12 | Image rollback does not undo volume or database migrations: a declared data backup or recovery plan, or rollback is unavailable | 487-489 |
| R13 | The new container incarnation is bound for any later action | 490 |
| R14 | Tree controls only propose; a parent never authorizes descendants; host and container sets are frozen before approval; stages with exact container subplans; current to approved shown first; CRITICAL and unsupported unavailable; CSP and accessibility kept; no unattended mutation | 447-454, P2-05 row |

## Current state and gaps

What exists and can be reused:

- `docker.list`, `docker.inspect`, `docker.check_updates`, `docker.start`,
  `docker.stop`, `docker.restart` and `docker.compose_update` 1.0.0
  (`internal/executions/actions/actions.go`), with strict result parsers in
  `internal/executions/dockerhost/`.
- Durable jobs with reconciliation that never reruns a mutation
  (`internal/executor/durable.go`, `internal/hostrun/durable.go`; up to 6 h).
- `batch-v1` (ADR 0007): one approval for an exact frozen list of up to 100
  members with per-member parameters, stage gates, thresholds, one member per
  target at a time, a single-use permit per member and an optional
  `BatchContainer` binding (`internal/canonical/batch.go`,
  `internal/permit/batch/`, `internal/executor/batch_dispatch.go`). Batch
  execution is wired in a real install (`cmd/nebula-executor/batch.go:56`,
  `cmd/nebula-server/main.go:322-328`).
- The ou02 tree pattern: no-JavaScript checkboxes, a confirmation that shows
  the frozen plan, and a binding of the confirm POST to the shown plan
  (`internal/web/ui/stages.go`, `web/templates/chart.html`).
- Private registry credentials and typed metadata reads in the executor
  (`internal/executor/registry_private.go`, `internal/registrymeta/`).

Gaps that the steps close:

| # | Gap | Where |
| --- | --- | --- |
| G1 | `docker.compose_update` 1.0.0 is project-only: `pull`, then `up -d`. The tag resolves at run time, so the update cannot bind images or containers | `internal/executions/actions/scripts/docker_compose_update.sh:44-48` |
| G2 | No standalone recreate exists. `docker.update` is named in canonical code but is not in the catalog | `internal/canonical/batch.go:308` |
| G3 | `BatchContainer` has four fields only. Name, repository, platform, tags, index and platform digests, affected set and registry credential are missing | `internal/canonical/batch.go:77-82` |
| G4 | Its `ConfigurationHash` is the server's SHA-256 of a stored sanitized inspect result, and old and new digest are both the image ID. That is fine for restart, but it is not a configuration digest (the inspect text holds state fields, not env or labels) and it cannot express a transition | `internal/executions/batchoutcome.go:516-517` |
| G5 | The binding is never enforced: it is cloned and printed, but nothing in the executor compares it with the host. **G5a** is the new update binding (closed by cu01 and cu02). **G5b** is `BatchContainer` on existing restart, stop and start members: this plan leaves it open (Q14) | `internal/permit/batch/batch.go:595`, `cmd/nebula/batch.go:157` |
| G6 | Risk cannot tell a digest refresh from a tag change: `MinimumRisk` sees artifact and host only, and `BatchPolicy.Evaluate` does not get the parameters. A CRITICAL member is told to be approved separately, which ADR 0006 forbids for containers | `internal/riskpolicy/riskpolicy.go:79`, `internal/executor/batch_policy.go:50`, `internal/executions/batchplan.go:80-82` |
| G7 | Classic staged proposals have one parameter set for all hosts, so they cannot carry per-container plans | `internal/executions/executions.go:177` |
| G8 | Batch members run **attached only**, at most 10 minutes. The server caps the timeout too, Compose is excluded, actions with secrets are refused, and a busy target gives up after about 16 minutes | `internal/executor/batch_dispatch.go:37,579`, `cmd/nebula-server/batchrun.go:38-40,302`, `internal/executions/batchplan.go:209,327` |
| G9 | Reconciliation reports to the classic authority only, not to the batch rollout | `internal/executor/durable.go:140` |
| G10 | Postchecks do not gate anything. The Compose verdict is computed for display on the server; the script's exit status covers only pull and up. `RequiredPostchecks` is always empty and `RecordPostcheck` has no production caller | `internal/web/ui/operations.go:537`, `internal/executions/actions/scripts/docker_compose_update.sh:61`, `internal/executions/batchplan.go:274`, `internal/permit/batch/rollout.go:456` |
| G11 | `docker.check_updates` covers running containers only, is anonymous, and compares against the index digest, so an index change on another architecture reads as an update (ADR lines 359-362). A container recreated by digest would read as `pinned` from then on | `internal/executions/actions/scripts/docker_check_updates.sh:21-22,60,64` |
| G12 | No candidate source for tag changes in a real install: nothing produces `registry.tags`, and `registrymeta.NewClient` has no production caller, so the chart's stable version stays "unknown" | `internal/web/ui/chart.go:446-451` |
| G13 | Private reads fail closed in a real install: `SetRegistryReadAuthorizer` has no production caller, and the server never calls `ReadPrivateRegistry`. `PrivateClient` cannot fetch blobs by design | `internal/executor/registry_private.go:137`, `internal/registrymeta/private.go:48` |
| G14 | No rollback state, action or image retention exists. `executor.db` migrations end at 0019 | `internal/executordb/migrations/` |
| G15 | Consumers keep old incarnations: batch bindings need a fresh `docker.inspect` of the new ID, and `ServicePlacement.ContainerID` keeps a full ID | `internal/executions/batchoutcome.go:489`, `internal/pveinventory/links.go:769` |

## Design defaults

- **Decision 1 (default, see Q1):** container updates are `batch-v1` members.
  Stages come from the existing layout (`executions.PlanStages`, DEV/QA/PROD)
  and become `BatchStageSpec` entries with manual gates. Classic staged
  permits cannot carry per-container plans (G7), and ADR 0007 already reserves
  the binding for batches.
- **Decision 2 (default):** one member is one atomic recreate unit: one
  standalone container, or one Compose project with its frozen service set.
  Several units on one host are several members, which run one at a time.
- **Decision 3 (default):** the binding decides, the parameters follow. The
  executor renders the parameter document from the binding and compares its
  hash with `ParametersHash`, so what was reviewed and what runs cannot
  differ, and it needs no parser for server-supplied parameters.
- **Decision 4 (default):** the risk rule is Go code in a protected path,
  derived from the binding by the executor. It is never trusted from the
  proposal and never left to a shell script.
- **Decision 5 (default):** container mutations run only as batch members. The
  executor refuses these action IDs on the classic propose and run paths, and
  it picks the durable transport from the frozen action ID. The server cannot
  choose attached.

## Risk classes

| Case | Base | Result after floors |
| --- | --- | --- |
| Same-tag digest refresh, update or rollback | MEDIUM | MEDIUM on a recorded host with a trusted artifact; approval by presence |
| Tag or version change, or tag reversal on rollback | HIGH | HIGH; user verification, manual stage gates (`internal/permit/batch/batch.go:237`), CLI when hardened |
| Unrecorded host or untrusted artifact | as above | At least HIGH (`internal/riskpolicy/riskpolicy.go:45-49`) |
| Any floor reaches CRITICAL: recorded host, scanner, linked-host floor | none | **Refused**, at proposal and again at approval and claim. No separate approval path and no downgrade |
| Digest-pinned image, unsupported or incomplete definition, unknown digest | none | **Unavailable**: no proposal is offered (ADR line 363, R3) |

`docker.update_preview` (cu02) is LOW and read-only: it writes nothing on the
host, not even a salt file, and does not authorize anything (ADR lines 423 and
439: LOW means read-only). `docker.update_prepare` (cu02) creates the per-host
salt of Q5, so it is MEDIUM and approved like any other host change. It touches
no container and is not a container update.

## Steps, in order

The mapping is: cu01 is P2-03 contracts, cu02 is P2-03 executor recreate, cu03
is P2-04, cu04 is P2-05. **Two parts are split out**
because each can wait without blocking the rest: standalone definitions go to
cu05 (from P2-03) and the private transfer profile goes to cu06 (from P2-04).
Until they land, cu04 shows those targets as unavailable with a reason.

### cu01 Container permit contract (P2-03 contracts)

- **Rules:** R5, R8, and the contract half of R6 and R2. **Gaps:** G3, G4, G6,
  and the contract half of G5a. cu01 does not touch G5b (Q14).
- **Paths:** `internal/canonical/`, `internal/permit/`,
  `internal/permit/batch/`, `internal/executor/batch_policy.go`,
  `internal/registrymeta/` (the tag comparison), `cmd/nebula/batch.go`,
  `test/security/`; `proto/` only if a typed view is needed (the plan travels
  as `batch_json`).
- **Protected: yes**, every production path except `internal/registrymeta/`.
- **Contract:** a new optional member field `container_update`
  (`BatchContainerUpdate`). It is absent on existing members, so existing
  digests and golden values do not change; `BatchContainer` stays as it is for
  restart, stop and start, and a member carries at most one of the two. Host,
  key, SSH credential version and stage plan are already bound by the member.
  The new field adds:
  - `kind` (update or rollback), `form` (compose or standalone);
  - `images`: sorted by `service`, exactly one entry per recreated service
    (standalone: one entry with an empty `service`). Two services with the same
    image have two entries, so nothing depends on how a project shares images.
    Each entry is:
    - `service`, `repository`, `platform`, `old_tag`, `new_tag`;
    - `old_index_digest`, `old_platform_digest`, `new_index_digest`,
      `new_platform_digest`. Platform digests are required; index digests are
      empty only for an image without an index;
    - `old_image_id`: the local image ID phase 1 compares and phase 3 retains;
    - `policy_version`, `policy_digest`, `major_change`: required on an entry
      whose tags differ and refused on a same-tag entry (R8, spec v23-11-09).
      `policy_version` is `registrymeta.Result.PolicyVersion`; `policy_digest`
      is the SHA-256 of the canonical `registrymeta.Policy`, so that two
      policies cannot share a version string unnoticed (see Q13).
  - `targets`: sorted `{service, container_id, container_name, image_id,
    configuration_digest}`, full 64-hex IDs only. Every target's `service` has
    an `images` entry and every entry has at least one target. `image_id` is
    per target, because a rollback of a partly recreated project starts from
    mixed replicas (cu03);
  - `source_digest` (see Q5): what the containers were created from, unchanged
    by the image change;
  - compose only: `project`, `working_dir_hash`, `config_files_hash` (over the
    operator's paths with the NOS override left out, so the value is the same
    before and after an update), `dependencies`;
  - `dependencies`: sorted `{service, relation, restart_on_update, containers}`
    for every project service **outside** `images` that is connected to a
    recreated service, directly or transitively. `relation` is `requires` (a
    recreated service depends on it) or `required_by` (it depends on a recreated
    service, so it is affected although it is not recreated).
    `restart_on_update` is true when Compose's `depends_on.restart` says so.
    `containers` is sorted `{container_id, container_name,
    configuration_digest}`. An empty list is explicit: no dependencies. Targets
    and dependencies together are R5's exact affected set (see Q12);
  - `registry`: empty for public images, otherwise registry ID, record digest,
    credential ID and credential version (cu06);
  - `definition_version` (cu05), `rollback_of` and `recovery_plan_digest`
    (cu03), each required exactly where those steps say and refused elsewhere.
- **Limits:** named constants beside the validation:
  `maxContainerUpdateImages = 20` and `maxContainerUpdateContainers = 50` over
  targets and dependency containers together. The existing
  `canonical.MaxParametersSize` (64 KiB) and `MaxBatchSize` (1 MiB) still apply.
  A plan over any of them is refused; the operator splits it into more
  batches, or the unit is shown as unavailable if one member alone is too large.
- **Validity:** an entry with equal tags and equal platform digests is refused,
  since it would recreate for nothing. A service whose image does not change
  belongs in `dependencies`, or nowhere.
- **Functions:**
  - `canonical.ContainerUpdateFloor`: MEDIUM when **every** entry has equal
    tags, otherwise HIGH. One tag change makes the whole member HIGH.
  - `canonical.ContainerUpdateParameters`: the rendering of Decision 3.
  - `registrymeta.CompareTags(old, new, policy)`: reuses the tag parser of
    `stable.go` and reports major change, variant change or not comparable.
  - `docker.update` at `internal/canonical/batch.go:308` moves to the new
    binding, and `docker.compose_update` joins it.
- **Enforcement:** `BatchPolicy.Evaluate` takes the maximum with the container
  floor and returns a typed `ErrContainerCritical` for CRITICAL, on every
  evaluation including member revalidation. For `kind=update` it also compares
  each entry's `policy_version` and `policy_digest` with the executor's own
  policy for that repository and recomputes `CompareTags`: a wrong
  `major_change`, a variant change, or tags that cannot be compared is a refusal
  (R8: unsupported conventions are unknown, no implicit major upgrade). A
  same-tag refresh of `latest` needs no comparison. The policy values go into
  the trust hash, so a policy changed after approval fails revalidation. Both
  authorities refuse the container mutation IDs on the classic path. The rule
  keys on the action ID, so a module cannot pick the name to avoid it.
- **Limit of the floor:** `ContainerUpdateFloor` trusts the binding's tags. They
  come from a server-side preview, so a forged `old_tag` could turn a tag change
  into MEDIUM here. Evaluate cannot see the host; cu02's phase 1 closes this by
  checking `old_tag` against the running container before anything changes.
- **Risk classes:** defines MEDIUM, HIGH and the CRITICAL refusal. Nothing can
  run yet.
- **Tests:**
  - canonical: table of malformed bindings (digest shape, short ID, leading
    `-` in a name, duplicate target, unsorted targets, unsorted images, a target
    without an image entry, an entry without a target, a second entry for one
    service, a no-op entry, policy missing on a tag change, policy set on a
    same-tag entry, malformed dependency relation, a service in both `images`
    and `dependencies`, each limit exceeded, unknown key); a mutation of any
    bound field in any image entry, target or dependency changes the digest; new
    golden files, and the existing ones byte-identical.
  - unit: `ContainerUpdateFloor` is HIGH when one of several entries changes its
    tag; `CompareTags` table for major, minor, variant, date and non-version tags.
  - security (`test/security`): `TestContainerTagChangeBelowHighRefused`
    (server labels a tag change MEDIUM), `TestContainerBindingDiffersFromParameters`,
    `TestContainerCriticalFloorRefusedNotDowngraded` at proposal, approval and
    claim, `TestContainerCriticalAfterApprovalStopsMember`,
    `TestContainerMutationRefusedOnClassicPath`,
    `TestRestartMemberCannotCarryUpdateBinding`,
    `TestContainerPolicyMismatchRefused`, `TestContainerPolicyChangedAfterApproval`,
    `TestImplicitMajorUpgradeRefused`, `TestContainerVariantChangeRefused`.
- **Real install:** nothing to enable; no action exists yet. `nebula batch
  review` prints every new field, per image and per container, because the
  hardened path reads the plan there.

### cu02 Pinned Compose recreate as a durable member (P2-03 executor)

- **Rules:** R1, R2, R4, R6, R13 (emission), and the running half of R11.
  **Gaps:** G1, G7, G8, G9, G11.
- **Paths:** `internal/executions/actions/` and its scripts,
  `internal/executions/dockerhost/`, `internal/executions/batchplan.go`,
  `internal/executions/batchoutcome.go`, `cmd/nebula-server/batchrun.go`,
  `web/templates/host.html`; protected: `internal/executor/`,
  `internal/executor/dispatch/`, `proto/`, `test/security/`,
  `test/integration/`.
- **Protected: yes** for the executor, proto and test parts; the actions and
  planner are not protected.
- **Contracts and RPCs:**
  - `docker.update_preview` 1.0.0 (LOW, read-only), one parameter
    `target_tags` that may be empty. For the host's containers it reports the
    identity and image facts a binding needs: full ID, name, Compose project,
    service, working directory and config file labels, dependency labels,
    `configuration_digest`, image ID, repository digests, platform, and for a
    requested tag the index and platform digests, resolved anonymously on the
    host as `docker.check_updates` does. Stopped containers are included. It
    never returns env, command line or other label values. Result format
    `docker-update-preview-v1`, with a strict parser and a fuzz target.
  - `docker.compose_update` 2.0.0 (durable, `reconcile-first`, 30 min, batch
    only), result `compose-update-v2`; `compose-update-v1` stays parseable for
    history. Phases, each stopping on failure:
    1. Precheck, nothing changed yet: labels match the bound project and
       config identities; the frozen containers are exactly the service's
       containers, by full ID and name; configuration and current digests
       match; no service uses `build:`. Mismatch is exit 10 with a typed reason.
    2. `docker pull repo@new_digest` per image, then verify digest and
       platform. It never pulls by tag and never runs `docker compose pull`.
    3. Retain the old image under a NOS tag (so that the later rollback step
       needs no script change), and tag the new image locally as `new_tag`.
    4. `docker compose ... -f <reviewed digest override> up -d --no-deps
       --no-build --pull never <frozen services>`.
    5. Bounded health wait and a full after-snapshot: new IDs, state, health,
       ports, mounts and networks. Exit status covers pull and up only; the
       verdict comes in cu03.
  - `docker.check_updates` 1.1.0: stopped containers, platform-manifest
    comparison, and a tag that survives a NOS digest override (see Q2). Fixes
    G11.
  - `InspectBindings` gets a sibling `UpdateBindings` over the latest preview,
    at most `maxContainerBindingAge` old. Compose leaves
    `batchExcludedActions`.
  - **Durable batch members:** the executor picks `hostrun.Dispatch` for the
    frozen action IDs of Decision 5. `RunBatchMember` returns once the job is
    dispatched, and the server follows it through a new
    `GetBatchMemberRun` (server, admin; added to `roles.go`) instead of
    holding one RPC open. Reconciliation routes a member run's outcome to the
    batch rollout. The target stays held while the job runs, and a busy
    target of a durable member does not expire the waiting member after
    16 minutes.
- **Risk classes:** enforces cu01. Update MEDIUM or HIGH, preview LOW,
  CRITICAL refused.
- **Tests:**
  - script tests with the fake host of `docker_test.go`, pinning the call
    order: changed ID, changed name, extra or missing replica, changed config
    digest, moved label, moved tag and wrong pulled digest each stop before
    any recreate; `TestComposeUpdateNeverPullsByTag`,
    `TestComposeUpdateTouchesOnlyFrozenServices`; no `down`, `rm -v`, `prune`
    or restart-only path; injection through names and paths; preview output
    never contains a planted env value.
  - parsers: bounds, malformed UTF-8, unsafe characters, fuzz.
  - executor: crash between intent and dispatch, lost session during dispatch,
    restart while the job runs (each reconciled and never redispatched, and
    the batch rollout gets the outcome); `TestServerCannotChooseAttachedForContainerMember`;
    target held past the old 16-minute limit; Lock during a running job.
  - security: `TestContainerSubstitutionRefused`, `TestTagDriftRefused`.
  - integration: real Docker and Compose, with a registry on loopback.
- **Real install:**
  - **`nebula artifact trust-builtins` must approve the new scripts**, or they
    stay at the HIGH floor. The server and executor must be upgraded together.
  - Durable jobs need root (sudo) on the host; the Compose plugin must be
    present, otherwise preview reports it and the update is unavailable.
  - The host page loses its unbound "update project" link. Do not release
    between cu02 and cu04, or the feature has no front end (see Q3).
- **Size note:** this is the largest step. Commit the durable member first; if
  review wants it smaller, that part becomes its own PR without changing any
  contract.

### cu03 Postchecks, retention and rollback (P2-04, public images)

- **Rules:** R9, R10, R11, R12, R13. **Gaps:** G10, G14, G15.
- **Paths:** protected: `internal/executordb/` (migration 0020 and store),
  `internal/executor/`, `internal/canonical/`, `internal/permit/batch/`,
  `proto/`, `cmd/nebula/`, `test/security/`; not protected:
  `internal/executions/dockerhost/`, `internal/executions/actions/`,
  `internal/executions/batchplan.go`.
- **Protected: yes** for the executor side.
- **Contracts and RPCs:**
  - A pure `dockerhost.JudgeContainerUpdate` over the after-snapshot: health,
    ports, mounts and networks, service and replica count, and the running
    digest equals the approved one. Unknown is not success. The verdict of
    `compose-update-v1` is left as it is.
  - The **executor** judges, then calls `RecordPostcheck`, with a fixed hash
    in `RequiredPostchecks`. A failed verdict is `OutcomeFailed`.
  - Canonical validation requires `failure_threshold` and
    `unreachable_threshold` of 0 for stages with `container_update` members,
    so any failure or unreachable member stops the rollout.
  - `executor.db` table `container_recreations`: execution, host and key,
    form, project or name, old and new incarnations, repository, tags, digests,
    configuration digest, state, window expiry. The row is written before
    dispatch and completed by the result or by reconciliation. Window constant
    `DefaultRollbackWindow = 7 * 24h`, with injected time.
  - `ListContainerRecreations` (server, admin): sanitized rows, so the UI can
    offer rollback and show why not.
  - `SetContainerRecoveryPlan` and `ClearContainerRecoveryPlan` (admin only):
    per project or container, a free-text reference without secrets, recorded
    with actor and time (see Q8). The plan state is bound into rollback.
  - `docker.compose_rollback` 1.0.0 (durable, `reconcile-first`, batch only):
    binding `kind=rollback`, `rollback_of` the recorded execution. Its `old_*`
    fields are the recorded new incarnation and its `new_*` fields are the
    prior digests and tag.
  - Evaluate refuses a rollback unless the row is terminal and not uncertain,
    the window is open, the source is unchanged, a recovery plan exists, and
    the retained image is present (precheck on the host).
- **Risk classes:** rollback same-tag MEDIUM, tag reversal HIGH (the cu01
  floor applied to the reversed tags), CRITICAL refused.
- **Tests:**
  - judge table per postcheck, including a lost mount, a changed network, a
    replica fewer, a wrong digest and `starting` past the wait.
  - security: `TestFailedPostcheckStopsRollout`,
    `TestUncertainRecreationBlocksRollback`, `TestRollbackNeedsOwnApproval`
    (no reuse of the update's permit), `TestRollbackBindsNewIncarnation`,
    `TestRollbackRefusedWithoutRecoveryPlan`, `TestRollbackRefusedAfterWindow`,
    `TestRollbackRefusedWhenConfigurationChanged`,
    `TestNoAutomaticRetryOrRollback`, `TestNoPruneInContainerActions`.
  - store: migration, restart, Lock, clock moved backwards at the window edge.
- **Real install:**
  - The migration runs at executor start; rows are in `executor.db`, so backups
    already cover them.
  - `trust-builtins` for the rollback script.
  - Retention costs disk on the host until an operator cleans up.
    `ListContainerRecreations` shows what is retained; NOS deletes nothing.
  - Placements that keep an old `ContainerID` (G15) show as stale and need
    rebinding. They do not follow silently.
  - Admin guide: rollback window, recovery plans, volume limitation.

### cu04 Tree controls (P2-05)

- **Rules:** R14, and the display of R8, R10, R12, R13. **Gaps:** G15 (UI),
  G12 for typed tags.
- **Paths:** `internal/web/ui/` (new `container_update.go`, `chart.go`,
  `chart_patch.go`, `hosts.go`, `operations.go`, `batch.go`),
  `web/templates/{chart,inventory,host,operation,batch}.html`, external files
  in `web/static/`, `cmd/nebula-server/main.go`; protected: `test/browser/`.
  The ADR row names inventory, host and operation; the ou02 controls actually
  live in `chart.html`, so that file is included.
- **Protected: no** for production paths, **yes** for browser tests.
- **Contracts:** no new RPC. `ui.Options` gets a `ContainerBatches` dependency
  (the same planner as `DeployBatches`), set in `main.go` and covered by a
  wiring test like `cmd/nebula-server/batches_wiring_test.go`.
- **Flow:**
  1. Containers and Compose groups in the tree get checkboxes in a no-JavaScript
     form. Selecting a parent selects nothing below it.
  2. For a tag change the operator names the target tag explicitly. A latest
     stable tag is only ever a suggestion.
  3. Fresh previews are run where the binding is too old.
  4. The confirmation shows current to approved per unit: repository, tag,
     index and platform digest, platform, configuration digest, the exact
     services, containers and dependencies, stage, and the rollback state
     including the text that volume and database migrations are not undone.
  5. The confirm POST is bound to the shown plan (the ou02b pattern, PostForm
     only), then proposed; approval happens on the existing batch page with
     the executor-derived risk.
  6. Progress and stops appear per member. Rollback is offered from
     `ListContainerRecreations` as a new proposal.
- **Unavailable, with reason and no button:** digest-pinned, unknown digest,
  CRITICAL, unsupported or `build:` project, no definition (until cu05),
  private image (until cu06), not enrolled or blocked, rollback window over,
  no recovery plan, retained image gone.
- **Risk classes:** shown from the executor. A proposal refused for CRITICAL
  states that no separate approval exists, instead of the batch default text.
- **Tests:** ou02 style handler tests: tampered POST, stale preview, selection
  outside the shown plan, parent without children, escaped host strings,
  every unavailable reason; `test/browser`: CSP without violations, keyboard
  use, state not shown by color alone, no JavaScript needed.
- **Real install:** the route and the wiring in `main.go`. After this step the
  public Compose path works end to end, provided cu02's trust step is done
  and `docker.update_preview` has run. Admin guide and handbook pages.

### cu05 Standalone definitions (P2-03, split out)

- **Rules:** R1, R3, R4, R6 for standalone containers.
- **Paths:** `internal/executions/actions/`, `internal/executions/batchplan.go`,
  `internal/web/ui/`; protected: `internal/executor/`, `proto/`, `cmd/nebula/`,
  `test/security/`.
- **Protected: yes** for the executor side.
- **Contracts and RPCs:**
  - `Put`, `Remove` and `ListContainerDefinition` (admin only, list metadata
    only). The definition is a vault secret `container.<id>.definition`, and
    its version and digest are bound as `definition_version`.
  - `docker.update` 1.0.0 and `docker.rollback` 1.0.0 (durable,
    `reconcile-first`, batch only), same phases as cu02. The executor adds the
    definition as a run secret, delivered over the existing tmpfs secret
    channel (`internal/hostrun/secrets.go`, 64 KiB). The planner sees no
    secret slot, which is what keeps batches possible (G8).
  - Format: see Q7. The definition must exactly name the container and may
    leave only the image to NOS.
- **Risk classes:** as cu01; a container without a definition is unavailable.
- **Tests:** `TestStandaloneWithoutDefinitionUnavailable`,
  `TestNoInspectReconstruction` (no inspect field reaches a create argument),
  definition absent from results, logs, audit and errors; rejected definition
  shapes; definition changed after approval refused; injection through the
  definition.
- **Real install:** the operator supplies a definition per container with the
  vault unlocked. Without that, nothing changes.

### cu06 Private registry transfer (P2-04, split out, gated)

**Do not start before Q6 is answered.** The ADR requires a reviewed profile
before enablement.

- **Rules:** R7, R5 (registry credential), R4.
- **Paths:** protected: `internal/executor/`, `cmd/nebula-executor/`,
  `proto/`, `docs/threat-model.md`, `.github/protected-paths.txt`,
  `test/security/`; a new package `internal/registrypull/` beside
  `internal/registrymeta/`, whose metadata client stays unable to fetch blobs.
  **That package holds credentials and must be added to the protected list by
  a maintainer.**
- **Protected: yes.**
- **Contract (recommended profile, Q6):** the executor fetches the manifest
  and blobs of the approved digest with the vault credential, verifies every
  digest and size, and streams an image archive over the authenticated SSH
  session into `docker load` on the target. The target gets image bytes, no
  credential and no token. The registry record digest, credential ID and
  version are bound in `registry` and rechecked around the transfer, with the
  same Lock, rotation and expiry rules as `ReadPrivateRegistry`. `docker
  load` does not set repository digests, so verification needs its own
  defined evidence, tested per image store (classic and containerd).
- **Risk classes:** unchanged. A private image is not a separate class.
- **Tests:** credential never on the host, in args, env, results or logs;
  wrong blob digest; oversize manifest or blob; out-of-scope repository;
  redirect; Lock, rotation and expiry during the transfer; no `docker login`
  and no `X-Registry-Auth`; both image stores.
- **Real install:** `SetRegistryReadAuthorizer` has no production caller
  (G13), so a read-grant profile and the call in `cmd/nebula-executor` are
  required first, together with a server caller for `ReadPrivateRegistry`.
  Also needed: executor egress to each registry, and bounded executor disk or
  a streaming path. The threat model gets a line for the new data flow.

## Non-goals

From the ADR and spec 11:

- **Private registry auth never leaves the executor:** no `docker login`, no
  Docker config on the host, no bearer token or `X-Registry-Auth` to the host,
  nothing to the server or collector.
- **No unapproved retries, no automatic rollback, no pruning.** A failed or
  uncertain member stays stopped. Cleanup never deletes a retained image, and
  this plan adds no cleanup at all.
- **No undoing of volume or database migrations.** Image rollback restores an
  image and its configuration, nothing else. Without a declared recovery plan
  rollback is unavailable.
- **No reconstruction from `docker inspect`.** Its sanitized subset cannot
  reproduce env, secrets, devices, capabilities or networking.
- **No CRITICAL variant,** and no path that lowers a floor to get one through.
- **No unattended mutation:** no schedules or read grants over pulls, updates
  or rollback; no implicit major upgrades, project-wide updates or descendants.
- **No update of digest-pinned images:** they stay pinned with advisory
  candidates only.
- **CVE findings are advisory** and never authorize an update.

Out of scope for this plan (no ADR rule; stated so that nobody assumes them):

- Editing operator Compose files; building images (`build:` services are
  unsupported); Swarm or Kubernetes.
- The stable-version pipeline (G12): tags are typed explicitly until Q10 is
  decided.

## Rule coverage

| Rule | cu01 | cu02 | cu03 | cu04 | cu05 | cu06 |
| --- | --- | --- | --- | --- | --- | --- |
| R1 pinned pull, retain, same config | | x | | | x | |
| R2 Compose freeze and override | x | x | | | | |
| R3 standalone definition | | | | | x | |
| R4 secrets stay out | | x | | x | x | x |
| R5 binding | x | | | | | x |
| R6 recheck and verify | x | x | | | x | |
| R7 private transfer | | | | | | x |
| R8 risk and CRITICAL refusal | x | x | x | x | x | |
| R9 retention window | | x | x | | | |
| R10 rollback and postchecks | | | x | x | | |
| R11 stop and reconcile | | x | x | | | |
| R12 volume limitation | | | x | x | | |
| R13 new incarnation | | x | x | x | | |
| R14 tree controls | | | | x | | |

## Order and release

cu01 → cu02 → cu03 → cu04, each its own PR with a maintainer review, because
all but cu04 touch protected paths. cu05 and cu06 follow cu03 in any order and
extend cu04's reasons list. Release after cu04, not before: cu02 removes the
old host-page link. Protected documents (`docs/spec/`, `docs/adr/`,
`docs/threat-model.md`) are changed by a maintainer, and the answers below may
need that.

## Open questions for Axel

Each has a recommendation; none is decided. "Blocks" names the first step that
cannot start without the answer.

1. **Batch or classic stages? Blocks cu01.** ADR line 449 says to reuse
   `internal/executions/stages.go` and the executor stage engine; the plan
   uses `PlanStages` for the layout but the batch rollout engine for running,
   because classic permits hold one parameter set (G7). *Recommendation:*
   accept batches and record it as an ADR note. Classic stages would need
   per-host parameters in the classic permit, a larger change.
2. **Where does the digest override live, and what about drift? Blocks cu02.**
   If an operator later runs a plain `docker compose up -d`, the service goes
   back to what the files say. *Recommendation:* a NOS-owned root-only file per
   project, kept and named in Compose's `config_files` label, never in the
   operator's directory; treat later differences as a changed configuration
   that refuses the next update. Also confirm the `pinned` handling: NOS
   override means "updatable", an operator pin stays pinned.
3. **Does `docker.compose_update` 1.0.0 go away? Blocks cu02.** Only one version
   per built-in ID exists, so 2.0.0 replaces it, and the unbound manual update
   of spec 11 ends. Today it also uses the host's own Docker login.
   *Recommendation:* replace it. Run the v2 pull with an empty `DOCKER_CONFIG`,
   so public-only stays true until cu06, and accept that hosts relying on an
   operator login wait for cu06.
4. **Does "executor rechecks before dispatch" allow the precheck inside the
   approved script? Blocks cu02.** The plan runs it as phase 1 of the bound,
   trusted artifact as root, immediately before the mutation, and the executor
   reads the typed result. That leaves no gap between check and change, but
   the executor itself does not read the host first. *Recommendation:* accept;
   the executor still rechecks trust, risk, pin, credentials, Lock and expiry.
5. **What exactly is the configuration digest? Blocks cu02.** It must cover
   what secrets may be in (env, compose files, `.env`), and even a digest can
   confirm a guessed low-entropy secret. *Recommendation:* hash on the host
   over the complete container config and the bytes of the config files, keyed
   with a root-only random per-host salt that never leaves the host. The salt
   makes a LOW read create one small file; please confirm that is acceptable.
6. **Which private transfer profile? Blocks cu06.** Options: (a) executor
   fetches, `docker load` over SSH (recommended: no credential or token on the
   host, no sshd change); (b) an executor-side authenticating proxy over an
   SSH reverse tunnel (the daemon verifies digests itself, but it needs
   forwarding enabled on every host and yields a rewritten image name). A
   credential handed to the engine is excluded by the ADR. Who signs off the
   review?
7. **Standalone definition format? Blocks cu05.** *Recommendation:* an exact
   argument list for `docker create`, which NOS completes only with the image.
   No shell, no template, no inspect input. Alternative: a one-service Compose
   document, which reuses cu02 but changes the container's labels.
8. **Recovery plan: where, and is "stateless" allowed? Blocks cu03.**
   *Recommendation:* an admin-set executor record per project or container,
   with an explicit "no persistent data" declaration by the operator, never
   inferred from a missing volume.
9. **Rollback window and a missing image. Blocks cu03.** Is 7 days fixed or
   per-install? If an operator pruned the retained image, is rollback
   unavailable or may it pull by digest? *Recommendation:* fixed at 7 days for
   the first release; unavailable, since it is the simpler and more honest
   state.
10. **Stable-tag wiring (G12): part of this work? Does not block.** The ADR's
    server-side lookup is not wired, so the chart cannot suggest a version.
    *Recommendation:* a separate job; typed tags resolved by preview are enough
    for the HIGH path.
11. **May the executor import `internal/executions/dockerhost`? Blocks cu03.**
    It would be the first import of that tree, although the package uses only
    the standard library. Alternative: move the judge to a new protected
    package. *Recommendation:* the judge decides rollout outcomes, so move it
    to a small package added to the protected list.
