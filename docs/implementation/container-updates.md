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
  differ, and it needs no parser for server-supplied parameters. Every value a
  script needs is therefore a binding field, for rollback too (`running_reference`
  per target, the `rollback` block per image). Nothing reaches a script any
  other way.
- **Decision 4 (default):** the risk rule is Go code in a protected path,
  derived from the binding by the executor. It is never trusted from the
  proposal and never left to a shell script. The script's only part is to prove
  the binding's `old_tag` against the running container (cu02 phase 1).
- **Decision 5 (default):** container mutations run only as batch members. The
  executor refuses these action IDs on the classic propose and run paths, and
  it picks the durable transport from the frozen action ID. The server cannot
  choose attached.

## Risk classes

| Case | Base | Result after floors |
| --- | --- | --- |
| Same-tag digest refresh, update or rollback | MEDIUM | MEDIUM on a recorded host with a trusted artifact; approval by presence |
| Tag or version change on any image of the member, or tag reversal on rollback | HIGH | HIGH; user verification, manual stage gates (`internal/permit/batch/batch.go:237`), CLI when hardened |
| Unrecorded host or untrusted artifact | as above | At least HIGH (`internal/riskpolicy/riskpolicy.go:45-49`) |
| Any floor reaches CRITICAL: recorded host, scanner, linked-host floor | none | **Refused**, at proposal and again at approval and claim. No separate approval path and no downgrade |
| Digest-pinned image, unsupported or incomplete definition, unknown digest | none | **Unavailable**: no proposal is offered (ADR line 363, R3) |

`docker.update_preview` (cu02) is LOW and read-only: its script writes nothing
on the host, not even a salt file, and it does not authorize anything (ADR
lines 423 and 439: LOW means read-only). The job directory of its durable
transport is the only file activity, the same for every durable job. That
Compose itself writes nothing either depends on Q23.
`docker.update_prepare` (cu02) creates the per-host
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
  - `kind` (update or rollback), `form` (compose or standalone), both fixed by
    the action ID (see the action rule below);
  - `images`: sorted by `service`, exactly one entry per recreated service
    (standalone: one entry with an empty `service`). Two services with the same
    image have two entries, so nothing depends on how a project shares images.
    Each entry is:
    - `service`, `repository`, `platform`, `old_tag`, `new_tag`. `repository`
      is in the canonical form of `canonical.ParseImageReference` (below);
    - `old_digests`: sorted, at least one, the digests the local image lists
      for `repository` at preview time. A classic store lists only the digest
      the image was pulled by, so this may be an index digest, a platform
      digest or both (see Q17);
    - update only, `new_index_digest` and `new_platform_digest`: the platform
      digest is required, the index digest is empty only for an image without
      an index;
    - update only, `old_image_id`: the local image ID cu02 compares in phase 1
      and retains in phase 4;
    - `policy_version`, `policy_digest`, `major_change`: required on an entry
      whose tags differ and refused on a same-tag entry (R8, spec v23-11-09).
      `policy_version` is `registrymeta.Result.PolicyVersion`; `policy_digest`
      is the SHA-256 of the canonical `registrymeta.Policy`, so that two
      policies cannot share a version string unnoticed (see Q13);
    - rollback only, `rollback`: `{prior_image_id, retained_tag,
      retained_reference}`, copied from the row (cu03). The digest fields above
      describe the update's result; these three describe what the rollback
      returns to.
  - `targets`: sorted `{service, container_id, container_name, image_id,
    running_reference, configuration_digest}`, full 64-hex IDs only.
    `running_reference` is the container's `Config.Image`, byte for byte. Every
    target's `service` has an `images` entry. On `kind=update` every entry has
    at least one target, each target's `image_id` equals its entry's
    `old_image_id`, and its `running_reference` parses to the entry's
    `repository` and `old_tag`. Replicas of one service on different images are
    therefore not a valid update (see [What phase 2 does not support](#what-phase-2-does-not-support)).
    On `kind=rollback` `image_id` and `running_reference` come from the row per
    target, because a partly recreated project has mixed replicas, and one
    `old_tag` per entry could not express them. There an entry may have no
    target, but only when the row records every container of that service as
    `missing` (cu03);
  - compose only, `source_digest` (see Q5): what the operator's files render to
    at preview time, unchanged by the image change. It shows that the files did
    not change since the preview. It does **not** show that the containers were
    created from them: cu02's phase 1 proves that on the host (Q21). It is
    refused on a standalone member, which binds `definition_id` and
    `definition_version` instead (Q20);
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
  - `definition_id`, `definition_version` (cu05), `rollback_of` and
    `recovery_plan_digest` (cu03), each required exactly where those steps say
    and refused elsewhere.
- **Limits:** named constants beside the validation:
  `maxContainerUpdateImages = 20` and `maxContainerUpdateContainers = 50` over
  targets and dependency containers together. The existing
  `canonical.MaxParametersSize` (64 KiB) and `MaxBatchSize` (1 MiB) still apply.
  A plan over any of them is refused; the operator splits it into more
  batches, or the unit is shown as unavailable if one member alone is too large.
- **Validity:** an entry with equal tags whose `new_platform_digest` or
  `new_index_digest` is in `old_digests` is refused, since it would recreate
  for nothing. A service whose image does not change belongs in `dependencies`,
  or nowhere.
- **Functions:**
  - `canonical.ContainerUpdateFloor`: MEDIUM when **every** entry has equal
    tags, otherwise HIGH. One tag change makes the whole member HIGH.
  - `canonical.ContainerUpdateParameters`: the rendering of Decision 3. It
    covers `running_reference` and the `rollback` block.
  - `canonical.ParseImageReference`: the single normalization rule, so no
    script has its own. The canonical repository keeps the registry host:
    `nginx`, `library/nginx` and `docker.io/nginx` all give
    `docker.io/library/nginx`, `index.docker.io` gives `docker.io`, and a first
    path part with `.` or `:`, or `localhost`, is a registry host, as in
    `docker_check_updates.sh`. A reference without a tag has the implicit tag
    `latest`, so `image: nginx` matches `old_tag=latest`. `repo:tag@digest`
    gives that repository and tag; cu02's phase 1 then decides whether the digest
    is the NOS override or an operator pin. `repo@digest` without a tag, a bare
    image ID and any other form are not comparable and are refused.
  - `registrymeta.CompareTags(old, new, policy)`: reuses the tag parser of
    `stable.go` and reports major change, variant change or not comparable.
- **Action rule:** `docker.update` leaves the `BatchContainer` list at
  `internal/canonical/batch.go:308`, and `normalizeBatchMember` gets one fixed
  table:

  | Action | Required `kind` | Required `form` |
  | --- | --- | --- |
  | `docker.compose_update` | update | compose |
  | `docker.compose_rollback` | rollback | compose |
  | `docker.update` | update | standalone |
  | `docker.rollback` | rollback | standalone |

  A member of these four actions must carry `container_update` with exactly
  these values, and `container` is refused on it. `container_update` on any other
  action is refused. This validation runs whenever a batch is parsed, so leaving
  the field out or naming another kind cannot skip Decision 3's rendering or
  Evaluate's row, window and recovery plan checks. The table is complete in cu01,
  before any of the rollback actions exists. It does not touch `docker.compose_update`
  1.0.0, which is not a batch member until cu02 (`batchExcludedActions`).
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
  keys on the action ID, so a module cannot pick the name to avoid it. cu01's
  list is `docker.update`, `docker.rollback` and `docker.compose_rollback`, none
  of which exists yet. `docker.compose_update` joins the list in **cu02**, in the
  change that replaces 1.0.0: until then it stays a classic-only action, and the
  host page keeps its link.
- **Limit of the floor:** `ContainerUpdateFloor` trusts the binding's tags. They
  come from a server-side preview, so a forged `old_tag` with a matching forged
  `running_reference` could turn a tag change into MEDIUM here. Evaluate cannot
  see the host; cu02's phase 1 closes this by comparing `running_reference` with
  the running container before anything changes.
- **Risk classes:** defines MEDIUM, HIGH and the CRITICAL refusal. Nothing can
  run yet.
- **Tests:**
  - canonical: table of malformed bindings (digest shape, short ID, leading
    `-` in a name, duplicate target, unsorted targets, unsorted images, a target
    without an image entry, an entry without a target on `kind=update`, a second
    entry for one service, a no-op entry, empty `old_digests`, policy missing on
    a tag change, policy set on a same-tag entry, a `rollback` block on an update,
    an update without `new_platform_digest`, `source_digest` on a standalone
    member, malformed dependency relation, a service in both `images` and
    `dependencies`, each limit exceeded, unknown key); a mutation of any bound
    field in any image entry, target or dependency changes the digest; new
    golden files, and the existing ones byte-identical.
  - `TestUpdateRefusesMixedReplicaImages` (a target's `image_id` differs from its
    entry's `old_image_id`), `TestRunningReferenceMustMatchOldTag`,
    `TestRollbackEntryMayHaveNoTarget` (canonical allows it on `kind=rollback`
    only; Evaluate's check against the row is in cu03).
  - action rule: `TestContainerActionRequiresUpdateBinding` (each of the four
    IDs, with no binding and with `container` instead),
    `TestContainerActionFixesKindAndForm` (all twelve wrong combinations),
    `TestUpdateBindingRefusedOnOtherAction`.
  - unit: `ContainerUpdateFloor` is HIGH when one of several entries changes its
    tag; `CompareTags` table for major, minor, variant, date and non-version tags;
    `TestParseImageReference`, a table with `nginx` (implicit `latest`),
    `nginx:1.27`, `library/nginx`, `docker.io/nginx:1`, `index.docker.io/a/b:1`,
    `ghcr.io/a/b:1`, `localhost:5000/a:1`, `repo:tag@sha256:…`, and the refused
    `repo@sha256:…`, bare image ID, uppercase path and empty tag.
  - security (`test/security`): `TestContainerTagChangeBelowHighRefused`
    (server labels a tag change MEDIUM), `TestContainerBindingDiffersFromParameters`,
    `TestContainerCriticalFloorRefusedNotDowngraded` at proposal, approval and
    claim, `TestContainerCriticalAfterApprovalStopsMember`,
    `TestContainerMutationRefusedOnClassicPath` (for `docker.update` here; cu02
    extends it to `docker.compose_update`),
    `TestComposeUpdateV1StaysOnClassicPath` (removed by cu02 together with 1.0.0),
    `TestRestartMemberCannotCarryUpdateBinding`,
    `TestContainerPolicyMismatchRefused`, `TestContainerPolicyChangedAfterApproval`,
    `TestImplicitMajorUpgradeRefused`, `TestContainerVariantChangeRefused`,
    `TestRollbackMemberWithoutBindingRefused` and
    `TestRollbackMemberWithKindUpdateRefused` (each for `docker.rollback` and
    `docker.compose_rollback`).
- **Real install:** nothing to enable. No action on the new list exists yet, and
  `docker.compose_update` 1.0.0 with the host page's update link works as before
  until cu02. `nebula batch review` prints every new field, per image and per
  container, because the hardened path reads the plan there.

### cu02 Pinned Compose recreate as a durable member (P2-03 executor)

- **Rules:** R1, R2, R4, R6, R8 (enforcement on the host), R9 (the retained
  image), R13 (emission), and the running half of R11. **Gaps:** G1, G5a (the
  comparison with the host), G7, G8, G9, G11.
- **Paths:** `internal/executions/actions/` and its scripts,
  `internal/executions/dockerhost/`, `internal/executions/batchplan.go`,
  `internal/executions/batchoutcome.go`, `cmd/nebula-server/batchrun.go`,
  `web/templates/host.html`; protected: `internal/executor/`,
  `internal/executor/dispatch/`, `internal/executordb/` (migration 0020:
  `runs.member_id` and `runs.action_id`), `internal/hostrun/` (the job probe of
  the hold rule), `proto/`, `test/security/`, `test/integration/`.
- **Protected: yes** for the executor, executordb, hostrun, proto and test
  parts; the actions and planner are not protected.
- **Output of all new scripts (R4):** `docker compose` and `docker pull` can
  echo interpolated values on stderr, and stderr is the job log that is returned
  and displayed. So every `docker` and `docker compose` call in these scripts
  sends stderr to `/dev/null`, and stdout too unless the script parses it; none
  uses `>&2` as 1.0.0 does. The log holds fixed phase lines only. A failure is a
  typed reason plus an exit code in the result. The cost is that the Compose
  error text stays on the host: the operator reruns the command there.
- **Contracts and RPCs:**
  - `docker.update_prepare` 1.0.0 (MEDIUM, durable, 2 min, not read-only, no
    parameters, not a container mutation under Decision 5): creates the per-host
    salt of Q5 as a root-only file if it is absent and never replaces an
    existing one. It touches no container. Result format
    `docker-update-prepare-v1` reports `created` or `present`, never the salt.
  - `docker.update_preview` 1.0.0 (LOW, read-only, **durable**, 5 min, classic
    path, not a batch member), one parameter `target_tags` that may be empty. It
    is durable because reading the salt and the config files needs root, as
    durable jobs do, and because only a durable run has a `runs` row that Resolve
    can read (cu03, Q19). Its script writes nothing on the host. For the host's
    containers it reports the identity and image facts a binding needs: full ID,
    name, run state, Compose project, service, working directory and config file
    labels, the file's scale per service, the dependency sets, per-container
    `configuration_digest`, per-unit `source_digest`, image ID, the running
    reference verbatim, repository digests, platform, and for a requested tag the
    index and platform digests, resolved anonymously on the host with the same
    request as `docker.check_updates`, plus a GET of the index to find the
    platform entry. A unit that cannot be bound carries its reason (see
    [What phase 2 does not support](#what-phase-2-does-not-support)). It never
    returns env, command line or other label values. Without a salt it reports
    `prepare_required` and no digests, and those units are unavailable. Without
    a required host tool it reports `tooling_missing` (Q18). Result format
    `docker-update-preview-v1`, with a strict parser and a fuzz target. Preview
    checks override drift as well as applied configuration;
    `override_drift` takes precedence over `config_not_applied` if both fail
    (Q27). Either reason disables an update but does not discard complete
    identity facts needed by Resolve. A limit still discards the whole unit.

    **Limits**, named constants initially in `internal/executions/dockerhost/`
    and moved with the parsers in cu03 (Q11), enforced by
    the script and again by the parser, because everything here comes from a
    hostile host and runs as root on label-supplied paths:

    | Constant | Value | Over the limit |
    | --- | --- | --- |
    | `maxPreviewContainers` | 200 | Units not reached are reported `truncated`, so unavailable |
    | `maxPreviewProjects` | 50 | Same |
    | `maxPreviewTargetTags` | 20 | Refused at proposal |
    | `maxPreviewConfigFiles` | 16, each a regular file of at most 1 MiB | Unit unsupported |
    | `maxPreviewComposeConfigBytes` | 4 MiB of `docker compose config` output | Unit unsupported |
    | `maxPreviewIndexBytes` | 256 KiB per manifest or index GET | `tag_unresolved` |
    | `maxPreviewResultBytes` | 768 KiB, below the 1 MiB `hostrun.MaxResult` | Remaining units are `truncated` |
    | `maxRunRegistryRequests` | 120 per run, one at a time and at least 1 second apart per registry (Q22) | `tag_unresolved` for the rest; stops at the first 429 |

    Each external call has its own bound (`timeout 30` for Compose and Docker,
    the `curl` limits of `docker_check_updates.sh`). These bounds alone do not fit
    the 5-minute job: even one 30-second call per project totals 25 minutes for
    50 projects, and one unit can need several calls and registry requests.
    *Recommendation, pending Q24:* keep the existing
    `maxPreviewWallClock = 4 * time.Minute`, but check its remaining time
    before every external call and registry spacing wait, including inside a
    started unit. Limit each call to the smaller of its own bound and that
    remaining time, including any kill grace; start none without time to stop
    it. On expiry, discard the unfinished unit's facts and report it and the
    remaining units as `truncated`. This reserves one minute for a bounded
    result within the 5-minute job; stopping only between units cannot do so.
    Every Compose call runs with the remote loaders switched off, and the limits
    above cover the label-named files only (Q23). A label-supplied path must be
    absolute, and the content of those files never leaves the host. A unit cut off by a limit is reported without
    facts, never half: a partial dependency set must not become a binding.
  - `docker.compose_update` 2.0.0 (durable, `reconcile-first`, 30 min, batch
    only), result `compose-update-v2`; `compose-update-v1` stays parseable for
    history. Phases, each stopping on failure except where noted:
    1. **Precheck, nothing changed yet.** Each check is a typed reason with
       exit 10:
       - labels match the bound project and config identities, and
         `source_digest` recomputes to the bound value;
       - no service uses `build:`;
       - the containers of each frozen service are exactly the bound targets,
         by full ID and name, each with its bound `image_id` and
         `configuration_digest`;
       - every target's state is `running` (`target_not_running`), and for each
         frozen service the number of targets equals the file's scale, the value
         `up` will converge to (`scale_mismatch`);
       - `old_tag`: every target's `Config.Image` equals its bound
         `running_reference`, byte for byte. Evaluate has proved that this
         reference parses to the entry's `repository` and `old_tag`, so the
         script normalizes nothing. A forged `old_tag` stops here (reason
         `old_tag_mismatch`), so nothing runs under a risk class derived from it;
       - a reference with a digest is accepted only as the NOS override: the
         `config_files` label names it and its entry for that service equals the
         reference. Otherwise it is an operator pin (`digest_pinned`);
       - **drift (Q2):** when a NOS override file exists for the project, each
         frozen service is one of two cases, otherwise `override_drift`. With an
         override entry, the targets' `config_files` label names the override and
         the entry equals their reference; a plain `docker compose up -d` after
         an update stops here. With no entry, the label does not name the
         override and the reference has no digest: the service never used the
         override, or the operator removed its entry (Q2);
       - **applied configuration (Q21):** `docker compose ... config --hash
         <frozen services>`, with the arguments of phase 5 and the override as it
         is now, must print for each frozen service the value of the
         `com.docker.compose.config-hash` label on every target. A difference, a
         service missing from the output or a failed call is
         `config_not_applied`. Neither call passes `--env-file` or `--profile`,
         and the job does not run in an operator's shell, so a project brought up
         with any of these stops here, as does a pending file edit. The hash is
         unkeyed (Q5), so it is compared on the host only and appears in no
         result, snapshot or log;
       - no frozen service publishes a port with a Docker-chosen host port
         (`ephemeral_port`), read from the same `docker compose config`;
       - the image `old_image_id` still lists every digest of `old_digests`;
       - the dependency closure, recomputed as in the preview, equals the bound
         `dependencies`, and each dependency container has its bound ID, name
         and `configuration_digest`.

       As its last step, after these checks passed, phase 1 captures the
       **baseline** with the same code and format as the after-snapshot of phase
       6, for every target and dependency container. The result carries it from
       here on, so `not_recreated` and failed runs have it too. A container whose
       entry exceeds `maxSnapshotContainerBytes` (8 KiB) stops the member
       (`snapshot_too_large`); with `maxContainerUpdateContainers` that keeps both
       snapshots within `hostrun.MaxResult`.
    2. **Resolve, nothing changed yet.** For **every** entry, resolve
       `repository:new_tag` with the preview's anonymous request and compare the
       index and platform digests with the entry. A difference is exit 10 with
       `tag_moved`; no answer, an unusable one or a used-up
       `maxRunRegistryRequests` (Q22) is exit 10 with `tag_unresolved` (unknown
       is not success). All entries are resolved before the first pull. This is
       what makes a moved tag stop before any change; the digest pull alone would
       hide it.
    3. **Pull.** `docker pull repository@new_platform_digest` for each distinct
       digest, then verify for each entry that the image lists that digest and
       has the bound platform. Each pull runs with `DOCKER_CONFIG` set to an empty
       directory inside `NEBULA_RUN_DIR`, so the host's Docker login cannot serve
       it (R7, Q3); only the pull, because the Compose plugin may be found through
       that variable too. It never pulls by tag and never runs `docker compose
       pull`. One failed image stops the member; nothing was recreated yet, and
       images already pulled stay as harmless unreferenced images.
    4. **Retain.** For each entry `docker tag <old_image_id>
       nos-retained:<execution-id>-<entry-index>`, then verify that the tag
       resolves to `old_image_id`. A failure stops before any recreate (exit 10,
       `retain_failed`). These tags are new names only. No other local tag is
       created or moved, in particular **not** `new_tag`: a local retag would
       change what an unfrozen container of that tag gets on its next recreate,
       and it would stay moved after a failed phase 5 (R2).
    5. **Recreate.** Atomically update the NOS override (Q2): set `image:
       repository:new_tag@new_platform_digest` for each frozen service and leave
       other services' entries as they are. Then `docker compose ... -f
       <operator files> -f <override> up -d --no-deps --no-build --pull never
       <frozen services>`. There is no `--scale`: phase 1 proved that each frozen
       service runs exactly the file's scale, so `up` keeps every replica and
       starts none that was stopped.
    6. **After-snapshot.** It runs whenever phase 5 was reached, **also when `up`
       failed**: bounded health wait, then for every container of the frozen
       services and of `dependencies` the ID, name, service, replica number,
       state, start time, health, ports, mounts, networks, image ID, running
       reference and `configuration_digest`. The result states the last phase
       reached and `up_exit`. Exit status covers pull and up only; the verdict
       comes in cu03.
  - `docker.check_updates` 1.1.0: stopped containers, platform-manifest
    comparison, and a reference `repo:tag@digest` reads as updatable with that
    tag when the container's `config_files` label names the NOS override, and
    as `pinned` otherwise (see Q2). The comparison follows Q17 and needs no bound
    old digest: `current` if the tag's index or platform digest is among the
    local digests; otherwise one bounded GET of each local digest, and `current`
    if it is an index whose entry for the platform is the tag's platform digest,
    so an index change on another architecture is not an update. A different
    entry or a local platform digest is `update`; no answer is `unknown` (ADR
    line 361). Those GETs count against `maxRunRegistryRequests` like every HEAD
    and token request (spec v23-11-02 and v23-11-06, Q22), and images not reached
    are `unknown`. As recommended in Q24, use
    `maxCheckUpdatesWallClock = 4 * time.Minute` inside the 5-minute job, with
    the same remaining-time checks on every call and spacing wait as preview.
    An unfinished comparison and all unreached images are `unknown`, with time
    left to return the result. The request cap alone gives no such bound.
    The 50-image and 64-KiB caps stay. Fixes G11.
  - `InspectBindings` gets a sibling `UpdateBindings` over the latest preview,
    at most `maxContainerBindingAge` old. It fills `images`, `targets`,
    `dependencies` and `source_digest`, and the policy values of Q13, and it
    refuses a unit that carries a reason or was truncated. Compose leaves
    `batchExcludedActions`, and `docker.compose_update` joins the list that is
    refused on the classic path (cu01), which ends 1.0.0's manual path (Q3).
  - **Timeouts:** `docker.compose_update`, `docker.compose_rollback`,
    `docker.update` and `docker.rollback` all use one named
    `containerMutationTimeout = 30 * time.Minute`, the value
    `batchBusyDurableWait` is derived from. Inside it each phase has a named
    budget (recommendations, pending Q25), so a hung call before phase 6 ends
    in a typed stop and leaves time for phase 6, instead of ending in
    `RuntimeMaxSec` with no result:

    | Constant | Value | Covers | When it runs out |
    | --- | --- | --- | --- |
    | `mutationCheckBudget` | 3 min | Phases 1 and 2 | Exit 10, `budget_exceeded` in phase 1 and `tag_unresolved` in phase 2; nothing changed |
    | `mutationPullBudget` | 12 min | All pulls of phase 3 | Exit 10, `pull_timeout`; nothing recreated |
    | `mutationRetainBudget` | 1 min | Phase 4 | Exit 10, `retain_failed` |
    | `mutationUpBudget` | 8 min | `up` in phase 5 | Preserve raw `up_exit` (timeout can return 124 or 137 after SIGKILL), reason `up_timeout` on timeout; phase 6 still runs |
    | `mutationSnapshotBudget` | 5 min | Phase 6, including the 3-minute `mutationHealthWait` | The after-snapshot is missing, so the row is `uncertain` |

    Every call runs under `timeout -k 10`, at most 30 seconds outside pulls
    and `up`, shortened to leave its kill grace inside the remaining phase
    budget; no call starts without that room. The five budgets total 29
    minutes (phases 1 and 2 share 3 minutes), leaving one minute for result
    handling within the 30-minute job. Grace must be charged per call, not
    added for each call after the budget. Preserve the raw exit status and
    classify an expired `up` as `up_timeout` whether it obeys SIGTERM or
    ignores SIGTERM and needs SIGKILL; an arbitrary non-timeout exit 137
    alone does not prove timeout. A killed `up` may leave a project partly
    recreated; phase 6 still records that as for any failed `up`. Rollback
    and cu05's actions use the same budgets for the phases they run.
  - **Durable batch members:** the executor picks `hostrun.Dispatch` for the
    frozen action IDs of Decision 5. `RunBatchMember` returns once the job is
    dispatched, and the server follows it through a new
    `GetBatchMemberRun` (server, admin; added to `roles.go`) instead of
    holding one RPC open. It looks the run up by batch digest and member ID
    through `runs.member_id`, which survives a restart of either side, and
    reports `finished` only when the run is finished and, from cu03 on, judged.
    After a server restart `ReconcileBatches` asks `GetBatchMemberRun` before it
    marks a dispatched durable member unknown, and an open run stays followed.
  - **One member at a time (R11):** the server keeps the member `dispatched`
    until `GetBatchMemberRun` gives its final outcome. `runOnce` and `runBatch`
    already skip a batch with a dispatched member (`batchrun.go:143,192`), so the
    next member is offered only after the previous one has ended, and a failed
    update stops the rollout before the next host starts. A container batch is
    strictly serial.
  - **Batch lifetime:** `batchplan.go:292` assumes `parallelHosts` hosts at once,
    which is wrong for this serial runner: 8 members of 30 minutes would get 125
    minutes against 240 worst case. For a stage with `container_update` members
    the planner counts one round per member, so that case gets 305 minutes.
    Other batches keep their formula, and their digests are unchanged. The
    existing 24-hour check then refuses a plan of more than about 45 such
    members; the operator splits it. Time spent at a manual gate is not
    planned, as for all batches: a member reached after expiry ends not executed
    and changes nothing. A running job is not cut off by expiry.
  - **Where an outcome goes:** the executor's finished run is the record, not the
    rollout. Rollout state and `batchExecIndex` are memory-only and cleared by
    Lock and restart (ADR 0007 line 177, `internal/permit/batch/batch.go:555`).
    - While the permit lives, the reconciler calls the batch `RecordOutcome`
      with `runs.member_id`, and a run with no result counts as a failure for the
      stop rule (`permit.OutcomeOfClass`).
    - After Lock or an executor restart there is no rollout to tell, and that
      call is ignored by design. The outcome stays in `runs` (cu03: also in the
      row), and the server gets it through `GetBatchMemberRun`, records it in
      `batch_members` and applies its stop policy. The stop rule still holds,
      because the revoked permit cannot claim another member: the next offer is
      refused and the member ends not executed.
  - **Hold of a durable member's target (see Q15):** the hold starts at the
    reservation, as for attached members, and is persisted with a `durable`
    mark. `hostrun.RunVisible` cannot end it, because it counts only the SSH
    user's own processes and the job runs as root. The hold ends:
    - when reconciliation closes the run with a result read, or as not executed:
      the job is over;
    - when the run closes with **no result**, it does **not** end. That covers
      `unknown` (job directory gone, or host not checkable before the reconcile
      deadline), and `script_interrupted` and `execution_timeout`: the wrapper
      publishes `result.json` only at its end, and `hostrun.Remove` deletes the
      `.tmp`, so a killed job leaves nothing to read. Those two classes come from
      a dead wrapper PID, which does not prove that the script's own processes are
      gone. So the target stays held until a new `hostrun.DurableJobGone` probe
      (sudo, complete check of unit `nebula-job-<execution-id>`; an error counts
      as running) shows the unit gone, which after a reboot is the next pass. It
      uses the existing recheck and the
      `batchHoldMax` and `batch-holds rearm` path unchanged: re-arming frees
      nothing by itself. The reconcile deadline (job timeout plus 24 h) lies
      beyond `batchHoldMax` (24 h), so a host that stays away reaches `expired`
      first.
  - **Waiting for such a target:** the executor refuses with the new code
    `batch_host_busy_durable:`, whatever kind of member is asking, because the
    waiter cannot know what holds the target. For that code the server replaces
    the attempts limit with `batchBusyDurableWait = 45 * time.Minute` (the
    30-minute job timeout plus margin), measured on the injected clock from the
    first refusal, with the existing backoff. Past it, or past the permit
    expiry, the member ends not executed through `reportNotExecuted`, and the
    stop rule applies. A target held after an unknown run therefore stops the
    waiting rollout with nothing run, instead of waiting without end.
- **Risk classes:** enforces cu01. Update MEDIUM or HIGH, preview LOW, prepare
  MEDIUM, CRITICAL refused.
- **Tests:**
  - script tests with the fake host of `docker_test.go`, pinning the call
    order: changed ID, changed name, extra or missing replica, changed
    configuration digest, changed source digest, moved label, wrong `old_tag`,
    wrong current digest, moved tag, unanswered resolve, and a wrong pulled
    digest or platform on the **second** image each stop before any recreate;
    `TestComposeUpdateNeverPullsByTag`,
    `TestComposeUpdatePullsEveryImageByDigest`,
    `TestComposeUpdateTouchesOnlyFrozenServices`,
    `TestRetentionFailureStopsBeforeRecreate`,
    `TestComposeUpdateMovesNoLocalTag` (only `nos-retained` tags appear, also
    when phase 5 fails), `TestComposeUpdateAddsOnlyImageToOverride`,
    `TestDependencySetChangedRefused`, `TestDependencyContainerChangedRefused`,
    `TestFailedUpStillReportsAfterSnapshot`, `TestBaselineUsesAfterSnapshotFormat`,
    `TestBaselineInResultWhenStoppedBeforePull`; each row of
    [What phase 2 does not support](#what-phase-2-does-not-support) by its named
    test; no `down`, `rm -v`, `prune` or restart-only path; injection through
    names and paths; preview output never contains a planted env value;
    `TestPreviewWritesNothing` (a read-only fake host, with and without a salt);
    `TestPrepareKeepsExistingSalt`; `TestSourceDigestSurvivesUpdate` (equal before
    and after an image change and a NOS override);
    `TestConfigHashCheckUsesPhaseFiveArguments` (same files, no `--env-file`, no
    `--profile`), `TestConfigHashNeverLeavesHost`;
    `TestNeverUpdatedServiceBesideOverridePasses` (update `web`, then update
    `db`, which has no entry), `TestRemovedOverrideEntryPasses`,
    `TestNoEntryWithOverrideLabelIsDrift`;
    `TestComposeUpdatePullHasEmptyDockerConfig` (a fake `docker` records
    `DOCKER_CONFIG` and that the directory is empty).
  - log (R4): `TestComposeFailureLogHoldsNoEnvValue`, a table where a fake
    `docker compose config`, `pull` and `up` fail and print a planted env value
    on stdout and stderr: neither result nor log may hold it, for preview and
    update here and for rollback in cu03.
  - preview limits: `TestPreviewBoundsHostileHost`, a table with one case over
    each constant and no partial unit in the result;
    `TestPreviewOversizeIndexIsUnresolved`; `TestPreviewResultStaysUnderLimit` at
    the maximum of every field; `TestPreviewWallClockTruncatesRemainingUnits` (a
    fake host where every Compose call hangs until its timeout);
    `TestPreviewDeadlineInsideUnit` (several slow daemon calls and stalling
    registry requests in one unit, no partial facts, a result before 5 minutes);
    `TestPreviewRequestCapGivesTagUnresolved`.
  - phase 2 registry stops: `TestResolveRequestCapStopsBeforePull` and
    `TestResolve429StopsBeforePull` (including token requests in the count,
    no later request, pull, retain or recreate).
  - check_updates: `TestCheckUpdatesFirstUpdateListsIndex` (tag pull),
    `TestCheckUpdatesSecondUpdateListsPlatform` (digest pull),
    `TestIndexChangeOnOtherArchitectureIsCurrent`,
    `TestUnanswerableLocalDigestIsUnknown`, `TestCheckUpdatesRequestCapIsUnknown`
    (a used-up cap and a 429 both leave the remaining images `unknown`);
    `TestCheckUpdatesWallClockIsUnknown` (a stalling registry at curl's limit,
    deadline before the request cap, unfinished and remaining images `unknown`,
    a result before 5 minutes).
  - planner: `TestContainerBatchLifetimeCoversSerialMembers` (8 members of 30
    minutes get at least 305 minutes), `TestContainerBatchOverLifetimeRefused`,
    `TestContainerActionsShareMutationTimeout`,
    `TestMutationBudgetsFitTimeout` (their sum includes every call's `-k`
    grace and stays below `containerMutationTimeout`; scripts use the same values).
  - budgets: `TestHungPullStopsBeforeRecreate`,
    `TestHungUpStillReportsAfterSnapshot`, `TestHungPrecheckStopsWithTypedReason`,
    and for rollback in cu03 `TestHungRollbackUpStillReportsAfterSnapshot`;
    both hung-`up` tests cover SIGTERM exit 124 and SIGKILL exit 137, preserve
    `up_exit`, report `up_timeout` and still run phase 6.
  - parsers: bounds, malformed UTF-8, unsafe characters, fuzz.
  - executor: crash between intent and dispatch, lost session during dispatch,
    restart while the job runs (each reconciled and never redispatched);
    `TestDurableOutcomeReachesLiveRollout`,
    `TestDurableOutcomeAfterExecutorRestartReachesServer` (no rollout exists; the
    server records it and stops the batch), `TestLockedExecutorCannotClaimNextMember`,
    `TestNextMemberNotOfferedWhileDurableMemberRuns`,
    `TestServerCannotChooseAttachedForContainerMember`;
    target held past the old 16-minute limit; Lock during a running job;
    `TestRunVisibleCannotEndDurableHold`, `TestUnknownDurableRunKeepsTargetHeld`,
    `TestKilledDurableRunKeepsTargetHeldUntilGone` (for `script_interrupted` and
    `execution_timeout`), `TestRearmDoesNotFreeDurableHold`, `TestHoldEndsWhenDurableJobGone`,
    `TestBusyDurableTargetEndsWaiterNotExecuted` (at the new limit, with an
    attached waiter too); `TestServerRestartFollowsDurableMember`.
  - security: `TestContainerSubstitutionRefused`, `TestTagDriftRefused` (the
    registry answers another digest for `new_tag`; no pull, retain or `up`
    runs), `TestForgedOldTagStopsBeforePull` (a tag change labelled same-tag
    with a forged `old_tag`, approved at MEDIUM, stops in phase 1).
  - integration: real Docker and Compose, with a registry on loopback, on both
    image stores (classic and containerd), including that `--pull never` finds
    a `repo:tag@digest` reference (Q2), and a `depends_on` project.
    `TestConfigHashMatchesLabelAcrossUpdates`: `config --hash` equals the label
    before a first update, after it with the override in place, and after a
    rollback (Q21). `TestConfigHashCoverage` lists what the hash leaves out on
    the supported Compose versions.
    `TestRemoteIncludeRefused` proves remote loaders are disabled on those
    versions, with no network and no cache (Q23).
- **Real install:**
  - **`nebula artifact trust-builtins` must approve the new scripts**, or they
    stay at the HIGH floor. The server and executor must be upgraded together.
  - **`docker.update_prepare` must run once per host**, approved like any
    MEDIUM action, or preview reports `prepare_required` and updates stay
    unavailable.
  - Durable jobs and the preview need root (sudo) on the host. The Compose
    plugin, `curl` and `python3` must be present (Q18), otherwise preview reports
    `tooling_missing` and the update is unavailable.
  - The host page loses its unbound "update project" link in this step, not
    earlier. Do not release between cu02 and cu04, or the feature has no front
    end (see Q3).
- **Size note:** this is the largest step. Commit the durable member first; if
  review wants it smaller, that part becomes its own PR without changing any
  contract.

### cu03 Postchecks, retention and rollback (P2-04, public images)

- **Rules:** R4 (rollback's silent output), R8 (the reversed floor), R9, R10,
  R11, R12, R13. **Gaps:** G10,
  G14, G15.
- **Paths:** protected: `internal/executordb/` (migration 0021 and store),
  `internal/executor/`, `internal/canonical/`, `internal/permit/batch/`,
  `proto/`, `cmd/nebula/`, `test/security/`, `test/integration/`,
  `.github/protected-paths.txt`; a new package `internal/containerjudge/` (Q11);
  not protected: `internal/executions/dockerhost/`,
  `internal/executions/actions/`, `internal/executions/batchplan.go`.
  **That package decides rollout outcomes and must be added to the protected
  list by a maintainer.**
- **Protected: yes** for the executor side.
- **Contracts and RPCs:**
  - A pure `containerjudge.JudgeContainerUpdate(baseline, binding, after)` in the
    new protected package (Q11), which also takes over the two strict parsers the
    executor needs, for `compose-update-v2` and `docker-update-preview-v1`, from
    cu02's `internal/executions/dockerhost/`. The `maxPreview*` constants and
    other parser-enforced limits move with the parsers, next to the code
    enforcing them. Callers use the relocated parser limits, without a second
    Go definition; tests keep the scripts' limits in agreement (Q11). It is
    the before/after postflight of spec 11 v23-11-02, which the v1 script does
    today, over the snapshots of cu02's phases 1 and 6. Containers are matched by service
    and replica number, because IDs change. Per frozen service, against the
    baseline:
    - the same replica count, each `running`;
    - no health regression: `healthy` or `starting` before must be `healthy`
      after, including past the wait; no health check stays none; `unhealthy`
      before is no regression, and the page shows it;
    - the same published ports, the same mounts (type, source, destination,
      mode) and the same network names. A mapping with a Docker-chosen host port
      (`ports: "80"`) gets a new port on every recreate, so such a unit is
      unavailable (`ephemeral_port`) and the judge needs no rule of its own: a
      changed host port always fails;
    - the image of every replica lists the approved `new_platform_digest`.

    Each `dependencies` container keeps its ID and `configuration_digest`, has
    the same run state as in the baseline and no health regression; its start
    time may change only with `restart_on_update`. Unknown is not success: a
    missing baseline, a missing field or an unmatched container fails. The
    verdict of `compose-update-v1` is left as it is.
  - The **executor** judges when it finishes the run, on the run path and in the
    reconciler, before it records the outcome. A member is `OutcomeSucceeded`
    only with class success **and** a passing verdict; a failed or missing
    verdict is `OutcomeFailed`. On a pass it calls `RecordPostcheck` with the
    member's own `canonical.ContainerPostcheckHash(member_id)` (a SHA-256 over a
    fixed label and the member ID). `stagePostchecksOK` accepts a hash from any
    member of the stage (`rollout.go:186`), so a shared hash would prove nothing
    per member. The planner therefore lists one hash per member in
    `RequiredPostchecks`, and canonical validation requires exactly that set for
    a stage with `container_update` members; this needs no change to the rollout
    code, and the 100 members of a batch fit `MaxBatchBindings`. After Lock or
    restart `RecordPostcheck` is ignored like `RecordOutcome` (cu02), and the
    verdict stays in the row.
  - Canonical validation requires `failure_threshold` and
    `unreachable_threshold` of 0 for stages with `container_update` members,
    so any failure or unreachable member stops the rollout.
  - `executor.db` table `container_recreations`, one row per member run:
    - execution, batch digest, member ID, `kind`, `rollback_of`, host and key,
      form, project or name;
    - the bound `images`, each with its prior image ID, retained tag and
      `retained_reference` (`repository:old_tag@` the first digest of
      `old_digests`; any of them works, because the retained image lists it);
    - per container: service, name, ID, running reference and
      `configuration_digest` before and after, image ID before and after,
      replica number, and `recreated`, `unchanged` or `missing`;
    - `baseline`: the phase 1 snapshot, unchanged once stored; empty if no result
      was ever read;
    - `source_digest` (standalone: `definition_id` and `definition_version`),
      the bound `dependencies`, and the replica count per service before the
      update, all from the binding, so they exist from `intent` on;
    - `recreation_definition`: the executor-owned definition of R9 (see below);
    - verdict, state, window expiry.

    The row is written before dispatch and completed by the result or by
    reconciliation. A row still in `intent` whose run has finished is judged
    from the run's result on the next pass, and `GetBatchMemberRun` holds back
    `finished`, and with it the release of the result, until the row has left
    `intent`. Window constant `DefaultRollbackWindow = 7 * 24h`, with injected
    time; expiry is set once, when the row first leaves `intent`.
  - **States:**

    | State | Meaning | Rollback |
    | --- | --- | --- |
    | `intent` | Written; the run is not finished | Refused |
    | `not_recreated` | Stopped in phases 1 to 4, or resolved so; every container is as it was, but the override may differ (see Resolve, Q27) | Refused: nothing to undo |
    | `recreated` | Phase 6 passed and the verdict passed; only a run's own result reaches this state | Allowed |
    | `partial` | Phase 5 was reached, the after-snapshot exists, and `up` or the verdict failed; or Resolve found a changed container | Allowed, if the row has a baseline |
    | `uncertain` | The run closed with no result (`unknown`, `script_interrupted`, `execution_timeout`), or the after-snapshot is missing | Refused until resolved |
    | `rolled_back` | A later rollback of this row succeeded | Refused |

  - **Partly recreated project (R10, R13):** the after-snapshot is the record
    of what exists, whatever `up_exit` says. A recreated container is bound by
    its new ID, one that was not recreated by its old ID, and one that is gone is
    `missing`. These are the incarnations for any later action. A rollback of a
    `partial` row binds in `targets` every present container of the frozen
    services, with the `image_id`, `running_reference` and
    `configuration_digest` from the snapshot, so mixed replicas are exact. A
    service with every replica `missing` keeps its `images` entry with no target.
    Rollback's postcheck expects the replica count from **before** the update, so
    it also restores `missing` replicas. `up` can do that without `--scale`,
    because cu02's phase 1 proved that this count equals the file's scale, and
    the unchanged `source_digest` proves the file's scale is still the same.
  - **Resolving `uncertain` (R11, see Q19):** `ResolveContainerRecreation`
    (server, admin) takes the execution ID of a finished `docker.update_preview`
    of that host that started after the target's hold ended. The executor reads
    the result from `runs`, never from the request, and requires
    `runs.action_id` to be that action, so a preview cannot be replaced by the
    output of another action. `ReleaseRun` keeps the result of the newest preview
    run of a host while that host has an `uncertain` row. A preview run attached,
    or a result already released, is refused and the row stays `uncertain`. The
    match against the row: every frozen container unchanged gives
    `not_recreated`, otherwise `partial`, with the preview's IDs, image IDs,
    references and `configuration_digest` as the new incarnations (R13). Phase 5
    writes the override before `up`, so a job killed between the two can leave
    the containers unchanged and the override ahead of them. Preview reports
    `override_drift` ahead of `config_not_applied` and retains complete identity
    facts for these checks. Resolve may use those facts to match incarnations,
    even though the reason makes the unit unavailable for an update. Truncated
    or incomplete facts cannot resolve a row. Drift alone cannot prove whether
    a killed job or an operator changed the override. As recommended in Q27,
    store only the existing state and incarnation fields, with no new persisted
    `override_ahead` value or cause. The preview page names observed drift and
    the repair from Q2: reconcile the affected entries with the intended running
    references, removing an entry if the service should no longer use it.
    Resolve
    **never** gives `recreated`: the preview has no health, ports, mounts or
    networks, so no verdict is possible, and unknown is not success. A project
    that really is fully recreated stays `partial`. Anything it cannot match
    stays `uncertain`. It changes nothing on the host, is audited, and does not
    extend the window. A run with no result left no baseline either, so rollback
    from such a row is refused (`no_baseline`); Q19 names the consequence.
  - **Recreation definition (R9, see Q16):** `recreation_definition` holds what a
    rollback recreates from: project, service set, per service the prior
    reference and prior NOS override entry, and `source_digest` (standalone: the
    definition ID and version). It contains no
    secret, because it holds no file content or env. The operator's files stay on
    the host, and `source_digest` proves at rollback that they are the same.
    Rows are not deleted, so the definition lasts through the window and
    afterwards remains history.
  - `ListContainerRecreations` (server, admin): sanitized rows, with the targets,
    `dependencies` and `rollback` values a rollback binding must equal, and the
    current recovery plan digest, so the UI can offer rollback and show why not. The definition
    and the baseline are not returned.
  - `SetContainerRecoveryPlan` and `ClearContainerRecoveryPlan` (admin only):
    per project or container, either a free-text reference without secrets or an
    explicit `no_persistent_data` declaration by the operator, exactly one of the
    two and never inferred from a missing volume, recorded with actor, time and
    version (see Q8). `recovery_plan_digest` is the SHA-256 of that record. A rollback binds it, and Evaluate compares it with the
    current record, so a plan changed or cleared after approval fails
    revalidation.
  - `docker.compose_rollback` 1.0.0 (durable, `reconcile-first`, 30 min through
    `containerMutationTimeout`, batch only): binding `kind=rollback`,
    `rollback_of` the recorded execution, `recovery_plan_digest` required. In
    each image entry `old_tag` and `old_digests` are the update's result, `new_tag`
    is the prior tag, and the `rollback` block holds `prior_image_id`,
    `retained_tag` and `retained_reference` from the row. `new_index_digest`,
    `new_platform_digest` and `old_image_id` stay empty, because nothing is
    pulled. Per target, `image_id` and `running_reference` come from the row. So
    every value below is rendered from the binding (Decision 3).
    `policy_*` and `major_change` are copied from the update, because a rollback
    selects no new version; Evaluate compares the whole binding with the row
    instead of running `CompareTags`. Differences from cu02's phases:
    - phase 1 compares each target's `Config.Image` and image ID with its bound
      `running_reference` and `image_id`, because replicas may differ after
      `partial`. The set of present containers must equal the bound targets, in
      whatever state they are: the `target_not_running` and `scale_mismatch`
      checks do not apply to a broken project. Nor does `config_not_applied`: the
      labels of a partly recreated project differ by design, and the update's
      phase 1 proved the applied configuration for this same `source_digest`
      (only a row with a baseline reaches this point). Nor does `override_drift`:
      an unreached replica may still have its old reference and a label without
      the override while phase 5 already wrote the new entry. Rollback binds
      that replica from the recorded after-snapshot instead (Q2, Q21); it does
      not require the failed update's override to have reached it. The check
      that a NOS digest reference equals the current override entry is likewise
      replaced by the exact recorded-reference check. It recomputes
      `source_digest`, the unchanged-source check, and captures its own baseline;
    - phases 2 and 3 do not run: nothing is resolved or pulled, so a tag that
      moved since the update does not matter;
    - phase 4 verifies that each `retained_tag` still resolves to
      `prior_image_id` (exit 10, `retained_image_missing`, before any recreate);
    - phase 5 writes `retained_reference` into the override and names every
      service of `images`, including one with no target left;
    - the judge compares frozen services with the **update's** baseline in the
      row, dependencies with the rollback's own baseline, and the running image
      with `prior_image_id` in place of the approved digest.
  - **Unchanged source:** `source_digest` of the row equals the recomputed one,
    and each target's `configuration_digest` equals the after-value of the row.
    Before-values are not compared with after-values, since an image change
    alters the container's merged env, labels and defaults (Q5).
  - Evaluate refuses a rollback unless the row is `recreated` or `partial`, the
    row has a baseline (`no_baseline`), the window is open, a recovery plan
    exists with the bound digest, and the binding equals the row (targets,
    `dependencies`, reversed images, the `rollback` blocks, `source_digest`). An
    entry without a
    target is accepted only if the row records every container of that service
    as `missing`. Phase 1 on the host adds the unchanged source and the retained
    image. A rollback's own row is never a rollback source; after a failed
    rollback the way forward is a new update proposal.
- **Risk classes:** rollback same-tag MEDIUM, tag reversal HIGH (the cu01
  floor applied to the reversed tags), CRITICAL refused.
- **Tests:**
  - judge table per postcheck, including a lost mount, a changed network, a lost
    published port, a changed host port, a replica fewer, a wrong digest on one of several services,
    `starting` past the wait, a health regression, a dependency recreated, a
    dependency stopped, a dependency restarted without `restart_on_update`, a
    missing baseline, and a replica matched by number after its ID changed.
  - security: `TestFailedPostcheckStopsRollout`,
    `TestMemberWithoutVerdictIsFailed` (class success, no verdict),
    `TestStageNeedsVerdictOfEveryMember` (one member's hash does not pass the
    stage), `TestUncertainRecreationBlocksRollback`, `TestRollbackNeedsOwnApproval`
    (no reuse of the update's permit), `TestRollbackBindsNewIncarnation`,
    `TestRollbackRefusedWithoutRecoveryPlan`,
    `TestRollbackRefusedWhenRecoveryPlanChanged`, `TestRollbackRefusedAfterWindow`,
    `TestRollbackRefusedWhenConfigurationChanged`,
    `TestRollbackRefusedWhenSourceChanged`,
    `TestRollbackRefusedWhenRetainedImageGone` (nothing is pulled, no recreate),
    `TestRollbackOfPartialBindsMixedReplicas`,
    `TestRollbackOfPartialWithUnreachedReplica` (override entry already written,
    one replica still has its old reference and label without the override;
    phase 1 passes and rollback restores the update's baseline),
    `TestRollbackBindsAllMissingService` (a service with no target left is bound
    and restored; the same entry is refused while the row shows a present
    container), `TestRollbackParametersRenderOnlyFromBinding`,
    `TestRollbackRefusedWithoutBaseline`,
    `TestPartialUpRecordsNewIncarnations`, `TestRollbackOfRollbackRefused`,
    `TestResolveUsesExecutorOwnPreview` (a preview from before the hold ended, of
    another host, or the output of another action, is refused),
    `TestResolveRefusedForAttachedOrReleasedPreview`,
    `TestReleaseKeepsPreviewWhileHostUncertain`,
    `TestResolveCannotReachRecreated`,
    `TestPreviewOverrideDriftPrecedesConfigNotApplied` (complete identity facts
    remain for Resolve, but UpdateBindings refuses the unit),
    `TestResolveUnchangedWithOverrideDrift` (killed between override write and
    `up`, or identical operator drift: `not_recreated`, no inferred cause),
    `TestRollbackRefusedWhenDependenciesDiffer`,
    `TestRecoveryPlanNeedsExplicitNoDataDeclaration`,
    `TestNoDataDeclarationBoundLikeAPlan`, `TestNoAutomaticRetryOrRollback`,
    `TestNoPruneInContainerActions`, and
    `TestComposeFailureLogHoldsNoEnvValue` extended to rollback.
  - store: migration, restart, Lock, clock moved backwards at the window edge,
    every state transition, baseline never overwritten, a finished run judged
    after a crash in `intent`, definition present until after the window.
  - integration: update then rollback, for a multi-service project and for a
    failed `up` that left it partly recreated.
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

- **Rules:** R14, R4 (nothing secret-bearing reaches the tree or the forms), and
  the display of R8, R10, R12, R13. **Gaps:** G15 (UI), G12 for typed tags.
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
  2. For a tag change the operator names the target tag explicitly, per service.
     A latest stable tag is only ever a suggestion. A major change needs a second
     explicit choice, which sets `major_change`; a variant change or tags that
     cannot be compared are not offered.
  3. Fresh previews are run where the binding is too old.
  4. The confirmation shows current to approved per unit and **per image**:
     repository, tag, index and platform digest, platform, for a tag change the
     policy and its version. It also shows the configuration and source digests,
     the exact services and containers, the dependencies marked "affected, not
     recreated", the stage, and the rollback state including the text that
     volume and database migrations are not undone.
  5. The confirm POST is bound to the shown plan (the ou02b pattern, PostForm
     only), then proposed; approval happens on the existing batch page with
     the executor-derived risk.
  6. Progress and stops appear per member. Rollback is offered from
     `ListContainerRecreations` as a new proposal.
- **Unavailable, with reason and no button:** digest-pinned, unknown digest,
  CRITICAL, unsupported or `build:` project, no definition (until cu05),
  private image (until cu06), not enrolled or blocked, host not prepared
  (`prepare_required`, with a link to propose `docker.update_prepare`), a
  required host tool missing, a service sharing a namespace with a selected one
  (Q12), a unit over the binding limits or cut off by a preview limit, every
  case of [What phase 2 does not support](#what-phase-2-does-not-support),
  rollback window over, no recovery plan, retained image gone, no baseline,
  recreation uncertain (with a pointer to resolve it).
- **Risk classes:** shown from the executor. A proposal refused for CRITICAL
  states that no separate approval exists, instead of the batch default text.
- **Tests:** ou02 style handler tests: tampered POST, stale preview, selection
  outside the shown plan, parent without children, escaped host strings,
  every unavailable reason, a major change without the second choice, a
  planted env value absent from every page; `test/browser`: CSP without
  violations, keyboard use, state not shown by color alone, no JavaScript
  needed.
- **Real install:** the route and the wiring in `main.go`. After this step the
  public Compose path works end to end, provided cu02's trust step is done,
  `docker.update_prepare` has run on the host and `docker.update_preview` has
  run. Admin guide and handbook pages.

### cu05 Standalone definitions (P2-03, split out)

- **Rules:** R1, R3, R4, R6, R8, R9, R10, R11, R12, R13 for standalone
  containers. **Gaps:** G2.
- **Paths:** `internal/executions/actions/`, `internal/executions/batchplan.go`,
  `internal/web/ui/`; protected: `internal/executor/`, `internal/executordb/`
  (migration 0022, `container_definitions`), `proto/`, `cmd/nebula/`,
  `test/security/`. `internal/vault/` does not change.
- **Protected: yes** for the executor side.
- **Contracts and RPCs:**
  - `Put`, `Remove` and `ListContainerDefinition` (admin only, list metadata
    only, no digest, see Q20).
  - **Storage:** a vault secret has one row and one version
    (`vault_secrets.id` is the primary key), so the vault itself cannot keep an
    earlier definition, and a 64-hex container ID neither fits the 64-character
    vault ID limit with a prefix nor survives a recreate. Table
    `container_definitions` holds `{host_id, container_name, definition_id,
    version, vault_secret_id, created_by, created_at}`. `definition_id` is a
    random UUID, issued once per host and container name, so it stays the same
    across recreates. Each version is its **own** vault secret with the ID
    `ctrdef.<definition_id>.<version>`, at most 64 characters, written once and
    never replaced. The binding carries `definition_id` and `definition_version`.
  - **Definition retention (R9):** `Put` adds a version and keeps the previous
    one. `Remove` is refused, and a version may not be dropped, while a
    `container_recreations` row inside its window references it. For a
    standalone row `recreation_definition` names that version.
  - `docker.update` 1.0.0 and `docker.rollback` 1.0.0 (durable,
    `reconcile-first`, 30 min through `containerMutationTimeout`, batch only),
    same phases as cu02, including the `running_reference` check, the resolve,
    retention, baseline, after-snapshot, the silent output and the row states of
    cu03. A standalone member has one target and no `dependencies`; a rollback
    whose container is `missing` has no target, as in cu03. The standalone
    baseline matches by container name. The executor adds the definition as a run
    secret, delivered over the existing tmpfs secret channel
    (`internal/hostrun/secrets.go`, 64 KiB). The planner sees no secret slot,
    which is what keeps batches possible (G8).
  - **Redaction of a batch member:** `redactDurable` returns early without
    `run.SecretRefs`, and those come from `permit.SecretRefs` over parameters,
    which hold no secret here and which the batch `CreateRun` does not read
    (`internal/executor/batch_dispatch.go:658`). So the executor derives the
    refs from the binding and passes them to `CreateRun`: slot `definition` to
    `ctrdef.<definition_id>.<version>`. Vault locked or secret gone then behave
    as for every durable run (wait, or withhold the output). Keep the existing
    whole-definition redaction only (Q26). Do not add individual env values:
    `hostrun.Redact` does substring replacement on the result before strict
    parsing and judging, so common values such as `8080`, `1000` or `state`
    could alter valid snapshot fields or JSON keys. Silent command output and
    env-free snapshots remain the protection against env disclosure; redaction
    is only a second layer, not permission to emit secret-bearing output.
  - Format: see Q7. The definition must exactly name the container and may
    leave only the image to NOS. A published port with a Docker-chosen host port
    is a rejected shape, for the same reason as `ephemeral_port`. An env value
    containing a newline is also rejected: `--env-file` cannot reproduce it
    (Q7), and NOS must not split or silently change it.
- **Risk classes:** as cu01; a container without a definition is unavailable.
- **Tests:** `TestStandaloneWithoutDefinitionUnavailable`,
  `TestNoInspectReconstruction` (no inspect field reaches a create argument),
  definition absent from results, logs, audit and errors; rejected definition
  shapes; definition changed after approval refused; injection through the
  definition; `TestDefinitionVersionKeptThroughWindow`,
  `TestDefinitionRemoveRefusedInsideWindow`,
  `TestStandaloneRollbackUsesBoundVersion`,
  `TestDefinitionIDSurvivesRecreate`, `TestDefinitionSecretIDFitsVaultLimit` (at
  the longest version number), `TestNoDefinitionDigestLeavesExecutor` (binding,
  list and results), `TestBatchMemberRecordsDefinitionSecretRefs`,
  `TestBatchMemberOutputRedactedWithLockedVaultWaits`,
  `TestCommonEnvValuesDoNotRewriteSnapshot` (env values `8080`, `1000` and
  `state` do not alter env-free result JSON before parsing or judging),
  `TestDefinitionEnvNotOnCommandLine`, `TestDefinitionNewlineEnvRefused`.
- **Real install:** the operator supplies a definition per container with the
  vault unlocked. Without that, nothing changes.

### cu06 Private registry transfer (P2-04, split out, gated)

**Do not start before Q6 is answered.** The ADR requires a reviewed profile
before enablement.

- **Rules:** R7, R5 (registry credential), R4, R6 (resolve and verify for
  private images). **Gaps:** G13.
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
  same Lock, rotation and expiry rules as `ReadPrivateRegistry`. For a member
  with `registry` set, cu02's phase 2 runs in the executor over that read path,
  because the host has no credential, and phase 3 is this transfer. `docker
  load` does not set repository digests, so verification needs its own
  defined evidence, tested per image store (classic and containerd). The same
  evidence must serve phase 1's current-digest check, `retained_reference`, and
  a `repo:tag@digest` reference that `--pull never` can find. Until that is
  shown, private images stay unavailable.
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

### What phase 2 does not support

These units are refused, not handled. Preview reports the reason, so cu04 shows
it with no button, and the executor enforces it even if a server builds the
binding anyway. Each case has a named test. The way out is on the host: the
operator brings the project back to what its files say.

| Case | Enforced | Reason | Test |
| --- | --- | --- | --- |
| Hand-scaled project: a frozen service runs another count than the file's scale, which `up` would converge to | cu02 phase 1 | `scale_mismatch` | `TestHandScaledProjectRefused` |
| Stopped replica or one-shot service among the targets, which `up` would start | cu02 phase 1 | `target_not_running` | `TestStoppedReplicaRefused` |
| Replicas of one service on different images, on an update | cu01 validation, cu02 phase 1 (`image_id`) | `mixed_images` | `TestUpdateRefusesMixedReplicaImages`, `TestMixedReplicasRefusedOnHost` |
| Operator pin on an update: a digest reference that is not the NOS override (rollback uses recorded references, Q2) | cu02 phase 1 | `digest_pinned` | `TestOperatorPinRefused` |
| Drift: the running state no longer follows the NOS override | Preview, cu02 phase 1 | `override_drift` (before `config_not_applied`, Q27) | `TestOverrideDriftRefused`, `TestPreviewOverrideDriftPrecedesConfigNotApplied` |
| Applied configuration differs from what `up` would apply: a pending file edit, or a project brought up with `--env-file`, `--profile` or a shell variable (Q21) | Preview, cu02 phase 1 | `config_not_applied` | `TestPendingFileEditRefused`, `TestOperatorEnvFileRefused`, `TestOperatorProfileRefused`, `TestShellVariableRefused` |
| A published port with a Docker-chosen host port, read from the same `docker compose config` | Preview, cu02 phase 1 | `ephemeral_port` | `TestEphemeralPortRefused` |
| The local digest can be neither listed nor compared | Preview, cu01 (empty `old_digests`) | `old_digest_unknown` | `TestUnanswerableLocalDigestIsUnknown` |
| A container whose snapshot entry exceeds its limit | cu02 phase 1 | `snapshot_too_large` | `TestOversizeSnapshotRefused` |
| Rollback of a row without a baseline | cu03 Evaluate | `no_baseline` | `TestRollbackRefusedWithoutBaseline` |

Rollback is the one exception to the first three rows, `override_drift` and
`config_not_applied`: it starts from what a failed update left, so it binds the
recorded state instead (cu03, Q2, Q21). Unchanged source and exact recorded
identities and configuration digests still apply; this is not an exemption
from checking operator changes since the recorded after-snapshot.

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
| R4 secrets stay out | | x | x | x | x | x |
| R5 binding | x | | | | | x |
| R6 recheck and verify | x | x | | | x | x |
| R7 private transfer | | | | | | x |
| R8 risk and CRITICAL refusal | x | x | x | x | x | |
| R9 retention window | | x | x | | x | |
| R10 rollback and postchecks | | | x | x | x | |
| R11 stop and reconcile | | x | x | | x | |
| R12 volume limitation | | | x | x | x | |
| R13 new incarnation | | x | x | x | x | |
| R14 tree controls | | | | x | | |

Each mark matches the step's "Rules" line. Every gap is on a step's "Gaps"
line, except G5b, which stays open (Q14).

## Order and release

cu01 → cu02 → cu03 → cu04, each its own PR with a maintainer review, because
all but cu04 touch protected paths. cu05 and cu06 follow cu03 in any order and
extend cu04's reasons list. cu01 can merge alone: `docker.compose_update` 1.0.0
and its host-page link keep working until cu02 replaces them. Release after
cu04, not before: cu02 removes that link. Protected documents (`docs/spec/`, `docs/adr/`,
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
   operator's directory; a later difference refuses the next update through
   cu02's phase 1 check `override_drift`, until the operator removes the entry or
   recreates from the override. The override sets only `image:
   repository:new_tag@new_platform_digest`, so the tag survives in the running
   reference without moving any local tag, and it is kept out of
   `config_files_hash` and `source_digest`. Also confirm the `pinned` handling:
   NOS override (the `config_files` label names it) means "updatable", an
   operator pin stays pinned. That Compose with `--pull never` accepts a
   reference with both tag and digest on both image stores is assumed here and
   must be shown by cu02's first integration test. If it fails, the fallback is
   `repository@digest` plus an executor-side record of the tag, and
   `docker.check_updates` needs that tag as a parameter.
   Also confirm the rollback exception: a `partial` row's recorded targets may
   include a replica that never reached `up`, with no override label although
   the entry was already written. *Recommendation:* skip `override_drift` for
   rollback as well as `config_not_applied` (Q21), while keeping the exact
   recorded identities, configuration digests and unchanged-source checks.
   For a recorded NOS digest reference, use that exact recorded-reference
   check rather than requiring equality with a partly applied override entry.
3. **Does `docker.compose_update` 1.0.0 go away? Blocks cu02.** Only one version
   per built-in ID exists, so 2.0.0 replaces it, and the unbound manual update
   of spec 11 ends. Today it also uses the host's own Docker login.
   *Recommendation:* replace it. Run the v2 pull with an empty `DOCKER_CONFIG`,
   so public-only stays true until cu06, and accept that hosts relying on an
   operator login wait for cu06.
4. **Does "executor rechecks before dispatch" allow the precheck inside the
   approved script? Blocks cu02.** The plan runs it as phases 1 and 2 of the
   bound, trusted artifact as root, immediately before the mutation, and the
   executor reads the typed result. That leaves no gap between check and change
   (the `old_tag` check that backs the risk class is one of these), but
   the executor itself does not read the host first. *Recommendation:* accept;
   the executor still rechecks trust, risk, pin, credentials, Lock and expiry.
5. **What exactly is the configuration digest, and who creates the salt? Blocks
   cu02.** It must cover what secrets may be in (env, compose files, `.env`), and
   even a digest can confirm a guessed low-entropy secret. A single value does not
   work: an image change alters the container's merged env, labels and defaults,
   and a NOS override alters the Compose result, so one digest could not be
   compared across an update, and excluding "the image" from it is not definable.
   *Recommendation, used by the steps:* two values, both HMAC-SHA-256 (Q18) on
   the host, keyed with a root-only random per-host salt that never leaves the
   host.
   - `configuration_digest`, per container: over the complete `.Config` and
     `.HostConfig` of **that incarnation**, with no exclusions. It is compared
     only with the same incarnation. After an update the after-snapshot gives
     the new value, which is what a rollback binds.
   - `source_digest`, per unit: over the output of `docker compose config` run on
     the operator's files **without** the NOS override, so it includes `.env`
     and `env_file` values and stays the same across an update. It says what
     the files render to now, not what the containers were created from (Q21). A
     standalone unit has no `source_digest` (Q20).

   A LOW read may not create the salt (ADR lines 423 and 439), so the MEDIUM
   `docker.update_prepare` does, and preview without a salt reports
   `prepare_required`. A lost salt makes every digest differ, which refuses
   updates and rollbacks (fail closed) until new previews are taken. Alternative:
   an executor-held per-host key delivered as a run secret, which leaves nothing
   on the host, but gives a LOW read a secret and every member a secret channel.
6. **Which private transfer profile? Blocks cu06.** Options: (a) executor
   fetches, `docker load` over SSH (recommended: no credential or token on the
   host, no sshd change); (b) an executor-side authenticating proxy over an
   SSH reverse tunnel (the daemon verifies digests itself, but it needs
   forwarding enabled on every host and yields a rewritten image name). A
   credential handed to the engine is excluded by the ADR. Who signs off the
   review?
7. **Standalone definition format? Blocks cu05.** *Recommendation:* an exact
   argument list for `docker create`, which NOS completes only with the image.
   No shell, no template, no inspect input. An argument list would put secret env
   values on the host's process command line, the same exposure Q18 rejects for
   `openssl dgst -hmac`. So the definition holds env values in a separate list,
   which the script writes to a file in the run's tmpfs and passes as `--env-file`,
   and an `-e` or `--env` argument with a value is a rejected shape
   (`TestDefinitionEnvNotOnCommandLine`). Env values containing a newline
   cannot be represented by that file. *Recommendation:* reject the definition
   before storage and again before dispatch (`TestDefinitionNewlineEnvRefused`),
   without echoing the value or replacing the newline. To confirm: accept this
   limitation rather than add another secret transport. Other arguments, such as a
   label or a health command, stay on the command line, so the admin guide must
   say they hold no secret. Alternative: a one-service Compose document, which
   reuses cu02 and avoids this, but changes the container's labels.
8. **Recovery plan: where, and is "stateless" allowed? Blocks cu03.**
   *Recommendation:* an admin-set executor record per project or container,
   with an explicit "no persistent data" declaration by the operator, never
   inferred from a missing volume. Either form is versioned and bound through
   `recovery_plan_digest`.
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
    package. *Recommendation, used by the steps:* the judge decides rollout
    outcomes, so it goes to a small package, `internal/containerjudge/`, added to
    the protected list, with the two parsers the executor reads results through.
    Move their `maxPreview*` and other parser-enforced constants too; callers
    reuse the relocated limits and tests keep the scripts in agreement, so
    limits stay next to the enforcing code without duplicate Go definitions.
12. **What counts as a dependency? Blocks cu01.** The ADR says to freeze
    dependencies but not what they are. *Recommendation, used by the steps:* the
    transitive closure in both directions over `depends_on`, `links` and
    `volumes_from`, taken from the same `docker compose config` as `source_digest`.
    A service that shares a namespace with a recreated one (`network_mode`, `pid`
    or `ipc` set to `service:<name>`) cannot stay running through the recreate,
    so it must be selected too, otherwise the unit is unavailable. Other Compose
    projects (external networks, shared volumes) are not frozen and the
    confirmation does not claim they are.
13. **Where does the tag policy come from? Blocks cu01.** ADR line 372 wants
    per-image reviewed overrides, but `registrymeta.Policy` is only a struct and
    no store or review path for overrides exists. *Recommendation, used by the
    steps:* the first release knows only the zero policy, version `stable-v1`
    (`registrymeta.DefaultPolicyVersion`), with its digest computed by the
    executor. The planner fills these values and Evaluate compares them.
    Reviewed overrides become an executor-side record later, and the binding
    needs no change for them. Consequence to confirm: without an override,
    non-version tags can only get a same-tag refresh.
14. **G5b: enforce `BatchContainer` on restart, stop and start? Does not block.**
    This plan does not change those members, so they stay bound on paper only,
    and G5 is not closed for them. *Recommendation:* a separate job after cu03: a
    check of container ID and image in the `docker_control.sh.tmpl` scripts, with
    its own version bump. Their configuration hash cannot be compared with the
    host (G4), so that needs a decision of its own.
15. **Holds and waiting for durable members. Blocks cu02.** *Recommendation, used
    by the steps:* a reconciled unknown run keeps the target held until a complete
    root probe shows the job unit gone, because the job may still run; there is no
    operator release without that evidence, in line with today's rearm rule. A
    waiter is bounded by `batchBusyDurableWait`, 45 minutes. Consequence to
    confirm: a host that never answers keeps its target held, and the operator's
    only way out is to bring the host back. A forced release would be a new
    operator action with its own audit, and it is not planned.
16. **What does "executor-owned recreation definition" require for Compose?
    Blocks cu03.** ADR line 482 could mean a copy of the Compose files in the
    executor, but those may hold secrets and live on the host (R4 allows that).
    *Recommendation, used by the steps:* the executor owns a secret-free
    definition (services, prior references, prior override entries,
    `source_digest`), the host keeps the operator's files, and rollback is refused
    if `source_digest` shows they changed. The cost: editing a Compose file during
    the window ends rollback for that project, until the operator restores it.
    Alternative: a sealed copy of the files in the vault per update, which keeps
    rollback available after an edit but adds secret storage and still restores a
    configuration the operator has since changed.
17. **Old digests: registry lookup or a relaxed binding? Blocks cu01.** A classic
    store lists only the digest an image was pulled by: the index after a tag
    pull, the platform manifest after NOS's own digest pull. So the first and
    second update can never fill both old digests from the host, and no registry
    lookup finds an index from a platform digest. *Recommendation, used by the
    steps:* relax the binding, which "index/platform manifest as applicable" in
    ADR lines 471-472 allows. `old_digests` binds what the host lists, and `old_image_id`
    is the exact local identity. `new_index_digest` and `new_platform_digest` stay
    fully bound. A registry GET of the local digest is used only to compare
    (`current`, `update` or `unknown`, cu02), never as a bound value. No answer
    means `unknown`, so the unit is unavailable, as ADR line 361 asks. Alternative:
    require both old digests through a lookup. It cannot work for a digest-pulled
    image, and it makes rollback depend on old manifests staying in the registry.
    Consequence to confirm: an image whose old index was deleted from the
    registry cannot get a same-tag update until the operator repulls it.
18. **Which host tooling, and which keyed construction? Blocks cu02.** The scripts
    must parse nested parameters, compute a keyed digest and walk the dependency
    closure. Today no script uses `jq`, only `image_vulns.sh` needs `python3`, and
    the rest use strict `sed` patterns, which cannot read nested JSON.
    *Recommendation, used by the steps:* require `python3`, run as `python3 -I`
    like `image_vulns.sh`, for all three jobs, and use HMAC-SHA-256 from its
    standard `hmac` and `hashlib` modules, with the salt as key. That is a
    library construction, not self-written cryptography, and the key is read from
    the root-only file, while `openssl dgst -hmac` would put it on a command line.
    Hand-built `sha256(salt || data)` is excluded. A host without `python3`
    reports `tooling_missing`, so its units are unavailable. To confirm: AGENTS.md
    rule 4 names Go libraries only, so please decide whether Python's standard
    library on the host counts as allowed. Alternative: `jq` for parsing plus
    `openssl`, which adds two requirements and puts the key on a command line.
19. **What evidence resolves `uncertain`? Blocks cu02, because it sets the
    preview's transport.** Attached runs write no `runs` row, and `ReleaseRun`
    nulls a durable result once the server took it, so a preview result was not
    there to read. *Recommendation, used by the steps:* the preview is durable,
    `runs.action_id` proves which action produced a result, and `ReleaseRun` keeps
    the newest preview of a host that has an `uncertain` row. Resolve reaches
    `not_recreated` or `partial`, never `recreated`, because the preview has no
    health, ports, mounts or networks. No new evidence format is added.
    Alternatives: a separate evidence action with its own format, which could
    reach `recreated` but adds an action; or no Resolve at all, so a row stays
    `uncertain` and the only way on is a new update proposal. Consequence to
    confirm: every run that closes with no result has a row without a baseline,
    and rollback from it is refused (`no_baseline`). That is not only `unknown`:
    a reboot, a kill or a job timeout during an update closes as
    `script_interrupted` or `execution_timeout`, also with no result. The call
    budgets of cu02 aim to keep a hung call out of this case (Q25), but a reboot
    during phases 5 or 6 stays in it. The operator repairs the project on the
    host using Q2: either reconcile the entries and recreate with the override,
    or remove the affected NOS override entries before a plain
    `docker compose up -d` from the operator's files. The latter deliberately
    returns those services to the files' image tags; it is not an exact-digest
    rollback, and the operator must review that image change. Take a new
    preview, then propose a new update, which R11 permits after Resolve.
    Keeping rollback in that case would need phase 1 to store the
    baseline on the host as well.
20. **`source_digest` of a standalone unit: key it or keep it in the executor?
    Blocks cu05.** It would be a digest of a secret-bearing definition, travelling
    to the server in the binding, and Q5 rejects unkeyed digests because they can
    confirm a guessed low-entropy secret. *Recommendation, used by the steps:*
    keep it in the executor. A standalone binding has no `source_digest`. It
    binds `definition_id` and `definition_version`, which identify an immutable
    vault secret, so the digest adds nothing, and no digest of a definition
    leaves the executor. Alternative: an HMAC with an executor-held key, which
    gives the review a value to compare but needs a new key for no added binding.
21. **What enforces "the same complete configuration"? Blocks cu02.** R1, ADR
    lines 456-457 and spec v23-11-12 allow only the image to change. `source_digest`
    hashes the current files and phase 1 compares it with the preview's value, so
    it shows only that nothing changed since the preview. A pending file edit, an
    operator `--env-file` or `--profile`, or a shell variable from the original
    `up` passes that comparison, phase 5 passes none of them, and `up` would
    apply the difference to the frozen containers together with the image. The
    judge sees ports, mounts and networks only. *Recommendation, used by the
    steps:* narrow the scope with phase 1's `config_not_applied` check, over the
    same files and environment as phase 5, and report the same reason in preview,
    so the unit is unavailable. Compose writes this label when it creates a
    container and decides on a recreate by this hash, so an equal hash means the
    file set renders what the container already runs, and the override's image is
    what `up` changes. The way out is on the host: first make the required
    environment and service selection reproducible without an operator's
    `--env-file`, `--profile` or shell variables. Then use the override as in Q2,
    or remove the affected NOS override entries before a plain
    `docker compose up -d` from the operator's files. Removing entries and
    using the plain command deliberately returns those services to the files'
    image tags, so the operator must review that image change. Leaving stale
    entries would still give `override_drift`. Take a new preview afterwards.
    No new state, action or evidence format is added. Consequences to confirm:
    - A project that needs `--env-file` or `--profile` at every `up` cannot be
      updated by NOS. Passing them on would need them bound and approved, which
      this plan does not do.
    - A Compose upgrade that changes how the hash is computed reads as
      `config_not_applied` until the next `up` with the reconciled override, or
      the entry-removal and plain-`up` repair above. That fails closed.
    - An edit between phase 1 and phase 5 is not caught.
    - Fields Compose leaves out of the hash are not proved. cu02's
      `TestConfigHashCoverage` must list them. If one of them can reach a recreated
      container, it needs its own check or the maintainer accepts it.
    - That `config --hash` equals the label for a service recreated through the
      override is assumed here and must be shown by cu02's first integration test,
      as in Q2. If it fails, the first update would be the only provable one, and
      the Compose path stops for a maintainer decision.
22. **How do host-side registry requests share the budget? Blocks cu02.** Spec
    v23-11-02 and v23-11-06 count every HEAD and GET and allow one request per
    second and two at once per registry, with a pause of at least 15 minutes
    after a 429. Preview, phase 2 and `docker.check_updates` run on the hosts,
    where no server cache or budget reaches them. One tag can cost four requests
    (HEAD, token, HEAD, index GET), so 20 entries cost up to 80 and 50 images in
    `docker.check_updates` more than that. *Recommendation, used by the steps:* a
    per-run cap only, `maxRunRegistryRequests = 120`, with requests in sequence
    and at least 1 second apart per registry. This is a count limit, not a
    wall-clock guarantee: 120 requests at curl's 10-second limit plus 119
    one-second gaps take 1,319 seconds (21 minutes 59 seconds), about 22 minutes.
    Even 80 requests for 20 entries can take 879 seconds (14 minutes 39 seconds).
    They do not fit the 5-minute preview/check or phase 2's shared 3-minute
    check budget. Enforce the earlier deadline as well: Q24 for preview and
    `docker.check_updates`, Q25 for phase 2. A used-up cap or a 429 ends that run's
    requests: preview and phase 2 report `tag_unresolved`, the check `unknown`,
    never "current". The result names `rate_limited`, and a script keeps nothing
    between runs, so `Retry-After` and the 15-minute pause are honoured only by
    the operator not rerunning. Consequences to confirm: several hosts behind one
    address, or two runs in a row, are not summed, so the per-registry budget of
    spec v23-11-06 is met per run and not across a lab. Sharing it would need the
    server to order host-side runs or a server-side lookup (Q10), a separate
    change. An operator with many images sees `unknown` for those past the cap.
    A slow registry can reach the deadline well before the cap; the check must
    still return `unknown` for unfinished and remaining images, rather than
    wait for the job timeout. The count-cap test alone does not prove that
    (`TestCheckUpdatesWallClockIsUnknown` in cu02).
23. **Is `docker compose config` as root on host-supplied paths acceptable? Blocks
    cu02.** `maxPreviewConfigFiles` and its 1 MiB limit cover only the files the
    label names. `.env`, `env_file`, `extends` and `include` targets are read by
    Compose as root, under `timeout 30` and the output cap alone, and a remote
    `include` can reach the network and write a cache, despite "writes nothing".
    The fake host of `TestPreviewWritesNothing` cannot show that, so its claim
    covers the script's own commands only. Finding these targets before Compose
    runs would need a YAML parser on the host, which Q18 does not provide.
    *Recommendation, used by the steps:* run every Compose call with the remote
    loaders switched off through their environment variables, treat a failure as unit unsupported, and
    prove it with an integration test on the supported Compose versions
    (`TestRemoteIncludeRefused`, no network and no cache). Accept the time and
    output bounds for local targets, since a host that hostile only harms its own
    preview. To confirm: whether a Compose version without such a switch counts as
    `tooling_missing`.
24. **Where do preview and check deadlines apply? Blocks cu02.** A stop between
    units leaves every call in the started unit running; per-call limits and
    Q22's request cap cannot bound the whole job. *Recommendation, used by the
    steps:* apply `maxPreviewWallClock = 4 * time.Minute` before every call and
    spacing wait within a unit, and use the same four-minute bound as
    `maxCheckUpdatesWallClock` for `docker.check_updates`. Shorten each call to
    the remaining time including kill grace, start no call without room to stop
    it, and reserve the last minute of each five-minute job for result handling.
    Preview discards the incomplete unit and reports it and the rest as
    `truncated`; check reports unfinished and remaining comparisons `unknown`.
    These reuse the existing timeouts and result reasons; no new action or
    evidence format is proposed. To confirm: the four-minute work/one-minute
    result split and earlier-deadline behavior, including a single unit with
    many slow calls. The named deadline tests in cu02 must cover that case;
    stopping only between units is insufficient.
25. **Mutation phase budgets and timeout reasons? Blocks cu02 and cu03.**
    The five budgets and the reasons `budget_exceeded`, `pull_timeout` and
    `up_timeout` are proposed contract choices, not ADR requirements.
    *Recommendation:* accept cu02's table: 3 minutes shared by phases 1 and 2,
    12 for pulls, 1 for retention, 8 for `up`, and 5 for the after-snapshot,
    including its 3-minute health wait. Total 29 minutes inside the 30-minute
    job. Charge each call's kill grace inside its phase, leaving one minute for
    result handling, rather than claiming one grace per phase covers many
    calls. Keep the listed reasons and raw `up_exit`; timeout may be 124 on
    SIGTERM or 137 after SIGKILL. Classify an actual timeout as `up_timeout` in
    either case; do not infer expiry from any arbitrary command exit 137.
    Phase 6 still runs after a timed-out `up`; exhausting phase 6 leaves
    `uncertain`, not success. To confirm: these exact budgets, reason vocabulary,
    grace accounting and status semantics for update, rollback and standalone.
26. **Redaction of env values inside a definition? Blocks cu05.** Adding them
    as individual redaction entries would be a new mechanism. Plain substring
    replacement before the parser/judge can rewrite valid JSON for common
    values such as `8080`, `1000` or `state` and turn a good update into a
    failure. *Recommendation:* drop those entries, keep existing whole-secret
    redaction with the binding-derived definition ref, and rely on silent
    command output plus env-free snapshots for env non-disclosure. To confirm:
    accept that narrower second layer; do not design structural redaction here.
    cu05 tests both planted-secret non-disclosure and unchanged snapshot JSON
    when common env values coincide with non-secret fields.
27. **Resolve evidence and naming override drift? Blocks cu02 and cu03.**
    `override_drift` cannot distinguish a job killed before `up` from an
    operator edit. A persisted `override_ahead` would add a value with no
    column in the row definition and assert an unproved cause.
    *Recommendation:* add no persisted field or cause; keep the existing row
    state and incarnation facts. Preview checks drift, gives `override_drift`
    priority over `config_not_applied` when both fail, and retains complete
    identity facts for these unavailable units so Resolve can match them.
    Resolve may use those facts without authorizing an update; truncated or
    incomplete facts leave the row `uncertain`. The preview page shows observed
    drift and Q2's repair, without attributing it to a killed job. To confirm:
    this reason precedence and reuse of the existing preview evidence, and
    leaving the diagnosis out of persisted recreation rows. No new evidence
    action, format or causal-state mechanism is proposed.
