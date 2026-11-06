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
transport is the only file activity, the same for every durable job.
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
  - `kind` (update or rollback), `form` (compose or standalone);
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
  - compose only, `source_digest` (see Q5): what the containers were created
    from, unchanged by the image change. It is refused on a standalone member,
    which binds `definition_id` and `definition_version` instead (Q20);
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
    `TestImplicitMajorUpgradeRefused`, `TestContainerVariantChangeRefused`.
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
    `docker-update-preview-v1`, with a strict parser and a fuzz target.

    **Limits**, named constants in `internal/executions/dockerhost/`, enforced by
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

    Each external call has its own bound (`timeout 30` for Compose and Docker,
    the `curl` limits of `docker_check_updates.sh`), inside the 5-minute job
    timeout. A label-supplied path must be absolute, and the content of those
    files never leaves the host. A unit cut off by a limit is reported without
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
       - **drift (Q2):** when a NOS override file exists for the project, the
         `config_files` label names it and each frozen service's override entry
         equals its targets' reference (`override_drift`). A plain `docker
         compose up -d` after an update stops here;
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
       `tag_moved`; no answer or an unusable one is exit 10 with
       `tag_unresolved` (unknown is not success). All entries are resolved before
       the first pull. This is what makes a moved tag stop before any change;
       the digest pull alone would hide it.
    3. **Pull.** `docker pull repository@new_platform_digest` for each distinct
       digest, then verify for each entry that the image lists that digest and
       has the bound platform. It never pulls by tag and never runs `docker
       compose pull`. One failed image stops the member; nothing was recreated
       yet, and images already pulled stay as harmless unreferenced images.
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
    line 361). That costs at most one more request per changed image, inside the
    budget of spec v23-11-02. The 50-image and 64-KiB caps stay. Fixes G11.
  - `InspectBindings` gets a sibling `UpdateBindings` over the latest preview,
    at most `maxContainerBindingAge` old. It fills `images`, `targets`,
    `dependencies` and `source_digest`, and the policy values of Q13, and it
    refuses a unit that carries a reason or was truncated. Compose leaves
    `batchExcludedActions`, and `docker.compose_update` joins the list that is
    refused on the classic path (cu01), which ends 1.0.0's manual path (Q3).
  - **Timeouts:** `docker.compose_update`, `docker.compose_rollback`,
    `docker.update` and `docker.rollback` all use one named
    `containerMutationTimeout = 30 * time.Minute`, the value
    `batchBusyDurableWait` is derived from.
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
      with `runs.member_id`, and an unknown outcome counts as a failure for the
      stop rule.
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
    - when reconciliation closes the run with a definite class (result read,
      or not executed): the job is over;
    - when the class is **unknown** (job directory gone, or host not checkable
      before the reconcile deadline), it does **not** end. The job may still
      run, so the target stays held until a new `hostrun.DurableJobGone` probe
      (sudo, complete check of unit `nebula-job-<execution-id>`; an error counts
      as running) shows it gone. It uses the existing recheck and the
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
    and after an image change and a NOS override).
  - log (R4): `TestComposeFailureLogHoldsNoEnvValue`, a table where a fake
    `docker compose config`, `pull` and `up` fail and print a planted env value
    on stdout and stderr: neither result nor log may hold it, for preview and
    update here and for rollback in cu03.
  - preview limits: `TestPreviewBoundsHostileHost`, a table with one case over
    each constant and no partial unit in the result;
    `TestPreviewOversizeIndexIsUnresolved`; `TestPreviewResultStaysUnderLimit` at
    the maximum of every field.
  - check_updates: `TestCheckUpdatesFirstUpdateListsIndex` (tag pull),
    `TestCheckUpdatesSecondUpdateListsPlatform` (digest pull),
    `TestIndexChangeOnOtherArchitectureIsCurrent`,
    `TestUnanswerableLocalDigestIsUnknown`.
  - planner: `TestContainerBatchLifetimeCoversSerialMembers` (8 members of 30
    minutes get at least 305 minutes), `TestContainerBatchOverLifetimeRefused`,
    `TestContainerActionsShareMutationTimeout`.
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
    `TestRearmDoesNotFreeDurableHold`, `TestHoldEndsWhenDurableJobGone`,
    `TestBusyDurableTargetEndsWaiterNotExecuted` (at the new limit, with an
    attached waiter too); `TestServerRestartFollowsDurableMember`.
  - security: `TestContainerSubstitutionRefused`, `TestTagDriftRefused` (the
    registry answers another digest for `new_tag`; no pull, retain or `up`
    runs), `TestForgedOldTagStopsBeforePull` (a tag change labelled same-tag
    with a forged `old_tag`, approved at MEDIUM, stops in phase 1).
  - integration: real Docker and Compose, with a registry on loopback, on both
    image stores (classic and containerd), including that `--pull never` finds
    a `repo:tag@digest` reference (Q2), and a `depends_on` project.
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

- **Rules:** R8 (the reversed floor), R9, R10, R11, R12, R13. **Gaps:** G10,
  G14, G15.
- **Paths:** protected: `internal/executordb/` (migration 0020 and store),
  `internal/executor/`, `internal/canonical/`, `internal/permit/batch/`,
  `proto/`, `cmd/nebula/`, `test/security/`, `test/integration/`; not protected:
  `internal/executions/dockerhost/`, `internal/executions/actions/`,
  `internal/executions/batchplan.go`.
- **Protected: yes** for the executor side.
- **Contracts and RPCs:**
  - A pure `dockerhost.JudgeContainerUpdate` over the after-snapshot: health,
    ports, mounts and networks, service and replica count, and the running
    digest equals the approved one, per service. Each `dependencies` container
    keeps its ID and `configuration_digest`, still runs and has not lost health;
    its start time may change only with `restart_on_update`. Unknown is not
    success. The verdict of `compose-update-v1` is left as it is.
  - The **executor** judges, then calls `RecordPostcheck`, with a fixed hash
    in `RequiredPostchecks`. A failed verdict is `OutcomeFailed`.
  - Canonical validation requires `failure_threshold` and
    `unreachable_threshold` of 0 for stages with `container_update` members,
    so any failure or unreachable member stops the rollout.
  - `executor.db` table `container_recreations`, one row per member run:
    - execution, `kind`, `rollback_of`, host and key, form, project or name;
    - the bound `images`, each with its retained tag and `retained_reference`
      (`repository:old_tag@` the digest the retained image lists, index or
      platform, because a classic store may list only the digest it was pulled
      by);
    - per container: service, name, ID and `configuration_digest` before and
      after, image ID after, replica number, and `recreated`, `unchanged` or
      `missing`;
    - `source_digest`, and the replica count per service before the update;
    - `recreation_definition`: the executor-owned definition of R9 (see below);
    - state, window expiry.

    The row is written before dispatch and completed by the result or by
    reconciliation. Window constant `DefaultRollbackWindow = 7 * 24h`, with
    injected time; expiry is set once, when the row first leaves `intent`.
  - **States:**

    | State | Meaning | Rollback |
    | --- | --- | --- |
    | `intent` | Written; the run is not finished | Refused |
    | `not_recreated` | Stopped in phases 1 to 4; every container is as it was | Refused: nothing to undo |
    | `recreated` | Phase 6 passed and the verdict passed | Allowed |
    | `partial` | Phase 5 was reached, the after-snapshot exists, and `up` or the verdict failed | Allowed |
    | `uncertain` | The run is unknown, or the after-snapshot is missing | Refused until resolved |
    | `rolled_back` | A later rollback of this row succeeded | Refused |

  - **Partly recreated project (R10, R13):** the after-snapshot is the record
    of what exists, whatever `up_exit` says. A recreated container is bound by
    its new ID, one that was not recreated by its old ID, and one that is gone is
    `missing`. These are the incarnations for any later action. A rollback of a
    `partial` row binds in `targets` every present container of the frozen
    services, with the `image_id` and `configuration_digest` from the snapshot,
    so mixed replicas are exact. Rollback's postcheck expects the replica count
    from **before** the update, so it also restores a `missing` replica.
  - **Resolving `uncertain` (R11):** `ResolveContainerRecreation` (server, admin)
    takes the execution ID of a completed `docker.update_preview` of that host
    that started after the target's hold ended. The executor reads that result
    from its own run table, never from the request, and matches it against the
    row: every frozen container unchanged gives `not_recreated`, otherwise the
    row becomes `partial`, or `recreated` if every container is on the approved
    digest and the judge passes. Anything it cannot match stays `uncertain`. It
    changes nothing on the host, is audited, and does not extend the window.
  - **Recreation definition (R9, see Q16):** `recreation_definition` holds what a
    rollback recreates from: project, service set, per service the prior
    reference and prior NOS override entry, and `source_digest`. It contains no
    secret, because it holds no file content or env. The operator's files stay on
    the host, and `source_digest` proves at rollback that they are the same.
    Rows are not deleted, so the definition lasts through the window and
    afterwards remains history.
  - `ListContainerRecreations` (server, admin): sanitized rows, the retained
    tags and the current recovery plan digest, so the UI can offer rollback and
    show why not. The definition is not returned.
  - `SetContainerRecoveryPlan` and `ClearContainerRecoveryPlan` (admin only):
    per project or container, a free-text reference without secrets, recorded
    with actor, time and version (see Q8). `recovery_plan_digest` is the SHA-256
    of that record. A rollback binds it, and Evaluate compares it with the
    current record, so a plan changed or cleared after approval fails
    revalidation.
  - `docker.compose_rollback` 1.0.0 (durable, `reconcile-first`, batch only):
    binding `kind=rollback`, `rollback_of` the recorded execution,
    `recovery_plan_digest` required. In each image entry the `old_*` fields are
    the recorded new state and the `new_*` fields are the prior digests and tag.
    `policy_*` and `major_change` are copied from the update, because a rollback
    selects no new version; Evaluate compares the whole binding with the row
    instead of running `CompareTags`. Differences from cu02's phases:
    - phase 1 compares each target's running reference with the snapshot in the
      row, because replicas may differ after `partial`; it also recomputes
      `source_digest`, the unchanged-source check;
    - phases 2 and 3 do not run: nothing is resolved or pulled, so a tag that
      moved since the update does not matter;
    - phase 4 verifies that each retained tag still resolves to the prior image
      ID (exit 10, `retained_image_missing`, before any recreate);
    - phase 5 writes `retained_reference` into the override.
  - **Unchanged source:** `source_digest` of the row equals the recomputed one,
    and each target's `configuration_digest` equals the after-value of the row.
    Before-values are not compared with after-values, since an image change
    alters the container's merged env, labels and defaults (Q5).
  - Evaluate refuses a rollback unless the row is `recreated` or `partial`, the
    window is open, a recovery plan exists with the bound digest, and the binding
    equals the row (targets, reversed images, `source_digest`). Phase 1 on the
    host adds the unchanged source and the retained image. A rollback's own row
    is never a rollback source; after a failed rollback the way forward is a new
    update proposal.
- **Risk classes:** rollback same-tag MEDIUM, tag reversal HIGH (the cu01
  floor applied to the reversed tags), CRITICAL refused.
- **Tests:**
  - judge table per postcheck, including a lost mount, a changed network, a
    replica fewer, a wrong digest on one of several services, `starting` past
    the wait, a dependency recreated, a dependency stopped, a dependency
    restarted without `restart_on_update`.
  - security: `TestFailedPostcheckStopsRollout`,
    `TestUncertainRecreationBlocksRollback`, `TestRollbackNeedsOwnApproval`
    (no reuse of the update's permit), `TestRollbackBindsNewIncarnation`,
    `TestRollbackRefusedWithoutRecoveryPlan`,
    `TestRollbackRefusedWhenRecoveryPlanChanged`, `TestRollbackRefusedAfterWindow`,
    `TestRollbackRefusedWhenConfigurationChanged`,
    `TestRollbackRefusedWhenSourceChanged`,
    `TestRollbackRefusedWhenRetainedImageGone` (nothing is pulled, no recreate),
    `TestRollbackOfPartialBindsMixedReplicas`,
    `TestPartialUpRecordsNewIncarnations`, `TestRollbackOfRollbackRefused`,
    `TestResolveUsesExecutorOwnPreview` (a preview from before the hold ended, or
    of another host, is refused), `TestNoAutomaticRetryOrRollback`,
    `TestNoPruneInContainerActions`.
  - store: migration, restart, Lock, clock moved backwards at the window edge,
    every state transition, definition present until after the window.
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
  service sharing a namespace with a selected one (Q12), a unit over the
  binding limits, rollback window over, no recovery plan, retained image gone,
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
  `internal/web/ui/`; protected: `internal/executor/`, `proto/`, `cmd/nebula/`,
  `test/security/`.
- **Protected: yes** for the executor side.
- **Contracts and RPCs:**
  - `Put`, `Remove` and `ListContainerDefinition` (admin only, list metadata
    only). The definition is a vault secret `container.<id>.definition`, and
    its version and digest are bound as `definition_version`. `source_digest`
    is that digest.
  - **Definition retention (R9):** `Put` adds a version and keeps the previous
    one. `Remove` is refused, and a version may not be dropped, while a
    `container_recreations` row inside its window references it. For a
    standalone row `recreation_definition` names that version.
  - `docker.update` 1.0.0 and `docker.rollback` 1.0.0 (durable,
    `reconcile-first`, batch only), same phases as cu02, including the `old_tag`
    check, the resolve, retention, after-snapshot and the row states of cu03. A
    standalone member has one target and no `dependencies`. The executor adds the
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
  definition; `TestDefinitionVersionKeptThroughWindow`,
  `TestDefinitionRemoveRefusedInsideWindow`,
  `TestStandaloneRollbackUsesBoundVersion`.
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
   that refuses the next update. The override sets only `image:
   repository:new_tag@new_platform_digest`, so the tag survives in the running
   reference without moving any local tag, and it is kept out of
   `config_files_hash` and `source_digest`. Also confirm the `pinned` handling:
   NOS override (the `config_files` label names it) means "updatable", an
   operator pin stays pinned. That Compose with `--pull never` accepts a
   reference with both tag and digest on both image stores is assumed here and
   must be shown by cu02's first integration test. If it fails, the fallback is
   `repository@digest` plus an executor-side record of the tag, and
   `docker.check_updates` needs that tag as a parameter.
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
   *Recommendation, used by the steps:* two values, both keyed on the host with a
   root-only random per-host salt that never leaves the host.
   - `configuration_digest`, per container: over the complete `.Config` and
     `.HostConfig` of **that incarnation**, with no exclusions. It is compared
     only with the same incarnation. After an update the after-snapshot gives
     the new value, which is what a rollback binds.
   - `source_digest`, per unit: over the output of `docker compose config` run on
     the operator's files **without** the NOS override, so it includes `.env`
     and `env_file` values and stays the same across an update. Standalone: the
     definition digest (cu05), not keyed.

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
   No shell, no template, no inspect input. Alternative: a one-service Compose
   document, which reuses cu02 but changes the container's labels.
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
    package. *Recommendation:* the judge decides rollout outcomes, so move it
    to a small package added to the protected list.
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
