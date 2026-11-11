<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Frozen project decisions before Milestone 1

The pre-Milestone-1 architecture decisions are now closed. Changes to these decisions require an explicit architecture revision rather than an implementation convenience change.

- [x] **Public name:** Nebula Operation Station. Internal binaries/services keep the `nebula-*` prefix.
- [x] **License:** AGPL-3.0-or-later for the entire project.
- [x] **Code hosting:** GitHub, preferably under a dedicated organization.
- [x] **Web frontend:** server-rendered Go templates + htmx; strict CSP; no SPA requirement for V1.
- [x] **RPC:** gRPC + Protobuf over `/run/nebula/executor.sock`.
- [x] **Default approval mode:** Standard; hardened CLI approval remains optional.
- [x] **Vault unlock:** CLI is default/recommended; Web unlock is opt-in and labelled weaker.
- [x] **Supported targets for 0.1:** Debian 12, Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, Proxmox VE 8 and 9 as Debian-based hosts.
- [x] **First-party signing key:** offline YubiKey-held Ed25519 root, never stored in CI; only public keys ship, rotation is signed, and recovery uses a separately enrolled second YubiKey root and encrypted offline key handle backups. `root-1` is active; `root-2` is pending. See [release signing](10-modules.md#release-signing) (owner decision 2026-10-30 within ADR 0001).

### Implementation details that remain intentionally non-architectural

The following can be chosen during implementation without reopening the architecture unless they alter the stated trust model or compatibility guarantees:

- exact GitHub organization/repository name and domain name availability
- exact CSS/component styling for the Go/htmx UI
- protobuf package names and field numbering
- concrete timeout and payload-limit defaults, provided they stay within the security model
- exact release automation tooling around the offline signing step
- offline storage arrangements for hardware roots and encrypted key handle backups, within the [owner-approved YubiKey signing contract](10-modules.md#release-signing)

<a id="v23-17-01"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-17-01 -->
### Spec v2.3 (ADR 0006, ADR 0007)

<a id="v23-17-02"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-17-02 -->
**Accepted revision and sources.** The maintainer accepted [ADR 0006: Proxmox integration](https://github.com/nebula-operation-station/nebula-operation-station/blob/docs/adr-0006-proxmox/docs/adr/0006-proxmox-integration.md) and [ADR 0007: Approval ergonomics](https://github.com/nebula-operation-station/nebula-operation-station/blob/docs/adr-0007-approval-ergonomics/docs/adr/0007-approval-ergonomics.md) on 2026-10-29. This is Spec v2.3 (ADR 0006, ADR 0007), implementing P1-01 and ADR 0007's required specification revision. The ADRs are sourced from those origin branches because neither file is present on the `origin/main` baseline; links do not assume unmerged local files. All unchanged v2.2 decisions remain frozen. This revision defines intended contracts, not completed implementation or verified PVE compatibility.

<a id="v23-17-03"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-17-03 -->
**Precedence and authority.** ADR 0007 unifies ADR 0006 P1-07/P1-36 into provider/telemetry profiles of the shared read-grant registry; it replaces the proposed 90-day provider maximum with default 7 days/maximum 30 days for new grants and renewals. Existing `read-schedule-v1` signatures retain original schedule-only scope/expiry, including 90-day grants, without new on-demand authority. Approved grants/spent budgets are durable; execution/batch permits, gates, pending proposals and privileged sessions remain volatile. M0's executor-vault custody replaces the old separate `vault.db` description. No undisclosed mutation, credential exception or weakening of unrelated rules is authorized.

<a id="v23-17-04"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-17-04 -->
**Authority review.** Each authority below is restricted by its owning paragraphs and per-run checks, not by UI selection or socket membership. Unspecified lifecycle details are explicit open questions, not implicit indefinite permissions. Their unresolved profiles must not be enabled by inventing rules; existing reviewed profiles keep their stated limits.

<a id="v23-17-05"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-17-05 -->
| Authority | Holder and exact scope | Limits and expiry | Revocation and audit |
| --- | --- | --- | --- |
| `pve-collector` role | Dedicated Unix UID may request only typed provider metadata/reads; executor holds credentials and validates remote/child identity; no unlock, approval, mutation, secret, database or network access | No standalone execution authority; standing grant methods/targets/budgets and 7/30-day expiry apply. Independent UID-map expiry/provisioning remains Q1 | Lock/restart pauses reads; grant revocation, expiry, pin/version/remote changes stop affected scope. Audit caller UID, grant, target, claim, denial/outcome; UID-map revocation protocol remains Q1 |
| Ordinary/provider read leases | Executor stores approved grants; server/collector may trigger frozen read-only effective-LOW actions, exact parameters/artifacts, SSH host/key or typed provider scope | ≤32 actions, ≤1,000 SSH targets, 7-day default/30-day maximum; ordinary 15-min floor and 24 default/240 maximum runs/host/rolling hour. Provider: one poll/two requests concurrent per remote, 10/30-s timeouts, backoff ≤15 min; non-metrics request budgets remain Q2 | Revoke without assertion, serialize against dispatch; lock/restart pauses, identity/version changes need replacement; audit proposal/approver/digest/scope/budget, lifecycle and each fresh execution/claim/outcome |
| SSH/provider telemetry leases | Executor-approved telemetry profile, exact enrolled host/key or provider remote/node/VMID/generation, approved actions/parameters and versions; viewer requests only select authorized work | 5-min history/10-s live; ≤4,096 runs/host/rolling hour, 7/30-day standing grant; visible request expires after 30 s without renewal; four live targets/one metrics request/s per remote; concurrency/defaults remain Q2 | Shared grant revocation/lock/identity checks; hidden/disconnected viewer stops renewal; audit grant lifecycle, targets, claims, denials/outcomes; SSE confers no authority |
| Batch approval | Executor holds frozen ordered `batch-v1`, derives internal single-use exact member permits; admin approves every displayed member at strictest risk | 1–100 members, ≤1 MiB, ≤20 stages, 5-min approval window, execution expiry ≤24 h; CRITICAL rejects entire batch; existing manual gates remain | Lock/restart/expiry revokes mutation authority; raised risk invalidates remaining plan. Audit approver/digest, derivation, claims, stage decisions, skips, denials and per-member outcomes; reconcile accepted tasks without redispatch |
| Public registry egress | Server anonymous metadata only, administrator-approved HTTPS registry/auth origins and validated repository/tag/platform/policy, never layers/PVE/private secrets | One request/s/two concurrent per registry, ≤1 MiB/response, ≤10,000 tags/scan; cache 24 h tag/check, 15-min failure, 7-day digest; 429 backoff ≥15 min; origin-approval expiry remains Q3 | Audit origin changes, scope/calls/throttling/denials/outcomes without secrets. Public reads survive vault lock; exact origin-approval/revocation lifecycle remains Q3, not a credential grant |
| Private registry credentials/reads | Executor vault only; typed repository/tag read grant binds approved registry/auth origins, platform and credential scope/version; private-network origins explicitly allowlisted | Same metadata budgets, 7/30-day grant expiry plus credential expiry; no layers or host login files. Auth/token lifetime and local management workflow remain Q4 | Lock/expiry pauses reads; rotation invalidates old-version authority. Audit credential scope/version/origin, approval, lifecycle, calls and denials without secrets; removal/revocation and private pull/load profile remain Q4 |

<a id="v23-17-06"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-17-06 -->
### Open questions for Spec v2.3

<a id="v23-17-07"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-17-07 -->
**Q1 — Local role and trust lifecycle.** How is the collector UID mapping provisioned, independently expired and removed, and how are those changes audited? The role has no execution authority outside a standing grant. The release-bundle/provenance packaging, size/count/field limits, signed root rotation and previous-byte retention part is resolved by the [owner-approved release-signing contract](10-modules.md#release-signing), 2026-10-30: two previous built-in versions plus every version superseded within 90 days, under a 2 GiB executor storage ceiling with fail-closed admission. The ADR sets no trust-record TTL; retention does not introduce one. Collector-role lifecycle remains open.

<a id="v23-17-08"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-17-08 -->
**Q2 — Grant encoding and rate profiles.** What exact new read-document version/schema, total encoded-size and parameter/artifact limits apply? What executor-wide ceiling policy, telemetry budget/concurrency defaults, expensive-action intervals and non-metrics provider request budgets are approved within the stated maxima? The ordinary profile keeps its specified default 24/maximum 240 runs per host per rolling hour. How are provider/private-registry resource ceilings represented? ADR 0007 resolves ADR 0006's maximum grant lifetime and telemetry aggregate maximum; it does not supply every profile default. No implementation may use unlimited values to fill these gaps.

<a id="v23-17-09"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-17-09 -->
**Q3 — Public registry egress lifecycle.** Which local administrator interface/authority installs registry/auth origins, what approval expiry/renewal applies, and how does revocation stop in-flight lookups and invalidate cached metadata? Cache TTL is not authority expiry. How are large-repository pagination/cache budgets and shared Docker Hub egress handled within fixed request limits? Public egress must remain anonymous and confined to approved origins while these details are reviewed.

<a id="v23-17-10"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-17-10 -->
**Q4 — Private registry profiles.** Which PAT/basic, scoped bearer/OAuth or helper mechanisms and auth realms are supported, with what token lifetime, rotation, removal and provider-side revocation workflow? How are origin/credential changes serialized with reads and cache use? What executor-mediated authenticated SSH pull/load profile retains credentials exclusively in the executor? Unsupported auth/pull profiles stay unavailable; no server credential exception or target Docker login file is permitted.

<a id="v23-17-11"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-17-11 -->
**Q5 — PVE version, ACL and TLS compatibility.** Record exact supported PVE 8/9 package versions and test per-method ACLs, filtered empty responses, PVE 8 agent limitations, LXC interfaces/snapshots, task retention and QEMU/LXC HA delegation/reboot behavior. Is there any safe read-only backup-catalog route? What node SANs, CA retrieval/renewal, custom/ACME trust profiles and same-CA endpoint-membership checks are supported? How reliably can local generations detect VMID reuse? Token lifetimes/permission validation details remain to be specified; broad roles are not a fallback.

<a id="v23-17-12"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-17-12 -->
**Q6 — Storage, snapshots and recovery.** Verify storage/format snapshot capabilities, including PVE 9 LVM, passthrough disk-only snapshots, agent consistency/quiescing and migration with local disks. Which cluster vote/qdevice/HA placement constraints and reboot recovery procedure are sufficient? Offsite actions remain read-only by default: should any be enabled? Which snapshot/backup thresholds are operator-selectable? No three-node safety shortcut or guessed capability is allowed.

<a id="v23-17-13"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-17-13 -->
**Q7 — Container definitions and image policy.** Which resolved Compose definition binds multiple files/profiles, replicas/dependencies and missing/spoofed labels? How do operators enroll complete non-Compose definitions/secret references, and which devices/networks/runtime options are reproducible? Which stable-tag/variant overrides, approved release-note mappings and private metadata visibility are supported? What rollback retention/storage budgets and application-data recovery plans are required? Sanitized inspect output never substitutes for a complete definition.

<a id="v23-17-14"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-17-14 -->
**Q8 — Evidence and metric semantics.** Define exact RRD/status units/normalization, filesystem exclusions, time-weighted bucket averages and minimum coverage for a full-day claim. Define NVIDIA PCI/UUID/passthrough/multi-function/multi-GPU/MIG correlation and unavailable fields. Which deployed PBS metadata safely identifies exact guest generations, catalog presence and verification coverage? Which Trivy version/profile, local-only enforcement, runtime/output/scan cadence, database freshness, CVE deduplication/coverage and severity-to-border policy apply? Default successful-backup age is 24 h, not proof of restorability.

<a id="v23-17-15"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-17-15 -->
**Q9 — Read schemas and presentation.** Set numeric nesting/pagination/runtime limits for new readers. Which service-check destinations, timeouts/cadence and latency-warning thresholds are approved? Which source tags/pools should map to NOS environments, and which service links beyond systemd/Compose require review? Validate chart density/viewport limits, prioritization and accessible pan/zoom/details on deep branches/hundreds of siblings, retaining the automatic ≤600 px list fallback. Discovered ports/labels never authorize probes or placement.

<a id="v23-17-16"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-17-16 -->
**Q10 — Later access/integrations.** Console support requires a separate credential/session ADR: verify ticket/token restrictions, fixed-origin executor relay, single-use short-lived guest session (maximum 15 min), idle expiry, byte/time limits, origin/CSRF checks and audited open/close; none is authorized by the default PVE tokens. Hypervisor shell remains outside committed phases: any future CRITICAL admin-only fresh-UV/target-count session is disabled in hardened mode and needs recording/redaction/retention review because recordings can contain secrets. Existing InfluxDB configuration, PDM/cross-remote credentials and other deferred integrations remain separately scoped questions.

<a id="v23-17-17"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-17-17 -->
### Paragraph changelog for Spec v2.3

<a id="v23-17-18"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-17-18 -->
**Revision markers.** Every changed paragraph, list or table block carries a `Spec v2.3 (ADR 0006, ADR 0007)` marker and stable anchor listed below. Existing section/file numbering and unchanged rules are retained; entries identify the exact changed blocks, including this authority review, open questions and changelog. The only implementation-status change is decision 83 in [m0.md](../implementation/m0.md), recording this documentation decision rather than claiming delivered features.

<a id="v23-17-19"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-17-19 -->
| Changed block | Short changelog |
| --- | --- |
| [v23-00-01](00-index.md#v23-00-01) | 00: Specification v2.3 baseline and revision pointer |
| [v23-00-02](00-index.md#v23-00-02) | 00: Index descriptions |
| [v23-01-01](01-product.md#v23-01-01) | 01: Operator-driven read scheduling |
| [v23-01-02](01-product.md#v23-01-02) | 01: Bounded telemetry/scanning exceptions and non-goals |
| [v23-01-03](01-product.md#v23-01-03) | 01: Proxmox integration phases |
| [v23-01-04](01-product.md#v23-01-04) | 01: Standing reads and exact change plans |
| [v23-02-01](02-architecture.md#v23-02-01) | 02: Executor-only SSH/PVE and bounded read triggers |
| [v23-02-02](02-architecture.md#v23-02-02) | 02: Provider read path |
| [v23-02-03](02-architecture.md#v23-02-03) | 02: Registry egress boundary |
| [v23-03-01](03-processes-and-data.md#v23-03-01) | 03: Process/UID responsibilities |
| [v23-03-02](03-processes-and-data.md#v23-03-02) | 03: Executor socket |
| [v23-03-03](03-processes-and-data.md#v23-03-03) | 03: Executor custody and observation stores |
| [v23-03-04](03-processes-and-data.md#v23-03-04) | 03: Private database/key custody |
| [v23-03-05](03-processes-and-data.md#v23-03-05) | 03: Durable authority and volatile approval |
| [v23-03-06](03-processes-and-data.md#v23-03-06) | 03: Collector authority lifecycle |
| [v23-03-07](03-processes-and-data.md#v23-03-07) | 03: Observation storage and spool |
| [v23-04-01](04-revision-history.md#v23-04-01) | 04: Spec v2.3 (ADR 0006, ADR 0007) |
| [v23-05-01](05-authentication.md#v23-05-01) | 05: Executor-owned session duration |
| [v23-05-02](05-authentication.md#v23-05-02) | 05: Interactive, lease and batch risk table |
| [v23-05-03](05-authentication.md#v23-05-03) | 05: Session extension |
| [v23-05-04](05-authentication.md#v23-05-04) | 05: Read-grant approval |
| [v23-05-05](05-authentication.md#v23-05-05) | 05: Batch approval |
| [v23-05-06](05-authentication.md#v23-05-06) | 05: Review and hardened batches |
| [v23-05-07](05-authentication.md#v23-05-07) | 05: Approval deception |
| [v23-06-01](06-credentials.md#v23-06-01) | 06: One unlock |
| [v23-06-02](06-credentials.md#v23-06-02) | 06: PVE credential custody |
| [v23-06-03](06-credentials.md#v23-06-03) | 06: Exact PVE token privilege profiles |
| [v23-06-04](06-credentials.md#v23-06-04) | 06: PVE profile limits |
| [v23-06-05](06-credentials.md#v23-06-05) | 06: PVE local administration |
| [v23-06-06](06-credentials.md#v23-06-06) | 06: PVE rotation and removal |
| [v23-06-07](06-credentials.md#v23-06-07) | 06: Private registry credentials |
| [v23-06-08](06-credentials.md#v23-06-08) | 06: Recovery and read authority |
| [v23-07-01](07-execution-model.md#v23-07-01) | 07: Interactive, batch-member and standing read authority |
| [v23-07-15](07-execution-model.md#v23-07-15) | 07: Single-action versus member permits, gates and retry authority |
| [v23-07-02](07-execution-model.md#v23-07-02) | 07: Canonical provider targets |
| [v23-07-03](07-execution-model.md#v23-07-03) | 07: Versioned read grants |
| [v23-07-04](07-execution-model.md#v23-07-04) | 07: Frozen read scope |
| [v23-07-05](07-execution-model.md#v23-07-05) | 07: Ordinary read budgets |
| [v23-07-06](07-execution-model.md#v23-07-06) | 07: Telemetry profile |
| [v23-07-07](07-execution-model.md#v23-07-07) | 07: Provider profile |
| [v23-07-08](07-execution-model.md#v23-07-08) | 07: Read eligibility and dispatch |
| [v23-07-09](07-execution-model.md#v23-07-09) | 07: Read lifecycle and audit |
| [v23-07-10](07-execution-model.md#v23-07-10) | 07: Legacy schedules |
| [v23-07-11](07-execution-model.md#v23-07-11) | 07: Canonical batches |
| [v23-07-12](07-execution-model.md#v23-07-12) | 07: Batch member authority |
| [v23-07-13](07-execution-model.md#v23-07-13) | 07: Member stages and partial outcomes |
| [v23-07-14](07-execution-model.md#v23-07-14) | 07: Provider durable jobs |
| [v23-08-01](08-ssh-transport.md#v23-08-01) | 08: PVE remote identity |
| [v23-08-02](08-ssh-transport.md#v23-08-02) | 08: PVE TLS enrollment |
| [v23-08-03](08-ssh-transport.md#v23-08-03) | 08: PVE transport failures and re-pin |
| [v23-09-01](09-untrusted-host-data.md#v23-09-01) | 09: Extend untrusted-input boundary to providers/registries/spool/scanners |
| [v23-09-02](09-untrusted-host-data.md#v23-09-02) | 09: Provider and spool limits |
| [v23-09-03](09-untrusted-host-data.md#v23-09-03) | 09: Allowlisted observations only |
| [v23-09-04](09-untrusted-host-data.md#v23-09-04) | 09: Spool integrity |
| [v23-09-05](09-untrusted-host-data.md#v23-09-05) | 09: Browser presentation |
| [v23-10-01](10-modules.md#v23-10-01) | 10: Read-only contract allowlist |
| [v23-10-02](10-modules.md#v23-10-02) | 10: Additional observation contracts |
| [v23-10-03](10-modules.md#v23-10-03) | 10: Additional read-only action contracts |
| [v23-10-04](10-modules.md#v23-10-04) | 10: Local built-in bundle review |
| [v23-10-05](10-modules.md#v23-10-05) | 10: Atomic built-in trust |
| [v23-10-06](10-modules.md#v23-10-06) | 10: Built-in trust status |
| [v23-11-01](11-operations.md#v23-11-01) | 11: Read scheduling and phased manual mutations |
| [v23-11-02](11-operations.md#v23-11-02) | 11: Complete container recreation and registry budget rules |
| [v23-11-03](11-operations.md#v23-11-03) | 11: Read refresh |
| [v23-11-04](11-operations.md#v23-11-04) | 11: Image metadata and stable versions |
| [v23-11-05](11-operations.md#v23-11-05) | 11: Registry metadata authority |
| [v23-11-06](11-operations.md#v23-11-06) | 11: Registry cache and request limits |
| [v23-11-07](11-operations.md#v23-11-07) | 11: Local image CVE observations |
| [v23-11-08](11-operations.md#v23-11-08) | 11: PVE action profiles and risks |
| [v23-11-09](11-operations.md#v23-11-09) | 11: PVE/container action risks and constraints |
| [v23-11-10](11-operations.md#v23-11-10) | 11: HA and node safety |
| [v23-11-11](11-operations.md#v23-11-11) | 11: Exact tree updates |
| [v23-11-12](11-operations.md#v23-11-12) | 11: Container recreation and rollback |
| [v23-11-13](11-operations.md#v23-11-13) | 11: PVE task completion |
| [v23-11-14](11-operations.md#v23-11-14) | 11: Later orchestration |
| [v23-12-01](12-inventory.md#v23-12-01) | 12: PVE inventory and reviewed links |
| [v23-12-02](12-inventory.md#v23-12-02) | 12: Read selections |
| [v23-12-03](12-inventory.md#v23-12-03) | 12: Observation cadences |
| [v23-12-04](12-inventory.md#v23-12-04) | 12: Staleness and availability |
| [v23-12-05](12-inventory.md#v23-12-05) | 12: Backup confidence |
| [v23-12-06](12-inventory.md#v23-12-06) | 12: Placement model |
| [v23-12-07](12-inventory.md#v23-12-07) | 12: Metric sources and retention |
| [v23-12-08](12-inventory.md#v23-12-08) | 12: Visible-target requests |
| [v23-12-09](12-inventory.md#v23-12-09) | 12: Org chart layout |
| [v23-12-10](12-inventory.md#v23-12-10) | 12: Compact chart box contracts |
| [v23-12-11](12-inventory.md#v23-12-11) | 12: Chart state and interaction |
| [v23-12-12](12-inventory.md#v23-12-12) | 12: Patch sources and PVE links |
| [v23-17-01](17-frozen-decisions.md#v23-17-01) | 17: Spec v2.3 (ADR 0006, ADR 0007) |
| [v23-17-02](17-frozen-decisions.md#v23-17-02) | 17: Accepted revision and sources |
| [v23-17-03](17-frozen-decisions.md#v23-17-03) | 17: Precedence and authority |
| [v23-17-04](17-frozen-decisions.md#v23-17-04) | 17: Authority review |
| [v23-17-05](17-frozen-decisions.md#v23-17-05) | 17: Authority holders, scope, limits, expiry, revocation and audit |
| [v23-17-06](17-frozen-decisions.md#v23-17-06) | 17: Open questions for Spec v2.3 |
| [v23-17-07](17-frozen-decisions.md#v23-17-07) | 17: Q1 — Local role and trust lifecycle |
| [v23-17-08](17-frozen-decisions.md#v23-17-08) | 17: Q2 — Grant encoding and rate profiles |
| [v23-17-09](17-frozen-decisions.md#v23-17-09) | 17: Q3 — Public registry egress lifecycle |
| [v23-17-10](17-frozen-decisions.md#v23-17-10) | 17: Q4 — Private registry profiles |
| [v23-17-11](17-frozen-decisions.md#v23-17-11) | 17: Q5 — PVE version, ACL and TLS compatibility |
| [v23-17-12](17-frozen-decisions.md#v23-17-12) | 17: Q6 — Storage, snapshots and recovery |
| [v23-17-13](17-frozen-decisions.md#v23-17-13) | 17: Q7 — Container definitions and image policy |
| [v23-17-14](17-frozen-decisions.md#v23-17-14) | 17: Q8 — Evidence and metric semantics |
| [v23-17-15](17-frozen-decisions.md#v23-17-15) | 17: Q9 — Read schemas and presentation |
| [v23-17-16](17-frozen-decisions.md#v23-17-16) | 17: Q10 — Later access/integrations |
| [v23-17-17](17-frozen-decisions.md#v23-17-17) | 17: Paragraph changelog for Spec v2.3 |
| [v23-17-18](17-frozen-decisions.md#v23-17-18) | 17: Revision markers |
| [v23-17-19](17-frozen-decisions.md#v23-17-19) | 17: Complete paragraph/block changelog |

<a id="v25-17-01"></a>
<!-- Spec revision (ADR 0013, EN-02): v25-17-01 -->
### Spec revision 2026-11-11: one-step enrollment (ADR 0013, EN-02)

<a id="v25-17-02"></a>
<!-- Spec revision (ADR 0013, EN-02): v25-17-02 -->
**Accepted revision and sources.** The maintainer accepted [ADR 0013: One-step host enrollment with pairing code and optional NetBird join](../adr/0013-one-step-enrollment.md) on 2026-11-11 (previously: proposed) and decided Q1–Q9 in its section "Decisions of the maintainer (2026-11-11)". The ticket plan is [`docs/implementation/one-step-enrollment.md`](../implementation/one-step-enrollment.md); this revision is its ticket EN-02 and is recorded in [spec 04](04-revision-history.md#v25-04-01). ADR 0013 takes precedence over this summary; where a ticket sets a detail the ADR leaves open (RPC messages, schema, NetBird response limits), the spec says so.

<a id="v25-17-03"></a>
<!-- Spec revision (ADR 0013, EN-02): v25-17-03 -->
**Authority review (ADR 0013).** Every authority one-step enrollment adds, with its holder, scope, limits, revocation and audit:

| Authority | Holder and exact scope | Limits and expiry | Revocation and audit | Spec, ADR 0013 |
| --- | --- | --- | --- | --- |
| Download endpoint `GET /enroll/<offer-id>` | `nebula-server`, unauthenticated, outside the UI auth chain; returns only the script of an open offer, once, via `FetchEnrollScript`; no other content | Offer single use and 15 min; 10/min and 60/h per client address (IPv6 per /64); 4096-bucket LRU table; script ≤ 64 KiB; uniform `404` for every refusal | Offer expiry or revocation ends it; `enroll_script_downloaded` with client and peer address; path never logged | [03 v25-03-05](03-processes-and-data.md#v25-03-05), [02 v25-02-01](02-architecture.md#v25-02-01); D2, D7 |
| "Show script" route (`ShowEnrollScript`) | `nebula-server` UI route, authenticated, creating web session only; returns the placeholder render of that offer's script; repeatable | Never consumes the offer, never changes its state, never reads the setup key from the vault; checks the placeholder render against the stored placeholder hash (never the download hash; previously: no hash check), a mismatch refuses only that request and audits `enroll_script_hash_mismatch` (variant `show`) at most once per offer; script ≤ 64 KiB; render error refuses only the request; shows the stored hash, or no hash for a NetBird offer in `awaiting_approval`; `no-store`, `nosniff`, sandbox CSP, no proxy buffering | Ends with the offer's final state or the end of the session binding; request carries client and peer address | [03 v25-03-04](03-processes-and-data.md#v25-03-04), [03 v25-03-05](03-processes-and-data.md#v25-03-05); D1, D2 |
| "Download in browser" route (`DownloadEnrollScript`) | `nebula-server` UI route, authenticated, creating web session only; releases the full script once, like the download endpoint; refused (without consuming) for offers with NetBird | Same single use, 15 min, hash check and uniform refusal as `GET /enroll/<offer-id>`; script ≤ 64 KiB | Offer expiry or revocation ends it; `enroll_script_downloaded` with client and peer address | [03 v25-03-02](03-processes-and-data.md#v25-03-02), [03 v25-03-05](03-processes-and-data.md#v25-03-05); D2, D7 |
| Trusted-proxies settings and client-address rule | `nebula-server` configuration: single proxy addresses, or networks declared proxy-only; decides whose `X-Forwarded-For` counts for the enrollment routes only | Header ≤ 1 KiB, ≤ 16 entries; unparsable entry or other prefix fails startup; refused header charges no bucket | Startup log of proxy-only networks; startup warning without trusted proxy on loopback/private/wildcard listener; refusals counted in a metric | [03 v25-03-06](03-processes-and-data.md#v25-03-06), [09 v25-09-01](09-untrusted-host-data.md#v25-09-01); D7 |
| Offer store | `nebula-executor`, `executor.db`: ID hash, salt, binding, state, script hash, every render input including the NetBird management URL and key-passing mode (so a re-render never reads live config), setup-key record, key ID, counters, orphan peers; never script bytes or plaintext setup key | 10 non-final offers, 30 per hour, 5 probes, 3 rejected codes, 1 mismatch; 2 non-final NetBird offers; 15 min lifetime; forward-only atomic state changes | UI revoke (any session of the user), `nebula host offer-revoke`; salt wiped at final state; offer events in [03 v25-03-04](03-processes-and-data.md#v25-03-04) | [03 v25-03-03](03-processes-and-data.md#v25-03-03), [03 v25-03-04](03-processes-and-data.md#v25-03-04); D2 |
| Offer session binding | The web session that created the offer may show, browser-download, submit, approve (Standard mode only; hardened mode approves only with `nebula approve`) and commit; other sessions read-only | Creation needs an open privileged session; lock, restart or session end does not resurrect the binding | Any session of the user and the admin CLI may revoke | [05 v25-05-02](05-authentication.md#v25-05-02); D2 |
| Paired enrollment permit | `nebula-executor` builds it after the executor's own constant-time code match; binds offer ID hash, host, endpoint, endpoint-to-add flag, SSH user, credential, full fingerprint, code matched | HIGH, user verification, single use, enrollment-permit expiry; commit re-probes and pins only the approved key | `enroll_paired_proposed`, `host_enrolled` (source `paired`), `inventory_endpoint_added`; `nebula approve` shows all bound fields | [05 v25-05-01](05-authentication.md#v25-05-01), [08 v25-08-01](08-ssh-transport.md#v25-08-01); D4 |
| NetBird offer permit | `nebula-executor`; binds offer ID hash, host, SSH user, credential, managed group, ephemeral flag, setup-key expiry; releases one setup key | HIGH, user verification, single use; 2 non-final NetBird offers, 5 keys per hour | `enroll_offer_approved`; `nebula approve` shows all bound fields | [05 v25-05-01](05-authentication.md#v25-05-01), [06 v25-06-02](06-credentials.md#v25-06-02); D1, D6 |
| NetBird peer delete permit | `nebula-executor`; binds peer ID, peer name, NetBird IP, offer ID hash, attribution method; needed only for peers attributed by the time-window fallback | HIGH, user verification, single use | `netbird_peer_deleted`; never automatic | [05 v25-05-01](05-authentication.md#v25-05-01), [06 v25-06-05](06-credentials.md#v25-06-05); D6, Q8 |
| NetBird peer delete, API-attributed | `nebula-executor` on request of an open privileged session; only an orphan or rogue peer the NetBird API attributes to this offer's setup key, in the managed group; no permit | One typed delete call per recorded peer ID; never automatic; unattributable peers are never offered for deletion | Operator may choose **keep** instead (`netbird_peer_kept`); `netbird_peer_deleted` with peer ID, attribution method, client and peer address | [06 v25-06-05](06-credentials.md#v25-06-05), [03 v25-03-06](03-processes-and-data.md#v25-03-06); D6, Q8 |
| NOS NetBird address in `from=` | `nebula-executor` reads it from the NetBird API (untrusted, spec 09) at offer creation and puts it into the root-granting `from=` option of the offer's script | Exactly one IP via `net/netip`, no prefix, zone, wildcard, comma, quote or other character, not unspecified/loopback/multicast/link-local, inside the NetBird range (executor-local, default `100.64.0.0/10`); re-encoded canonically and stored in the offer row | A failing value refuses the NetBird offer before any setup key exists; the stored value ends with the offer | [08 v25-08-02](08-ssh-transport.md#v25-08-02), [09 v25-09-01](09-untrusted-host-data.md#v25-09-01), [03 v25-03-03](03-processes-and-data.md#v25-03-03); D5, D6 |
| NetBird setup key and key ID from the create response | `nebula-executor` reads them from the create-setup-key response (untrusted, spec 09) after the NetBird offer permit; the key goes into the root-run script, the key ID only into the typed get-by-ID and revoke calls (previously: revoke call only) and text-only audit/CLI output | Setup key exactly 36 characters, uppercase hex UUID form 8-4-4-4-12 (`NetBirdSetupKeyLen`); key ID 1–64 characters `0-9a-z` (`NetBirdKeyIDMaxLen`; exact length recorded by EN-12); key name equals the requested `nos-offer-<prefix>`; checked on the decoded JSON string values, untrimmed and unnormalised, before vault write, record update or render (previously: on the raw bytes before vault write or render); key rendered only as a single-quoted literal | A failing value is never stored or rendered: offer `failed`, `netbird_setup_key_invalid` (failed check, no raw value), key revoked by a stored valid key ID (when the key name or setup key failed, only after a get by ID returns that ID with exactly the requested key name and every candidate property) or reconciled by the requested name only (previously: else by window and group when the create answered with a mismatched key name); a window-only match never revokes and alerts; foreign-key revocation residuals R1–R3 named in [06 v25-06-02](06-credentials.md#v25-06-02) | [09 v25-09-01](09-untrusted-host-data.md#v25-09-01), [06 v25-06-02](06-credentials.md#v25-06-02), [03 v25-03-04](03-processes-and-data.md#v25-03-04); D5, D6 |
| NetBird management token and egress | `nebula-executor` vault; dedicated NetBird service user; typed calls only (setup keys create/revoke, get by key ID, list without a name filter as one unpaginated request (`GET /api/setup-keys`, status `200`, bare JSON array, ≤ 10 000 keys, ≤ 16 MiB, no pagination sign), any other result truncated → alert, no revoke (previously: within named key, byte and page limits with an unnamed last-page indication; before that: create/revoke/list by name, no list limit), peers list/get, NOS peer, delete after confirmation, policies read) to the executor-configured management URL and TLS trust; no generic proxy | Role may be broader than needed (accepted, Q3); NOS never changes policies or groups | Set only by `nebula netbird token set` (admin UID, non-echoing); never in argv, environment, server or browser; never in errors or logs | [06 v25-06-01](06-credentials.md#v25-06-01), [02 v25-02-02](02-architecture.md#v25-02-02); D6 |
| Per-offer NetBird setup key | `nebula-executor` vault only; created after the NetBird offer permit under a persisted `pending` record with key name, managed group and creation time window; reaches the host only in the downloaded script | One use, ≤ 1 h (default offer expiry + 45 min, clamped to the 1 h cap), auto-group only the managed group, not ephemeral by default; not in "Show script", no browser download | Wiped and revoked unconditionally at every final state; retry 1 min then ≤ 5 min until revoked or expired; reconcile takes the key list first, then the record snapshot, and matches by exactly the requested key name only (previously: else by window and group for a record whose create answered with a mismatched key name; before that: by window for every record); never on a revoked, operator or other-offer key; zero or several matches, a name-mismatched record without a name match and a truncated key list (key, byte and page limits; one failing list entry or a named pagination header truncates the whole list, spec 09; previously: limits only) alert without revoke; residuals R1–R3 (foreign key with the requested name or a wrong key ID in a valid create response) and the late create named in spec 06; `netbird_setup_key_*` events | [06 v25-06-02](06-credentials.md#v25-06-02) – [v25-06-04](06-credentials.md#v25-06-04); D2, D6 |

<a id="v25-17-04"></a>
<!-- Spec revision (ADR 0013, EN-02): v25-17-04 -->
**Limit map (ADR 0013).** Every limit is a named constant next to the code that enforces it:

| Limit | Value | Specified in | ADR 0013 |
| --- | --- | --- | --- |
| Offer lifetime | 15 min in total (raising it up to 60 min is a later constant change, Q2; the 1 h setup-key cap then clamps the default setup-key expiry) | [03 v25-03-04](03-processes-and-data.md#v25-03-04) | D2, Q2 |
| Offer ID | ≥ 128 bits (recommended 160), SHA-256 at rest, 8-hex log prefix | [03 v25-03-04](03-processes-and-data.md#v25-03-04) | D2 |
| Offer salt | 256 bits | [03 v25-03-03](03-processes-and-data.md#v25-03-03), [08 v25-08-01](08-ssh-transport.md#v25-08-01) | Terms, D3 |
| Pairing code | 25 characters: 24 Crockford data (120 bits) + 1 mod-37 check | [08 v25-08-01](08-ssh-transport.md#v25-08-01), [09 v25-09-01](09-untrusted-host-data.md#v25-09-01) | D3, Q1 |
| Non-final offers / offers per hour | 10 / 30 | [03 v25-03-04](03-processes-and-data.md#v25-03-04) | D2 |
| Probes per offer | 5 | [03 v25-03-04](03-processes-and-data.md#v25-03-04), [08 v25-08-01](08-ssh-transport.md#v25-08-01) | D2, D3 |
| Rejected codes / mismatches per offer | 3 / 1 | [03 v25-03-04](03-processes-and-data.md#v25-03-04), [08 v25-08-01](08-ssh-transport.md#v25-08-01) | D2, D3, Q7 |
| Non-final NetBird offers / setup keys per hour | 2 / 5 | [06 v25-06-02](06-credentials.md#v25-06-02) | D2, D6 |
| Setup key | one use, ≤ 1 h from creation (default offer expiry + 45 min, clamped to the 1 h cap) | [06 v25-06-02](06-credentials.md#v25-06-02) | D6 |
| NetBird setup key / key ID format | exactly 36 characters uppercase hex UUID form / 1–64 characters `0-9a-z` | [09 v25-09-01](09-untrusted-host-data.md#v25-09-01) | D5, D6 |
| Setup-key revoke retry | first after 1 min, then at most every 5 min, until revoked or expired | [06 v25-06-03](06-credentials.md#v25-06-03) | D6 |
| NetBird join wait on the host | 60 s | [06 v25-06-04](06-credentials.md#v25-06-04) | D6 |
| Rendered script size | 64 KiB | [03 v25-03-04](03-processes-and-data.md#v25-03-04) | D5 |
| Download rate | 10/min, 60/h per client address, IPv6 per /64 | [03 v25-03-06](03-processes-and-data.md#v25-03-06) | D7 |
| Rate-limit table | 4096 buckets, LRU, never refuse because full | [03 v25-03-06](03-processes-and-data.md#v25-03-06) | D7 |
| Forwarded header | 1 KiB combined, 16 entries | [03 v25-03-06](03-processes-and-data.md#v25-03-06), [09 v25-09-01](09-untrusted-host-data.md#v25-09-01) | D7 |
| NetBird API response limits | setup-key list: `NetBirdKeyListMaxKeys` = 10 000, `NetBirdKeyListMaxBytes` = 16 MiB, `NetBirdKeyListMaxPages` = 1; setup-key get by key ID: `NetBirdKeyGetMaxBytes` = 64 KiB; every other NetBird call: named constants set by EN-11 (not ADR numbers) (amended 2026-11-11; previously: all "named constants set by EN-11") | [03 v25-03-04](03-processes-and-data.md#v25-03-04), [09 v25-09-01](09-untrusted-host-data.md#v25-09-01) | — |

<a id="v25-17-05"></a>
<!-- Spec revision (ADR 0013, EN-02): v25-17-05 -->
**Verifications pending before EN-12 (not open decisions).** ADR 0013 decided Q1–Q9; two facts are still to be established and recorded in the ADR before EN-12 starts: whether the NetBird management API attributes a peer to the setup key it joined with (Q8; otherwise the decided time-window fallback applies, with the NetBird peer delete permit for deletes based on it), and whether the reference lab uses self-hosted management or NetBird Cloud (Q3; both TLS trust settings are supported). EN-12 also records per supported NetBird client version whether it accepts the setup key by environment variable or key file; a version that accepts neither is not offered. EN-12 further records the exact key ID length of the reference-lab NetBird version, after which `NetBirdKeyIDMaxLen` becomes an exact length, and confirms that its setup keys have the 36-character uppercase UUID form; a NetBird version that issues another form is not supported until the ADR is amended.

<a id="v25-17-06"></a>
<!-- Spec revision (ADR 0013, EN-02): v25-17-06 -->
**Paragraph changelog (ADR 0013, EN-02).** Every changed or added block carries a `Spec revision (ADR 0013, EN-02)` marker and the stable anchor below. One existing sentence was changed in place: [spec 08](08-ssh-transport.md) "Enrollment" now names three ways to avoid blind trust (previously: two).

| Changed block | Short changelog |
| --- | --- |
| [v25-02-01](02-architecture.md#v25-02-01) | 02: One-step enrollment boundary, unauthenticated download endpoint |
| [v25-02-02](02-architecture.md#v25-02-02) | 02: Executor NetBird egress |
| [v25-03-01](03-processes-and-data.md#v25-03-01) | 03: One-step enrollment responsibilities per process |
| [v25-03-02](03-processes-and-data.md#v25-03-02) | 03: Enrollment socket methods |
| [v25-03-03](03-processes-and-data.md#v25-03-03) | 03: Enrollment data (offer store) |
| [v25-03-04](03-processes-and-data.md#v25-03-04) | 03: Offer lifecycle, limits and audit events |
| [v25-03-05](03-processes-and-data.md#v25-03-05) | 03: Download endpoint, headers, reverse proxy |
| [v25-03-06](03-processes-and-data.md#v25-03-06) | 03: Client address, trusted proxies, rate-limit table |
| [v25-03-07](03-processes-and-data.md#v25-03-07) | 03: Durable offer records and volatile approval |
| [v25-04-01](04-revision-history.md#v25-04-01) | 04: Spec revision 2026-11-11, one-step enrollment |
| [v25-05-01](05-authentication.md#v25-05-01) | 05: Paired enrollment, NetBird offer and NetBird peer delete permits |
| [v25-05-02](05-authentication.md#v25-05-02) | 05: Offer session binding |
| [v25-05-03](05-authentication.md#v25-05-03) | 05: Pairing-code trust anchor and approval deception |
| [v25-06-01](06-credentials.md#v25-06-01) | 06: NetBird management token custody |
| [v25-06-02](06-credentials.md#v25-06-02) | 06: Per-offer setup keys and creation order |
| [v25-06-03](06-credentials.md#v25-06-03) | 06: Setup-key revocation at the final state |
| [v25-06-04](06-credentials.md#v25-06-04) | 06: Setup key on the target host |
| [v25-06-05](06-credentials.md#v25-06-05) | 06: NetBird peers: cross-check, orphans, deletion, policy warning |
| [v25-08-01](08-ssh-transport.md#v25-08-01) | 08: Paired enrollment (third way to avoid blind trust) |
| [v25-08-02](08-ssh-transport.md#v25-08-02) | 08: One-step enrollment script and compatibility |
| [v25-09-01](09-untrusted-host-data.md#v25-09-01) | 09: One-step enrollment input |
| [v25-12-01](12-inventory.md#v25-12-01) | 12: One-step enrollment dialog |
| [v25-12-02](12-inventory.md#v25-12-02) | 12: Endpoint added at commit |
| [v25-17-01](#v25-17-01) – [v25-17-06](#v25-17-06) | 17: Accepted revision, authority review, limit map, pending verifications, changelog |
