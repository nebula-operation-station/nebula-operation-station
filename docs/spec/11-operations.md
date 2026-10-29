<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Operations: patching, services, Docker

<a id="v23-11-01"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-11-01 -->
V1 covers Debian/Ubuntu patching, systemd services and Docker operations, with bounded read-only scheduling/on-demand leases. PVE phase 1 adds observations and proposals; phase 2 enables the exact approved mutations below. No mutation runs unattended.

**Supported targets for 0.1.** Official support covers **Debian 12, Ubuntu 22.04 LTS and Ubuntu 24.04 LTS**. **Proxmox VE 8 and 9** are additionally supported as Debian-based managed hosts with adapter-specific behavior such as `full-upgrade`. Other Debian derivatives are best-effort/unsupported until explicitly added to the support matrix.

**Patching.** Per host: normal, security and kernel updates, reboot required, last refresh, last patch. Actions: refresh metadata, check updates, install security updates, install all updates, check reboot required, reboot. Release upgrades are not patch actions.

- Security updates are the packages whose candidate comes from the security archive (`-security` on Ubuntu, `debian-security` on Debian); they are installed with `apt-get install --only-upgrade`. Dependencies from other archives can come along, and the result lists them.
- All apt calls use `DEBIAN_FRONTEND=noninteractive`, `--force-confold` and `DPkg::Lock::Timeout=600`. On apt older than 1.9.11 the adapter waits for the lock itself. A lock still held after 10 minutes, for example by unattended-upgrades, ends as `precheck_failed` with the reason.
- Proxmox VE nodes are detected by `os.facts`: “install all” becomes `full-upgrade`, as Proxmox requires, and the host's default criticality is HIGH.
- Prechecks: free space on `/` and `/var`, package lock, `dpkg --audit` clean, filesystem writable.
- Postchecks: `dpkg --audit` clean, reboot required, failed systemd units compared before and after, Docker state if present, host reachable.
- Reboot is a separate durable action. The executor waits for SSH and fresh facts; past the timeout the result is `host_not_returned`. No reboot after patching in V1.

**Services.** list, status, start, stop, restart, reload, recent journal lines (capped). Risk comes from core metadata and host criticality, not from the UI.

**Docker.**

<a id="v23-11-02"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-11-02 -->
- Standalone containers: inventory, state, health, image and tag, current and available digest, ports, mounts, logs, start, stop, restart. Phase 2 may recreate only from an operator-supplied complete reproducible creation definition and an exact approved plan. Never reconstruct from sanitized `docker inspect`: devices, GPU bindings, env/secrets, capabilities, ulimits, sysctls, log drivers, health checks and networking are easily lost. Unsupported/incomplete definitions disable update rather than guess.
- Digest checks prefer manifest HEAD, but every HEAD/GET consumes request budgets; never assume HEAD is unlimited or exempt from registry pull/abuse limits. Default same-tag checks remain daily, with cache/rate-limit handling below.
- Compose stacks use `com.docker.compose.project.working_dir` and `com.docker.compose.project.config_files` as hints, validated against approved project/config identities. Before tree updates ship, extend the durable versioned `docker.compose_update` contract beyond project-only `pull; up -d`: freeze every affected service/replica/dependency and approved immutable image digest, preserve configuration through a reviewed digest override and prohibit implicit project-wide changes. Keep preflight/postflight and durable reconciliation.
- Postflight compares running containers, health, published ports and container count before and after; a regression gives WARNING or FAILED.

<a id="v23-11-03"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-11-03 -->
**Read refresh.** Update lists, facts, Docker/service observations and manual Refresh now use the read-only allowlist and shared ordinary/provider/telemetry budgets in [07-execution-model.md](07-execution-model.md). A selection or parent box must resolve to exact frozen targets before grant/plan approval. Showing cached age and next eligible time is mandatory when throttled. Read grants cannot cover package metadata refresh, logs, pulls, updates or rollback.

<a id="v23-11-04"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-11-04 -->
**Image metadata and stable versions.** Reuse host-side `docker.check_updates` typed results for running and stopped containers; same-tag update means a changed applicable platform manifest, not necessarily a newer release. An index change only on another architecture is not a local update. Keep image configuration ID, manifest/index digests, OS/architecture/variant and bounded image/container creation times distinct. Missing/incomparable digests remain unknown; digest-pinned images stay pinned and show advisory candidates only. Default latest stable is the highest numeric SemVer `MAJOR.MINOR.PATCH` tag, optional leading `v`, no prerelease suffix; ignore `latest`, `edge`, `nightly` and non-version tags. Build metadata does not order versions; equal-precedence tags with different digests are ambiguous. Reviewed per-image extraction/variant, major/range or explicit stable-tag overrides are versioned; tag changes need approval. Never mix variants/architectures. Incomplete pagination or no supported matching tags means unknown, never up to date; stable is not a compatibility/security guarantee.

<a id="v23-11-05"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-11-05 -->
**Registry metadata authority.** The server holds only anonymous public metadata egress to administrator-approved HTTPS registry/auth origins; the executor alone holds private metadata credentials and typed repository/tag grants. Validate TLS and repository references, reject redirects/environment proxies, and prevent host references, pagination links and auth challenges from selecting arbitrary origins/private addresses. Private-network registries require explicit executor-side origin approval. No metadata path pulls layers. Private grants bind credential scope/version and the normal read-grant expiry/revocation/audit; lock, rotation and expiry stop their use. Public reads remain possible while the vault is locked. Audit origin approvals/changes and lookup scope, throttling, denials and outcomes without credentials/raw bodies. The ADRs leave the public-origin approval holder/interface, independent expiry and revocation semantics, private auth profiles and credential lifetime/removal workflow open; [17-frozen-decisions.md](17-frozen-decisions.md) records these explicitly. No unreviewed credential or arbitrary egress exception is implied.

<a id="v23-11-06"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-11-06 -->
**Registry cache and request limits.** Cache by registry/repository/tag/platform/policy, plus private credential scope/version: same-tag checks 24 h, stable tag lists 24 h, failures 15 min, immutable digest metadata 7 days. Coalesce in-flight reads and share caches across hosts. Per registry: one request/s, two concurrent requests, 1 MiB/response, 10,000 tags/scan and bounded pagination. Exhausted budgets leave a scan incomplete. Manual refresh shares budgets. Manifest HEAD, bounded index/config GET and tag-list calls all consume request allowance. Honor remaining/reset and `Retry-After`; on 429 pause with jittered exponential backoff, minimum 15 min, without hard-coding subscription quotas. Show cached/stale/rate-limited state. Release notes require a reviewed per-image HTTPS upstream/template and validated version, open with `noopener noreferrer`; otherwise show unavailable, never fetch/render arbitrary image-label URLs or HTML.

<a id="v23-11-07"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-11-07 -->
**Local image CVE observations.** Optional phase-1 `image.vulnerabilities` uses operator-installed Trivy on the enrolled Docker host and an already-local immutable image. Use a reviewed local-only profile, bounded runtime/output, one concurrent scan/host, coalesced by image digest/platform/database version and cached at most 24 h. NOS never installs the scanner, pulls images, refreshes its database or exports image layers/credentials. Database provisioning/refresh is operator-managed. Show unique CVE counts, severity, scan/database age and coverage; disabled, missing/stale database, failed or unsupported scans are unavailable/stale, never zero. Findings are advisory and never authorize updates; no raw scanner output, image configuration/files or secrets enter the spool. Exact scan/cadence/severity rules remain open.

<a id="v23-11-08"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-11-08 -->
**PVE action profiles and risks.** Phase 2 starts with lifecycle baseline only; snapshot/backup/configuration/migration/node reboot require individually verified profiles. Effective risk is the maximum of the built-in floor, executor-owned remote/node/guest criticality and every affected linked-host floor; unknown criticality defaults HIGH. LOW remains read-only. Risk-relevant links require admin confirmation in the executor registry; server link edits/deletion cannot remove a recorded floor. `ProxmoxOFS1` stays read-only by default; any future offsite node reboot is CRITICAL, manual and needs an agreed recovery path. Recheck risk/identity before dispatch and retain ordinary presence/UV/target-count/hardened approval rules.

<a id="v23-11-09"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-11-09 -->
| Typed action | Base risk | Exact constraints |
| --- | --- | --- |
| VM/LXC start | MEDIUM | Exact guest incarnation; never LOW |
| Graceful shutdown/reboot | MEDIUM | ACPI/agent or LXC graceful operation; never automatic force-stop fallback |
| Hard stop/reset | HIGH | Explicit destructive verb; LXC reset unavailable unless separately specified |
| Snapshot create | MEDIUM | Name, disk set, RAM choice and storage/guest capability checks |
| Snapshot delete/rollback | HIGH | Exact snapshot identity/generation; explicit start/RAM effects for rollback; no automatic deletion/rollback |
| Backup now | MEDIUM | Exact guest/storage/mode/bandwidth; no pruning/deletion flags |
| Configuration change | HIGH | Allowlisted fields, old configuration digest, secret values executor-side |
| Intra-cluster migration | HIGH | Source/destination nodes/storage mapping; HA-aware, no passthrough live migration |
| Node reboot | HIGH standalone; CRITICAL cluster | Exact node/all impacted guests, HA evacuation/quorum gates, max one node at a time |
| OS update | Existing MEDIUM base for security/all installs | Exact enrolled host/key, existing SSH adapter/pre/postchecks/stages, PVE full-upgrade retained; reboot separate |
| Container same-tag refresh/rollback | MEDIUM | Exact container/configuration and from/to immutable digests; pull/recreate, never just restart |
| Container tag/version change or reversal | HIGH | Also bind old/new tag and policy, explicit version, no implicit major upgrade; container update/rollback refuses any CRITICAL floor |

<a id="v23-11-10"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-11-10 -->
**HA and node safety.** For HA-managed guests use the HA manager, including guest endpoints only when verified to delegate for the exact supported QEMU/LXC version/action. Never bypass HA, set `ignored`, treat desired state as completion or grant broad `Sys.Console` on `/` for direct HA updates. Reboot/reset without a verified HA-safe route stays disabled. Observe desired and actual guest state. Node reboot additionally needs fresh executor-read votes/qdevice/HA checks after evacuation, a cluster-wide reboot lock and post-return quorum checks before another node. Stale/unknown state blocks it. Passthrough guests are ineligible for live migration and RAM snapshots; disk/storage/format capabilities are yes/no/unknown, not inferred from a storage label. Pending version/ACL/HA/storage verification is recorded as an open question.

<a id="v23-11-11"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-11-11 -->
**Exact tree updates.** Tree buttons only propose existing executor operations. Parent selection/expansion never authorizes descendants; freeze host/container/service/replica/dependency sets and reuse DEV/QA/PROD, canary/waves, gates and stop thresholds. ADR 0007 member stages govern mixed actions and multiple containers per host; reconcile/postcheck each member. OS updates use existing SSH actions, never the PVE token or a new patch engine; unenrolled nodes/guests remain read-only. Bind host/key, full container ID and name, repository/platform, old/new tag, from/to image digests (index/platform as applicable), configuration digest, exact affected set, credential version and stage plan into canonical parameters. Recheck current identity/configuration/digest, pull only the approved immutable digest and verify it. A moved tag or changed target/configuration requires a new proposal.

<a id="v23-11-12"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-11-12 -->
**Container recreation and rollback.** Preserve the complete configuration except the approved image reference. Secrets/creation definitions stay executor/host-side, never in tree/results. Private pulls require a reviewed executor-mediated SSH transfer/load profile with registry credentials retained by the executor, never target Docker login files; unsupported profiles remain disabled. Retain the old image by digest and executor-owned recreation definition through an explicit rollback window, default 7 days, with no automatic prune. Rollback is separately approved exact-target recreation of the prior digest/configuration, with health, ports, mounts/network and service/replica-count postchecks. A failed update stops rollout; reconcile uncertain recreation before retry/rollback, and bind the new container incarnation for subsequent actions. Image rollback cannot undo volume/database migrations: require a declared data backup/recovery plan or mark rollback unavailable. Cleanup cannot delete a retained rollback image. Container update/rollback has no CRITICAL variant; refuse any such floor without downgrade.

<a id="v23-11-13"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-11-13 -->
**PVE task completion.** Use executor-owned intent/UPID persistence, typed polling and postchecks from [07-execution-model.md](07-execution-model.md); accepted API requests are not success. Neither failover nor restart reissues uncertain mutations. Cancellation of undispatched work does not cancel an accepted remote task; task cancellation needs separate approval.

<a id="v23-11-14"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-11-14 -->
**Later orchestration.** Phase 3 snapshot-before-update composes into the same stage engine for VM OS/in-guest container updates only on verified snapshot-capable storage. Immediately recheck generation, disks, passthrough, storage and consistency/quiescing; unknown blocks the option. Snapshot failure stops that target's update; opt-out needs an explicit revised plan, never silent fallback. Snapshot, patch, rollback and cleanup each need the appropriate exact-target authority, with no standing HIGH deletion/automatic rollback grant. Offer an explicit backup alternative when snapshots are unavailable. Provisioning binds template, destination, new VMID, IPAM reservation and configuration and then follows normal SSH enrollment. Console credentials/relay and hypervisor shell remain outside this authority revision pending separate review.
