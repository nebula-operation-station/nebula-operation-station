# ADR 0006: Proxmox VE remotes, inventory and executor-owned actions

Status: accepted by the maintainer, 2026-10-29

## Context

NOS should understand where a Linux guest runs and offer controlled hypervisor
operations without becoming another Proxmox web UI. The requirements source is
the maintainer's `proxmox-ideas.md` (2026-10-27): one cluster, `NebulaNetwork`,
and 2..n standalone hosts, including intermittent `poxmox` and offsite
`ProxmoxOFS1`. VMIDs collide between remotes; passthrough and HA matter.

Spec [02](../spec/02-architecture.md), [03](../spec/03-processes-and-data.md),
[05](../spec/05-authentication.md), [06](../spec/06-credentials.md),
[07](../spec/07-execution-model.md), [08](../spec/08-ssh-transport.md),
[09](../spec/09-untrusted-host-data.md), [10](../spec/10-modules.md),
[11](../spec/11-operations.md) and
[12](../spec/12-inventory.md) define the trust boundary, approvals and staging.
Spec 01 currently excludes monitoring dashboards and scheduled mutations.
This proposal adds a built-in HTTPS provider, not a server-side module plugin.
Acceptance requires a reviewed spec revision before implementation; this ADR
does not silently extend the SSH-only transport or authorize automation.
Spec 11 also forbids standalone-container recreation from inspect; phase 2
requires an explicit revision and a complete approved configuration source.

[M0 decisions](../implementation/m0.md) also apply: vault ciphertext is in
`executor.db` (decision 41), permits and privileged sessions are memory-only,
restart revokes them, risk is executor-derived, and read schedule grants are
distinct from permits (decisions 15, 20–24, 61). No new dependency is proposed;
use Go `net/http`, `crypto/tls`, `crypto/x509` and existing security primitives.

## Decisions

### Remote identity and TLS trust

- A remote is exactly one PVE cluster with ordered node API endpoints, or one
  standalone PVE host with one API endpoint. VPN routing does not create another
  remote. Endpoint aliases for standalone hosts are deferred.
- Assign an immutable local `remote_id`; names are labels. Nodes are identified
  by `(remote_id, node)`, guests by `(remote_id, vmid)`; record QEMU/LXC kind.
  Moving within a cluster changes location, not identity. A cross-remote move
  creates another identity and requires explicit relinking.
- VMID reuse after deletion must not inherit links, criticality or approvals.
  Keep tombstones and a local guest generation, comparing available UUID,
  creation/config metadata and MACs. Ambiguity suspends actions and requires
  review; PVE does not provide a universal immutable guest incarnation ID here.
- The executor owns authoritative endpoints, pins, credential references,
  criticality and generations. Server tables are presentation copies only.
  Reject registration of the same trust identity under a second remote ID,
  preventing aliases from lowering risk. Names never authenticate a remote.
- Pin the cluster CA certificate's SHA-256 DER fingerprint; verify every leaf
  against that exclusive root, its validity and configured DNS/IP SAN.
  For standalone hosts, pin the served leaf certificate and still check validity
  and SAN. Do not silently fall back to system roots or accept any certificate.
  PVE's default node certificates use its cluster CA; custom proxy certificates
  need an explicit compatible trust choice ([certificate documentation][certs]).
- Adding a remote happens through the admin CLI on the executor host. Probe
  without credentials; display each endpoint, leaf and CA fingerprint. Import
  the CA from a trusted local file for a cluster, compare fingerprints out of
  band, and require typed `yes` before storing trust or sending either token.
  A server-supplied CA or unauthenticated API response cannot establish trust.
- A changed pin, invalid chain or SAN mismatch blocks the whole remote
  persistently, emits an executor event and notification, and stops failover.
  Re-pin is an explicit admin operation requiring the old and new fingerprints
  and HIGH user-verified approval; it increments trust generation and revokes
  affected grants and permits. CA-preserving leaf renewal needs no re-pin.
- Only connection failures/timeouts allow ordered endpoint failover for reads.
  Authentication failure stops the request. A mutation with an uncertain outcome
  is reconciled, never repeated at another endpoint. Endpoints are admin-approved
  HTTPS origins (normally port 8006); disable redirects and environment proxies.
  Discovery never adds dial targets, and credentials never follow API URLs.

### Credential custody and least privilege

Both tokens stay envelope-encrypted in the executor vault and are decrypted
only there. A collector-held read token would isolate HTTP parsing from the
executor, but would create another secret store, unlock path and credential
exception to spec 02/06. Choose executor custody and keep parsing small and typed.
Phase 1 installs only the read token; the action token is optional until phase 2.

`nebula-pve-collector` runs as its own Unix user with a new `pve-collector`
peercred role, no capabilities, network listener, database access or credentials.
It schedules typed reads over the executor socket and writes sanitized results
to a spool, following discovery's ownership split. The executor alone contacts
PVE. The server imports the spool and renders it; it never performs PVE API calls.
Collector socket membership is not authority: its UID may call only provider
metadata/read methods, never unlock, approve, propose mutations or reveal secrets.

Use separate noninteractive PVE users per remote and purpose, with expiring,
privilege-separated tokens (`privsep=1`). Grant both user and token the needed
ACLs: effective rights are their intersection ([PVE user management][users]).
No `root@pam`, passwords, `Administrator` or `PVEVMAdmin` token is accepted.

| Token/profile | Exact privileges and ACL scope |
| --- | --- |
| `NOSRead`, all supported versions | `Sys.Audit` on `/` for cluster/HA and node/task metadata; `VM.Audit` on `/vms`; `Datastore.Audit` on `/storage`; `Pool.Audit` on `/pool`, propagated to children |
| Read guest-agent extension, PVE 9 | `VM.GuestAgent.Audit` on `/vms` or selected `/vms/<vmid>`; only informational methods enabled |
| Action baseline | `VM.PowerMgmt` on explicitly enabled `/vms/<vmid>`; prechecks and task observation use the read token |
| Snapshot extension | `VM.Snapshot` on enabled guests; add `VM.Snapshot.Rollback` only where the supported version requires it for rollback |
| Backup extension | `VM.Backup` on enabled guests and `Datastore.AllocateSpace` on the selected `/storage/<id>` |
| Configuration extension | Only needed members of `VM.Config.CPU`, `VM.Config.Memory`, `VM.Config.Network`, `VM.Config.Cloudinit`, `VM.Config.Options`, `VM.Config.Disk`, `VM.Config.CDROM`, `VM.Config.HWType` on enabled guests; `SDN.Use` on exact approved bridge/VNet paths and `Datastore.AllocateSpace` on exact storage where required |
| Intra-cluster migration extension | `VM.Migrate` on enabled guests; exact destination storage allocation/mapping privileges only for an explicitly supported migration profile |
| Node reboot extension | `Sys.PowerMgmt` on the exact `/nodes/<node>`; disabled by default |

These are feature-specific unions, not a role containing every extension.
Phase 2 initially enables only the baseline; extensions add rights to that
action token only for enabled features. Before enabling another profile,
document its endpoint/parameter ACL checks for each supported PVE minor version;
an unverified additional privilege keeps that feature disabled, never widened
to an admin role. Pools changing membership cannot widen the action token scope.
No console, guest exec, guest file access, permission administration, storage
deletion or HA-configuration privileges belong to either default token.

The read role is an explicit PVEAuditor-like subset, avoiding changes to the
built-in role across releases. PVE 9 informational agent methods use the granular
privilege ([agent API source][agent]); PVE 8's legacy `VM.Monitor` is broader.
Do not grant it to a read-only token: agent-derived fields on PVE 8 remain
unavailable unless a future separately reviewed safe mechanism is provided.

PVE privileges are coarser than NOS risks. In the inspected QEMU API,
`VM.Snapshot` permits deletion and can also authorize rollback. Separating these
rights with tokens alone is insufficient ([QEMU API source][qemu]). The executor
must enforce distinct typed actions, parameters and permits; there is no generic
HTTP verb/path proxy. The same principle applies to `VM.PowerMgmt` and backup
rights, which can authorize more than the operation NOS exposes.

Proposed CLI family: `nebula pve remote add|rotate-token|remove|repin`.
Only the authenticated admin UID on the executor host may call these methods.
Enter token values via a non-echoing terminal or stdin, never argv, environment,
server configuration or browser. Store only opaque references and versions in
metadata. Do not log headers, raw bodies, URLs with credentials or token IDs
containing unnecessary account information; CLI output never echoes secrets.

Rotation imports a separately created token, validates it against pinned TLS
and its permission profile, then atomically changes the credential version.
Revoke pending permits/read grants using the old version; reconcile existing
jobs read-only with the replacement, without redispatch. The admin revokes the
old token in PVE after verification. Removal first disables the remote and
revokes its authorizations, then removes NOS secrets; PVE-side revocation is
also required. Removal/rotation cannot undo already running PVE tasks. Keep
nonsecret audit/tombstone data. Vault lock/restart stops new authenticated reads
and mutations until local unlock; stale inventory remains visible.

### Phase 1 read path and stored observations

The proposed spec revision adds a provider read grant: exact remote ID, trust
and credential versions, typed enumeration methods, minimum intervals, request
budgets and expiry (at most 90 days), approved locally by the admin. It is
durable read authority, never a mutation permit. Enumerations are scoped to
that remote; the executor resolves and validates every child node/guest request.
Do not retrofit 10-second reads into existing SSH grants with a 15-minute floor.
The spec revision must separately authorize bounded SSH telemetry leases; until
then, guest-internal and bare-metal values keep their permitted cadence.
Lock pauses these grants; re-pin, rotation, removal or expiry invalidates them.
The collector and a compromised server cannot widen their scope or frequency.
The server writes typed poll/lease requests to the spool's request directory;
the collector alone writes results. Neither accepts URLs or raw API paths.

| Observation | Default cadence and phase-1 scope |
| --- | --- |
| Nodes and QEMU/LXC inventory | Every 60 s: names, kind, location, running/stopped state, uptime and resource totals |
| Guest configuration | Every 5 min: CPU, RAM, disk/storage references, NIC MAC/bridge/VLAN, boot order, `hostpci` device/target mappings, nonsecret Cloud-Init IP configuration, tags and pool membership |
| Guest interfaces | Every 60 s where supported: QEMU agent IP/MAC/hostname/OS/filesystem summary; LXC interfaces from its typed API, explicitly labelled by source |
| Snapshots and storage | Every 5 min: snapshot names/time/parent/RAM flag; storage type, format, availability, capacity and supported features; never image or backup contents |
| Backups | Every 5 min: available nonsecret `vzdump`/PBS metadata and recent task summaries; freshness warnings are phase 1, with source/coverage/age and unknown states; distinguish task success from a currently present/restorable backup |
| Cluster and HA | Every 60 s: membership, votes/quorum, HA resource desired/observed states, maintenance; replication/Corosync-link summaries where readable |
| Node details and foreign activity | Every 15 min: PVE/kernel versions and bounded task metadata (actor, type, time, target, exit status); no raw task logs or command output |

Full backup listings are **not guaranteed** with a read-only token: storage
content is filtered using `VM.Backup` and `Datastore.AllocateSpace` checks
([volume access source][storage], [content listing source][content]). Do not
borrow the action token or add write privileges for inventory. Show
`unavailable: insufficient read privileges`; task history is merely evidence
of a past run. PBS retention/verification requires a separately approved
read-only source; it gets no new credential integration implicitly.
Compare the last evidenced successful backup against an operator-selected
maximum age (default 24 h), separately displaying catalog presence, verification
and restore confidence. Stale, failed and overdue evidence warns in phase 1;
denied catalogs and missing samples stay unknown/unavailable.
Missing visibility must never become “no backups” or “backup safe”.

Store normalized observations in the server's `nebula.db`: `pve_remotes`,
`pve_nodes`, `pve_guests`, `pve_guest_configs`, `pve_interfaces`, `pve_snapshots`,
`pve_backup_observations`, `pve_storages`, `pve_cluster_status`, `pve_tasks`,
`pve_host_links` and `pve_staging`. All remote children carry `remote_id`;
guest records carry VMID and generation. Include `observed_at`, `source`,
collection generation and completeness/availability reason per dataset.
Commit each validated dataset atomically. A partial poll does not erase unseen
guests; only a complete enumeration can tombstone them. Keep current inventory,
30 days of task/drift metadata, and explicit link/tombstone history. Store
normalized machine/container/GPU metric samples and backup/scan evidence with
the same source, identity/incarnation and availability fields; never raw outputs.

Defaults: one poll per remote at a time, two concurrent API requests per remote,
10 s connect/30 s request timeouts, jitter and exponential backoff capped at
15 min. Mark a dataset stale after three missed intervals. `poxmox` may be
configured on-demand: expected offline is grey UNKNOWN with a reason, not an
alarm. Offsite reads tolerate VPN loss without changing trust or endpoints.

Every response is untrusted, including config, labels and task metadata. Use
named limits: 1 MiB decoded per response/spool page, 1,000 objects per page,
10,000 guests per remote, 128 interfaces per guest, 4 KiB per text field,
bounded nesting and pagination; oversize/incomplete results are marked as such.
Validate UTF-8, identifiers, numeric ranges and schemas; drop unknown fields.
Forward only allowlisted fields: discard Cloud-Init passwords, SSH keys,
snippets, descriptions, hook scripts and storage credentials before spooling.
Never persist raw API responses/errors. Render text through escaped templates.
Spool files use separate writer directories, no symlink following, bounded
reads, atomic writes and collection IDs; revalidate at server ingestion.

An explicit reviewed `(remote_id, vmid, generation)` link is authoritative for
display, never proof of an SSH identity. MAC matches suggest links; IP/hostname
matches are POSSIBLE MATCH, with conflicts shown. No automatic merge by VMID,
IP or hostname; cloned MACs also require review. Unmanaged guests enter staging
as NEW/EXISTING/POSSIBLE MATCH/CONFLICT. Import preserves the asset identity and
still requires ordinary SSH enrollment and host-key pinning.

Show IP/RAM/node/status drift against the linked host and IPAM; accepting a hint
is explicit and audited. Guest IPs never silently replace SSH endpoints or
criticality. Proxmox tags/pools are source-labelled suggestions, not automatic
NOS groups/environments or rollout membership. Docker/services appear below
linked guests only from existing SSH observations, not inferred from PVE.
PVE state explains Ops State without declaring SSH healthy. Subscription and
ZFS-health details needing more rights remain unavailable; obtain pending
PVE/Debian packages through the node's ordinary NOS SSH enrollment below.

Capabilities are yes/no/unknown hints computed from all attached disks, formats,
storage support, passthrough and guest state. `Datastore_4TB_NVME` plain LVM is
expected to lack snapshots in this lab, pending version/config verification.
Do not equate every ZFS/LVM-thin guest with snapshot safety, or local storage
with an absolute migration ban. Phase 1 treats passthrough guests as ineligible
for live migration and RAM snapshots; phase 2 repeats authoritative prechecks.

Metrics have two bounded paths: collect one sample per 5 min for 24 h of
history (288 buckets per target/metric), and refresh live values every 10 s
while the page is open and visible. Compute 24 h averages server-side from
valid collected buckets; show coverage/age, never fill missing samples with
zero or call a short history a full-day average. Live samples update the current
value and the corresponding bucket, not an unbounded raw history. Retention
prunes buckets older than 24 h; identity/generation changes start a new series.

PVE node and QEMU/LXC CPU/RAM use typed status/RRD API reads; PVE disk allocation
or I/O is not filesystem utilization. Fullest-filesystem DISK and all mount
usage, OS patch state, Docker and NVIDIA driver data use the existing NOS
read-only SSH action pipeline on explicitly enrolled bare-metal/node/guest
hosts. Never use guest exec or infer an SSH endpoint. Without an enrolled
filesystem source, DISK is unavailable even if PVE capacity is known.

A visible chart/details page renews a 30-second exact-target read lease;
closing/hiding it ends renewal. Bind targets to remote/node/VMID/generation or
SSH host/key and read-grant versions. Coalesce viewers; cap each remote at
four live targets and one metrics request/s, prioritize visible boxes and label
budget-deferred boxes with their last observation age. SSE delivers sanitized
values every 10 s; it confers no execution authority. Background 5-min history
and short SSH telemetry leases require the reviewed grant revision above,
with per-host budgets; they cannot bypass the current SSH schedule floor.
No InfluxDB endpoint or general monitoring dashboard is introduced.

| SSH observation/action | Phase-1 contract and executor base risk |
| --- | --- |
| Existing `core.facts`, `package.list_updates`, `service.list/status`, `docker.list/inspect` | Reuse LOW read-only observations; extend sanitized `docker.inspect` with creation/platform/digest fields, never env/secrets |
| New `host.metrics`, `filesystem.list` | LOW, read-only: bounded CPU/RAM percentages and per-filesystem used/total/percent; identify the fullest filesystem and retain mount details |
| New `pci.inventory`, `gpu.status` | LOW, read-only: NVIDIA PCI identity on the owning machine; fixed `nvidia-smi --query-gpu` fields for GPU UUID/PCI ID, util %, VRAM used/total, temperature and power; no arbitrary command/flags or device changes |
| New `docker.stats` | LOW, read-only: one bounded non-streaming CPU/RAM snapshot keyed by full container ID; Compose grouping derives from validated list/inspect hints |
| New `service.check` | LOW, read-only: bounded HTTP/TCP port, health and latency checks from the enrolled host; explicit approved destinations, no redirects, arbitrary URLs or response bodies; unknown if unconfigured |
| New `image.vulnerabilities` (optional) | LOW, read-only: sanitized CVE counts/severity, image identity and scanner/database age from an operator-installed host-local scanner |

LOW is the base class, not an exemption from executor-derived host/trust floors
or read grants. Missing tools/drivers/permissions return unavailable, never a
successful zero. Apply the response/text/count/time limits above to SSH results
and reject malformed numbers, unsupported schemas and changed incarnations.

### Phase 1 inventory org chart and patch state (read-only)

Reuse `internal/web/ui/{inventory,hosts,stages}.go`,
`web/templates/{inventory,host,layout}.html` and the existing external
`web/static/{inventory.js,host.js,app.css}` assets/patterns. Inventory already
batches package/container/failed-service counts; host tabs show their details. Reuse
`internal/executions/observe.go`/`osdebian` for package data and `dockerhost`
parsers for container results; do not create another SSH collector or dashboard.

The display model is PVE node → VM/LXC → optional Compose stack → Docker
container → service; a Compose project is a grouping box, not another host or
a source of action authority. Its reviewed identity includes the host and
project/config identity; spoofed labels do not prove membership. Bare-metal
managed hosts are roots with containers/services directly below them. Nodes and
guests may also have direct services/containers. Existing reviewed host links
attach SSH observations without duplicating the managed host as another box.
Container identity is `(host_id, full container ID)` with name as a label;
recreation produces a new incarnation. `docker.list` supplies image reference,
state/health, ports and Compose project/service/working-directory hints;
`docker.inspect` supplies image ID, repository digests and runtime details.
Neither currently exposes creation time; add bounded container `created_at`
and image `created_at` fields, keeping image configuration ID distinct from
registry manifest/index digests and recording OS/architecture/variant.

Services already exist as systemd `service.list`/`service.status` observations,
keyed by host and unit. Compose service labels identify logical container
services (including replicas), not systemd units or proof of arbitrary workloads
inside a container. Store explicit service → host/guest/container associations
with source/time; use Compose labels as hints and require review for other
links. Missing service discovery stays unknown; do not inspect processes or
infer relationships from matching names. A service has one placement; replicas
are distinct instances. Add placement, image, telemetry, backup and scan
observations; reuse existing host/update/execution results as the underlying
read model rather than copying their data into another inventory.

The desktop view is an **org chart**: boxes connected by lines, laid out
left-to-right by level, with siblings stacked **vertically** in a column. A
host is on the left, its VMs form the next column, each VM's containers the
next, and services sit to their right. Reserve each subtree's vertical extent
so branches do not overlap: many siblings grow the chart downwards, never into
side-by-side cards or a wide horizontal sibling strip. Long columns scroll
vertically; fit the fixed depth to the viewport, with pan, Ctrl+wheel zoom and
“fit to screen” for navigation. There is no orientation toggle. At ≤600 px,
automatically fall back to an indented list via CSS, retaining the same data,
collapse controls and details links.

| Box | Compact content |
| --- | --- |
| Host / PVE node and VM/LXC (~220×110 px, expandable for GPU lines) | Name (+VMID for guests), status dot with text, OS/PVE version, patch state `⬆ n updates` / `✓` only for a complete fresh check; CPU, RAM, DISK mini bars each show current % and 24 h average `⌀`. Bar color uses current value: ≥70% yellow, ≥90% red. DISK is the fullest filesystem; hover/focus reveals every filesystem |
| NVIDIA GPU, inside its owning machine box | Node PCI device plus passthrough target from guest `hostpci`, e.g. `RTX A6000 → bigai (101)`; guest with the driver shows a GPU mini-bar block with util %, VRAM used/total, temperature and power from `gpu.status`. Bare-metal hosts use the same block; one line per GPU, matched by PCI/UUID, never imply host driver telemetry for a passed-through device |
| Docker container (~180×70 px) | Image version, `→ latest stable ⬆` only when a newer stable candidate is known, optional image-scan CVE count badge, CPU % and RAM usage as numbers; Compose containers sit inside their project grouping box |
| Service (mini box) | Port, HTTP/TCP health-check result and latency, distinct from systemd/Docker runtime state; show unknown when no check is configured |

Border color reflects the worst own/descendant state: red for unreachable,
critical health/CVEs or ≥90% utilization; yellow for updates, drift, overdue
backups or ≥70%; grey for off/expected off. Unknown/stale has an explicit label
and never becomes healthy/off; an expected-off parent cannot mask a known
critical child. CVE severity/age and backup confidence remain visible in details;
counts alone do not imply exploitability or restore safety.

Every subtree has `[–]`/`[+]` collapse controls; collapsed boxes show child counts
by kind and retain aggregate problem badges (deduplicate linked hosts/replicas).
Initially expand through the VM level, collapsing below it, but open branches
with known problems through the affected box. Clicking a box opens a details
side panel for configuration, snapshots, updates and backups; mutations appear
only in phase 2. Keep a normal details-page link for no-JS navigation.

Server-render bounded, paginated nested lists with CSS connectors and native
`<details>/<summary>` collapse; the chart and mobile list work without JS. Use
one small self-hosted chart script for pan/zoom, automatic responsive-mode and
focus handling, details-panel enhancement and 10-second live values; no manual
orientation control or graph-layout library. Preserve expansion/focus during
refresh, use labelled controls, Tab and Enter/Space, announced expanded state
and polite refresh announcements. Strict CSP: external script/style only, no
inline handlers/styles or host/registry HTML; render all untrusted values as
escaped text, with text labels alongside color.

| Level | Patch badge and details source |
| --- | --- |
| PVE node / bare-metal host | Existing `package.list_updates` and `HostUpdates`: total/security/kernel, installed → candidate versions, reboot required, observation and package-list refresh times; PVE packages included alongside Debian packages |
| VM/LXC OS | The same existing action on its explicitly linked, enrolled SSH host; never PVE guest exec; unmanaged/unsupported guests show unavailable |
| Docker container | Current repository/tag, image ID, manifest/platform digest and creation times; separate same-tag digest refresh and latest-stable-version badges, shared per-image metadata with per-container current digest |
| Service | Its runtime's package/image patch state, labelled inherited; no independent service-version claim without a supported source |

`docker.check_updates` already checks same-tag digests anonymously **on the
managed host**, only for running containers; reuse its typed statuses/results,
not a claim of stable-version discovery. Extend coverage to stopped containers
from `docker.list`. Same-tag “update” means the applicable platform manifest
changed, not necessarily a newer release; missing/incomparable digests are
unknown. An index-only change on another architecture is not a local update.
Digest-pinned images stay pinned and only show advisory candidates.

“Latest stable” defaults to the highest numeric SemVer `MAJOR.MINOR.PATCH` tag
with optional leading `v`, no prerelease suffix; ignore `latest`, `edge`,
`nightly` and other non-version tags. Apply [SemVer precedence][semver], never
lexical order or creation time; build metadata does not order versions and ties
with different digests are ambiguous. “Stable” is a tag-selection rule, not a
compatibility/security guarantee. Per-image reviewed overrides define tag
extraction/variant (for example Alpine), allowed major/range or an explicit
stable tag; record the policy/version and require approval for tag changes.
Do not mix variants or architectures. Incomplete tag pagination, no matching
tags or unsupported conventions means unknown, never “up to date”.

Choose anonymous public registry metadata lookup in `nebula-server`, coalesced
across hosts; it needs no stored credential. Private registry lookups run only
in the executor using vault credentials, typed repository/tag read grants and
sanitized results; lock/rotation/expiry pauses them. No Docker config, password
or authenticated bearer token reaches the server/collector. This adds registry
metadata egress to the server, not PVE API access. Use administrator-approved
HTTPS registry/auth origins, verified TLS, validated repository references,
bounded schemas and no redirects/proxies; host-supplied refs, pagination links
or authentication challenges cannot select arbitrary origins/private addresses.
Private-network registries require an explicit executor-side origin allowlist.

Cache by registry/repository/tag/platform/policy (private entries also credential
scope/version): same-tag checks 24 h, stable tag lists 24 h, failures 15 min,
immutable digest metadata 7 days. Coalesce in-flight reads; cap each registry at
one request/s, two concurrent requests, 1 MiB/response and 10,000 tags per scan;
bounded pagination exhausting a budget remains incomplete. Manual refresh
shares those budgets. Prefer manifest HEAD; bounded GETs for indexes/configs
and tag listing still consume request budgets. Docker Hub has separate
[pull and abuse limits][hub-limits]; honor remaining/reset and `Retry-After`
when supplied, pause on 429 with jittered exponential backoff (minimum 15 min),
and show cached/stale/rate-limited explicitly. Do not assume HEAD is unlimited
or hard-code a subscription quota. Registry lookups never pull image layers.

The box or its patch badge opens the server-rendered details panel comparing
current vs. same-tag candidate digest and latest stable tag/digest, platform,
policy, check
time and unavailable reason. Offer release-note links only from a reviewed
per-image HTTPS upstream/template and validated version, with
`noopener noreferrer`; do not fetch or render arbitrary image-label URLs/HTML.
Without a reliable mapping, show “release notes unavailable”.

CVE badges are optional **phase-1 read-only** observations. Choose an
operator-installed Trivy on the enrolled Docker host, scanning an already-local
immutable image via `image.vulnerabilities`; NOS does not install a scanner,
pull images, refresh its database or send image layers/credentials to the
server. Database provisioning/refresh is operator-managed. Use a reviewed
local-only scan profile, bounded runtime/output and one concurrent scan/host;
coalesce by image digest/platform and database version, cache for at most 24 h.
Show unique CVE counts with severity, scan/database age and coverage; disabled,
missing/stale database, failed or unsupported scans are unavailable/stale, never
“0 CVEs”. Findings are advisory, not authority to update; never spool image
configuration, files, secrets or raw scanner output.

### Phase 2 actions, permits and reconciliation

| Typed action | Executor base risk | Required constraints |
| --- | --- | --- |
| VM/LXC start | MEDIUM | LOW was considered; current NOS LOW means read-only, so starting a guest cannot use it |
| Graceful shutdown / reboot | MEDIUM | ACPI/guest-agent or LXC graceful operation; no automatic force-stop fallback |
| Hard stop / reset | HIGH | Explicit destructive verb; LXC reset unsupported unless separately specified |
| Snapshot create | MEDIUM | Exact name, disk set and RAM choice; storage/guest capability checks |
| Snapshot delete | HIGH | Exact snapshot identity and generation; never automatic age-based deletion |
| Snapshot rollback | HIGH | Exact snapshot; explicit start/RAM side effects; no automatic rollback |
| Backup now | MEDIUM | Exact guest, storage, mode and bandwidth; no pruning/deletion flags |
| Configuration change | HIGH | Allowlisted fields and old config digest; secret values remain executor-side |
| Intra-cluster migration | HIGH | Exact source/destination nodes and storage mapping; HA-aware; no passthrough live migration |
| Node reboot | HIGH standalone; CRITICAL cluster | Exact node and all impacted guests; cluster quorum/HA evacuation gates and max one node at a time |
| OS package update from tree | Existing executor-derived risk (`package.install_security` / `package.install_all` base MEDIUM) | Exact enrolled host/key, existing adapter, pre/postchecks and staged rollout; PVE install-all keeps existing full-upgrade behavior; reboot separate |
| Container same-tag digest refresh | MEDIUM base | Exact container/configuration and from → to digest; pull and recreate, never just restart |
| Container tag/version change | HIGH base | Also bind old/new tag and policy; explicit version selection, no implicit major upgrade |

The effective risk is the maximum of the built-in action floor, executor-owned
remote/node/guest criticality and every affected linked-host floor. Unknown
criticality defaults to HIGH; LOW grants remain read-only. `ProxmoxOFS1` stays
read-only by default; any future offsite node reboot is CRITICAL, manual and
requires an agreed recovery path. Recheck risk and identity before dispatch.
Use existing approval semantics: MEDIUM presence; HIGH user verification;
CRITICAL user verification plus target count; hardened HIGH/CRITICAL via CLI.
Risk-relevant host links require admin confirmation in the executor registry;
editing or deleting a server-side display link cannot remove a recorded floor.

Tree update buttons only propose existing executor operations/permits; expanding
or selecting a parent never authorizes its descendants. Freeze explicit host
and container sets before approval and reuse `internal/executions/stages.go`
and the executor stage engine (DEV/QA/PROD, canary/waves, gates and stop
thresholds). Multiple containers on one host are an explicit frozen subplan of
that host's stage; reconcile and postcheck each before reporting its outcome.
OS updates use existing SSH actions, never the PVE token or a new patch engine;
unenrolled guests/nodes remain read-only. No unattended mutation is introduced.

Container update means pull the **approved immutable digest**, retain the old
image, then recreate with the same complete configuration. Reuse the durable
`docker.compose_update` path and postflight comparison, but its current
project-only `pull; up -d` contract cannot bind exact images/containers: extend
the versioned action before exposing tree updates. Validate Compose labels
against approved project/config-file identities and freeze every affected
service/replica/dependency; prohibit implicit project-wide updates. Preserve
configuration except the approved image reference (use a reviewed digest
override for Compose). Standalone `docker run` containers need an operator-
supplied complete reproducible creation definition; inspect's sanitized subset
cannot reproduce env/secrets, devices, capabilities or networking. Unsupported
or incomplete definitions disable update rather than guess. Secret-bearing
configuration remains executor/host-side, never in the tree/results.

Bind host ID/key fingerprint, full container ID **and** name, repository,
platform, old/new tag, image digest from → to (index/platform manifest as
applicable), configuration digest, exact affected set, credential version and
stage plan into canonical permit parameters. The executor rechecks identity,
config and current digest before dispatch, verifies the pulled digest and
refuses changed targets/configs; a moved tag needs a new proposal, not an
unapproved digest. Private pulls are executor-mediated over authenticated SSH
to the target engine; registry credentials stay in the executor, never host
Docker login files. Their transfer/load profile must be reviewed before enablement.
Apply normal trust/scanner/host floors. Container update/rollback has **no
CRITICAL variant**: if any floor requires CRITICAL, refuse it; never downgrade.

Keep the previous image by digest and the executor-owned recreation definition
through an explicit rollback window (default 7 days); no automatic image prune.
Rollback is a separately approved exact-target recreation with the prior digest
and configuration (same-tag MEDIUM base, tag reversal HIGH base), with health,
ports, mounts/network and service/replica-count postchecks. A failed update stops
its rollout; reconcile uncertain recreation before retry/rollback. Image
rollback does not undo volume/database migrations: require a declared data
backup/recovery plan or mark rollback unavailable. Cleanup must not delete a
retained rollback image; bind the new container incarnation for any later action.

For HA-managed guests, power/movement requests must go through the HA manager,
including PVE guest endpoints only when verified to delegate to it. The inspected
QEMU start/shutdown/stop/migrate paths do delegate ([QEMU API][qemu]); test each
supported version and LXC separately. Do not bypass HA, change it to `ignored`,
or treat a desired-state change as completion. Reboot/reset without a verified
HA-safe route stays disabled. Direct HA resource updates require broad
`Sys.Console` on `/` ([HA resource API][ha-api]); do not add that privilege to
either token as a workaround. Observe both HA desired and actual guest state.

Introduce versioned canonical provider targets, not fake SSH host IDs. Bind
remote ID, guest generation/kind, exact node and VMID (or explicit node target),
the pinned CA/leaf fingerprint and trust generation, approved API endpoint set,
action/adapter version and artifact digest, credential reference/version,
parameters, precondition digests, stage plan and expiry into the execution
digest. The executor reconstructs paths and hashes canonical bytes itself.
Migration binds both nodes/storages; reboot freezes all impacted guests and
blocks if that set changes. A guest moving nodes after approval requires a new
proposal; failover may change the API entry node only within the approved set.
HA-driven placement must not silently widen the NOS-approved target set.
PVE can relocate guests autonomously regardless of NOS permits; NOS records
that external change, stops affected dispatch and requests approval again.
Node reboot additionally requires fresh executor-read vote/qdevice and HA
checks after evacuation, a cluster-wide reboot lock and post-return quorum
checks before another node; stale/unknown state blocks the operation.

Before dispatch, persist intent and claim the single-use authorization in
`executor.db`; fsync before sending a mutation. Store the returned UPID, task
node, target tuple, request digest and timestamps durably before reporting it.
Reuse NOS durable job states, with PVE's task as the remote job (no uploaded
shell or systemd unit). Poll typed task status and perform action-specific
postchecks; an accepted request/UPID is not success. Bound and sanitize any
phase-2 task-log excerpts; task status API details come from [PVE Tasks][tasks].

Reconcile unfinished jobs after either process restarts using stored UPIDs and
read credentials once unlocked. Persisted jobs confer observation authority,
never a new mutation permit. Lost response after dispatch means `reconciling`,
then `unknown` if the exact task cannot be identified; never infer success from
power state alone or retry the mutation. Missing/expired task records preserve
uncertainty. HA operations without UPIDs need durable intent plus observed
manager/guest convergence. Cancellation stops undispatched work; cancelling a
remote task is a separately approved action. Lock cannot undo an accepted task.

### One-click access and later phases

Phase 1 exposes deep links to the correct node/guest in the PVE UI only. Build
HTTPS links from approved endpoint metadata and encoded identifiers, never
host-provided URLs; open with `noopener noreferrer`. PVE performs its own login
and MFA; no token, ticket or SSO credential travels in a link. NOS API pinning
does not establish browser trust: the browser must independently trust PVE TLS.

Phase 3 may add a ticketed VM VNC/WebSocket proxy: HIGH approval for one exact
guest/session, single-use short-lived ticket, fixed origin, 15-minute maximum,
idle expiry and audited open/close. Executor-side relay retains every PVE
credential/ticket; the server sees only session-scoped console traffic and is
therefore still a sensitive relay. Enforce origin/CSRF checks, byte/time limits
and self-hosted CSP-compatible assets. Current [PVE documentation][users] says
console endpoints require user privileges rather than API tokens: do not assume
the two tokens can support this; a separate credential/session ADR is required.

Hypervisor shell is CRITICAL: admin-only, fresh user verification and target
count, short session, disabled in hardened mode, with a separately reviewed
recording/redaction/retention policy. Recordings themselves can contain secrets.
Neither tokens nor interactive SSH get extended implicitly to provide it;
shell remains outside the committed phases pending another architecture review.

Phase 1 delivers read-only remotes, staging, the collapsible org chart,
patch/image state, optional CVE badges, backup-freshness warnings (vzdump/PBS),
GPU/CPU/RAM/filesystem values with 24 h averages,
service checks, drift hints and deep links.
Phase 2 adds tree-triggered OS/container and Compose-stack update/rollback
with approved exact service/replica sets, plus VM/LXC actions, starting
with lifecycle operations, then individually gated snapshot/backup/config/
migration profiles; node reboot needs
its separate cluster-safety gate. Phase 3 offers optional snapshot-before-update
for VMs on verified snapshot-capable storage, composed into the existing stage
engine (OS or in-guest container updates), provisions guests, and may add
consoles after review. Recheck guest generation, disks, passthrough, storage and
consistency/quiescing immediately before snapshot; unknown capability blocks
that option. Snapshot failure stops that target's update; opting out requires
an explicit revised plan, never silent fallback.
Snapshot, patch, rollback and cleanup each need their appropriate exact-target
authorization; no standing HIGH deletion or automatic rollback grant. Offer an
explicit backup alternative when snapshots are unavailable. Provisioning binds
template, destination, new VMID, IPAM reservation and configuration, then follows
normal SSH enrollment. Rolling node maintenance, cross-remote migration, WoL
and a Datacenter Manager adapter remain separately scoped follow-ups.

## Consequences and open questions

The server still holds no provider secrets or execution authority. The executor
gains an outbound HTTPS parser and must enforce origin, resource and method
limits. More collector processes do not remove that attack surface. Credentialed
polling pauses while locked; public registry metadata remains readable. Read-only
ACLs mean incomplete PVE 8 agent and backup visibility. These limits are
preferable to secretly broadening rights.

Official sources below were inspected on 2026-10-29; upstream `master` is not a
compatibility contract. No lab API, ACL, TLS, HA or storage experiment was run.
Before release, record exact supported PVE 8/9 package versions and verify:

- Minimal per-method ACLs, filtered empty responses, legacy PVE 8 agent rights,
  LXC interfaces/snapshots, task retention, and HA delegation/reboot semantics.
- Whether any safe read-only backup catalog route exists on deployed versions;
  task history does not establish PBS backup existence or restore safety.
- Actual node SANs, custom/ACME certificates, CA retrieval and renewal behavior;
  same-CA endpoint membership checks and reliable VMID-reuse detection.
- Storage/format snapshot capabilities (including PVE 9 LVM changes), passthrough
  disk-only snapshots, guest-agent consistency, and migration with local disks.
- Cluster votes/qdevice/HA placement constraints and a reboot recovery procedure;
  no “three nodes means safe” shortcut. Should offsite actions ever be enabled?
- Console ticket/token restrictions and secure relay feasibility; existing
  InfluxDB export configuration; PDM/cross-remote APIs and their credential model.
- Which source tags/pools should map to NOS environments, and operator-selected
  snapshot/backup-age thresholds. Foreign task metadata is not a trusted audit.
- Compose detection with missing/spoofed labels, multiple config files/profiles,
  replicas and dependencies: which complete resolved configuration can NOS bind?
- How will operators enroll non-Compose creation definitions and secret references,
  and which device/network/runtime options can be reproduced safely?
- Private registry auth (PAT/basic, scoped bearer/OAuth, credential helpers),
  approved auth realms, rotation and executor-mediated pull/load compatibility;
  unsupported auth stays unavailable, never a server credential exception.
- Per-image stable-tag/variant overrides, release-note mappings, private metadata
  visibility and cache budgets for large repositories/shared Docker Hub egress.
- Container-to-service links beyond Compose/systemd, rollback retention/storage
  budgets, application data recovery and VM snapshot consistency requirements.
- Exact PVE RRD/status units and per-version availability; CPU normalization,
  filesystem exclusions (pseudo/duplicate mounts), time-weighted bucket averages
  and minimum 24 h coverage; per-host SSH lease budgets and large-chart target
  prioritization without exceeding read-grant floors.
- NVIDIA PCI/UUID correlation, multi-function/passthrough and multi-GPU cases,
  absent guest drivers and unsupported/MIG devices; which fields are unavailable?
- Optional host-local Trivy profile/version, local-only scan enforcement,
  operator-managed database freshness, severity-to-border policy and scan budgets;
  how to present digest correlation, deduplication and incomplete coverage?
- Which deployed PBS metadata is safely readable without broader rights,
  how to associate jobs with exact guest generations, and how to distinguish
  unknown catalog/verification coverage from an overdue successful-backup age?
- Approved service HTTP/TCP targets, check timeouts/cadence and latency-warning
  thresholds; no arbitrary egress or automatic probing of discovered ports.
- Chart density/viewport limits and accessible pan/zoom/side-panel behavior;
  validate deep mixed branches and hundreds of siblings without wide horizontal
  scrolling, with automatic ≤600 px fallback and no orientation toggle.

[certs]: https://github.com/proxmox/pve-docs/blob/master/certificate-management.adoc
[users]: https://github.com/proxmox/pve-docs/blob/master/pveum.adoc
[agent]: https://github.com/proxmox/qemu-server/blob/master/src/PVE/API2/Qemu/Agent.pm
[qemu]: https://github.com/proxmox/qemu-server/blob/master/src/PVE/API2/Qemu.pm
[storage]: https://github.com/proxmox/pve-storage/blob/master/src/PVE/Storage.pm
[content]: https://github.com/proxmox/pve-storage/blob/master/src/PVE/API2/Storage/Content.pm
[ha-api]: https://github.com/proxmox/pve-ha-manager/blob/master/src/PVE/API2/HA/Resources.pm
[tasks]: https://github.com/proxmox/pve-manager/blob/master/PVE/API2/Tasks.pm
[semver]: https://semver.org/
[hub-limits]: https://docs.docker.com/docker-hub/usage/

## Tickets for phase 1

Each item is a separate agent job with tests first and `make check`; no live
network tests, only loopback TLS servers and temporary Unix sockets. Protected
paths below require explicit maintainer authorization in their own tickets.
Migration numbers are assigned at implementation time. No phase-2 mutation
method or action credential is needed to ship phase 1. P1-01 must also approve
the metrics/history and short SSH telemetry grant model; later jobs depend on
that revision. Reader, model, presentation and live-interaction jobs are separate
so the new surfaces each fit one agent job.

| Ticket | Package and files | Acceptance tests |
| --- | --- | --- |
| P1-01: approve the architecture revision | `docs/spec/{01-product,02-architecture,03-processes-and-data,06-credentials,07-execution-model,08-ssh-transport,09-untrusted-host-data,11-operations,12-inventory,17-frozen-decisions}.md` | Map every new authority, target/read-grant type and limit; explicitly revise standalone recreation prohibition, registry egress/credential boundary and 5-min history/10-s SSH telemetry authority before implementation; spec links resolve |
| P1-02: remote/observation contracts | New `internal/pvecontract/{remote,observation,limits}.go`, corresponding `_test.go`, `fuzz_test.go` | Reject malformed IDs, duplicate keys, invalid UTF-8, excessive sizes/counts/nesting; preserve unavailable vs empty |
| P1-03: pinned HTTPS transport | New `internal/pvetransport/{client,tls}.go` and tests | CA/leaf pin, SAN/expiry, renewal, failover order, mismatch hard stop, redirects/proxies refused; no credentials before trust |
| P1-04: executor remote registry | `internal/executordb/pve.go`, next `migrations/*_pve_remotes.sql`, tests | Durable pins/blocks/tombstones, duplicate trust identity, endpoint/generation changes, fail-closed database errors |
| P1-05: typed RPC and UID boundary | `proto/nebula/executor/v1/executor.proto`, generated `internal/rpc/executorv1/` via `make generate`; `internal/peercred/`, `internal/executor/roles.go`, `internal/executorclient/` | Dedicated collector UID gets only typed read methods; unknown/server/collector callers cannot manage trust/secrets; no reveal/generic HTTP method |
| P1-06: local credential lifecycle | New `cmd/nebula/pve.go`, `internal/executor/pve_admin.go`, tests; reuse `internal/vault` | Fingerprint confirmation, non-echoing input, permission-profile rejection, atomic rotation/remove/re-pin and revocation; secrets absent from replies/logs |
| P1-07: bounded provider read grants | New `internal/pveread/{grant,lease}.go`, `internal/executor/pve_read.go`, executor DB grant migration and tests | Exact remote/trust/credential/method scope, expiry, atomic budgets, metrics target lease, lock/restart and invalidation; no mutation dispatch |
| P1-08: node/guest reader | New `internal/pveapi/{inventory,config,agent}.go` and tests | Loopback PVE 8/9 fixtures, secret-field removal, QEMU/LXC schemas, unavailable agent data, partial enumeration, VMID reuse |
| P1-09: storage/snapshot reader | New `internal/pveapi/{storage,snapshots}.go` and tests | Typed storage/snapshot metadata, unknown capabilities, pagination/response limits, no contents or mutation methods |
| P1-10: collector and spool | New `cmd/nebula-pve-collector/main.go`, `internal/pvecollect/{poll,spool}.go` and tests | Injected time/backoff, bounded concurrency, no network/DB/secret access, safe atomic spool, symlink/oversize/replay rejection |
| P1-11: persistence and ingestion | New `internal/pveinventory/{store,ingest}.go`, server DB migration, tests | Cross-remote VMID/node collisions, atomic dataset updates, stale/partial data, no silent deletion, retention/tombstones |
| P1-12: host linking and staging | New `internal/pveinventory/{links,staging,drift}.go`, tests | MAC/IP conflicts, explicit import, preserved asset IDs, reused VMID unlink, no automatic SSH endpoint/criticality changes |
| P1-13: remote pages and deep links | New `internal/web/ui/pve.go`, `pve_test.go`, `web/templates/pve.html`; wire `cmd/nebula-server/main.go` | Escaped hostile data, approved-origin links, logged-in read access, source/staleness labels; no second chart script |
| P1-14: service/install and operator guide | New `deploy/systemd/nebula-pve-collector.service`; `deploy/install.sh`, `deploy/install_test.sh`, `deploy/container/{Dockerfile,compose.yaml}`, `.goreleaser.yaml`; new `test/security/pve_test.go`, `docs/operator/proxmox.md` | Distinct UID/peercred role, spool permissions, no collector network/capabilities or executor DB mount, locked startup, CLI rotation/re-pin walkthrough; isolated tests only |
| P1-15: org-chart read model | `internal/pveinventory/{tree,links}.go`, tests; reuse existing batch observations | PVE/guest/bare-metal branches, Compose grouping, reviewed placements/replicas/full-ID incarnations; bounded queries, no duplicate counts or inferred SSH authority; aggregate worst state/counts |
| P1-16: Docker image observation fields | `internal/executions/actions/{actions.go,scripts/docker_list.sh,scripts/docker_inspect.sh}`, `internal/executions/dockerhost/`, tests | LOW list/inspect, creation/platform/full-ID/digest fields and stopped containers; index vs platform changes, digest pins, malformed/oversize/secret rejection; no configuration recreation |
| P1-17: public registry metadata client/cache | New `internal/registrymeta/{client,cache,limits}.go`, tests | Anonymous server reads, approved origins/SSRF/redirect rejection, bounded pagination, coalescing/TTLs/429 budgets with injected time; no layer pulls |
| P1-18: server-rendered org-chart layout | `web/templates/{inventory,host}.html`, `web/static/app.css`, UI render tests | Connected boxes, left-to-right levels/vertical siblings, ~220×110 / 180×70 sizes, Compose grouping, native collapse/counts, VM-depth default/problem expansion; hundreds of siblings scroll down, ≤600 px list, no orientation toggle, no-JS/CSP/accessibility |
| P1-19: cluster/task reader | New `internal/pveapi/{cluster,tasks}.go`, tests | HA/quorum/foreign-task summaries, typed pagination, source/age and response limits; no task logs or mutation methods |
| P1-20: PVE backup evidence reader | New `internal/pveapi/backups.go`, tests | vzdump/PBS metadata correlation, success vs catalog/verification, denied/filtered reads remain unavailable; no action token or broadened ACLs |
| P1-21: PVE status/RRD metrics | New `internal/pveapi/metrics.go`, tests | Node/QEMU/LXC unit normalization, missing/partial RRD/status, invalid ranges; disk allocation never masquerades as filesystem use |
| P1-22: SSH machine/filesystem telemetry | `internal/executions/actions/`, new `internal/executions/hostmetrics/`, tests | LOW `host.metrics`/`filesystem.list`, bare-metal and linked guests, current CPU/RAM/fullest filesystem/all mounts, bounded schemas/numbers, unavailable distinct from zero |
| P1-23: PCI/GPU telemetry | `internal/executions/actions/`, new `internal/executions/gpuhost/`, tests | LOW `pci.inventory`/`gpu.status`, fixed nvidia-smi query, hostpci target correlation, per-GPU UUID/PCI identity; bare metal, multiple/absent GPUs and missing drivers, no device mutation |
| P1-24: Docker runtime stats | `internal/executions/actions/`, `internal/executions/dockerhost/`, tests | LOW non-streaming `docker.stats`, CPU/RAM numbers, stopped/removed/full-ID replacement handling, bounded output, no env/secrets |
| P1-25: metric retention/averages | New `internal/pveinventory/metrics.go`, server DB migration, tests | Injected time, 288 five-minute buckets/24 h per metric, server-side averages/coverage, missing samples not zero, pruning and incarnation reset; live values share buckets |
| P1-26: telemetry collection scheduling | `internal/pvecollect/`, existing SSH observation scheduler, tests | Authorized 5-min history/10-s live leases only, exact target scopes, remote/host budgets, injected time, coalescing; lock/expiry stop reads |
| P1-27: service placement and health | `internal/pveinventory/links.go`, `internal/executions/actions/`, new `internal/executions/servicecheck/`, tests | Explicit host/container service placement, LOW `service.check`, approved HTTP/TCP destination/port, bounded latency/timeouts, redirect/SSRF refusal, no bodies; runtime vs endpoint health and unconfigured unknown |
| P1-28: Dropped (owner decision 2026-10-30: no Veeam support; PBS evidence via P1-20/P1-29) | — | — |
| P1-29: backup freshness model | New `internal/pveinventory/backups.go`, server DB migration, tests | Phase-1 warnings, operator age/default 24 h, failed/overdue/stale/expected-off, exact guest association; task/catalog/verification confidence kept separate, unknown never safe |
| P1-30: optional image CVE observations | `internal/executions/actions/`, `internal/executions/dockerhost/`, tests | LOW `image.vulnerabilities`, optional host-local Trivy/local immutable image, no install/pull/DB refresh, bounded one-scan/host, digest/platform/DB cache ≤24 h; severity/count/age/coverage, missing/stale/failed never zero, no raw findings/secrets |
| P1-31: stable-version selection | New `internal/registrymeta/stable.go`, tests | Numeric SemVer/variants/overrides, policy version, ambiguous ties/incomplete tags unknown, same-tag/platform vs stable-version distinction, no tag mutation |
| P1-32: private registry read authority | Executor registry vault/admin/read-grant/RPC wiring, tests | Executor-only credentials, approved auth realms, lock/rotation/expiry and repository scope, no server credential exception or layer pulls |
| P1-33: patch and details presentation | `internal/web/ui/{inventory,hosts}.go`, `web/templates/{inventory,host}.html`, UI tests | Reuse package.list_updates/HostUpdates for node/guest OS, source/list age and unknown; current/same-tag/stable comparison, safe release notes; config/snapshots/updates/backups side-panel content, no mutations |
| P1-34: chart indicators | `internal/web/ui/{inventory,hosts}.go`, templates, `web/static/app.css`, tests | Status/version/patch, current/⌀ CPU/RAM/DISK, ≥70 yellow/≥90 red using current values, all-filesystem hover/focus, GPU lines/target, container stats/CVE, backup warnings and service latency; worst border and stale/unknown labels |
| P1-35: chart interaction enhancement | Existing `web/static/inventory.js`, chart UI tests | One small script: pan/Ctrl+wheel zoom/fit, automatic mobile mode, details panel, 10-s live values; preserve expansion/focus, accessible no-JS links, strict CSP, no orientation toggle or second chart runtime |
| P1-36: bounded SSH telemetry leases | Existing SSH read-grant/RPC/executor boundary, tests | Reviewed 10-s telemetry/5-min history scope distinct from 15-min ordinary schedules; exact host/key/action/expiry/budget, lock/restart/revocation, no mutation or arbitrary command authority |
| P1-37: live chart SSE delivery | `internal/web/ui/`, tests | Logged-in sanitized 10-s values, viewer coalescing/visible-box prioritization, 30-s target leases, hidden/disconnected expiry, deferred-box age labels; no scope widening |

## Tickets for phases 2 and 3

The same tests-first/check and protected-path review rules apply. Phase 2
depends on the approved spec revision and phase-1 read models; snapshot-before-update
orchestration is phase 3, not a prerequisite for manual phase-2 updates.

| Ticket | Package and files | Acceptance tests |
| --- | --- | --- |
| P2-01: provider actions and reconciliation | `internal/pveapi/`, `internal/executor/`, `internal/executordb/`, provider target/RPC contracts, tests | Ship lifecycle baseline first; independently gate snapshot/backup/config/migration/node-reboot profiles; exact-target permits, inherited risks, HA/quorum/storage rejection, UPID persistence, restart/lost-response reconciliation without redispatch |
| P2-02: OS update proposals from tree | `internal/web/ui/{inventory,hosts,operations,stages}.go`, templates/static and tests; reuse `internal/executions/` | Node/bare-metal/VM/LXC selection resolves only enrolled SSH targets; existing package installs/permits/adapters, PVE full-upgrade, canary/waves/gates/stop thresholds, no implicit descendants or reboot; unlinked guests refused |
| P2-03: container permits and recreate actions | `internal/executions/actions/`, `internal/executor/`, `internal/permit/`, `internal/canonical/`, RPC/contracts, tests | Full host/key/container ID+name/config and digest from→to binding, frozen Compose services/replicas/dependencies or complete standalone definition, pinned pull/recreate with same config, no unsafe inspect reconstruction; MEDIUM same-tag/HIGH version, CRITICAL refused; substitution/tag drift rejected |
| P2-04: registry pull, rollback and postchecks | Executor/SSH action transport, `internal/executordb/`, `internal/executions/dockerhost/`, tests | Private auth never leaves executor; approved digest verified, prior image/config retained for window, separately permitted recreate rollback, volume-migration limitation, bounded health/ports/mounts/network/count checks, stop/reconcile failure, no unapproved retries/pruning |
| P2-05: container/Compose-stack update/rollback tree controls | `internal/web/ui/`, `web/templates/{inventory,host,operation}.html`, external static assets and tests | Current→approved image/config/targets shown before normal approval; tag changes HIGH, CRITICAL/unsupported unavailable; reuse host stages with exact container subplans, stop on regression, bind recreated incarnation for rollback; CSP/accessibility retained |
| P3-01: optional snapshot-before-update | Existing stage engine, provider/SSH action contracts, executor and UI, tests | Exact VM/generation snapshot on verified storage before OS/container update, quiescing/passthrough checks, failed snapshot blocks patch, explicit opt-out/new plan or backup alternative; separate snapshot/update/rollback/cleanup permits and no standing deletion authority |
