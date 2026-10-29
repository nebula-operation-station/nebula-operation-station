<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Inventory, IPAM and discovery

Nebula knows every network asset, manages a subset of them over SSH, and never writes scan results into the inventory without review.

**Assets and managed hosts.** Network assets (server, NAS, firewall, switch, printer, IoT, unknown) are tracked separately. “Add to managed hosts” starts SSH enrollment and keeps the asset's identity. Managed hosts carry environment (DEV, QA, PROD), criticality (LOW to CRITICAL, meaning the impact of a disruption), groups, tags (`role=web`, `gpu=a2000`) and saved selections, static or dynamic.

**Ops State instead of a health score.** READY, WARNING, UNREACHABLE or UNKNOWN, each with `observed_at`, `source` and `reason`, for example “WARNING · 21:13 · reboot required”.

**IPAM-light.** Networks and subnets, simple pools, reservations, assignments, exclusions, conflict indication. IP status: FREE, RESERVED, ASSIGNED, DISCOVERED, CONFLICT, EXCLUDED, UNKNOWN. A free-IP suggestion combines IPAM state, reservations, discovery and an optional targeted reachability test, and is shown as a suggestion, never as certainty. No DHCP or DNS management.

**CSV import.** A mapping screen assigns arbitrary columns, for example `server_name` → display name, `ip` → endpoint 1, `vpn_ip` → endpoint 2.

**Discovery.**

- Nmap modes: host discovery, selected ports, service discovery, full TCP, custom. Nmap is an optional dependency.
- Runs in `nebula-discovery`, a one-shot systemd service with `AmbientCapabilities=CAP_NET_RAW`; neither server nor executor gets raw-socket rights.
- Results land in staging, classified NEW, EXISTING, POSSIBLE MATCH or CONFLICT, then imported selectively or all at once.
- Matching uses the MAC address where the scanner shares the layer-2 segment, otherwise IP plus hostname. Across VPNs and routed networks there is no MAC, so those matches are shown as POSSIBLE MATCH.
- Scheduling is manual, once, or an interval the user sets. There is no default schedule.

**Global search** over hostname, IP, subnet, asset, execution ID, module and runbook. Quick actions from search go through the normal approval path.

<a id="v23-12-01"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-12-01 -->
**PVE inventory and reviewed links.** Remotes/nodes/guests use executor-owned identities and generations from [08-ssh-transport.md](08-ssh-transport.md); server tables are presentation copies. An explicitly reviewed `(remote_id, vmid, generation)` link is authoritative for display, never SSH identity. MACs suggest links; IP/hostname matches remain POSSIBLE MATCH, with cloned MACs/conflicts requiring review. No automatic merge by VMID/IP/name. Unmanaged guests enter NEW/EXISTING/POSSIBLE MATCH/CONFLICT staging; import preserves asset identity and still requires ordinary SSH enrollment/key pinning. VMID reuse cannot inherit links, criticality or approvals. Show IP/RAM/node/status drift against linked hosts/IPAM; accepting hints is explicit and audited. Guest IPs never silently replace SSH endpoints or criticality. Source-labelled tags/pools only suggest NOS groups/environments, never automatic rollout membership.

<a id="v23-12-02"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-12-02 -->
**Read selections.** All-host/tag/environment selection is a convenience resolved to an explicit host/key snapshot before lease or batch approval, never a live authorization predicate. New enrollment, changed labels or replacement keys need a new approved lease; removing a host disables its scope immediately. Read Refresh now shares scheduled budgets and shows cached age/next eligible time. Display grant expiry, remaining budget, blocked reasons and Revoke; public presentation links do not confer execution rights. Risk-relevant host links require separate admin confirmation in the executor registry.

<a id="v23-12-03"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-12-03 -->
| PVE observation | Default authorized cadence and scope |
| --- | --- |
| Nodes and QEMU/LXC inventory | 60 s: name/kind/location/state/uptime/resource totals |
| Guest configuration | 5 min: CPU/RAM/disk-storage references, NIC MAC/bridge/VLAN, boot order, `hostpci` mappings, nonsecret Cloud-Init IP configuration, tags/pools |
| Interfaces | 60 s where supported: informational QEMU agent IP/MAC/hostname/OS/filesystem summary or typed LXC interfaces, source-labelled; PVE 8 broader agent rights remain unavailable |
| Snapshots and storage | 5 min: name/time/parent/RAM flag and storage type/format/availability/capacity/features, never image/backup contents |
| Backup evidence | 5 min: available nonsecret vzdump/PBS/task metadata and detectable Veeam evidence from enrolled hosts, with source/coverage/age |
| Cluster and HA | 60 s: membership/votes/quorum, desired/observed HA states, maintenance and readable replication/Corosync summaries |
| Node details/foreign activity | 15 min: PVE/kernel versions and bounded actor/type/time/target/exit-status metadata, no raw task logs/commands |

<a id="v23-12-04"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-12-04 -->
**Staleness and availability.** Mark datasets stale after three missed intervals; partial polls do not erase unseen guests, and only a complete enumeration may tombstone them. `poxmox` may be on-demand: expected-offline is grey UNKNOWN with a reason, not an alarm. Offsite VPN loss changes neither trust nor endpoints. Unknown, denied, incomplete and unavailable stay distinct from empty/zero/healthy. Foreign task metadata is untrusted evidence, not the NOS audit. Subscription/ZFS-health fields needing more privileges stay unavailable. PVE state can explain Ops State but cannot establish SSH health.

<a id="v23-12-05"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-12-05 -->
**Backup confidence.** Read-only tokens may lack full backup catalogs due to write-privilege filtering; show unavailable: insufficient read privileges rather than borrow action tokens/widen ACLs. Task success is evidence of a past run, distinct from currently present/restorable backup, catalog availability and verification/restore confidence. Compare last evidenced success against operator-selected maximum age, default 24 h; stale/failed/overdue evidence warns in phase 1. Undetected Veeam, denied catalogs and missing samples remain unknown/unavailable, never no backups or backup safe. PBS retention/verification needs a separately approved read-only source; Veeam uses allowlisted local metadata, no implicit credential integration.

<a id="v23-12-06"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-12-06 -->
**Placement model.** Reuse existing host/update/execution observations for PVE node → VM/LXC → optional Compose project → Docker container → service; bare-metal hosts are roots with containers/services beneath. Nodes/guests may also have direct workloads. Reviewed SSH links avoid duplicate host boxes. A Compose box groups validated hints and reviewed host/project/config identity, never proves action scope from labels. Container identity is `(host_id, full container ID)`; names are labels and recreation is a new incarnation. Keep image configuration ID distinct from registry manifest/index digests and record OS/architecture/variant plus bounded image/container creation times. systemd services use host/unit; Compose service labels describe logical replicas, not systemd units or arbitrary processes. Explicit service placement carries source/time, one placement per instance with distinct replicas; non-Compose links need review. Missing discovery remains unknown; never infer relationships by process inspection or matching names.

<a id="v23-12-07"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-12-07 -->
**Metric sources and retention.** PVE node/QEMU/LXC CPU/RAM use typed status/RRD reads. Disk allocation or I/O is never filesystem utilization. Fullest-filesystem DISK/all mounts, OS patch state, Docker and NVIDIA driver observations use the existing read-only SSH pipeline on explicitly enrolled bare-metal/node/guest hosts, never guest exec or inferred endpoints. Without an enrolled filesystem source, DISK stays unavailable. Retain one sample/5 min for 24 h, 288 buckets per target/metric; live ten-second values update current value and the same bucket, never an unbounded raw history. Compute averages server-side from valid buckets, show age/coverage, never fill missing samples with zero or call short coverage a full day. Prune older buckets and start a new series on identity/generation change. Exact normalization, filesystem exclusions, time weighting and minimum full-day coverage remain open.

<a id="v23-12-08"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-12-08 -->
**Visible-target requests.** A visible chart/details page renews a 30-second exact-target request bound to remote/node/VMID/generation or SSH host/key and read-grant versions. Closing/hiding/disconnecting ends renewal; the request adds no authority to the standing grant. Coalesce viewers, prioritize visible boxes, cap each remote at four live targets and one metrics request/s, and label deferred boxes with last observation age. SSE sends sanitized values every 10 s without execution rights. Five-minute background history and ten-second SSH reads require the separately approved telemetry profile, aggregate budgets and lock/revocation rules in [07-execution-model.md](07-execution-model.md).

<a id="v23-12-09"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-12-09 -->
**Org chart layout.** Desktop uses connected boxes with levels left-to-right and siblings vertically stacked, reserving each subtree's vertical extent. Many siblings grow downwards, never side-by-side strips; scroll vertically and fit fixed depth to viewport, with pan, Ctrl+wheel zoom and fit to screen. There is no orientation toggle. At ≤600 px use an automatic CSS indented-list fallback with the same data, collapse controls and detail links. Server-render bounded paginated nested lists with CSS connectors and native `<details>/<summary>` so chart/list works without JavaScript. One small self-hosted script enhances pan/zoom, focus, responsive mode, details panel and live values; no graph-layout dependency or second chart runtime. Preserve expansion/focus during refresh; labelled keyboard controls use Tab/Enter/Space, announced expanded state and polite refresh announcements.

<a id="v23-12-10"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-12-10 -->
| Box | Compact display |
| --- | --- |
| Host/PVE node/VM/LXC, about 220×110 px, expandable GPU lines | Name (+VMID), status text/dot, OS/PVE version, patch count or check mark only after a complete fresh check; CPU/RAM/DISK current % and 24 h average, current-value bars yellow at ≥70%, red at ≥90%; DISK is fullest filesystem with every mount on hover/focus |
| NVIDIA GPU in owning machine | Node PCI identity plus guest `hostpci` target; driver-equipped guest/bare metal shows UUID/PCI-matched utilization, VRAM, temperature/power per GPU; never imply host driver telemetry for a passed-through device |
| Container, about 180×70 px | Image version, latest-stable update hint only if known, optional CVE-count badge, numeric CPU/RAM; Compose containers grouped by project |
| Service | Approved port/HTTP/TCP health/latency separate from runtime state; unknown when unconfigured |

<a id="v23-12-11"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-12-11 -->
**Chart state and interaction.** Borders show worst own/descendant state: red for unreachable, critical health/CVEs or ≥90% utilization; yellow for updates/drift/overdue backups or ≥70%; grey for off/expected-off. Unknown/stale has an explicit label and never becomes healthy/off; an expected-off parent cannot hide known critical children. Show CVE severity/age and backup confidence in details, not only counts. Each subtree has collapse controls, child counts by kind and deduplicated aggregate problem badges. Initially expand through VM level and collapse below, except open known-problem branches to the affected box. Box click opens configuration/snapshots/updates/backups details; keep a normal no-JS details link. Mutations appear only in phase 2 and use exact plan approval. Keep text labels alongside colors and the strict CSP in [09-untrusted-host-data.md](09-untrusted-host-data.md).

<a id="v23-12-12"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-12-12 -->
**Patch sources and PVE links.** Node/bare-metal and linked enrolled guest OS patch state reuse `package.list_updates`/HostUpdates, total/security/kernel counts, installed/candidate versions, reboot status and observation/package-list-refresh times. PVE packages use the existing Debian adapter; unmanaged/unsupported guests remain unavailable. Containers distinguish current/same-tag platform digest/latest-stable candidates with policy/platform/check time and unavailable reason; services inherit labelled runtime package/image state unless a supported independent version source exists. Link to PVE HTTPS UI using approved endpoint metadata/encoded IDs with `noopener noreferrer`, without token/ticket/SSO credentials. PVE handles login/MFA and the browser must independently trust TLS; NOS API pinning does not establish browser trust.
