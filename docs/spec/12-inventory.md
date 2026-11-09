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
| Backup evidence | 5 min: available nonsecret vzdump/PBS/task metadata, with source/coverage/age |
| Cluster and HA | 60 s: membership/votes/quorum, desired/observed HA states, maintenance and readable replication/Corosync summaries |
| Node details/foreign activity | 15 min: PVE/kernel versions and bounded actor/type/time/target/exit-status metadata, no raw task logs/commands |

<a id="v23-12-04"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-12-04 -->
**Staleness and availability.** Mark datasets stale after three missed intervals; partial polls do not erase unseen guests, and only a complete enumeration may tombstone them. `poxmox` may be on-demand: expected-offline is grey UNKNOWN with a reason, not an alarm. Offsite VPN loss changes neither trust nor endpoints. Unknown, denied, incomplete and unavailable stay distinct from empty/zero/healthy. Foreign task metadata is untrusted evidence, not the NOS audit. Subscription/ZFS-health fields needing more privileges stay unavailable. PVE state can explain Ops State but cannot establish SSH health.

<a id="v23-12-05"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-12-05 -->
**Backup confidence.** Read-only tokens may lack full backup catalogs due to write-privilege filtering; show unavailable: insufficient read privileges rather than borrow action tokens/widen ACLs. Task success is evidence of a past run, distinct from currently present/restorable backup, catalog availability and verification/restore confidence. Compare last evidenced success against operator-selected maximum age, default 24 h; stale/failed/overdue evidence warns in phase 1. Denied catalogs and missing samples remain unknown/unavailable, never no backups or backup safe. PBS retention/verification needs a separately approved read-only source; no implicit credential integration.

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

<a id="v24-12-01"></a>
<!-- Spec revision (ADR 0011, VU-02): v24-12-01 -->
**Vulnerability findings (ADR 0011 D1, D2).** A finding is one vulnerability on one component of one subject: a managed host or linked guest OS, a container image by platform digest, or a network device (ADR 0010). The Hermes agent (VM `hermes`, outside NOS) fetches feeds, matches and writes an assessment; NOS is the system of record. There is one finding store, holding Hermes findings only; NOS computes `finding_key` from the validated fields. The P1-30 host-local Trivy result stays a separate, partial `trivy-local` observation (previously: planned as observer `trivy-local` in the store) that never opens, closes or re-opens a finding and is never closed by a Hermes run; when both exist they are shown side by side, labelled, never merged. Findings, scores, priorities, paths and assessment text are **advisory**: none ever creates, submits or approves a proposal, permit, lease or schedule. Every fix goes through the existing proposal and approval flow.

- **Version basis.** Debian and Ubuntu packages compare on the installed `source:Version` (lowest across the source package's binaries) against the fixed **source** version with dpkg ordering, never the binary version, an upstream version or a CPE range. Kernel findings use the **running** kernel mapped to its unsigned kernel source; installing a fixed kernel closes nothing, booting it does ("fixed after reboot" until then); an unmappable kernel is "kernel version unknown". Proxmox packages are "coverage unknown", never clean.
- **Re-check label.** Findings NOS cannot re-check (images without `image.packages`, language ecosystems, vendor and CPE matches, an unmapped kernel) are labelled "not re-checked by NOS"; the label never feeds a closure decision.

<a id="v24-12-02"></a>
<!-- Spec revision (ADR 0011, VU-02): v24-12-02 -->
**Finding states and closure (ADR 0011 D5, D6).**

| State | Set by | Rules |
| --- | --- | --- |
| `open` | Hermes run (new or re-opened) | Default |
| `fixed` | Only through the closure paths below; stores `closed_by` (`nos_inventory`, `subject_removed`, `hermes_unconfirmed`, `admin_confirmed`) | Re-opens when a run with `run_seq ≥ state_run_seq` reports it again; a re-open starts a new episode. `hermes_unconfirmed` is shown everywhere as "closed by Hermes, not confirmed by NOS", has its own filter, and a subject with such closures is never clean or green |
| `accepted_risk` | **Maintainer (admin) only**, each time with a **fresh WebAuthn assertion** | Reason (≤ 1 KiB), approver, expiry (default 90 days, **maximum 365 days**; a longer expiry is refused); re-opens on expiry, when the finding becomes KEV-listed, or when its version basis changes or becomes unknown |
| `false_positive` | **Maintainer (admin) only**, each time with a **fresh WebAuthn assertion** | Category (`backport_fixed`, `not_affected_config`, `component_not_used`, `vendor_disputed`, `other`) and reason (≤ 1 KiB); re-opens when its version basis changes or becomes unknown |

Q4, decided 2026-11-09 (previously: admins only, assertion and maximum expiry open). The same rule (maintainer, fresh WebAuthn assertion, as for read-lease approval) covers confirming or discarding a held closure and resetting a feed high-water mark. The Hermes token can do none of these; its `likely_false_positive` flag only sorts and annotates. The version basis stored with a human state is the D4 basis (`source:Version`; kernel: the mapped running kernel; images: the `image.packages` source version; devices: firmware), so a binNMU-only change or an installed but not booted kernel changes nothing, and "unknown" re-opens.

**Closure paths.** No other path closes a finding: (1) NOS inventory shows the basis version `≥` the episode fixed version in a **complete** read newer than the finding's last write (kernel: mapped running kernel); (2) NOS inventory shows the source package absent from a complete read (never for the kernel); (3) the subject was removed by an admin or its image digest is absent from a complete Docker read of every host that ran it; (4) a run closure that NOS evidence confirms; (5) an unconfirmed run closure; (6) a held closure confirmed by the maintainer; (7) a hold discarded (the finding stays open). Run closures (omission of a finding, or a `not_affected` record) come only from a **complete** run, ordered by `run_seq` (`run_seq ≥ state_run_seq`, at or above the subject watermark), serialized per subject, with the subject fully covered, every basis source named, accepted, dated and not stale, and no rejected record of that `finding_key` or rejected batch in the run.

- **Contradicted** closures (NOS's current inventory still shows the component below the episode fixed version) are **always held** for the maintainer and can never become plain `fixed`; the maintainer can only discard the hold or set a human state.
- **Unconfirmed** closures of findings that are episode KEV or reached the critical tier in the episode are always held; these high-water marks never fall inside an episode, so dropping the KEV flag or lowering a score first does not help. Closures resting on a source on probation after a mark reset are held as well. Other unconfirmed closures close as `hermes_unconfirmed`.
- **Bulk-closure guards.** A run whose unevidenced closures exceed 50 % and at least 20 of the findings open at its start on the subjects it covered (or 50 % and 10 of one subject) has all of them held as "suspicious run, confirm". The same limits apply cumulatively over a rolling 24 h window whose baseline is the findings open at the window start. Below the floors (up to 19 unevidenced closures a day, fewer than 10 per subject) the guards do not trip; there the protection is the always-held classes and the visible "not confirmed by NOS" label.
- Maintainer confirmation re-checks `state_run_seq` and the subject watermark; a newer run supersedes the hold.

<a id="v24-12-03"></a>
<!-- Spec revision (ADR 0011, VU-02): v24-12-03 -->
**Staleness and feed ages (ADR 0011 D4, D5, D6; Q5, decided 2026-11-09).** Unknown, stale or not assessed is never zero, clean, safe or green.

- **Subject staleness.** A subject whose last complete Hermes run is older than **48 h** shows its findings "stale since …"; a subject with no complete run is "not assessed". Hermes offline for more than 48 h raises one `vuln.hermes_stale`.
- **Maximum snapshot age per feed source.** **72 h** for daily feeds (Debian tracker, OSV, NVD, KEV, EPSS) and **30 days** for vendor CSAF and signed offline bundles; an operator may lower but not raise these. A source past its age is "feed `<source>` stale since …" on the vulnerabilities page and on every finding resting on it, raises `vuln.feed_stale` and closes nothing through a run (only NOS evidence closes such findings).
- **Content dates.** A source's age is NOS's clock minus its content date, taken from the data or a dated companion, never Hermes' fetch time. The Debian tracker JSON is **proxy-dated** by the newest DSA/DLA list date (`proxy:<companion>`). A source with content date kind `none` is "undated, freshness unknown" and counts as stale.
- **Per-source high-water marks.** Source IDs come from a fixed list shipped with NOS (changed only by a release). NOS keeps per listed source the newest content date and highest bundle `sequence` ever accepted, also across runs that omit the source. A run naming a source below its mark (**regressed**) or more than 10 minutes in NOS's future (**invalid**) still starts; that source alone is frozen for the run: it closes nothing, while findings resting on it are still opened and re-opened (including KEV). It is shown as "feed `<source>` behind its high-water mark" or "dated in the future" and raises `vuln.feed_regressed`. An ID not on the list is **unknown**: no mark, closes nothing, no per-ID notification.
- **Raise-only.** A record any of whose basis sources is regressed, invalid, unknown, undated or on probation may raise a finding (higher fixed version, new KEV flag, higher score) but never lowers its fixed version (including a switch to `no_fix_yet` or `wont_fix`), KEV flag, scores, tier or assessment text; each ignored change is listed in the run report. Limit (accepted with the proxy date, Q5): a proxy-dated source is not raise-only, so a replay of the tracker JSON beside fresh DSA/DLA lists can lower current values, never the episode marks, and a freeze of the tracker JSON alone is not detected.
- **Mark reset.** Only the maintainer, with a fresh WebAuthn assertion and a reason (≤ 1 KiB), can lower a source's mark, and only to the value the latest regressed run reported; the reset is audited and raises `vuln.feed_mark_reset`. The source then stays on probation (raise-only, unevidenced closures held) until a run names it strictly above the pre-reset mark.

<a id="v24-12-04"></a>
<!-- Spec revision (ADR 0011, VU-02): v24-12-04 -->
**Vulnerability presentation and priority (ADR 0011 D7, D8).** A vulnerabilities page lists findings by vulnerability and by subject with filters (tier, KEV, state, subject kind, stale, "closed by Hermes, not confirmed by NOS"); host, image and device details get a Vulnerabilities tab with states, labelled assessment, coverage and run age. Priority is computed by NOS with the versioned formula `vu-prio-v1` (stored with each value) from CVSS, KEV, EPSS, exposure (unknown exposure weighs like a NetBird/VPN entry, never like internal-only) and host criticality; a KEV finding is never below tier high. The LLM supplies text only. Org-chart badges reuse the P1-30 container CVE badge and the host patch badge and border colour (red for an open critical-tier finding), labelled with their observer; unknown or stale is labelled, never green. "Fix with" links only prefill existing proposal flows, never submit: an OS update counts as a fix only when the candidate's source version is `≥` the fixed version, otherwise "fix not verified"; a kernel fix says "reboot required".

<a id="v24-12-05"></a>
<!-- Spec revision (ADR 0011, VU-02): v24-12-05 -->
**Crown jewels and attack paths (ADR 0011 D10; Q6, Q7, Q8 decided 2026-11-09).** The maintainer marks at most 50 attack-path targets ("crown jewels") with a role and an impact weight 1–10; marking, changing and unmarking are audited admin actions with history. Default weights by role are suggestions the admin confirms: NOS executor host and firewall 10; Proxmox nodes, NAS and Home Assistant host 8 (previously: suggested executor 10, Proxmox 8, NAS 8, Home Assistant 6, no firewall). Roles only; NOS fills no weight from a role or name, and no addresses or host names are in code or fixtures. Attack paths are computed by NOS deterministically, **admin-only**, not served by the read-only or the agent API, and **Hermes may not read attack-path steps or topology** (Q6; most restrictive, the maintainer may revisit; previously: open, with optional Hermes path narratives). Listener process names are not used to map packages to ports (Q8; most restrictive, the maintainer may revisit); unmapped steps stay "possible" and flagged. "No path found" with low coverage reads "unknown", never "safe".
