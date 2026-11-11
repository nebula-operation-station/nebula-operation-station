<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Product definition, principles and non-goals

Nebula Operation Station is a self-hosted operations control plane for Linux homelabs of about 5 to 100 hosts. It makes administrative changes visible, controlled, reviewable, reproducible, recoverable and auditable.

It combines a network asset inventory with light IPAM, a managed host inventory, SSH-based operations, Debian/Ubuntu patching, service and Docker operations, versioned runbooks, extensible host-side modules, staged multi-host rollouts, execution history and executor-held credentials.

Stack: Go, SQLite, Linux, SSH. One static binary per role, no external database or message broker.

Principles:

<a id="v23-01-01"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-01-01 -->
- **Agentless-first.** No persistent Nebula daemon on managed hosts. Hosts may keep small state under `/var/lib/nebula/` (`inventory.json`, `jobs/`); scripts are transferred only for execution.
- **Operator-driven.** Nebula never patches, reboots, updates containers, rolls back hosts or changes network configuration on its own in V1. Scheduling and on-demand read leases are limited to reviewed read-only work under the exact scopes, expiry and budgets in [07-execution-model.md](07-execution-model.md); discovery retains its separate reviewed scan scope.
- **Pull-first.** Nebula fetches information. Managed hosts never receive Nebula credentials and never write into Nebula's databases.
- **The server proposes, the executor authorizes.** Every privileged action is bound to the exact artifact, targets, parameters and credentials that were approved.
- **Host data is untrusted input.**
- **Honest limits.** Where a protection is partial, the documentation says so.

<a id="v23-01-02"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-01-02 -->
Not a goal for V1: Windows, a persistent agent, event-triggered or scheduled mutations, automatic patching, reboots, Docker updates or rollbacks, Kubernetes, general storage management, general vulnerability scanning or monitoring dashboards, DNS or DHCP management, OIDC, enterprise RBAC, a full Ansible replacement, third-party server plugins, a self-updater. The bounded inventory telemetry and optional local-image CVE observations below are the only monitoring/scanning exceptions introduced here; no InfluxDB endpoint is added. ADR 0011 adds advisory vulnerability management below; it scans nothing itself (previously: the two exceptions above only). ADR 0015 adds bounded, advisory integrity monitoring below as a further exception (previously: no integrity monitoring).

<a id="v24-01-01"></a>
<!-- Spec revision (ADR 0011, VU-02): v24-01-01 -->
**Vulnerability management (ADR 0011, accepted 2026-11-09).** NOS records which known vulnerabilities apply to its hosts, images and network devices, prioritises them and shows attack paths to the maintainer's crown jewels. The Hermes agent on its own VM fetches the CVE feeds, matches and writes an assessment; NOS exports a bounded package inventory to it, stores and re-checks its findings and computes priorities and paths itself. Findings are **advisory**: no finding, score, path or assessment ever patches, updates, proposes, schedules or approves anything, so this does not change "Operator-driven" above. Still not goals: automatic patching from findings, feed fetching, matching or an LLM inside NOS, an agent on managed hosts, active vulnerability probing or exploitation, matching distro packages on upstream versions, compliance reporting, device firmware updates.

<a id="v26-01-01"></a>
<!-- Spec revision (ADR 0015, IG-01): v26-01-01 -->
**Integrity monitoring (ADR 0015, accepted 2026-11-11).** A bounded monitoring exception next to vulnerability management above. **I1** checks NOS's own binaries, systemd units, built-in module files, web assets and root keys on the NOS machine against the YubiKey-signed `installed-files.json` of the admitted release, and NOS configuration against an admin-approved baseline. **I2** reads selected paths on managed Debian, Ubuntu and PVE hosts agentlessly with the fixed read-only built-in action `fim.scan` inside an approved read lease and compares them with a NOS-held, admin-approved baseline, and package files additionally with signed archive references once the package reference builder exists (ADR 0015 D8, Q6). I3 (measured boot and TPM attestation) is not part of this revision; it needs its own ADR (Q5). Findings are **advisory**, like ADR 0011 findings: no integrity finding ever patches, restores, reinstalls, rolls back or quarantines anything, and none starts, approves or authorizes an action, so this does not change "Operator-driven" or "Agentless-first" above (no daemon, timer, state file or baseline on the host). The only reactions that *withhold* NOS authority are the I1 unlock refusal on a code mismatch ([06-credentials.md](06-credentials.md#v26-06-01)) and the opt-in per-host "block mutations on open critical integrity finding", which withholds new permits, never cancels a running job, never touches the host and can always be overridden by the admin with a fresh assertion (Q3). **Honest limits.** A root attacker on a machine controls every answer that machine gives: I1 and I2 detect operator error, faulty automation and ordinary attackers, not a root attacker who tampers with the checker. A clean I2 result means "the host reported no unexpected change", never "the host is not compromised", and the UI and documentation use exactly that wording; the limits are listed in ADR 0015 "Honest limits". Still not goals: a persistent agent, inotify/fanotify, auditd or eBPF sensor on managed hosts, automatic restore or rollback, proving the absence of a rootkit, integrity of databases, logs and spools, containers or LXC guests as separate subjects, Windows and network devices.

<a id="v23-01-03"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-01-03 -->
**Proxmox integration phases.** Phase 1 adds read-only PVE remotes, reviewed inventory links and staging, an org chart, patch/image state, optional host-local image CVE observations, backup-freshness warnings, GPU/CPU/RAM/filesystem values with 24 h averages, service checks, drift hints and PVE deep links. Phase 2 adds explicitly approved VM/LXC operations and tree-triggered OS/container/Compose updates and rollback; lifecycle actions ship first, with each further privilege profile gated separately. Phase 3 adds optional snapshot-before-update and provisioning; consoles require a separate credential/session review. Rolling node maintenance, cross-remote migration, WoL, Datacenter Manager and hypervisor shells remain separately scoped follow-ups. These phases do not imply unattended mutations.

<a id="v23-01-04"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-01-04 -->
**Standing reads and exact change plans.** The executor holds durable read grants for frozen actions, targets and parameters; the server or collector may trigger only those reads and spend their budgets, without a privileged session or per-run assertion. A compromised server can consume this bounded disclosure/load authority and see sanitized results. Mixed-action batches authorize one fully enumerated change plan, with single-use members, existing gates and no CRITICAL members; they do not authorize future plans. See [05-authentication.md](05-authentication.md) and [07-execution-model.md](07-execution-model.md).
