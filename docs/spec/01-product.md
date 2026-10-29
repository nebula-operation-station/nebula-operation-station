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
Not a goal for V1: Windows, a persistent agent, event-triggered or scheduled mutations, automatic patching, reboots, Docker updates or rollbacks, Kubernetes, general storage management, general vulnerability scanning or monitoring dashboards, DNS or DHCP management, OIDC, enterprise RBAC, a full Ansible replacement, third-party server plugins, a self-updater. The bounded inventory telemetry and optional local-image CVE observations below are the only monitoring/scanning exceptions introduced here; no InfluxDB endpoint is added.

<a id="v23-01-03"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-01-03 -->
**Proxmox integration phases.** Phase 1 adds read-only PVE remotes, reviewed inventory links and staging, an org chart, patch/image state, optional host-local image CVE observations, backup-freshness warnings, GPU/CPU/RAM/filesystem values with 24 h averages, service checks, drift hints and PVE deep links. Phase 2 adds explicitly approved VM/LXC operations and tree-triggered OS/container/Compose updates and rollback; lifecycle actions ship first, with each further privilege profile gated separately. Phase 3 adds optional snapshot-before-update and provisioning; consoles require a separate credential/session review. Rolling node maintenance, cross-remote migration, WoL, Datacenter Manager and hypervisor shells remain separately scoped follow-ups. These phases do not imply unattended mutations.

<a id="v23-01-04"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-01-04 -->
**Standing reads and exact change plans.** The executor holds durable read grants for frozen actions, targets and parameters; the server or collector may trigger only those reads and spend their budgets, without a privileged session or per-run assertion. A compromised server can consume this bounded disclosure/load authority and see sanitized results. Mixed-action batches authorize one fully enumerated change plan, with single-use members, existing gates and no CRITICAL members; they do not authorize future plans. See [05-authentication.md](05-authentication.md) and [07-execution-model.md](07-execution-model.md).
