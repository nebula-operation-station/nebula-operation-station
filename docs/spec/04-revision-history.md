<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Changes from v2.1

This revision freezes the pre-Milestone-1 architecture decisions from v2.1. The security model and technical architecture remain unchanged unless explicitly noted below. The public product name is now **Nebula Operation Station**. Internal binary and service names may continue to use the short `nebula-*` prefix.

| Area | Decision in v2.2 | Reason |
| --- | --- | --- |
| Product name | **Nebula Operation Station**; `nebula-*` remains the internal binary/service prefix | Clear public identity while preserving concise technical names |
| License | **AGPL-3.0-or-later for the entire project**, including core, CLI, modules, schemas, SDK and examples | One consistent strong-copyleft license; modified network-served versions remain open |
| Code hosting | **GitHub**, preferably under a dedicated organization | Security advisories, CI, dependency tooling, releases and contributor reach |
| Web frontend | **Server-rendered Go templates + htmx**; no SPA required for V1 | Small attack surface, strict CSP, no mandatory Node build |
| RPC | **gRPC + Protobuf over Unix Domain Socket** | Typed contracts, streaming support and clear method boundaries |
| Approval mode | **Standard mode by default**; hardened CLI approval remains available | Good homelab usability without removing the stronger trust path |
| Vault unlock | **CLI unlock is default and recommended**; Web unlock is optional and explicitly labelled weaker | A compromised web process should not normally see the passphrase |
| Supported 0.1 targets | **Debian 12, Ubuntu 22.04 LTS, Ubuntu 24.04 LTS; Proxmox VE 8 and 9 as Debian-based hosts with adapter-specific behavior** | Focused, testable support matrix with immediate homelab value |
| First-party signing key | **Offline Ed25519 root signing key**; never stored in GitHub Actions; public key ships with the project; signed rotation metadata; encrypted offline recovery backup | Keeps release trust outside CI compromise scope |

<a id="v23-04-01"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-04-01 -->
**Spec v2.3 (ADR 0006, ADR 0007).** The accepted Proxmox integration and approval-ergonomics decisions revise the v2.2 baseline: executor-owned typed PVE HTTPS and credentials, a separate collector UID, scoped registry metadata egress, durable ordinary/provider/telemetry read leases, exact mixed-action batch approval, local bulk built-in trust and configurable privileged sessions. ADR 0007 replaces ADR 0006's proposed 90-day provider maximum with a 7-day default/30-day maximum for new grants and renewals; existing schedule-only signatures retain their original scope/expiry. Phase 1 remains read-only; phase 2 mutations need exact permits, and unresolved profiles remain gated. Every changed paragraph/block and explicit open question is recorded in [17-frozen-decisions.md](17-frozen-decisions.md).

**Owner-approved revision, 2026-10-30 — no Veeam support.** PBS covers backup evidence via [ADR 0006 P1-20/P1-29](../adr/0006-proxmox-integration.md#tickets-for-phase-1); P1-28 remains dropped. This decision supersedes the Veeam requirements in [module observation contracts](10-modules.md#v23-10-03) and [inventory backup evidence/confidence](12-inventory.md#v23-12-03), and the corresponding read-lease addition in [ADR 0007](../adr/0007-approval-ergonomics.md#one-standing-read-grant-mechanism). The Veeam-only `backup.status` contract and local metadata collection are dropped; available nonsecret vzdump/PBS/task evidence and existing backup-confidence safeguards remain.
