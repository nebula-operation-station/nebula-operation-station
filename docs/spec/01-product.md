<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Product definition, principles and non-goals

Nebula Operation Station is a self-hosted operations control plane for Linux homelabs of about 5 to 100 hosts. It makes administrative changes visible, controlled, reviewable, reproducible, recoverable and auditable.

It combines a network asset inventory with light IPAM, a managed host inventory, SSH-based operations, Debian/Ubuntu patching, service and Docker operations, versioned runbooks, extensible host-side modules, staged multi-host rollouts, execution history and executor-held credentials.

Stack: Go, SQLite, Linux, SSH. One static binary per role, no external database or message broker.

Principles:

- **Agentless-first.** No persistent Nebula daemon on managed hosts. Hosts may keep small state under `/var/lib/nebula/` (`inventory.json`, `jobs/`); scripts are transferred only for execution.
- **Operator-driven.** Nebula never patches, reboots, updates containers, rolls back hosts or changes network configuration on its own in V1. Scheduling is limited to read-only work: discovery, update checks, Docker digest checks, facts.
- **Pull-first.** Nebula fetches information. Managed hosts never receive Nebula credentials and never write into Nebula's databases.
- **The server proposes, the executor authorizes.** Every privileged action is bound to the exact artifact, targets, parameters and credentials that were approved.
- **Host data is untrusted input.**
- **Honest limits.** Where a protection is partial, the documentation says so.

Not a goal for V1: Windows, a persistent agent, event-triggered or scheduled privileged automation, automatic patching, reboots, Docker updates or rollbacks, Kubernetes, storage management, vulnerability scanning, monitoring dashboards, DNS or DHCP management, OIDC, enterprise RBAC, a full Ansible replacement, third-party server plugins, a self-updater.
