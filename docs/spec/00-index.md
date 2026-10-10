# Specification index

Nebula Operation Station, Technical Specification v2.2 (decision-frozen, Oct 9, 2026), split into one file per section so that agents and reviewers can load only what a task needs.

Changing anything here is an architecture revision, not an implementation detail. See `17-frozen-decisions.md` and `../adr/`.

| File | Section |
| --- | --- |
| [01-product.md](01-product.md) | Product definition, principles and non-goals |
| [02-architecture.md](02-architecture.md) | Architecture and trust boundary |
| [03-processes-and-data.md](03-processes-and-data.md) | Processes, data stores and what each may access |
| [04-revision-history.md](04-revision-history.md) | Changes from v2.1 |
| [05-authentication.md](05-authentication.md) | Authentication, sessions and approval |
| [06-credentials.md](06-credentials.md) | Credentials: executor-owned agent and secret vault |
| [07-execution-model.md](07-execution-model.md) | Execution model: permits, stages, durable jobs, reconciliation |
| [08-ssh-transport.md](08-ssh-transport.md) | SSH transport and host identity |
| [09-untrusted-host-data.md](09-untrusted-host-data.md) | Untrusted host data and log safety |
| [10-modules.md](10-modules.md) | Modules, runbooks, OS adapters and trust |
| [11-operations.md](11-operations.md) | Operations: patching, services, Docker |
| [12-inventory.md](12-inventory.md) | Inventory, IPAM and discovery |
| [13-notifications.md](13-notifications.md) | Notifications and integrations |
| [14-open-source-project.md](14-open-source-project.md) | Open-source project: license, releases, install paths, security process |
| [15-backup-and-upgrades.md](15-backup-and-upgrades.md) | Backup, restore and upgrades |
| [16-milestones.md](16-milestones.md) | Milestones |
| [17-frozen-decisions.md](17-frozen-decisions.md) | Frozen project decisions before Milestone 1 |

Implementation status and documented deviations: [`../implementation/m0.md`](../implementation/m0.md).
