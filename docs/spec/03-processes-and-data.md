<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Processes, data stores and what each may access

Each role runs under its own OS user, and filesystem permissions enforce the split. The split protects against a compromised web process; it does not protect against root or kernel compromise of the Nebula machine, and the documentation says so.

<a id="v23-03-01"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-03-01 -->
| Process | OS user | Holds and does | Never has |
| --- | --- | --- | --- |
| `nebula-server` | `nebula-server` | Web UI, inventory, IPAM, execution planning, read-grant triggers, audit view, read-only API, vulnerability agent API and findings store (ADR 0011; previously: read-only API only), notifications, anonymous approved public registry metadata | SSH keys, vault plaintext, vault master key, signer private keys, authority to execute |
| `nebula-executor` | `nebula-executor` | ssh-agent, vault, SSH sessions, host-key and PVE TLS trust, typed PVE/private registry HTTPS, read grants/budgets, permit and WebAuthn verification, artifact hash checks, signing of executor events | Any network listener; it only serves a Unix socket |
| `nebula-discovery` | `nebula-discovery` | One-shot Nmap runs with `CAP_NET_RAW`, results go to staging | Credentials, database access |
| `nebula-pve-collector` | `nebula-pve-collector` | Typed provider read scheduling over the executor socket, sanitized result spool | Credentials, database access, network access/listener, capabilities, mutation or approval methods |
| `nebula` CLI | an admin user | Vault unlock, hardened approval, backup, restore | Persistent state of its own |

<a id="v23-03-02"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-03-02 -->
**Executor socket.** `/run/nebula/executor.sock`, owner `nebula-executor`, group `nebula-rpc`, mode 0660. gRPC over the socket. On every connection the executor reads the peer UID via `SO_PEERCRED` and allows a fixed method set per UID: the server may propose/query work and relay browser assertions for executor verification; only the admin CLI may unlock or give hardened approval. The server may also lock and revoke read grants, since these remove capability. The `pve-collector` UID may call only provider metadata/read methods, never unlock, approve, propose mutations or reveal secrets. Group membership alone is not authorization.

**Data stores.**

<a id="v23-03-03"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-03-03 -->
| Path | Owner | Content |
| --- | --- | --- |
| `/var/lib/nebula/server/nebula.db` | `nebula-server` | Users, hosts, assets, networks, IP allocations, groups, tags, module metadata, execution metadata, audit, scheduler configuration, presentation copies of PVE inventory and links, normalized telemetry/backup/scan evidence, public registry cache, credential references (names and types only) |
| `/var/lib/nebula/server/artifacts/<sha256>` | `nebula-server` | Immutable, content-addressed scripts and manifests |
| `/var/lib/nebula/executor/executor.db` | `nebula-executor` | Host keys, trusted signers/artifact trust, WebAuthn public keys/counters, signed executor events, spent execution IDs, durable job intent/outcomes, authoritative PVE remote endpoints/pins/criticality/generations/tombstones, approved read grants and durable budget claims, encrypted vault master key and envelope-encrypted secrets |

<a id="v23-03-04"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-03-04 -->
The server and collector cannot read the executor database or key files. The executor receives artifact bytes over RPC and computes the hash itself; it never trusts a hash the server reports.

<a id="v23-03-05"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-03-05 -->
**Durable authority and volatile approval.** Approved read grants, their spent budgets and legacy schedule grants persist in `executor.db`; pending proposals, execution/batch approvals, derived permits, gate state, unlocked secrets and privileged sessions are memory-only. Every restart starts locked and revokes mutation authority; only still-valid read grants resume after explicit local unlock. Job intent/outcomes survive for observation and reconciliation, never redispatch authority. This reflects M0 decisions 15, 41 and 61, while adding the shared grant registry in [07-execution-model.md](07-execution-model.md).

<a id="v23-03-06"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-03-06 -->
**Collector authority lifecycle.** A fixed peercred UID method set is only permission to request typed reads; actual remote/method/target authority, minimum intervals, budgets and expiry come exclusively from the executor's standing read grant. Lock/restart pauses use; expiry, removal, re-pin, rotation or grant revocation stops affected reads. Record caller UID, grant and target, budget claims, denials and outcomes without secrets. The ADRs specify no independent expiry or provisioning/revocation protocol for the collector UID mapping; that remains an explicit [open question](17-frozen-decisions.md). No collector membership can outlive or widen its grant's execution authority.

<a id="v23-03-07"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-03-07 -->
**Observation storage and spool.** The server stores `pve_remotes`, `pve_nodes`, `pve_guests`, `pve_guest_configs`, `pve_interfaces`, `pve_snapshots`, `pve_backup_observations`, `pve_storages`, `pve_cluster_status`, `pve_tasks`, `pve_host_links` and `pve_staging`. Remote children carry `remote_id`, guests carry VMID/generation, and every dataset carries `observed_at`, source, collection generation and completeness/availability reason. Validate and commit each dataset atomically; partial polls never erase unseen guests, and only complete enumeration may tombstone them. Keep current inventory, 30 days of task/drift metadata and explicit link/tombstone history. Normalized metric/evidence records carry the same identity/incarnation/source fields; never raw output. Spool ownership and validation follow [09-untrusted-host-data.md](09-untrusted-host-data.md).

<a id="v24-03-01"></a>
<!-- Spec revision (ADR 0011, VU-02): v24-03-01 -->
**Hermes as an external API client (ADR 0011 D1, D3, D5).** The Hermes agent runs on its own VM (`hermes`) outside NOS and is not a NOS process, user or role: it has no OS user on the Nebula machine, no socket access, no database access, no SSH keys, host credentials, vault or NOS secrets. It talks to `nebula-server` only through the vulnerability agent API ([13-notifications.md](13-notifications.md#v24-13-01)) with the one `hermes-vuln` token. It is the only component that fetches CVE feeds for the finding store; `nebula-server` and `nebula-executor` gain no feed egress (Q2, decided 2026-11-09: egress only from `hermes`, no proxy assumed and none that terminates TLS; the proxy part is most restrictive and the maintainer may revisit). Findings never reach the executor or the permit path. The documented exception is the operator-managed host-local Trivy database of P1-30, which never feeds the finding store.

<a id="v24-03-02"></a>
<!-- Spec revision (ADR 0011, VU-02): v24-03-02 -->
**Vulnerability tables and retention (ADR 0011 D5, D6, D10; Q3, decided 2026-11-09).** `nebula.db` (owner `nebula-server`) adds the findings store (`vuln_findings`, `vuln_finding_history`, `vuln_held_closures`, `vuln_subject_watermarks`), run records (`vuln_runs`, `vuln_run_sources`, `vuln_run_batches`, `vuln_run_subjects`, `vuln_run_reported`, `vuln_run_rejected`), per-source high-water marks and their resets (`vuln_source_marks`, `vuln_mark_resets`), `vuln_store_state`, and the crown jewels (`crown_jewels`, `crown_jewel_history`). `executor.db` gains nothing. Feed data is never stored in NOS; only per-finding scores, basis sources and snapshot IDs (Hermes assertions kept for audit, not a trust anchor). Retention defaults, as proposed and decided (previously: open):

| Data | Kept |
| --- | --- |
| Open, `accepted_risk` and `false_positive` findings | While the subject exists |
| `fixed` findings | 365 days after closing |
| Finding history entries | 365 days |
| Run records | 90 days after the run ended |
| Assessment text of closed findings | 90 days |
| Crown-jewel history | Kept; bounded by admin actions |
