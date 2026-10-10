<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Processes, data stores and what each may access

Each role runs under its own OS user, and filesystem permissions enforce the split. The split protects against a compromised web process; it does not protect against root or kernel compromise of the Nebula machine, and the documentation says so.

| Process | OS user | Holds and does | Never has |
| --- | --- | --- | --- |
| `nebula-server` | `nebula-server` | Web UI, inventory, IPAM, execution planning, read-only scheduler, audit view, read-only API, notifications | SSH keys, vault plaintext, vault master key, signer private keys, authority to execute |
| `nebula-executor` | `nebula-executor` | ssh-agent, vault, SSH sessions, host-key trust, permit and WebAuthn verification, artifact hash checks, signing of executor events | Any network listener; it only serves a Unix socket |
| `nebula-discovery` | `nebula-discovery` | One-shot Nmap runs with `CAP_NET_RAW`, results go to staging | Credentials, database access |
| `nebula` CLI | an admin user | Vault unlock, hardened approval, backup, restore | Persistent state of its own |

**Executor socket.** `/run/nebula/executor.sock`, owner `nebula-executor`, group `nebula-rpc`, mode 0660. gRPC over the socket. On every connection the executor reads the peer UID via `SO_PEERCRED` and allows a fixed method set per UID: the server may propose and query; only the admin CLI may unlock, approve and lock. Group membership alone is not authorization.

**Data stores.**

| Path | Owner | Content |
| --- | --- | --- |
| `/var/lib/nebula/server/nebula.db` | `nebula-server` | Users, hosts, assets, networks, IP allocations, groups, tags, module metadata, execution metadata, audit, scheduler configuration, credential references (names and types only) |
| `/var/lib/nebula/server/artifacts/<sha256>` | `nebula-server` | Immutable, content-addressed scripts and manifests |
| `/var/lib/nebula/executor/executor.db` | `nebula-executor` | Host keys, trusted signers, permits, privileged session state, WebAuthn public keys for approval, signed executor events |
| `/var/lib/nebula/executor/vault.db` | `nebula-executor` | Encrypted vault master key, envelope-encrypted secrets |

The server cannot read either executor file. The executor receives artifact bytes over RPC and computes the hash itself; it never trusts a hash the server reports.
