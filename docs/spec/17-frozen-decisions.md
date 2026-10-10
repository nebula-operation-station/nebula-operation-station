<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Frozen project decisions before Milestone 1

The pre-Milestone-1 architecture decisions are now closed. Changes to these decisions require an explicit architecture revision rather than an implementation convenience change.

- [x] **Public name:** Nebula Operation Station. Internal binaries/services keep the `nebula-*` prefix.
- [x] **License:** AGPL-3.0-or-later for the entire project.
- [x] **Code hosting:** GitHub, preferably under a dedicated organization.
- [x] **Web frontend:** server-rendered Go templates + htmx; strict CSP; no SPA requirement for V1.
- [x] **RPC:** gRPC + Protobuf over `/run/nebula/executor.sock`.
- [x] **Default approval mode:** Standard; hardened CLI approval remains optional.
- [x] **Vault unlock:** CLI is default/recommended; Web unlock is opt-in and labelled weaker.
- [x] **Supported targets for 0.1:** Debian 12, Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, Proxmox VE 8 and 9 as Debian-based hosts.
- [x] **First-party signing key:** offline Ed25519 root key, never stored in CI, with signed rotation metadata and encrypted offline recovery backup.

### Implementation details that remain intentionally non-architectural

The following can be chosen during implementation without reopening the architecture unless they alter the stated trust model or compatibility guarantees:

- exact GitHub organization/repository name and domain name availability
- exact CSS/component styling for the Go/htmx UI
- protobuf package names and field numbering
- concrete timeout and payload-limit defaults, provided they stay within the security model
- exact release automation tooling around the offline signing step
- exact hardware/media used to store the offline signing key and its recovery copy
