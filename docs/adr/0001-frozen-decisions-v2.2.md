# ADR 0001: Decisions frozen with specification v2.2

Status: accepted, 2026-10-09

## Decisions

| Area | Decision |
| --- | --- |
| Product name | Nebula Operation Station; binaries and services keep the `nebula-*` prefix |
| License | AGPL-3.0-or-later for the entire project |
| Hosting | GitHub, dedicated organization |
| Web frontend | Server-rendered Go templates + htmx, strict CSP, no SPA |
| Internal RPC | gRPC + Protobuf over `/run/nebula/executor.sock` |
| Approval mode | Standard by default; hardened CLI approval optional |
| Vault unlock | CLI by default; web unlock opt-in and labelled weaker |
| Targets for 0.1 | Debian 12, Ubuntu 22.04, Ubuntu 24.04, Proxmox VE 8 and 9 |
| Release signing | Offline Ed25519 root key, never in CI, signed rotation metadata |

## Consequences

Changing any of these requires a new ADR that supersedes this one. Implementation convenience is not a reason. The full rationale is in `docs/spec/04-revision-history.md` and `docs/spec/17-frozen-decisions.md`.
