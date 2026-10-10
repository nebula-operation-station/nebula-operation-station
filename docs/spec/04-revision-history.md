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
