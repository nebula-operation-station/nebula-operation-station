# ADR 0002: Libraries for the Milestone 0 security core

Status: accepted, 2026-10-10

The security core uses established libraries instead of hand-written cryptography or parsers.

| Need | Library | License | Why |
| --- | --- | --- | --- |
| RFC 8785 JSON canonicalization | `github.com/gowebpki/jcs` | Apache-2.0 | Port of the reference implementation by the RFC author |
| WebAuthn assertion verification | `github.com/go-webauthn/webauthn/protocol` | BSD-3-Clause | Maintained, used by many Go relying parties; we call the low-level `Verify` so the executor controls challenge and credential storage |
| SSH keys, agent keyring | `golang.org/x/crypto/ssh`, `.../ssh/agent` | BSD-3-Clause | Standard OpenSSH key format, in-process keyring |
| Peer credentials | `golang.org/x/sys/unix` | BSD-3-Clause | `SO_PEERCRED`, `prctl` |
| RPC | `google.golang.org/grpc`, `google.golang.org/protobuf` | Apache-2.0, BSD-3-Clause | Frozen decision (ADR 0001) |
| Test authenticator | `github.com/descope/virtualwebauthn` (tests only) | MIT | Produces real signed assertions without a browser |

All licenses are compatible with AGPL-3.0-or-later.

Rule for contributors and agents: no new dependency in `internal/canonical`, `internal/permit`, `internal/peercred`, `internal/keyring`, `internal/webauthnverify` or `internal/fsguard` without a new ADR.
