# ADR 0004: age for backup encryption

Status: accepted, 2026-10-19

Spec 15 encrypts every backup by default "to an `age` recipient key chosen
at setup". Writing our own file encryption would break the rule against
self-written cryptography (AGENTS.md), so the CLI uses the reference Go
implementation of age.

| Need | Library | License | Where |
| --- | --- | --- | --- |
| Encrypting and decrypting backup archives | `filippo.io/age` v1.3.2 (with `filippo.io/hpke` v0.4.0) | BSD-3-Clause | `internal/backup`, `cmd/nebula` (`backup`, `restore`) only |

The rule of ADR 0002 stands: no new dependency in the security core. The
executor does not link age: it hands its part of a backup (a database
snapshot and the passphrase-encrypted SSH key files) to the admin CLI,
which encrypts the archive. Recipients are X25519 or SSH public keys in
`/etc/nebula/backup-recipients`; the identity stays off the Nebula machine.
