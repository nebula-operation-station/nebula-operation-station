# Milestone 10 plan: hardening (Release 0.9 beta)

Status: **in progress 2026-10-19**: M10-1 to M10-3 implemented (decisions 73 to 75 in m0.md); work continues with the defaults below.
It turns spec 15 (backup, restore, upgrades) and spec 16 (Milestone 10,
Release 0.9 beta) into a concrete plan.

## What the spec asks for

- Executor-signed events, an optional audit hash chain.
- Backup and restore (spec 15): `nebula backup [--full]` as admin, online
  SQLite backups with `PRAGMA integrity_check`, a manifest with versions
  and SHA-256 per file, encrypted to an `age` recipient by default; never
  the passphrase, the plaintext vault master key or a plaintext secret.
  `nebula restore` is CRITICAL and CLI-only: stop the services, verify
  manifest, checksums and schema compatibility, restore, start locked.
- APT repository and container images; no self-updater; a pre-upgrade
  backup.
- Fuzzing, documentation, the threat model, all pre-1.0 security tests.

## Parts, in order

### M10-1 Executor-signed events and the audit view

- The executor already writes one structured `audit` log line per
  security-relevant step (about 50 kinds: unlock, logins, approvals and
  runs, trust, signers, host keys, vault, credentials). A log handler in
  front of the executor's logger also appends each of them to an event
  table in `executor.db`: sequence number, time, kind, attributes
  (canonical JSON), the hash of the previous event and
  `SHA-256(previous hash || canonical event)`, signed with Ed25519.
- **Decision 1 (default):** the signing key is created on first start in
  the executor's data directory (`events.key`, 0600, never leaves the
  executor) and does not depend on the unlock, so events are signed while
  locked too. Its public key and fingerprint are shown by
  `nebula events key`; the chain proves the events came from the executor
  and were not changed, reordered or dropped in the middle. A root
  attacker on the Nebula machine can still forge (documented).
- `nebula events [--verify] [--after N]` (admin) lists and verifies the
  chain against the key; `nebula events export` writes JSON lines for an
  offsite copy. The server reads events over a new read-only RPC and shows
  them on *History* together with its own audit lines, verifying the chain
  against the key fingerprint the admin confirmed.
- **Decision 2 (default):** the server keeps its own audit lines (the web
  `audit` log lines) in `server.db`; the hash chain over them is optional
  (`audit_hash_chain` in `server.json`, off by default) because the server
  cannot sign them in a way a compromised server could not repeat.

### M10-2 Backup and restore

- **Decision 3 (default):** the executor makes its part of the backup
  itself (`BackupExecutor`, admin role only): `VACUUM INTO` a private
  temporary file (the executor holds an exclusive lock on its database),
  `PRAGMA integrity_check`, plus the encrypted SSH key files (never the
  event key, decision 74); it streams them to the CLI. The server part is read by the
  CLI run with `sudo` (online backup API of `server.db`, config files).
  Nothing decrypted: the vault and keys stay encrypted with the
  passphrase.
- Archive: tar with `manifest.json` (Nebula version, schema versions,
  SHA-256 per file, created at, full or config), encrypted with `age` to
  the recipients in `/etc/nebula/backup-recipients` (created at setup);
  `--no-encrypt` only with a typed confirmation. `--full` adds execution
  logs and artifacts.
- `nebula restore ARCHIVE` (root, CRITICAL, typed confirmation): decrypt
  with an identity file, verify manifest, checksums and schema versions
  (refuse newer schemas), stop the services, move the current data aside
  (kept), restore, start the services (locked), print what to check.
- `install.sh` and the future `.deb` run `nebula backup --pre-upgrade`
  when a previous install exists.

### M10-3 Fuzzing and security tests

- Fuzz targets for every parser of untrusted input added since M4:
  Nmap XML, discovery jobs and results, module locks and archives, the
  prelude's result line, docker output parsers, update lists, CSV import,
  SSH signatures; `make fuzz` runs each briefly, CI runs them for a short
  time, a nightly job longer.
- A `test/security` index: one acceptance test per spec 16 criterion and
  per threat-model line, named after it, so the list in the threat model
  links to a test.

### M10-4 Threat model and documentation

- `docs/threat-model.md` final for 0.9: discovery, modules and signers,
  secrets on hosts, events, backups; every "Protected" line names its
  test, every "Not protected" line its mitigation.
- Admin guide: backup, restore, events, upgrade; a restic example for
  offsite copies.

### M10-5 Packages and images

- **Decision 4 (default):** `.deb` packages built by GoReleaser (nfpm)
  with the units, users and directories `install.sh` creates today; the
  APT repository is a static directory signed offline with the release
  key (ADR 0001): CI builds unsigned packages, the maintainer signs and
  publishes.
- **Decision 5 (default):** one container image with the four binaries;
  a Compose file runs server, executor and discovery as three containers
  from it with fixed, distinct UIDs, the executor socket and the
  discovery spool on shared volumes, the executor data on a volume only
  the executor container mounts, and `CAP_NET_RAW` only for discovery.

## Order and release

M10-1 → M10-2 → M10-3 → M10-4 → M10-5, each its own PR with a Hermes
review; Release 0.9 beta after M10-5 and a full run of the security tests
in the reference lab.
