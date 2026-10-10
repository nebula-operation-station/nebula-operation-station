<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Backup, restore and upgrades

Nebula backs itself up with one CLI command, and a backup never contains anything that unlocks the vault or the SSH keys.

**Backup.** `nebula backup [--full]` runs as admin, because it needs both server and executor data.

- Each database is copied with SQLite's online backup API and checked with `PRAGMA integrity_check`.
- The archive carries a manifest with Nebula version, schema versions and SHA-256 per file, and is verified after writing.
- Config backup: server and executor databases, encrypted vault, encrypted SSH key files, configuration, modules, runbooks, trust metadata.
- Full backup adds execution logs and immutable artifacts.
- Never included: the passphrase, the plaintext vault master key, any plaintext secret.
- The archive also holds inventory and audit data, which reveal the lab's layout. It is therefore encrypted by default to an `age` recipient key chosen at setup.
- Offsite copies are left to existing tools; the docs show a restic example.

**Restore.** CRITICAL and CLI-only: `nebula restore <archive>` stops the services, verifies manifest, checksums and schema compatibility, restores, starts the services locked and requires `nebula unlock`.

**Upgrades.** No self-updater. Upgrades come through APT, a new container image or a new tarball.

1. Pre-upgrade backup: the `.deb` runs `nebula backup --pre-upgrade`; the container entrypoint does the same before migrating.
2. Stop services, replace binaries.
3. Run versioned, forward-only migrations, each in a transaction; any failure rolls back and aborts the start.
4. Start and run a self-check.

An automatic downgrade is not provided; the pre-upgrade backup is the way back. Remote job files carry a `schema_version`, so a newer executor can still reconcile jobs started by the previous version.
