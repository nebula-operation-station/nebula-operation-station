<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Credentials: executor-owned agent and secret vault

SSH private keys stay in standard OpenSSH format with a passphrase on disk and are decrypted into the executor's in-process keyring on unlock, the same model as ssh-agent with keychain. The vault holds only what is not an SSH key: API tokens, provider credentials, secret runbook parameters.

**SSH keys.**

- Stored under `/var/lib/nebula/executor/keys/` as OpenSSH private keys (bcrypt-pbkdf, the standard format). Users can bring existing keys.
- `nebula unlock` decrypts them into an in-process keyring (`x/crypto/ssh/agent`). No agent socket exists that another process could use.
- Default and recommendation: one dedicated key per Nebula instance, accepted on the hosts by a dedicated `nebula` user.
- Each host binds exactly one credential reference; the executor offers only that key (the `IdentitiesOnly` principle).
- Ephemeral keys can be uploaded for the current privileged session and are never written to disk.

**Vault.**

- Vault master key: 256 random bits, stored only encrypted.
- Unlock: passphrase → Argon2id (parameters stored with the vault, default 256 MiB, 3 passes) → key-encryption key → decrypts the master key.
- Each secret has its own data key; encryption is XChaCha20-Poly1305 with the secret's ID and version as associated data, so encrypted blobs cannot be swapped between records.
- Passphrase: at least 32 random characters from a password manager. Never stored, logged, backed up or sent to hosts.

**One unlock.** The recommended setup uses the same generated passphrase for the vault and the SSH key. `nebula unlock` asks once, tries it on both and asks again only if one fails. Web unlock is opt-in and labelled as weaker, because a compromised server could capture the passphrase. **CLI unlock is the default and recommended mode.**

**Secret parameters at run time.** Passed over the SSH channel and, only if a script needs a file, written to `/run/nebula/<execution-id>/` (tmpfs, directory 0700, files 0600) and deleted right after use. Never in `jobs/`, results, state files, audit or logs. Output redaction of known secret values is an extra safeguard, not the main protection.

**Stated limit.** Go cannot reliably wipe memory. While unlocked, keys and secrets live in executor memory; the systemd unit disables core dumps and the docs recommend encrypted or no swap on the Nebula machine.
