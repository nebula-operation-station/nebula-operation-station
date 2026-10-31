<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Credentials: executor-owned agent and secret vault

SSH private keys stay in standard OpenSSH format with a passphrase on disk and are decrypted into the executor's in-process keyring on unlock, the same model as ssh-agent with keychain. The vault holds only what is not an SSH key: API tokens, provider credentials, secret runbook parameters.

<a id="release-root-custody"></a>
**Release root custody.** The SSH credentials described here authenticate to managed hosts. Offline release-signing roots are separate YubiKey-held Ed25519 keys under [spec 10](10-modules.md#release-signing): their signing secrets never enter executor storage/keyrings, the vault, CI or hosts. Only public root keys ship with Nebula. Root recovery uses a separately enrolled second YubiKey and encrypted offline non-resident key handle backups; it is not part of `nebula unlock` or instance backup/restore.

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

<a id="v23-06-01"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-06-01 -->
**One unlock.** The recommended setup uses the same generated passphrase for the vault and the SSH key. `nebula unlock` asks once, tries it on both and asks again only if one fails. Lock wipes unlocked execution keys/secrets, pauses read grants and cancels queued dispatch; restart starts locked. A local unlock resumes still-valid approved read leases without a privileged session; expiry keeps advancing while paused. Web unlock is opt-in and labelled as weaker, because a compromised server could capture the passphrase. **CLI unlock is the default and recommended mode.**

**Secret parameters at run time.** Passed over the SSH channel and, only if a script needs a file, written to `/run/nebula/<execution-id>/` (tmpfs, directory 0700, files 0600) and deleted right after use. Never in `jobs/`, results, state files, audit or logs. Output redaction of known secret values is an extra safeguard, not the main protection.

**Stated limit.** Go cannot reliably wipe memory. While unlocked, keys and secrets live in executor memory; the systemd unit disables core dumps and the docs recommend encrypted or no swap on the Nebula machine.

<a id="v23-06-02"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-06-02 -->
**PVE credential custody.** Use separate noninteractive PVE users per remote and purpose with expiring privilege-separated tokens (`privsep=1`); effective ACLs are the intersection of user and token rights. Both tokens remain envelope-encrypted in the executor vault in `executor.db`, decrypted only there. Phase 1 installs only the read token; phase 2's action token is optional until enabled. Neither the server nor collector receives a token, Docker config, password or authenticated bearer token. Reject `root@pam`, passwords, `Administrator` and `PVEVMAdmin`. PVE token expiry is additional to NOS grant/permit expiry; the ADRs do not prescribe its lifetime.

<a id="v23-06-03"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-06-03 -->
| PVE token/profile | Exact privileges and ACL scope |
| --- | --- |
| `NOSRead`, supported versions | `Sys.Audit` on `/` for cluster/HA and node/task metadata; `VM.Audit` on `/vms`; `Datastore.Audit` on `/storage`; `Pool.Audit` on `/pool`, propagated to children |
| PVE 9 informational guest-agent extension | `VM.GuestAgent.Audit` on `/vms` or selected `/vms/<vmid>`, informational methods only; never grant PVE 8's broader `VM.Monitor` to the read token |
| Action baseline | `VM.PowerMgmt` on explicitly enabled `/vms/<vmid>`; read-token prechecks/task observation |
| Snapshot extension | `VM.Snapshot` on enabled guests; `VM.Snapshot.Rollback` only where the supported version requires it |
| Backup extension | `VM.Backup` on enabled guests and `Datastore.AllocateSpace` on selected `/storage/<id>` |
| Configuration extension | Only needed `VM.Config.CPU`, `VM.Config.Memory`, `VM.Config.Network`, `VM.Config.Cloudinit`, `VM.Config.Options`, `VM.Config.Disk`, `VM.Config.CDROM`, `VM.Config.HWType` on enabled guests; `SDN.Use` on exact approved bridge/VNet paths and `Datastore.AllocateSpace` on exact required storage |
| Intra-cluster migration extension | `VM.Migrate` on enabled guests; destination storage allocation/mapping rights only for a verified supported profile |
| Node reboot extension | `Sys.PowerMgmt` on the exact `/nodes/<node>`, disabled by default |

<a id="v23-06-04"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-06-04 -->
**PVE profile limits.** Profiles are feature-specific unions, never one all-extension role. Phase 2 initially enables only the baseline. Verify endpoint/parameter ACL checks for every supported PVE minor version before enabling an extension; unknown additional privileges keep it disabled. Pool membership changes cannot widen action scope. Neither default token includes console, guest exec/file access, permission administration, storage deletion or HA-configuration rights. PVE privileges are coarser than NOS operations (`VM.Snapshot` can permit deletion/rollback); the executor must enforce distinct typed actions and parameters. Missing PVE 8 agent or read-only backup visibility stays unavailable, never borrows action credentials.

<a id="v23-06-05"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-06-05 -->
**PVE local administration.** Only the authenticated admin UID on the executor host may manage `nebula pve remote add|rotate-token|remove|repin`. Enter tokens through a non-echoing terminal or stdin, never argv, environment, browser or server configuration. Metadata contains opaque references/versions only. Audit admin UID, remote, trust and credential version changes and resulting revocations; never record token values, headers, raw bodies, credential-bearing URLs or unnecessary token account identifiers. Probe and establish trust before any credential is sent, following [08-ssh-transport.md](08-ssh-transport.md).

<a id="v23-06-06"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-06-06 -->
**PVE rotation and removal.** Validate a separately created replacement token against pinned TLS and its permission profile, then change its credential version atomically. Revoke pending permits/read grants using the old version; reconcile running tasks read-only with the replacement, never redispatch. The admin revokes the old token in PVE after verification. Removal first disables the remote and revokes its authorizations, then removes NOS secrets; PVE-side revocation is also required. Keep nonsecret audit/tombstone history. Neither operation undoes accepted tasks. Lock/restart stops new authenticated reads and mutations until local unlock; stale observations remain visible. Re-pin increments trust generation and revokes affected authority.

<a id="v23-06-07"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-06-07 -->
**Private registry credentials.** Only the executor holds vault-encrypted private registry credentials, decrypts them after unlock and uses them for approved HTTPS registry/auth origins and typed repository/tag/platform scope. Metadata reads require a standing read grant with exact credential version, 7-day default/30-day maximum expiry, budgets and revocation/audit as in [07-execution-model.md](07-execution-model.md); they never authorize pulls. Lock or credential expiry pauses reads, and rotation invalidates old-version authority. Audit scope/version, approved origins, calls, denials and outcomes without secrets; return only sanitized metadata. Private-network origins need an explicit executor-side allowlist. Supported PAT/basic/bearer/OAuth/helper mechanisms, token lifetimes, realm approval and rotation/removal workflow remain [open questions](17-frozen-decisions.md); unsupported profiles stay unavailable. Private phase-2 pulls must be executor-mediated over authenticated SSH to the target engine, with no host Docker login file and no credentials leaving executor custody; their transfer/load profile needs review before enablement.

<a id="v23-06-08"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-06-08 -->
**Recovery and read authority.** Removing a WebAuthn credential or entering recovery pauses grants until local review and unlock. Read-grant revocation via UI/CLI blocks future claims without an assertion; already dispatched work may finish. Changing a key/pin, removing a target, rotating a credential, withdrawing artifact trust or raising effective risk blocks affected scope, with identity/version changes requiring a replacement approved grant. No secret-bearing action can enter a read lease.
