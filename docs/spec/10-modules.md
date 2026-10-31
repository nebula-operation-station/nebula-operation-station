<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Modules, runbooks, OS adapters and trust

Modules extend what Nebula can do on hosts but never run code on the Nebula machine and never bypass the executor.

**OS adapters.** OS-specific commands live only in adapters; the core never calls `apt`, `dnf`, `zypper` or `apk`. V1 ships `os-debian` for Debian and Ubuntu with the capabilities `os.detect`, `os.facts`, `package.refresh`, `package.list_updates`, `package.install_security`, `package.install_all`, `system.reboot_required`, `system.reboot`, `service.list`, `service.status`, `service.restart`. Each capability has a versioned result contract such as `package.list_updates@1`.

**Script contract.** stdout carries exactly one JSON document that matches the contract; stderr carries human-readable diagnostics and goes to the execution log.

**Module contents.** `module.yaml`, host scripts, checks, JSON schemas, declarative UI metadata and templates the module owns.

```yaml
name: telegraf
version: 1.2.0
supported_os: [debian>=12, ubuntu>=22.04]
actions:
  deploy_config:
    script: actions/deploy_config.sh
    risk: medium
    privilege: sudo
    retry: reconcile-first
    durable: true
    timeout: 300s
    params:
      interval: {type: string, pattern: '^[0-9]+s$'}
    secrets: [influx_token]
    prechecks: [telegraf.config_valid]
    postchecks: [telegraf.service_active]
    declares: [writes_config, network_access]
ui:
  host_tab: {title: Telegraf, cards: [status, version]}
```

**Boundaries.** No server-side binaries or Go plugins, no SQL against the core database. Modules that need state use core-managed key/value storage or their own SQLite file under `/var/lib/nebula/server/modules/<name>/`. Declared permissions (`requires root`, `writes_config`, `network_access`) drive warnings and risk; they are not a sandbox, and the UI says so.

**Declarative UI.** Host tabs, tables, forms, cards and buttons from metadata; no module JavaScript. Every privileged confirmation dialog is rendered by the core from core metadata, never from module-provided labels.

**Trust.** Verified (valid signature from a trusted signer), Local (created or imported here), Unverified. Signatures use the SSH signature format (`ssh-keygen -Y sign`, Ed25519), so authors sign with tools they already have. Adding a trusted signer is CRITICAL; a module update signed by a different signer needs manual review. The executor verifies the artifact hash at run time; server-side trust status alone is never enough.

**First-party signing key.** Official releases and first-party artifacts use the offline YubiKey-held Ed25519 root, signed release manifest and signed rotation metadata defined in [Release signing](#release-signing). Only public root keys ship in the repository and binaries; the signing secret never reaches CI. Recovery uses a separately generated second hardware root after signed enrollment and encrypted offline key handle backups.

**Effective risk** = max(declared risk, scanner finding, trust floor). Unverified scripts running as root are at least HIGH. The Safety Scanner is an advisory pattern list that only raises risk: destructive filesystem commands, network and firewall changes, users and groups, package removal, reboot, bootloader, Docker removal, download-and-execute, `eval`, encoded payloads such as `base64 -d | sh`.

**Runbooks** are local modules with a single action: versioned scripts, parameters, secret parameters, declared risk, pre- and postchecks, OS compatibility. Versions are immutable; editing creates a new version, and every execution keeps a reference to the exact artifact it ran.

**Bootstrap** is an ordinary module (`install`, `verify`, `update`, `uninstall`) that may deliberately install services on a host. Components deployed through Nebula are recorded in `/var/lib/nebula/inventory.json` on the host, without credentials.

<a id="v23-10-01"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-10-01 -->
**Read-only contract allowlist.** Standing grants initially cover `core.facts`, `package.list_updates`, `docker.list`, `docker.inspect`, `docker.check_updates`, `service.list` and `service.status`, only at effective LOW risk with an explicitly approved read-only contract. Bind exact container incarnation/unit parameters for inspection/status; enumeration does not authorize arbitrary follow-ups. Exclude `package.refresh` because it writes package metadata even if declared LOW, and exclude `docker.logs` and all secret-bearing actions. Neither declared LOW nor a clean scanner result proves harmlessness. Typed PVE readers are built-in provider methods, never generic HTTP proxies or server plugins.

<a id="v23-10-02"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-10-02 -->
**Additional observation contracts.** ADR 0006 permits the following reviewed additions, each requiring its own exact parameter/cost/timeout limits and effective LOW eligibility before inclusion in a grant. Unknown tools, drivers or privileges yield unavailable, never a successful zero; reject malformed numbers, unsupported schemas and changed incarnations. Reuse the existing read-only SSH action pipeline, without another SSH collector or guest exec.

<a id="v23-10-03"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-10-03 -->
| Action | Read-only scope |
| --- | --- |
| `host.metrics`, `filesystem.list` | Bounded CPU/RAM percentages and per-filesystem used/total/percent, fullest filesystem plus mount details |
| `pci.inventory`, `gpu.status` | NVIDIA PCI identity; fixed `nvidia-smi --query-gpu` fields for UUID/PCI ID, utilization, VRAM used/total, temperature and power; no arbitrary flags/command or device changes |
| `docker.stats` | One bounded non-streaming CPU/RAM snapshot keyed by full container ID; validated list/inspect hints for Compose grouping |
| `service.check` | Bounded HTTP/TCP health/latency from an enrolled host, exact approved destination/port, no redirects, generic URLs or response bodies; unknown if unconfigured |
| `image.vulnerabilities` (optional) | Sanitized unique CVE counts/severity, immutable local image identity and scanner/database age from operator-installed host-local Trivy; no installation, image pull or database refresh |

<a id="v23-10-04"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-10-04 -->
**Local built-in bundle review.** `nebula artifact trust-builtins` is executor-local admin CLI only in both modes. Read a bounded bundle from a locally verified NOS release under the existing release trust root; a server-exported directory does not establish provenance. The executor hashes exact candidate bytes and retains prior trusted built-in bytes/manifest. Show action-by-action old/new versions, hashes, risks/contracts, full script diffs and executor scanner findings; new actions appear in full, removals explicitly. On first use or missing prior bytes require full review, never infer unchanged. Unchanged actions need no confirmation. Reject same-version changed bytes and invalid provenance. Exact bundle/manifest limits, provenance packaging and previous-byte retention are specified in [Release signing](#release-signing), resolving that part of spec 17 Q1.

<a id="v23-10-05"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-10-05 -->
**Atomic built-in trust.** One local confirmation commits all displayed additions/changes atomically, bound to the reviewed manifest digest. Rehash candidate bytes and compare trust-store generation before commit to reject substitution/concurrent changes. No browser bulk-trust endpoint is created; individual trust operations remain available. Record admin UID and every old/new trust tuple. Retain or retire old versions explicitly; retirement revokes affected authority, never retargets it. Scanner/host floors still apply. Trust does not approve a mutation or update an existing lease to new bytes; approve a replacement grant for a new version. The ADRs set no independent trust-record expiry; normal trust withdrawal and per-run checks remain effective.

<a id="v23-10-06"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-10-06 -->
**Built-in trust status.** Show the executor-verdict banner “Built-ins are untrusted: every operation using them needs UV until you trust them.” Include the local CLI command and affected versions; distinguish unreachable from untrusted and explain read-lease replacement. Trust may restore declared risk but never bypasses host criticality or the read-only contract requirement.

## Release signing

**Owner decision, 2026-10-30 (Axel).** This specifies the offline Ed25519 root and signed rotation already required by [ADR 0001](../adr/0001-frozen-decisions-v2.2.md); it needs no new ADR. These are required contracts, not a claim that release tooling or executor support has shipped. The [maintainer walkthrough](../admin/release-signing.md) records the implementation prerequisites.

**Root custody and bootstrap.** Generate each root on its own YubiKey with `ssh-keygen -t ed25519-sk`, with touch required. The signing secret never leaves the hardware and never reaches CI, the executor vault or a managed host. Root public keys alone belong in the repository, release metadata and compiled binary trust anchors. OpenSSH key handle files, PINs and passphrases stay offline; encrypt and back up the handle files separately. A second YubiKey holds an independently generated backup root, not a clone of the primary secret; keep it physically separate. The earlier proposal to require resident credentials is superseded by the actual non-resident root below. Neither residency nor PIN-based user verification is required; user presence is mandatory for every signature.

**Primary `root-1`, active bootstrap anchor.** Generated by Axel on 2026-10-30 on YubiKey 34718658 (YubiKey 5C NFC, firmware 5.7.4); non-resident FIDO2 credential, touch required. Fingerprint: `SHA256:DMcoE6ngofND0L6+vT1OIPrvzDFSRmBNDPrR3hpy1MY`.

```text
sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIH6DVvY6q6jDyLGQeYjKhNufFKi2jzFHzFO04+ng5mkoAAAABHNzaDo= nebula-release-root-1 (Axel, YubiKey 34718658)
```

**Backup `root-2`: pending.** It has not been generated; there is no backup public key, fingerprint or recovery signing authority yet. Generate it on the second YubiKey, verify its fingerprint offline, and enroll it through rotation metadata signed by `root-1` before relying on it for recovery. Only then publish its public key and compile it into subsequent binaries, together with the signed enrollment chain. Loss of `root-1` or its non-resident handle before enrollment cannot be repaired by an unsigned replacement key. On macOS, generation needs Homebrew OpenSSH. `-O resident` and `-O verify-required` failed with `invalid format` on the recorded hardware; back up the non-resident key handle file, which cannot be reconstructed with `ssh-keygen -K`.

**Signature envelope and verification.** Use the existing `internal/sshsig` OpenSSH SSHSIG version-1 envelope, detached ASCII armor, at most 4,096 bytes including armor/whitespace, with namespace exactly `nebula-release` and empty reserved field. Signers use SHA-512 as the SSHSIG message hash; verifiers accept SHA-256 or SHA-512 only. Release and rotation signatures require public-key and inner-signature type `sk-ssh-ed25519@openssh.com`, application exactly `ssh:`, and exact public-key-blob equality with a currently trusted root. Do not strip the FIDO wrapper to treat this as plain `ssh-ed25519`; reject certificates, other algorithms, wrong namespace, malformed/trailing data, mismatched keys and invalid signatures. The signed JSON `format` field separates manifests from rotations within this namespace. Existing third-party module signatures retain namespace `nebula-module` and their existing key policy.

The FIDO signature carries a 64-byte Ed25519 signature, a flags byte and a uint32 counter, using [OpenSSH's security-key encoding](https://raw.githubusercontent.com/openssh/openssh-portable/master/PROTOCOL.u2f). Verify the entire security-key signature, including its application, flags and counter, through `golang.org/x/crypto/ssh`; also explicitly require the user-presence bit `(flags & 0x01) != 0`. Fail closed if the verifier cannot expose/check that bit. The user-verification bit is optional. The counter is authenticated and may be recorded for diagnostics, but zero, repeats and out-of-order historical signatures are allowed: the counter is not a release/rotation ordering mechanism. The current `internal/sshsig.Verify` accepts only plain Ed25519; adding this FIDO verification and policy is required before this release workflow is enabled. No shell/`ssh-keygen` call in Go production code and no software-key fallback are authorized.

### Release manifest and provenance bundle

**Encoding.** `release-manifest.json` is exactly the UTF-8 bytes of [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785.html) JSON: no BOM, trailing newline or other whitespace outside strings. Reject invalid UTF-8, duplicate object keys, unknown fields, nulls, wrong types, invalid Unicode, excessive nesting and noncanonical input rather than silently reserializing it for verification. All schema fields below are required; arrays are sorted by the indicated ASCII identity and reject duplicate identities. Sizes are positive JSON integers in bytes (no floats); the bounds below keep them exactly representable. A SHA-256 is exactly 64 lowercase hexadecimal characters over the exact file bytes, without newline conversion, extraction/repacking or executable stripping.

| Object | Exact fields and meaning |
| --- | --- |
| Manifest | `format`: literal `nebula-release-v1`; `release_version`: release SemVer; `artifacts`: array sorted by `name`; `modules`: array sorted by `name` |
| Artifact | `name`: release attachment basename; `size`: exact byte count; `sha256`: digest |
| Built-in module | `name`: module family; `version`: module version; `size`: exact module tar byte count; `sha256`: digest of that complete tar, including headers/padding |

`artifacts` lists every published release payload: binaries, packages, source archive, checksums if published, and exactly one `builtins.tar`. Only `release-manifest.json`, its detached `release-manifest.json.sig`, and separately authenticated rotation metadata/signatures are excluded, avoiding self-reference. A hosting service's automatically generated source downloads are outside this signed payload set unless explicitly listed. `modules` lists every built-in module shipped in any artifact for this release, once per family. All architectures/packages must contain identical bytes for each listed module version; otherwise split the releases. Modules absent from the manifest cannot acquire first-party provenance. A signature is not proof that CI built safe bytes: the maintainer must review the build and rehash all payloads offline before signing.

**Local provenance packaging.** The local review input is a directory with exactly `release-manifest.json`, `release-manifest.json.sig` and `builtins.tar`, all regular files opened without following symlinks. Apply any needed signed root rotations separately first. The manifest is attached to the release with its signature, and `builtins.tar` is a listed release artifact. Verify the signature against executor-owned root state, then the bundle's size/hash and the complete module list before displaying a diff. Other release payloads need not be copied to the executor for built-in review; installation verifies every artifact it consumes. A directory exported by the server, a checksum alone or a public key supplied beside the bundle establishes no trust.

`builtins.tar` is an uncompressed POSIX ustar archive containing exactly one regular file `modules/<name>/<version>.tar` for each manifest module, in manifest order. Each nested, also uncompressed ustar archive is the exact module byte object hashed by the manifest. It contains `module.lock.json` and its referenced scripts and declarative assets, in ASCII path order. The lock uses the existing `nebula-module-v1` action contracts and canonical encoding; first-party family names, including reserved built-in names and `os-debian`, are allowed only in this release-bundle profile. Its name/version must equal the manifest, and every script hash and action artifact must be checked/constructed by the executor. Do not relax third-party name restrictions. Only lock-referenced files are allowed; duplicate or missing files reject the whole bundle. Release provenance does not itself grant artifact trust or execution authority.

**Hard limits.** KiB/MiB/GiB mean powers of 1,024. Enforce bounds while reading, before allocation/extraction; overflow or a limit violation rejects the whole candidate without changing trust. String bounds are encoded UTF-8 bytes; schema identifiers below are ASCII only.

| Item | Limit/grammar |
| --- | --- |
| Manifest | 1 MiB; nesting depth at most 4 (root object depth 1); 1–128 artifacts and 1–128 built-in modules |
| Release version | 1–64 bytes; SemVer 2.0.0 without leading `v`; each numeric core component 0–999999; prerelease/build identifiers follow SemVer |
| Module name | 1–64 bytes; `[a-z][a-z0-9_-]{0,63}` |
| Module version | Three dot-separated decimal components, each 0–999999 without leading zeros except `0`; at most 20 bytes, no prefix/prerelease/build suffix |
| Artifact basename | 1–128 bytes; `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`; reject `.` and `..`; no slashes, backslashes, controls, whitespace or URLs |
| Release payload sizes | Each artifact at most 4 GiB; sum at most 8 GiB; `builtins.tar` additionally bounded below |
| Bundle | At most 80 MiB on disk; at most 128 outer entries; sum of nested tar file sizes at most 64 MiB |
| Module tar | At most 4 MiB including headers/padding; at most 128 regular files; at most 4,096 inner entries and 64 MiB of inner file content over the entire bundle |
| Module files | Lock at most 256 KiB; 1–50 actions/module; each script at most 256 KiB; other individual files at most 1 MiB; existing tighter action/schema limits still apply |
| Inner path | 1–240 bytes total, at most 4 components, each 1–64 bytes of `[a-z0-9][a-z0-9_.-]{0,63}`; reject `.`/`..`, absolute paths, empty components, backslashes and NUL |
| Signature | At most 4,096 armored bytes per document; exactly one detached signature per manifest/rotation |

For both tar levels require regular files only: reject symlinks, hard links, directories, devices, FIFOs, sparse files, extension/PAX/GNU long-name records, duplicate paths and size mismatches. Ignore archive ownership/modes; never apply them. Require two zero end blocks, zero padding, and no nonzero trailing content; all padding counts toward the byte cap. Read into executor-owned bounded staging without following filesystem links or overwriting existing files. Do not execute module content locally. Scripts and textual metadata must be valid UTF-8; render review content as text only. No compressed or recursive archive processing is permitted beyond these two specified tar levels.

### Root rotation and revocation

**Rotation document.** `root-rotation.json` uses the same canonical JSON and SSHSIG policy as a manifest, with `format` exactly `nebula-root-rotation-v1`. Its only fields are `format`, `sequence`, `previous_sha256`, `add` and `revoke`. `sequence` is an integer 1–9007199254740991, exactly the persisted sequence plus one. `previous_sha256` is SHA-256 of the previous accepted canonical rotation document; before the first rotation use 64 zeroes (bootstrap sequence 0). `add` is an array of objects with exactly `id` and `public_key`, sorted by `id`; `revoke` is an array of root IDs sorted in ASCII order. Both arrays are required, each at most four entries, and at least one is nonempty. The document is at most 16 KiB, nesting depth at most 4; its detached signature is `root-rotation.json.sig`.

A root ID is 1–32 bytes matching `root-[1-9][0-9]{0,26}`. `public_key` is at most 256 ASCII bytes: exactly `sk-ssh-ed25519@openssh.com`, one space, and canonical padded base64 of the SSH public-key blob (application `ssh:`), without comment/newline/options. A new ID and key blob must never have been enrolled before; duplicate entries, reuse, unknown revocations, add/revoke overlap or more than four active roots after the change reject the document. Keep at least one active root. Root IDs/comments are labels, not key identities; compare the complete key blob and fingerprint.

**Authorization and durability.** Verify with a currently trusted, non-revoked root from the state *before* applying the document; a newly added key cannot authorize itself. A trusted backup has equal rotation authority and can sign metadata that revokes the primary and adds a replacement. Persist root changes, revocations, sequence and document digest atomically before accepting new releases. Replays, skipped sequences, wrong predecessor digests and competing updates fail closed. Revocations override compiled anchors and survive restart, downgrade and ordinary software replacement; never reset root state from a downloaded bundle. A fresh installation must validate the published rotation chain from its compiled bootstrap anchors; an already provisioned installation must continue its durable chain. Missing required root state blocks admission pending local recovery, not silent bootstrap. If no root remains usable, recovery requires a separately reviewed bootstrap trust change, not an unsigned online replacement.

Publish every signed rotation and all old public keys in repository/release metadata for historical cryptographic verification. A revoked root cannot authorize new release admission, even for an old/backdated manifest; historical verification must label that root revoked. Rotation has no retroactive execution power and does not retarget existing trust tuples. Apply affected trust withdrawal and per-run checks normally. As with other offline update mechanisms, a verifier cannot detect a newer revocation withheld from it; obtain and review the latest published chain before release admission.

### Built-in module retention

**Exact bytes and minimum lifetime.** The executor retains the active version and the exact bytes of the two previous distinct accepted versions of every built-in module, including their lock/scripts/assets, signed manifest, signature and root-chain provenance. Keep each superseded version for at least 90 days (90 × 24 hours) after it ceases to be active, even when faster releases create more than two predecessors. The two most recent predecessors remain after 90 days until displaced by newer predecessors. Order predecessors by their last active-to-inactive transition, counting distinct versions, not SemVer order; repeated import of the active version is not a transition. Removal/retirement does not bypass the 90-day floor or erase the last two predecessors; retain the former active version for 90 days as well. Retention confers no execution authority. Versions never observed locally cannot be reconstructed: on first use/missing history show full content for review and audit the gap, never infer unchanged. Do not synthesize history from server-supplied text.

**Substitution detection and cleanup.** Store an immutable tombstone `(name, version, size, sha256)` for every accepted module version, including after byte garbage collection, plus the release digest and acceptance/supersession times. Reject same-version changed bytes/size against either active/history bytes or the tombstone, across releases, restarts and garbage collection; re-importing identical active bytes is idempotent and does not reset age/order. Reactivating a retained version uses its unchanged bytes; when it later ceases to be active, start a new 90-day floor and never shorten an existing retention deadline. Maintain tombstones even when a module is removed. Bound wall-clock rollback conservatively: a detected backward/uncertain clock must not make bytes eligible for early deletion. Garbage collection may remove bytes only when they are inactive, outside the two required predecessors, at least 90 days superseded, and not otherwise pinned for a retained execution/review. Missing/corrupt required bytes block automatic unchanged/diff claims; require full review without overriding a hash conflict. Audit collection and retention failures without script/secret contents.

**Storage ceiling and admission.** Use executor-owned storage, inaccessible to the server for writes, with a hard total ceiling of 2 GiB: at most 512 MiB active module tar bytes, 1 GiB historical module tar bytes, 128 MiB staging, 128 MiB provenance/tombstone/root metadata, and 256 MiB filesystem/index overhead. Permit at most 128 distinct retained module names (including removed ones), 200,000 version tombstones and 1,024 rotation records; hitting a metadata/count ceiling requires a reviewed capacity/schema change, never silently dropping evidence. Serialize admission; reserve worst-case space for candidate bytes, preservation of current bytes, provenance and atomic commit before activation. The two-predecessor baseline fits 128 × 4 MiB × 2 = 1 GiB; rapid updates/other pins can still fill history. On insufficient quota, free disk space, metadata capacity or retention I/O failure, reject the update atomically with a clear diagnostic; keep the current trust/version and all required history. Do not evict protected history, shorten 90 days, or trust without retaining bytes to make an upgrade fit. Local review rehashes the staged bytes and binds the commit to the reviewed manifest digest and trust-store generation as specified above.
