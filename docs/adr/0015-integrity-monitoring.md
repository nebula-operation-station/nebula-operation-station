# ADR 0015: Integrity monitoring for NOS itself and for managed hosts

Status: **proposed, 2026-11-11**. Awaiting the maintainer's answers to the
open questions below. Nothing here is implemented; every path, unit name and
package below is to be *verified* in the ticket that implements it.

## Context

NOS holds SSH keys that give root on every managed host. Two questions are
unanswered today:

1. **Is NOS itself still the software that was released?** A replaced
   `nebula-executor`, a changed systemd unit or an edited built-in module on
   the NOS machine would undermine every control in specs 05–07. Spec 15
   already ends an upgrade with "start and run a self-check", but defines
   no reference for that check. The release manifest (spec 10, "Release
   signing") is signed with the offline YubiKey-held Ed25519 root (spec 17),
   but it lists release *attachments* (`.deb`, tarballs, `builtins.tar`),
   not the files those attachments install.
2. **Has anything on a managed host changed that NOS did not do?** A new
   `authorized_keys` line, a modified `sudoers` file, a replaced
   `/usr/sbin/sshd` or a new cron job is invisible to NOS today. Package
   inventory (ADR 0011 D3) says what dpkg *believes* is installed, not what
   is on disk.

Constraints this ADR must respect:

- **Agentless-first** (spec 01, `v23-01-01`): no persistent daemon on
  managed hosts; scripts are transferred only for execution. Only the
  executor talks SSH (spec 02); the server and collectors may only trigger
  reads inside executor-approved read leases (ADR 0007).
- **Host data is untrusted** (spec 09): strict schemas, UTF-8 checks,
  explicit limits, text-only rendering, fuzzed parsers. A partial read is
  never presented as complete or clean.
- **Operator-driven** (spec 01): no unattended mutation. Integrity findings
  are advisory, like ADR 0011 findings; they never patch, restore or roll
  back anything.
- **Honest limits** (spec 01): where a protection is partial, say so. This
  ADR has an unusually large honest-limits section on purpose.
- **No self-written cryptography** (AGENTS.md rule 4): SHA-256 from
  `crypto/sha256`, signatures through the existing `internal/sshsig`
  release path, canonical JSON through the existing JCS library (ADR 0002).

## Threat model (read this first)

Integrity monitoring is only useful if it is clear what it can and cannot
see. The decisive fact:

> **A root attacker on a machine controls every answer that machine gives.**
> A hash script that runs on a compromised host runs under the attacker's
> kernel, libc, `sha256sum`, `find` and shell. A rootkit can return the
> old, expected hash for a file it has replaced, hide files from directory
> listings, and fake `mtime`, `ctime` and inode numbers. No script-based
> check, however carefully written, can prove the absence of a root-level
> compromise on the machine it runs on.

What follows from that, per stage:

| Adversary | I1 (NOS self-check) | I2 (agentless host FIM) | I3 (measured boot, attestation) |
| --- | --- | --- | --- |
| Operator error, botched or partial upgrade, disk corruption, wrong file copied over a NOS binary | Detected | Detected | Detected (boot chain) |
| Non-root attacker or service account that can write some files (misconfigured permissions, a compromised service user) | Detected for covered code (D2) and approved configuration (D3), including cross-checks between NOS processes | Detected inside the D5 profile; not outside it (see "Honest limits") | Detected where the file is measured |
| `nebula-server` UID writing files it owns by design: databases, logs, spools, runtime directories, caches | **Not detected**: D2 excludes exactly these files; `PRAGMA integrity_check` and backups catch only corruption, not a well-formed deliberate edit | n/a | Not measured |
| Root attacker who changes files with ordinary tools and does not tamper with the checker or its stored references | Detected | Detected | Detected |
| Root attacker who runs a rootkit or patches the checker, `sha256sum`, the kernel or the NOS binary that performs the check | **Not reliably detected**: a replaced binary can skip its own check, and all NOS processes on one machine fall to the same root | **Not reliably detected**: the host lies | Detected for everything measured **before** or **at load** by the TPM-backed log, within the IMA policy; see I3 limits |
| Attacker who restores the original file before the next scan | Missed between scans | Missed between scans (incremental runs use `ctime`, which ordinary tools cannot set; root can still fake it) | IMA records every measured load, including short-lived ones |
| Compromised `nebula-server` | Executor detects server-binary changes (different UID, server cannot write executor storage); a compromised server can still suppress the *display* of I2 findings | Server can hide findings from the UI; it cannot silently rewrite an approved baseline (D7). It can misrepresent in the browser which paths an approval covers; critical-class entries are therefore approved only in the executor-local CLI (D7), other entries carry this limit (see "Honest limits") | Quotes are verified by the executor, not the server |
| Compromised D8 reference builder or its signing key supplying false package references (a compromised server alone cannot: the executor verifies the pinned builder key, D8) | n/a (I1 uses the YubiKey-signed list, D2) | **Not detected as such**: it can make an attacker's file match a "verified" reference, so a change with a version change is labelled expected (info) during a NOS job or, outside a NOS job and outside critical-class paths, "package updated outside NOS" (medium); a same-version change stays high or critical (D7). The change stays an open finding and cannot enter a baseline without the admin's executor-bound approval (D7, D9), but an admin who approves trusts the label (see "Honest limits") | IMA entries are compared against the same references (D10); same limit |

Consequences stated plainly:

- **I1 and I2 detect manipulation by ordinary attackers, faulty
  automation and operator error.** They raise the cost of a stealthy
  compromise (the attacker must know NOS is watching and tamper with the
  checker) and they leave a NOS-side record of every observed state.
- **I2 gives no guarantee against a root attacker on the managed host.** A
  clean I2 result means "the host reported no unexpected change", never
  "the host is not compromised". The UI and documentation must use exactly
  that wording.
- **A stronger, hardware-backed guarantee needs I3** (TPM-anchored measured
  boot and IMA with remote attestation). Even I3 is not absolute (see
  "I3 limits"); it moves trust from the host's software to its TPM and boot
  firmware.
- **The baseline never lives only on the system it describes** (D3, D6,
  D7). A baseline on the target would be rewritten by the same attacker
  who changed the files.

### Honest limits: what I1 and I2 do not cover

Beyond the root-attacker limit above, these are outside I1/I2 and are
named in the handbook next to every "no unexpected change" result:

- **Server-writable NOS state.** Databases, logs, spools, runtime
  directories and caches on the NOS machine (excluded by D2). A
  well-formed, deliberate edit there by the `nebula-server` UID is not an
  integrity finding; `PRAGMA integrity_check` and backups only catch
  corruption, and the audit log only what it records.
- **Unwatched host paths.** Everything outside the D5 roots: `/var`
  (except the crontab spool), `/srv`, `/home` and `/root` except
  `authorized_keys*` and the other SSH login files of D9 (so shell start files such as `~/.bashrc`,
  `~/.profile` and per-user systemd units under `~/.config/systemd/`),
  `authorized_keys` and other SSH login files (D9 "SSH login files") of
  service accounts whose home is under `/var`, `/srv` or `/opt` outside
  the scanned `/opt` tree, SSH login files that the SSH configuration
  names by an absolute path outside the D5 roots (not scanned, but each
  such directive opens an "SSH login file outside the scanned roots"
  finding, D9), files that an `AuthorizedKeysCommand` or
  `AuthorizedPrincipalsCommand` program reads or runs (only the program
  itself is critical-class), `at` job spools,
  and the files that sshd follows a symlink to outside the scanned roots
  (each such symlink at an SSH login file position is critical-class and
  opens the same finding, D9),
  `/tmp`, `/dev/shm`, `/run`, `/etc/pve` (excluded by design, D5; Q1),
  container images and
  volumes. Under `/usr`, only the D5 roots are watched: **`/usr/share`
  is not**, although it holds executable code, including
  `/usr/share/perl5` with the whole Proxmox VE Perl codebase and many
  packages' helper scripts; nor are `/usr/local/share`,
  `/usr/local/etc`, `/usr/local/include`, `/usr/include`, `/usr/src` and
  `/usr/games`. Persistence placed there is not seen by I2.
- **Login-relevant files that are not critical-class.** D9 "SSH login
  files" makes every file that sshd reads to grant a login
  critical-class, plus PAM, the account files and `/etc/nsswitch.conf`.
  Files that the PAM or NSS modules themselves read are not derived and
  stay ordinary `/etc` or `/usr/lib` entries (high findings, approvable
  in the browser): for example `/etc/sssd/`, LDAP client configuration,
  `/etc/krb5.conf`, the `libnss_*` modules and any data file a module
  reads outside `/etc/pam.d/` and `/etc/security/` (both
  critical-class). A changed NSS source named in `/etc/nsswitch.conf` is
  critical; a change inside that source's own configuration is not.
- **Default exclusions that affect what runs.** D5 excludes Python
  `__pycache__` bytecode at any depth under `/usr/lib/python3*` and
  `/usr/local/lib/python3*`, which the interpreter executes instead of
  the watched source when its header matches; `/etc/ld.so.cache`, which
  decides where the dynamic loader finds libraries; the
  `/usr/lib/modules/*/modules.*` index files, which decide which module
  file is loaded for an alias; and the other generated caches the profile
  names. A change there is a persistence place I2 cannot see.
- **Other file systems.** `find -xdev` does not descend into a separate
  mount below a root (D5 "Separate mounts below a root"). Mounts that
  are themselves profile roots, such as `/boot` and the `/boot/efi`
  vfat partition with the shim and GRUB EFI binaries, are scanned. A
  mount **excluded by design** (in `fim-default-v1` only `/etc/pve` of
  type `fuse`) is not scanned and does not make a run partial: changes
  there, including the PVE cluster configuration, are not seen by I2.
  Any other mount below a root is **skipped**: it makes the run partial
  and opens a finding; it is never silently treated as covered. The
  mount list comes from the host, so a root attacker can hide a mount
  (threat model). On vfat, owner and mode come from mount options, so
  under a vfat `/boot/efi` root owner and permission-bit changes,
  including those from changed mount options, open no finding (D5);
  content, size, type, presence and the setuid, setgid and sticky bits
  are still compared. The file-system type is reported by the host: a
  host that already reported `vfat` at its first approved scan keeps
  the relaxation, and a later change of the reported type is a critical
  finding (D5).
- **Between scans.** A change that is reverted before the next scan is
  missed (threat model). Incremental runs hash only files whose `ctime`
  or `mtime` falls in the look-back window, and files larger than
  512 MiB only in full runs (D5, D9); a content change with faked
  timestamps is seen only by the next full run.
- **The checker's own references on the NOS machine.** Root on the NOS
  machine can rewrite the executor's admitted list and baseline digest
  and the approved configuration baseline with ordinary tools, so the
  threat-table row "root attacker with ordinary tools" assumes the
  attacker does not also edit those; only the offline check (D4) is
  independent of the NOS machine.
- **`nebula verify` from an admin machine.** It hashes locally, but the
  bytes come from the NOS machine's kernel and file system (D2 "(b)"). A
  root rootkit on the NOS machine can serve the original bytes for a
  replaced file, so a clean `nebula verify` does not prove the absence
  of a root compromise; it also trusts the admin machine and the
  `nebula` binary on it. Only the offline check from read-only media
  (D4) avoids the NOS machine's software.
- **GitHub as distribution channel.** The signature, not GitHub, is
  trusted (D2). GitHub (or whoever controls the release page) can still
  withhold a release or a newer root rotation, or serve an older,
  validly signed version; the executor rejects a lower version than it
  admitted (D4), and `nebula verify` checks the version the admin names.
  A signed list proves only that the maintainer approved those hashes,
  not that the build was safe; until reproducible builds (IG-11) are in
  place, nobody but the release process can re-derive them.
- **What a browser approval shows.** WebAuthn signs a challenge, not the
  displayed list (ADR 0007). For baseline approvals in the browser (D3
  configuration baselines and D7 entries that are not critical-class), a
  compromised server can show a harmless list while the assertion covers
  the executor digest of other paths it named; the record values still
  come from the executor's own scan. Critical-class entries are approved
  only in the executor-local CLI (D7, D9), and in hardened mode D3
  baselines too (the executor rejects a browser assertion for them,
  D3); the CLI view is only as trustworthy as the NOS machine
  (previous item).
- **Trust on first scan.** The first complete scan of a host becomes its
  proposed baseline (D7); a host that was already compromised then is
  baselined as compromised.
- **Package files before Q6.** Until Q6 is answered there are no archive
  references (D8): package files are compared only against the
  trust-on-first-scan baseline, and every package file a NOS apt job
  changes is "changed during NOS job, unverified" (D9). NOS cannot tell
  a file an attacker replaced during the job from the genuine upgrade.
  Critical-class paths are never batch-approved and stay critical (D9),
  but the admin's individual review of, for example, a new
  `/usr/sbin/sshd` is only as good as the admin's own comparison with a
  `.deb` they verified themselves. The same holds after Q6 for versions
  that have no reference (D8 "Old versions").
- **Trust in the reference builder for "verified" (after Q6).** Package
  references are built on the D8 builder host; the executor verifies
  them against the pinned builder key but cannot re-derive them (D8).
  The server relays them and cannot forge one. A compromised builder or
  builder key can sign a reference that matches an attacker's file. Its
  effect is exactly this (D7, D9):
  - during a NOS job that brings the package to the executor-requested
    version, the change is shown as a verified expected change (info,
    `expected_pending`), for critical-class paths too, except a new
    setuid/setgid file or bit, which stays critical even when the forged
    reference carries the bit (D9, highest severity wins);
  - outside a NOS job, with a reported version upgrade (strictly higher
    in dpkg ordering), it is "package updated outside NOS" (medium) for a
    path that is not critical-class; a critical-class path stays
    critical; a lower reported version is "package downgraded outside
    NOS" (high, D9), even with a matching signed reference;
  - without a version change it lowers nothing: the finding stays high,
    or critical for a critical-class path (D7 "Same version, changed
    content"), and a reference already admitted for an installed
    `(package, version, arch)` can neither be replaced nor joined by a
    second one, whatever deb SHA-256 the builder names (D8);
  - a compromised key can pre-sign forged references for future
    versions; the first one admitted for a triple is the one used when
    that version is installed and blocks the correct reference for it.
    The correct reference then raises an `integrity.reference_conflict`
    finding (D8 "Reference conflict alert", D9), but until the admin
    replaces the key the forged reference keeps its effects listed here
    for that version;
  - a file that was already replaced at the first scan and matches the
    forged reference raises no "differs from signed reference" finding,
    so only trust on first scan remains for it.

  In every case the change stays an open finding until a baseline
  approval covers it: a reference never closes, suppresses or approves a
  difference from the approved baseline (D7), every baseline entry needs
  the admin's approval of an executor-computed digest, and critical-class
  entries need one executor-local CLI approval each (D7, D9). An admin
  who approves an entry labelled "verified" still trusts the builder for
  that label. Replacing the builder key after a compromise revokes every
  reference the old key signed and lets the builder re-admit correct
  ones (D8 "Builder key replacement"); entries the admin approved on a
  forged label stay in the baseline until the next full run compares
  them with the re-admitted references, and for a version that can no
  longer be fetched they stay undetected.
- **Anything not a file.** Running processes, loaded kernel modules,
  memory-only implants, firmware and BIOS/UEFI settings (only I3 sees
  part of this).

## Decisions

### D1: Three stages

| Stage | Scope | Trust anchor | Status in this ADR |
| --- | --- | --- | --- |
| **I1** | NOS's own binaries, systemd units, built-in module files, web assets and configuration on the NOS machine | YubiKey-signed release manifest (code) and an admin-approved baseline (configuration) | Proposed for implementation |
| **I2** | Selected paths on managed Debian, Ubuntu and PVE hosts, read agentlessly over SSH | Signed distribution archive indices via the D8 builder (package files, once Q6 is answered) and a NOS-held, admin-approved baseline (everything else, and package files until then) | Proposed for implementation |
| **I3** | Measured boot and IMA with TPM remote attestation for hosts that have a TPM | Host TPM endorsement and attestation keys enrolled in NOS | Optional, later; separate ADR before implementation (Q5) |

All three produce **integrity findings**: advisory records that open,
update and close like ADR 0011 findings but live in their own store (D9).
None of them ever starts, approves or authorizes an action, except the
narrow I1 unlock refusal in D4, which only *withholds* authority.

### D2: I1 reference for NOS code: a signed installed-files list

The release manifest (spec 10) signs attachments, not installed paths. I1
adds one **new release artifact**, `installed-files.json`, listed in the
manifest's `artifacts` array like every other payload. Its SHA-256 is
therefore covered by the YubiKey-signed manifest; no change to the
manifest format `nebula-release-v1` is needed, but spec 10 must make the
artifact mandatory (see "Required specification changes").

- **Format.** RFC 8785 JCS JSON, `format` `nebula-installed-files-v1`,
  `release_version` equal to the manifest's, and one entry per install
  flavour (`deb:<arch>`, `tarball:<arch>`, `container:<arch>`). Each
  flavour lists every file the release installs: absolute path, file type
  (regular file or symlink with exact target), exact size, SHA-256 of the
  exact bytes and the expected mode/owner. Sorted by path, no duplicates,
  same strict parsing rules as the manifest (unknown fields, nulls,
  non-canonical input rejected).
- **Limits.** At most 4 MiB, at most 4,096 entries per flavour, paths at
  most 255 bytes of `[A-Za-z0-9/._+-]` under the documented NOS prefixes.
- **Producing it.** Release tooling computes it from the built packages;
  the maintainer rehashes it offline before signing, as for every other
  artifact (spec 10). A signature still proves only that the maintainer
  approved these bytes, not that the build was safe.
- **Covered files.** `/usr/bin/nebula*`, the units under
  `/usr/lib/systemd/system/nebula-*` (or `/lib/systemd/system`, *verify*
  against `deploy/deb`), unit drop-ins shipped by the package, the
  built-in module bundle and its extracted YAML/scripts, web templates and
  static assets, shipped nftables files and the public root keys. Not
  covered: configuration (D3) and data (databases, logs, spools, runtime
  directories and caches), which change by design; their integrity is
  the job of D3, `PRAGMA integrity_check`, backups (spec 15) and the
  audit log.

**Per-version publication on GitHub (maintainer decision, 2026-11-11).**
The target hashes of every version are public, so anyone can check an
installation against them:

- **What is published.** The existing signed release process (spec 10
  "Release signing", `docs/admin/release-signing.md`, YubiKey root) is
  extended by `installed-files.json` as above: per installed file the
  path, size and SHA-256 (plus type, mode and owner), for every binary,
  systemd unit, the built-in module bundle and its files, and every web
  asset; no configuration and no data. `release-manifest.json`,
  `release-manifest.json.sig` and `installed-files.json` are attached as
  assets to the GitHub release of **every** version, next to the other
  artifacts.
- **GitHub is only a distribution channel, never a trust anchor.** The
  trust anchor is the signature: a verifier accepts the files only after
  verifying `release-manifest.json.sig` against the root public keys
  built into its NOS binaries, advanced by the published signed root
  rotations (spec 10), and the SHA-256 of `installed-files.json` against
  the manifest. An unsigned manifest, a wrong signature, a signature by
  a revoked or unknown key, a hash mismatch or a non-canonical document
  is rejected, **also when it comes from the official GitHub release**.
  A public key, checksum or signature published beside the files (on
  GitHub or elsewhere) establishes no trust.
- **Offline installations.** The three files are part of every update
  bundle. The upgrade (spec 15) admits them into executor-owned storage
  before installing (D4 "Reference"); all later checks use that local
  copy. The NOS machine never fetches from GitHub itself (no new egress).
  GitHub is the second source: an admin can download the same assets on
  another machine and compare them, by hand or with `nebula verify`
  (below). Two validly signed but different manifests for the same
  `release_version` mean misuse of a root key or a broken release
  process; `nebula verify` reports that as critical, and the maintainer
  must be told.

**Two ways to check against the published list.**

- **(a) On the NOS machine.** The executor and the server check the
  installed files against the admitted list of the running version (D4).
  This runs continuously but depends on the NOS machine's own software.
- **(b) From a trusted admin machine: `nebula verify`.** The admin runs
  the `nebula` binary of a verified release on a separate, trusted
  machine: `nebula verify --host <NOS machine> --version <version>
  --flavour <flavour> [--from <dir>]`. It takes the three files from the
  GitHub release of that exact version (or from a local directory),
  verifies them as above, connects to the NOS machine with the admin's
  own SSH account and key (`golang.org/x/crypto/ssh`, host key pinned by
  the admin; no `ssh` binary, never NOS's managed-host keys), reads every
  listed file and hashes it **locally** (`crypto/sha256`). It reports
  each file as matching, different, missing or (for `/usr/bin/nebula*`)
  extra, and compares the SHA-256 of the manifest copy the executor
  admitted with the GitHub copy. The version is given by the admin, not
  taken from the machine, so an old installation is not checked against
  its own old list unnoticed. Everything read from the NOS machine is
  untrusted input (size limit from the list, strict parsing, escaped
  text output). How file bytes are read without a new module (a fixed
  read command per listed path, whose characters D2 restricts, versus
  SFTP, which needs a new dependency) is decided in IG-04. Limit: a
  root rootkit on the NOS machine answers these reads too and can
  return the original bytes; only the offline check from read-only media
  (D4 "Recommended outside anchor") is independent of the NOS machine's
  software (see "Honest limits").

**Reproducible builds (follow-up, IG-11).** A signature proves only that
the maintainer approved the hashes, not that the build was safe. Spec 14
already asks for reproducible builds (`-trimpath`, pinned toolchain).
IG-11 makes them checkable, so that anyone can rebuild a tag and obtain
the same hashes as `installed-files.json` (sketch only; the build and CI
files it touches are protected paths and need the maintainer):

- Build flags: `CGO_ENABLED=0`, `-trimpath`, `-buildvcs` with the tag
  commit only (a dirty tree fails the build), `-ldflags=-buildid=`, the
  exact Go version pinned for releases (not only the `go.mod` minimum).
- Deterministic packaging: `SOURCE_DATE_EPOCH` from the tag commit for
  every file time in `.deb`, tarball, container layer and
  `builtins.tar`; sorted entries; fixed owner `0:0` and modes; web assets
  from a locked dependency set.
- Check: a CI job that rebuilds the tag in a clean container and compares
  every installed file with `installed-files.json`; a documented
  `make reproduce` style procedure for third parties. Comparison is by
  installed file, not by `.deb`, because package metadata may still
  differ.
- Acceptance: two independent rebuilds of one tag produce identical
  `installed-files.json` hashes; any difference blocks the release.

### D3: I1 reference for NOS configuration: an admin-approved baseline

Configuration (`/etc/nebula/*`, admin-created unit drop-ins under
`/etc/systemd/system/nebula-*.service.d/`, the iconfetch nftables file if
locally edited) changes legitimately and has no release reference.

- The baseline is a list of `(path, type, size, mode, owner, SHA-256)`.
- It is **approved like a read grant** (ADR 0007): the executor shows the
  full list with old and new values. In standard mode the admin approves
  its digest with a fresh user-verified assertion in its own challenge
  domain (`nebula-integrity-baseline-v1`, nonce, five-minute expiry,
  single use). In hardened mode it is approved **only** with the
  executor-local CLI; the executor rejects a browser assertion for a D3
  baseline there. Recovery mode cannot approve a baseline.
- The executor stores the approved baseline and its digest in
  executor-owned storage. The server may display it but cannot change it.
- Content hashes of configuration files are **keyed** with the same
  executor-held HMAC scheme as D6 ("Content hashes and secrets"), with the
  NOS machine as the subject; the content and its plain hash never leave
  the executor. Low-entropy secret files should not exist under
  `/etc/nebula` (secrets belong in the vault); if one does, the UI shows
  only "content changed" for it (same rule as D6 "Named secret-bearing
  paths").

### D4: I1 checks: who checks what, when, and what happens

**Who.** Every long-running NOS process (`nebula-server`,
`nebula-executor`, `nebula-pve-collector`, `nebula-netdev-collector`, and
the timer-driven helpers when they start) hashes its own executable and
the files it loads at start. In addition, **the executor checks every
covered NOS file** (D2, D3), and **the server checks the executor's
binary and unit**. Cross-checks matter because the processes run as
different UIDs: a compromised server UID cannot write the executor's
binary or the executor's stored reference, so the executor sees what the
server did. A self-check alone is weak (a replaced binary can skip it);
it is kept because it catches corruption and partial upgrades cheaply.

**Reference.** The executor admits a release's `installed-files.json`
only after verifying the manifest signature against its root state (spec
10, same path as `nebula artifact trust-builtins`) and the artifact's
SHA-256 against the manifest. The admitted list is copied into
executor-owned storage; later checks compare against that copy, never
against the copy in `/usr/share`. Rollback rule: a manifest with a lower
`release_version` than the last admitted one is rejected; going back uses
the pre-upgrade backup (spec 15).

**When.** At process start, after every upgrade (spec 15 step 4 "self
check" becomes this check), and periodically (default every 60 minutes,
Q2). Periodic checks are bounded: at most 4,096 files and 1 GiB hashed
per run, read with `O_NOFOLLOW`, no symlink following, regular files
only.

**What happens on a mismatch.**

| Mismatch | Default reaction (subject to Q4) |
| --- | --- |
| A covered NOS **binary**, unit, built-in module file or root key differs from the admitted signed list, or a covered file is missing, or an unlisted executable appears under `/usr/bin/nebula*` | Integrity finding (critical), notification, and **the executor refuses `nebula unlock` and all mutation and read-grant dispatch** while the mismatch is open. The system stays locked; nothing is deleted, restored or rolled back. The admin clears it with an executor-local CLI command (`nebula integrity ack <finding>`, admin UID, audited) after reinstalling or after accepting a new signed release |
| A web asset or template differs | Finding (critical) and notification; the server refuses to serve the changed asset and shows a static "integrity failure" page (Q4) |
| A configuration file differs from the approved baseline (D3) | Finding (high) and notification; no lock. The admin either approves a new baseline (D3) or restores the file |
| The check itself could not run completely (I/O error, limit reached) | Finding "integrity check incomplete" (high); never reported as clean |

The unlock refusal only *withholds* authority. It cannot help when the
executor binary itself is the replaced one: that executor need not obey.
This is stated in the UI next to every I1 result ("NOS checks cannot
detect a root compromise of the NOS machine; see ADR 0015").

**Recommended outside anchor.** The handbook documents
`nebula integrity verify --offline <dir>`: verify the installed files
against a signed release fetched and checked on another machine, run from
read-only boot media or with the NOS disk mounted elsewhere. This is the
only I1 check whose result does not depend on the NOS machine's own
software, and it is what an admin should run after any I1 alarm.

### D5: I2 collection: agentless, fixed read-only script

I2 adds one built-in read-only action, **`fim.scan`**, to the signed
built-in bundle, with an approved read-only action contract (spec 10) and
an addition to the ADR 0007 read-lease allowlist.

- **Agentless.** The executor transfers a fixed script for each run over
  its existing SSH connection, like `net.facts`
  (`internal/executions/actions/scripts/`). Nothing stays on the host:
  no daemon, no timer, no state file, no baseline under `/var/lib/nebula/`.
  The script only reads: no writes, no package database queries that take
  locks, no network access, no `-exec` of anything but the hash tool.
- **Trigger.** Scheduled and on-demand runs go through a normal ADR 0007
  read lease bound to the exact action, script hash, parameters, hosts and
  budgets. The server's scheduler (or a collector role, *verify* which
  one owns scheduling when IG-05 lands) only triggers; the executor
  authorizes and dials. (The ticket text said "the collector hashes over
  SSH"; under spec 02 only the executor talks SSH, so the collector at most
  triggers.)
- **Fixed parameters.** The grant freezes a **profile ID** (`fim-default-v1`
  or an admin-approved variant, Q1) and a **mode** (`incremental` or
  `full`). There are no free-form path parameters: the path list lives in
  the signed script and the approved profile, so a compromised server
  cannot point the read at other files.
- **Privilege.** Reading `/root/.ssh`, `/etc/sudoers.d` and
  `/var/spool/cron/crontabs` needs root; the action uses the same SSH
  identity and privilege path as other built-in reads (spec 08). Running
  as root does not make its output trustworthy (threat model).
- **Load.** Run under `nice -n 19` and `ionice -c3` where available; a
  full run hashes at most 8 GiB and stops after 30 minutes (partial). Files
  larger than 512 MiB are hashed only in full runs; in incremental runs
  they appear by metadata only.

**Default profile `fim-default-v1`** (fixed roots, `find -P -xdev`, never
following symlinks; final list is Q1):

| Group | Roots |
| --- | --- |
| System configuration | `/etc` (complete), including `/etc/sudoers`, `/etc/sudoers.d/`, `/etc/ssh/`, `/etc/pam.d/`, `/etc/ld.so.preload`, `/etc/systemd/`, `/etc/cron*`, `/etc/apt/` |
| Boot | `/boot` |
| Executables and libraries | `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/usr/libexec` (with `/bin`, `/sbin`, `/lib` recorded as the usrmerge symlinks they should be) |
| Local software | `/usr/local/bin`, `/usr/local/sbin`, `/usr/local/lib`, `/opt` (none of these is package-owned, so they are always compared against the baseline; `/usr/local/{bin,sbin}` come before `/usr/{bin,sbin}` in the default `PATH`, so a new file there that shadows a system command name is critical, D9) |
| systemd units | `/usr/lib/systemd/system`, `/etc/systemd/system`, user units under `/etc/systemd/user` |
| SSH access | `/root/.ssh/authorized_keys*`, `/home/*/.ssh/authorized_keys*`, the home-relative fixed SSH login files of D9 (`.shosts`, `.rhosts`, `.k5login`, `.ssh/known_hosts`, `.ssh/known_hosts2`) under `/root/` and `/home/*/`, every symlink among the home directories and their `.ssh` directories (recorded, never followed), plus every path that a login-granting directive (D9 "SSH login files": `AuthorizedKeysFile`, `AuthorizedPrincipalsFile`, `TrustedUserCAKeys`, `RevokedKeys`, the program of `AuthorizedKeysCommand` and `AuthorizedPrincipalsCommand`) found in `/etc/ssh/sshd_config` and its includes names, limited to the roots above and `/home/*/`. A target that can lie outside these roots is not scanned; the executor reports it as "SSH login file outside the scanned roots" (D7, D9) and names it in "Honest limits" |
| Scheduled jobs | `/etc/crontab`, `/etc/cron.*/`, `/var/spool/cron/crontabs/`, systemd timers (covered by the unit roots) |
| EFI system partition | `/boot/efi` as its **own root** when it is a mount point (UEFI hosts); otherwise it is ordinary `/boot` content. On vfat, owner, mode and `ctime` come from mount options, so every file under it is hashed in every run, incremental too (the partition is small), and for entries under a `/boot/efi` root whose type in the D6 mounts array is `vfat` only type, size, content hash, symlink target, presence and the setuid, setgid and sticky bits are compared; owner and the permission bits (`0777`) are recorded as context and never open a finding (D9). **Precedence:** this relaxation never covers the setuid, setgid and sticky bits: vfat cannot store them, so a reported setuid or setgid bit under `/boot/efi` is a new setuid/setgid bit and always critical (D9). **The type is host-reported and untrusted:** the relaxation applies only when `/boot/efi` is a covered root (D5 "Separate mounts below a root") and both the approved baseline and the run report `vfat` for it; the reported type is recorded in the baseline as part of the `/boot/efi` root, and a change of it (for example `ext4` to `vfat`) is a change of a critical-class path, in which run the relaxation is not applied |

**Optional roots.** Each root in the approved profile carries a fixed
`optional` flag (part of the profile, never taken from the host). In
`fim-default-v1` exactly these roots are optional: `/boot/efi` (BIOS
hosts), `/opt`, `/usr/libexec`, `/etc/systemd/user` and
`/var/spool/cron/crontabs`; the `authorized_keys*` globs under
`/root/.ssh` and `/home/*/.ssh`, the other home-relative SSH login
files and the `AuthorizedKeysFile` targets may match nothing. A missing optional root is recorded as **absent**
in the run summary and does not make the run partial; if the approved
baseline holds entries under it, they are reported as removed like any
other absent path. A missing root that is not optional makes the run
partial (D6). An approved profile variant may change the flags (Q1).

Excluded by default: `/etc/pve` (Q1), `/usr/lib/python3*/**/__pycache__`,
`/usr/local/lib/python3*/**/__pycache__`,
`/etc/ld.so.cache`, `/usr/lib/modules/*/modules.*` index files and other
generated caches named in the profile; `/run`, `/proc`, `/sys`, `/tmp`,
`/var` except the crontab spool.

**Separate mounts below a root.** `find -xdev` does not descend into
another file system. The script therefore also reports every mount point
it finds below a profile root (path and file-system type, from
`/proc/self/mountinfo`; untrusted like every other record), and the
executor sorts each one into exactly one of three cases:

- **Covered.** The mount point is itself a profile root (for example
  `/boot` on its own partition, `/boot/efi` above, `/opt` or the crontab
  spool). It is scanned as that root; nothing is skipped.
- **Excluded by design.** The mount point path *and* its file-system
  type match an entry of the profile's fixed `excluded_mounts` list. In
  `fim-default-v1` that list has one entry: `/etc/pve` with type
  `fuse` (pmxcfs, Q1). An approved profile variant may add entries (Q1).
  Such a mount is not scanned, is listed as "excluded by design" in the
  run summary and in "Honest limits", and **does not make the run
  partial**: it is outside the profile, like `/var`.
- **Skipped.** Any other mount below a root, including an excluded path
  with an unexpected type (for example a `tmpfs` or bind mount over
  `/etc/pve` or over `/etc/ssh`). It makes the run **partial** (D6) and
  opens an "unexpected mount below a profile root" finding (high;
  critical when it covers a critical-class path, D9). The admin resolves
  it by removing the mount or by approving a profile variant that adds it
  as a root or as an excluded mount.

So a standard PVE host (`/etc/pve`) or UEFI host (`/boot/efi`) has
complete runs, and a partial run always means something unexpected.

### D6: I2 output format and spec 09 rules

Every byte the script returns is **untrusted host data** (spec 09). The
parser is strict, bounded and fuzzed before the beta.

- **Format.** One JSON document, `format` `fim-scan-v1`, with the profile
  ID, mode, start and end time as the host reports them (informational
  only; NOS uses its own clock), counters and an array of records. Same
  strict-JSON rules as `net.facts` (`v23-09-06`): exact ASCII member
  names, no case variants or duplicates, unknown fields rejected, nothing
  after the document.
- **Record.** `path` (raw bytes, standard padded base64, because Linux
  file names need not be UTF-8; at most 4,096 decoded bytes, no NUL, must
  start with a profile root, no `.` or `..` components), `type` (`file`,
  `dir`, `symlink`, `other`), `size`, `mode`, `uid`, `gid`, `inode`,
  `mtime`, `ctime` (integers in range), `sha256` (64 lowercase hex, files
  only, absent when not hashed) and `link` (symlink target, base64, at
  most 4,096 decoded bytes, never followed).
- **Mounts.** A separate array of mount points below the profile roots
  (D5 "Separate mounts below a root"): `path` (same encoding and rules as
  a record path) and `fstype` (at most 64 bytes of `[a-z0-9._-]`), at
  most 256 entries per run. The executor, not the host, classifies each
  one as covered, excluded by design or skipped.
- **SSH configuration.** A separate array with the raw content
  (base64) of `/etc/ssh/sshd_config` and of every file it includes,
  each with its `path` (same rules as a record path), at most 64 files
  and 256 KiB decoded in total per run. The executor parses it in
  memory to derive the critical-class set of D7 "The executor
  classifies, from its own data" and the D5 SSH login file paths (D9
  "SSH login files") and keeps only that derived path set; the content itself is never
  persisted, logged or forwarded (the files' content hashes are keyed
  like all of `/etc`). The script sends this array and hashes every file
  in it in **every** run, incremental runs included (the files are
  small), so every complete run, full or incremental, supplies a derived
  set. The executor checks that every path of this array has a file
  record in the same run whose hashed content matches it, and that every
  file an `Include` names or matches is in the array: an `Include` whose
  path or glob reaches outside the profile roots (no file record can
  exist there) or matches a recorded file that the array leaves out
  makes the array inconsistent. Both checks resolve paths component by
  component against the run's records (D9 "Symlinks at or above SSH
  positions"), never lexically: a symlink record at or above
  `/etc/ssh/sshd_config` or at or above any path an `Include` names or
  matches (for example `/etc/ssh/sshd_config.d` replaced by a symlink) is
  followed, and the files below its resolved target are what the
  `Include` matches. A symlink there that cannot be resolved within the
  run's records (a target outside the scanned roots, a loop, the link
  limit, a missing record) makes the array inconsistent **even when no
  record lies below it**, because the files sshd reads behind it are not
  in the run, and opens the D9 finding. A missing, oversized or inconsistent
  array makes the run partial; a partial run supplies no derived set and
  replaces no retained records, so D7 keeps classifying with the latest
  complete run and the approved baseline.
- **Limits (new named constants, implementation choices to be fixed in
  IG-05).** 300,000 records per host and run, **128 MiB** raw document per
  run (above the 1 MiB `result.json` default of spec 09, so spec 09 needs
  an action-specific limit like ADR 0011 D3), path depth at most 64, one
  record at most 16 KiB. The two run limits are sized to agree:
  - *Record size.* A typical hashed file record (base64 path of a
    60-byte path = 80 characters, 64-hex `sha256`, nine integer fields,
    member names and punctuation) is about 250–300 bytes; budget 300.
  - *Expected volume.* A Debian 12/13 or PVE 8/9 host has on the order of
    100,000–150,000 entries under the D5 roots (mostly `/usr/lib`:
    kernel modules of several kernels, firmware, Perl and Python);
    150,000 × 300 B ≈ 43 MiB.
  - *Cap consistency.* 300,000 records × 300 B = 90,000,000 B ≈ 86 MiB,
    which fits in 128 MiB with room for an average record of up to
    ~447 bytes (128 × 1,048,576 / 300,000), i.e. paths averaging about
    250 bytes. The record cap, not the byte limit, is therefore the
    binding limit for any normal host, and a normal full scan uses well
    under half of both.
  - *Memory.* The parser reads the document as a stream through a
    byte-counting reader and validates record by record; it never buffers
    the raw document. Validated records go to the store in batches.
  - IG-05 measures real full-scan record counts and sizes on reference
    Debian and PVE hosts; if either uses more than half of a limit, the
    limit is raised (or the profile narrowed by an approved variant)
    before the beta, so that a normal full scan can complete and close
    findings.

  A run cut at any limit, a non-zero exit, a skipped root, a skipped
  mount (D5), an unreadable file or an invalid record is **partial**: it
  may open findings but never closes one and never proves that a file is
  unchanged or absent. A mount that is excluded by design (D5) does not
  make a run partial; a profile root that the host does not have and the
  profile marks `optional` (D5 "Optional roots", for example `/boot/efi`
  on a BIOS host) is absent, not skipped. A missing root without that
  flag is skipped and makes the run partial.
- **Display.** Paths are shown as escaped text: valid printable UTF-8 as
  is, everything else as `\xNN`; bidi controls and other format
  characters are always escaped. No host-supplied path ever becomes a
  link, a template or part of a shell command, including in exports.
- **Content hashes and secrets: keyed by default, plain only on an
  allowlist.** A plain SHA-256 of a short or low-entropy secret file
  allows offline guessing (AGENTS.md rule 7), and no denylist of secret
  files can be complete. Therefore:
  - **Plain SHA-256 is stored only for an allowlist of roots** whose
    content is package-shipped binaries or kernel images:
    `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/usr/libexec`, and in `/boot`
    only `vmlinuz-*`, `initrd.img-*`, `System.map-*` and `config-*`.
    These are the files later compared against public archive references
    (D7 item 1).
  - **Every other content hash is keyed:** all of `/etc`, the rest of
    `/boot` (for example GRUB configuration with `password_pbkdf2`
    lines), `/usr/local`, `/opt`, SSH access files and the crontab spool.
    The executor replaces the host's SHA-256 with
    `HMAC-SHA-256(k_host, sha256)` (`crypto/hmac`), where `k_host` is
    derived with HKDF (`crypto/hkdf`, info `nebula-fim-content-v1` plus
    the host ID) from a 32-byte installation key generated with
    `crypto/rand` and held only in executor-owned storage. Per-host keys
    stop cross-host comparison (identical secrets on two hosts do not
    show as identical values).
  - The plain hash exists only in executor memory while the result is
    parsed; the raw script output is never persisted, logged or forwarded.
    The server, database, exports and notifications only ever see the
    keyed value, which detects a change but cannot be tested against
    guesses without the executor's key. The executor offers no operation
    that keys a caller-supplied value (that would be a guessing oracle);
    for this reason a keyed `/etc` conffile is not compared by hash with
    its package default (D7 item 1, "Conffiles"), only shown next to it.
  - **Named secret-bearing paths** are always keyed even if a future
    profile puts them under an allowlisted root, and the UI shows only
    "content changed" for them, never the keyed value: `/etc/shadow`,
    `/etc/gshadow`, `/etc/ssh/ssh_host_*_key` (private keys),
    `/etc/ssl/private/`, `/etc/wireguard/`, `*.key`/`*.pem` under `/etc`,
    `/etc/NetworkManager/system-connections/`, `/etc/ppp/chap-secrets`,
    `/etc/ppp/pap-secrets`, `/etc/ipsec.secrets`, `/etc/ipsec.d/private/`,
    `/etc/postfix/sasl_passwd` (and its `.db`/`.lmdb`),
    `/etc/cifs-credentials*` and other files named by a `credentials=`
    option in `/etc/fstab` that lie under a profile root,
    `/etc/mysql/debian.cnf`, `/etc/krb5.keytab`, `/etc/pve/priv/` (if
    `/etc/pve` is ever included, Q1) and `/etc/nebula/` secret files (D3).
  - Losing the installation key means re-baselining every keyed path;
    the key is part of the executor's backup (spec 15). Their `size`,
    `mode`, `owner`, `mtime`, `ctime` and `inode` are compared as for any
    other file.

### D7: I2 references: never only on the host

Every file is compared against the **approved NOS-held baseline**
(item 2); for package files, NOS additionally checks a **signed archive
reference** (item 1). Both are chosen by NOS, not by the host. The two
roles never mix:

- Every difference from the approved baseline is a finding until a D7
  baseline approval covers it. A matching archive reference never
  closes, suppresses or approves such a difference; it only selects the
  class and severity (D9). A reference therefore never acts as a
  baseline.
- A package file that differs from its verified archive reference is a
  critical finding even when it equals the approved baseline (for
  example a trust-on-first-scan baseline taken after the file was
  replaced), unless the admin accepted that local modification
  explicitly (state `accepted`, D9).
- **Same version, changed content.** If the content of a package file
  changes while the package version the host reports stays the same,
  no package update explains it. The finding is **high**, or
  **critical** for a critical-class path or when the new content differs
  from a verified reference; a match with a reference is shown as
  context only and never lowers the severity below high. The executor
  keeps at most one admitted reference per `(package, version, arch)`
  under the pinned builder key, the first one admitted, and rejects a
  later, different reference for the same triple, whatever `.deb`
  SHA-256 it names (D8). That one reference is the only one used for
  the triple, so a builder cannot add or swap in a second reference for
  an installed version; only a builder key replacement (D8) clears it.

1. **Package files against the signed distribution archive.** For a
   path that belongs to an installed package from a configured Debian,
   Ubuntu or Proxmox archive, the reference is the SHA-256 of that file
   inside the exact `.deb`, reached by a verified chain: archive signing
   key (pinned, out of band) → `InRelease` signature → `Packages` index
   SHA-256 → `.deb` SHA-256 → file in `data.tar.*`. **The archive indices
   only hash whole `.deb` files, not the files inside**, so each `.deb`
   must be fetched once and unpacked to build the per-file reference (D8).
   - **Not used:** `/var/lib/dpkg/info/*.md5sums`, `debsums` or `dpkg
     --verify`. They live on the host, an attacker with root rewrites them
     with the file, and MD5 is broken. Their result is not even shown as
     a hint, to avoid a false sense of safety.
   - **Which version?** The host's package list (`package.list_installed`,
     ADR 0011 D3) is untrusted and only *selects* the reference. If the
     host claims a different real version whose file matches, NOS sees a
     consistent but possibly downgraded package; this is cross-checked
     against NOS's own inventory history and ADR 0011 findings and shown
     as "package updated outside NOS" or, for a lower version, "package
     downgraded outside NOS" (D9) when no NOS job explains it. A job
     explains a version only under the D9 rule: the version the executor
     requested, never a lower or equal one, so a downgrade is never an
     expected change.
   - **Conffiles and generated files.** Package conffiles under `/etc`
     and files that maintainer scripts generate (initramfs, alternatives,
     diversions) are compared against the NOS baseline (2.), with the
     package default shown as context.
2. **Every file against a NOS-held baseline.** Every file, including
   package files (above), and all metadata (mode, owner, symlink target,
   presence) are compared against a per-host baseline. For non-package
   files, files from unconfigured archives or local `.deb`s and conffiles
   it is the only reference. The baseline **exists only on NOS**: the
   full record list in
   the server database and, as tamper evidence, its digest in executor
   storage.
   - **Initial baseline.** The first complete scan becomes a *proposed*
     baseline. It is labelled "trust on first scan": NOS cannot know
     whether the host was already compromised, and the admin is told so.
     Until Q6 is answered, package files too are compared only against
     this trust-on-first-scan baseline (D8, D9); only once D8 builds
     archive references are they checked against the archive
     independently of the first scan.
   - **Approval.** The admin approves a baseline (initial or updated) by
     digest (the initial one only in the executor-local CLI, below), with
     the same assertion as D3 (challenge domain
     `nebula-fim-baseline-v1`). The signed challenge binds the host ID,
     the currently approved digest the proposal was built on and the new
     executor-computed digest, so an approval cannot be applied to
     another host or on top of a baseline that changed in the meantime
     (the executor rejects it if its stored digest is no longer the
     bound previous digest). Bulk approval per host and per finding batch
     is allowed except for critical-class paths (D9); every approved
     entry is audited with old and new values.
   - **Critical-class entries are approved only in the executor-local
     CLI.** WebAuthn signs a challenge, not what the browser displays
     (ADR 0007): a compromised server chooses which paths it names and
     serves the approval screen, so it could show a harmless list while
     the admin's assertion covers the executor digest of an
     attacker-chosen critical-class entry. Therefore a proposed baseline
     that adds, changes or removes **any** critical-class path (D9) is
     approved only with `nebula integrity pending <host>` and
     `nebula integrity approve <host> <digest>` on the NOS machine, run
     as the admin UID, audited, in every mode (the same independent
     executor view as `nebula approve` for hardened HIGH/CRITICAL
     batches, ADR 0007). A proposed baseline that changes a
     critical-class entry changes **only that entry**: the executor
     builds it as the approved list plus exactly one added, changed or
     removed entry, and `approve` rejects a digest whose difference from
     the approved baseline has more than one entry when any of them is
     critical-class (the initial baseline is the one exception, below).
     **The executor keeps every proposal it computes.** For each
     proposed digest it stores, in executor-owned storage, the previous
     approved digest the proposal was built on, the run ID of the
     retained records it took the values from, and every entry in which
     the proposal differs from that previous baseline with its old and
     new values (the old values from the digest-checked approved list,
     the new values copied from the retained run when the proposal was
     built), and the derived set (d) of that run (below). A newer run that replaces the retained records does not
     change a stored proposal. **The proposal store is bounded** (new
     named constants, fixed in IG-05): at most **16** stored proposals
     per host, of which at most **one** initial proposal (a new initial
     proposal replaces the stored one); a stored proposal expires
     **7 days** after the executor built it (executor clock); and when a
     baseline approval stores a new approved digest, the executor deletes
     every stored proposal of that host whose previous digest is no
     longer the approved digest (they could never be approved). When the
     per-host cap is reached, a new proposal evicts the oldest one; an
     evicted or expired proposal is refused by `approve` like an unknown
     digest, and the admin requests a new one. A compromised server can
     therefore make the executor discard pending proposals, never store
     more than the cap or approve anything. `pending` only lists stored proposed
     digests and approves nothing. `approve` itself, whatever the source
     of the digest the admin passes (typed, pasted from `pending` or from
     the browser), refuses a digest for which it holds no stored
     proposal, refuses when the executor's current approved digest is not
     the proposal's previous digest (the baseline changed meanwhile; the
     admin needs a new proposal), and otherwise renders **every** entry
     of that stored proposal's difference (which for such a digest is
     that one entry), with its old and new values, from the stored
     proposal itself and never from the current retained records
     (escaped as in D6 "Display", so no host byte reaches the terminal as
     a control sequence), together with the host ID and both digests. It
     then asks for an interactive confirmation on the terminal; it
     approves only after that confirmation, has no flag that skips it,
     and refuses when stdin is not a terminal. On confirmation it checks
     the previous digest again and, in one step, stores exactly the
     digest of the list it rendered (the approved list plus that stored
     difference) as the new approved digest. So the CLI never approves an
     entry it did not show, and never shows values other than the ones
     the digest approves. The executor rejects a browser
     assertion for a digest whose difference from the approved baseline
     adds, changes or removes a critical-class entry; unchanged
     critical-class entries carried over from the approved baseline (for
     example `/etc/sudoers` in every full baseline) do not prevent a
     browser approval. Recovery mode cannot approve either way. Browser
     approval remains for entries that are not critical-class, with the
     limit named in "Honest limits".
     - **Initial baseline.** While the executor holds no approved digest
       for a host, the "one entry" rule cannot apply: the first complete
       run holds thousands of critical-class entries (all of `/boot`,
       every systemd unit, every setuid file). The initial proposal is
       therefore the executor's whole retained complete run and nothing
       else: the server names no paths for it and cannot add, drop or
       change an entry, and its stored previous digest is "none". It is
       approved only with `nebula integrity approve --initial <host>
       <digest>` in the executor-local CLI, never in the browser (it
       always contains critical-class entries). `--initial` is refused
       when the executor already holds an approved digest for the host,
       and a digest without `--initial` is refused while it holds none.
       The CLI first shows the "trust on first scan" warning, the host
       ID, the run ID, the digest and the number of entries per D9 class,
       then **every critical-class entry** (escaped as above, paged on
       the terminal), and asks the admin to confirm by typing the host ID;
       it has no flag that skips the listing or the confirmation and
       refuses when stdin is not a terminal. Entries that are not
       critical-class are counted, not listed. The approval stores the
       digest and, since the whole SSH configuration then comes from one
       run, that run's derived set (d) (below).
   - **The executor classifies, from its own data.** Whether an entry is
     critical-class is decided by the executor, never by the server: a
     server-supplied class or label is at most compared and never makes
     an entry non-critical. The executor uses only (a) the fixed D9 path
     patterns of the approved profile, (b) the old record (approved
     baseline) and new record (its own retained run) of the entry, for the
     setuid/setgid rule, (c) the command names in `/usr/bin` and
     `/usr/sbin`, for the shadowing rule, and (d) the set of
     `sshd_config` includes and SSH login file targets (D9 "SSH login
     files": `AuthorizedKeysFile`, `AuthorizedPrincipalsFile`,
     `TrustedUserCAKeys`, `RevokedKeys` and the `AuthorizedKeysCommand`
     and `AuthorizedPrincipalsCommand` programs) that it derives itself
     from D6 "SSH configuration" records. Item (a)
     includes, independent of any `sshd_config`, every file whose name
     begins with `authorized_keys` anywhere in the scanned paths (D5,
     including `/root/.ssh` and `/home/*/.ssh`) and every path ending in `/.ssh/authorized_keys` or
     `/.ssh/authorized_keys2`, so every real `authorized_keys` file is
     critical-class whatever `AuthorizedKeysFile` says, and likewise the
     fixed SSH login files of D9 (hostbased trust, `known_hosts`,
     `.k5login`, `/etc/krb5.keytab` and the account files), whatever
     `HostbasedAuthentication` or `GSSAPIAuthentication` say, and the
     sshd command-line configuration sources of D9.
     - **Derived sets only grow until a change is approved.** The sets
       for (c) and (d) are each the **union** of the set derived from the
       approved baseline and the set derived from the latest complete
       run. For (c), these are the `/usr/bin` and `/usr/sbin` names in the
       approved list (digest-checked, below) and in the executor's
       retained run. For (d), the executor never keeps SSH configuration
       content (D6), so it stores, next to the approved baseline digest,
       an approved derived set S and changes it only on a baseline
       approval, by this rule. Let R be the complete run the approved
       proposal was built from (its run ID and derived set are stored
       with the proposal, above). R's SSH configuration array (D6) holds
       `/etc/ssh/sshd_config` and every file it includes, checked for
       consistency. A derived set holds the `Include` values (paths and
       globs, as written, resolved against `/etc/ssh` like sshd does) as
       well as the files they matched and the SSH login file targets.
       The **SSH configuration entries** of a baseline are its entries for
       `/etc/ssh/sshd_config` and for every path that an `Include` value
       in S or in R's derived set names or matches. S is **replaced** by
       R's derived set only when all three conditions hold:

       1. the approval is an executor-local CLI approval
          (`nebula integrity approve`, including `--initial`); a browser
          approval never replaces S, it only unites S with R's set;
       2. for **every** path in R's SSH configuration array, the newly
          approved baseline holds an entry equal to R's record of that
          path (type and content hash); and
       3. the reverse: the newly approved baseline holds **no** SSH
          configuration entry whose path is not in R's array. So an
          approved include that R no longer has (for example
          `sshd_config.d/z.conf`, deleted on the host but its removal not
          yet approved) blocks the replacement.

       Then the approved SSH configuration is exactly R's, file for file
       in both directions, so R's derived set is exactly the set of the
       approved configuration. In every other case, in particular a
       browser approval, an approval that takes `sshd_config` but not a
       changed include from R (or the reverse, one CLI approval at a
       time), an approval while an include R names is still missing from
       the baseline or while the baseline still holds an include R does
       not have, and a baseline whose SSH configuration entries were taken
       from another run with different content, S becomes the **union** of
       S and R's derived set and never shrinks. So the set shrinks only
       when the approved baseline holds the whole SSH configuration of one
       run and nothing else; after one-entry CLI approvals of a
       multi-file change (adding, changing and removing includes), that is
       the last of them, provided the entries approved earlier still equal
       that run's records. If a newer run changed one of them in between,
       the condition fails and S stays the larger union until the admin
       has approved the whole configuration of one run in the CLI, which
       only over-classifies. Classification keeps using the union of S and
       the latest complete run's set, as stated above. A pending
       `sshd_config` change, a deleted include or a removed `/usr/bin`
       command therefore never makes an entry non-critical; the smaller
       set takes effect only after the admin approved the whole change in
       the CLI. Before the first approved baseline, the run's set alone is
       used; the initial approval (above) sets S to the initial run's
       derived set.
     - **Derived-set limit.** S, and the derived set of any one run, holds
       at most **4,096** values (`Include` values, matched files and SSH
       login file targets together; new named constant, fixed in IG-05).
       A run whose derived set would exceed it supplies no usable derived
       set (below). When a union would make S exceed it, the executor
       marks S **overflowed** instead of dropping values: while S is
       overflowed, every entry that a proposed digest of that host adds,
       changes or removes is unclassifiable and therefore critical-class
       (each needing its own CLI approval). Only a replacement under the
       three conditions above clears the mark.
     - **`AuthorizedKeysFile` expansion.** The executor parses `Include`
       and every SSH login file directive of D9 (including those inside
       `Match` blocks) and expands `AuthorizedKeysFile`,
       `AuthorizedPrincipalsFile`, `TrustedUserCAKeys` and `RevokedKeys`
       values alike; without an `AuthorizedKeysFile` directive it uses the
       OpenSSH default `.ssh/authorized_keys .ssh/authorized_keys2`.
       `%h` expands to a whole home directory, and a value that does not
       start with `/` or `%h` is relative to the home directory. Because
       the host's passwd entries are untrusted and homes may lie anywhere
       (`/root`, `/home/alice`, service homes under `/var`), the executor
       does not resolve homes: it matches `%h` and the implied home
       prefix of a relative value against **any** sequence of one or more
       path components (`/root` included), and `%u` and `%U` against any
       single path component; `%%` is a literal `%`. So `%h/.config/keys`
       covers `/root/.config/keys` and `/var/lib/svc/.config/keys`, and
       `/etc/ssh/authorized_keys/%u` covers every file in that directory.
       Over-matching only makes more entries critical-class, never fewer.
     - **Unclassifiable means critical.** When the executor cannot
       classify an entry with certainty (no usable derived set, a parse
       failure, a limit hit, a directive, value or token it does not
       understand, an SSH login file value it cannot expand as
       above, a command program path that is not absolute, contains a
       `%` token or is quoted or escaped (D9 "SSH login files"), a symlink
       at or above an SSH position it cannot resolve (D9), an
       overflowed or oversized derived set (above), an `Include` that
       names or matches a file outside the profile roots or a file that
       is not in the run's SSH configuration array, D6), it treats the
       entry as critical-class. If it lacks a
       usable derived set for a host from the latest complete run, it
       treats **every** entry that a proposed digest of that host adds,
       changes or removes as critical-class (each needing its own CLI
       approval) until a complete run provides one.
   - **The executor alone decides what goes into a baseline.** The
     digest the admin approves is computed by the executor, never taken
     from the server:
     - The executor parses each `fim.scan` result it received over its
       own SSH session (D5) and keeps the validated records of the latest
       complete run per host in executor-owned storage until the next
       complete run replaces them or a baseline is approved from them.
       A complete incremental run replaces a retained content hash only
       for paths it hashed; for a path it did not hash, the hash from the
       last complete full run is kept while the metadata is unchanged
       and dropped when the metadata changed (D9).
       The records are written with content hashes already keyed (D6),
       except on the plain-hash allowlist; the plain hash of a keyed path
       is never written to disk.
     - A proposed baseline is built by the executor as: the currently
       approved list (fetched from the server and accepted only if its
       digest equals the executor-stored digest; otherwise an
       `integrity.baseline_tamper` finding and no approval) plus, for
       the paths the admin selects, the record values from the executor's
       own retained run, or removal of the entry where that run shows the
       path absent. A path for which the retained records hold no
       current content hash (changed metadata seen only by an
       incremental run, D9) cannot be selected until a full run has
       hashed it. The server only names paths to include or remove; it
       cannot supply record values, a list or a digest that the executor
       would approve.
     - The approval screen is rendered from the executor's data, and the
       assertion binds the executor-computed digest. A server-supplied
       proposed list or digest is at most compared with it; a mismatch is
       a baseline tamper finding, never a reason to approve.

     This stops a compromised server from supplying record values or a
     digest. It does not stop a compromised server from naming other
     paths than the ones it displays in the browser; for critical-class
     paths the executor-local CLI (above) closes that gap, for other
     paths it remains a named limit ("Honest limits"). Nor does it
     protect against a host that was already compromised at its first
     scan ("trust on first scan" above).
   - **Server compromise.** A compromised server could display a forged
     baseline or hide findings; it cannot make the executor's stored
     digest match a rewritten list. On every scan and after any NOS
     restore, the executor recomputes the digest of the server's list and
     opens an I2 baseline digest mismatch finding
     (`integrity.baseline_tamper`, D9) on mismatch.

### D8: Package reference builder

Building per-file references needs archive egress, OpenPGP verification
of `InRelease` and decompression of `data.tar.xz` (Debian) and
`data.tar.zst` (Ubuntu since 21.10). The NOS server has no feed egress
(ADR 0011 D1, Q2) and the executor must not gain any.

- **Where.** On the vulnerability agent host (ADR 0011 Amendment 1,
  `nebula-vuln-agent`), which already has allowlisted feed egress (A1.5),
  or on a separate host with the same egress rules (Q6). It fetches only
  packages that appear in NOS's installed-package inventory, from
  operator-configured archive origins (or a local mirror/apt cache),
  rate limited, with cache keys
  `(archive, suite, component, package, version, arch, deb SHA-256)`.
- **What NOS receives.** Per `(package, version, arch)`, naming the deb
  SHA-256 it was built from, a bounded list `(path, type, size, mode, uid, gid, sha256, link)` taken
  from the `data.tar.*` headers and contents, as an RFC 8785 JCS
  document (`format` `nebula-fim-reference-v1`), posted through a
  new write scope on `/api/v1`. This is **untrusted input** under spec 09
  (strict schema, limits: 20,000 files and 4 MiB per package, path rules as
  D6). NOS cannot re-derive these hashes itself: the reference is as
  trustworthy as the builder host plus the archive signatures.
- **The executor verifies every reference against a pinned builder
  key.** The server only relays the document; it is not trusted for it.
  The builder signs each reference document with its own Ed25519 key
  (`crypto/ed25519`, in the existing `internal/sshsig` envelope with
  namespace `nebula-fim-reference`; whether `internal/sshsig` needs a
  signing function is verified in IG-09). The builder's public key is
  pinned in executor-owned storage by the admin with an executor-local
  CLI command (`nebula integrity trust-builder <public key file>`, admin
  UID, audited, both modes; replacing it is the same command and is
  audited with old and new key). The executor admits a reference only if
  the signature verifies against the pinned key, the document passes the
  strict schema and no different reference for the same
  `(package, version, arch)` was admitted before under that key. The
  deb SHA-256 is part of the signed document but not of this key: the
  first admitted reference for a triple is the only one the executor
  ever uses for it; a later one that differs in any byte, including a
  different deb SHA-256, is rejected, audited and never replaces or
  joins the first. **Reference conflict alert.** Each such rejection
  opens an `integrity.reference_conflict` finding (high, D9) that names
  the triple and both deb SHA-256 values and is notified like other
  integrity events. It tells the admin that either two configured
  archives publish different builds (below) or the builder or its key
  signed a reference that is not the archive's, and that the second case
  is resolved only by replacing the builder key ("Builder key
  replacement" below). A compromised key can also **pre-sign**
  references for versions that are not yet installed or published;
  under the first-admitted rule such a forged reference is the one used
  when that version arrives and blocks the correct one, which then
  raises this conflict alert, until the key is replaced (named in
  "Honest limits"). (Two
  configured archives that publish different builds under the same
  triple are therefore not both verifiable: hosts with the other build
  show "differs from signed reference" until the admin accepts it or
  configures one origin.) A reference that fails any check counts as
  "no reference" (D9), never as verified. Only references admitted this
  way are "verified" in D7 and D9. A compromised server therefore cannot
  forge a reference; a compromised builder (or its key) can, with
  exactly the effects listed in "Honest limits". The builder key is
  file-based on the builder host: root on that host can sign with it. It
  cannot change a host and cannot authorize anything.
- **Builder key replacement revokes the old references.** Replacing the
  pinned key (`trust-builder` with a new key, for example after a
  builder compromise) drops every reference admitted under the old key:
  from then on they count as "no reference", and every open finding
  whose class or severity rested on one of them is re-rated as if no
  reference existed: `expected_pending` findings with a "verified" label
  become "changed during NOS job, unverified" (high, or critical for a
  critical-class path, D9), and open "package updated outside NOS"
  (medium) findings become "other changed file" (high, or critical for
  a critical-class path, D9). The builder re-fetches and re-signs references with the new key,
  and the executor admits them again under the first-admitted rule, now
  per new key, so a forged reference from the compromised key cannot
  block the correct one. The next complete full run compares every
  package file with the re-admitted references; a file that matches
  the approved baseline but differs from the new reference is a
  critical "differs from signed reference" finding (D7). The lasting
  effect of a builder compromise is limited to what the admin approved
  into a baseline while the forged reference was trusted: those entries
  stay approved until that full run flags them, and for a version that
  can no longer be fetched (D8 "Old versions") no new reference exists,
  so a forged file the admin approved for it stays in the baseline
  undetected until the package version changes.
- **Old versions.** Debian versions that left the mirror are fetched from
  `snapshot.debian.org` if the operator allows that origin; Ubuntu and
  PVE versions that are no longer published become "no reference" and
  fall back to the baseline (labelled so).
- **Dependencies (conflict with "no new dependency", needs Q6).** I1, I2
  collection, the baseline mode and the finding store need no new module
  (`crypto/sha256`, `archive/tar`, existing `internal/sshsig` and JCS).
  The package reference builder does: the standard library has no
  OpenPGP, xz or zstd. `github.com/ProtonMail/go-crypto` is approved for
  the vuln agent only for CSAF signatures (ADR 0011 A1.6); using it for
  `InRelease` and adding xz and zstd decompressors are new maintainer
  decisions. Until Q6 is answered, package files are compared against the
  baseline like any other file, and the UI says so; a package file changed
  during a NOS apt job is then always "changed during NOS job, unverified"
  (D9), never an expected change.

### D9: Change detection, attribution, findings and notifications

**Incremental and full runs.**

- **Incremental** (default every 6 hours, Q2): the script records metadata for
  every file in the profile and hashes only files whose `ctime` or `mtime`
  falls within the profile's fixed look-back window (default 26 hours, a
  frozen grant parameter, so a missed run still overlaps). NOS compares
  metadata `(size, mode, uid, gid, inode, mtime, ctime, type, link)` with
  the last complete record per path; any metadata change of a file that
  was not hashed opens a "changed, not yet hashed" finding and schedules a
  full run inside the existing lease budget. `ctime` cannot be set by
  ordinary tools, but root can fake it (threat model).
- **Full** (default weekly, Q2): hash every regular file in the profile.
  Only a complete full run can close a finding. "Complete" is the D6
  definition: a mount excluded by design (D5, for example `/etc/pve` on
  PVE) does not prevent it, so findings on standard PVE and UEFI hosts
  can close; a skipped mount does.

**Expected changes are attributed automatically, never by time window
alone.** A change is *expected* only when all of these hold:

- it falls between the start and end of a NOS job on that host that the
  executor authorized (apt install/upgrade, a module action that declares
  the paths it writes, an ADR 0007 batch member), and
- for a package file: the package is one the executor authorized the job
  to change, **and** the version the host reports afterwards is the one
  the executor requested: the exact target version frozen in the job's
  parameters or, for a job without a pinned version (for example
  `apt upgrade`), a version strictly higher in dpkg ordering than the one
  in NOS's last complete inventory before the job. The host-reported
  result only confirms this; a lower or equal version is never expected,
  so a signed downgrade or a reinstall of an older build is a finding
  (D7 item 1 "Which version?"); **and** the new record equals a
  **verified** archive reference for that version (D7 item 1, built by
  D8) in every field the reference carries: content hash, type, size,
  mode including the setuid, setgid and sticky bits, owner and symlink
  target. A new setuid or setgid bit, a mode or owner change or a type
  change that the reference does not carry is never expected, and
- for a non-package file: the job's action contract declares the path
  **and** the new hash equals content the executor itself knows (the bytes
  it sent or the artifact it deployed) **and** type, mode and owner equal
  those the action sets or, where it sets none, the previous baseline
  values.

**Without a verified reference a change is never expected.** If no
verified per-file reference exists for the package version (always the
case until Q6 is answered, and afterwards for versions that left the
archive, D8 "Old versions"), or if a declared non-package path was
rewritten by a command whose resulting content the executor does not know,
the change is classed **"changed during NOS job, unverified"**:

- it is an open finding of severity **high**, or **critical** for a
  critical-class path (precedence below), never info-level and never
  `expected_pending`;
- it is **never approved together with the job**, in any mode (Q3 does
  not apply to it); the admin approves it only through a separate
  baseline approval (D7) whose screen labels every such entry
  "unverified: NOS cannot tell this change from an attacker's change made
  during the job". Batch approval of the unverified entries of one job is
  allowed for entries that are not critical-class paths, but the batch is
  its own assertion and never part of the job approval;
- host-side evidence does **not** make it verified:
  `/var/lib/dpkg/info/*.md5sums`, `debsums` and `dpkg --verify` are
  controlled by the same root that could have replaced the file, and
  MD5 is broken (D7). Only the signed-archive chain of D7 item 1 counts as
  a verified reference.

Consequently, before Q6 every package file changed by a NOS apt job is an
unverified finding the admin must review.

**Critical-class paths.** These are: `authorized_keys*` files and every
SSH login file (below, including hostbased trust files, `known_hosts`,
`.k5login`, `/etc/krb5.keytab`, `/etc/passwd`, `/etc/shadow`,
`/etc/group`, `/etc/gshadow`, `/etc/nsswitch.conf` and symlinks at or
above SSH positions), `/etc/sudoers` and `/etc/sudoers.d/`, PAM
configuration (`/etc/pam.d/`, `/etc/security/`) and PAM modules
(`pam_*.so`), `/etc/ssh/sshd_config` and its includes, the sshd
command-line configuration sources (below), `/etc/ld.so.preload`, systemd
units, drop-ins and timers under the D5 unit roots, crontabs and the
crontab spool, every file under `/boot` (under a vfat `/boot/efi` root,
D5, owner and permission-bit changes never open a finding; the setuid,
setgid and sticky bits and the reported file-system type are still
compared, D5), the
SSH daemon and its helpers
(`/usr/sbin/sshd`, `/usr/lib/openssh/`), `sudo` and `su`, the dynamic
loader (`ld-linux*`), every file in `/usr/local/bin` or `/usr/local/sbin`
whose name shadows a command in `/usr/bin` or `/usr/sbin`, and every file
that has a setuid or setgid bit before or after the change.

**SSH login files.** Every file that sshd reads or runs to decide whether
a login is granted is critical-class, so none of them can be approved in
the browser. These are the targets of these directives in
`/etc/ssh/sshd_config` and its includes, including inside `Match`
blocks, expanded as in D7 "`AuthorizedKeysFile` expansion":

- `AuthorizedKeysFile` (default `.ssh/authorized_keys
  .ssh/authorized_keys2`): adds keys;
- `AuthorizedPrincipalsFile`: names the certificate principals that may
  log in as a user;
- `TrustedUserCAKeys`: a CA key there makes every certificate it signs a
  valid login key, for any user whose principals it names;
- `RevokedKeys`: removing a key from it re-enables that key;
- `AuthorizedKeysCommand` and `AuthorizedPrincipalsCommand`: the program
  (the first word of the value, which sshd requires to be an absolute
  path) decides which keys or principals are accepted.

In addition, these files are SSH login files by fixed path pattern (D7
item (a)), whatever the SSH configuration says, because sshd, its PAM
stack or its authentication methods read them to grant a login:

- hostbased and rhosts trust: `/etc/hosts.equiv`,
  `/etc/ssh/shosts.equiv`, and every path ending in `/.shosts` or
  `/.rhosts`;
- host keys trusted for hostbased login: `/etc/ssh/ssh_known_hosts`,
  `/etc/ssh/ssh_known_hosts2`, and every path ending in
  `/.ssh/known_hosts` or `/.ssh/known_hosts2`;
- GSSAPI/Kerberos: every path ending in `/.k5login` (principal
  mapping) and `/etc/krb5.keytab` (the host service key sshd accepts
  tickets with; whoever replaces it can forge tickets that log in through
  `.k5login` or the default principal mapping);
- account and name-service data: `/etc/passwd`, `/etc/shadow`,
  `/etc/group`, `/etc/gshadow` and `/etc/nsswitch.conf` (a new UID-0
  account, a changed password hash, shell or home, or a changed
  name-service source can each grant a login).

The home-relative files are scanned under `/root` and `/home/*/` (D5);
the `/etc` files are under the `/etc` root.

**sshd command-line configuration sources.** sshd's command line can
replace or extend `/etc/ssh/sshd_config` (`-f <file>`, `-o
<directive>=<value>`, for example `-o AuthorizedKeysFile=/srv/k/%u`).
On the supported distributions that command line comes from
`/etc/default/ssh` (`SSHD_OPTS`) and from the units that start sshd
(`ssh.service`, `ssh@.service`, `ssh.socket`, `sshd.service` and their
drop-ins). `/etc/default/ssh` is critical-class by fixed path (D7
item (a)); the units and drop-ins already are as systemd units under the
D5 unit roots. The executor does **not** parse `SSHD_OPTS` or
`ExecStart` lines, so `-f` and `-o` targets are not derived: a change
that adds such an option is critical and needs its own CLI approval,
but the files it names are classified only by the fixed patterns, a
named limit ("Honest limits").

A value of `none` names no file. The executor takes the program of an
`AuthorizedKeysCommand` or `AuthorizedPrincipalsCommand` value only when
the value contains no quote character (`"` or `'`) and no backslash, so
that a split at the first space or tab is exactly what sshd runs; a
value with a quote or a backslash anywhere (sshd's quoting and escape
rules could make the program path differ from the naive first word), a
program path that is not absolute or contains a `%` token, and any other
value the executor cannot expand, is unclassifiable and handled as in D7
"Unclassifiable means critical".

**Symlinks at or above SSH positions.** The scan never follows
symlinks (D5), so the file sshd actually reads may sit behind one. One
general rule covers this: **any symlink at or above a position that
sshd reads configuration or login data from is critical-class, and
opens an "SSH login file outside the scanned roots" finding if it
leaves the scanned roots.** An **SSH position** is:

- a **configuration position**: `/etc/ssh/sshd_config`, every path that
  an `Include` value (in S or in the run's derived set, D7) names or
  matches, and every sshd command-line configuration source (above);
- a **login file position**: every path that an SSH login file pattern
  (fixed or derived) matches;

and every directory **at or above** such a path, whether the pattern
names it literally or matches it with a token or glob (for example
`/etc`, `/etc/ssh` and `/etc/ssh/sshd_config.d` for `Include
/etc/ssh/sshd_config.d/*.conf`; `/etc/ssh/ak` and every `/etc/ssh/ak/<x>`
directory for `AuthorizedKeysFile /etc/ssh/ak/%u/keys`, since `%u`
matches any single component; `/root`, `/home`, `/home/<name>`, every
directory that `%h` or the implied home prefix matches, and the `.ssh`
directory below it, for the home-relative patterns). Matching uses D7
"`AuthorizedKeysFile` expansion", so it over-matches rather than
under-matches. Whenever the old or new record at an SSH position is a
symlink (or, for a file position, any type other than `file`):

- the symlink entry itself is critical-class; and
- the executor resolves it as the kernel does and classifies the
  resolved path, and for a directory position every entry below the
  resolved directory that the rest of the pattern matches, as SSH login
  files or SSH configuration files, so they are critical-class too.

**Resolution is component by component, never lexical.** The executor
walks the path from `/` one component at a time against the same run's
records: a `.` is dropped; a `..` moves to the parent of the directory
reached **so far**, that is, after every symlink before it has been
followed (so `/etc/ssh/l/../x`, with `l` a symlink to `/srv/a/b`,
resolves via `/srv/a/x`, not `/etc/ssh/x`); a component whose record is
a symlink is replaced by its target (an absolute target restarts at
`/`, a relative one continues from the link's directory) before the
next component is taken. At most **40** symlinks are followed per
resolution (the Linux limit; new named constant `maxSymlinkFollows`,
fixed in IG-05).

If it cannot resolve the path within the run's records (a component
outside the profile roots or `/home/*/`, a loop, the link limit, a
missing record), the symlink entry is unclassifiable and therefore
critical-class (D7 "Unclassifiable means critical"), and a target
outside the scanned roots, a loop or the link limit opens the "SSH login
file outside the scanned roots" finding below (critical for a
configuration position, high otherwise; naming the symlink and its
escaped target, kept open while the approved baseline or the latest run
holds that symlink), since the files sshd reads there are not scanned.
At a configuration position this also makes the run's SSH configuration
array inconsistent (D6), so the run is partial and supplies no derived
set; a symlinked include directory therefore never lets the script leave
included files out of the array.

Files that an `AuthorizedKeysCommand` or `AuthorizedPrincipalsCommand`
program itself reads or runs are not derived (named in "Honest
limits"). An absolute target outside the D5 roots and
`/home/*/` (for example `TrustedUserCAKeys /srv/ca.pub` or
`AuthorizedKeysFile /var/lib/keys/%u`) is not scanned; the executor
opens an "SSH login file outside the scanned roots" finding (high)
naming the directive and its escaped value, kept open while the
approved or the latest complete run's SSH configuration names it. A
`%h`-based or relative value does not open this finding, because it
matches homes anywhere: such files in homes outside `/root` and
`/home` (service accounts under `/var`, `/srv`, `/opt`) are not
scanned, a named limit ("Honest limits").

For all critical-class paths:

- **Severity precedence.** When a change matches several classes of the
  table below, the highest severity wins, so a new setuid or setgid file
  or bit stays critical even when it is a verified expected change. A critical-class path stays
  **critical** when it changes during a NOS job without a verified
  reference; it is labelled "changed during NOS job, unverified" in
  addition, never downgraded to high.
- **Never batch-approvable, never in the browser.** In any mode, before
  and after Q6, verified or not, each critical-class entry is approved
  with its own executor-local CLI approval that covers that one entry
  (D7 "Critical-class entries are approved only in the executor-local
  CLI"). It is never part of a bulk, per-job or per-finding-batch
  approval, never part of the Q3 standard-mode bulk approval of
  verified expected changes, and never approved with a browser
  assertion.

**"Expected" is a label, never an approval.** An expected change is
recorded as `expected_pending` and shown as "changed by NOS job <id>,
matches verified reference". It enters the baseline **only through a D7
baseline approval, in every mode**: the executor builds the proposed
entries from its own retained post-job scan (D7 "The executor alone
decides"), computes the digest, and the admin approves exactly that
digest with the `nebula-fim-baseline-v1` assertion (with the
executor-local CLI for a critical-class entry). The job approval
never covers baseline entries: it is given before the job and cannot bind
a scan result, and the "verified" label rests on a D8 reference that the
executor verifies against the pinned builder key but cannot re-derive
(D8). A compromised builder can therefore make an attacker's file *look*
expected (and lower its severity to info), but it cannot put that file
into a baseline without the admin's executor-bound approval; the
approval screen says that the "verified" label comes from the reference
builder (see "Honest limits"). A compromised server alone cannot forge
the label.

Anything else changed in the same window, and every unverified change,
is a finding the admin sees separately from the job. This makes hiding
behind a running NOS job harder, **not impossible**. Before Q6, a
replaced `/usr/sbin/sshd` during an approved `openssh-server` upgrade is
a critical, individually approved entry, but NOS cannot tell it from the
genuine new binary; the admin can only compare its plain hash (D6
allowlist) with the file from a `.deb` they verified themselves. After
Q6 the replaced binary fails the verified reference unless the builder
or its signing key is compromised as well (the server alone cannot
forge a reference, D8). Both limits are listed in "Honest
limits". Package updates done on the host outside NOS (for example
unattended-upgrades) that raise the reported package version (strictly
higher in dpkg ordering than in NOS's last complete inventory) and whose
new records match the verified archive reference for the new version in
every field listed above are medium-severity findings ("package updated
outside NOS"), not alarms, unless the path is critical-class
(precedence above). A **lower** reported version made outside NOS is
"package downgraded outside NOS", severity high (critical for a
critical-class path), even when its records match a signed reference
for that older version: a validly signed old build can reintroduce a
fixed vulnerability, and unattended upgrades never downgrade. A content
change without a version change is never "package updated outside NOS"
(D7 "Same version, changed content").

**Findings.** A new store `integrity_findings` (not the ADR 0011 store,
whose observer is always Hermes): subject (NOS machine or host ID), path
(raw bytes plus escaped display form), class, old and new record, first
and last seen, state (`open`, `expected_pending`, `accepted`,
`resolved`), and the run IDs that opened and closed it. Retention and
dedupe follow ADR 0011 D6/D9 patterns. Severity by class (the highest
matching severity wins, see "Critical-class paths"):

| Class | Severity |
| --- | --- |
| Package file differs from signed reference; NOS binary/unit mismatch (I1); any new, changed or removed critical-class path (above) that is not a verified expected change, including one changed during a NOS job without a verified reference; new setuid/setgid file or bit; missing NOS own key or extra key in root's `authorized_keys` | critical |
| Other changed or new file in `/etc` or a watched `/usr` root (D5); owner/mode change; I2 baseline digest mismatch; change of a path that is not critical-class during a NOS job without a verified reference ("changed during NOS job, unverified"); package file content changed without a version change, even if it matches a reference (D7); package downgraded outside NOS (lower reported version), even with a matching signed reference; unexpected (skipped) mount below a profile root (D5), critical when it covers a critical-class path; SSH login file outside the scanned roots (D9 "SSH login files"); reference conflict (`integrity.reference_conflict`, D8) | high |
| Package updated outside NOS (strictly higher reported version) with matching reference; partial or stale scan | medium |
| Verified expected change from a NOS job (`expected_pending` until approved by D7; a critical-class path still needs its own executor-local CLI approval) | info (record only) |

**Notifications** go through the existing webhook, ntfy and Telegram
senders (ADR 0011 D9 pattern): events `integrity.nos_mismatch`,
`integrity.host_change`, `integrity.scan_incomplete`,
`integrity.baseline_tamper`, `integrity.reference_conflict`. Messages carry **structured fields only**:
host label, class, severity, count and a NOS link. **No host-supplied path
or content is put into a notification**, because chat clients render
Markdown and links; the path is shown only in the NOS UI under spec 09
rules. Dedupe per `(subject, class, path)`, at most 10 messages per hour,
then an hourly digest.

**Reaction stays advisory.** By default an I2 finding does not block
jobs on the host (Q3 asks whether it should). It never triggers a
restore, reinstall or any other mutation.

### D10: I3, later: measured boot and IMA attestation (outline only)

For hosts with a TPM 2.0 (physical TPM, or a vTPM on PVE guests):

- Enroll the host's attestation key once (trust on enrollment, approved
  like a host key, ADR 0007 assertion).
- Per run the executor sends a fresh nonce; a fixed read-only script
  returns a TPM quote over the boot PCRs and PCR 10 plus the UEFI event
  log and the IMA measurement list. The executor verifies the quote
  signature and replays both logs against the quoted PCRs. Every IMA entry
  is then compared against the I2 references (D7).
- **What it adds.** A root attacker who replaces a measured binary cannot
  remove its measurement from the TPM's extend-only PCRs; lying about it
  makes the replay fail. That is the guarantee I1 and I2 cannot give.
- **I3 limits.** Only what the IMA policy measures, and only at load:
  a memory-only exploit after measurement is not seen. A vTPM is only as
  trustworthy as the PVE host that provides it. Physical attacks on the
  TPM bus, firmware bugs and an IMA policy the attacker can change before
  it is locked are out of scope. IMA must be enabled with a kernel command
  line change and reboot on each host, which NOS will not do on its own.
- **Dependencies.** Quote and event-log parsing would need
  `github.com/google/go-tpm` or similar: a new module, Q5.

I3 needs its own ADR before any implementation; this section only fixes
the direction.

## Non-goals

- A persistent agent, inotify/fanotify watcher, auditd configuration or
  eBPF sensor on managed hosts.
- Automatic restore, reinstall, rollback or quarantine actions. Q3 asks
  only about *withholding* NOS authority.
- Proving the absence of a rootkit with I1 or I2.
- Integrity of databases, logs and spools (covered elsewhere).
- Containers and LXC guests as separate subjects (a managed guest is its
  own host); Docker image layers.
- Windows, network devices (ADR 0010).

## Open questions for the maintainer

- **Q1: Scope of paths and exceptions.** Is `fim-default-v1` (D5) the
  right default? Include `/etc/pve` (cluster-wide, changes on every node
  at once) and `/var/lib/docker` metadata? Is the plain-hash allowlist
  and the keyed hash for everything else (D6) acceptable? May admins add
  per-host roots or excludes, and must such a profile change be approved
  like a grant?
  **Recommendation:** ship `fim-default-v1` as listed; `/etc/pve` out of
  scope in I2 (it is better watched once per PVE cluster later);
  keyed hash outside the plain-hash allowlist (D6, recommended over the
  earlier metadata-only idea because it still detects content changes);
  per-host excludes allowed only as an
  approved profile variant (grant digest covers it), additional roots
  only from a fixed list.
- **Q2: Intervals.** I1 every 60 minutes plus start/upgrade? I2
  incremental hourly, full weekly? **Recommendation:** I1 at start, after
  upgrade and every 60 minutes; I2 incremental every 6 hours and full
  weekly by default (hourly incremental on hosts the admin marks as crown
  jewels, ADR 0011 D10), all within the ADR 0007 ordinary read budget.
- **Q3: Reaction on an I2 finding.** Only alarm, or also a host
  quarantine that blocks new NOS jobs (except reads and the job that
  investigates) until the admin acknowledges it? **Recommendation:**
  alarm only by default; an opt-in per host "block mutations on open
  critical integrity finding" that withholds new permits (never cancels a
  running job, never touches the host). A block that an untrusted host
  can trigger must not stop the admin from fixing it, so admin override
  with a fresh assertion is always possible. Also: in standard mode, may
  the *verified* expected changes of one job (except critical-class
  paths, D9) be approved in one bulk D7 assertion offered right after the
  job (recommended), or must they be reviewed in smaller batches? In
  every mode they enter the baseline only through an executor-computed
  digest (D7, D9), never through the job approval; unverified changes and
  critical-class paths follow D9 and are not part of this question.
- **Q4: I1 lock on mismatch.** Should the executor refuse unlock and all
  dispatch on a binary/unit/module mismatch (D4)? On a configuration
  mismatch? **Recommendation:** yes for binaries, units, built-in modules
  and root keys (cleared only by local CLI); no lock for configuration
  (alarm and baseline approval); web assets are refused individually
  rather than locking the whole system.
- **Q5: I3 yes or no.** Plan measured boot/IMA attestation, including a
  new TPM library dependency? **Recommendation:** yes as a later,
  separate ADR after I2 is in use, starting with physical hosts with a
  TPM and the NOS machine itself; vTPM guests only with the stated limit.
- **Q6: Package reference builder and dependencies.** Where does it run,
  and which modules may it use (D8)? **Recommendation:** on the
  `nebula-vuln-agent` host, extending the ADR 0011 A1.6 approval of
  `github.com/ProtonMail/go-crypto` to `InRelease` verification and
  approving one xz and one zstd decompression module for that binary
  only; until then, package files use the baseline mode.

## Required specification changes (IG-01)

- Spec 01: integrity monitoring as a bounded monitoring exception next to
  ADR 0011; restate that findings are advisory.
- Spec 05/06: I1 unlock refusal and `nebula integrity ack` (if Q4 is
  accepted); baseline approval challenge domains and what they bind
  (host ID, previous and new digest); `nebula integrity pending` and
  `nebula integrity approve` (rendering and approving exactly the
  executor-stored proposal bound to the digest, with the previous-digest
  check) as the only approval path for critical-class entries, and
  `nebula integrity approve --initial` for the first baseline (D7); the
  rule by which an approval replaces the stored derived SSH set (D7).
- Spec 07: `fim.scan` in the read-lease allowlist with its intervals and
  budgets.
- Spec 09: `fim-scan-v1` schema, the action-specific limits of D6, path
  encoding and display rules, reference-builder input limits and the
  `nebula-fim-reference-v1` schema (D8).
- Spec 10 or 06: the pinned builder key, `nebula integrity
  trust-builder` and the `nebula-fim-reference` signature namespace
  (D8).
- Spec 10: mandatory `installed-files.json` artifact and its schema;
  `release-manifest.json`, its signature and `installed-files.json` as
  assets of every GitHub release, with GitHub named as distribution
  channel only (D2); the `fim.scan` read-only action contract.
- Spec 14: reproducible-build acceptance criteria (D2, IG-11).
- Spec 13: `integrity.*` notification events.
- Spec 15: upgrade step 4 "self-check" is the I1 check against the
  admitted installed-files list; every update bundle carries the signed
  manifest, its signature and `installed-files.json` (offline case, D2).

## Ticket plan (sketch only)

| Ticket | Content | Depends on |
| --- | --- | --- |
| IG-01 | Spec revision listed above | maintainer answers Q1–Q4 |
| IG-02 | `installed-files.json` in release tooling and `docs/admin/release-signing.md`; publication of manifest, signature and list as GitHub release assets; parser and verifier with fuzz tests; executor admission next to `trust-builtins` | IG-01 |
| IG-03 | I1 checks in all NOS processes, executor cross-check, server check of executor; `integrity_findings` store | IG-02 |
| IG-04 | I1 reaction (unlock refusal per Q4), `nebula integrity ack` and `verify --offline`, `nebula verify` from an admin machine (D2), configuration baseline approval | IG-03 |
| IG-05 | `fim.scan` script, read-only contract, `fim-scan-v1` parser with fuzz tests and limits | IG-01 |
| IG-06 | Host baseline store, executor-held digest, baseline approval UI, `nebula integrity pending`/`approve` for critical-class entries | IG-05 |
| IG-07 | Incremental/full logic and expected-change attribution from NOS jobs | IG-06 |
| IG-08 | Findings UI and `integrity.*` notifications | IG-03, IG-06 |
| IG-09 | Package reference builder, reference signing, executor admission against the pinned builder key, archive comparison | Q6 |
| IG-10 | I3 ADR | Q5 |
| IG-11 | Reproducible builds: pinned release toolchain, deterministic packaging, CI rebuild comparison against `installed-files.json` (D2; touches protected build and CI files) | IG-02 |

## Consequences

- NOS can tell the admin whether its own installed code still matches a
  YubiKey-signed release, and whether watched files on managed hosts
  changed without a NOS job explaining it. The signed target hashes of
  every version are public on GitHub, so an admin can also check from a
  separate machine (`nebula verify`).
- The guarantee is deliberately modest and stated everywhere it is
  shown: I1 and I2 catch mistakes and ordinary attackers, not a root
  attacker who tampers with the checker. A hardware-backed answer needs
  I3.
- Release tooling gains one artifact; the executor gains one more trusted
  reference; the server gains a large but bounded per-host baseline store
  (about 300,000 records per host at most).
- Package-file verification against signed archives depends on Q6;
  without it, package files fall back to trust-on-first-scan baselines,
  and every package file a NOS apt job changes is an unverified finding
  the admin reviews separately from the job.
