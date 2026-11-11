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
| Compromised `nebula-server` | Executor detects server-binary changes (different UID, server cannot write executor storage); a compromised server can still suppress the *display* of I2 findings | Server can hide findings from the UI; it cannot silently rewrite an approved baseline (D7) | Quotes are verified by the executor, not the server |
| Compromised `nebula-server` or D8 reference builder supplying false package references | n/a (I1 uses the YubiKey-signed list, D2) | **Not detected as such**: it can make an attacker's file match a "verified" reference, so the change is labelled expected (info) or "package updated outside NOS" (medium) instead of critical; it cannot put the file into a baseline without the admin's executor-bound assertion (D7, D9), but an admin who approves trusts the label (see "Honest limits") | IMA entries are compared against the same references (D10); same limit |

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
  `authorized_keys*` (so shell start files such as `~/.bashrc`,
  `~/.profile` and per-user systemd units under `~/.config/systemd/`),
  `authorized_keys` of service accounts whose home is under `/var`,
  `/srv` or `/opt` outside the scanned `/opt` tree, `at` job spools,
  `/tmp`, `/dev/shm`, `/run`, `/etc/pve` (Q1), container images and
  volumes. Persistence placed there is not seen by I2.
- **Other file systems.** `find -xdev` does not descend into a separate
  mount below a root, for example the `/boot/efi` vfat partition with
  the shim and GRUB EFI binaries. Until IG-05 adds such mounts as explicit
  roots, a skipped mount below a root is reported and makes the run
  partial; it is never silently treated as covered.
- **Between scans.** A change that is reverted before the next scan is
  missed (threat model).
- **The checker's own references on the NOS machine.** Root on the NOS
  machine can rewrite the executor's admitted list and baseline digest
  and the approved configuration baseline with ordinary tools, so the
  threat-table row "root attacker with ordinary tools" assumes the
  attacker does not also edit those; only the offline check (D4) is
  independent of the NOS machine.
- **Trust on first scan.** The first complete scan of a host becomes its
  proposed baseline (D7); a host that was already compromised then is
  baselined as compromised.
- **Trust in the reference builder and the server for "verified".**
  Package references are built on the D8 builder host and reach NOS
  through the server; the executor cannot re-derive them (D8). A
  compromised builder or server can make an attacker's file match a
  "verified" reference, so the change is shown as an expected change
  (info) or "package updated outside NOS" (medium) rather than as a
  critical mismatch. It cannot put the file into a baseline: every
  baseline entry, expected or not, needs the admin's assertion over an
  executor-computed digest (D7, D9), and critical-class paths need one
  assertion each (D9). An admin who approves an entry labelled
  "verified" still trusts the builder and the server for that label.
- **Anything not a file.** Running processes, loaded kernel modules,
  memory-only implants, firmware and BIOS/UEFI settings (only I3 sees
  part of this).

## Decisions

### D1: Three stages

| Stage | Scope | Trust anchor | Status in this ADR |
| --- | --- | --- | --- |
| **I1** | NOS's own binaries, systemd units, built-in module files, web assets and configuration on the NOS machine | YubiKey-signed release manifest (code) and an admin-approved baseline (configuration) | Proposed for implementation |
| **I2** | Selected paths on managed Debian, Ubuntu and PVE hosts, read agentlessly over SSH | Signed distribution archive indices (package files) and a NOS-held, admin-approved baseline (everything else) | Proposed for implementation |
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
  covered: databases, logs, spools, runtime directories and caches, which
  change by design; their integrity is the job of `PRAGMA integrity_check`,
  backups (spec 15) and the audit log.

### D3: I1 reference for NOS configuration: an admin-approved baseline

Configuration (`/etc/nebula/*`, admin-created unit drop-ins under
`/etc/systemd/system/nebula-*.service.d/`, the iconfetch nftables file if
locally edited) changes legitimately and has no release reference.

- The baseline is a list of `(path, type, size, mode, owner, SHA-256)`.
- It is **approved like a read grant** (ADR 0007): the executor shows the
  full list with old and new values, the admin approves its digest with a
  fresh user-verified assertion in its own challenge domain
  (`nebula-integrity-baseline-v1`, nonce, five-minute expiry, single use),
  or with the executor-local CLI in hardened mode. Recovery mode cannot
  approve a baseline.
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
| SSH access | `/root/.ssh/authorized_keys*`, `/home/*/.ssh/authorized_keys*`, plus any path named by an `AuthorizedKeysFile` directive found in `/etc/ssh/sshd_config` and its includes, limited to the roots above and `/home/*/` |
| Scheduled jobs | `/etc/crontab`, `/etc/cron.*/`, `/var/spool/cron/crontabs/`, systemd timers (covered by the unit roots) |

Excluded by default: `/etc/pve` (pmxcfs cluster file system, a separate
mount skipped by `-xdev`; Q1), `/usr/lib/python3*/__pycache__`,
`/usr/local/lib/python3*/**/__pycache__`,
`/etc/ld.so.cache`, `/usr/lib/modules/*/modules.*` index files and other
generated caches named in the profile; `/run`, `/proc`, `/sys`, `/tmp`,
`/var` except the crontab spool.

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

  A run cut at any limit, a non-zero exit, a skipped root, an unreadable
  file or an invalid record is **partial**: it may open findings but never
  closes one and never proves that a file is unchanged or absent.
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

A file is compared against exactly one reference, chosen by NOS, not by
the host:

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
     as "version changed outside NOS" when no NOS job explains it. A job
     explains a version only under the D9 rule: the version the executor
     requested, never a lower or equal one, so a downgrade is never an
     expected change.
   - **Conffiles and generated files.** Package conffiles under `/etc`
     and files that maintainer scripts generate (initramfs, alternatives,
     diversions) are compared against the NOS baseline (2.), with the
     package default shown as context.
2. **Everything else against a NOS-held baseline.** Non-package files,
   files from unconfigured archives or local `.deb`s, conffiles and all
   metadata (mode, owner, symlink target, presence) are compared against a
   per-host baseline that **exists only on NOS**: the full record list in
   the server database and, as tamper evidence, its digest in executor
   storage.
   - **Initial baseline.** The first complete scan becomes a *proposed*
     baseline. It is labelled "trust on first scan": NOS cannot know
     whether the host was already compromised; the admin is told so and
     package files are still checked against the archive from day one.
   - **Approval.** The admin approves a baseline (initial or updated) by
     digest, with the same assertion as D3 (challenge domain
     `nebula-fim-baseline-v1`). Bulk approval per host and per finding
     batch is allowed; every approved entry is audited with old and new
     values.
   - **The executor alone decides what goes into a baseline.** The
     digest the admin approves is computed by the executor, never taken
     from the server:
     - The executor parses each `fim.scan` result it received over its
       own SSH session (D5) and keeps the validated records of the latest
       complete run per host in executor-owned storage until the next
       complete run replaces them or a baseline is approved from them.
     - A proposed baseline is built by the executor as: the currently
       approved list (fetched from the server and accepted only if its
       digest equals the executor-stored digest; otherwise an
       `integrity.baseline_tamper` finding and no approval) plus, for
       the paths the admin selects, the record values from the executor's
       own retained run. The server only names paths to include; it
       cannot supply record values, a list or a digest that the executor
       would approve.
     - The approval screen is rendered from the executor's data, and the
       assertion binds the executor-computed digest. A server-supplied
       proposed list or digest is at most compared with it; a mismatch is
       a baseline tamper finding, never a reason to approve.

     This stops a compromised server from injecting entries; it does not
     protect against a host that was already compromised at its first
     scan ("trust on first scan" above).
   - **Server compromise.** A compromised server could display a forged
     baseline or hide findings; it cannot make the executor's stored
     digest match a rewritten list. On every scan and after any NOS
     restore, the executor recomputes the digest of the server's list and
     opens an I1 finding on mismatch.

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
- **What NOS receives.** Per `(package, version, arch, deb SHA-256)` a
  bounded list `(path, type, size, mode, uid, gid, sha256, link)` taken
  from the `data.tar.*` headers and contents, posted through a
  new write scope on `/api/v1`. This is **untrusted input** under spec 09
  (strict schema, limits: 20,000 files and 4 MiB per package, path rules as
  D6). NOS cannot re-derive these hashes itself: the reference is as
  trustworthy as the builder host plus the archive signatures. A
  compromised builder could whitelist a modified file; it cannot change a
  host and cannot authorize anything.
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
  Only a complete full run can close a finding.

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

- it is an open finding of severity **high** (D9 table), never
  info-level and never `expected_pending`;
- it is **never approved together with the job**, in any mode (Q3 does
  not apply to it); the admin approves it only through a separate
  baseline approval (D7) whose screen labels every such entry
  "unverified: NOS cannot tell this change from an attacker's change made
  during the job". Batch approval of the unverified entries of one job is
  allowed, but the batch is its own assertion and never part of the job
  approval;
- host-side evidence does **not** make it verified:
  `/var/lib/dpkg/info/*.md5sums`, `debsums` and `dpkg --verify` are
  controlled by the same root that could have replaced the file, and
  MD5 is broken (D7). Only the signed-archive chain of D7 item 1 counts as
  a verified reference.

Consequently, before Q6 every package file changed by a NOS apt job is an
unverified finding the admin must review; this is the deliberate price of
keeping the next sentence true.

**"Expected" is a label, never an approval.** An expected change is
recorded as `expected_pending` and shown as "changed by NOS job <id>,
matches verified reference". It enters the baseline **only through a D7
baseline approval, in every mode**: the executor builds the proposed
entries from its own retained post-job scan (D7 "The executor alone
decides"), computes the digest, and the admin approves exactly that
digest with the `nebula-fim-baseline-v1` assertion. The job approval
never covers baseline entries: it is given before the job and cannot bind
a scan result, and the "verified" label rests on a D8 reference that
reaches NOS through the server and that the executor cannot re-derive
(D8). A compromised server or builder can therefore make an attacker's
file *look* expected (and lower its severity to info), but it cannot put
that file into a baseline without the admin's executor-bound assertion;
the approval screen says that the "verified" label comes from the
reference builder (see "Honest limits"). Anything else changed in the same window, and every unverified
change, is a finding: an attacker cannot hide behind a running apt job,
because a replaced `/usr/sbin/sshd` during an approved `openssh-server`
upgrade either fails the verified reference or has none, and both are
findings the admin sees separately from the job. Package updates done on the
host outside NOS (for example unattended-upgrades) whose new hashes match
the signed archive reference are low-severity findings ("package updated
outside NOS"), not alarms.

**Findings.** A new store `integrity_findings` (not the ADR 0011 store,
whose observer is always Hermes): subject (NOS machine or host ID), path
(raw bytes plus escaped display form), class, old and new record, first
and last seen, state (`open`, `expected_pending`, `accepted`,
`resolved`), and the run IDs that opened and closed it. Retention and
dedupe follow ADR 0011 D6/D9 patterns. Severity by class:

| Class | Severity |
| --- | --- |
| Package file differs from signed reference; NOS binary/unit mismatch (I1); new or changed `authorized_keys`, `sudoers`, PAM, `sshd_config`, `ld.so.preload`, systemd unit or timer, crontab, `/boot` file; new setuid/setgid file; new file in `/usr/local/bin` or `/usr/local/sbin` whose name shadows a command in `/usr/bin` or `/usr/sbin`; missing NOS own key or extra key in root's `authorized_keys` | critical |
| Other changed or new file in `/etc`, `/usr`; owner/mode change; I2 baseline digest mismatch; change during a NOS job without a verified reference ("changed during NOS job, unverified") | high |
| Package updated outside NOS with matching reference; partial or stale scan | medium |
| Expected change from a NOS job | info (record only) |

**Notifications** go through the existing webhook, ntfy and Telegram
senders (ADR 0011 D9 pattern): events `integrity.nos_mismatch`,
`integrity.host_change`, `integrity.scan_incomplete`,
`integrity.baseline_tamper`. Messages carry **structured fields only**:
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
  accepted); baseline approval challenge domains.
- Spec 07: `fim.scan` in the read-lease allowlist with its intervals and
  budgets.
- Spec 09: `fim-scan-v1` schema, the action-specific limits of D6, path
  encoding and display rules, reference-builder input limits (D8).
- Spec 10: mandatory `installed-files.json` artifact and its schema; the
  `fim.scan` read-only action contract.
- Spec 13: `integrity.*` notification events.
- Spec 15: upgrade step 4 "self-check" is the I1 check against the
  admitted installed-files list.

## Ticket plan (sketch only)

| Ticket | Content | Depends on |
| --- | --- | --- |
| IG-01 | Spec revision listed above | maintainer answers Q1–Q4 |
| IG-02 | `installed-files.json` in release tooling; parser and verifier with fuzz tests; executor admission next to `trust-builtins` | IG-01 |
| IG-03 | I1 checks in all NOS processes, executor cross-check, server check of executor; `integrity_findings` store | IG-02 |
| IG-04 | I1 reaction (unlock refusal per Q4), `nebula integrity ack` and `verify --offline`, configuration baseline approval | IG-03 |
| IG-05 | `fim.scan` script, read-only contract, `fim-scan-v1` parser with fuzz tests and limits | IG-01 |
| IG-06 | Host baseline store, executor-held digest, baseline approval UI | IG-05 |
| IG-07 | Incremental/full logic and expected-change attribution from NOS jobs | IG-06 |
| IG-08 | Findings UI and `integrity.*` notifications | IG-03, IG-06 |
| IG-09 | Package reference builder and archive comparison | Q6 |
| IG-10 | I3 ADR | Q5 |

## Consequences

- NOS can tell the admin whether its own installed code still matches a
  YubiKey-signed release, and whether watched files on managed hosts
  changed without a NOS job explaining it.
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
