# ADR 0008: Guest provisioning from deploy profiles

Status: proposed (draft by Claude for maintainer review), 2026-11-01; open questions decided by the maintainer 2026-11-02; amendment 1 (preset guest host key) after the maintainer decision of 2026-11-03, written by Claude, awaiting maintainer acceptance

## Context

The maintainer wants to deploy new VMs from Nebula Ops onto a chosen Proxmox
remote and node: pick an OS and a size, set hostname, IP and optionally a
password, tick which bootstrap components the new host should get, attach
install scripts, save the combination as a reusable template, and have the
VM join Nebula Ops without manual steps.

[ADR 0006](0006-proxmox-integration.md) already names provisioning as a
phase-3 capability: "Provisioning binds template, destination, new VMID, IPAM
reservation and configuration, then follows normal SSH enrollment." It gives
no design, and phase 3 as written waits for all of phase 2 (lifecycle
buttons, tree updates, container recreate). Provisioning needs much less: the
phase-2 action token, one exact-target mutation path and UPID reconciliation.

The building blocks exist:

- **Read side:** PVE remotes with pinned trust and typed reads (ADR 0006
  phase 1, `internal/pveapi`, `internal/executor/pve_read.go`).
- **Action token:** the token purpose `action` in the executor registry
  (`PvePurposeAction`).
- **Network and enrollment:**
  - IPAM pools and reservations (`internal/ipam`, status `RESERVED`);
  - host enrollment with host-key pinning and fingerprint review (spec 16
    item 3).
- **Install scripts:**
  - runbooks: versioned local scripts with parameters, secret parameters,
    declared risk and pre/postchecks (spec 10);
  - the bootstrap module slot (spec 10, spec 14 `modules/bootstrap`).
- **Approvals:** batch approval and staged execution (ADR 0007, spec 07,
  `internal/executions/stages.go`).
- **Prior art:** the Ubuntu Server Bootstrap Toolkit outside the repository.
  Its modules (user, SSH hardening, hostname, timezone, Netplan, guest agent,
  packages, Docker, NetBird, fail2ban+ufw, Telegraf, package report) are the
  functional model for the bootstrap module set.

## Decision

Provisioning becomes its own track, milestone `pve-provision`. It is a
separate product area ("Deploy"), not a button set inside the org chart.
It pulls the provisioning part of ADR 0006 phase 3 forward. It depends only
on a minimal phase-2 mutation foundation, not on the rest of phase 2.

### 1. Deploy profiles ("templates")

- A deploy profile is a server-side, versioned, secret-free document:
  - OS image: a reference into the image catalog, section 2;
  - size;
  - disk storage class;
  - network: bridge, VLAN, and an IPAM pool or DHCP;
  - DNS;
  - an ordered bootstrap selection, section 5, with parameters;
  - an ordered list of runbook references (install scripts) with
    parameters.
- **Size presets:**
  - S = 1 vCPU / 1 GiB / 16 GiB;
  - M = 2 / 4 GiB / 32 GiB;
  - L = 4 / 8 GiB / 64 GiB;
  - XL = 8 / 16 GiB / 128 GiB;
  - custom values are bounded by the target node's read capacity and named
    limits.
- **Versions:** editing a profile creates a new version. A deployment
  records the exact profile version, each runbook artifact digest and the
  module versions it ran.
- **Secrets:** profiles never contain secret values, only references to
  executor vault entries, for example a NetBird setup key or a Telegraf
  token.

### 2. Image catalog and template preparation

- **Catalog:** NOS ships the image catalog as signed release data, reusing
  the E15 release-signing chain. Each entry has:
  - OS and release, e.g. Ubuntu 22.04/24.04, Debian 12/13;
  - architecture;
  - the vendor cloud-image URL;
  - SHA-256.

  An operator may add local catalog entries. Those carry trust "Local" and
  raise the preparation action to HIGH.
- **Preparation** is a one-time HIGH action per (remote, node, storage,
  image), action `pve.image.prepare`:
  - PVE `download-url` with the catalog checksum, so PVE verifies it;
  - create a VM from the imported disk with a cloud-init drive and
    `agent=1`;
  - convert it to a PVE template.
- The executor records the template's VMID, generation and source digest.
  Provisioning binds that record; a template changed outside NOS fails the
  binding.

### 3. Provision action

- **Action:** a typed executor action `pve.guest.provision`, using the
  action token only.
- **It binds exactly:**
  - remote, trust pin and generation;
  - node and storage;
  - template record;
  - new VMID, reserved atomically against the live guest list;
  - name/hostname, cores, memory, disk size, bridge/VLAN and MAC policy;
  - IPAM reservation or DHCP;
  - the cloud-init fields: `ciuser`, `sshkeys`, `ipconfig0`, `nameserver`,
    `searchdomain`;
  - start-after-create;
  - the digest of the complete configuration.
- **Steps:**
  1. full clone;
  2. allowlisted config set;
  3. disk resize;
  4. start.

  Each step stores its UPID before dispatch and reconciles on restart or
  lost response; nothing is ever redispatched blindly.
- **Risk:** base MEDIUM, never LOW (spec 11: LOW remains read-only). ADR 0008
  adds no automatic raise of its own: a production profile does not raise it,
  and neither does any other provisioning-specific condition (decision 2).
  The general rule of spec 11 ("PVE action profiles and risks": maximum of
  the floor, criticality and affected linked-host floors; unknown
  criticality HIGH) still applies, scored on the remote and node (and any
  recorded floor): the guest that provisioning creates does not exist yet,
  so its criticality does not count as unknown. Unset remote or node
  criticality is unknown and therefore HIGH, and a PVE node that is also a
  managed host defaults to HIGH (spec 11); out of the box provisioning is
  HIGH until the operator records criticality LOW or MEDIUM (spec 12) for the remote
  and the node in the executor registry and, when the node is also an
  enrolled host, for that linked host (it counts as affected, because the
  guest is created on it); then it is MEDIUM. Criticality is the operator's
  knob in both directions. A template
  prepared from a Local-trust entry does not raise provisioning either;
  only its preparation is HIGH. The allowlisted
  config set on the newly cloned guest is a step of `pve.guest.provision`
  and covered by its floor, not a separate configuration-change action.
  (Draft before: HIGH also on PCI passthrough or over-commit; the decision
  of 2026-11-02 first read "always LOW" and was corrected the same day
  because LOW is reserved for read-only actions.)
- **Failure:** a failed deployment leaves the guest for inspection. Deleting
  it is a separate HIGH action, never automatic.
- **Access and password:** cloud-init `sshkeys` always contains the NOS
  automation public key. An optional custom password is entered only on the
  executor side (CLI secret input, as for PVE tokens). It is stored in the
  vault, sent only as `cipassword` and never shown or logged. SSH-key-only
  access stays the default.

### 4. Join (enrollment)

- After first boot the executor enrolls the new guest as a managed host with
  the normal enrollment path.
- **Host-key pin:** the guest's SSH host key is pinned in one of two ways
  (amendment 1, 2026-11-03; previously: agent read first, fingerprint
  review as the fallback):
  - Preset key, where the remote and node offer it (amendment 1): the
    executor generates the guest's ed25519 host key pair, presets it at
    provision time through an operator-provisioned snippet storage and a
    per-guest `cicustom` vendor-data file, and pins the public key before
    first boot. No trust-on-first-use, no manual review, no guest-agent
    privilege. The preset key is rotated over the pinned channel as the
    first post-enrollment step.
  - Fingerprint review (the default whenever the preset path is not
    available, decision 1): the existing review, shown on the deployment
    page; the bootstrap module then installs `qemu-guest-agent`.
  - (Previously: agent read, when the image ships the QEMU guest agent,
    reading `/etc/ssh/ssh_host_ed25519_key.pub` through the agent over the
    pinned PVE channel. Not pursued: it needs a guest file read privilege
    that spec 06 forbids on the read token, and vendor cloud images do not
    ship the agent. The PV-06 code path stays without a credential and
    therefore always falls back.)
- **Linking:** the inventory host is linked to the PVE guest (remote, node,
  VMID, generation), so the org chart shows it as enrolled.

### 5. Bootstrap modules and install scripts

- **Bootstrap modules:** the toolkit's functions become first-party modules
  under `modules/bootstrap/`. Each one is idempotent with `install`,
  `verify`, `update` and `uninstall` (spec 10):
  - user;
  - ssh-hardening;
  - timezone;
  - packages;
  - qemu-guest-agent;
  - docker;
  - netbird;
  - firewall (fail2ban+ufw);
  - telegraf;
  - pkg-report.

  The profile's checkboxes are this module selection.
- **Install scripts are runbooks:**
  - versioned, digest-bound, risk declared by the runbook;
  - Local trust raises the risk as spec 10 defines;
  - there is no free-form command field (ADR 0007 forbids a generic command).
- **Order after enrollment:** bootstrap modules, then runbooks, as one frozen
  staged plan. It goes through one batch approval (ADR 0007), with stop on
  failure and per-step outcome.

### 6. User interface

- **Navigation:** "Deploy" is its own navigation entry with three pages:
  - profiles: list, edit, version history;
  - new deployment wizard;
  - deployment runs.
- **Org chart:** the node context menu offers "Deploy here" as a shortcut
  into the wizard with the remote and node preselected.
- **Wizard:**
  - target remote/node/storage;
  - profile, or an ad-hoc profile that can be saved as a new one;
  - size;
  - OS;
  - hostname;
  - IP from the IPAM pool (suggested free address), static or DHCP;
  - password option;
  - bootstrap checkboxes;
  - runbooks.
- **Review step:** shows the frozen plan with its effective risk before
  approval.
- **Run page:** shows the states:
  1. `proposed`
  2. `approved`
  3. `creating`
  4. `booting`
  5. `enrolling`, which may wait for a fingerprint review
  6. `bootstrapping`
  7. `done` or `failed`

  It also shows the PVE task links and the step outcomes.

## Consequences

- The PVE action token becomes required for remotes that allow
  provisioning. Read-only remotes stay read-only and the Deploy UI hides them.
- **Executor:** the first PVE mutations arrive in the executor. They need the
  minimal phase-2 foundation (exact-target mutation permit, UPID
  persistence, reconciliation), which later phase-2 actions reuse.
- **Untrusted input:** everything read back from the new guest stays
  untrusted, including agent output and the host-key file. It is
  size-limited and validated before use.
- **Allowlist:** no PVE write method outside the allowlist exists. `pveapi`
  write methods are typed (clone, config set of named fields, resize, start,
  download-url, template) with no URL or raw-path input.

## Decisions on the open questions (maintainer, 2026-11-02)

Questions 1–3 were open in the draft of 2026-11-01 and keep their question
and alternatives; 4 and 5 were already settled in the draft.

1. **Guest agent in cloud images:** the vendor Ubuntu/Debian cloud images do
   not ship `qemu-guest-agent`, and PVE's API cannot upload a cloud-init
   vendor snippet. Decided: (a) fingerprint review for the first enrollment,
   the bootstrap module installs the agent. (b) a snippet storage written
   once by the operator and referenced with `cicustom` may follow as an
   opt-in; (c) a NOS-prepared image is not planned. (Draft: (a) now, (b) as
   an opt-in.) Amendment 1 (2026-11-03) makes (b) the path for presetting
   the guest host key rather than for installing the agent; (a) stays the
   default wherever (b) is not set up.
2. **Risk of the provision action** (question: should a production-environment
   profile always be HIGH?): no. Base MEDIUM with no automatic raise from
   ADR 0008. Criticality still applies as in spec 11 "PVE action profiles
   and risks": unset criticality is HIGH, so the operator records the
   remote's and node's criticality to get MEDIUM (see section 3 above).
3. **VMID allocation** (next free VMID from the cluster, or operator-defined
   ranges per remote?): the next free VMID from the cluster.
4. **Windows and other OS families:** out of scope for this track.
5. **LXC containers:** provisioning containers from `vztmpl` templates is a
   natural follow-up with the same profile model; not in this track.

## Amendment 1 (2026-11-03): preset guest host key

Status: maintainer direction 2026-11-03; mechanism and threat model below
written by Claude, awaiting maintainer acceptance. Nothing here was tried
in a lab; every PVE and cloud-init behaviour marked *verify* is a release
gate (ticket PK-10).

### Context

Maintainer decision 2026-11-03: instead of reading the host key through the
guest agent, which needs a privilege spec 06 forbids on the read token,
the executor generates the guest's SSH host key pair and presets it at
provision time. The fingerprint is then pinned before first boot: no
trust-on-first-use, no manual review, no guest-agent privilege.

The constraint is delivery. PVE's API cannot upload cloud-init snippets
(upload accepts ISO images, container templates and import images only).
PVE's built-in cloud-init fields (`ciuser`, `cipassword`, `sshkeys`,
`ipconfig`, `nameserver`, `searchdomain`) carry authorized keys, not host
keys. Cloud-init itself can install a preset host key: the `cc_ssh` module
takes `ssh_keys: {ed25519_private, ed25519_public}` from user-data or
vendor-data.

### Delivery paths evaluated

| Path | Needs | Failure modes | Verdict |
| --- | --- | --- | --- |
| (i) Operator-provisioned snippet storage plus a per-guest `cicustom` vendor-data file that NOS writes on the node | Once, by the operator: a node-local `dir` storage with content `snippets`, recorded in the executor registry. Each time: the PVE node is an enrolled managed host (spec 16 item 3, ADR 0006 "node's ordinary NOS SSH enrollment") and a new typed SSH action writes or removes exactly one file in that directory. The action token gets the `cicustom` field under `VM.Config.Cloudinit` (already part of the configuration extension) and, *verify*, the volume access check on `/storage/<snippets>` (expected `Datastore.Audit`). No new broad PVE privilege; no guest privilege. | Node not enrolled, blocked or keyring locked; storage absent on the target node; HA or manual move to a node without the file before cleanup (PVE regenerates the cloud-init drive at start and refuses a missing volume, *verify*); image with vendor-data disabled; changing `cicustom` later changes the NoCloud instance-id (*verify*), so cloud-init would regenerate host keys on next boot unless told not to | **Chosen** |
| (ii) A generic, secret-free snippet that makes the guest fetch its key once from NOS over an authenticated one-time channel | A NOS endpoint the guest can reach: the executor has no network listener (spec 02) and the server must not hold secrets, so either rule would have to break. A per-guest one-time token still has to reach the guest through a PVE field (`smbios1`, `cipassword`), which is as exposed as the key itself. A network path from every new guest to NOS. | Guest network or DNS not ready at first boot; listener exposed to every guest network; token replay before the real guest fetches | Rejected: adds a network-facing secret endpoint and solves nothing that (i) leaves open |
| (iii-a) Per-guest NoCloud seed ISO (`cidata`) uploaded through the API and attached as a CD-ROM | `Datastore.AllocateTemplate` on a dedicated ISO storage, `VM.Config.CDROM`, a volume delete right (*verify*); NOS replaces PVE's cloud-init drive, so it must render user-data and network-config itself; an ISO9660 writer in Go without a new dependency | Any PVE user who can attach ISOs from that storage can read the key; two `cidata` sources when the template keeps its cloud-init drive; more generated format code | Not now; alternative for remotes whose nodes cannot be enrolled (open question 2) |
| (iii-b) Guest agent `file-write`, `args`/`fw_cfg`, SMBIOS strings | Guest file access (forbidden by spec 06); `args` is `root@pam` only; SMBIOS values sit in the VM config that every `VM.Audit` holder, including the read token, can read | — | Rejected |

### Decision

1. **Method bound in the permit.** At proposal time the executor decides
   the host-key method, `preset` or `review`, and binds it into the
   `pve.guest.provision` parameters, so the approver sees it. `preset` is
   offered only when the remote and node have a registered snippet storage,
   the node is an enrolled, unblocked host, and the profile does not opt
   out. Otherwise `review` (fingerprint review, decision 1) is bound. An
   approved method is never changed after approval.
2. **Key generation.** The executor generates an ed25519 key pair with
   `crypto/ed25519` and encodes it with `golang.org/x/crypto/ssh`
   (`MarshalPrivateKey`); no self-written cryptography. It persists only the
   public key and fingerprint (`executor.db`, with the provisioning job)
   and fsyncs before writing the snippet. The private key is never stored
   on the executor: not on disk, not in the vault, not in a result, log or
   audit line. It lives in executor memory only until the snippet write
   returns. Spec 06's rule that the vault holds no SSH keys is therefore
   unchanged.
3. **Snippet write.** A new typed SSH action on the node writes
   `nos-<remote>-<vmid>-<generation>.yaml` into the registered snippet
   directory. The content arrives on stdin (never argv), is written to a
   temporary file with mode 0600 owned by root and renamed into place; the
   directory must be a root-owned real directory, not a symlink. The
   result carries the path and the public fingerprint only. The
   vendor-data contains, and nothing else:
   - `ssh_keys` with the ed25519 pair;
   - `ssh_deletekeys: true` and `ssh_genkeytypes: []` for this first boot,
     so only the preset key exists;
   - a `write_files` drop-in `/etc/cloud/cloud.cfg.d/99-nebula-hostkey.cfg`
     with `ssh_deletekeys: false` and `ssh_genkeytypes: []`, so a later
     instance-id change never regenerates the pinned key.

   PVE keeps generating user-data (`ciuser`, `sshkeys`, `cipassword`) and
   network-config; only the vendor part is custom (*verify* the merge on
   each supported image).
4. **Steps.** `pve.guest.provision` with `preset` becomes: generate and
   persist the public key, write the snippet, full clone, allowlisted config
   set including `cicustom: vendor=<storage>:snippets/<file>`, resize,
   start. It stays one frozen plan with one approval, binding both the PVE
   target and the node's SSH host ID and pinned fingerprint. The node
   already counts as an affected host (section 3), so the risk is
   unchanged. A lost snippet write is reconciled by generating a new pair
   and writing again; that is allowed only while the start step has not
   been dispatched. After start the key is fixed.
5. **Join.** With `preset` bound, enrollment pins the recorded public key
   and connects. If the endpoint presents another key, the join stops with a
   key mismatch. It does **not** fall back to fingerprint review on its
   own, because that would let an attacker turn a preset into trust on
   first use. The operator may start an explicit review enrollment, which
   shows "preset key not presented" and is HIGH like every enrollment.
6. **Rotation.** The first step of the post-enrollment plan (section 5),
   before any secret-bearing module or runbook, is a reserved action
   `nebula.host_key.rotate`. Over the session authenticated with the
   preset key, the guest generates a new ed25519 key and returns its
   public key (untrusted input, validated). The executor re-pins old → new
   in one transaction and proves the new pin with a fresh connection. This
   re-pin needs no fingerprint comparison: the new key is learned over the
   channel already bound to the pinned key. It needs a spec 08 revision
   (PK-00). Until rotation succeeds, the host carries "bootstrap key not
   rotated" and secret-bearing steps are refused.
7. **Cleanup.** After rotation the executor removes `cicustom` from the
   guest config (a new typed delete of that one field) and removes the
   snippet with the node action. Both are audited. A failed provisioning
   leaves guest and snippet for inspection (section 3). Removing the
   snippet of an abandoned provisioning is an explicit operator action.
8. **Audit.** Executor events `guest_hostkey_generated`,
   `guest_hostkey_snippet_written`, `guest_hostkey_pinned`,
   `guest_hostkey_rotated` and `guest_hostkey_snippet_removed` carry
   execution, remote, node, VMID, generation, path and fingerprints, never
   key material.
9. **Fallback.** Fingerprint review stays the default whenever the preset
   path is unavailable or opted out. The agent-read code path of PV-06 gets
   no production credential.

### Threat model of the preset private key

The preset key is a bootstrap credential. Whoever holds it before rotation
can impersonate the guest to NOS: they could run a man in the middle on the
first sessions and see the commands NOS sends, including secret runbook
parameters. That is why rotation comes before every secret-bearing step.
After rotation, every leftover copy is worthless.

| Where | When | Who can read it | Mitigation |
| --- | --- | --- | --- |
| Executor memory | From generation until the snippet write returns | Executor process (already holds every SSH key) | Never persisted; same "stated limit" as spec 06 |
| SSH channel to the node | Snippet write | Nobody outside the pinned, authenticated node session | stdin, not argv (not visible in `ps`) |
| Snippet file on the node | Until cleanup (minutes after first boot) | Root on that node; admins of the storage if it were shared; node filesystem backups | Node-local `dir` storage only, never shared NFS/CephFS (registry refuses shared storage types); mode 0600; prompt cleanup; rotation |
| Generated cloud-init drive (`vm-<vmid>-cloudinit`) on VM storage | Until the next regeneration after cleanup | Root on the node, storage admins; PVE users able to attach that volume elsewhere (*verify* ACL) | Rotation; vzdump skips cloud-init drives (*verify*) |
| Guest: `/etc/ssh`, `/var/lib/cloud/instance/vendor-data.txt*`, CD-ROM device | Until rotation; the cache until a later cleanup module | Guest root; members of group `cdrom` while the drive is attached (the Ubuntu default user is one, and is a sudoer anyway) | Rotation; bootstrap removes the cached vendor-data |
| PVE config, `/etc/pve`, config reads, read-token spool | Always | Only the `cicustom` reference, no key material | — |
| PVE backups | Guest disk backups hold the *current* host key, as for every VM today | Backup operators | Not new; after rotation the preset key in backups is worthless |

PVE administrators and node root are not new readers in substance: they
already control the guest (console, disks, snapshots) and could take over
any VM. The readers this design adds are storage admins of a shared
snippet store and node backup operators. They are excluded by node-local
storage and made irrelevant by rotation.

**Comparison.**

- Fingerprint review: nothing secret at rest. But in practice it is trust
  on first use unless the operator really compares on the console, and it
  is a manual step on every deployment.
- Scoped guest-agent token, option (a): needs `VM.GuestAgent.FileRead`
  (PVE 9) or the much broader `VM.Monitor` (PVE 8). Either lets the
  credential read any guest file as root, `/etc/shadow` and secrets
  included. Spec 06 excludes guest file access from both tokens. Vendor
  images do not ship the agent, so it would only work after the bootstrap
  it is supposed to protect.
- Preset key: no TOFU, no manual step, no guest privilege. The cost is a
  short-lived secret on the hypervisor that is no more exposed than the
  guest itself, an enrolled node and one operator-provisioned storage.

### Open questions for the maintainer

1. Writing files on the PVE node through its SSH enrollment is new
   authority on the node: a typed action limited to one directory and one
   name pattern. Is that acceptable, or must the snippet directory belong
   to an unprivileged account (for example group-writable for `nebula`)?
2. Remotes whose nodes are not enrolled: stay on review, or later add
   (iii-a), the per-guest seed ISO, with `Datastore.AllocateTemplate` on a
   dedicated storage?
3. Rotation: is `nebula.host_key.rotate` acceptable as a spec 08 revision
   (re-pin learned over the pinned channel, no console comparison)?

## Tickets (milestone `pve-provision`)

| Ticket | Scope | Depends on |
| --- | --- | --- |
| PV-00 | This ADR accepted; spec revision for spec 07/10/11/12 (spec 11: PVE action rows for `pve.guest.provision` MEDIUM and `pve.image.prepare` HIGH) | — |
| PV-01 | Minimal phase-2 mutation foundation: action-token use, exact-target mutation permit, UPID persistence and reconciliation (executor, executordb, permit; protected) | PV-00 |
| PV-02 | `pveapi` typed write methods: clone, allowlisted config set, resize, start, download-url, template conversion, task status; httptest only | PV-00 |
| PV-03 | Signed image catalog and `pve.image.prepare` | PV-01, PV-02 |
| PV-04 | Deploy profiles: server model, validation, versioning, UI CRUD (no secrets) | PV-00 |
| PV-05 | `pve.guest.provision`: VMID reservation, IPAM reservation, cloud-init, executor-side password, risk, approval, start | PV-01, PV-02, PV-04 |
| PV-06 | Join: inventory host creation, enrollment with agent-read pin or fingerprint review, guest link | PV-05 |
| PV-07 | First-party bootstrap modules from the toolkit, secrets via vault references | PV-00 |
| PV-08 | Deploy wizard, run page, post-enrollment staged bootstrap/runbook plan with batch approval | PV-05, PV-06, PV-07 |
| PK-00 … PK-10 | Amendment 1, preset guest host key: see [docs/implementation/preset-host-key.md](../implementation/preset-host-key.md) | PV-05, PV-06 |
