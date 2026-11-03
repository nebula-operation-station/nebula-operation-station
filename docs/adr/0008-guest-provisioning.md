# ADR 0008: Guest provisioning from deploy profiles

Status: proposed (draft by Claude for maintainer review), 2026-11-01; open questions decided by the maintainer 2026-11-02; amendment 1 (preset guest host key) after the maintainer decision of 2026-11-03, written by Claude, status Proposed pending a lab check of PVE's cloud-init dump endpoint (previously: awaiting maintainer acceptance)

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
  - Preset key, where the remote and node offer it (amendment 1,
    Proposed, not yet accepted; conditional on a lab check and on
    mitigations M1/M2 there): the executor generates the guest's ed25519
    host key pair, presets it at provision time through an
    operator-provisioned snippet storage and a per-guest `cicustom`
    vendor-data file, and pins the public key before first boot. No
    trust-on-first-use, no manual review, no guest-agent privilege. The
    preset key is rotated over the pinned channel as the first
    post-enrollment step; rotation limits later use of leftover copies but
    cannot undo a theft before the join.
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
   an opt-in.) Amendment 1 (2026-11-03, Proposed) would make (b) the path for
   presetting the guest host key rather than for installing the agent; (a)
   stays the default wherever (b) is not set up or not accepted.
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

Status: **Proposed, not accepted** (revised 2026-11-03 after review; previously
"maintainer direction, awaiting acceptance"). The maintainer chose to preset
the guest host key (option c) over a scoped guest-agent token (option a) and
over widening the read token (option b). Review then found that the preset
private key is probably readable by every `VM.Audit` holder through PVE's
cloud-init dump endpoint (see "Exposure through the PVE API" below). Until
the lab check PK-10a answers that, the decision is recorded as **"(c)
accepted only with mitigations M1 and M2 together, lab check required"**
(previously "M1 or M2"; M1 alone is not sufficient, see the variants).
(c) is not viable whenever M1 or M2 cannot hold, including M1 failing or an
endpoint M1/M2 do not cover (previously "if they cannot both hold"); the
options are then listed under "If the lab check fails". Mechanism and threat model written by
Claude. Nothing here was tried in a lab; every PVE and cloud-init behaviour
marked *verify* is a release gate (ticket PK-10).

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
| (i) Operator-provisioned snippet storage plus a per-guest `cicustom` vendor-data file that NOS writes on the node | Once, by the operator: a node-local `dir` storage with content `snippets`, recorded in the executor registry. Each time: the PVE node is an enrolled managed host (spec 16 item 3, ADR 0006 "node's ordinary NOS SSH enrollment") and a new typed SSH action writes or removes exactly one file in that directory. The action token gets the `cicustom` field under `VM.Config.Cloudinit` (already part of the configuration extension) and, *verify*, the volume access check on `/storage/<snippets>` (expected `Datastore.Audit`). No new broad PVE privilege; no guest privilege. | Node not enrolled, blocked or keyring locked; storage absent on the target node; HA or manual move to a node without the file before cleanup (PVE regenerates the cloud-init drive at start and refuses a missing volume, *verify*); image with vendor-data disabled; changing `cicustom` later changes the NoCloud instance-id (*verify*); **the rendered vendor-data is probably readable by every `VM.Audit` holder through `cloudinit/dump` until cleanup (*verify*, PK-10a)** | Chosen, conditional on M1 and M2 together |
| (ii) A generic, secret-free snippet that makes the guest fetch its key once from NOS over an authenticated one-time channel | A NOS endpoint the guest can reach: the executor has no network listener (spec 02) and the server must not hold secrets, so either rule would have to break. A per-guest one-time token still has to reach the guest through a PVE field or snippet, which is as exposed as the key itself. A network path from every new guest to NOS. | Guest network or DNS not ready at first boot; listener exposed to every guest network; token theft before the real guest fetches (see variant V3 below for what one-time use does and does not buy) | Rejected: adds a network-facing endpoint and does not remove the exposure of (i) |
| (iii-a) Per-guest NoCloud seed ISO (`cidata`) uploaded through the API and attached as a CD-ROM | `Datastore.AllocateTemplate` on a dedicated ISO storage, `VM.Config.CDROM`, a volume delete right (*verify*); NOS replaces PVE's cloud-init drive, so it must render user-data and network-config itself; an ISO9660 writer in Go without a new dependency | Any PVE user who can attach ISOs from that storage can read the key; two `cidata` sources when the template keeps its cloud-init drive; more generated format code | Not now; alternative for remotes whose nodes cannot be enrolled (open question 2) |
| (iii-b) Guest agent `file-write`, `args`/`fw_cfg`, SMBIOS strings | Guest file access (forbidden by spec 06); `args` is `root@pam` only; SMBIOS values sit in the VM config that every `VM.Audit` holder, including the read token, can read | — | Rejected. Note: if PK-10a shows that `cloudinit/dump` renders `cicustom` content, path (i) has the same `VM.Audit` exposure as SMBIOS and is not better on that axis |

### Exposure through the PVE API

PVE offers `GET /nodes/{node}/qemu/{vmid}/cloudinit/dump?type=…`, which
needs only `VM.Audit` on the guest and returns rendered cloud-init data.
Whether it renders the content of a `cicustom` snippet (for `vendor`, and
for `user` when `cicustom user=` is set) or only PVE's generated parts,
and which `type` values each supported version accepts, is not known
without a lab check (PK-10a). This amendment assumes the worst case: **the
preset private key is readable by every principal with `VM.Audit` on the
new guest from the moment `cicustom` is set until the snippet is removed or
`cicustom` is cleared.** That includes:

- the NOS read token (spec 06: `VM.Audit` on `/vms`). It is held only in the
  executor vault, the same custody as the key, so it is not a new reader in
  substance; but a stolen read token would now also yield bootstrap keys,
  which raises the value of a credential that is otherwise read-only. The
  executor never calls `cloudinit/dump` for a guest with `preset`, and no
  response of that endpoint may reach the spool, the collector or the
  server;
- every other `VM.Audit` holder on `/vms` or on the guest's pool: the
  built-in `PVEAuditor` role, monitoring exporters, lab users with
  read-only access, other automation. These are new readers that do **not**
  already control the guest.

The same question applies to any storage content or download endpoint that
can return a `snippets` volume, and to attaching the generated cloud-init
volume to another guest (PK-10a).

### Variants and residual risk

The attacker that matters for every variant is: someone who learns the
bootstrap secret **and** has a network position at the join (on the guest's
bridge or VLAN, the router, or DNS for the guest's name), so that NOS's SSH
connection to the guest's address reaches them. A secret alone does not
help an attacker without that position, and a network position alone does
not help against a pinned key. An attacker in the middle cannot relay NOS's
user authentication to the real guest (the signature covers the session),
so a successful attacker has to impersonate the whole guest from then on;
the real guest stays unenrolled.

| Variant | Secret in cloud-init | Who learns it (worst case of PK-10a) | Theft detectable | Residual risk vs fingerprint review | vs option (a) |
| --- | --- | --- | --- | --- | --- |
| V1: (c) as specified (preset key in vendor-data, cleanup after rotation) | Host private key, minutes to hours | Node root, node backups, and every `VM.Audit` holder | No. A thief at the join is indistinguishable from the guest | Better than review as practiced (operators rarely compare on the console): the attacker needs `VM.Audit` *and* a network position, not just a network position. Worse than review done properly on the console, and worse in kind because the failure is silent and also leaks to read-only users | Worse: (a) reads the key over the authenticated PVE channel with no secret at rest; its cost is a credential that can read any guest file |
| V2: V1 plus **M1** (early cleanup) and **M2** (`VM.Audit` precondition), see below | Host private key, from config set until the start task returns | Node root and node backups; no other `VM.Audit` holder, because M2 refuses `preset` when one exists | No | Better than review in both forms against everyone but node root, whom review does not protect against either (node root controls the console) | Comparable: no guest-file credential, but a short-lived secret on the node |
| V3: guest generates its own host key, one-time registration secret in cloud-init, NOS accepts exactly one registration per VMID and generation | One-time token | Same readers as V1 | Partly: a thief who registers first makes the real guest's registration fail loudly, but a thief with a network position simply blocks the real guest's attempt and nothing is seen | None gained against the attacker that matters (needs a network position in both); needs a guest-to-NOS listener that spec 02 forbids | Worse (listener) |
| V4: guest generates its own host key, nothing secret in cloud-init | Nothing | Nobody | — | Equal to review: without a secret or a hypervisor-mediated read, nothing binds the presented key to the VM. Values readable inside the guest (`product_uuid`, MAC address) are visible to `VM.Audit` holders too and prove nothing | Worse; (a) is exactly the hypervisor-mediated read V4 lacks |

Conclusion: no preset variant avoids the `VM.Audit` exposure by design.
Putting nothing secret into cloud-init (V4) collapses to review. A
one-time secret (V3) only becomes "fail loudly" against an attacker without
a network position, who could not have used a preset key either. So (c) is
worth having only if the exposure is closed by PVE behaviour (PK-10a) or by
mitigations M1 and M2.

**Mitigations.**

- **M1, early cleanup.** The snippet is needed only when PVE generates the
  cloud-init drive at start. As soon as the start task has returned OK,
  the executor clears `cicustom` and removes the snippet, before the join
  (previously: after rotation). The key then lives on in the generated
  cloud-init drive on VM storage (root and storage admins only, *verify*)
  and in the guest. *Verify:* clearing `cicustom` on a running guest does
  not regenerate the drive before cloud-init has read it, and the drive is
  readable through no `VM.Audit` endpoint. If the guest reboots before
  cloud-init ran, the new drive has no vendor-data, the guest generates its
  own keys and the join fails closed with a key mismatch. M1 shrinks the
  window from minutes or hours to the clone-to-start interval, but a
  `VM.Audit` holder polling for new guests can still win the race, so M1
  alone is not sufficient.
- **M2, `VM.Audit` precondition.** At proposal time, and again right
  before the config step, the executor reads the effective ACLs for the
  target path (`/vms/<vmid>`, `/vms`, `/`, the target pool, the snippet
  storage `/storage/<snippets>`, its parent `/storage`, and every pool
  `/pool/<pool>` that contains the snippet storage, because ACLs on all of
  these propagate `Datastore.Audit` to the snippet storage; previously only
  `/storage/<snippets>`) through the
  read token (`GET /access/acl` needs `Sys.Audit` on `/access`, which the
  read token's `Sys.Audit` on `/` propagates to, *verify*). `preset` is
  offered only if every principal with `VM.Audit` (or, on the snippet
  storage, `Datastore.Audit` or any other `Datastore.*` privilege, because
  which of them allow listing or downloading `snippets` content is
  unverified, PK-10a; previously only `Datastore.Audit`) there is the NOS read
  token, the NOS action token or `root@pam` (previously also holders of a
  role with `VM.Console`; removed, because console access alone neither
  gives root in a cloud-image guest nor lets the holder impersonate it, so
  such a reader could still use a leaked preset key). Group membership is resolved; an unknown role or an
  unreadable ACL means `review`. The result is bound in the permit and a
  change between proposal and the config step stops the plan. M2 cannot
  see a principal created after the check, which is why M1 is also
  required.

### If the lab check fails

(c) is not viable whenever M1 or M2 cannot hold, including M1 failing or an
endpoint M1/M2 do not cover (previously "if M1 and M2 cannot both hold").
That is the case when PK-10a shows any of: M2 cannot be implemented reliably (ACL read
not permitted, roles not resolvable); M1 does not work (for example,
clearing `cicustom` regenerates the cloud-init drive before cloud-init has
read it, or the snippet cannot be removed in time); or a `VM.Audit` or
`Datastore.Audit` endpoint returns the snippet content in a way M1 and M2
do not cover. (Previously: only when dump exposure was confirmed and M2
could not be built.) The maintainer then chooses among:

1. Review stays the only method (status quo, decision 1); the PK tickets
   are closed except the documentation of this finding.
2. Option (a), a scoped guest-agent token on enabled guests only, with its
   known cost (guest file read as root) and the bootstrap gap on vendor
   images.

There is no third option within this amendment. (Previously: "3. (c) as an
explicit per-remote operator opt-in with the risk stated in the UI". Removed,
because it would allow (c) without M1 and M2, which this amendment never
allows. Any opt-in of that kind would be a separate future amendment with its
own review and is not proposed here.)

### Decision

Decisions 1–9 apply only once the amendment is accepted, and only with
M1 and M2 together; a PK-10a result can make (c) not viable, but it can
never waive M1 or M2 (previously: "or with a PK-10a result that makes M2
unnecessary").

1. **Method bound in the permit.** At proposal time the executor decides
   the host-key method, `preset` or `review`, and binds it into the
   `pve.guest.provision` parameters, so the approver sees it. `preset` is
   offered only when the remote and node have a registered snippet storage,
   the node is an enrolled, unblocked host, M2 passes, and the profile does
   not opt out. Otherwise `review` (fingerprint review, decision 1) is
   bound. An approved method is never changed after approval.
2. **Key generation.** The executor generates an ed25519 key pair with
   `crypto/ed25519` and encodes it with `golang.org/x/crypto/ssh`
   (`MarshalPrivateKey`); no self-written cryptography. It persists only the
   public key, its fingerprint and the generation timestamp from the
   injected clock (`executor.db`, with the provisioning job; previously
   public key and fingerprint only, which left the age bound without a
   persisted reference) and fsyncs before writing the snippet. The private key is never stored
   on the executor: not on disk, not in the vault, not in a result, log or
   audit line. It lives in executor memory only until the snippet write
   returns. Spec 06's rule that the vault holds no SSH keys is therefore
   unchanged.
3. **Snippet write.** A new typed SSH action on the node writes
   `nos-<remote>-<vmid>-<generation>.yaml` into the registered snippet
   directory. The content arrives on stdin (never argv), is written to a
   temporary file with mode 0600 owned by root and renamed into place; the
   directory must be a root-owned real directory, not a symlink, on a local
   filesystem (the action checks the filesystem type against an allowlist,
   for example ext4, xfs, zfs, btrfs). The result carries the path and the
   public fingerprint only. The vendor-data contains, and nothing else:
   - `ssh_keys` with the ed25519 pair;
   - `ssh_deletekeys: true` and `ssh_genkeytypes: []` for this first boot,
     so only the preset key exists;
   - a `write_files` drop-in `/etc/cloud/cloud.cfg.d/99-nebula-hostkey.cfg`
     with `ssh_deletekeys: false` and `ssh_genkeytypes: []`, so the
     instance-id change caused by clearing `cicustom` never regenerates the
     pinned key. Consequence: host-key generation stays off in this guest.
     A guest later converted to a template or cloned outside NOS gives its
     clones the same host key (or none after a `cloud-init clean` that
     deletes keys). The operator guide (PK-09) says to remove the drop-in
     and the host keys before templating; NOS-provisioned guests always get
     a fresh key.

   PVE keeps generating user-data (`ciuser`, `sshkeys`, `cipassword`) and
   network-config; only the vendor part is custom (*verify* the merge on
   each supported image).
4. **Steps.** `pve.guest.provision` with `preset` becomes: generate and
   persist the public key, write the snippet, full clone, M2 recheck,
   allowlisted config set including `cicustom: vendor=<storage>:snippets/<file>`,
   resize, start, early cleanup (M1). It stays one frozen plan with one
   approval, binding both the PVE target and the node's SSH host ID and
   pinned fingerprint. The node already counts as an affected host
   (section 3), so the risk is unchanged.

   **Reconciling a lost snippet write** (previously: "generate a new pair
   and write again", which collided with the refusal of existing names).
   The name is deterministic, so a retry meets the file of the lost
   attempt if that attempt succeeded. Rule, applied only while no start
   request has been dispatched for this VMID and generation:
   1. Run the read-only node action `pve.snippet.stat` for the exact name.
      It returns absent, or present with the SHA-256 fingerprint of the
      `ed25519_public` entry it parses (public data only; the private part
      is never read into the result).
   2. Present, the fingerprint equals the recorded one, the recorded key
      was generated less than the preset key age bound ago (a named
      constant next to the reconciler, `presetKeyMaxAge`, proposed 15
      minutes) and the job has not failed: the write is adopted as done.
      The executor needs no private key for this. A key at or over the
      bound is never adopted (previously: adopted at any age), because it
      has sat on the node as a live secret for longer than the design
      allows. Age is measured with the executor's injected clock
      (`Now func() time.Time`, AGENTS.md), never the wall clock directly.
      The same bound is checked on the normal path right before the start
      request is dispatched (previously: only when a lost write was
      reconciled, so a slow clone or resize kept the key on the node past
      the bound unchecked): a recorded key at or over the bound is
      replaced as in step 3 before start. After start dispatch the bound
      no longer applies; M1 then removes the snippet.
   3. Absent, unparsable, another fingerprint, or a recorded key at or over
      the age bound: generate a new pair,
      replace the recorded public key and fsync, then run
      `pve.snippet.put` with `replace=true`. Replace is accepted only for
      the exact name of this job, renames atomically over the old file and
      is audited as `guest_hostkey_snippet_replaced`. A plain put
      (`replace=false`) still refuses an existing name.
   4. A crash between steps 3's persist and put converges: the next pass
      sees a fingerprint that differs from the new record and repeats 3.

   Once a start request has been dispatched (even if its outcome is
   unknown) the recorded key is fixed: no stat-adopt, no replace. If the
   guest then presents another key, the join fails closed (decision 5).
   An unknown start outcome is reconciled as in decision 7 ("Start outcome
   unknown").
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
   in one transaction and checks the new pin with a fresh connection. It
   needs a spec 08 revision (PK-00). Until rotation succeeds, the host
   carries "bootstrap key not rotated" and secret-bearing steps are
   refused.

   What rotation does and does not do (previously: "after rotation every
   leftover copy is worthless", which overstated it): rotation protects
   only against copies of the preset key that are *used after* it, for
   example from node backups, the cloud-init drive or the guest's cached
   vendor-data. It does not protect against a holder of the preset key who
   is in the network path at the join: that attacker answers the rotation
   with a key of their own and is re-pinned permanently. The new key
   cannot be proven in-band in a way such an attacker cannot fake: every
   check over the session (fresh connection, `product_uuid`, MAC address,
   cloud-init instance-id) is answered by whoever holds the preset key, and
   those values are visible to `VM.Audit` holders anyway. The re-pin is
   therefore exactly as trustworthy as the secrecy of the preset key from
   snippet write to rotation, which is why M1 and M2 carry the security of
   this design and rotation only limits its lifetime. An out-of-band check
   that the attacker cannot fake would need a hypervisor-mediated signal
   from inside the real guest (open question 4); none is part of this
   amendment.
7. **Cleanup.** Early cleanup (M1) clears `cicustom` (a new typed delete of
   that one field) and removes the snippet with the node action right after
   the start task returns OK (previously: after rotation). Both are
   audited. A bootstrap step removes the cached vendor-data in the guest
   after rotation. If either step fails (for example node unreachable),
   the same single-dispatch rule and "snippet cleanup pending" flag apply
   as for failure cleanup below (previously: retry and flag were defined
   only for failures before start; later: an automatic retry with backoff,
   see *One dispatch per step*), and the join is not marked done while the
   flag is set.

   **Failure cleanup** (previously: "a failed provisioning before start
   leaves guest and snippet for inspection; removing the snippet of an
   abandoned provisioning is an explicit operator action", which left a
   live private key on the node until an operator acted and let a later
   reconciliation adopt it). On every failure path before start, the
   executor removes the snippet automatically and, if it was set, clears
   `cicustom`, within the limits of *Authority for cleanup* and *External
   change and compensation authority* below. That covers a failed or
   refused snippet write, clone, M2 recheck, config set or resize, a
   forward step refused because of an external change that keeps
   compensation authority (previously: any target or registry change),
   cancellation, and a start task that resolves
   as failed (previously also "an executor restart that finds the job
   failed", which conflicted with spec 03; a restart now only raises the
   flag, see below). Only the guest stays for inspection (section 3); the
   snippet does not stay by design. Removal is idempotent (absent counts
   as removed) and audited as `guest_hostkey_snippet_removed` with the
   failure reason. The recorded key of a failed job is marked revoked at
   the moment of failure: it is never adopted, never pinned by a join and
   never reused; a new attempt uses a new generation and a new pair.

   *Start outcome unknown* (previously undefined, so the snippet could stay
   on the node indefinitely; later "Resolved OK → M1; resolved failed →
   failure cleanup" without a lifetime limit, which could be read as
   allowing a mutation after a reconciliation following a restart, which
   spec 03 v23-03-05 forbids). If a start request was dispatched and its
   outcome is unknown, the executor never redispatches the start. It
   reconciles read-only:
   - *UPID stored.* The executor polls the stored UPID with the read
     credential. This observation is allowed in any executor lifetime and
     grants no mutation authority.
   - *No UPID stored* (the start request was sent after its intent was
     persisted, but the response was lost before the UPID was persisted).
     The job enters `reconciling` (ADR 0006). The executor may identify the
     task read-only from the task list of the recorded node: a `qmstart`
     task for the recorded VMID, issued by the NOS mutation token, started
     no earlier than the persisted intent timestamp. Exactly one match →
     its UPID is persisted and reconciliation continues as above. Zero or
     several matches, an unreadable task list, or an expired task record →
     the outcome stays `unknown`: no cleanup step runs (the guest may be
     booting from the drive), the power state alone is never taken as
     success, and the run is flagged "snippet cleanup pending".
   - *Mutations after resolution.* M1 (resolved OK) or failure cleanup
     (resolved failed) runs automatically **only** if the resolution is
     observed within the same executor lifetime that dispatched the start
     **and** the job's permit is still valid then (not expired, not
     revoked, no risk raise, no external change that ends compensation
     authority), each step under the single-dispatch rule below. A
     resolution observed after a restart or lock, or after the permit
     ended, triggers no mutation: the run is flagged "snippet cleanup
     pending" and only the PK-08 action under fresh approval cleans up.
   - *`startOutcomeMaxWait`* (named constant, proposed 10 minutes,
     measured with the injected clock). If the task is still unresolved
     when it elapses, no cleanup step runs and the run is flagged "snippet
     cleanup pending". Read-only polling continues while the permit is
     valid. If the task then resolves OK (or failed) within the same
     executor lifetime while the permit is still valid, M1 (or failure
     cleanup) still runs automatically, because the reason for waiting
     (the guest may still read the drive) is gone and removal shortens the
     exposure; the flag clears only when removal is confirmed (stat
     absent). Once the permit ends, polling no longer leads to any
     mutation.

   *Authority for cleanup* (previously: "the permit authorizes the job's
   compensating steps" with automatic cleanup and retry across a restart,
   which conflicted with spec 03 v23-03-05 "Durable authority and volatile
   approval" and ADR 0007: every restart or lock revokes mutation
   authority, and persisted job intent never grants redispatch). Cleanup
   is part of the approved job: the derived permit authorizes, besides the
   forward steps, the job's own compensating steps (`cicustom` delete,
   `pve.snippet.remove`) for exactly its recorded target, and nothing
   beyond it. Automatic cleanup runs only inside the same executor
   lifetime and only while that permit is still valid, each step at most
   once (*One dispatch per step* below). After a restart or lock, or once
   the permit has expired or been revoked, nothing runs automatically: the
   job persists "snippet cleanup pending" and cleanup runs only through the
   PK-08 operator action, which needs a fresh approval under the existing
   semantics (a new permit for the cleanup steps only, at the job's risk
   level or, after a risk raise, at the raised level; never lower). The
   persisted cleanup state holds only the pending flag and the recorded
   target; it grants no authority.

   *External change and compensation authority* (previously: "a forward
   step refused because the target or registry changed stops the forward
   steps but leaves the permit valid for the compensating steps", which
   kept authority after any change and contradicted ADR 0006 "NOS records
   that external change, stops affected dispatch and requests approval
   again", spec 07 "anything that changes the approved binding invalidates
   affected authority" and ADR 0007 "a raised risk invalidates remaining
   authority"). An external change always stops every undispatched forward
   step. It leaves the compensating steps their authority only if it does
   not touch the binding of that compensating step, which is exactly its
   recorded target plus, for the `cicustom` delete, the remote's trust
   binding. Concretely:
   - **Keeps compensation authority** (the compensating step's own binding
     is unchanged; each step is still rechecked against it right before its
     claim, see *Recorded target*): an M2 recheck that finds a new foreign
     `VM.Audit` or `Datastore.*` holder (removal then shortens a real
     exposure); a change or removal of the snippet registry entry after the
     snippet was written (cleanup uses the recorded values); a changed
     precondition digest that only forward steps bind (template or source
     guest, target disk storage, network or IPAM inputs of a step not yet
     dispatched); operator cancellation, which stops undispatched forward
     steps while the approval shows the cleanup steps as running on
     cancellation.
   - **Never keeps compensation authority** (the whole job's remaining
     authority ends, forward and compensating; the run is flagged and only
     PK-08 under fresh approval cleans up): a risk raise of the job (ADR
     0007; never downgraded); revocation of the permit in any form
     (explicit revoke, lock, executor restart, expiry); a change of the
     remote's CA/leaf pin, trust generation or credential version (spec 07
     canonical provider target); a raised risk or revocation found while a
     compensating step is in flight leaves that one dispatch to reconcile
     read-only and stops the rest.
   - **Ends authority for one step only** (that step does nothing on the
     current object, the other step keeps its authority if its own binding
     holds, the run is flagged): for `pve.snippet.remove`, the recorded
     node gone, re-enrolled or presenting another fingerprint; for the
     `cicustom` delete, a VMID proof mismatch or the guest relocated to
     another node than the recorded one (ADR 0006: moving nodes needs a new
     proposal).
   A change not listed here ends compensation authority (fail closed).

   *Recorded target.* The snippet storage ID, directory and file name are
   recorded in the job when the snippet is written, and cleanup uses the
   recorded values, never the current registry, so a registry change after
   approval cannot redirect removal. Each step has its own check
   (previously one check for both, which refused snippet removal after a
   failed or refused clone, when no guest owns the VMID):
   - `pve.snippet.remove` is bound only to the recorded node (enrolled host
     ID and fingerprint) and the recorded path. It runs whether or not a
     guest exists.
   - The `cicustom` delete also requires that the VMID still belongs to
     this job's guest. The proof is the SMBIOS UUID (`smbios1 uuid`) and
     `vmgenid` read from the guest config right after the clone and
     recorded in the job, never the guest name. The proof assumes that
     every clone (full and linked) gets a fresh `smbios1 uuid` and
     `vmgenid` that differ from the template's and from those of any later
     guest that reuses the VMID (*verify*, PK-10; previously stated as
     fact). Until PK-10 confirms this per supported PVE version, `preset`
     stays disabled; if it does not hold, or a recorded value is empty, the
     `cicustom` delete is refused (flagged) and the proof needs a
     replacement. A PVE user with
     `VM.Config.*` rights on the guest can change those values, so a match
     is not proof against such a user (M2 already refuses `preset` when a
     foreign principal can see the guest; config rights are not checked
     separately), while a mismatch always refuses.
   If a check fails (VMID reused, node gone or re-enrolled with another
   fingerprint), that step does nothing on the current object and the run
   is flagged "snippet cleanup pending".

   *One dispatch per step, no automatic retry* (previously: "the executor
   retries with exponential backoff from 30 seconds capped at 10 minutes
   until it succeeds or the permit ends", which conflicted with ADR 0006
   "claim the single-use authorization" per dispatch and with ADR 0007 and
   spec 07 "no automatic rollback, unapproved retry or redispatch after an
   uncertain mutation; retries or rollback need fresh exact-target
   approval"). Pre-authorizing a bounded number of automatic retries in the
   approval was considered and rejected: spec 07 requires fresh approval
   for every retry, and an approval cannot pre-approve one. Instead:
   - The approval of `pve.guest.provision` with `preset` lists every
     cleanup step it authorizes, each with its exact recorded target
     (`cicustom` delete on the recorded node and VMID; `pve.snippet.remove`
     on the recorded node and path), and the condition under which it runs
     (M1 after start OK; failure cleanup on the failure paths above). These
     are the only compensating dispatches the approval covers.
   - Each listed step is its own single-use authorization derived from the
     job's permit (like an ADR 0007 member permit: bound to the job digest,
     step ID, exact target and the permit's expiry). The executor claims it
     atomically under the spent-ID discipline and persists intent (fsync)
     before the dispatch. A claimed step is never dispatched again by the
     executor, whatever its outcome.
   - If a step fails, is refused by its check or has an unknown outcome
     (for example node unreachable, lost response), the executor does not
     retry it. The run is flagged "snippet cleanup pending" (persisted; a
     failed run stays failed) and the run page shows it prominently. Every
     further attempt is the PK-08 operator action under a fresh approval,
     which again claims one single-use authorization per dispatch. A failed
     `cicustom` delete does not stop the independent `pve.snippet.remove`
     step, and vice versa; each is claimed and dispatched once.
   - Read-only checks (for example `pve.snippet.stat`, reading the guest
     config for the VMID proof, polling a stored UPID) are not mutations and
     may repeat; they never grant or extend mutation authority.
   This applies to every cleanup, including M1 after a successful start.

   *Resolving the flag* (previously undefined for a target mismatch). The
   operator resolves a pending flag with the PK-08 action, under a fresh
   approval, in one of two ways: (a) manual removal bound only to the
   node identity shown in that approval (the recorded host, or its
   re-enrolled successor named explicitly) and the recorded path (plus the `cicustom` delete when the
   VMID proof still matches); or (b) an explicit acknowledgement "key
   remains on node, rotate/destroy", audited as
   `guest_hostkey_cleanup_acknowledged`. The flag clears only when removal
   is confirmed (stat shows absent) or the acknowledgement is recorded.
8. **Audit.** Executor events `guest_hostkey_generated`,
   `guest_hostkey_snippet_written`, `guest_hostkey_snippet_replaced`,
   `guest_hostkey_pinned`, `guest_hostkey_rotated`,
   `guest_hostkey_snippet_removed`, `guest_hostkey_cleanup_acknowledged` and `guest_hostkey_preset_refused` (M2
   failure, with the offending principal's role, not its token) carry
   execution, remote, node, VMID, generation, path and fingerprints, never
   key material.
9. **Fallback.** Fingerprint review stays the default whenever the preset
   path is unavailable, M2 fails or the profile opts out. The agent-read
   code path of PV-06 gets no production credential.

### Threat model of the preset private key

The preset key is a bootstrap credential. Whoever holds it before rotation
and has a network position at the join can impersonate the guest to NOS
permanently (decision 6): they see the commands NOS sends and survive the
rotation. Rotation before every secret-bearing step limits what leftover
copies can do *later*; it does not undo a theft before the join. The
security of the design rests on keeping the key secret from snippet write
to rotation.

| Where | When | Who can read it | Mitigation |
| --- | --- | --- | --- |
| Executor memory | From generation until the snippet write returns | Executor process (already holds every SSH key) | Never persisted; same "stated limit" as spec 06 |
| SSH channel to the node | Snippet write | Nobody outside the pinned, authenticated node session | stdin, not argv (not visible in `ps`) |
| Snippet file on the node | From write until early cleanup or automatic failure cleanup (normally seconds to minutes); while "snippet cleanup pending" is set (node unreachable, restart, expired permit, target mismatch, start outcome unresolved) it stays until the operator removes it or acknowledges it (previously: "seconds to minutes" only) | Root on that node; admins of the storage if it were shared; node filesystem backups | Node-local storage only: registry refuses shared types (nfs, cifs, cephfs, glusterfs, pbs) **and** any storage flagged `shared 1`; the put action refuses a network filesystem; mode 0600; M1 |
| **PVE API: `cloudinit/dump` and any storage read of the snippet (*verify*, PK-10a)** | While `cicustom` is set and the snippet exists | Worst case: every `VM.Audit` holder on the guest, including the NOS read token and read-only users or monitoring | M2 refuses `preset` when any principal other than the NOS tokens and `root@pam` holds `VM.Audit` on the guest path or `Datastore.Audit` (or any other `Datastore.*` privilege) on the snippet storage (`/storage/<snippets>`, inherited from `/storage`, `/` or a pool containing the storage); M1 shortens the window; executor never calls the endpoint for preset guests |
| Generated cloud-init drive (`vm-<vmid>-cloudinit`) on VM storage | Until the next regeneration after cleanup | Root on the node, storage admins; PVE users able to attach that volume elsewhere (*verify* ACL) | Rotation limits later use; vzdump skips cloud-init drives (*verify*) |
| Guest: `/etc/ssh`, `/var/lib/cloud/instance/vendor-data.txt*`, CD-ROM device | Until rotation; the cache until the bootstrap cleanup step | Guest root; members of group `cdrom` while the drive is attached (the Ubuntu default user is one, and is a sudoer anyway) | Rotation; bootstrap removes the cached vendor-data |
| PVE config, `/etc/pve`, config reads, read-token spool | Always | Only the `cicustom` reference, no key material | — |
| PVE backups | Guest disk backups hold the *current* host key, as for every VM today | Backup operators | Not new; a backup taken before rotation holds the preset key, which rotation makes useless for later impersonation |

PVE administrators and node root are not new readers in substance: they
already control the guest (console, disks, snapshots) and could take over
any VM. The readers this design adds are storage admins of a shared snippet
store, node backup operators and, unless PK-10a rules it out, every
`VM.Audit` holder. Node-local storage excludes the first; M1 limits the
second to backups taken in a seconds-long window; M2 excludes the third.
Without M2 the third group is a real and silent exposure.

**Comparison.**

- Fingerprint review: nothing secret at rest. But in practice it is trust
  on first use unless the operator really compares on the console, and it
  is a manual step on every deployment.
- Scoped guest-agent token, option (a): needs `VM.GuestAgent.FileRead`
  (PVE 9) or the much broader `VM.Monitor` (PVE 8). Either lets the
  credential read any guest file as root, `/etc/shadow` and secrets
  included. Spec 06 excludes guest file access from both tokens. Vendor
  images do not ship the agent, so it would only work after the bootstrap
  it is supposed to protect. Its binding is hypervisor-mediated, so it
  has no bootstrap secret to steal.
- Preset key with M1 and M2: no TOFU, no manual step, no guest privilege.
  The cost is a short-lived secret on the node, an enrolled node, one
  operator-provisioned storage, an ACL precondition that will refuse
  `preset` on remotes with read-only users, and a silent failure mode if
  the secret leaks before the join anyway.
- Preset key without M2, if PK-10a confirms the dump exposure: worse than
  it looks, because read-only PVE users can obtain a credential that, with
  a network position, gives them permanent impersonation of the guest.

### Open questions for the maintainer

1. Writing files on the PVE node through its SSH enrollment is new
   authority on the node: a typed action limited to one directory and one
   name pattern. Is that acceptable, or must the snippet directory belong
   to an unprivileged account (for example group-writable for `nebula`)?
2. Remotes whose nodes are not enrolled: stay on review, or later add
   (iii-a), the per-guest seed ISO, with `Datastore.AllocateTemplate` on a
   dedicated storage? (iii-a has the same class of exposure to readers of
   that ISO storage.)
3. Rotation: is `nebula.host_key.rotate` acceptable as a spec 08 revision
   (re-pin learned over the pinned channel, no console comparison), given
   that it is only as strong as the preset key's secrecy?
4. Is an out-of-band check of the rotated key worth exploring, for example
   a challenge only the real guest can answer and NOS can observe through
   the read token (such as a requested power-state change seen in the PVE
   status)? Not proposed here; it would need its own review.
5. Is M2 acceptable as a precondition that makes `preset` unavailable on
   remotes with read-only users or monitoring roles, or should the
   decision move to "If the lab check fails" option 1 or 2 right away?

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
| PK-00 … PK-10 | Amendment 1 (Proposed), preset guest host key; PK-10a gates acceptance: see [docs/implementation/preset-host-key.md](../implementation/preset-host-key.md) | PV-05, PV-06 |
