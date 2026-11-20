# PVE image preparation: wiring decision paper (ADR 0008 PV-03)

Status: decision paper, proposal. No code is changed by this document.
Date: 2026-11-20. Ticket: uf18 (gap G04). Scope: the path that prepares a
PVE template from a signed catalog entry, so that `pve.guest.provision` can
clone it. Read with [ADR 0008](../adr/0008-guest-provisioning.md) section 2
and PV-03 (line 1261).

Citations are `path:line` against the tree at the time of writing. Items
marked **(open)** are not decided by ADR 0008 and need a decision before
PV-03 is built.

## 1. Current state (as built)

Guest provisioning is shown as merged (`README.md:66`, `docs/status.md:16`),
but no provisioning can get past its proposal. The operator documentation
says so (`docs/operator/proxmox.md:595-607`: "there is no RPC, page or CLI
command for it"; troubleshooting row at `docs/operator/proxmox.md:744`).

The pieces that exist, and what calls them:

| Piece | Where | Callers outside tests |
| --- | --- | --- |
| Action ID `pve.image.prepare` | `internal/executor/pve_images.go:33-34` | used by the mutation request (`pve_images.go:373-390`) |
| Base risk HIGH, risk floor for preparation | `pve_images.go:194-196`, `pve_images.go:226` | inside `ImagePrepareRiskFloor` |
| Catalog struct: signed part and local map, both in memory, `State` required | `pve_images.go:105-115` | constructed at `pve_rpc.go:346` (empty) |
| `PveImageCatalog.LoadSigned` (verify, rollback floor, persist, swap) | `pve_images.go:124` | **none** outside tests (`pve_images_test.go:191`, `:344-347`) |
| `PveImageCatalog.AddLocal` (in-memory, prefix `local-`, trust Local) | `pve_images.go:157` | **none** outside tests |
| `PveImageCatalog.RemoveLocal` | `pve_images.go:171` | **none** outside tests |
| `PveImages.ProposalRequest` (builds the proposal, risk at least HIGH) | `pve_images.go:416-437` | **none** outside tests |
| `PveImages.Prepare` (runs an approved permit, records the template) | `pve_images.go:440-442` | **none** outside tests |
| `PveImages.BindTemplate` (checks the record against the catalog, the trust generation and the live config) | `pve_images.go:530`; ErrPveTemplateNotPrepared at `pve_images.go:539` | `pve_provision.go:678` |
| Refusal text for a missing template | `pve_rpc.go:1169` | maps `ErrPveTemplateNotPrepared` / `ErrPveTemplateChanged` |
| Provisioning proposal | `pve_rpc.go:1213-1240` (`ProposePVEGuestProvision`, `ProposalRequest` at `:1240`) | RPC handler |
| Executor RPC table: provisioning roles | `internal/executor/roles.go:218-219` (`server`, `admin`) | RPC authorisation |
| Proto: no image RPC in `ExecutorService`; only the template reference message `PVETemplateRef` | `proto/nebula/executor/v1/executor.proto:2757` (service starts at `:16`; provisioning RPCs at `:563-564`) | — |
| Built-in release bundle directory used by the executor | `cmd/nebula-executor/builtin_trust.go:19` (`/usr/share/nebula/release`) | trust wiring only; no catalog file is read from it |
| Signed catalog format and limits | `internal/release/catalog.go:21` (`nebula-image-catalog-v1`), `:29` (`image-catalog.json`, 256 KiB), types at `:52-70`, `VerifyCatalog` at `:94` | `LoadSigned` (test-only caller) |

What the operator sees in the deploy wizard (`internal/web/ui/deploy.go`):

- **Template VMID** is a drop-down of the QEMU guests stored on the chosen
  node (`deploy.go:616-617`, `:702`). Nothing marks a guest as a prepared
  template.
- **OS image** is a free-text field (`deploy.go:870-872`). No catalog list
  is shown anywhere in the UI.
- **Template image SHA-256** is a free-text field, 64 hex characters
  (`deploy.go:879-881`). The message calls it "the image catalog digest the
  template was prepared from", which the operator has no way to look up.
- The proposal then builds `PVETemplateRef` (`deploy.go:1178-1179`) and fails
  with `the template is not prepared or changed; prepare it again`
  (`pve_rpc.go:1169`). The refusal comes before any permit, VMID reservation
  or PVE change.

The wizard also sends the wrong generation. `templateGeneration`
(`deploy.go:1379-1389`, called at `deploy.go:1154`) takes `Generation` from
the server's PVE-inventory guest (`g.Generation`), which is the server's
count of the guest's incarnations. `BindTemplate` compares it with
`rec.Generation` (`pve_images.go:541`), the executor's preparation counter
that `Prepare` starts at 1 and raises by one per preparation
(`pve_images.go:476`). The two counters are unrelated. Whenever they differ,
the provisioning is refused with `ErrPveTemplateChanged` (refusal text at
`pve_rpc.go:1169`), even for a template that is prepared and unchanged. The
wizard's `Generation` (`deploy.go:1178-1179`) must therefore come from the
executor's record, not from the inventory.

**Result:** the chain `catalog -> prepare -> record -> bind -> clone` has a
verified middle (`Prepare`, `BindTemplate`) and no way in at either end. The
wizard's image fields and the generation are all wrong or unbound, so the
middle is not reached from the UI.

Two further facts the decision depends on:

- `AddLocal` and the catalog itself are not persisted. Only the rollback
  floor (`PveCatalogStateStore`) is on disk (`pve_rpc.go:346`). A local entry
  added today would be gone after a restart.
- Nothing in this repository produces `image-catalog.json` or reads it from
  the release bundle. `internal/release/catalog.go:29` is the only mention of
  the file name, and `cmd/nebula-release-stage` does not build it.

## 2. What ADR 0008 fixes, and what it leaves open

**Fixed by ADR 0008 section 2 (`docs/adr/0008-guest-provisioning.md:73-95`):**

- The catalog is **signed release data**, reusing the E15 release-signing
  chain. Entries carry OS and release, architecture, the vendor cloud-image
  URL (https) and the SHA-256 (lines 75-81).
- An operator **may add local entries**. They carry trust `Local` and raise
  preparation to HIGH (lines 82-83). The code enforces the prefix `local-`
  and the Local validation rules (`pve_images.go:158-159`,
  `internal/release/catalog.go:172`).
- **Preparation** is a one-time HIGH action per (remote, node, storage,
  image), action `pve.image.prepare` (line 84-85). It uses PVE `download-url`
  with the catalog checksum, creates a VM with a cloud-init drive and
  `agent=1`, and converts it to a template (lines 86-89).
- The executor records VMID, generation and source digest. Provisioning
  binds that record, and a template changed outside NOS fails the binding
  (lines 90-92).
- A template prepared from a Local entry does not raise provisioning; only
  its preparation is HIGH (`docs/adr/0008-guest-provisioning.md:132`).

**Not fixed by ADR 0008 (open):**

1. The **form of the RPCs**: Propose/Commit as for guest power, or an
   admin-only path, or a CLI only.
2. **Who loads the signed catalog, and when**: at executor start from the
   release bundle directory, by a separate admin step, or at some other time.
   The catalog file's name, its place in the release bundle, and its
   production by the release tooling are also not decided.
3. **How local entries are added, removed and persisted.**
4. **Operator visibility**: whether the wizard offers a catalog list, and
   whether there is an "Images" page.
5. **Re-preparation**: the ADR says a template is recorded with a generation
   but does not say how a removed or broken template is prepared again. The
   code already answers this (see D5): the refusal at
   `pve_images.go:424-436` sits in `ProposalRequest`, not in `Prepare`, and
   fires only while the old record still binds. A gone or changed template
   falls through to a new proposal, and `Prepare` writes generation + 1
   (`pve_images.go:476`). Item 5 is settled by the existing code, but the
   fall-through is wider than D5 states (see D5); PV-03b narrows it, and the
   ADR amendment (PV-03j) records the result.

Items 1-4 block PV-03.

## 3. Open decisions, variants and recommendation

### D1. RPC form for `pve.image.prepare`

| Variant | Who may propose / commit | Consequence for roles | Consequence for the threat model |
| --- | --- | --- | --- |
| (a) Propose/Commit RPCs, like guest power and provisioning | `server` and `admin` for both | Same pattern as `roles.go:206` (guest power, WA-05 variant (a)) and `roles.go:218-219`. The web UI can drive it. | The server can start a preparation, but cannot approve it: HIGH needs the user's security-key assertion, or the CLI in hardened mode (the note at `roles.go:198-205`). The catalog SHA-256 pins the image, so a compromised server can only ask for catalog images, not arbitrary URLs. |
| (b) Admin-only Propose/Commit | `admin` only | The server's role table does not change. The UI must use the admin channel for this one step. | Smaller server surface. More friction, and a second, different way to run the same action. |
| (c) Admin CLI only | none on the RPC surface | No new RPC, no proto change. The UI can only show status, read-only. | Smallest network surface. The operator must be on the executor host. No server-side feedback path. |

**Recommendation: (a).** It matches guest power and guest provisioning, and
the permit remains the gate. The server never approves, and the catalog
digest and the HIGH approval limit what a compromised server can do. Note
that (a) is a **new path for the server to propose a HIGH action**: today the
server can propose guest power and provisioning, but not an image
preparation. This is why PV-03j (ADR amendment) and PV-03k (threat model)
are in the follow-up list. (c) remains the fallback if the team wants no
server write path for HIGH actions at all.

### D2. Loading the signed catalog

| Variant | Mechanism | Consequences |
| --- | --- | --- |
| (a) At executor start, from the release bundle directory | Read `image-catalog.json` and its signature from `defaultBuiltinBundleDir` (`cmd/nebula-executor/builtin_trust.go:19`), verify with the active release roots, call `LoadSigned`. | Follows the existing built-in trust flow (ADR 0007 E15/E16). The rollback floor in `LoadSigned` (`pve_images.go:124-151`) already holds across restarts. A new catalog takes effect with a release install and a restart. No new RPC. |
| (b) Separate admin step | A `nebula` command or RPC that hands a signed file to the executor at any time. | Allows catalog updates without an install, but adds a write path for catalog data and another role entry. Needs its own permit or policy decision. |
| (c) Runtime fetch from the vendor or from the network | Executor downloads the catalog. | **Rejected.** It would make the trust anchor the network path and not the release signature, and it is not in the E15 chain. |

**Failure behaviour at start (decided here, tested in PV-03c).** The
executor does not start with an older or unverified catalog. If the file is
missing, its signature does not verify (`release.VerifyCatalog`,
`internal/release/catalog.go:94`), or `LoadSigned` refuses a rollback
(`pve_images.go:124-151`, `ErrPveCatalogRollback`), the executor logs an
audit event, starts, and loads no signed catalog. The signed part stays
empty, so `mutation` refuses every **signed** image with `ErrPveImageUnknown`
(`mutation` at `pve_images.go:373-376`, which uses `Lookup`, and `Lookup`
returns not-found when `c.signed == nil`, `pve_images.go:187-188`). Nothing is
persisted on these paths, because `VerifyCatalog` runs before
`PutPveCatalogState`. This is fail closed for the signed catalog.

**Local entries are deliberately not affected.** `Lookup` serves `local-` IDs
from the local map before it looks at the signed part (`pve_images.go:182-185`).
At start that map is empty, because nothing persists it today, so a `local-`
ID is refused at start only for that reason. Once PV-03b persists local
entries (D3a), a local entry stays preparable when no signed catalog is loaded.
This is intended: a Local entry carries its own trust (Local, HIGH approval,
`ImagePrepareRisk`), and a broken release file must not take away an image the
operator added on purpose. The cost is that a local entry does not depend on
the release signature; the HIGH approval is the gate.

The executor does not stop the whole process, so a broken release file cannot
disable unrelated executor actions. A maintainer may choose to refuse start
instead; that choice belongs in PV-03c.

**Recommendation: (a).** Open sub-question, to settle in PV-03: whether the
catalog is a separate signed file (`image-catalog.json` plus a signature, as
`catalog.go:29` implies) or a document inside `release-manifest.json`. The
separate file is simpler to verify with the existing `VerifyCatalog`. Either
way the release tooling has to produce it, which is not in place today.

### D3. Local entries

| Variant | Mechanism | Consequences |
| --- | --- | --- |
| (a) `nebula` CLI calls an **admin-only RPC** (`AddPVELocalImage`, `RemovePVELocalImage`) over the admin socket | The executor is the only writer. The RPC is in the role table with `admin` only (`internal/executor/roles.go`). The peer's UID comes from the peercred socket, as for the other admin CLI commands (`cmd/nebula/batch.go:21`, `cmd/nebula/artifact_unpin.go:36`). The executor validates the entry (`release.ValidateImage(img, true)`, the `local-` prefix, size limits), checks the role, audits, and persists it. | Local entries never travel through the server. The entry is persisted by the executor, which `AddLocal` does not do today (`pve_images.go:157`), so PV-03b adds persistence (e.g. `pve-catalog-local.json` beside `pve-catalog.json`, `pve_rpc.go:297`). The in-memory catalog is updated by the same code path that persists it. |
| (b) CLI writes a local-entry file into the executor data directory | `nebula` command writes a file the executor loads at start. | **Rejected.** It bypasses the executor's validation, role check and audit, and needs the CLI to write into the executor's state directory (a write path the executor did not authorise). A file written outside the executor is also not seen by the running catalog until restart. |
| (c) RPC from the server | Server proposes a local entry to the executor. | **Rejected.** A server-originated entry widens the set of images the executor will download and turns server compromise into image injection, even though preparation is HIGH. The `admin` role in (a) keeps the server out. |
| (d) Deploy wizard form for local entries | Form in `internal/web/ui/deploy.go`. | Same as (c), with the UI added. Rejected for the same reason. |

**Recommendation: (a).** Local entries are added and removed only by an
operator on the executor host, through the admin socket that the CLI already
uses for other admin commands. The executor stays the only writer of its
catalog state. This variant needs the persistence added to `PveImageCatalog`
and the two RPCs in PV-03a, both in protected paths.

### D4. Operator visibility

| Variant | Consequences |
| --- | --- |
| (a) Read-only "Images" page under `/deploy` (catalog entries, template records, trust) | Operator can see which SHA-256 a template was prepared from. Needs the read RPC `ListPVEImages`. Its roles: **`server` and `admin`**, read-only, no approval. The `pve-collector` role gets no access (it has only `ListReadGrants` and `ReadPVE`, `roles.go:129`, `:160-163`). Its `integrity_lock.go` entry goes next to `ListReadGrants` (`integrity_lock.go:401`) with the same value. |
| (b) Wizard drop-downs for the OS image and the template SHA-256, and the template generation taken from `ListPVEImages` | Removes the two free-text fields. The generation is the executor's record generation for the chosen key, not the inventory value (`deploy.go:1379-1389`). Depends on (a)'s data. |
| (c) Nothing new; document the CLI | Leaves the wizard as is. The generation mismatch stays, so wizard provisioning keeps failing with `ErrPveTemplateChanged`. |

**Recommendation: (a) first, (b) in the same ticket as the page if it is
small.** This is the page the proposal names (`internal/web/ui/`). Option (b)
is required, not optional, for the wizard to provision after PV-03b: the
generation replacement is part of it (see the chain in section 1).

### D5. Re-preparation (decide inside PV-03)

**Recommendation: the existing flow, no record removal.** Verified in the
code:

- `ProposalRequest` (`pve_images.go:428-431`) refuses with `ErrPveImagePrepared`
  only when `BindTemplate` succeeds on the old record, that is while the
  template still exists, is unchanged and the catalog still lists the image.
- **The fall-through is wider than "gone or changed".** Lines 433-434 return
  only the store errors (`ErrPveTemplateStore`, `ErrPveJobStore`). Every other
  `BindTemplate` error lets the proposal through as a new `pve.image.prepare`.
  That includes:
  - `ErrPveRemoteChanged` (`pve_images.go:552-553`): the remote is not active,
    or its trust generation changed.
  - Any read error of the live template. `liveTemplate` maps every
    `TargetState` error to `ErrPveTemplateChanged` (`pve_images.go:505-507`),
    so a transient PVE read failure looks like a changed template. A failure
    of `readToken` is returned unchanged (`pve_images.go:500-503`) and also
    falls through.
  - A withdrawn catalog entry does **not** reach this point. `mutation`
    (`pve_images.go:374`) refuses the unknown image first with
    `ErrPveImageUnknown`.
- A gone or changed template makes `BindTemplate` fail (`ErrPveTemplateNotPrepared`
  or `ErrPveTemplateChanged`, `pve_images.go:539-546`), so the proposal goes
  through as a new `pve.image.prepare`.
- `Prepare` sets `Generation = prev.Generation + 1` when a record exists
  (`pve_images.go:475-477`) and overwrites that key's record with
  `PutPveTemplate`.

So no operator step, CLI command or new write path to `pve-templates.json` is
needed, and `BindTemplate` stays the single check. **Decision for PV-03b:**
narrow the fall-through in `ProposalRequest` to `ErrPveTemplateNotPrepared`
and `ErrPveTemplateChanged`, and refuse every other error. A transient read
failure then refuses the re-preparation, and the record and the generation
stay as they are. The "gone" case needs a distinction that the code does not
have yet: `liveTemplate` must report a missing VM as `ErrPveTemplateChanged`
(or `ErrPveTemplateNotPrepared`) and any other read error as a separate
sentinel that is refused. PV-03b confirms in the PVE client how a missing VM
shows up. If the client cannot tell "missing" from "unreachable", the paper
accepts the cost instead: a gone template is re-prepared only after a
successful read of its absence, and an unreachable PVE leaves the proposal
refused.

PV-03b must test: prepare, delete the template in PVE, re-propose and
re-prepare (generation 2, the old record is not needed); a changed template
(config digest differs), which fails the binding and allows re-preparation;
and the refusal cases: a `TargetState` read error and `ErrPveRemoteChanged`
each refuse the re-preparation proposal with no permit, leave the record
unchanged and bump no generation. PV-03b also checks what happens when the VMID
of the gone template is reused, since the VMID reservation path
(`ErrPveVMIDTaken`) applies there.

## 4. Follow-up tickets

Protection status is taken from `.github/protected-paths.txt`.

| # | Ticket | Paths | Protected? | Scope | Required test (real path) |
| --- | --- | --- | --- | --- | --- |
| PV-03a | RPCs `ProposePVEImagePrepare` / `CommitPVEImagePrepare` (D1a), read RPC `ListPVEImages` (D4a), admin-only `AddPVELocalImage` / `RemovePVELocalImage` (D3a) | `proto/nebula/executor/v1/executor.proto`, generated `internal/rpc/executorv1/` (via `make generate`) | `proto/` **yes**; generated code follows `proto/` | Messages and service methods only | `buf lint` and the generated-code check (`make check`) |
| PV-03b | Handlers, role table (`server`, `admin` for prepare and for `ListPVEImages`; `admin` only for the local-entry RPCs; `pve-collector` for none of them), per-method entries, `pveImagePrepare` wiring, catalog load function, local-entry persistence | `internal/executor/roles.go`, `internal/executor/pve_rpc.go`, `internal/executor/pve_images.go`, `internal/executor/integrity_lock.go` (per-method tables at `:320`, `:427`) | `internal/executor/` **yes** | Executor side of D1-D3 and D5 | Executor RPC test against the PVE fake (httptest on loopback, see `internal/executor/pve_admin_test.go`): propose, approve (permit), commit, then `BindTemplate` succeeds on the recorded template. Then `ProposePVEGuestProvision` for that template must succeed exactly: no error, a provisioning permit in the response (`respond(res.Permit)`, `pve_rpc.go:1247`) and the VMID reserved for that execution. Any other outcome fails the test, including `ErrPveTemplateChanged`, `ErrPveRemoteChanged` and `ErrPveVMIDTaken`. Re-preparation after a gone template (generation 2) and after a changed one (D5 cases). D5 refusal cases: a `TargetState` read error and `ErrPveRemoteChanged` each refuse the re-preparation proposal with no permit, and the record and generation stay unchanged. Security rejections: wrong role (server calling `AddPVELocalImage`), unsigned or rolled-back catalog, local ID without the prefix, oversize catalog, local entry that fails `ValidateImage`. |
| PV-03c | Catalog load at executor start (D2a), with the fail-closed start behaviour | `cmd/nebula-executor/` (builtin trust wiring, `builtin_trust.go:19`) | `cmd/nebula-executor/` **yes** | Read `image-catalog.json` and its signature from the bundle directory, call `LoadSigned` | Start-up test with a temporary bundle directory (no `/usr/share` access): signed catalog loads; a catalog with a lower sequence is refused after restart. **Fail-closed cases (D2a):** file missing, bad signature and rollback each start the executor with no signed catalog, store no catalog state, and make a `pve.image.prepare` for every **signed** image return `ErrPveImageUnknown`. A local entry persisted under D3a stays preparable with no signed catalog loaded (D2: local entries are served by `Lookup` independently of the signed part, `pve_images.go:182-185`); the test asserts this on purpose and does not narrow it. Then the PVE-fake test of PV-03b runs through the started binary's wiring. |
| PV-03d | CLI `nebula` subcommands for local entries (D3a) and, if chosen, a prepare command; they call the PV-03a admin RPCs | `cmd/nebula/` | `cmd/nebula/` **yes** | `nebula` subcommands on the executor host only, over the admin socket | CLI test against the executor RPC on a Unix socket in a temporary directory: add and remove a local entry; entry survives an executor restart; ID without `local-` refused; a non-admin peer refused. |
| PV-03e | Release tooling produces `image-catalog.json` and its signature (decides the open sub-question in D2) | `internal/release/` and `cmd/nebula-release-stage/` | **not on the list** (`internal/release` and `cmd/nebula-release-stage` are not in `.github/protected-paths.txt`; verify before starting) | Build and sign the catalog in the release pipeline | Round-trip test: staged catalog verifies with `VerifyCatalog` and loads with `LoadSigned`. |
| PV-03f | Server pass-through of three RPCs: propose, commit and list (`ProposePVEImagePrepare`, `CommitPVEImagePrepare`, `ListPVEImages`). The local-entry RPCs are not forwarded. | `internal/executorclient/` | **no** | Client methods for the three RPCs | Client test against an in-process executor on a Unix socket in a temporary directory, or on loopback. |
| PV-03g | Server handlers that forward the three RPCs of PV-03f and map errors | `cmd/nebula-server/` | **no** | Forward propose, commit and list; keep the approval on the user's key; do not forward the local-entry RPCs | Server handler test with a fake executor client: a server request cannot approve (the approval step needs the user's assertion). Then the PVE-fake end-to-end test of PV-03b, started from the server side. |
| PV-03h | "Images" page under `/deploy` (D4a) and drop-downs (D4b) | `internal/web/ui/` | **no** | Read-only list; replace the two free-text fields with drop-downs; take `PVETemplateRef.Generation` from `ListPVEImages` (the executor record), not from `templateGeneration` (`deploy.go:1379-1389`). This generation change is required, not optional. | UI handler test: list shows catalog entries and records; the template SHA-256 and OS image fields accept only listed values; the generation sent is the record's generation for the chosen key. **Wizard acceptance:** after a successful prepare, a provisioning through the wizard has the same outcome as PV-03b (no error, provisioning permit registered, no `ErrPveTemplateChanged`). **Rendering check:** the page renders catalog URLs and executor data as text only (`html/template` escaping, no raw HTML or script), offers only `https` links, and its response carries a Content-Security-Policy in the same style as the existing UI pages (e.g. `internal/web/ui/enroll_onestep.go:524`). Test with a catalog entry containing `<script>` and a `javascript:` URL. |
| PV-03i | Documentation update after the path works | `docs/operator/proxmox.md`, `README.md:66`, `docs/status.md:16` | `docs/adr/` and `docs/spec/` **yes**; `docs/operator/` and the two status lines are not on the list | Replace "Not available today" and the status wording | Doc check: every changed `path:line` grep-verified. |
| PV-03j | **ADR 0008 amendment** (new "Amendment 2 (date): image preparation wiring") recording D1 (roles and the server's new HIGH proposal path), D2 (catalog load, fail-closed start), D3 (admin-only local-entry RPCs), D4 and D5 (re-preparation through the existing flow). Changes the open-question list in section 2 of the ADR. | `docs/adr/0008-guest-provisioning.md` | `docs/adr/` **yes** | Decision record only; no code | Doc check: each decision cites `path:line` from the code and states the test ticket (PV-03b, PV-03c, PV-03d). Maintainer approval needed, as for amendment 1. The earlier role decisions were recorded this way (ADR 0008 "Roles of the provision RPCs", amendment 2026-11-03, line 146); the WA-05 decision for guest power has no record in `docs/` (`docs/implementation/wiring-audit.md:290`), so it is not a precedent to copy. |
| PV-03k | **Threat-model update** for the new server path to propose a HIGH action (D1a), the admin-only local-entry RPCs (D3a) and the catalog trust chain (D2a) | `docs/threat-model.md` | `docs/threat-model.md` **yes** | New rows next to the existing "Compromised web process" row (`docs/threat-model.md:54`) and risk row (`:58`): a compromised server can propose, but not approve, an image preparation; a server-originated local entry is refused by role; unsigned or rolled-back catalog refused, and a catalog the executor could not verify loads nothing | Doc check: each row names the package and test that enforces it (PV-03b, PV-03c). |

Order: PV-03j (ADR amendment) and PV-03k (threat model) are decision records
and come first, with PV-03e (catalog source) and PV-03a (contract); they are
the reviewable basis for the protected code. PV-03b depends on PV-03a. PV-03c,
PV-03d, PV-03f, PV-03g and PV-03h depend on PV-03b. PV-03i comes last.

**Protection note:** the executor, release-wiring, proto, CLI, ADR and threat
model tickets (PV-03a-d, PV-03j, PV-03k) need a human maintainer review. The
server, client and UI tickets (PV-03f-h) do not appear on the protected list,
but they carry the approval boundary: the server forwards requests and never
approves. PV-03h also carries the rendering check, because it shows catalog
data from the executor.

## 5. Status of the existing merged claims

`README.md:66` and `docs/status.md:16` say guest provisioning is merged. That
is true for the deploy profiles, the wizard and the cloud-init and enrollment
code. It is not true for the end-to-end path, which needs the tickets above.
Until PV-03 lands, the status line should say so; this paper does not change
those lines, because they are outside the change allowed for this ticket.

## 6. Decisions requested

1. Accept D1 (a): Propose/Commit RPCs for `server` and `admin`, approval by
   the user only.
2. Accept D2 (a): catalog loaded at executor start from the release bundle
   directory, fail closed on a missing, unverifiable or rolled-back catalog
   (no catalog loaded, process still starts), with the file layout settled
   in PV-03e.
3. Accept D3 (a): local entries via admin-only RPCs called by the `nebula`
   CLI over the admin socket on the executor host; the executor writes and
   persists them. No file written by the CLI.
4. Accept D4 (a): read-only Images page as the first step, with the rendering
   check in PV-03h. `ListPVEImages` is readable by `server` and `admin` only.
   Accept D4 (b) in the same ticket as far as the generation is concerned:
   the wizard takes the generation from the executor record.
5. Accept D5 (existing flow, narrowed): re-preparation through a new proposal
   only after a gone or changed template (`ErrPveTemplateNotPrepared`,
   `ErrPveTemplateChanged`); every other `BindTemplate` error refuses it. No
   operator record removal and no new write path to `pve-templates.json`.
6. Accept the follow-up tickets PV-03j (ADR 0008 amendment) and PV-03k
   (threat-model update) before PV-03a-b start.
