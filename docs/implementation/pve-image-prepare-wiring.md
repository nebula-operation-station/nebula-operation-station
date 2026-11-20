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

**Result:** the chain `catalog -> prepare -> record -> bind -> clone` has a
verified middle (`Prepare`, `BindTemplate`) and no way in at either end.

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
   but does not say how a removed or broken template is prepared again.
   `Prepare` refuses when a valid record exists (`pve_images.go:425-431`);
   the path for "record exists, template gone" is not specified.

Items 1-4 block PV-03. Item 5 can be decided in the PV-03 ticket itself.

## 3. Open decisions, variants and recommendation

### D1. RPC form for `pve.image.prepare`

| Variant | Who may propose / commit | Consequence for roles | Consequence for the threat model |
| --- | --- | --- | --- |
| (a) Propose/Commit RPCs, like guest power and provisioning | `server` and `admin` for both | Same pattern as `roles.go:206` (guest power, WA-05 variant (a)) and `roles.go:218-219`. The web UI can drive it. | The server can start a preparation, but cannot approve it: HIGH needs the user's security-key assertion, or the CLI in hardened mode (the note at `roles.go:198-205`). The catalog SHA-256 pins the image, so a compromised server can only ask for catalog images, not arbitrary URLs. |
| (b) Admin-only Propose/Commit | `admin` only | The server's role table does not change. The UI must use the admin channel for this one step. | Smaller server surface. More friction, and a second, different way to run the same action. |
| (c) Admin CLI only | none on the RPC surface | No new RPC, no proto change. The UI can only show status, read-only. | Smallest network surface. The operator must be on the executor host. No server-side feedback path. |

**Recommendation: (a).** It matches guest power and guest provisioning, and
the permit remains the gate. The server never approves, and the catalog
digest and the HIGH approval limit what a compromised server can do. (c)
remains the fallback if the team wants no server write path for HIGH
actions at all.

### D2. Loading the signed catalog

| Variant | Mechanism | Consequences |
| --- | --- | --- |
| (a) At executor start, from the release bundle directory | Read `image-catalog.json` and its signature from `defaultBuiltinBundleDir` (`cmd/nebula-executor/builtin_trust.go:19`), verify with the active release roots, call `LoadSigned`. | Follows the existing built-in trust flow (ADR 0007 E15/E16). The rollback floor in `LoadSigned` (`pve_images.go:124-151`) already holds across restarts. A new catalog takes effect with a release install and a restart. No new RPC. |
| (b) Separate admin step | A `nebula` command or RPC that hands a signed file to the executor at any time. | Allows catalog updates without an install, but adds a write path for catalog data and another role entry. Needs its own permit or policy decision. |
| (c) Runtime fetch from the vendor or from the network | Executor downloads the catalog. | **Rejected.** It would make the trust anchor the network path and not the release signature, and it is not in the E15 chain. |

**Recommendation: (a).** Open sub-question, to settle in PV-03: whether the
catalog is a separate signed file (`image-catalog.json` plus a signature, as
`catalog.go:29` implies) or a document inside `release-manifest.json`. The
separate file is simpler to verify with the existing `VerifyCatalog`. Either
way the release tooling has to produce it, which is not in place today.

### D3. Local entries

| Variant | Mechanism | Consequences |
| --- | --- | --- |
| (a) Admin CLI on the executor host only | `nebula` command run on the executor host writes a local entry to a file in the data directory; the executor loads it at start. | Local entries never travel through the server. The file must be persisted, which `AddLocal` does not do today (`pve_images.go:157`), so PV-03 adds persistence (e.g. `pve-catalog-local.json` beside `pve-catalog.json`, `pve_rpc.go:297`). Validation stays in `release.ValidateImage(img, true)`. |
| (b) RPC from the server | Server proposes a local entry to the executor. | **Rejected.** A server-originated entry widens the set of images the executor will download and turns server compromise into image injection, even though preparation is HIGH. |
| (c) Deploy wizard form for local entries | Form in `internal/web/ui/deploy.go`. | Same as (b), with the UI added. Rejected for the same reason. |

**Recommendation: (a)**, which matches the wording in the proposal: local
entries only via CLI on the executor host. This variant needs the persistence
added to `PveImageCatalog`, which is in the protected `internal/executor/`
path.

### D4. Operator visibility

| Variant | Consequences |
| --- | --- |
| (a) Read-only "Images" page under `/deploy` (catalog entries, template records, trust) | Operator can see which SHA-256 a template was prepared from. Needs a read RPC (`ListPVEImages`) and a read role. |
| (b) Wizard drop-downs for the OS image and the template SHA-256 | Removes two free-text fields. Depends on (a)'s data. |
| (c) Nothing new; document the CLI | Leaves the wizard as is. |

**Recommendation: (a) first, (b) in the same ticket as the page if it is
small.** This is the page the proposal names (`internal/web/ui/`).

### D5. Re-preparation (decide inside PV-03)

**Recommendation:** a template that is gone or changed is handled by the
existing `ErrPveTemplateChanged` path, and re-preparation is a new
`pve.image.prepare` with a new generation, after the operator has removed the
old record through the CLI. This keeps `BindTemplate` as the single check.

## 4. Follow-up tickets

Protection status is taken from `.github/protected-paths.txt`.

| # | Ticket | Paths | Protected? | Scope | Required test (real path) |
| --- | --- | --- | --- | --- | --- |
| PV-03a | RPCs `ProposePVEImagePrepare` / `CommitPVEImagePrepare` (D1a) and read RPC `ListPVEImages` (D4a) | `proto/nebula/executor/v1/executor.proto`, generated `internal/rpc/executorv1/` (via `make generate`) | `proto/` **yes**; generated code follows `proto/` | Messages and service methods only | `buf lint` and the generated-code check (`make check`) |
| PV-03b | Handlers, role table, per-method entries, `pveImagePrepare` wiring, catalog load function, local-entry persistence | `internal/executor/roles.go`, `internal/executor/pve_rpc.go`, `internal/executor/pve_images.go`, `internal/executor/integrity_lock.go` (per-method tables at `:320`, `:427`) | `internal/executor/` **yes** | Executor side of D1-D3 | Executor RPC test against the PVE fake (httptest on loopback, see `internal/executor/pve_admin_test.go`): propose, approve (permit), commit, then `BindTemplate` succeeds on the recorded template. Then a provisioning proposal on that template no longer returns `template is not prepared`. Security rejections: wrong role, unsigned or rolled-back catalog, local ID without the prefix, oversize catalog. |
| PV-03c | Catalog load at executor start (D2a) | `cmd/nebula-executor/` (builtin trust wiring, `builtin_trust.go:19`) | `cmd/nebula-executor/` **yes** | Read `image-catalog.json` and its signature from the bundle directory, call `LoadSigned` | Start-up test with a temporary bundle directory (no `/usr/share` access): signed catalog loads; a catalog with a lower sequence is refused after restart. Then the PVE-fake test of PV-03b runs through the started binary's wiring. |
| PV-03d | CLI for local entries (D3a) and, if chosen, a prepare command | `cmd/nebula/` | `cmd/nebula/` **yes** | `nebula` subcommands on the executor host only | CLI test: add and remove a local entry, entry survives an executor restart, ID without `local-` refused. |
| PV-03e | Release tooling produces `image-catalog.json` and its signature (decides the open sub-question in D2) | `internal/release/` and `cmd/nebula-release-stage/` | **not on the list** (`internal/release` and `cmd/nebula-release-stage` are not in `.github/protected-paths.txt`; verify before starting) | Build and sign the catalog in the release pipeline | Round-trip test: staged catalog verifies with `VerifyCatalog` and loads with `LoadSigned`. |
| PV-03f | Server pass-through of the two RPCs | `internal/executorclient/` | **no** | Client methods for propose, commit, list | Client test against an in-process executor on a Unix socket in a temporary directory, or on loopback. |
| PV-03g | Server handlers that forward the RPCs and map errors | `cmd/nebula-server/` | **no** | Forward propose, commit and list; keep the approval on the user's key | Server handler test with a fake executor client: a server request cannot approve (the approval step needs the user's assertion). Then the PVE-fake end-to-end test of PV-03b, started from the server side. |
| PV-03h | "Images" page under `/deploy` (D4a) and drop-downs (D4b) | `internal/web/ui/` | **no** | Read-only list; optionally replace the two free-text fields | UI handler test: list shows catalog entries and records; the template SHA-256 and OS image fields accept only listed values. |
| PV-03i | Documentation update after the path works | `docs/operator/proxmox.md`, `README.md:66`, `docs/status.md:16` | `docs/adr/` and `docs/spec/` **yes**; `docs/operator/` and the two status lines are not on the list | Replace "Not available today" and the status wording | Doc check: every changed `path:line` grep-verified. |

Order: PV-03e (decides the catalog source) and PV-03a (contract) can run in
parallel. PV-03b depends on PV-03a. PV-03c, PV-03d, PV-03f, PV-03g and PV-03h
depend on PV-03b. PV-03i comes last.

**Protection note:** the executor, release-wiring, proto and CLI tickets
(PV-03a-d) need a human maintainer review. The server, client and UI tickets
(PV-03f-h) do not appear on the protected list, but they carry the approval
boundary: the server forwards requests and never approves.

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
   directory, with the file layout settled in PV-03e.
3. Accept D3 (a): local entries via CLI on the executor host only, persisted
   in a separate file.
4. Accept D4 (a): read-only Images page as the first step.
