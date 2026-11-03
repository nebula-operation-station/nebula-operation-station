# Preset guest host key: implementation plan

Status: plan by Claude, 2026-11-03, for [ADR 0008 amendment 1](../adr/0008-guest-provisioning.md#amendment-1-2026-11-03-preset-guest-host-key).
Nothing below is implemented. The amendment is **Proposed, not accepted**
(revised 2026-11-03 after review): the preset private key is probably
readable by every `VM.Audit` holder through PVE's `cloudinit/dump` endpoint
until cleanup. PK-10a (lab check of that endpoint) and PK-00 (maintainer
acceptance with mitigations M1 and M2, and spec revision) gate every other
ticket. (c) is not viable whenever M1 or M2 cannot hold, including M1
failing or an endpoint M1/M2 do not cover; the tickets below are then
dropped (see the amendment, "If the lab check fails"). (Previously: only if
PK-10a confirmed the exposure and M2 could not be built.)

## Summary

- The executor generates an ed25519 host key pair per provisioned guest. It
  persists only the public key, then writes a per-guest vendor-data snippet
  through the PVE node's SSH enrollment into an operator-provisioned,
  node-local snippet storage. It references the snippet with
  `cicustom: vendor=…`.
- `preset` is offered only if no principal besides NOS's tokens and
  `root@pam` holds `VM.Audit` on the guest path or `Datastore.Audit` on the
  snippet storage, including grants inherited from `/storage`, `/` or a pool
  that contains the storage (M2), and
  `cicustom` plus the snippet are removed as soon as the start task returns
  (M1).
- The join pins the recorded public key before first contact. A mismatch
  stops the join. There is no automatic fallback to review.
- The first post-enrollment step rotates the key over the pinned channel.
  Rotation limits later use of leftover copies; it cannot undo a theft
  before the join, because the rotated key is learned over the channel
  bound to the preset key.
- Fingerprint review stays the default wherever the preset path is not set
  up.

## Current code this builds on

- `internal/pveapi/write_config.go`: allowlisted `ConfigRequest`, which has
  no `cicustom` and cannot delete fields.
- `internal/executor/pve_provision.go`: steps clone → config → resize →
  start, with UPIDs stored before each step, and `AutomationKey` in
  `sshkeys`.
- `internal/executor/pve_join.go`: join methods `agent`/`review`.
  `PveGuestAgentCredentials` has no implementation, so production joins use
  review.
- `internal/deployprofile`: bootstrap module order. `ssh-hardening` and the
  other modules run after enrollment.

## Tickets

Protected paths (`.github/protected-paths.txt`) are marked **P**.

| Ticket | Scope | Files | Acceptance tests | Depends on |
| --- | --- | --- | --- | --- |
| PK-00 | Maintainer accepts amendment 1 (or records it as not viable) after PK-10a and answers its open questions. Spec revision: spec 06 (transient guest host key custody: never at rest on the executor), spec 07/11 (snippet put/remove node action, `cicustom` step, rotation as reserved action, risk unchanged), spec 08 (preset enrollment, rotation re-pin over the pinned channel), spec 16 item 3 (preset as a third way to avoid blind trust) | `docs/spec/*` **P**, ADR status | Spec links resolve; every new authority is listed; the decision records the PK-10a result; M1 and M2 stay required in every case | PK-10a |
| PK-01 | `pveapi`: `ConfigRequest.CIVendor` (volume ID `<storage>:snippets/<file>`, storage ID and file name allowlisted, no other `cicustom` parts). Typed `DeleteConfigField` for `cicustom` only. Storage read that returns type, content and nodes. | `internal/pveapi/write_config.go`, `write_config_test.go`, new `write_delete.go` + test | httptest: encoding, rejection of `user=`/`network=`/`meta=`, of path traversal, foreign content type and over-long names; delete refuses any other field; no raw path input | PK-00 |
| PK-02 | Executor registry: per-remote/node snippet storage (`storage_id`, directory, node's enrolled host ID and fingerprint). Admin CLI `nebula pve snippets set|remove`. Registration verifies over the read token that the storage is type `dir`, has content `snippets` and is available on the node, and refuses shared types (nfs, cifs, cephfs, glusterfs, pbs) and any storage flagged `shared 1`. | `internal/executordb/` **P**, migration, `internal/executor/` **P**, `cmd/nebula/` **P** | Shared type refused; `dir` with `shared 1` refused; mismatched node refused; host link must match a pin; only the admin UID can set or remove; audit without secrets | PK-00, PK-01 |
| PK-03 | Vendor-data renderer and key generation: a deterministic YAML renderer from typed input only (ed25519 pair, fixed drop-in). The key pair comes from `crypto/ed25519` plus `ssh.MarshalPrivateKey`. A `Secret`-style wrapper never prints the private part. | New `internal/cloudinitseed/` | Golden output (with a fixed test key generated in the test, never a fixture secret); no caller string reaches the YAML; `%v`/JSON redaction; fuzz parse round trip; size limit constant | PK-00 |
| PK-04 | Node actions `pve.snippet.put` / `pve.snippet.remove`: built-in SSH actions, content on stdin. The directory comes from the registry and the name matches `nos-<remote>-<vmid>-<gen>.yaml`. The file is a temporary file (0600, root) renamed into place; symlinked or non-root directories are refused. The directory must be on a local filesystem (type allowlist). `pve.snippet.stat` returns absent or the fingerprint of the parsed `ed25519_public` entry, never private data. `put` refuses an existing name unless `replace=true`, which is accepted only for the exact job name and renames atomically. Results carry the path and fingerprint only. | `internal/executions/actions/` (+ script), tests | Symlinked directory, foreign owner, network filesystem, existing name without `replace` and oversize input refused; `replace` for another name refused; stat output never contains private data; output never contains the content; retry class `reconcile-first` | PK-02, PK-03 |
| PK-05 | `pve.guest.provision` with `hostkey_method` (`preset`/`review`) bound in the parameters (plan version 2). New first steps: generate, persist the public key (fsync), snippet put. Config gets `cicustom`. The node's host ID and fingerprint are bound. M2: ACL read at proposal and again before the config step, for the guest path (`VM.Audit` on `/vms/<vmid>`, `/vms`, `/`, the guest's pool) and for the snippet storage (`Datastore.Audit` or any other `Datastore.*` privilege on `/storage/<snippets>`, `/storage`, `/` and every pool containing the storage; previously `Datastore.Audit` only); any other `VM.Audit` or `Datastore.*` holder, unknown role or unreadable ACL binds `review`, a change after approval stops the plan. Reconciliation before any start dispatch: stat; matching fingerprint, recorded key younger than `presetKeyMaxAge` (named constant, measured with the injected `Now`) and job not failed → adopt; the same age check runs right before start dispatch and replaces an over-age key; absent, unparsable, other, or key at or over the bound → new pair, persist (fsync), put with `replace=true`. After start dispatch: no adopt, no replace. M1: clear `cicustom` and remove the snippet right after the start task returns OK; a failed M1 step gets the same retry and flag as failure cleanup and the join is not marked done while the flag is set. Cleanup authority: the permit covers the job's own compensating steps for exactly its recorded target (remote, node, VMID, generation, snippet storage, directory and name recorded at write time); a permit or registry refusal does not revoke it; cleanup uses the recorded path, never the current registry; a target that no longer matches (VMID reused, node gone or re-enrolled) → cleanup refuses and flags "snippet cleanup pending". Failure cleanup: on every failure path before start (put, clone, M2 recheck, config, resize, permit or registry refusal, cancellation, restart finding the job failed, start task failed) remove the snippet and clear `cicustom` if set, automatically; the recorded key is revoked and never adopted or pinned; failed removal is retried with exponential backoff (30 s up to 10 min, named constants, survives restart) and the run flagged "snippet cleanup pending". The executor never calls `cloudinit/dump` for a preset guest. | `internal/executor/pve_provision.go` **P**, `internal/executordb/` **P**, tests | Method frozen after approval; private key never in DB, log, result or audit (scan in test); lost put that did succeed → adopted by fingerprint; matching snippet with a recorded key at or over `presetKeyMaxAge` → not adopted, replaced with a new pair; with a fake clock, a key one second below the bound is adopted and one at the bound is not; slow clone or resize that pushes the key over the bound → replaced before start dispatch; each failure path before start (one test per step listed above) → snippet removed and `cicustom` cleared without operator action, key revoked; reconciliation after a failure never adopts the revoked key; removal failure → retried with backoff, run flagged, no adopt; M1 removal or `cicustom` clear failing after a successful start → retried, run flagged, join not marked done; permit or registry refusal → cleanup still runs on the recorded target; registry changed after approval → cleanup uses the recorded directory; VMID reused or node gone → cleanup refused, flagged; lost put that failed or wrong file → replaced with a new pair; crash between persist and put converges; after start dispatch → no adopt or replace; M2 refusal binds `review`, one test per inherited path: for a foreign `VM.Audit` holder on `/vms/<vmid>`, on `/vms`, on `/` and through the guest's pool (previously a single `VM.Audit` test), and for a foreign `Datastore.Audit` holder on the snippet storage granted directly, on `/storage`, on `/` and through a pool containing the storage; a foreign holder of another `Datastore.*` privilege on the snippet storage → `review`; ACL change after approval → stop; cleanup runs right after start; registry change after approval → refuse | PK-01, PK-02, PK-04 |
| PK-06 | Join method `preset`: pin the recorded key and probe; a mismatch is `ErrPveJoinKeyMismatch` with no automatic review. An explicit operator review enrollment shows "preset key not presented". | `internal/executor/pve_join.go`, `pve_join_rpc.go` **P**, server join UI | Matching key → enrolled with no review; other key → stop; review only on explicit request, HIGH; the agent path is unchanged and still without a credential | PK-05 |
| PK-07 | Reserved action `nebula.host_key.rotate`: a guest script generates a new ed25519 key and returns its public key (validated). The executor re-pins old → new in one transaction, moves the criticality record and checks the new pin with a fresh connection (not a proof against a holder of the preset key; see amendment decision 6). The host flag "bootstrap key not rotated" blocks secret-bearing steps. | `internal/executor/` **P**, `internal/executordb/` **P**, `internal/sshtransport/` **P** if needed, action script, tests | Rotation only over a session bound to the old pin; malformed or duplicate key refused; crash between re-pin and verify reconciles; secret-bearing step refused before rotation | PK-00, PK-06 |
| PK-08 | Remaining cleanup (the early cleanup M1 and the automatic failure cleanup are part of PK-05; previously all cleanup ran after rotation and failed provisionings kept their snippet until an operator removed it): an operator action re-triggers removal of a snippet flagged "snippet cleanup pending" (failure cleanup or a failed M1 step); the run page lists such snippets prominently. A bootstrap step after rotation removes the cached vendor-data in the guest. Operator guide note: remove the `99-nebula-hostkey.cfg` drop-in and host keys before turning a guest into a template. | `internal/executor/` **P**, `modules/bootstrap/`, tests | A missing snippet is reported, never fatal; the operator action is a manual retry only, never the sole removal path (previously: "nothing is automatic for failed provisionings"); vendor-data cache removed only after rotation | PK-04, PK-07 |
| PK-09 | UI and operator docs: the wizard and review step show the host-key method; the run page shows `preset written`, `pinned`, `rotated`, `cleaned up`. Operator guide for creating the node-local snippet storage. | `internal/web/ui/`, `web/templates/`, `docs/operator/proxmox.md` | Escaped text, CSP; review default visible when preset is unavailable | PK-05 … PK-08 |
| PK-10a | Lab check that gates acceptance (maintainer, no agent job), per supported PVE 8/9 minor version: does `GET /nodes/{node}/qemu/{vmid}/cloudinit/dump` with each accepted `type` (`user`, `network`, `meta`, `vendor` where present) return the content of a `cicustom` snippet, tested with a token that has only `VM.Audit`; can any storage content or download endpoint return a `snippets` volume or the generated cloud-init volume with `VM.Audit`/`Datastore.Audit` only, and which other `Datastore.*` privileges (for example `Datastore.AllocateSpace`, `Datastore.AllocateTemplate`) allow listing or downloading it; can the read token read `/access/acl` (M2); does clearing `cicustom` on a running guest regenerate the drive before cloud-init read it (M1) | Notes in this file and the ADR | A written yes/no per question and version; (c) is not viable whenever M1 or M2 cannot hold, including M1 failing or an endpoint M1/M2 do not cover, and the amendment then moves to "not viable" (previously: only if dump rendered snippet content and M2 was not possible) | — |
| PK-10 | Remaining lab verification (maintainer, no agent job), per supported PVE 8/9 minor version and image (Ubuntu 22.04/24.04, Debian 12/13): ACL needed for `cicustom` volume access; merge of `cicustom vendor=` with PVE's generated user-data; whether cloud-init drive regeneration happens at start; instance-id change when `cicustom` is removed, including which per-instance modules then re-run (users and groups, `set-passwords` from `cipassword`, authorized keys) and whether that changes anything NOS set up; vzdump handling of cloud-init drives; behaviour after HA move | Notes in this file and the ADR | Every *verify* in the amendment answered or the feature stays disabled | PK-01 |

## Order

PK-10a → PK-00 → PK-01, PK-03 (parallel) → PK-02 → PK-04 → PK-05 → PK-06 → PK-07 →
PK-08 → PK-09. PK-10 runs alongside PK-01. No production remote enables
`preset` before PK-07 (rotation) and PK-10 are done.

## Not in scope

- A guest-agent credential (option a): it stays unimplemented.
- The fetch-once channel (path ii) and the per-guest seed ISO (path iii-a).
  The second is open question 2 of the amendment.
