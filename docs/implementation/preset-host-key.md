# Preset guest host key: implementation plan

Status: plan by Claude, 2026-11-03, for [ADR 0008 amendment 1](../adr/0008-guest-provisioning.md#amendment-1-2026-11-03-preset-guest-host-key).
Nothing below is implemented. PK-00 (maintainer acceptance and spec
revision) gates every other ticket.

## Summary

- The executor generates an ed25519 host key pair per provisioned guest. It
  persists only the public key, then writes a per-guest vendor-data snippet
  through the PVE node's SSH enrollment into an operator-provisioned,
  node-local snippet storage. It references the snippet with
  `cicustom: vendor=…`.
- The join pins the recorded public key before first contact. A mismatch
  stops the join. There is no automatic fallback to review.
- The first post-enrollment step rotates the key over the pinned channel.
  Then `cicustom` and the snippet are removed.
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
| PK-00 | Maintainer accepts amendment 1 and answers its open questions. Spec revision: spec 06 (transient guest host key custody: never at rest on the executor), spec 07/11 (snippet put/remove node action, `cicustom` step, rotation as reserved action, risk unchanged), spec 08 (preset enrollment, rotation re-pin over the pinned channel), spec 16 item 3 (preset as a third way to avoid blind trust) | `docs/spec/*` **P**, ADR status | Spec links resolve; every new authority is listed | — |
| PK-01 | `pveapi`: `ConfigRequest.CIVendor` (volume ID `<storage>:snippets/<file>`, storage ID and file name allowlisted, no other `cicustom` parts). Typed `DeleteConfigField` for `cicustom` only. Storage read that returns type, content and nodes. | `internal/pveapi/write_config.go`, `write_config_test.go`, new `write_delete.go` + test | httptest: encoding, rejection of `user=`/`network=`/`meta=`, of path traversal, foreign content type and over-long names; delete refuses any other field; no raw path input | PK-00 |
| PK-02 | Executor registry: per-remote/node snippet storage (`storage_id`, directory, node's enrolled host ID and fingerprint). Admin CLI `nebula pve snippets set|remove`. Registration verifies over the read token that the storage is type `dir`, has content `snippets` and is available on the node, and refuses shared types (nfs, cifs, cephfs, glusterfs, pbs). | `internal/executordb/` **P**, migration, `internal/executor/` **P**, `cmd/nebula/` **P** | Shared storage refused; mismatched node refused; host link must match a pin; only the admin UID can set or remove; audit without secrets | PK-00, PK-01 |
| PK-03 | Vendor-data renderer and key generation: a deterministic YAML renderer from typed input only (ed25519 pair, fixed drop-in). The key pair comes from `crypto/ed25519` plus `ssh.MarshalPrivateKey`. A `Secret`-style wrapper never prints the private part. | New `internal/cloudinitseed/` | Golden output (with a fixed test key generated in the test, never a fixture secret); no caller string reaches the YAML; `%v`/JSON redaction; fuzz parse round trip; size limit constant | PK-00 |
| PK-04 | Node actions `pve.snippet.put` / `pve.snippet.remove`: built-in SSH actions, content on stdin. The directory comes from the registry and the name matches `nos-<remote>-<vmid>-<gen>.yaml`. The file is a temporary file (0600, root) renamed into place; symlinked or non-root directories are refused. Results carry the path and fingerprint only. | `internal/executions/actions/` (+ script), tests | Symlinked directory, foreign owner, existing name and oversize input refused; output never contains the content; retry class `reconcile-first` | PK-02, PK-03 |
| PK-05 | `pve.guest.provision` with `hostkey_method` (`preset`/`review`) bound in the parameters (plan version 2). New first steps: generate, persist the public key (fsync), snippet put. Config gets `cicustom`. The node's host ID and fingerprint are bound. Reconciliation: after a lost put, regenerate and rewrite only while start has not been dispatched. | `internal/executor/pve_provision.go` **P**, `internal/executordb/` **P**, tests | Method frozen after approval; private key never in DB, log, result or audit (scan in test); lost put before start → new pair; after start → no rewrite; registry change after approval → refuse | PK-01, PK-02, PK-04 |
| PK-06 | Join method `preset`: pin the recorded key and probe; a mismatch is `ErrPveJoinKeyMismatch` with no automatic review. An explicit operator review enrollment shows "preset key not presented". | `internal/executor/pve_join.go`, `pve_join_rpc.go` **P**, server join UI | Matching key → enrolled with no review; other key → stop; review only on explicit request, HIGH; the agent path is unchanged and still without a credential | PK-05 |
| PK-07 | Reserved action `nebula.host_key.rotate`: a guest script generates a new ed25519 key and returns its public key (validated). The executor re-pins old → new in one transaction, moves the criticality record and verifies the new pin with a fresh connection. The host flag "bootstrap key not rotated" blocks secret-bearing steps. | `internal/executor/` **P**, `internal/executordb/` **P**, `internal/sshtransport/` **P** if needed, action script, tests | Rotation only over a session bound to the old pin; malformed or duplicate key refused; crash between re-pin and verify reconciles; secret-bearing step refused before rotation | PK-00, PK-06 |
| PK-08 | Cleanup after rotation: delete `cicustom` (PK-01) and run snippet remove (PK-04), both audited. An operator action removes the snippet of an abandoned provisioning. A bootstrap step removes the cached vendor-data in the guest. | `internal/executor/` **P**, `modules/bootstrap/`, tests | Cleanup only after rotation succeeded; a missing snippet is reported, never fatal; nothing is automatic for failed provisionings | PK-04, PK-07 |
| PK-09 | UI and operator docs: the wizard and review step show the host-key method; the run page shows `preset written`, `pinned`, `rotated`, `cleaned up`. Operator guide for creating the node-local snippet storage. | `internal/web/ui/`, `web/templates/`, `docs/operator/proxmox.md` | Escaped text, CSP; review default visible when preset is unavailable | PK-05 … PK-08 |
| PK-10 | Lab verification (maintainer, no agent job), per supported PVE 8/9 minor version and image (Ubuntu 22.04/24.04, Debian 12/13): ACL needed for `cicustom` volume access; merge of `cicustom vendor=` with PVE's generated user-data; whether cloud-init drive regeneration happens at start; instance-id change when `cicustom` is removed; vzdump handling of cloud-init drives; behaviour after HA move | Notes in this file and the ADR | Every *verify* in the amendment answered or the feature stays disabled | PK-01 |

## Order

PK-00 → PK-01, PK-03 (parallel) → PK-02 → PK-04 → PK-05 → PK-06 → PK-07 →
PK-08 → PK-09. PK-10 runs alongside PK-01. No production remote enables
`preset` before PK-07 (rotation) and PK-10 are done.

## Not in scope

- A guest-agent credential (option a): it stays unimplemented.
- The fetch-once channel (path ii) and the per-guest seed ISO (path iii-a).
  The second is open question 2 of the amendment.
