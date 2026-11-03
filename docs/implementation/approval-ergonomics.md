# Approval ergonomics (ADR 0007): batches, sessions and built-in trust

ADR 0007 adds four operator ergonomics on top of the M0 approval model, each
still executor-owned and digest-bound. Read grants (the read-only standing
grant, `read-grant-v2`) are documented in
[`schedule-grants.md`](schedule-grants.md). The operator-facing walkthroughs
are in the admin guide, sections 8.2, 9.2, 9.4 and 11.1.

## Batches (exact batches)

A **batch** is one frozen plan of up to 100 member runs
(`canonical.MaxBatchMembers`), staged into up to 20 stages
(`canonical.MaxBatchStages`). It is proposed as a single canonical document
and approved by its SHA-256 digest, so a whole rollout is approved at once
instead of one run at a time.

`internal/permit/batch`:

- A batch **grants no execution rights**: each member still needs its own
  claim, dispatch and stage gate. The approval binds the plan, not the
  ability to run.
- The plan is frozen: the CLI re-derives the canonical plan from the
  executor and refuses to approve if the canonical plan's digest differs
  from the requested one, if any typed member's member or execution ID
  differs from the canonical plan, or if any member's parameters do not
  hash to the planned parameters hash (`reviewBatch` in
  `cmd/nebula/batch.go`). It does not re-check artifact bytes; those are
  bound by the artifact hash inside the digested plan. Nothing is truncated
  in the review, but the script itself is not shown.
- A batch whose members include a **CRITICAL** run is rejected as a whole
  (`ErrCritical`); CRITICAL members must be approved individually.
- After approval, stages open one at a time with `nebula batch stage N
  <digest>` (N from 2 to `MaxBatchStages`); a member can be skipped with
  `nebula batch skip <member> <digest>`.

CLI (hardened path, full 64-hex batch digest):

```
nebula batch review <digest>         # show the executor's frozen plan
nebula batch approve <digest>        # approve the whole plan (rejects CRITICAL)
nebula batch stage N <digest>        # open stage N (2..MaxBatchStages)
nebula batch skip <member> <digest>  # skip a member
```

## Sessions (session policy)

A **privileged session** is a time-boxed window opened with a single
security-key assertion, during which LOW-risk operations are issued
automatically and logged (no per-operation key). MEDIUM and above still need
a key per operation.

`internal/permit/session.go`:

- Length is bounded to 15 minutes to 4 hours
  (`MinSessionLength` / `MaxSessionLength`); the executor default is 60
  minutes (`DefaultSessionLength` in `internal/permit/permit.go`),
  configurable with the executor's `-session-minutes` flag.
- The session challenge binds the operation, the configured duration, the
  deadline and a fresh nonce, so an approval from another domain cannot be
  replayed as a session extension.
- The same `session_extension` operation reopens an expired session.

## Built-in trust (`trust-builtins`)

After an upgrade the built-in actions' versions change and their trust
decisions must be re-made. `trust-builtins` reviews a locally verified
release bundle in one step and commits it to the built-in trust store
(`internal/executor/trust`). **It does not replace `nebula artifact
trust` today:** the risk policy (`internal/riskpolicy`) reads only the
executordb `trusted_artifacts` table (`ArtifactRisk`), which only
`TrustArtifact` / `nebula artifact trust` writes. Nothing copies the
built-in trust store into that table, so built-ins stay untrusted for
risk purposes until they are trusted per action. The store is read by
`GetBuiltinTrustStatus`, which drives the web "Built-ins are untrusted"
banner.

`cmd/nebula/trust_builtins.go`:

- The bundle must come from a **locally verified NOS release** (not a
  server-exported directory): `builtins.tar` plus `release-manifest.json`
  and its `release-manifest.json.sig`, read and checked against the
  executor's trust roots (`release.ReadBundleDir`).
- The command always shows the review first (Safety Scanner floors applied,
  no commit yet). If every action is unchanged it stops with "no changes".
- Commit is **atomic**: one digest-bound confirmation commits the whole
  review, or none. With `--yes-digest DIGEST` the commit is non-interactive
  (old versions handled by `--pin name@ver` / `--retire name@ver`); without
  it the command prompts for the old versions to pin or retire and then for
  the manifest digest to commit (empty aborts).
- It runs as root (`sudo`): it opens and writes the built-in trust store
  directly (default `/var/lib/nebula/executor/trust`), not through the
  executor socket, and chowns the store back to the executor user after the
  commit. It does not call the executor's `CommitBuiltinTrust` RPC.
- The commit result — admin UID, generation, every old/new trust tuple and
  the pinned, retired and collected versions — is printed to standard
  output only; the command writes no audit record or event. (The
  `CommitBuiltinTrust` RPC logs its own "built-in trust committed" line.)
- Pin and retire only steer the trust store's garbage collection in this
  one commit (`internal/executor/trust/bulk.go`, `admit.go`): pins are
  passed to that `AdmitPinned`/`collect` call and are not persisted, so a
  later admission can collect a version pinned now once it is beyond the
  two most recent predecessors and past its 90-day retention; retired
  versions are simply not protected.
  Retiring revokes no permit, read grant or schedule grant; those must be
  revoked separately (web *Revoke*, `nebula schedule revoke` for legacy
  grants, or `nebula lock`).
- Trusting a built-in at its declared risk does not change how its runs are
  approved; the Safety Scanner findings and the host criticality floor still
  apply on every run.

Flags: `--bundle DIR` (required), `--store DIR` (the built-in trust store,
default), `--yes-digest DIGEST` (non-interactive commit), `--pin name@ver`
and `--retire name@ver` (repeatable).
