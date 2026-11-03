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
decisions must be re-made. `trust-builtins` reviews the executor's locally
verified release bundle in one step and commits it atomically.

**Which store is authoritative for risk.** The executordb
`trusted_artifacts` table stays the only trust the risk policy
(`internal/riskpolicy`, `ArtifactRisk`) reads. The built-in trust store
(`internal/executor/trust`) holds retained bytes, provenance and
tombstones; its package documentation says retention confers no execution
authority, and it does not persist the admin's retain/retire decisions,
so it cannot be the authority. ADR 0007 makes bulk trust a convenience
over the existing individual trust ("existing individual trust operations
remain available", "trust may restore declared risks"), and retirement
must revoke authority; both follow from writing the same exact entries.
A commit therefore records, after the store commit, one `trusted_artifacts`
row per action of every new, changed or reactivated version — exact
(action ID, module version, artifact SHA-256, declared risk), the same row
`nebula artifact trust` writes, `trusted_by` = `admin:uid<UID>`, label
`built-in release <version>` — and deletes every row of each retired module
version in the same SQLite transaction (`executordb.ApplyBuiltinTrust`).
No version ranges. Unchanged modules add nothing; an action must belong to
its own module family (`trust.ArtifactTrustFor`). Previously (before this
change) a commit wrote only the store, so built-ins stayed HIGH.

Ordering and failure: the executor first derives and validates the rows
(`CheckBuiltinTrust`), the manifest digest and the retain/retire decisions
(`trust.CheckDecisions`), lists the rows the retirement will delete
(`BuiltinTrustRows`) and writes a write-ahead record
(`trust.PendingFile` in the store directory: base generation, digest, the
change and those rows). Then it deletes the retired versions' rows,
commits the store, applies the rows (retiring again in the same
transaction) and removes the record. Revoking before the store commit is
fail closed: no failure leaves a retired version trusted while the store
no longer lists it (previously, in round 1 of this change, the rows were
deleted only after the store commit, and before that a re-run could not
repair a failure because the modules were then unchanged).

Failures after the revoke return `*BuiltinTrustCommitError` and are
audited. Store commit failed (`ErrBuiltinTrustStoreCommit`, audit
`builtin_trust_store_failed`): the revoked rows are re-inserted at once;
if that fails the record stays. Apply failed after the store committed
(`ErrBuiltinArtifactTrust`, audit `builtin_trust_artifacts_failed`): the
new versions stay at the untrusted floor and the record stays. The next
`ReviewBuiltinTrust` resolves a record first (audit
`builtin_trust_pending_recovered`): store still at the base generation →
restore the rows; store's active versions are the record's new versions →
apply the change; otherwise → repeat only the retirements (fail closed).
`CommitBuiltinTrust` refuses while a record exists. Recovery therefore
needs no artifact file: module artifacts are built by the executor
(`modulelock.Artifact`, prelude plus script) and are not exported anywhere
an admin could pass to `nebula artifact trust`.

Wiring: `cmd/nebula-executor` calls `Service.SetBuiltinTrust` with
`NewDirBuiltinTrust(<-builtin-trust-dir, default <data-dir>/trust>,
<-builtin-bundle-dir, default /usr/share/nebula/release>,
release.Anchors(), time.Now, executor.db)`. If the store cannot be opened
the executor logs a warning and runs without built-in trust (review and
commit Unimplemented, status UNAVAILABLE). Previously production never
wired it, so `GetBuiltinTrustStatus` always answered UNAVAILABLE.

`cmd/nebula/trust_builtins.go`:

- Runs as a local admin user (refuses root) and uses the executor RPCs
  `ReviewBuiltinTrust` and `CommitBuiltinTrust`; the executor reads the
  bundle only from its configured directory (`builtins.tar` plus
  `release-manifest.json` and `release-manifest.json.sig`, checked against
  its trust roots by `release.ReadBundleDir`). Previously it ran as root,
  opened the store directly with `--bundle`/`--store` and chowned it back;
  those flags are gone.
- The command always shows the review first (Safety Scanner floors applied,
  artifact hashes, no commit yet). If every action is unchanged it stops
  with "no changes".
- Commit is **atomic** for the store and digest-bound: the executor only
  commits a review it delivered in full, at the same store generation.
  With `--yes-digest DIGEST` the commit is non-interactive (old versions
  handled by `--pin name@ver` / `--retire name@ver`); without it the
  command prompts for the old versions to retain or retire and then for
  the manifest digest (empty aborts).
- Audit: the executor logs `builtin_trust_committed` to the signed event
  log with the admin UID from peer credentials, manifest digest, release,
  generation, every old/new module tuple, every trusted and revoked
  artifact tuple, and the retained, retired and collected versions. No
  script content.
- Retain keeps the old version's trust rows and protects its bytes from
  this commit's garbage collection (pins are not persisted). Retire deletes
  the old version's trust rows; because the executor rechecks risk on every
  run, permits, read leases and schedule grants bound to it fall to the
  untrusted floor and stop running at their old risk. They are never
  retargeted; revoke them and approve replacements for the new versions.
- Trusting a built-in at its declared risk does not change how its runs are
  approved; the Safety Scanner findings and the host criticality floor still
  apply on every run.

Flags: `--yes-digest DIGEST` (non-interactive commit), `--pin name@ver`
and `--retire name@ver` (repeatable, only with `--yes-digest`).

Known gap: built-in versions committed with the old root-run command have
no `trusted_artifacts` rows and a later review reports them unchanged, so
they stay untrusted until the next changed release or a per-action
`nebula artifact trust`.
