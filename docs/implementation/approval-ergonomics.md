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
  executor and refuses to approve if the typed plan, any member's artifact
  bytes or any parameters hash differs from the reviewed digest
  (`cmd/nebula/batch.go`). Nothing is truncated in the review.
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
decisions must be re-made. `trust-builtins` does that in one review from a
locally verified release bundle, instead of one `nebula artifact trust` per
action.

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
- The commit result reports what was pinned, retired and the retirement
  audit (admin UID, old versions).
- Trusting a built-in at its declared risk does not change how its runs are
  approved; the Safety Scanner findings and the host criticality floor still
  apply on every run.

Flags: `--bundle DIR` (required), `--store DIR` (the built-in trust store,
default), `--yes-digest DIGEST` (non-interactive commit), `--pin name@ver`
and `--retire name@ver` (repeatable).
