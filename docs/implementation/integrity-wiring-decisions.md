# Decision paper: wiring I1 status and the I2 scan chain (ADR 0015)

Status: **open, maintainer decides.** This paper decides nothing. Each open
point gives the question, what ADR 0015 says, what the code says today (with
file:line), the options, a recommendation and the consequence. Where the ADR
leaves a point open, this paper says so and does not present a choice as made.

Ticket: uf13 (autopilot). Covers gaps G12, G13, G14 and G38 in `out/gaps.md`
(that file is not in this clone; the gap IDs come from the ticket text).

Line numbers were checked against the tree at branch
`agent/uf13-integrity-wiring-paper` (based on `main`, 2026-11-21). They are
references for review, not stable identifiers; re-check them when a point is
decided.

## Summary

- **I2 (file integrity on hosts) has no working end-to-end chain.** The scan
  script exists and is embedded. The executor-side digest comparison of a
  server-supplied baseline list is registered and reachable. Everything between
  them (catalog entry, scheduling, scan result intake, retained records,
  approval, diff, findings, UI, notification) either has no production caller
  or is missing. Details in section 1.
- **I1 (self-check) cannot report "ok".** The server's own monitor has no
  admitted reference to check against, so every release-build run is reported
  as incomplete. The executor's status RPC exists and the server role may call
  it, but the server never does; only the admin CLI calls it.
- **Two ADR points are contradicted by the code** and need a maintainer
  decision before IG-05: the Lease allowlist already contains `fim.scan`
  (permit/lease.go:108), and the lease runner and proposal path both exclude
  actions with parameters, which `fim.scan` has (section 2 (d)).

## 1. Current chain (Ist-Kette)

| Step | Status today | Evidence (file:line) |
| --- | --- | --- |
| Script | Exists. Embedded, read-only per the contract, not run by anything. | `internal/fimscan/script.go:35` (`//go:embed scripts/fim_scan.sh`), `internal/fimscan/scripts/fim_scan.sh` |
| Catalog | **Missing.** `Action()` builds the contract, but it is not in `actions.Builtin`. The Builtin list (384–566) has no `fim.scan` entry. The comment on `Action` says it is not yet in Builtin or the allowlist; the allowlist part is stale (see (d) and section 4). | `internal/fimscan/script.go:77-81`; `internal/executions/actions/actions.go:384` (`var Builtin`), no `fim` entry in 384–566 |
| Lease | **Partly.** `fim.scan` is in the read-only allowlist and its lease entry is validated. But the lease runner and the proposal code skip any action with parameters, and `fim.scan` has two (`mode`, `profile`). So no lease can run it today. | `internal/permit/lease.go:104-108` (allowlist), `:122`, `:419`; `internal/permit/lease_fimscan.go:99` (`validateFimScanAction`); `internal/executions/leaserunner.go:93-94`; `internal/executions/readgrants_propose.go:178`; params `internal/fimscan/script.go:92-95` |
| Transport | **Limits do not agree.** Attached runs and the durable result read are capped at 1 MiB output and 10 min attached. The scan allows 128 MiB and 40 min. | `internal/hostrun/hostrun.go:39` (`MaxResult = 1 << 20`), `:41-42` (`MaxTimeout = 10 min`), `:211`; `internal/hostrun/durable.go:358,370`; `internal/fimscan/limits.go:13` (`MaxDocumentBytes = 128 << 20`); `internal/fimscan/script.go:30` (`ActionTimeout = 40 min`) |
| Parser | Built, no production caller. `Parse` is only called from tests. | `internal/fimscan/parse.go:33`; no non-test caller found |
| Retention | Built, no production caller. Merge of scan runs (`fimretain`), the retention store (`fimstore`) and `integritystore` are not called from production code. | `internal/fimretain/merge.go`; `internal/fimstore/store.go:128` (`Propose`); `internal/integritystore/integritystore.go`; `internal/fimresolve/resolve.go` (no production caller) |
| Baseline (digest) | **Partly wired.** The executor's `CompareBaselineList` stream builds a baseline from the streamed list and compares its digest with the executor-held approved digest. This RPC is registered on the gRPC service. It does not take its records from a scan run, because no scan run reaches the executor. The server-side `fimstore.Propose` also builds a baseline, without a production caller. | `internal/executor/integrity_baseline.go:153` (`NewBaseline`), `:355` (`CompareBaselineList`); `internal/executor/service.go:221` (`RegisterExecutorServiceServer`); `internal/fimstore/store.go:143` |
| Approval | **Missing.** `StoreApprovedBaselineDigest` (the only writer of the approved digest) has no production caller. No approval RPC, no approval screen, no `nebula integrity pending/approve`. | `internal/executordb/integrity_baseline.go:111`; no non-test caller |
| Diff | Built, no production caller. | `internal/fimbaseline/diff.go:111` (`Diff`) |
| Findings | Classes exist, no production caller. The executor writes its own tamper finding on a digest mismatch (`RecordBaselineTamper`), so the lock-related finding path is live. Severity is missing for one row (section 2 (e)). | `internal/fimfinding/classes.go`; `internal/fimfinding/doc.go:48-56`; `internal/executor/integrity_baseline.go:259` |
| UI | **Missing** for I2. The server has `/integrity/status` for its own I1 monitor only. No baseline or findings page. | `cmd/nebula-server/integrity.go:118-131`; `cmd/nebula-server/main.go:649` |
| Notification | `IntegrityGate` is built but has no production caller. The executor logs the tamper finding name with slog only. The notification kind exists in notifylog. | `internal/notify/integrity.go:194` (`NewIntegrityGate`); `internal/executor/integrity_baseline.go:264,271`; `internal/notifylog/notifylog.go:176` |

**I1 chain, for the same table:**

| Step | Status today | Evidence (file:line) |
| --- | --- | --- |
| Server self-check | Runs at start and every 60 min. Its reference loader always returns an error: a release build reports `no-admitted-reference` (ERROR, hashes nothing), a development build reports not-checkable. It cannot report "ok". | `cmd/nebula-server/integrity.go:53-61` (comment), `:65-80` (`newIntegrityMonitorAt`, `Load` at `:68-74`); `cmd/nebula-server/main.go:359-362` (`selfCheck`, comment says "no reaction here (IG-04)") |
| Executor status RPC | Exists, read-only, server and admin roles allowed. | `internal/executor/roles.go:257`; `internal/executor/integrity_lock.go:494` (`GetIntegrityStatus`) |
| Server calls executor status | **Never.** The only callers are the admin CLI. | `cmd/nebula/integrity_ack.go:39,88`; no server caller; the server's lock watcher uses `GetStatus`, not `GetIntegrityStatus` (`cmd/nebula-server/main.go:348-357`) |
| Server UI for I1 | `/integrity/status` shows the server monitor's result only. | `cmd/nebula-server/integrity.go:118-131` |

## 2. Open points

Each point: question, what the ADR says, what the code says, options,
recommendation. Nothing below is decided.

### (a) Who plans the scans (scheduling owner)

- **ADR:** the server's scheduler, or a collector role, "*verify* which one
  owns scheduling when IG-05 lands" (`docs/adr/0015-integrity-monitoring.md:493-494`).
  The executor authorizes and dials; the server or collector only triggers.
- **Code:** the executor already runs read leases through the lease runner
  (`internal/executions/leaserunner.go`), and the server's grant-proposal path
  (`internal/executions/readgrants_propose.go`) creates grants. No scan
  scheduler exists.
- **Options:**
  1. *Server schedules, executor runs.* The server creates a read grant for
     `fim.scan`; the executor's lease runner executes it. One trigger path,
     the same as other read actions.
  2. *Executor schedules itself* from a lease it holds. No server trigger at all.
  3. *Separate collector role.* New role, new trust boundary. The ADR does not
     name one; this would need an ADR amendment.
- **Recommendation:** option 1. It reuses the existing grant and lease path,
  so the scan gets the same bounds (interval floor, run budget) as other reads.
  The ADR wording stays as it is until IG-05 lands; the maintainer confirms
  the owner then.

### (b) Transport limits (1 MiB and 10 min against 128 MiB and 40 min)

- **ADR:** the 128 MiB document and the 40 min action timeout are chosen so
  that the scan fits (`docs/adr/0015-integrity-monitoring.md:624-627`). The
  ADR says spec 09's 1 MiB default needs an action-specific limit, "like ADR
  0011 D3". The spec revision is listed at `:1652`.
- **Code:** attached runs cap output at `MaxResult` = 1 MiB and attached
  timeout at 10 min (`internal/hostrun/hostrun.go:39,41-42,211`); the durable
  result read is capped at the same 1 MiB (`internal/hostrun/durable.go:358,370`).
  The scan's own constants are `internal/fimscan/limits.go:13` and
  `internal/fimscan/script.go:30`. 300,000 records at the record size in the
  ADR cannot fit in 1 MiB.
- **Options:**
  1. *Action-specific limit in hostrun* for `fim.scan` only (128 MiB output,
     a durable job for the 40 min run), with a spec 09 amendment first.
     Touches the protected `internal/hostrun/`.
  2. *Chunked result* (several documents, each under 1 MiB, reassembled and
     checked by the executor). New protocol framing; touches protected code
     and the spec.
  3. *Smaller document* (fewer fields, shorter encodings). Does not reach the
     required size for a full run with many records.
- **Recommendation:** option 1, with the spec 09 amendment and the ADR's
  limits as the only numbers. Option 2 only if the maintainer wants no
  per-action limit at all.

### (c) Who computes the baseline digest: server or executor

- **ADR:** the executor alone decides what goes into a baseline; the digest the
  admin approves is computed by the executor, never taken from the server
  (`docs/adr/0015-integrity-monitoring.md:1035-1060`).
- **Code:** `fimstore.Propose` computes the baseline and its digest on the
  server (`internal/fimstore/store.go:128` onward, `NewBaseline` at `:143`,
  `base.Digest()` used for the stored proposal). The executor has its own
  `NewBaseline` call in `CompareBaselineList` (`internal/executor/integrity_baseline.go:153`).
- **Options:**
  1. *Executor only.* Delete the server-side digest; the server keeps a
     display copy at most. The executor builds the proposal from its retained
     run and computes the digest. Matches the ADR.
  2. *Server proposes, executor re-checks at approval.* The server's digest is
     only a preview; the approval binds the executor's digest. Closer to the
     current code, but the ADR does not allow the server's digest to be the
     stored one.
- **Recommendation:** option 1. `fimstore` then has no digest logic on the
  server and becomes a view cache (or is removed). This is a protected-path
  change (`internal/executor/`, `internal/executordb/`).

### (d) Lease runner and proposal drop actions with parameters

- **ADR:** the grant freezes a profile ID and a mode, and the lease binds the
  exact action, script hash and parameters (`docs/adr/0015-integrity-monitoring.md:489-500`;
  `permit/lease_fimscan.go` implements the lease check).
- **Code:** the lease runner skips an action unless `da.ParametersHash` is
  empty and `len(a.Params) == 0` (`internal/executions/leaserunner.go:93-94`).
  The proposal path requires `len(a.Params) == 0` (`internal/executions/readgrants_propose.go:178`).
  `fim.scan` has `mode` and `profile` (`internal/fimscan/script.go:92-95`).
  Also `actions.Lookup("fim.scan")` fails today because the catalog entry is
  missing (section 1), so both checks drop it twice.
- **Options:**
  1. *Allow the one action:* accept `fim.scan` with its two fixed parameters
     when the grant's parameter hash matches the canonical parameters; reject
     every other parameter set.
  2. *Keep the generic rule* and give `fim.scan` a separate runner. More code,
     two lease paths.
- **Recommendation:** option 1, restricted to `FimScanActionID`, with tests
  that a foreign profile, a foreign mode and a wrong parameter hash are each
  rejected. The code is not protected (`internal/executions/`), but the
  lease semantics are ADR 0007 territory: the maintainer confirms the rule.

### (e) Missing severity row for non-critical paths

- **ADR:** the severity table row "Other changed or new file in `/etc` or a
  watched `/usr` root" is `high` (`docs/adr/0015-integrity-monitoring.md:1518`).
  Local software under `/opt` and `/usr/local` is always compared against the
  baseline (`:520`), but no row gives a severity for a change there.
- **Code:** `internal/fimfinding/doc.go:48-56` documents this gap.
  `Classes` returns `ErrNotCovered` for such a deviation. The `Findings`
  function still returns the finding with `NotCovered` set and no severity.
- **Options:**
  1. *Maintainer adds a row* (ADR text, protected) and the code follows.
  2. *Show as "not covered" with no severity and no notification* until a row exists.
  3. *Default to a low severity* for uncovered paths. The ADR does not
     provide this; it would be an invented decision.
- **Recommendation:** option 2 now, option 1 when the maintainer decides. Do not
  pick a severity in code.

### (f) I1: show the executor's status or the server's own check

- **ADR:** IG-03 has the "server check of executor" and IG-04 has the I1
  reaction (`docs/adr/0015-integrity-monitoring.md:1674-1675`). The ADR
  does not say what the server page shows.
- **Code:** `/integrity/status` shows the server monitor's result, which cannot
  be "ok" (section 1). The executor's status is read by the admin CLI only.
- **Options:**
  1. *Server page shows only its own check.* Honest, but it will show the
     incomplete state until a reference is admitted (IG-04).
  2. *Server page shows only the executor's status.* Shows "ok" from the
     executor, which would hide that the server has no check of its own.
  3. *Both, labelled by source* ("server self-check: no admitted reference",
     "executor status: ..."), and neither is presented as the other.
- **Recommendation:** option 3. The server page must never call the executor
  result "the server's check".

## 3. Work split

### 3.1 Without a maintainer (not on the protected list)

These use existing RPCs and packages, so they need no protected change.

| Item | Files | Required test (real HTTP unless noted) |
| --- | --- | --- |
| Server stores (`fimstore`, `integritystore`) built on the server database | `internal/fimstore/`, `internal/integritystore/`, `cmd/nebula-server/` | `httptest`-served handler that writes and reads a baseline proposal; error path for a host without a stored host row |
| I1 status from `GetIntegrityStatus`, shown beside the server check (option (f)3) | `cmd/nebula-server/integrity.go`, `internal/executorclient/client.go:896` (existing) | `httptest` server returns the executor status; a test that a failing executor call shows "unavailable", not "ok" |
| `IntegrityGate` wired to the notifier | `internal/notify/integrity.go:194`, `cmd/nebula-server/` | `httptest` notification sink receives an `integrity.*` message; a held message is recorded |
| Stale comment in `fim.scan` contract | `internal/fimscan/script.go:78-80` | none (comment only); correct after (d) is decided |

Note: "server stores" is only safe after (c) is decided. Otherwise the server
keeps digest logic that the ADR forbids.

### 3.2 Needs protected paths (maintainer)

| Path | Why |
| --- | --- |
| `internal/executor/` | Executor side of the scan (intake, retained records, baseline approval, scheduling in (a)), and the `CompareBaselineList` path in (c) |
| `internal/executordb/` | Approved-digest writer (`StoreApprovedBaselineDigest`) and the approval transaction |
| `internal/hostrun/` | Action-specific limit in (b) |
| `proto/` | Any new RPC (for example the approval RPC or a findings query); regenerate with `make generate` |
| `cmd/nebula/` | `nebula integrity pending`/`approve` (IG-06) |
| `internal/permit/` | Lease rule for `fim.scan` in (d), if the rule moves out of `executions` |

Also check before IG-05: `internal/executions/actions/actions.go` (the catalog)
is not on `.github/protected-paths.txt`, but the ADR puts `fim.scan` into the
signed built-in bundle, which the executor admits. The maintainer should
confirm that adding the entry does not need a protected change.

Note on the protected list: `AGENTS.md` lists fewer paths than
`.github/protected-paths.txt`. The authoritative list is the file; it also
protects `docs/handbook/`, `docs/admin/guide.md`, `internal/registrypull/`
and `CODEOWNERS`.

## 4. Ticket order (ADR 0015:1676-1679)

| Ticket | Paths | Protected | Required test |
| --- | --- | --- | --- |
| IG-05: `fim.scan` script, read-only contract, parser with fuzz tests and limits | `internal/fimscan/`, `internal/executions/actions/actions.go` (catalog), `internal/executions/leaserunner.go`, `internal/executions/readgrants_propose.go` (d), `internal/hostrun/` (b), `internal/executor/` (intake) | Yes for `internal/hostrun/`, `internal/executor/`; catalog and `executions` not listed (see 3.2 note) | Lease with `fim.scan` and foreign parameters rejected; a 128 MiB-class document accepted by the transport limit; parser fuzz for limit boundaries |
| IG-06: host baseline store, executor-held digest, baseline approval UI, `nebula integrity pending`/`approve` | `internal/fimstore/` (server view only, c), `internal/executordb/`, `internal/executor/`, `internal/web/ui/`, `cmd/nebula/` | Yes for `executordb`, `executor`, `cmd/nebula` | Approval binds the executor-computed digest; a stale `PreviousDigest` is rejected (over real HTTP for the UI) |
| IG-07: incremental/full logic and expected-change attribution | `internal/fimretain/`, `internal/fimbaseline/`, `internal/executor/` | Yes for `executor` | A complete incremental run keeps a hash only for paths it hashed; a metadata change drops the hash (D9) |
| IG-08: findings UI and `integrity.*` notifications | `internal/fimfinding/`, `internal/integritystore/`, `internal/notify/integrity.go`, `cmd/nebula-server/integrity.go` | No | Findings page over real HTTP; notification sink receives the finding; the "not covered" case of (e) shows no severity |

I1 pieces (IG-03/IG-04) are section 3.1 and need no ticket order change.

## 5. Outdated statements (for the maintainer to correct in protected files)

These are not edited by this paper.

- `docs/adr/0015-integrity-monitoring.md:5-7`: says "Nothing here is implemented"
  and "awaiting the maintainer's answers". Code exists for `fimscan`,
  `fimbaseline`, the executor baseline compare and the I1 monitor. The status
  text should say what is implemented.
- `docs/adr/0015-integrity-monitoring.md:493-494`: still open (scheduling),
  not outdated. Listed here so the maintainer does not mistake it for stale.
- `internal/fimscan/script.go:78-80` (not protected, can be fixed without a
  maintainer): says `fim.scan` is not in the read-lease allowlist. It is
  (`internal/permit/lease.go:108`).
- `cmd/nebula-server/integrity.go:53-61`: says the server cannot read executor
  storage; the executor's status RPC is readable by the server role
  (`internal/executor/roles.go:257`). The statement is about the admitted
  reference, not the status; the comment should say so.

## 6. Verification for this paper

No Go code changed; no test is possible for a document. Instead:

- Every file:line cited above was checked with `grep` or `sed` against the
  tree on this branch before the commit. The result is stated in the PR
  summary and the report.
- No option in this paper is presented as decided. Where the ADR is open, the
  text says so.
