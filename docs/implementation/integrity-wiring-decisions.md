# Decision paper: wiring I1 status and the I2 scan chain (ADR 0015)

Status: **decided** by the maintainer, 2026-11-21; see "Decision (2026-11-21,
maintainer)" below (previously: **open, maintainer decides.** This paper
decides nothing). Each open point gives the question, what ADR 0015 says, what the code says today (with
file:line), the options, a recommendation and the consequence. Where the ADR
leaves a point open, this paper says so and does not present a choice as made.

Ticket: uf13 (autopilot). Covers gaps G12, G13, G14 and G38 in `out/gaps.md`
(that file is not in this clone; the gap IDs come from the ticket text).

Line numbers were checked against the tree at branch
`agent/uf13-integrity-wiring-paper` (based on `main`, 2026-11-21). They are
references for review, not stable identifiers; re-check them when a point is
decided.

## Decision (2026-11-21, maintainer)

The maintainer (Axel) decided on 2026-11-21 at 13:48 (UTC+1) in chat. Where the
decision differs from the text below, the decision wins. Original wording
(German), verbatim:

> **uf13 (docs/implementation/integrity-wiring-decisions.md, ADR 0015):**
> Empfehlungen angenommen: (a) Option 1, (c) Option 1, (d) Option 1
> beschränkt auf `FimScanActionID` mit (i)–(iii), (e) Option 2, (f) Option 3.
> (b)/(g) zusammen: Scan als dauerhafter Job (Option 2, ohne Permit-Mutex
> über 40 min), mit der nötigen Lease-Regel-Änderung (ADR 0007-Bereich,
> hiermit entschieden).

In English (translation by Claude, not part of the decision): the
recommendations are accepted.

- **(a)** option 1; **(c)** option 1; **(d)** option 1, restricted to
  `FimScanActionID`, with (i)–(iii); **(e)** option 2; **(f)** option 3.
- **(b) and (g) together:** the scan runs as a durable job (option 2, without
  a permit mutex held over 40 min), with the lease rule change this needs
  (ADR 0007 territory, decided hereby).

Work that follows from the decisions (moved here from section 3.1 on
2026-11-21, Claude):

- **(f) option 3, I1 status beside the server check:** read-only. Show the
  executor's `GetIntegrityStatus` result (`internal/executorclient/client.go:922-923`)
  next to the server's own check on `cmd/nebula-server/integrity.go`, labelled by
  source; neither is presented as the other. Files: `cmd/nebula-server/integrity.go`,
  `internal/executorclient/` (both unprotected; the executor is not changed).
  Test: `httptest` server returns the executor status; a failing executor call shows
  "unavailable", not "ok".

## Summary

- **I2 (file integrity on hosts) has no working end-to-end chain.** The scan
  script exists and is embedded. The executor-side digest comparison of a
  server-supplied baseline list is registered on the gRPC service, but no server
  code calls it. Everything between
  them (catalog entry, scheduling, scan result intake, retained records,
  approval, diff, findings, UI, notification) either has no production caller
  or is missing. Details in section 1.
- **I1 (self-check) cannot report "ok".** The server's own monitor has no
  admitted reference to check against, so every release-build run is reported
  as incomplete. The executor's status RPC exists and the server role may call
  it, but the server never does; only the admin CLI calls it.
- **The fim.scan allowlist entry is not a contradiction.** ADR 0015:1650-1651
  plans it, and `internal/permit/lease.go:108` has it. The mismatch is the
  stale comment at `internal/fimscan/script.go:78-80`, which says the opposite.
- **The lease path cannot run fim.scan today. Three blockers, none of them
  durability:** (1) there is no catalog entry, so `actions.Lookup` fails
  (section 1); (2) read leases drop actions with parameters, and `fim.scan` has
  two (`mode`, `profile`), and the runner also sends `ParametersJson: {}`
  (section 2 (d)); (3) the executor rejects any attached run above 10 min
  before dispatch (`internal/executor/schedule.go:133-135`,
  `internal/executor/roles_read.go:258-259`), and `hostrun` would clamp it
  to 10 min anyway (`internal/hostrun/hostrun.go:221-222`), while the scan
  needs 40 min (`internal/fimscan/script.go:30`). The durable exclusion is
  **not** a blocker today: `fimscan.Action()` does not set `Durable`
  (`internal/fimscan/script.go:81-97`). Whether `fim.scan` should be durable
  is open (section 2 (g)); the ADR does not decide it.

## 1. Current chain (Ist-Kette)

| Step | Status today | Evidence (file:line) |
| --- | --- | --- |
| Script | Exists. Embedded, read-only per the contract, not run by anything. | `internal/fimscan/script.go:35` (`//go:embed scripts/fim_scan.sh`), `internal/fimscan/scripts/fim_scan.sh` |
| Catalog | **Missing.** `Action()` builds the contract, but it is not in `actions.Builtin`. The Builtin list (384–566) has no `fim.scan` entry, so `actions.Lookup("fim.scan")` fails. The comment on `Action` (`script.go:78-80`) says it is not yet in Builtin or the read-lease allowlist; the allowlist part is stale (`lease.go:108`). The ADR puts `fim.scan` into the signed built-in bundle (ADR 0015:481-482). | `internal/fimscan/script.go:77-81`; `internal/executions/actions/actions.go:384` (`var Builtin`) |
| Lease | **Blocked.** `fim.scan` is in the read-only allowlist and its lease entry is validated (`validateFimScanAction`). But the lease runner and the proposal code skip any action with parameters, and `fim.scan` has two (`mode`, `profile`). The runner also always sends `ParametersJson: {}`, so even an allowed action would not carry its parameters. Durability is **not** a cause today: the contract does not set `Durable`, so the `!a.Durable` checks do not match it. | `internal/permit/lease.go:104-108` (allowlist), `:122`, `:419-420` (`validateFimScanAction`); `internal/permit/lease_fimscan.go:99`; `internal/executions/leaserunner.go:93-94` (skip rules), `:264` (`ParametersJson: {}`); `internal/executions/readgrants_propose.go:173-178` (`leaseableAction`); params `internal/fimscan/script.go:92-95`; no `Durable` in `internal/fimscan/script.go:81-97` |
| Transport | **Limits do not agree.** Attached runs (the only path read leases use) are capped at 1 MiB output and 10 min. Durable result reads are capped at the same 1 MiB. The scan allows 128 MiB and 40 min. The 10 min limit is enforced in the executor before dispatch (`schedule.go:133-135`, `roles_read.go:258-259`) and clamped in `hostrun`. | `internal/hostrun/hostrun.go:39` (`MaxResult = 1 << 20`), `:41-42` (`MaxTimeout = 10 min`), `:211` (output cap applied), `:221-222` (timeout clamp); `internal/hostrun/durable.go:358,370`; `internal/executor/schedule.go:133-135,211`; `internal/executor/roles_read.go:258-259`; `internal/fimscan/limits.go:13` (`MaxDocumentBytes = 128 << 20`); `internal/fimscan/script.go:30` (`ActionTimeout = 40 min`) |
| Parser | Built, no production caller. `Parse` is only called from tests. | `internal/fimscan/parse.go:33`; no non-test caller found |
| Retention | Built, no production caller. Merge of scan runs (`fimretain`), the retention store (`fimstore`) and `integritystore` are not called from production code. | `internal/fimretain/merge.go`; `internal/fimstore/store.go:128` (`Propose`); `internal/integritystore/integritystore.go`; `internal/fimresolve/resolve.go` (no production caller) |
| Baseline (digest) | **Partly wired.** The executor's `CompareBaselineList` stream builds a baseline from the streamed list and compares its digest with the executor-held approved digest. This RPC is registered on the gRPC service. By design it receives the server's approved list, not a scan run (ADR 0015:1049-1052; `internal/executor/integrity_baseline.go:25-30`). The gap is that no server code calls it: the only client wrapper is `internal/executorclient/client.go:947`, and no caller of that wrapper exists. The server-side `fimstore.Propose` also builds a baseline and stores its digest, without a production caller. | `internal/executor/integrity_baseline.go:153` (`NewBaseline`), `:355` (`CompareBaselineList`); `internal/executor/service.go:221` (`RegisterExecutorServiceServer`); `internal/fimstore/store.go:143` |
| Approval | **Missing.** `StoreApprovedBaselineDigest` (the only writer of the approved digest) has no production caller. No approval RPC, no approval screen, no `nebula integrity pending/approve`. The server's `Approve` re-hashes its own stored proposal rows (section 2 (c)). | `internal/executordb/integrity_baseline.go:111`; no non-test caller; `internal/fimstore/store.go:205` (`Approve`), `:241` (`verifyProposal`) |
| Diff | Built, no production caller. | `internal/fimbaseline/diff.go:111` (`Diff`) |
| Findings | Classes exist, no production caller. The executor writes a tamper finding on a digest mismatch (`RecordBaselineTamper`), but that path is not reachable in production: `CompareBaselineList` has no server caller, and `StoreApprovedBaselineDigest` (the only writer of the approved digest) has no production caller. So `approvedBaselineDigest` finds no digest and `finishBaselineCompare` returns `BaselineNone` before the call (`internal/executor/integrity_baseline.go:249`, `:253-254`). Severity is missing for uncovered paths (section 2 (e)). | `internal/fimfinding/classes.go`; `internal/fimfinding/doc.go:48-56`; `internal/executor/integrity_baseline.go:259` |
| UI | **Missing** for I2. The server has `/integrity/status` for its own I1 monitor only. No baseline or findings page. | `cmd/nebula-server/integrity.go:118-129`; `cmd/nebula-server/main.go:649` |
| Notification | `IntegrityGate` is built (`NewIntegrityGate`) but has no production caller. The executor logs the tamper finding name with slog only (audit lines: `integrity_baseline_tamper` at `:270-275`, the unrecorded-storage error branch at `:263-266`). The notification kind exists in notifylog. | `internal/notify/integrity.go:194`; `internal/executor/integrity_baseline.go:263-275`; `internal/notifylog/notifylog.go:176` |

**I1 chain, for the same table:**

| Step | Status today | Evidence (file:line) |
| --- | --- | --- |
| Server self-check | Runs at start and every 60 min. Its reference loader always returns an error: a release build reports `no-admitted-reference` (ERROR, hashes nothing), a development build reports not-checkable. It cannot report "ok". | `cmd/nebula-server/integrity.go:53-61` (comment), `:65-80` (`newIntegrityMonitorAt`, `Load` at `:68-74`); `cmd/nebula-server/main.go:359-362` (`selfCheck`, comment says "no reaction here (IG-04)") |
| Executor status RPC | Exists, read-only, server and admin roles allowed. | `internal/executor/roles.go:257`; `internal/executor/integrity_lock.go:494` (`GetIntegrityStatus`); client `internal/executorclient/client.go:922-923` |
| Server calls executor status | **Never.** The only callers of `GetIntegrityStatus` are the admin CLI. The server's lock watcher calls the separate `GetStatus` RPC for the lock state only. | `cmd/nebula/integrity_ack.go:39,88`; `cmd/nebula-server/main.go:348-357` (`GetStatus`) |
| Server UI for I1 | `/integrity/status` shows the server monitor's result only. | `cmd/nebula-server/integrity.go:118-129` |

## 2. Open points

Each point: question, what the ADR says, what the code says, options,
recommendation. The points marked "Decided 2026-11-21" follow the decision
block above; the others are still open.

### (a) Who plans the scans (scheduling owner)

- **Decided 2026-11-21: option 1** (see the Decision block). The ADR wording
  stays until IG-05 lands, as noted below.
- **ADR:** the server's scheduler, or a collector role, "*verify* which one
  owns scheduling when IG-05 lands" (`docs/adr/0015-integrity-monitoring.md:492-494`).
  The executor authorizes and dials; the server or collector only triggers.
- **Code:** the scheduling of ordinary read leases already has this shape.
  The server-side lease runner (`internal/executions/leaserunner.go`, package
  `executions`; block comment at `:26-33`) selects the work, and
  `RunDueReadGrants` (`:143`) and `runLeaseAction` (`:247`) call the executor's
  `RunReadGrant` (`:266`). The executor re-checks expiry, revocation, lock,
  scope and budget. Its `RunReadGrant` (`internal/executor/roles_read.go:266`)
  goes through `RunRead` (`internal/executor/schedule.go:125`), which runs the
  action with `hostrun.Attached` (`schedule.go:211`). No scan scheduler for
  `fim.scan` exists. `fim.scan` also cannot be selected by the lease runner
  today, see (d) and (g).
- **Options:**
  1. *Server schedules, executor re-checks and dials.* This is the existing
     pattern for ordinary read leases. `fim.scan` then needs to be a
     leaseable action, which depends on (d), (g) and the catalog entry.
  2. *Executor schedules itself* from a lease it holds. A new trigger path in
     the executor (protected); the ADR does not describe it.
  3. *Separate collector role.* New role, new trust boundary. The ADR does not
     name one; this would need an ADR amendment.
- **Recommendation:** option 1, because it reuses the existing lease path. The
  ADR wording stays as it is until IG-05 lands; the maintainer confirms the
  owner then. Option 1 does not unblock the scan by itself: (d), (g) and the
  catalog entry still block it.

### (b) Transport limits (1 MiB and 10 min against 128 MiB and 40 min)

- **Decided 2026-11-21: option 2, together with (g)** (see the Decision block).
- **ADR:** the 128 MiB document per run and the 40 min action timeout are
  chosen so that the scan fits (`docs/adr/0015-integrity-monitoring.md:624-627`).
  The ADR says that the 1 MiB `result.json` default of spec 09 needs an
  action-specific limit, "like ADR 0011 D3" (`:625-627`). The spec revision is
  listed at `:1652`.
- **Code:** attached runs cap output at `MaxResult` = 1 MiB (`internal/hostrun/hostrun.go:39`,
  applied at `:211`) and clamp the attached timeout to 10 min (`:41-42`, clamp
  at `:221-222`). The executor refuses a longer timeout before dispatch
  (`internal/executor/schedule.go:133-135`, `internal/executor/roles_read.go:258-259`),
  so option 1 must change those two checks as well as the clamp. Read leases
  run attached only (`internal/executor/schedule.go:211`). The durable result
  read is capped at the same 1 MiB (`internal/hostrun/durable.go:358,370`), and
  the durable maximum is 6 h (`durable.go:105`). The scan's own constants are
  `internal/fimscan/limits.go:13` and `internal/fimscan/script.go:30`.
- **Options:**
  1. *Action-specific limits for `fim.scan` in `hostrun.Attached`* (128 MiB
     output, 40 min timeout, only for this action), and the two executor timeout
     checks above accepting the action's own limit.
     **Cost, precisely:** `dispatchReadRun` takes `Authority.mu`
     (`internal/permit/lease.go:1086-1087`) and calls the dispatch callback while
     it holds the mutex (`:1102`). That callback is the closure returned by
     `ReadDispatchGuard` (`internal/executor/schedule.go:142`), and it runs
     `hostrun.Attached` (`schedule.go:211`). So for the whole attached run, every
     call that takes the same mutex waits: `AuthorizeReadRun` (`lease.go:885`,
     called at `schedule.go:163`), `AuthorizeGrant` (`internal/permit/permit.go:816`),
     the revocations (`lease.go:802`, `:825`), and `Lock` (`permit.go:949-954`,
     which also pauses reads). Today that wait is up to 10 min; with the scan it
     is up to 40 min. The doc comment at `lease.go:1076-1078` already names this
     wait ("lifecycle calls may wait for its bounded timeout"); the bound is 10 min
     today and would be 40 min under option 1. The held SSH session is the
     smaller part of the cost.
     **Option 1 therefore needs a guard change, not only limits.** The run must
     leave the mutex: claim the read under the lock, release it, run the SSH
     session, and let lock or revocation cancel the in-flight run's context so
     the connection closes. That changes the "serialized with lock" guarantee of
     `dispatchReadRun`, is a lease-semantics decision (ADR 0007), and is protected
     (`internal/permit/`, `internal/executor/`). The alternative, keeping the
     mutex, means a lock or a read-grant revocation can take up to 40 min to take
     effect, which is not acceptable for a revocation.
     Protected: `internal/hostrun/`, `internal/executor/`, `internal/permit/`.
  2. *Action-specific limits and a durable run for `fim.scan`.* A durable job
     survives an SSH drop and fits the 6 h maximum. It needs the lease path to
     accept durable actions (section (g)), a durable branch in the executor's
     read path, and the same per-action 128 MiB cap in the durable result read
     (`durable.go:358,370`). The durable path does not call `ReadDispatchGuard`
     (its only caller is `schedule.go:142`), so it does not hold this mutex; its
     lock and revocation behaviour is not checked in this paper.
     Protected: `internal/hostrun/`, `internal/executor/`.
  3. *Chunked result* (several documents, each under 1 MiB, reassembled and
     checked by the executor). New protocol framing; touches `proto/` and the
     spec. Protected.
  4. *Smaller document* (fewer fields, shorter encodings). Does not remove the
     need for a per-action limit, because the ADR chose 128 MiB above the 1 MiB
     default on purpose (`:624-627`).
- **Recommendation:** do not take option 1 as a limits-only change. It needs the
  guard change above before a 40 min run is safe, so the earlier reading that
  option 1 is the smaller change is withdrawn. Option 2 does not hold the permit
  mutex, so for a 40 min run this paper would lean to option 2, once the durable
  path's lock and revocation behaviour is checked (not done here). Option 2 also
  needs (g) decided. Decided 2026-11-21 together with (g): option 2, as a
  durable job (see the Decision block). The spec 09
  amendment comes first in either case, and the ADR's limits stay the only numbers.

### (c) Who computes the baseline digest: server or executor

- **Decided 2026-11-21: option 1** (see the Decision block). The server digest is
  removed after the executor check is wired; the open direction question below
  still applies.
- **ADR:** the executor alone decides what goes into a baseline; the digest the
  admin approves is computed by the executor, never taken from the server
  (`docs/adr/0015-integrity-monitoring.md:1035-1037`).
- **Code:** `fimstore.Propose` computes the baseline and its digest on the
  server (`internal/fimstore/store.go:128` onward, `NewBaseline` at `:143`) and
  stores the proposal with that digest. `Approve` (`store.go:205`) calls
  `verifyProposal` (`store.go:241`, defined at `:527-551`). `verifyProposal`
  re-hashes the stored proposal rows on the server and refuses the approval with
  `ErrDigestMismatch` if they do not match the stored digest. This is an
  existing server-side consistency check; it does not involve any executor
  digest. The executor has its own `NewBaseline` call in `CompareBaselineList`
  (`internal/executor/integrity_baseline.go:153`), and compares it with the
  executor-held digest (`executordb/integrity_baseline.go:111`, which has no
  production caller).
- **Options:**
  1. *Executor only, after the executor check on the list is wired.* Delete the
     server-side digest (computed at `store.go:143`) and the `verifyProposal`
     check that compares it (`store.go:241`, `:527-551`). The server still holds
     the approved list, because the ADR has the executor take that list from the
     server and accept it only if its digest equals the executor-held digest
     (ADR 0015:1049-1052). The executor recomputes the digest of the fetched
     list and compares it with the digest it holds (`CompareBaselineList`,
     `internal/executor/integrity_baseline.go:25-30`, `:249-260`). The executor
     builds the proposal from its retained run and computes the digest, and the
     approval binds that digest (ADR 0015:1035-1037). Protected:
     `internal/executor/`, `internal/executordb/`.
     **Direction, not decided by this paper:** the code has the server push the
     list in a client stream (`internal/executorclient/client.go:947`), while the
     ADR text has the executor fetch it from the server (`:1049-1050`). Option 1
     works with either, but the maintainer should confirm which one the ADR means.
  2. *Server proposes, executor re-checks at approval.* The server's digest is
     a preview. The approval sends it, and the executor compares it with its own
     digest and refuses on mismatch. This keeps `verifyProposal` and adds the
     executor half. The ADR does not clearly allow a server-computed digest to
     exist even as a preview, so this needs a maintainer reading of ADR
     `:1035-1060`.
- **Recommendation:** option 1, because it matches the ADR text, in this order:
  first wire the executor check on the list (this needs a server caller of
  `CompareBaselineList`, which would sit in `cmd/nebula-server/` and is not
  protected, and the direction question above), then remove the server digest. Removing the server check first would
  leave the approval with no digest check at all. Option 2 only if the maintainer
  reads the ADR as allowing a server preview.

### (d) Lease runner and proposal drop actions with parameters

- **Decided 2026-11-21: option 1, restricted to `FimScanActionID`, with (i) to (iii)**
  (see the Decision block).
- **ADR:** the grant freezes a profile ID and a mode, and the lease binds the
  exact action, script hash and parameters (`docs/adr/0015-integrity-monitoring.md:489-500`;
  `permit/lease_fimscan.go` implements the lease check).
- **Code:** the lease runner skips an action unless `da.ParametersHash` is
  empty and `len(a.Params) == 0` (`internal/executions/leaserunner.go:93-94`).
  The proposal path requires `len(a.Params) == 0` (`internal/executions/readgrants_propose.go:178`,
  within `leaseableAction` at `:173-179`). `fim.scan` has `mode` and `profile`
  (`internal/fimscan/script.go:92-95`). Also `actions.Lookup("fim.scan")` fails
  today because the catalog entry is missing (section 1), so both checks drop it
  twice.
  Even when the skip rules are lifted, `runLeaseAction` sends
  `ParametersJson: {}` (`internal/executions/leaserunner.go:264`), so the
  executor would get the empty object, not `mode` and `profile`. The executor
  runs the lease-run check `checkReadRun` (`internal/permit/lease.go:950`): it
  canonicalizes the run's parameters (`lease.go:964`) and refuses unless their hash
  equals the granted action's `ParametersHash` (`lease.go:1022`). The similar check
  at `internal/permit/permit.go:854` is in `authorizeGrant`, the permit path; it is
  not the lease check and does not apply to read leases.
  The accepted hashes for `fim.scan` are fixed in `internal/permit/lease_fimscan.go:34-39,107-125`.
  The runner keeps no per-entry mode. `ordinaryLease.actions` holds
  `actions.Action` values only (`internal/executions/leaserunner.go:57`), so the
  entry's `da.ParametersHash` (read at `:93`) is dropped. The runner keys its last
  run by action ID and host (`leaserunner.go:222-226`, `:239`) and computes the due
  time from the lease interval or `permit.ReadActionMinInterval`, which for
  `fim.scan` is the incremental floor of 1 h (`leaserunner.go:199`;
  `internal/permit/lease.go:122-125`; `internal/permit/lease_fimscan.go:45`). The
  executor's full-mode floor is 7 d − 6 h under its own key `fim.scan#full`
  (`lease_fimscan.go:52`, `:55`, `:60`, `:117-128`).
- **Options:**
  1. *Allow the one action:* accept `fim.scan` with its two fixed parameters
     when the grant's parameter hash matches the canonical parameters; reject
     every other parameter set. Restricted to `FimScanActionID`. This needs
     three changes: (i) lift the skip rules for `FimScanActionID` in
     `leaserunner.go:93-94` and `readgrants_propose.go:178`; (ii) the runner
     builds the canonical parameters JSON for the grant (`mode`, `profile`)
     and sends it in `runLeaseAction` (`leaserunner.go:264`) instead of `{}`,
     so the bytes hash to the grant's `ParametersHash`. Without (ii) the lease
     check at `lease.go:1022` fails for every run; (iii)
     keep each entry's mode in the runner: carry the entry's `ParametersHash`
     with `ordinaryLease.actions` (`leaserunner.go:57`), key the last run and the
     due time by that mode with the executor's floor (incremental 1 h, full
     7 d − 6 h; `lease_fimscan.go:45`, `:52`, `:117-128`), and check whether the
     stored run row records the parameters hash, because `leaseRuns` groups by
     action ID and host only (`leaserunner.go:222-226`). Without (iii) a
     full-mode entry is due after the 1 h floor (`leaserunner.go:199`), the
     executor refuses it with `ResourceExhausted` (`leaserunner.go:274-275`), and
     that refusal ends the host's other actions for the tick (`:197-198`, `:204-205`).
     This repeats every hour for the whole 7 day floor. The tests listed under
     the recommendation do not catch it, because they check acceptance and
     parameters, not timing.
  2. *Keep the generic rule* and give `fim.scan` a separate runner. More code,
     two lease paths.
- **Recommendation:** option 1, restricted to `FimScanActionID`, with (i) to (iii)
  above. Tests: a foreign profile, a foreign mode and a wrong parameter hash are
  each rejected; the runner sends exactly the canonical parameters (the bytes
  whose hash the grant binds); and a full-mode entry is not requested before
  7 d − 6 h, with a fake executor that refuses earlier requests and fails the
  test if one arrives. A recent incremental run must not delay a full entry, and
  the reverse. The code is not protected
  (`internal/executions/`), but the lease semantics are ADR 0007 territory:
  the maintainer confirms the rule. The catalog entry (section 1) must come
  first.

### (e) Severity for paths the table does not cover

- **Decided 2026-11-21: option 2** (see the Decision block). Option 1 stays
  possible later; the text below is the analysis.
- **ADR:** the severity table row "Other changed or new file in `/etc` or a
  watched `/usr` root (D5)" is `high` (`docs/adr/0015-integrity-monitoring.md:1518`).
  Local software is always compared against the baseline (`:520`): `/usr/local/bin`,
  `/usr/local/sbin`, `/usr/local/lib` and `/opt`. No row gives a severity for a
  change there, and no row covers a removed non-critical path.
- **Facts from the ADR:** "Under `/usr`, only the D5 roots are watched"
  (`docs/adr/0015-integrity-monitoring.md:125`). The D5 root table lists
  `/usr/local/bin`, `/usr/local/sbin`, `/usr/local/lib` and `/opt` in the
  "Local software" group (`:520`). `:128-129` names `/usr/local/share`,
  `/usr/local/etc` and `/usr/local/include` among the unwatched `/usr` paths.
- **Interpretation, not fact:** the ADR does not connect the phrase "watched
  `/usr` root" in the severity row (`:1518`) to the "Local software" group
  (`:520`). Whether the `high` row covers `/usr/local/{bin,sbin,lib}` is therefore
  the open reading; the ADR does not define "watched `/usr` root" as a list.
- **Code:** `internal/fimfinding/doc.go:48-56` lists every uncovered case: a
  removed non-critical path; a changed or new non-critical path under `/opt`;
  under `/bin` on a host without merged `/usr`; and under `/usr/local`. For these
  `Classes` returns `ErrNotCovered`. `Findings` still returns the finding with
  `NotCovered` set and no class or severity.
- **Options:**
  1. *Maintainer adds rows* (ADR text, protected) and decides whether
     `/usr/local/{bin,sbin,lib}` are watched roots. The code follows.
  2. *Show as "not covered" with no severity and no notification* until a row exists.
  3. *Default to a low severity* for uncovered paths. The ADR does not provide
     this; it would be an invented decision.
- **Recommendation:** option 2 now, option 1 when the maintainer decides. Do not
  pick a severity in code.

### (f) I1: show the executor's status or the server's own check

- **Decided 2026-11-21: option 3** (see the Decision block at the top of this
  paper and ADR 0015 Amendment 2026-11-21). The text below is the pre-decision
  analysis and is kept as history.
- **ADR:** IG-03 has the "server check of executor" and IG-04 has the I1
  reaction (`docs/adr/0015-integrity-monitoring.md:1674-1675`). The ADR does
  not say what the server page shows.
- **Code:** `/integrity/status` shows the server monitor's result, which cannot
  be "ok" (section 1). The executor's status is read by the admin CLI only.
  The server's reference read is tied to IG-04 by the code comment
  (`cmd/nebula-server/integrity.go:53-61`, `:72-73`), but the ADR's admission of
  `installed-files.json` is IG-02 (`docs/adr/0015-integrity-monitoring.md:1673`).
  The paper flags this mismatch; it does not decide it.
- **Options:**
  1. *Server page shows only its own check.* Honest, but it shows the
     incomplete state until the reference is admitted and readable.
  2. *Server page shows only the executor's status.* Shows "ok" from the
     executor, which would hide that the server has no check of its own.
  3. *Both, labelled by source* ("server self-check: no admitted reference",
     "executor status: ..."), and neither is presented as the other.
- **Recommendation:** option 3. The server page must never call the executor
  result "the server's check".

### (g) Durable actions cannot run through read leases (new)

- **Decided 2026-11-21: option 2, together with (b)** (see the Decision block).
- **ADR:** the ADR does not say whether `fim.scan` is durable. It names a 40 min
  action timeout (`:624-627`) and calls `fim.scan` a read-only action
  (`:481-482`). The ADR never uses the word "durable".
- **Code:** the contract does not set `Durable` (`internal/fimscan/script.go:81-97`),
  so as the code stands `fim.scan` is an attached action, and the `!a.Durable`
  checks (`internal/executions/leaserunner.go:94`, `readgrants_propose.go:178`
  through `leaseableAction`) do not block it. Read leases run attached only
  (`internal/executor/schedule.go:211`); durable actions go through the
  executor's durable path (`internal/executor/durable.go:98`, `hostrun.Dispatch`).
  So a read lease cannot run a durable action today; this matters only if
  `fim.scan` is made durable (option 2). The 40 min run is blocked by the
  10 min attached limit (section 1, (b)), not by durability.
- **Options:**
  1. *Keep `fim.scan` attached.* Action-specific limits and the guard change
     (section 2 (b) option 1). No durability rule change and no `Durable` flag;
     the (d) rule change still applies.
  2. *Make `fim.scan` durable.* Set `Durable: true` in the contract, and lift
     the `!a.Durable` skip for `FimScanActionID` in both places, plus a durable
     branch in the executor's read path (`internal/executor/durable.go`). Two
     protected packages, plus an ADR 0007 rule change. This also fits the 6 h
     durable maximum (section 2 (b) option 2).
  3. *Shorten the scan below the attached 10 min limit.* Contradicts the ADR's
     40 min budget (`:624-627`). Not recommended.
- **Decided 2026-11-21 together with (b): option 2** (see the Decision block).
  The lease rule change is ADR 0007 territory and is decided there as well.
- **Recommendation (before the decision):** option 1 needs the (b) guard change
  before a 40 min run; option 2 avoids the permit mutex but needs the lease rule
  change and a durable branch.

## 3. Work split

### 3.1 Without a maintainer (not on the protected list)

These use existing RPCs and packages, and the listed files are not protected
(`.github/protected-paths.txt`). Nothing here needs an executor or `cmd/nebula`
change.

| Item | Files | Required test (real HTTP unless noted) |
| --- | --- | --- |
| Server baseline proposal store (`fimstore`) built on the server database. Decided 2026-11-21, (c) option 1: the server digest (`internal/fimstore/store.go:143`) and the `verifyProposal` check are removed, but only after the executor check on the list is wired (section 2 (c)). Do not add server digest logic. Until that removal, the existing code stays as it is. | `internal/fimstore/`, `cmd/nebula-server/` | `httptest`-served handler that writes and reads a baseline proposal; error path for a host without a stored host row |
| `IntegrityGate` wired to the notifier (`internal/notify/integrity.go:194`) | `internal/notify/integrity.go`, `cmd/nebula-server/` | `httptest` notification sink receives an `integrity.*` message; a held message is recorded |
| Stale comment in `fim.scan` contract (`internal/fimscan/script.go:78-80`) | `internal/fimscan/script.go` | none (comment only); correct the sentence about the allowlist now, the catalog sentence after the catalog entry is decided |

Note: the I1 status work from (f) option 3 is listed under the Decision block,
not here. The IG-04 reaction (section 3.2) is not part of this list.

### 3.2 Needs protected paths (maintainer)

| Path | Why |
| --- | --- |
| `internal/executor/` | Executor side of the scan (intake, retained records, baseline approval, scheduling in (a)), the `CompareBaselineList` path in (c), the durable read branch in (g) option 2, the attached-run guard call in (b) (`schedule.go:142`, `:211`), and the IG-04 I1 reaction (unlock refusal per Q4, ADR 0015:1675) |
| `internal/executordb/` | Approved-digest writer (`StoreApprovedBaselineDigest`) and the approval transaction (c) |
| `internal/hostrun/` | Action-specific limit in (b) |
| `proto/` | Any new RPC (for example the approval RPC or a findings query); regenerate with `make generate` |
| `cmd/nebula/` | `nebula integrity ack` and `verify --offline` (IG-04, ADR 0015:1675); `nebula verify` from an admin machine (IG-04); `nebula integrity pending`/`approve` (IG-06) |
| `internal/permit/` | Lease rule for `fim.scan` in (d), if the rule moves out of `executions`; the `dispatchReadRun` guard change in (b) (`lease.go:1085-1102`) |
| `internal/executions/`, `cmd/nebula-server/` | **Not** protected. Listed here only to note that (d) and (g) lease-rule changes can be made there, but the rule itself needs the maintainer (ADR 0007) |

Also check before IG-05: `internal/executions/actions/actions.go` (the catalog)
is not on `.github/protected-paths.txt`, but the ADR puts `fim.scan` into the
signed built-in bundle (ADR 0015:481-482), which the executor admits. The
maintainer should confirm that adding the entry does not need a protected change.

Note on the protected list: `AGENTS.md` lists fewer paths than
`.github/protected-paths.txt`. The authoritative list is the file; it also
protects `CODEOWNERS`, `docs/handbook/`, `docs/admin/guide.md` and
`internal/registrypull/`.

## 4. Ticket order (ADR 0015:1672-1679)

| Ticket | Paths | Protected | Required test |
| --- | --- | --- | --- |
| IG-03: I1 checks, executor cross-check, server check of executor, `integrity_findings` store (ADR 0015:1674) | `internal/integritystore/`, `cmd/nebula-server/integrity.go`, `internal/executorclient/`; executor cross-check in `internal/executor/` | Yes for `internal/executor/` (the cross-check) | Proposed: findings row written and read back through `internal/integritystore/` on a real database; the server page shows the executor status and its own check labelled apart (decision (f) 3). Depends on IG-02 (ADR 0015:1674), not on (c) |
| IG-05: `fim.scan` script, read-only contract, parser with fuzz tests and limits | `internal/fimscan/`, `internal/executions/actions/actions.go` (catalog), `internal/executions/leaserunner.go`, `internal/executions/readgrants_propose.go` (d), `internal/hostrun/` (b), `internal/executor/` (intake) | Yes for `internal/hostrun/`, `internal/executor/`; catalog and `executions` not listed (see 3.2 note) | Lease with `fim.scan` and foreign parameters rejected; a 128 MiB-class document accepted by the transport limit; parser fuzz for limit boundaries |
| IG-06: host baseline store, executor-held digest, baseline approval UI, `nebula integrity pending`/`approve` | `internal/fimstore/` (server view only, c), `internal/executordb/`, `internal/executor/`, `internal/web/ui/`, `cmd/nebula/` | Yes for `executordb`, `executor`, `cmd/nebula` | Approval binds the executor-computed digest; a stale `PreviousDigest` is rejected (over real HTTP for the UI) |
| IG-07: incremental/full logic and expected-change attribution | `internal/fimretain/`, `internal/fimbaseline/`, `internal/executor/` | Yes for `executor` | A complete incremental run keeps a hash only for paths it hashed; a metadata change drops the hash (D9) |
| IG-08: findings UI and `integrity.*` notifications | `internal/fimfinding/`, `internal/notify/integrity.go`, `cmd/nebula-server/integrity.go` | No | Findings page over real HTTP; notification sink receives the finding. Conditional on (e) option 2 (decided 2026-11-21): the "not covered" case shows no severity. If (e) option 1 is chosen later, this test changes |

IG-03 and IG-04 are mixed: IG-03 (I1 checks, server check of executor, server
page, `integrity_findings` store) is the (f) work item under the Decision block
plus the IG-03 row above; section 3.1 holds no IG-03 item. IG-04 (unlock refusal, `ack`, `verify --offline`,
configuration approval) is mostly section 3.2 and needs the maintainer. The
admission of `installed-files.json` into executor storage is IG-02 (ADR
0015:1673). Its executor part is protected (`internal/executor/`). The
release-tooling part (`docs/admin/release-signing.md`) is not on the protected
list, but the `docs/admin/guide.md` entry is; check the file before IG-02 starts.

## 5. Outdated statements (for the maintainer to correct in protected files)

These are not edited by this paper.

- `docs/adr/0015-integrity-monitoring.md:3-6`: the status line says
  "Accepted, 2026-11-11" and is current. The phrase "awaiting the maintainer's
  answers" is inside "(previously: proposed, ...)" and is history. What is
  outdated is "Nothing here is implemented" (`:5-6`): code exists for `fimscan`,
  `fimbaseline`, the executor baseline compare and the I1 monitor. The text
  should say what is implemented.
- `docs/adr/0015-integrity-monitoring.md:492-494`: still open (scheduling),
  not outdated. Listed here so the maintainer does not mistake it for stale.
- `internal/fimscan/script.go:78-80` (not protected, can be fixed without a
  maintainer): says `fim.scan` is not in the read-lease allowlist. It is
  (`internal/permit/lease.go:108`, planned by ADR 0015:1650-1651). The catalog
  statement in the same comment is still true (section 1).

## 6. Verification for this paper

No Go code changed; no test is possible for a document. Instead:

- Every file:line cited above was checked with `grep` or `sed` against the
  tree on this branch. Round 1 re-checked the lines named in the local review,
  and the ADR line numbers in sections 2 to 5. Round 3 re-read the code for
  the points named in its review: section 1 (baseline and findings rows), section
  2 (b), (c), (d) and (g), and the lock and revocation callers of the permit mutex.
- Options marked "Decided 2026-11-21" follow the maintainer's decision block at
  the top. All other options are open, and the text says so.
- Review round 4 (uf13g, Claude): the (d) lease-run parameter check was re-checked
  at `internal/permit/lease.go:950-1024` (`checkReadRun`); `permit.go:814-854` is
  `authorizeGrant` on the permit path. The IG-03 row and `integrity_findings` were
  checked against ADR 0015:1674. Work items from the decided (f) option 3 moved
  under the Decision block.
