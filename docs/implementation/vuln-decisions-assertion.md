# Decision paper: security key assertion for maintainer decisions (ADR 0011 Q4)

Status: **open, maintainer decides.** This paper decides nothing. It sets out
the current state, two ways to bind the security key assertion to a
maintainer decision, a recommendation (marked as a proposal) and the follow-up
tickets for each variant. The recommendation does not change any ADR or spec.

Ticket: uf04 (autopilot), Issue: none.

## Why this is open

ADR 0011 decides who may make the five maintainer decisions and that each one
needs a **fresh WebAuthn assertion** "as for read-lease approval"
(`docs/adr/0011-vulnerability-management.md:794-800`, Q4 decided at
`:1108`). It does not say how the assertion is bound to the decision. The
only executor RPC that binds an assertion to a digest for vulnerability
decisions does not exist, so every submit of a decision is refused. The
maintainer therefore cannot act on held closures, accepted risks, false
positives or feed mark resets through the product today.

The A1.8 agent settings (LLM endpoint) already have a working assertion path.
ADR 0011 explicitly accepts it there and names its mechanism
(`docs/adr/0011-vulnerability-management.md:3896-3904`). This paper asks
whether the same mechanism is acceptable for decisions, or whether the executor
must enforce the binding.

## Current state (verified in this clone)

### The five decision kinds

`internal/web/ui/vuln_decide.go:57-61`:

| Kind | Constant | Store method (no caller today) |
| --- | --- | --- |
| `accept_risk` | `VulnAcceptRisk` | `vulnstore.(*Store).SetAcceptedRisk`, `internal/vulnstore/human.go:70` |
| `false_positive` | `VulnFalsePositive` | `vulnstore.(*Store).SetFalsePositive`, `internal/vulnstore/human.go:92` |
| `confirm_hold` | `VulnConfirmHold` | `vulnstore.(*Store).ConfirmHeld`, `internal/vulnstore/human.go:277` |
| `discard_hold` | `VulnDiscardHold` | `vulnstore.(*Store).DiscardHeld`, `internal/vulnstore/human.go:358` |
| `mark_reset` | `VulnMarkReset` | `vulnstore.(*Store).ResetMark`, `internal/vulnstore/reset.go:165` |

`VulnDecision.Digest()` (`internal/web/ui/vuln_decide.go:89-96`) is the
SHA-256 over the kind, the key and every field, with the domain prefix
`nos-vuln-decision-v1`. It is the value a challenge would bind to.

### The stubs that refuse every decision

`cmd/nebula-server/vuln.go`:

- `:592-594` `errVulnDecisionsUnavailable`: "the executor has no RPC yet that
  binds a WebAuthn assertion to a vulnerability decision digest (Q4)".
- `:706-708` `BeginVulnDecision` returns that error.
- `:711-713` `CommitVulnDecision` returns that error.

The UI interface is `internal/web/ui/vuln.go:166-172`
(`BeginVulnDecision`, `CommitVulnDecision`). The handler contract is already
there; only the backend is missing.

### Store methods without a caller

Non-test code contains no call to any of these (checked with a grep for
`.Name(` over the tree, excluding `_test.go`):

- `internal/vulnstore/human.go:70` `SetAcceptedRisk`
- `internal/vulnstore/human.go:92` `SetFalsePositive`
- `internal/vulnstore/human.go:170` `ReviewHumanStates`. Its only caller is
  in tests (`internal/vulnstore/human_test.go:129,154`, inside
  `TestReviewHumanStatesReopens` at `:95`). `runSweeps`
  (`cmd/nebula-server/vuln.go:474`) does not call it.
- `internal/vulnstore/human.go:277` `ConfirmHeld`
- `internal/vulnstore/human.go:358` `DiscardHeld`
- `internal/vulnstore/reset.go:165` `ResetMark`
- `internal/vulnnotify/vulnnotify.go:607` `(*Notifier).MarkReset`

Consequence: after iv06, a held closure (a run asks to close a finding and the
closure is held for an admin) can never be confirmed or discarded. A mark
reset (D5, ADR 0011 Q4 row at `docs/adr/0011-vulnerability-management.md:1108`)
cannot be applied either, so a regressed feed source stays frozen
(`docs/threat-model.md:78`).

### What the operator sees

`docs/admin/guide.md:1791-1795`: "Maintainer decisions are refused for now.
The forms for accepting a risk, marking a false positive, confirming or
discarding a held closure and resetting a feed mark are shown to the
maintainer. Submitting one fails with "vulnerability decisions need an
executor-verified security key assertion, which this executor does not
offer": the executor has no call yet that binds a security key assertion to
such a decision (planned)." The guide is a protected path; this paper does
not change it.

### Assertion paths that already exist

| Path | Who verifies | Binding | Where |
| --- | --- | --- | --- |
| Read grant approval (`CommitReadGrant`) | executor | executor challenge bound to the grant digest; the server only relays the assertion | `proto/nebula/executor/v1/executor.proto:2884-2889` (request), `internal/executor/roles_read.go:142-155` |
| Permit approval | executor | challenge = SHA-256(digest, nonce, expiry), single use, sign counter checked | `docs/threat-model.md:57` (`internal/permit`, `internal/webauthnverify`) |
| Agent LLM settings (A1.8) | executor for the assertion, `nebula-server` for the binding | login assertion (`BeginLogin`/`FinishLogin`, `executor.proto:161,165`); server holds a single-use challenge bound to user and change digest | `cmd/nebula-server/vuln_agentcfg.go:56-60` (relay interface), `:166` (`take`), `:181-200` (commit) |

`executor.(*Service).BeginLogin` and `FinishLogin` take no digest
(`internal/executor/webauthn.go:174-200`). The executor checks the signature
against its own login challenge and returns the credential and the user name.
It does not know which change the user signed. The binding exists only in
`nebula-server`.

## Common limit: `nebula-server` owns the decision state

The decision state is held by `nebula-server`: the `vulnstore` tables in
`server.db` (`docs/adr/0011-vulnerability-management.md:3891-3892` names the
same `server.db` and `internal/vulnstore` location for the A1.8 settings).
Neither variant moves that state into the executor. The executor sees a
decision only as a digest it signs or verifies; it never writes or reads the
applied state.

Consequence for both variants: a compromised `nebula-server` can write any
decision (accept a risk, mark a false positive, confirm or discard a held
closure, reset a feed mark) directly into its own store, with no assertion at
all. The assertion gates the decision path the UI uses. It does not gate the
database. Neither variant prevents this.

What each variant adds on top of that:
- **Variant A** checks the binding in `nebula-server`. A refused request
  (no fresh assertion, wrong user, wrong digest, reused challenge) is refused
  only if the server runs its own check. A compromised server skips it.
- **Variant B** moves the digest and single-use check into the executor. A
  server with a faulty check still cannot obtain a valid signature for a
  digest the maintainer did not sign. The executor also records a signed event
  for every decision it accepted. That event is evidence of what was signed.
  It does not change the applied state: step 3 of Variant B has the server
  apply the decision itself, and nothing in B makes the server read the
  executor's record back.

Making the executor the authority over the applied state, or making the server
verify the executor's record before it applies a decision, would be a separate
design decision and is outside both variants.

## Variant A: login assertion with a server-side digest binding (A1.8 path)

Same mechanism as the accepted agent settings change:

1. `BeginVulnDecision(user, d)` in `cmd/nebula-server` calls `BeginLogin` on the
   executor, stores `{user, d.Digest(), expiry}` under the challenge ID, and
   returns the request options.
2. The browser runs `navigator.credentials.get()` and posts the assertion.
3. `CommitVulnDecision` checks the admin role, takes the challenge (user, digest
   and expiry must match, single use), calls `FinishLogin`, checks that the
   returned user equals the requesting user, and writes the decision and its
   audit entry in one `vulnstore` transaction.

   **The one-transaction write is new work, not existing code.** The five
   decision store methods take no auditor. `internal/vulnstore/human.go:33-35`
   says the caller "audits the change", `internal/vulnstore/reset.go:49-50`
   says the caller writes the audit log, and `internal/vulnstore/vulnstore.go:35`
   says the audit log is the caller's job. Only `AgentConfigStore.Change` takes
   an auditor: `internal/vulnstore/agentcfg.go:209` (interface `AgentAuditor`)
   and `:284` (`audit AgentAuditor`), with `auditlog.Store.WithTx`
   (`internal/auditlog/auditlog.go:114`) as the implementation. Variant A
   therefore needs a `vulnstore` API change before the handler can be written:
   each decision method (`SetAcceptedRisk`, `SetFalsePositive`, `ConfirmHeld`,
   `DiscardHeld`, `ResetMark`) takes an auditor like `AgentConfigStore.Change`,
   or a transactional variant of it, and writes the decision row and the audit
   line inside one `WithTx` call. Without that change a decision row and its
   audit line can commit separately.

**Protected paths touched:** none. `cmd/nebula-server/` is not in
`.github/protected-paths.txt`; `internal/vulnstore/` and `internal/web/ui/` are
not either. `proto/` and `internal/executor/` stay unchanged.

**What a compromised `nebula-server` could do.** (The common limit above
applies to every item: a compromised server can also write decisions to
`vulnstore` with no assertion.)
- It can start login challenges itself and have the maintainer sign any
  decision that the maintainer is shown. The signature covers the executor's
  login challenge, not the decision text. That is the UI deception case in
  `docs/threat-model.md:160` and the same limit that the T3 row accepts for
  the LLM URL (`docs/threat-model.md:127`: "detected by the audit entry and
  event, not prevented").
- It can skip the digest check in its own code. The executor cannot detect
  this, because the executor never sees the digest.
- It can forge the server-side audit line. Server audit lines are not signed
  (`docs/threat-model.md:163`).
- It cannot obtain a privileged session from a login assertion:
  `FinishLogin` only returns the credential and user name.

**Effort.** Medium (estimate, not measured). Three parts: (a) the `vulnstore`
change above, which alters the signatures of five decision methods and so
touches their callers and tests; (b) a new `cmd/nebula-server` file modelled
on `vuln_agentcfg.go`, plus wiring in `cmd/nebula-server/vuln.go`; (c) the
tests. The login flow is already written and in use for A1.8.

**Tests affected.** New: handler-level tests for `BeginVulnDecision` and
`CommitVulnDecision` (rejections: wrong user, wrong digest, expired, reused
challenge, assertion refused, not admin). Existing tests that must keep
passing after the signature change, updated and not weakened: the
`cmd/nebula-server` vuln tests, the `internal/web/ui` vuln tests, and the
`internal/vulnstore` human-state and reset tests (`human_test.go`,
`closure_test.go`, `reset_test.go`).

## Variant B: new executor RPC that binds the assertion to the decision digest

A new executor RPC, modelled on `CommitReadGrant`:

1. `ProposeVulnDecision` (role: server) receives the canonical decision fields
   and returns a decision digest and a challenge that the executor binds to
   that digest.
2. `CommitVulnDecision` (role: server) relays the assertion. The executor
   verifies the assertion against the digest-bound challenge, single use, and
   records a signed event.
3. `nebula-server` applies the decision only after the executor accepted it.

The executor must compute the digest itself. The current digest
(`vuln_decide.go:89-96`) is `json.Marshal` of a Go struct, which is not a
cross-language canonical encoding. Moving it into `internal/canonical`
(protected) or defining a canonical proto encoding is part of this variant.

**Protected paths touched:** `proto/` (new RPCs; run `make generate`) and
`internal/executor/` (new handler, role check, signed event). Both are listed
in `.github/protected-paths.txt` (lines 16 and 29). The challenge can be held
in memory as for read grants, so `internal/executordb/` (listed at line 30)
may not change. `internal/executorclient/` is **not** listed in
`.github/protected-paths.txt` (no line matches it; `internal/executor/` ends
in a slash and does not match it), so it is not protected. It changes only if
the server needs a new client call. Any change to the protected paths needs a
maintainer review under AGENTS.md. This paper does not change them.

**What a compromised `nebula-server` could do.** (The common limit above
applies: it can still write decisions to `vulnstore` with no assertion.)
- It can still show a false decision in the UI and get a signature for it
  (same UI deception limit as A, `docs/threat-model.md:160`).
- It cannot get a signature to count for a different digest: the challenge is
  bound to the digest in the executor. In A, the same protection holds only if
  the server's own check is correct.
- It cannot make the executor's signed record show a decision the user did
  not sign. It can still apply a different decision to its own store, because
  step 3 leaves the applying to the server.
- The executor's signed events are evidence of what was accepted. The server's
  applied state and its server-side audit line remain server-owned, as in A.

**Effort.** Medium to large. A proto change with generated code, an executor
handler and tests under the executor's privileged test setup, a server client
call, and a canonical encoding for the decision digest. Requires a maintainer
review of protected paths.

**Tests affected.** Protobuf and `make generate` check, executor role tests,
a replay test (a signature for digest X rejected for digest Y), single-use and
expiry tests, plus the server-side tests of Variant A.

## Comparison

| | Variant A | Variant B |
| --- | --- | --- |
| Binding checked by | `nebula-server` | executor (digest and single use); the server still applies the decision |
| Applied decision state | `nebula-server` (`vulnstore`) | `nebula-server` (`vulnstore`), unchanged by B |
| Compromised server writes a decision directly, no assertion | possible (common limit) | possible (common limit), same |
| Compromised server gets a maintainer to sign a shown decision | possible (UI deception) | possible (same UI limit) |
| Signature for one digest used for another | refused only if the server's check is correct | refused by the executor |
| Evidence of what was signed | server audit line only (not signed) | executor's signed event, in addition |
| Protected paths | none | `proto/`, `internal/executor/` (both listed); `internal/executorclient/` is not protected |
| Effort | medium (includes the `vulnstore` auditor change) | medium to large |
| Precedent | A1.8 agent settings, accepted in ADR 0011 | `CommitReadGrant` (read grants) |
| Matches ADR Q4 text | yes ("fresh WebAuthn assertion") | yes |

## Recommendation (proposal, the maintainer decides)

**Adopt Variant A now, and plan Variant B as a later hardening step.**

Reasons:
1. It uses a mechanism the maintainer has already accepted for a comparable
   admin change (A1.8).
2. It closes the gap that the operator sees today, without touching protected
   paths. It needs the `vulnstore` auditor change (follow-up 1), which is
   work in its own right.
3. Variant B is stronger at the request layer and gives signed evidence, but
   it moves the decision check into the executor and needs a canonical digest
   encoding. Against a compromised `nebula-server` it protects no more of the
   applied state than A does (see the common limit). That is more work and risk
   than the present gap justifies on its own.

The maintainer should accept the limit explicitly, because it holds for both
variants: a compromised `nebula-server` can write any decision to `vulnstore`
without an assertion. Under Variant A it can also get a maintainer to sign a
shown decision and apply it, and the audit trail shows it afterwards. Accepting
risk and false positives can hide findings, so the impact is not zero. Choosing
B does not remove this limit; only a change to where the decision state is
held would do that, and that is a separate decision.

## Follow-up tickets

### If Variant A is chosen

1. **`vulnstore` auditor change (prerequisite, new work).** Give the five
   decision methods (`SetAcceptedRisk`, `SetFalsePositive`, `ConfirmHeld`,
   `DiscardHeld`, `ResetMark`) an auditor argument of the `AgentAuditor` kind
   (`internal/vulnstore/agentcfg.go:209`), or a transactional variant, so each
   decision row and its audit line commit in one `WithTx` call. Today the
   methods take no auditor (`human.go:33-35`, `reset.go:49-50`). Files:
   `internal/vulnstore/human.go`, `internal/vulnstore/reset.go`, the auditor type
   (new or reused), and the callers and tests of these methods:
   `internal/vulnstore/human_test.go`, `closure_test.go`, `reset_test.go`. The
   tests are updated for the new signature and keep their assertions.
2. **Backend (`cmd/nebula-server`).** New file, modelled on
   `cmd/nebula-server/vuln_agentcfg.go`, implementing `BeginVulnDecision` and
   `CommitVulnDecision` in place of `vuln.go:706-713`, and calling the auditor
   version from follow-up 1. Remove `errVulnDecisionsUnavailable`
   (`vuln.go:592-594`) only when both methods are real. Files:
   `cmd/nebula-server/vuln.go`, the new file.
3. **Required test over real HTTP with a real `vulnstore`.** Start the real
   handler, post a decision, and check: refused for a non-admin; refused when
   the digest or user does not match the challenge; refused on reuse; accepted
   once; the decision row and the audit entry are written in one transaction
   (a failing audit write leaves no decision row). No mocks of `vulnstore`.
4. **Call `ReviewHumanStates` from `runSweeps`** (`cmd/nebula-server/vuln.go:474`)
   so that human states are re-checked after each run. Test: a state whose
   basis changed is reopened after a sweep.
5. **Notify `MarkReset`.** Call `(*Notifier).MarkReset` (`internal/vulnnotify/vulnnotify.go:607`)
   from the mark reset path after a successful `ResetMark`. Test: a reset
   produces exactly one notification.
6. **Documentation.** Update `docs/admin/guide.md:1791-1797` (protected, so a
   separate maintainer change).

### If Variant B is chosen later

1. **Proto.** `proto/nebula/executor/v1/executor.proto`: `ProposeVulnDecision`
   and `CommitVulnDecision` RPCs with a canonical decision message. Run
   `make generate`. Protected.
2. **Executor.** `internal/executor/`: handler, role check (server relays,
   admin approves), digest-bound challenge, single use, signed event. Protected.
3. **Canonical digest.** Move the digest into a shared encoding (protected, or
   in a new package with a maintainer decision).
4. **Server client.** `internal/executorclient/` (not protected per
   `.github/protected-paths.txt`), then `cmd/nebula-server` switches from
   Variant A to Variant B. The `vulnstore` auditor change of Variant A's
   follow-up 1 stays in place: B's applying step still writes the decision and
   its audit line in one transaction.
5. **Tests.** Replay across digests rejected; single use; expiry; the
   Variant A tests from above still pass; the real-HTTP test with real
   `vulnstore`.
6. **Follow-ups 4 and 5 of Variant A** apply to both variants.

## Test

This is a document; no test can cover it. Each cited `file:line` was checked
against the tree by reading or grepping the cited lines. The check list is
below, so a reader can repeat it. Lines are as they stand on this branch.

| Citation | Checked content |
| --- | --- |
| `internal/web/ui/vuln_decide.go:57-61` | five `VulnDecisionKind` constants |
| `internal/web/ui/vuln_decide.go:89-96` | `Digest()`: `json.Marshal` plus `nos-vuln-decision-v1` prefix |
| `internal/web/ui/vuln.go:166-172` | `BeginVulnDecision` / `CommitVulnDecision` interface |
| `cmd/nebula-server/vuln.go:474` | `runSweeps` definition (no call to `ReviewHumanStates`) |
| `cmd/nebula-server/vuln.go:592-594`, `:706-708`, `:711-713` | `errVulnDecisionsUnavailable` and the two stubs |
| `internal/vulnstore/human.go:33-35` | comment: caller "audits the change" |
| `internal/vulnstore/human.go:70,92,170,277,358` | `SetAcceptedRisk`, `SetFalsePositive`, `ReviewHumanStates`, `ConfirmHeld`, `DiscardHeld` |
| `internal/vulnstore/human_test.go:95,129,154` | test `TestReviewHumanStatesReopens` (:95) and its two calls |
| `internal/vulnstore/reset.go:49-50`, `:165` | comment: caller writes the audit log; `ResetMark` |
| `internal/vulnstore/vulnstore.go:35` | audit log is the caller's job |
| `internal/vulnstore/agentcfg.go:207-210`, `:284` | `AgentAuditor` interface; `AgentConfigStore.Change` takes it |
| `internal/vulnnotify/vulnnotify.go:607` | `(*Notifier).MarkReset` |
| `internal/auditlog/auditlog.go:114` | `Store.WithTx` |
| `internal/executor/webauthn.go:174-200` | `BeginLogin` / `FinishLogin` take no digest |
| `internal/executor/roles_read.go:142-155` | `CommitReadGrant` |
| `proto/nebula/executor/v1/executor.proto:161,165,2884-2889` | `BeginLogin`, `FinishLogin` rpc; `CommitReadGrantRequest` |
| `cmd/nebula-server/vuln_agentcfg.go:56-60`, `:166`, `:181-200` | login relay interface; `take`; `CommitVulnAgentChange` |
| `docs/adr/0011-vulnerability-management.md:794-800`, `:1108`, `:3891-3892`, `:3896-3904` | Q4 assertion rule; Q4 decision row; A1.8 `server.db` and login assertion |
| `docs/threat-model.md:57,78,127,160,163` | permit/WebAuthn row; feed row; T3; UI deception; unsigned server audit lines |
| `docs/admin/guide.md:1791-1795` | operator text on refused decisions |
| `.github/protected-paths.txt:16,29,30` | `proto/`; `internal/executor/`; `internal/executordb/`. No line matches `internal/executorclient/` |

No Go file changed, so `make check` is not run here; CI runs it on the PR.
