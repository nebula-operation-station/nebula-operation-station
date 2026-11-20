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
  in tests (`internal/vulnstore/human_test.go:95`). `runSweeps`
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
maintainer. Submitting one fails with 'vulnerability decisions need an
executor-verified security key assertion, which this executor does not
offer'." The guide is a protected path; this paper does not change it.

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

**Protected paths touched:** none. `cmd/nebula-server/` is not in
`.github/protected-paths.txt`; `internal/vulnstore/` and `internal/web/ui/` are
not either. `proto/` and `internal/executor/` stay unchanged.

**What a compromised `nebula-server` could do.**
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

**Effort.** Small to medium (estimate, not measured). A new
`cmd/nebula-server` file modelled on `vuln_agentcfg.go`, plus wiring. The
design is already written and in use for A1.8.

**Tests affected.** New: handler-level tests for `BeginVulnDecision` and
`CommitVulnDecision` (rejections: wrong user, wrong digest, expired, reused
challenge, assertion refused, not admin). Existing tests that must keep
passing: the `cmd/nebula-server` vuln tests, the `internal/web/ui` vuln tests,
and the `internal/vulnstore` human-state and reset tests (`human_test.go`,
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

**Protected paths touched:** `proto/` (new RPCs; run `make generate`) and `internal/executor/` (new
handler, role check, signed event). The challenge can be held in memory as
for read grants, so `internal/executordb/` may not change. `internal/executorclient/`
is **not** listed in
`.github/protected-paths.txt`; the task text lists it as protected, so the
maintainer should confirm that. Any change to those paths needs a
maintainer review under AGENTS.md. This paper does not change them.

**What a compromised `nebula-server` could do.**
- It can still show a false decision in the UI and get a signature for it
  (same UI deception limit as A, `docs/threat-model.md:160`).
- It cannot reuse one signature for another decision: the challenge is bound
  to the digest in the executor. In A, the same protection holds only if the
  server's own check is correct.
- It cannot change the decision after the user signed it, because the executor
  checks the digest it issued.
- Its audit trail is in the executor's signed events, not only in the server
  audit line.

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
| Binding checked by | `nebula-server` | executor |
| Forgery by compromised server | can get any decision signed by a maintainer who is shown the same text; can skip its own check | same UI limit; cannot replay a signature across digests; cannot alter the decision after signing |
| Protected paths | none | `proto/`, `internal/executor/`, and `internal/executorclient/` if the maintainer confirms it is protected |
| Effort | small to medium | medium to large |
| Precedent | A1.8 agent settings, accepted in ADR 0011 | `CommitReadGrant` (read grants) |
| Matches ADR Q4 text | yes ("fresh WebAuthn assertion") | yes |

## Recommendation (proposal, the maintainer decides)

**Adopt Variant A now, and plan Variant B as a later hardening step.**

Reasons:
1. It uses a mechanism the maintainer has already accepted for a comparable
   admin change (A1.8). Its guarantee against a compromised server is the same
   as the one already accepted for the LLM URL.
2. It closes the gap that the operator sees today, without touching protected
   paths.
3. Variant B is stronger, but it moves the decision logic into the executor and
   needs a canonical digest encoding. That is more work and risk than the
   present gap justifies on its own.

The maintainer should accept the limit explicitly: under Variant A, a
compromised `nebula-server` that gets a maintainer to sign a shown decision
can apply it, and the audit trail shows it afterwards. Accepting risk and
false positives can hide findings, so the impact is not zero.

## Follow-up tickets

### If Variant A is chosen

1. **Backend (`cmd/nebula-server`).** New file, modelled on
   `cmd/nebula-server/vuln_agentcfg.go`, implementing `BeginVulnDecision` and
   `CommitVulnDecision` in place of `vuln.go:706-713`. Remove
   `errVulnDecisionsUnavailable` (`vuln.go:592-594`) only when both methods
   are real. Files: `cmd/nebula-server/vuln.go`, the new file.
2. **Required test over real HTTP with a real `vulnstore`.** Start the real
   handler, post a decision, and check: refused for a non-admin; refused when
   the digest or user does not match the challenge; refused on reuse; accepted
   once; the decision row and the audit entry are written in one transaction.
   No mocks of `vulnstore`.
3. **Call `ReviewHumanStates` from `runSweeps`** (`cmd/nebula-server/vuln.go:474`)
   so that human states are re-checked after each run. Test: a state whose
   basis changed is reopened after a sweep.
4. **Notify `MarkReset`.** Call `(*Notifier).MarkReset` (`internal/vulnnotify/vulnnotify.go:607`)
   from the mark reset path after a successful `ResetMark`. Test: a reset
   produces exactly one notification.
5. **Documentation.** Update `docs/admin/guide.md:1791-1797` (protected, so a
   separate maintainer change).

### If Variant B is chosen later

1. **Proto.** `proto/nebula/executor/v1/executor.proto`: `ProposeVulnDecision`
   and `CommitVulnDecision` RPCs with a canonical decision message. Run
   `make generate`. Protected.
2. **Executor.** `internal/executor/`: handler, role check (server relays,
   admin approves), digest-bound challenge, single use, signed event. Protected.
3. **Canonical digest.** Move the digest into a shared encoding (protected, or
   in a new package with a maintainer decision).
4. **Server client.** `internal/executorclient/` (confirm protected status
   first), then `cmd/nebula-server` switches from Variant A to Variant B.
5. **Tests.** Replay across digests rejected; single use; expiry; the
   Variant A tests from above still pass; the real-HTTP test with real
   `vulnstore`.
6. **Follow-ups 3 and 4 above** apply to both variants.

## Test

This is a document; no test can cover it. Each cited `file:line` was checked
against the tree with grep before the commit, and the result is in the report.
No Go file changed, so `make check` is not run here; CI runs it on the PR.
