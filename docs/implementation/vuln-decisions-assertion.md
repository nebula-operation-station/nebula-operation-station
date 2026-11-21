# Decision paper: security key assertion for maintainer decisions (ADR 0011 Q4)

Status: **decided** by the maintainer, 2026-11-21; see "Decision (2026-11-21,
maintainer)" below (previously: **open, maintainer decides.** This paper
decides nothing). It sets out the current state, two ways to bind the security key assertion to a
maintainer decision, a recommendation (marked as a proposal) and the follow-up
tickets for each variant. The recommendation does not change any ADR or spec.

Ticket: uf04 (autopilot), Issue: none.

## Decision (2026-11-21, maintainer)

The maintainer (Axel) decided on 2026-11-21 at 13:48 (UTC+1) in chat. Where the
decision differs from the text below, the decision wins. Original wording
(German), verbatim:

> **uf04 (docs/implementation/vuln-decisions-assertion.md, ADR 0011 Q4):**
> Variante A (Login-Assertion mit serverseitiger Digest-Bindung wie A1.8);
> Variante B bleibt spätere Härtung. Zusatz: auch `discard_hold` braucht eine
> frische Assertion.

In English (translation by Claude, not part of the decision):

- **Variant A** (login assertion with a server-side digest binding, as in
  A1.8) is chosen; **Variant B** stays a later hardening step.
- **Addition:** `discard_hold` also needs a fresh assertion.

## Why this is open

ADR 0011 decides who may make the five maintainer decisions. Four of them need
a **fresh WebAuthn assertion** "as for read-lease approval": accept risk, false
positive, held-closure confirmation and the mark reset
(`docs/adr/0011-vulnerability-management.md:796-800`; Q4 was decided 2026-11-09
at `:798`; the Q4 row at `:1108` still reads "open"). The fifth, discarding a
held closure (`discard_hold`), is not named there: its row at `:731` names only
"Admin" (or automatic supersession). Whether it needs an assertion is an open point for the maintainer.
The ADR does not say how the assertion is bound to the decision, and it
does not say whether the hardened mode of the executor (CLI-only approval,
see below) applies to decisions. The only executor RPC that binds an assertion
to a digest for vulnerability decisions does not exist, so every submit of a
decision is refused. The maintainer therefore cannot act on held closures,
accepted risks, false positives or feed mark resets through the product today.

The A1.8 agent settings (LLM endpoint) already have a working assertion path.
ADR 0011 explicitly accepts it there and names its mechanism
(`docs/adr/0011-vulnerability-management.md:3899-3904`). This paper asks
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

`docs/admin/guide.md:1791-1797`: "Maintainer decisions are refused for now.
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
| Read grant approval, default mode (`CommitReadGrant`) | executor | executor challenge bound to the grant digest (SHA-256 over the domain separator `nebula-read-grant-v2`, digest, nonce, expiry); the server only relays the assertion | `internal/permit/lease.go:636-649` (challenge; separator at `:642`), `:682-691` (issued), `:737-760` (commit); `internal/executor/roles_read.go:142-155`; request `proto/nebula/executor/v1/executor.proto:2884-2889` |
| Permit approval | executor | challenge = SHA-256(digest, nonce, expiry), single use, sign counter checked | `docs/threat-model.md:57` (`internal/permit`, `internal/webauthnverify`) |
| Agent LLM settings (A1.8) | executor for the assertion, `nebula-server` for the binding | login assertion (`BeginLogin`/`FinishLogin`, `executor.proto:161,165`); server holds a single-use challenge bound to user and change digest | `cmd/nebula-server/vuln_agentcfg.go:56-60` (relay interface), `:166` (`take`), `:181-200` (commit) |

`executor.(*Service).BeginLogin` and `FinishLogin` take no digest and no mode
(`internal/executor/webauthn.go:174-199`). The executor checks the signature
against its own login challenge and returns the credential and the user name.
It does not know which change or decision the user signed. The binding exists
only in `nebula-server`.

### Hardened mode: read grants are CLI-only

The executor has a mode, `ModeHardened`, which "requires `nebula approve`" for
the high-risk approvals (`internal/permit/permit.go:46-47`). Read grants show
the pattern that ADR 0011 Q4 names as its model:

- In hardened mode a proposed read grant gets the requirement `RequireCLI`, and
  **no challenge is issued** (`internal/permit/lease.go:682-687`; a challenge
  is created only when `req != RequireCLI`, `:687-691`).
- The browser commit is refused in hardened mode: `CommitReadGrant` returns
  "hardened mode: use nebula read-grant approve" (`internal/permit/lease.go:746-748`).
- Approval is the CLI: `nebula read-grant approve <digest>`
  (`cmd/nebula/readgrant.go:26` usage, `:51` dispatch, `:152` RPC call). It
  calls `ApproveReadGrantCLI`, which is admin-only and takes no assertion
  (`internal/executor/roles.go:123`, `internal/executor/roles_read.go:175-188`,
  `internal/permit/lease.go:763-773`). The admin reviews the frozen document
  with `ListPendingReadGrants` first (`internal/executor/roles_read.go:158`,
  `roles.go:122`).
- The threat model names this CLI path as the defence for UI deception
  (`docs/threat-model.md:160`: "Defence: `nebula approve` (hardened mode)").
  Batches and permits use the command `nebula approve` (`cmd/nebula/batch.go:214`).
  Read grants use `nebula read-grant approve`.

Decisions have no hardened-mode path today. The browser-side decision would
have to be approved with a WebAuthn assertion in every mode, unless the
maintainer decides that decisions follow the read-grant rule.

## Common limit: `nebula-server` owns the decision state

The decision state is held by `nebula-server`: the `vulnstore` tables in
`server.db` (`docs/adr/0011-vulnerability-management.md:3890-3892` names the
same `server.db` and `internal/vulnstore` location for the A1.8 settings).
Neither variant moves that state into the executor. The executor sees a
decision only as a digest it signs or verifies; it never writes or reads the
applied state.

Consequence for both variants: a compromised `nebula-server` can write any
decision (accept a risk, mark a false positive, confirm or discard a held
closure, reset a feed mark) directly into its own store, with no assertion at
all. The assertion gates the decision path the UI uses. It does not gate the
database. Neither variant prevents this. The same holds for web sessions: the
server creates them itself (`internal/web/auth/auth.go:281`), so no assertion
gates a session once the server is compromised.

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
not either. `proto/` and `internal/executor/` stay unchanged. Two limits below
can only be closed in protected paths (see "Login purpose" and "Hardened mode").

**What a compromised `nebula-server` could do.** (The common limit above
applies to every item: a compromised server can also write decisions to
`vulnstore` with no assertion.)
- It can start login challenges itself and have the maintainer sign any
  decision that the maintainer is shown. The signature covers the executor's
  login challenge, not the decision text. That is the UI deception case in
  `docs/threat-model.md:160`. It is also the same limit that the threat model
  accepts for the help assistant's LLM URL (T3 row, `docs/threat-model.md:127`,
  ADR 0014 D6; a different feature, detected by the audit entry and event, not
  prevented). No threat-model row covers the ADR 0011 A1.8 vuln-agent LLM URL;
  ADR 0011 accepts the login-assertion mechanism at
  `docs/adr/0011-vulnerability-management.md:3899-3904`.
- **Login purpose.** A login assertion is not bound to a purpose.
  `FinishLogin` checks the signature against the executor's login challenge
  and returns the credential and user name (`internal/executor/webauthn.go:183-199`).
  Variant A's decision challenges come from the same executor login pool as
  web logins: `BeginLogin` stores them in `r.logins` (`internal/webauthnreg/login.go:47-74`;
  challenge of 32 random bytes, `:62`, TTL `LoginTTL` 2 min at `:21`, pool
  limit `MaxPendingLogin` 32 at `:22`). A decision assertion is therefore also
  a valid login assertion for the same user, and the executor cannot tell the
  two uses apart. The web login path creates a web session from that result
  (`internal/web/auth/auth.go:272-281`, audit line at `:287`).
  **Against a compromised `nebula-server` this gap adds nothing.** The server
  creates web sessions itself: `h.sessions.Create` at `auth.go:281` (and the
  recovery path at `:313`) runs with no assertion at all, so a compromised
  server can open a session for any user without a decision signature. The
  login assertion protects only against an attacker outside the server who
  lacks the key (for example someone holding only a stolen browser session).
  Against a compromised server only a CLI/executor-side check protects, which
  is hardened mode (see below); neither variant gives that in default mode.
  Purpose binding still matters for a party that holds a decision assertion but
  not the server. Its window is the 2-minute challenge TTL, and a separate
  challenge type would close it. The executor logs login uses
  (`login_succeeded` at `internal/executor/webauthn.go:197`), but it cannot
  tell a decision use from a login. Purpose binding lies in protected paths
  (`internal/webauthnreg/`, `internal/executor/`) and is outside Variant A as
  written.
- It can skip the digest check in its own code. The executor cannot detect
  this, because the executor never sees the digest.
- It can forge the server-side audit line. Server audit lines are not signed
  (`docs/threat-model.md:163`).

**Hardened mode under Variant A.** A has no CLI-only path. `BeginLogin` takes
no mode and issues a login challenge in every mode (`internal/executor/webauthn.go:174-180`),
so the browser can always sign a decision, and the UI deception limit above
holds in hardened mode too. Hardened mode for decisions would need a mode
check in the executor (protected) plus a CLI command (`cmd/nebula/`, protected),
or a server-side refusal that a compromised server would skip.

**Effort.** Medium (estimate, not measured). Three parts: (a) the `vulnstore`
change above, which alters the signatures of five decision methods and so
touches their callers and tests; (b) a new `cmd/nebula-server` file modelled
on `vuln_agentcfg.go`, plus wiring in `cmd/nebula-server/vuln.go`; (c) the
tests. The login flow is already written and in use for A1.8. The login-purpose
and hardened-mode limits are not included; closing them is separate protected
work (see Variant B).

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

**Read-grant precedent, corrected.** The read-grant challenge is held in
memory: the pending grant (`internal/permit/lease.go:615-621`, `pendingReadGrant`)
carries its challenge, which is derived by `readGrantChallengeFor`
(`lease.go:636-649` (separator `nebula-read-grant-v2` at `:642`)). The approved grant is **not** only in memory. It is
stored with `SaveReadGrant` (`internal/permit/lease.go:794`, implemented by
`internal/executordb/lease.go:33`). The signed event of B is stored the same
way: the executor writes its event chain through `executordb.InsertEvent`
(`internal/executordb/events.go:32`, interface `internal/events/events.go:67`).
So B needs storage changes in `internal/executordb/` for the approved decision
and the signed event, and that package is protected (line 30). The in-memory
part of the precedent covers only the challenge.

**Protected paths touched:** `proto/` (new RPCs; run `make generate`, line 16),
`internal/executor/` (new handler, role check, signed event, line 29),
`internal/permit/` (the read-grant model and the hardened-mode rule are
there; a decision model would sit beside it, line 18), `internal/canonical/`
(the canonical digest, if placed there, line 17), `internal/executordb/`
(stored decision and signed event, line 30), `cmd/nebula/` (CLI approval in
hardened mode, line 34), and `internal/webauthnreg/` (only if the decision
challenge gets its own pool, line 22). `internal/executorclient/` is **not**
listed in `.github/protected-paths.txt` (no line matches it; `internal/executor/`
ends in a slash and does not match it), so it is not protected. It changes only
if the server needs a new client call. Any change to the protected paths needs
a maintainer review under AGENTS.md. This paper does not change them.

**Login purpose under B.** B's decision challenge is digest-bound and must be
a separate challenge type that the login path (`FinishLogin`) cannot consume.
That is a requirement of this variant, not an existing feature: today the login
pool has no purpose field (`internal/webauthnreg/login.go:47-74`).

**Hardened mode under B.** B can mirror read grants. In hardened mode
`ProposeVulnDecision` would issue no challenge (as `lease.go:682-687`), the
browser commit would be refused (as `lease.go:746-748`), and an admin-only
CLI approval (`cmd/nebula/`, protected, with a new executor RPC like
`ApproveReadGrantCLI`, `roles_read.go:175-188`) would approve it after the
admin reviews the frozen canonical document. Whether the ADR's "fresh WebAuthn
assertion" still applies in hardened mode is a maintainer decision, because
in that case the approval would not be an assertion at all.

**What a compromised `nebula-server` could do under B.** (The common limit above
applies: it can still write decisions to `vulnstore` with no assertion.)
- In default mode it can still show a false decision in the UI and get a
  signature for it (same UI deception limit as A, `docs/threat-model.md:160`).
  In hardened mode, if B mirrors read grants, it cannot get a signature at all,
  because no challenge is issued; the admin's CLI approval is the gate.
- It cannot get a signature to count for a different digest: the challenge is
  bound to the digest in the executor. In A, the same protection holds only if
  the server's own check is correct.
- Against a compromised server the separate challenge type of "Login purpose
  under B" adds nothing: the server can already create a session with no
  assertion (`auth.go:281`). It matters only for a party that holds a signature
  and not the server, and there B is stronger than A.
- It cannot make the executor's signed record show a decision the user did
  not sign. It can still apply a different decision to its own store, because
  step 3 leaves the applying to the server.
- The executor's signed events are evidence of what was accepted. The server's
  applied state and its server-side audit line remain server-owned, as in A.

**Effort.** Medium to large. A proto change with generated code, an executor
handler and tests under the executor's privileged test setup, a stored decision
and signed event in `executordb`, a server client call, a canonical encoding
for the decision digest, and (for hardened mode) a CLI command. Requires a
maintainer review of protected paths.

**Tests affected.** Protobuf and `make generate` check, executor role tests,
a replay test (a signature for digest X rejected for digest Y), single-use and
expiry tests, a test that a decision challenge is refused by `FinishLogin` (and
a login challenge by the decision RPC), a hardened-mode test (no challenge
issued, browser commit refused), plus the server-side tests of Variant A.

## Comparison

| | Variant A | Variant B |
| --- | --- | --- |
| Binding checked by | `nebula-server` | executor (digest and single use); the server still applies the decision |
| Applied decision state | `nebula-server` (`vulnstore`) | `nebula-server` (`vulnstore`), unchanged by B |
| Compromised server writes a decision directly, no assertion | possible (common limit) | possible (common limit), same |
| UI deception, default mode (server shows a false decision, maintainer signs) | possible | possible (same limit) |
| UI deception, hardened mode | possible: no CLI-only path; `BeginLogin` issues a challenge in every mode (`internal/executor/webauthn.go:174-180`) | avoidable: read-grant pattern (no challenge, CLI approval); needs `cmd/nebula/` and a new RPC |
| Decision signature used as a login | against a compromised server: no effect, it creates sessions itself (`auth.go:281`). Against a party holding only the signature: possible, same login pool, `FinishLogin` checks no purpose (`internal/webauthnreg/login.go:47-74`) | against a compromised server: no effect. Against a signature holder: avoidable, if the decision challenge is a separate type (a requirement of B, not yet designed) |
| Signature for one digest used for another | refused only if the server's check is correct | refused by the executor |
| Evidence of what was signed | server audit line (unsigned) and executor `login_succeeded` log (a login, not a decision) | executor's signed event in `executordb`, in addition |
| Protected paths | none for the change itself; closing login purpose and hardened mode needs `internal/webauthnreg/`, `internal/executor/`, `cmd/nebula/` | `proto/`, `internal/executor/`, `internal/permit/`, `internal/canonical/`, `internal/executordb/`, `cmd/nebula/` (hardened CLI), `internal/webauthnreg/` (if separate pool); `internal/executorclient/` is not protected |
| Effort | medium (includes the `vulnstore` auditor change) | medium to large |
| Precedent | A1.8 agent settings, accepted in ADR 0011 (`:3899-3904`); no hardened mode there | `CommitReadGrant` (`internal/executor/roles_read.go:142-155`) and hardened mode (`internal/permit/lease.go:682-687, 746-748`) |
| Matches ADR Q4 text | the assertion: yes ("fresh WebAuthn assertion"). Hardened-mode CLI approval: no, and ADR 0011 is silent on it | the default-mode assertion: yes. A hardened-mode CLI approval is not an assertion, so it needs the maintainer to say whether Q4 covers hardened mode |

## Recommendation (proposal, the maintainer decides)

**Adopt Variant A now, as a conditional choice, and plan Variant B as a later
hardening step if the maintainer needs either of the two limits below closed.**

Reasons:
1. It uses a mechanism the maintainer has already accepted for a comparable
   admin change (A1.8), and the change itself touches no protected path.
2. It closes the gap that the operator sees today, without touching protected
   paths. It needs the `vulnstore` auditor change (follow-up 1), which is
   work in its own right.
3. Variant B is stronger on three points: the digest binding, the signed
   evidence, and two limits that A cannot close: a decision signature usable as
   a login by a party outside the server, and no CLI-only approval in hardened
   mode. It moves the decision
   check into the executor and needs a canonical digest encoding and changes in
   six protected paths. Against a compromised `nebula-server` it protects no
   more of the applied state than A does (see the common limit). That is more
   work and risk than the present gap justifies on its own, unless the
   maintainer requires the two limits closed.

The maintainer should accept three limits explicitly, because they hold for
Variant A:
- A compromised `nebula-server` can write any decision to `vulnstore` without
  an assertion (holds for both variants).
- A compromised `nebula-server` can get a maintainer to sign a shown decision
  and apply it, and the audit trail shows it afterwards (both variants in
  default mode; A in hardened mode too).
- A decision signature is also a login signature for the same user (A only).
  This adds no capability against a compromised server, which can create a
  session for any user with no assertion (`auth.go:281`). It matters only for a
  party that holds a signature and not the server. Only the hardened-mode
  CLI/executor check protects against a compromised server, and only if the
  maintainer requires it.

Accepting risk and false positives can hide findings, so the impact is not zero.
Choosing B does not remove the first limit; only a change to where the decision
state is held would do that, and that is a separate decision.

The maintainer also decides whether decisions must be CLI-only in hardened
mode, as read grants are. If yes, Variant A is not enough, and B's hardened part
is required.

## Follow-up tickets

### If Variant A is chosen

0. **Maintainer decisions first.** (a) Accept the three limits above in
   `docs/threat-model.md` (protected, a separate maintainer change). (b) Say
   whether decisions follow the hardened-mode CLI rule. If yes, do not choose
   Variant A alone. (c) Say whether `discard_hold` needs the assertion (open
   point: ADR 0011 `:796-800` does not name it; its row at `:731` names only "Admin" or automatic supersession).
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
7. **Login purpose and hardened mode (only if the maintainer requires them).**
   Both need protected paths (`internal/webauthnreg/`, `internal/executor/`,
   `cmd/nebula/`). Without them, these limits stay open under A.

### If Variant B is chosen later

1. **Proto.** `proto/nebula/executor/v1/executor.proto`: `ProposeVulnDecision`
   and `CommitVulnDecision` RPCs with a canonical decision message. Run
   `make generate`. Protected.
2. **Executor.** `internal/executor/`: handler, role check (server relays,
   admin approves), digest-bound challenge in a purpose-bound pool that
   `FinishLogin` cannot consume, single use, signed event. Protected.
3. **Permit model.** `internal/permit/`: the decision's pending state and the
   hardened-mode rule (no challenge, `RequireCLI`), modelled on the read grants
   (`lease.go:682-687`, `:746-748`). Protected.
4. **Storage.** `internal/executordb/`: stored approved decision (as
   `SaveReadGrant`, `lease.go:794`) and signed event (`InsertEvent`,
   `events.go:32`). Protected.
5. **Canonical digest.** Move the digest into a shared encoding (protected, or
   in a new package with a maintainer decision).
6. **CLI (hardened mode).** `cmd/nebula/`: a decision approval command beside
   `nebula read-grant approve` (`readgrant.go:26,51,152`), with an admin-only
   RPC. Protected.
7. **Server client.** `internal/executorclient/` (not protected per
   `.github/protected-paths.txt`), then `cmd/nebula-server` switches from
   Variant A to Variant B. The `vulnstore` auditor change of Variant A's
   follow-up 1 stays in place: B's applying step still writes the decision and
   its audit line in one transaction.
8. **Tests.** Replay across digests rejected; single use; expiry; decision and
   login challenges not interchangeable; hardened mode issues no challenge; the
   Variant A tests from above still pass; the real-HTTP test with real
   `vulnstore`.
9. **Follow-ups 4 and 5 of Variant A** apply to both variants.

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
| `internal/vulnstore/agentcfg.go:209`, `:284` | `AgentAuditor` interface; `AgentConfigStore.Change` takes it |
| `internal/vulnnotify/vulnnotify.go:607` | `(*Notifier).MarkReset` |
| `internal/auditlog/auditlog.go:114` | `Store.WithTx` |
| `internal/executor/webauthn.go:174-199` | `BeginLogin` (`:174-180`, no mode, no digest) / `FinishLogin` (`:183-199`, no digest) |
| `internal/executor/webauthn.go:197` | `login_succeeded` audit line |
| `internal/webauthnreg/login.go:21-22`, `:47-74`, `:62`, `:72` | `LoginTTL`, `MaxPendingLogin`; `BeginLogin`; challenge bytes; `r.logins` store |
| `internal/web/auth/auth.go:272-281`, `:287`, `:313` | `FinishLogin` call (`:272`) and `sessions.Create` (`:281`, session minted by the server from its result); `web_login` audit line (`:287`); recovery `sessions.Create` (`:313`, no assertion) |
| `internal/permit/permit.go:46-47` | `ModeHardened` and its "requires `nebula approve`" comment |
| `internal/permit/lease.go:615-621`, `:636-649`, `:682-691` | `pendingReadGrant`; `readGrantChallengeFor` (domain separator `nebula-read-grant-v2` at `:642`); requirement, `RequireCLI` and challenge issue |
| `internal/permit/lease.go:737-760`, `:746-748` | `CommitReadGrant`; hardened-mode refusal |
| `internal/permit/lease.go:763-773`, `:794` | `ApproveReadGrantCLI` (no assertion); `SaveReadGrant` call |
| `internal/executordb/lease.go:33` | `SaveReadGrant` implementation |
| `internal/executordb/events.go:32`, `internal/events/events.go:67` | `InsertEvent` implementation and interface |
| `internal/executor/roles_read.go:142-155`, `:158`, `:175-188` | `CommitReadGrant`; `ListPendingReadGrants`; `ApproveReadGrantCLI` (admin-only, peercred) |
| `internal/executor/roles.go:122-123` | role table: `ListPendingReadGrants` and `ApproveReadGrantCLI` are admin |
| `cmd/nebula/readgrant.go:26`, `:51`, `:152` | usage `read-grant approve`; dispatch; `ApproveReadGrantCLI` RPC call |
| `cmd/nebula/batch.go:214` | `nebula approve` for batches |
| `docs/threat-model.md:57,78,127,160,163` | permit/WebAuthn row; feed row; T3 (help assistant, LLM URL); UI deception and hardened-mode defence; unsigned server audit lines |
| `docs/adr/0011-vulnerability-management.md:796-800`, `:798`, `:731`, `:1108`, `:3890-3892`, `:3899-3904` | "as for read-lease approval" and the four named decisions (`:796-800`); Q4 decided 2026-11-09 (`:798`); hold discard row, "Admin" only (`:731`); Q4 row still "open" (`:1108`); A1.8 `server.db`; A1.8 login assertion |
| `docs/admin/guide.md:1791-1797` | operator text on refused decisions (whole bullet) |
| `.github/protected-paths.txt:13,15,16,17,18,21,22,29,30,34` | `docs/threat-model.md`; `docs/admin/guide.md`; `proto/`; `internal/canonical/`; `internal/permit/`; `internal/webauthnverify/`; `internal/webauthnreg/`; `internal/executor/`; `internal/executordb/`; `cmd/nebula/`. No line matches `internal/executorclient/` |

No Go file changed, so `make check` is not run here; CI runs it on the PR.
