# Ops agent plan (ADR 0016)

Status: **ADR accepted 2026-11-17; ag01 (this plan, spec revision
`v28`, threat model, amendments) done; ag02–ag05, ag07–ag17, ag21 and
ag22 merged; ag06, ag18–ag20 and ag23–ag26 in progress (see [status](../status.md)).**

This plan carries [ADR 0016](../adr/0016-ops-agent.md) into tickets. The
ADR is the authority: where this file and the ADR differ, the ADR and the
spec revision `v28` ([spec 04](../spec/04-revision-history.md#v28-04-01))
win. Every number below is copied from the ADR; a ticket adds no limit,
scope or authority that the ADR does not name.

## Rules every ticket keeps

### Guard rails (ADR 0016, verbatim)

| # | Guard rail |
| --- | --- |
| G1 | **No execution through the API.** No scope of `/api/v1` creates a proposal, plan, permit, lease, schedule, approval or batch. The agent writes notes only |
| G2 | **No event stream over the executor socket.** The agent is not in `nebula-rpc` and never talks to the executor. It polls a server-built work list |
| G3 | **The server sends notifications.** The agent holds no provider token and sends nothing. Message text is a fixed server template, never model output |
| G4 | **No tool loop.** One LLM call per work item with a strict JSON schema. The trigger decides what data is fetched; the model chooses nothing |
| G5 | **ADR 0014 D1 stays.** The help assistant keeps its scope and data limits. The ops agent is a separate backend for admins only |

### Working rules

| # | Rule | Source |
| --- | --- | --- |
| R1 | **Limits are named constants** next to the code that enforces them, with exactly the values in "Limits" below. The ticket that enforces a limit names its constant and tests the value and the rejection one past it | AGENTS.md, ADR 0016 D4, D6 |
| R2 | **No new module.** `go.mod` and `go.sum` stay unchanged; the LLM client is the shared `internal/llmclient` (ADR 0016 Consequences: "No new dependency") | AGENTS.md rule 3 |
| R3 | **Tests first.** Every acceptance criterion and every security rejection (scope, size, character, digest, candidate, data-class and origin rules) becomes at least one test before the code | AGENTS.md |
| R4 | **No network in tests** except loopback and Unix sockets in temporary directories; the LLM is a loopback test server | AGENTS.md rule 8 |
| R5 | **No change to `proto/`, `internal/permit/` or `nebula-executor`** (ADR 0016 Consequences). A ticket that finds it needs one stops and reports (see "Stop and report") | ADR 0016 D9, Consequences |
| R6 | **Everything from the LLM and every projected field is untrusted input:** size limit before parsing, strict schema, unknown fields and invalid UTF-8 rejected, text rendered escaped only | ADR 0016 D6, D7, T8 |
| R7 | **Secrets never appear** in logs, audit, notes, notifications or fixtures; the agent logs no prompt or answer text and never its token | AGENTS.md rule 7, ADR 0016 D14 |
| R8 | **Off by default:** the settings row starts disabled, timer and path unit are not enabled by default | ADR 0016 D1, D12, D13 |

### Limits (ADR 0016)

| Limit | Value | ADR |
| --- | --- | --- |
| Ops-agent tokens | at most one; scopes `ops.read` and `ops.notes.write` only on it, no other scope on it | D2 |
| Timer interval | every 30 minutes | D3 |
| Work list | at most 20 due items per page; `summary` once per day | D3, D4 |
| Work item size | ≤ 32 KiB | D4 |
| API rate | 60 requests per hour per token | D4 |
| Host label in the projection | ≤ 64 bytes | D4 |
| Listening ports per item | ≤ 32 | D4 |
| Findings per group | ≤ 40 by score, the rest as counts | D4 |
| Documentation chunks per item | ≤ 3 | D4 |
| Operator instructions | ≤ 4 KiB | D6 |
| `fix` output | `summary` ≤ 600 bytes; `steps` ≤ 6, each `why` ≤ 300 bytes; `mitigations` ≤ 3, each `text` ≤ 400 bytes; `urgency` ≤ 300 bytes; `citations` ≤ 3 | D6 |
| `summary` and `answer` output | `text` ≤ 2 KiB, `citations` | D6 |
| Retries per item | one at most | D6 |
| Prompt / output | ≤ 12,000 tokens (estimated from bytes) / ≤ 1,024 tokens | D6 |
| LLM call timeout | 90 s | D6 |
| LLM calls | ≤ 20 per run, ≤ 200 per day | D6 |
| Notes | at most 100 per day; retention 30 days or 500 notes, whichever is reached first | D7 |
| Questions | ≤ 2 KiB each; at most 20 open, 50 per day, 30 days; group facts of ≤ 5 named hosts (class `lab`) | D11 |
| Notification log | 30 days, at most 5,000 entries | D10 |
| `lease.expiring` thresholds | within 7 days and again within 1 day; once per grant and threshold | D10 |
| Daily digest windows | grants expiring within 7 days; failed executions of the last 24 h | D10 |

### Stop and report (from the ADR)

- `nebula backup` copies the notes file without a change in `cmd/nebula/`
  (protected): the ticket stops and reports (D7).
- The batch path cannot carry a raised member class without a change in a
  protected path: the ticket stops and reports; container update buttons
  are then not shipped until the maintainer decides (D9).
- Every path, unit name and package in the ADR is to be *verified* in the
  ticket that implements it (ADR status line); a mismatch is reported, not
  guessed.

## Tickets

The plan is `plan-ag.tickets` (IDs `ag01`–`ag26`); the per-ticket scope and
acceptance live there. The phases and their content below are the ADR's
"Tickets" table; the last column names the ADR decisions each phase
carries. **Protected** means a path in `.github/protected-paths.txt`.

| Phase | Tickets | Content (ADR 0016) | ADR decisions | Protected |
| --- | --- | --- | --- | --- |
| A | ag01 | This ADR, spec revision `v28`, threat model, amendments (protected) | all; "Required specification changes" | yes (`docs/adr/`, `docs/spec/`, `docs/threat-model.md`) |
| B (no agent, no LLM) | ag02, ag03, ag04, ag05, ag06, ag07 | Notification log, inbox, lease events, daily digest | D10 | per ticket |
| C | ag08, ag09, ag10, ag11, ag12, ag13, ag14, ag15 | Token class, shared LLM client, fix logic package, projector, notes store, settings store, execution origin, ops API | D2, D3, D4, D5, D6, D7, D9, D12, D14 | per ticket |
| D | ag16, ag17, ag18, ag19, ag20, ag21 | Agent binary, panel and cards, prefilled forms with origin, settings UI, suggestion event, units | D2, D6, D8, D9, D10, D11, D12, D13 | per ticket (units: `deploy/systemd/`) |
| E | ag22, ag23 | Questions in the Ops tab | D11 | per ticket |
| F | ag24, ag25, ag26 | Security tests, browser tests, operator documentation | T1–T9 | per ticket (`test/security/`, `test/browser/`) |

Order: phase B ships first ("Deterministic server parts first", maintainer
decision 7); it needs no agent and no LLM.
