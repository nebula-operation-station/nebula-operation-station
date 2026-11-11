# One-step enrollment plan (ADR 0013)

Status: **plan, not started, 2026-11-11.** ADR 0013 is Proposed; only EN-01
is done. Tickets EN-02 onwards start after the maintainer has decided the open
questions Q1–Q7 of [ADR 0013](../adr/0013-one-step-enrollment.md). EN-03 and
EN-04 are pure libraries and may start before acceptance if the maintainer
agrees, because they change no behaviour.

This plan turns ADR 0013 into PR-sized tickets: one agent job each, tests
first, `make check` per Go ticket, no new dependencies.

## Rules every ticket keeps

| # | Rule | ADR |
| --- | --- | --- |
| E1 | No pin without a matching salted pairing code **and** a HIGH approval with user verification; commit re-probes and pins only the approved key | D3, D4 |
| E2 | The executor decides the code match and builds the permit; the server only forwards operator input | D4 |
| E3 | Offer ID ≥ 128 bits from `crypto/rand`, stored only as SHA-256, logged only as an 8-hex prefix; single use; 15-minute expiry; revocable; uniform `404` for every refusal | D2, D7 |
| E4 | `from=` addresses and the NetBird management URL come from executor-local configuration only | D5, D6 |
| E5 | The NetBird token and setup keys stay in the executor vault; typed NetBird calls only, no generic proxy; setup keys one use, ≤ 1 h, auto-group only the managed group | D6 |
| E6 | The script is downloaded over the NOS TLS origin, hash-checked, then run; never `curl \| sh`, never `-k` | D7 |
| E7 | Script-printed addresses are untrusted hints; endpoints are validated like inventory endpoints | D5 |
| E8 | CLI enrollment, `known_hosts` import, bulk **Enroll hosts** and the ADR 0008 guest join stay byte- and behaviour-compatible | D9 |
| E9 | Named constants for every limit: offer lifetime, open offers (10), offers per hour (30), probes per offer (5), rejected codes (3), script size (64 KiB), download rate (10/min, 60/h per address), NetBird join wait (60 s) | D2, D5, D7 |
| E10 | No secret (setup key, token, offer ID, salt) in logs, errors, results, fixtures or commit messages | AGENTS.md |

## Tickets

**P** marks protected paths (`.github/protected-paths.txt`); such a ticket
needs the maintainer's explicit authorization. "Deps" lists tickets that must
land first.

| Ticket | Scope / paths | P | Deps | Acceptance tests or review |
| --- | --- | --- | --- | --- |
| EN-01: this ADR and plan | `docs/adr/0013-one-step-enrollment.md`, `docs/implementation/one-step-enrollment.md` | yes (`docs/adr/`) | — | Maintainer decision on Q1–Q7; status changed to Accepted with a "Decisions" section |
| EN-02: spec revision | `docs/spec/02`, `03`, `05`, `06`, `08`, `09`, `12`, `04`, `17` | yes | EN-01 | Every new authority (download endpoint, offer store, NetBird token, paired permit) and every limit mapped; reviewer checks spec 08's three ways to avoid blind trust |
| EN-03: pairing code library | new `internal/pairing/` (code construction, Crockford base32, check character, parse/normalise input, constant-time compare); propose adding the path to `.github/protected-paths.txt` | yes (only the protected-paths line) | EN-01 | Fixed test vectors (salt, key blob → code) shared with EN-04's script test; malformed input table (length, alphabet, check character, case, `O/0`, `I/L/1`, separators); non-ed25519 keys rejected; fuzz parse |
| EN-04: shared script generator | new `internal/enrollscript/` from `enrollScript` in `cmd/nebula/enroll.go`; CLI switched to it | yes (`cmd/nebula/`) | EN-03 | Golden test: CLI output byte-identical to today for the same options; one-step template adds pairing, address list and optional NetBird section; script code equals Go code for the EN-03 vectors (run the script part with `sh` in a temp dir, no network); `bash -n`/`shellcheck` on rendered variants; 64 KiB limit; injection table for user, refs, addresses |
| EN-05: offer store | `internal/executordb/` migration and store | yes | EN-02 | Offer row with ID hash, salt, host, SSH user, credential, session binding, expiry, state, script hash, setup-key reference, download time and address, counters; state transitions only forward; final state wipes salt, script and setup-key reference; concurrent download/submit claims are atomic; `Now` injected for expiry |
| EN-06: executor-local enrollment config | `cmd/nebula-executor/` flags/config | yes | EN-02 | Enrollment source addresses (IPs/CIDRs, validated as in `enroll.go`), NetBird management URL and TLS trust, managed group name; invalid config fails at startup; nothing settable over RPC |
| EN-07: paired enrollment permit | `internal/permit/`, `internal/canonical/` | yes | EN-05 | HIGH with UV; binds offer ID hash, host, endpoint, SSH user, credential, full fingerprint, code-matched flag; substitution of any field rejected; replay and expiry; `nebula approve` view shows all bound fields |
| EN-08: offer RPCs | `proto/` (CreateEnrollOffer, FetchEnrollScript, SubmitPairingCode, CommitPairedEnroll, RevokeEnrollOffer, ListEnrollOffers), `make generate`, `internal/executor/` and `roles.go` | yes | EN-04, EN-05, EN-06, EN-07 | Roles: server may create/fetch/submit/commit/revoke, admin may list/revoke; session binding enforced; limits (E9); malformed code counted and never probed; mismatch fails the offer, audits presented fingerprint, notifies; probe failure not counted; pinned or blocked host refused; commit re-probes and pins only the approved key, then tests login; source `paired` in the pin record |
| EN-09: download endpoint | `internal/web/` new unauthenticated route `GET /enroll/<id>` outside the UI auth chain | no | EN-08 | Uniform `404` for unknown, expired, consumed, revoked, malformed and rate-limited; headers (`text/plain`, `attachment`, `no-store`, `nosniff`); path not logged; per-address rate limit; second download refused; loopback-only test server |
| EN-10: one-step UI | `internal/web/ui/`, templates, static JS (no inline script) | no | EN-08, EN-09 | Dialog requires a privileged session; command block with URL and SHA-256; "Show script" does not consume; browser download fallback; code input with check-character validation before submit; address picker as plain text; approval page shows full fingerprint and "code matched"; mismatch page text from ADR 0013 D3; TOFU warning for remote hosts; inventory creation per Q4 |
| EN-11: NetBird API client | new `internal/netbirdapi/` (typed: create/revoke setup key, list peers, get peer, delete peer, read policies); propose adding the path to `.github/protected-paths.txt` | yes (only the protected-paths line) | EN-02, EN-06 | `net/http` + `encoding/json` only; TLS per executor config, no fallback to accept-any; response size limits and schema checks; token never in errors or logs; loopback `httptest` server only; no generic request method exported |
| EN-12: NetBird in offers | `internal/executor/`, `internal/enrollscript/`, `cmd/nebula/` (`nebula netbird token set`) | yes | EN-08, EN-11 | Token via non-echoing input, vault-stored; per-offer key: usage 1, expiry ≤ 1 h, auto-group exactly the managed group, ephemeral off by default; revoked on expiry/revoke/fail when unused; peer cross-check (exactly one peer, only the managed group) before a NetBird endpoint is offered; rogue-peer report and audited delete on confirmation; script: repository key fingerprint pinned, setup key in a `0600` temp file removed by `trap`, self-delete; documented per client version whether the key avoids argv; policy read-only warning (Q3) |
| EN-13: CLI offers view | `cmd/nebula/` (`nebula host offers`, `nebula host offer-revoke`) | yes | EN-08 | Admin UID only; lists state, host, expiry, script hash, download address; revoke works in every non-final state |
| EN-14: security acceptance | `test/security/` | yes | EN-08 – EN-12 | Machine in the path with a different key → no pin, offer failed, notification; precomputed key for the unsalted fingerprint does not match; leaked offer ID after download → `404`; tampered script fails the hash check; compromised-server simulation cannot pin without a matching code; rogue NetBird peer detected; no secret in logs |
| EN-15: operator documentation | `docs/admin/guide.md` §7 and a NetBird section, `docs/implementation/one-step-enrollment.md` status | no | EN-10, EN-12 | One-step walkthrough, TOFU caveat and console recommendation, `--cacert` instead of `-k`, proxy log exclusion for `/enroll/`, NetBird service user and one-way policy (`nos` → `nos-managed` TCP 22), browser-download fallback for hosts without access to NOS |

## Protected paths touched by the plan

`docs/adr/` (EN-01), `docs/spec/` (EN-02), `.github/protected-paths.txt`
(EN-03, EN-11, one line each), `cmd/nebula/` (EN-04, EN-12, EN-13),
`internal/executordb/` (EN-05), `cmd/nebula-executor/` (EN-06),
`internal/permit/` and `internal/canonical/` (EN-07), `proto/` and
`internal/executor/` (EN-08, EN-12), `test/security/` (EN-14).

## Dependencies

No new Go modules. NetBird is called with `net/http` and `encoding/json`;
SHA-256 and randomness come from `crypto/sha256` and `crypto/rand`. On hosts
the script needs coreutils (`sha256sum`, `base64`, `basenc`), `curl` or
`wget`, and for the NetBird option the official NetBird package repository.

## Order

EN-01 → EN-02 → (EN-03, EN-04, EN-05, EN-06, EN-11 in parallel) → EN-07 →
EN-08 → (EN-09, EN-13) → EN-10 → EN-12 → EN-14 → EN-15. Without NetBird
(Q3 "manual step"), EN-11 and EN-12 are dropped and the rest stays valid.
