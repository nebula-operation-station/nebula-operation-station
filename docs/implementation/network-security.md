# Network security advisor plan (ADR 0012)

Status: **plan, not started, 2026-11-11; ADR 0012 Proposed** with Q1 to Q10
open. Only NS-01 (this plan and the ADR) and the lab verification NS-03 may
run before acceptance. Phase-1 libraries (NS-05, NS-09) may start once the
ADR is accepted, before the spec revision NS-02 is merged, as in ADR 0009
and ADR 0010.

It turns [ADR 0012](../adr/0012-network-security-advisor.md) into PR-sized
steps, in the style of [network-devices.md](network-devices.md).

## What the ADR asks for

| # | Rule | ADR section |
| --- | --- | --- |
| S1 | Advisory only: no device change, no auto-block, no proposal, permit or approval from any result; never lowers an ADR 0010 D5 risk class | D1, Non-goals |
| S2 | Reachability `nr-v1`: placement, same-L2 crossing test → `not_filtered`, NAT first (pre-NAT address, post-NAT zone), rules in order with disabled skipped and listed, conditional matches, default rules; verdicts `allowed`/`conditional`/`denied`/`not_filtered`/`unknown`; explanation chain; snapshot hash; determinism | D2 |
| S3 | Inputs only from server stores (ND-16, IPAM, ADR 0009); ADR 0010 D3 limits reused; work limits named; limit hit → `unknown` | D2 |
| S4 | `vu-prio-v2`: exposure from reachability; KEV floor unchanged; mitigation never closes, not a state; ADR 0011 D5/D6/D9 unchanged | D3 |
| S5 | Fail closed: stale/incomplete input, policy or object change, `unknown` verdict, or contradiction by observed traffic → v1 exposure, "mitigation unknown" | D3 |
| S6 | Attack-path network edges from the model; `not_filtered` and `unknown` edges "assumed" | D3 |
| S7 | Advisor checks `na-v1` (shadowed, any-any, allow without profile, zero hits ≥ 30 days with reset time, DNS bypass, management from untrusted, model contradiction); separate store; NOS resolves; admin acknowledge with expiry | D4 |
| S8 | Segmentation proposals `sp-v1` (rule-based) and what-if (findings mitigated, paths cut, flows broken, ADR 0010 CRITICAL flag); no apply | D4 |
| S9 | Logs via executor typed methods `panos.log.traffic_hourly`/`threat_hourly` (recommended, Q1); minimisation in the executor; hourly aggregates with caps and `incomplete` | D5 |
| S10 | Retention: aggregates 30 days, external non-hit addresses full 7 days then /24 and /48, hits 90 days, admin-only, no export, excluded from backup (all Q2) | D5 |
| S11 | Feeds fetched only by the agent host; no per-address lookups; upload via `netsec.reputation.write`; NOS-side validation (special/internal ranges dropped, prefix minimum, caps, content dates, plausibility hold) | D6 |
| S12 | Matching in NOS; hits with first/last seen, allowed vs denied, direction, internal endpoints; `netsec.reputation_allowed` with dedupe and the ADR 0011 D9 rate limit | D6 |
| S13 | EDL (only if Q4): HTTPS, basic credential or mTLS, no token in URL, manual entries with assertion only (no feed-driven rule sets, Q4b), refusals, size cap, audit, last-pulled view | D7 |
| S14 | Server runs everything (Q5); admin-only pages; not in the read-only API; strict CSP; device, log and feed text escaped | D8 |

## Current state and reuse

| What | Where | Use |
| --- | --- | --- |
| Firewall policy, NAT, objects, zones, hit counts (parsers) | `internal/panapi/{rules,nat,objects,zones,hitcount,jobs}.go` | Model inputs; async job polling pattern for log queries (NS-12) |
| Device inventory store | `internal/netdevinventory/` | Snapshot inputs, dataset versions, staleness |
| Device contracts and parse limits | `internal/netdevcontract/` | Reused limits (S3), log record contract (NS-12) |
| PAN-OS redaction allowlist | `internal/netdevredact/` **P** | Allowlist additions (NS-04) |
| Flows, endpoints, guest NICs | `internal/trafficstore/`, `internal/trafficingest/` | Crossing test, contradiction check, segmentation, matching |
| IPAM networks and VLANs | `internal/ipam/` | Placement |
| Priority `vu-prio-v1` | `internal/vulnprio/` | `vu-prio-v2` beside v1 (NS-07) |
| Attack paths | `internal/attackpath/`, `internal/attackpath/sources/` | Edge source from the model (NS-08) |
| Notifications | `internal/notify/`, `internal/vulnnotify/` | Rate limit and digest pattern (NS-16) |
| Agent feed sync | `internal/vulnfeed/` (ADR 0011 amendment 1, va-tickets) | Reputation feeds as a subpackage, inside the A1.2 import allowlist (NS-14) |
| API scopes and tokens | `internal/web/api/`, `internal/serverconfig/` | `netsec.reputation.write` (NS-15) |

Gaps: no reachability model, no advisor store, no log read methods, no
log store, no reputation store or matcher, no EDL endpoint, no zone trust
classes.

## Tickets

Each row is one agent job: tests first, `make check`, no new dependencies,
no network access in tests (loopback TLS servers and Unix sockets in
temporary directories only, recorded fixtures from NS-03). **P** = touches
a protected path and needs explicit maintainer authorization in that
ticket. Order is the column "After".

### Phase 0: decision and lab facts

| Ticket | Scope / paths | P | After | Acceptance |
| --- | --- | --- | --- | --- |
| NS-01 | This plan, `docs/adr/0012-network-security-advisor.md` | yes (ADR) | — | Maintainer answers Q1–Q10 and accepts or changes the ADR; answers recorded in the ADR ("Decisions <date>") and here |
| NS-02 | Spec revision: `docs/spec/{01,03,04,07,09,12,13,16}*.md`, `docs/threat-model.md` | yes | NS-01, NS-03 | Every new table, retention, scope, event, read method and limit mapped; ADR 0012 threat items in the threat model; links resolve |
| NS-03 | Lab verification note `docs/implementation/network-security-lab.md`; sanitized fixtures under `testdata/` of the parser packages (no secrets, public names, real subnets, addresses, serials or exact releases) | no | — (may run before acceptance) | Each *verify* in ADR 0012 answered with device family, release train and document version: NAT/security evaluation order and pre-/post-NAT matching; default security rule element path and overrides; `profile-setting`, `negate-*`, `schedule`, `log-setting` paths; XML API log query (async job, `nlogs` cap, field names, read-only role permission); custom report aggregation option; log volume per lab hour against the cap; EDL authentication options (basic, client certificate), EDL capacity of the model, behaviour when a pull fails; feed formats, update intervals and terms (Feodo, SSLBL, Spamhaus DROP/EDROP, FireHOL level1) |

### Phase 1: model, priority and advisor (server only, no new device reads)

| Ticket | Scope / paths | P | After | Acceptance |
| --- | --- | --- | --- | --- |
| NS-04 | PAN-OS allowlist additions and parsers: `internal/netdevredact/` (allowlist), `internal/panapi/{rules,config}.go` (fields), fixtures | yes (`internal/netdevredact/`) | NS-01, NS-03 | Only the ADR 0012 D2 element paths added; fail-closed keyword rule unchanged and tested on the new elements; profile and group **names** only; unknown elements still dropped with marker; fixtures from NS-03 parse; fuzz |
| NS-05 | Reachability library `nr-v1`: new `internal/netreach/{snapshot,place,nat,eval,explain,limits}.go`, tests, fuzz | no | NS-01 (accepted) | Table tests per verdict; same-L2 → `not_filtered` in a flat-network fixture; NAT pre-NAT address/post-NAT zone; first match wins; disabled skipped and listed; negation; conditional (App-ID, user, URL category, schedule) continues to the next unconditional match; FQDN/EDL/dynamic/region objects → `unknown`; a known IPAM subnet owned by no firewall interface → `unknown` "subnet not on a firewall interface", never `denied` by the default interzone rule (test with source, destination and both sides unowned; same-subnet pair stays `not_filtered`); multi-vsys → `unknown`; stale or `incomplete` input → `unknown`; every limit is a named constant tested at limit and limit+1 with `unknown` "limit reached"; snapshot hash ignores `raw_digest`; determinism (same hash + version → identical output) |
| NS-06 | Reachability job and store: server migration, new `internal/netreachstore/` | no | NS-05, ND-16 | Recompute on new dataset version and at most hourly; wall-clock budget; verdicts keyed by snapshot hash and model version; old snapshots pruned with their consumers; a policy or object change marks dependent results void before recomputation |
| NS-07 | `vu-prio-v2` and mitigation records: `internal/vulnprio/`, `internal/vulnstore/` (mitigation table), server migration | no | NS-02, NS-06, VU-10 | Every exposure level and the KEV floor tested; a listening service never below 0.4; `not_filtered` from the own segment or any zone never counts as mitigated (test: all zones `denied` except own segment `not_filtered` → 0.4, summary "not filtered"); v1 kept beside v2; fail-closed cases each a test (stale input, policy change, object change, `unknown`, contradiction by flow or allowed log aggregate in 24 h, port unknown) → v1 exposure and "mitigation unknown: <reason>"; no state, closure or D5 path touched (test: mitigated finding stays `open`, closure preconditions unchanged); tier rise after void raises `vuln.critical_new` under D9 dedupe |
| NS-08 | Attack-path edges from the model: `internal/attackpath/sources/` | no | NS-06, VU-22 | `allowed`/`conditional` → policy edge, `not_filtered` → L2 edge "assumed", `denied` → no edge, `unknown` → "assumed"; graph snapshot hash includes the reachability snapshot hash; `ap-v1` numbers unchanged for golden graphs without firewall data |
| NS-09 | Advisor checks `na-v1`: new `internal/netadvisor/{shadow,anyany,profile,hits,dns,mgmt,contradiction}.go`, tests | no | NS-05 | Shadowed vs partial overlap vs "cannot decide"; any-any variants; profile check only with NS-04 data, else "data not collected"; zero hits only with ≥ 30 days observed since the later of creation and reset, reset time in evidence, never a delete proposal; DNS bypass (53/udp, 53/tcp, 853/tcp) against designated resolvers and against permissive DNS rules; management targets × untrusted classes incl. `not_filtered` and `unknown`; unknown zone class counts as untrusted |
| NS-10 | Advisor store and pages: server migration, new `internal/netadvisorstore/`, `internal/web/ui/` (placement per Q6), templates | no | NS-09, NS-06 | NOS resolves on fresh complete snapshot; "not evaluated since"; acknowledge with reason and expiry ≤ 365 days bound to rule UUID and `redacted_digest`, re-opens on change; zone trust classes and management targets as audited admin settings; admin-only; device text escaped; strict CSP asserted; explanation chain rendered as text |
| NS-11 | Segmentation proposals `sp-v1` and what-if: `internal/netadvisor/{segment,whatif}.go`, UI | no | NS-07, NS-08, NS-10 | Deterministic grouping by role, tag, kind, then communication; operator overrides; crossing flows aggregated; minimal allow list as text; coverage window stated; what-if on a copied snapshot lists findings mitigated (tier before/after), paths cut, flows broken (traffic map 21 days, log aggregates per Q2) and the ADR 0010 D5 CRITICAL flag (flat network: any deny overlapping `<lab-net>` or `any`); nothing stored as a proposal; no submit to any change path (test) |

### Phase 2: firewall logs

| Ticket | Scope / paths | P | After | Acceptance |
| --- | --- | --- | --- | --- |
| NS-12 | Typed log reads: `internal/panapi/logs.go` (query, job poll, parse), `internal/executor/` dispatch and minimisation, `internal/netdevcontract/` log aggregate contract, device read-lease methods in `internal/schedgrant/` and `internal/permit/` | yes (`internal/executor/`, `internal/permit/`) | NS-01 (Q1 = API), NS-03, ND-13 | Parameters only `(device_id, hour)`; fixed query, no caller filter/xpath; dropped fields (user, URL, file, pcap, XFF, host names, session IDs, NAT source port) absent from every output (test per field); hour truncation; per-hour key cap with top-by-sessions and `incomplete` plus dropped count; `nlogs` cap → `incomplete`; XML limits; loopback TLS fixtures; fuzz; lease binds the new methods and budgets; no change dispatch |
| NS-13 | Collector and log store: `internal/netdevcollect/` (schedule the two methods), server migration, new `internal/fwlogstore/` | no | NS-12, ND-14, ND-16 | Hourly aggregates; retention and prefix reduction per Q2 (7-day full external addresses then /24 and /48, 30-day aggregates; hit addresses exempt) with injected time; pruning hourly; excluded from the instance backup unless Q2 says otherwise; admin-only access; no export path |
| NS-13b | Syslog receiver (**only if Q1 chooses syslog**): separate ADR amendment first | yes (`deploy/systemd/`) | NS-01 | Not planned unless Q1 changes the recommendation |

### Phase 3: reputation

| Ticket | Scope / paths | P | After | Acceptance |
| --- | --- | --- | --- | --- |
| NS-14 | Agent reputation feeds: new `internal/vulnfeed/reputation/` (inside the ADR 0011 A1.2 import allowlist), agent config for origins and optional keys | no | NS-01, ADR 0011 amendment 1 merged, va-tickets for feed sync | Origin allowlist and A1.5 egress; verified TLS, no cross-origin redirects; size and decompression limits; content dates; normalisation to `(CIDR, category)`; keys only in agent files, never logged; no per-address lookup code path exists (test); `TestVulnAgentImportsOnlyAllowlist` still passes |
| NS-15 | Reputation API and store: `internal/web/api/` (upload endpoint), `internal/serverconfig/` (scope `netsec.reputation.write`), server migration, new `internal/reputation/{validate,store}.go` | no; yes if token handling in `internal/web/auth/` changes | NS-14 (contract), NS-02 | Fixed feed ID list; special, private, CGNAT, documentation, reserved ranges and IPAM/NOS-path overlaps dropped and counted; prefix minimum; per-feed and total caps (refuse, previous stays, "feed stale"); content date high-water mark and future-date refusal; plausibility hold for an admin; scope grants no read; token source-bound and rotatable |
| NS-16 | Matcher, hits and notifications: `internal/reputation/{match,hits}.go`, `internal/notify/`, UI per Q6 | no | NS-13, NS-15 | Prefix trie matcher over log aggregates, flows and endpoints; hits with allowed vs denied, direction, internal endpoints linked to traffic map and assets, first/last seen, snapshot; delisting ends the episode; hit retention per Q2; `netsec.reputation_allowed` dedupe per (address, endpoint, feed) episode, 10 per hour plus digest, external address omitted unless enabled (Q8); denied-only hits counted daily, no message; `netsec.feed_stale` per feed and episode |

### Phase 4: EDL (only if Q4 = yes)

| Ticket | Scope / paths | P | After | Acceptance |
| --- | --- | --- | --- | --- |
| NS-17 | EDL lists and entries: server migration, new `internal/edl/` | no | NS-02, NS-15, Q4 | Add with fresh WebAuthn assertion (ADR 0011 Q4 rule), reason, expiry; removal audited; no code path adds an entry from feed data, reputation hits or the agent token (test; a hit only prefills the form); refusals (special ranges, IPAM, NOS path, firewall addresses, protected destinations) on add and publish; size cap → not published, previous stays; deterministic output, ASCII, one entry per line |
| NS-18 | EDL endpoint: `internal/web/` route `/edl/`, credential handling | yes if `internal/web/auth/` changes | NS-17, NS-03 | HTTPS only; basic credential (≥ 32 random bytes, shown once, stored hashed, rotatable) or mTLS per NS-03; no token in URL accepted; no cookies or session; source allowlist; `Content-Type: text/plain`, `Cache-Control: no-store`; every pull audited; "last pulled" shown |

### Phase 5: hardening and documentation

| Ticket | Scope / paths | P | After | Acceptance |
| --- | --- | --- | --- | --- |
| NS-19 | Security and browser tests: `test/security/netsec_test.go`, `test/browser/` | yes | NS-11, NS-16, NS-18 (if built) | No path from any advisor result, what-if, hit or EDL to a proposal, permit or device method; agent token cannot read flows, logs, endpoints or findings; hostile rule names, threat names and feed categories rendered as text; dropped log fields never stored; EDL refusals hold against a crafted feed; pages admin-only, not in the read-only API |
| NS-20 | Operator guide: `docs/operator/network-security.md` | no | NS-19 | Zone trust classes, management targets, how to read verdicts and "not filtered", log permission on the PAN-OS role, retention and personal data (informing household members and guests), feeds and keys, EDL setup only in deny rules on untrusted/WAN zones, what NOS never does |

## Order and release

NS-01 (decision) and NS-03 (lab) first. After acceptance: NS-04 and NS-05
in parallel, then NS-06 → NS-07, NS-08, NS-09 → NS-10 → NS-11 (phase 1
needs only ADR 0010 phase-1 data and ADR 0011 VU-10/VU-22). Phase 2 needs
Q1 and ND-13/ND-14. Phase 3 needs ADR 0011 amendment 1 and its agent
tickets. Phase 4 only if Q4 says yes. NS-02 lands before the first phase-2
ticket that adds a table or method to the spec. Release placement per Q10.

## Non-goals

As ADR 0012: no device change, no auto-block, no automatic EDL entries
(no feed-driven rule sets; Q4b would need an ADR amendment), no change to ADR 0011 closure rules, no
per-address reputation lookups, no feed egress from the server, no
payload, URL or user identity storage, no host-firewall modelling in
`nr-v1`.
