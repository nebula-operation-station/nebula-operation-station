# Network security advisor plan (ADR 0012)

Status: **plan, not started, 2026-11-11; ADR 0012 Proposed** with Q1 to Q11
open (previously Q1 to Q10). Only NS-01 (this plan and the ADR) and the
lab verification NS-03 may run before acceptance. Pure libraries without tables or migrations
(NS-04, NS-05, NS-09) may start once the ADR is accepted, before the spec
revision NS-02 is merged, as in ADR 0009 and ADR 0010; every ticket that
adds a table, migration, API scope or device method waits for NS-02.

It turns [ADR 0012](../adr/0012-network-security-advisor.md) into PR-sized
steps, in the style of [network-devices.md](network-devices.md).

## What the ADR asks for

| # | Rule | ADR section |
| --- | --- | --- |
| S1 | Advisory only: no device change, no auto-block, no proposal, permit or approval from any result; never lowers an ADR 0010 D5 risk class | D1, Non-goals |
| S2 | Reachability `nr-v1`: placement, same-L2 crossing test → `not_filtered`, NAT first (pre-NAT address, post-NAT zone) with reverse-NAT lookup of the pre-NAT destinations that forward to the host, `netbird` placed on the firewall only when proven (overlay bypass → `not_filtered`, unproven → `unknown`), rules in order with disabled skipped and listed, conditional matches for allow and deny rules (a conditional deny before an allow → `conditional`), private ranges outside IPAM → `unknown`, default rules; verdicts `allowed`/`conditional`/`denied`/`not_filtered`/`unknown`; explanation chain; snapshot hash; determinism | D2 |
| S3 | Inputs only from server stores (ND-16, IPAM, ADR 0009); ADR 0010 D3 limits reused; work limits named; limit hit → `unknown` | D2 |
| S4 | `vu-prio-v2`: exposure from reachability; KEV floor unchanged; mitigation never closes, not a state; ADR 0011 D5/D6/D9 unchanged | D3 |
| S5 | Fail closed: stale/incomplete input, policy or object change, `unknown` verdict, or contradiction by observed traffic → v1 exposure, "mitigation unknown" | D3 |
| S6 | Attack-path network edges from the model; `not_filtered` and `unknown` edges "assumed"; a `denied` without the Q11 elements keeps the edge "assumed" | D3 |
| S7 | Advisor checks `na-v1` (shadowed, any-any, allow without profile, zero hits ≥ 30 days with reset time, DNS bypass, management from untrusted, model contradiction); separate store; NOS resolves only on a snapshot complete for the check (incl. Q11 elements), never from "cannot decide" or "data not collected"; admin acknowledge with expiry | D4 |
| S8 | Segmentation proposals `sp-v1` (rule-based) and what-if (findings mitigated, paths cut, flows broken, ADR 0010 CRITICAL flag); no apply | D4 |
| S9 | Logs via executor typed methods `panos.log.traffic_hourly`/`threat_hourly` (recommended, Q1); minimisation in the executor; hourly aggregates with caps and `incomplete` | D5 |
| S10 | Retention: aggregates 30 days, external non-hit addresses full 7 days then /24 and /48, hits 90 days, admin-only, no export (advisor finding exports carry counts only for log- or flow-derived evidence, which follows its source's retention), excluded from backup; earlier minimisation of internal addresses open (all Q2) | D5, D8 |
| S11 | Feeds fetched only by the agent host; no per-address lookups; upload via `netsec.reputation.write`; NOS-side validation (special/internal ranges dropped, prefix minimum, caps, content dates, plausibility hold) | D6 |
| S12 | Matching in NOS; hits with first/last seen, allowed vs denied, direction, internal endpoints; `netsec.reputation_allowed` with dedupe and the ADR 0011 D9 rate limit | D6 |
| S13 | EDL (only if Q4 explicitly allows a firewall-enforced effect outside the ADR 0010 permit path and phase-2a write gate): HTTPS, required source allowlist, basic credential or mTLS, no token in URL, manual entries with assertion only (no feed-driven rule sets, Q4b), refusals, size cap, audit, last-pulled view | D7 |
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
| NS-01 | This plan, `docs/adr/0012-network-security-advisor.md` | yes (ADR) | — | Maintainer answers Q1–Q11 and accepts or changes the ADR; answers recorded in the ADR ("Decisions <date>") and here |
| NS-02 | Spec revision: `docs/spec/{01,03,04,07,09,12,13,16}*.md`, `docs/threat-model.md` | yes | NS-01, NS-03 | Every new table, retention, scope, event, read method and limit mapped; ADR 0012 threat items in the threat model; links resolve |
| NS-03 | Lab verification note `docs/implementation/network-security-lab.md`; sanitized fixtures under `testdata/` of the parser packages (no secrets, public names, real subnets, addresses, serials or exact releases) | no | — (may run before acceptance) | Each *verify* in ADR 0012 answered with device family, release train and document version: NAT/security evaluation order and pre-/post-NAT matching; default security rule element path and overrides; `profile-setting`, `negate-*`, `schedule`, `log-setting` paths; XML API log query (async job, `nlogs` cap, field names, read-only role permission); custom report aggregation option; log volume per lab hour against the cap; EDL authentication options (basic, client certificate), EDL capacity of the model, behaviour when a pull fails; feed formats, update intervals, terms and shortest prefix per feed (Feodo, SSLBL, Spamhaus DROP/EDROP, FireHOL level1) |

### Phase 1: model, priority and advisor (server only, no new device reads)

| Ticket | Scope / paths | P | After | Acceptance |
| --- | --- | --- | --- | --- |
| NS-04 | PAN-OS allowlist additions and parsers: `internal/netdevredact/` (allowlist), `internal/panapi/{rules,config}.go` (fields), fixtures | yes (`internal/netdevredact/`) | NS-01, NS-03, Q11 = yes | Only if Q11 allows the change to the accepted ADR 0010 allowlist; only the ADR 0012 D2 element paths added; fail-closed keyword rule unchanged and tested on the new elements; profile and group **names** only; unknown elements still dropped with marker; fixtures from NS-03 parse; fuzz |
| NS-05 | Reachability library `nr-v1`: new `internal/netreach/{snapshot,place,nat,eval,explain,limits}.go`, tests, fuzz | no | NS-01 (accepted) | Table tests per verdict; same-L2 → `not_filtered` in a flat-network fixture; NAT pre-NAT address/post-NAT zone; reverse-NAT lookup: a query from `internet` (or another zone) to a host's internal address also evaluates, on its pre-NAT packet, every destination NAT rule that translates to that address and port, so a port-forwarded service with an allow rule → `allowed`, never `denied` via the default interzone rule (test with a WAN-address port forward; without a matching NAT rule the same query stays `denied`; a NAT rule with an unevaluable object → `unknown`; the chain lists every pre-NAT destination tried); `netbird` source: a destination that is a NetBird peer (NetBird interface in `net.facts`) or is reached through a routing peer off the firewall path → `not_filtered` "overlay path bypasses the firewall", missing host data or unknown routing peers → `unknown`, never a firewall `denied` even with a deny rule for the NetBird zone (test per case; a proven firewall-crossing NetBird path still gets the rule verdict); first match wins; disabled skipped and listed; negation; conditional (App-ID, user, URL category, schedule, service `application-default`) continues to the next unconditional match, for allow and deny rules alike; a conditional deny followed by a later allow (conditional or not) or the default intrazone allow → `conditional`, never `denied`, and never counted as mitigating (test per condition kind); a conditional deny whose fall-through is an unconditional or default deny → `denied`; a conditional deny followed by an unevaluable rule → `unknown`; a private or special-range address (RFC 1918, CGNAT, ULA, link-local, and the other D2 ranges) outside every IPAM subnet → `unknown` "private address outside known subnets", never placed in the WAN zone via the default route and never `denied` (test with source and destination side; a public address outside known subnets still follows its route; a proven specific route for the range still places it); FQDN/EDL/dynamic/region objects → `unknown`; a known IPAM subnet owned by no firewall interface → `unknown` "subnet not on a firewall interface", never `denied` by the default interzone rule (test with source, destination and both sides unowned; same-subnet pair stays `not_filtered`); multi-vsys → `unknown`; stale or `incomplete` input → `unknown`; every limit is a named constant tested at limit and limit+1 with `unknown` "limit reached"; snapshot hash ignores `raw_digest`; determinism (same hash + version → identical output) |
| NS-06 | Reachability job and store: server migration, new `internal/netreachstore/` | no | NS-02, NS-05, ND-16 | Recompute on new dataset version and at most hourly; wall-clock budget; verdicts keyed by snapshot hash and model version; old snapshots pruned with their consumers; a policy or object change marks dependent results void before recomputation |
| NS-07 | `vu-prio-v2` and mitigation records: `internal/vulnprio/`, `internal/vulnstore/` (mitigation table), server migration | no | NS-02, NS-06, VU-10 | Every exposure level and the KEV floor tested; a listening service never below 0.4; `not_filtered` from the own segment or any zone never counts as mitigated (test: all zones `denied` except own segment `not_filtered` → 0.4, summary "not filtered"); v1 kept beside v2; fail-closed cases each a test (stale input, policy change, object change, `unknown`, contradiction by flow or allowed log aggregate in 24 h, port unknown, snapshot without the Q11 elements, conditional deny followed by an allow) → v1 exposure and "mitigation unknown: <reason>"; a port forward from `internet` to the finding's port (internal address otherwise denied by the default interzone rule) keeps expo 1.0 and is never listed as mitigated (test); a `netbird` overlay path that bypasses the firewall or is not proven keeps expo 0.7, never 0.4 (test); no state, closure or D5 path touched (test: mitigated finding stays `open`, closure preconditions unchanged); tier rise after void raises `vuln.critical_new` under D9 dedupe |
| NS-08 | Attack-path edges from the model: `internal/attackpath/sources/` | no | NS-06, VU-22 | `allowed`/`conditional` → policy edge, `not_filtered` → L2 edge "assumed", `denied` → no edge only from a snapshot with the Q11 elements and fresh inputs; a `denied` from a snapshot without the Q11 elements (negation flags not collected or default rules "assumed") keeps the edge flagged "assumed" (test); `unknown` → "assumed"; graph snapshot hash includes the reachability snapshot hash; `ap-v1` numbers unchanged for golden graphs without firewall data |
| NS-09 | Advisor checks `na-v1`: new `internal/netadvisor/{shadow,anyany,profile,hits,dns,mgmt,contradiction}.go`, tests | no | NS-05 | Shadowed vs partial overlap vs "cannot decide" (also when negation flags are not collected); a check that cannot be evaluated reports "cannot decide" or "data not collected", never "no longer fires" (test per check: `shadowed-rule` with an unevaluable object or without negation flags, `mgmt-from-untrusted` with a `denied` from a snapshot without the Q11 elements, `allow-without-profile` without NS-04 data); any-any variants; profile check only with NS-04 data, else "data not collected"; zero hits only with ≥ 30 days observed since the later of creation and reset, reset time in evidence, never a delete proposal; DNS bypass (53/udp, 53/tcp, 853/tcp) against designated resolvers and against permissive DNS rules; management targets × untrusted classes incl. `not_filtered` and `unknown`; unknown zone class counts as untrusted |
| NS-10 | Advisor store and pages: server migration, new `internal/netadvisorstore/`, `internal/web/ui/` (placement per Q6), templates | no | NS-02, NS-09, NS-06 | NOS resolves only on a fresh snapshot complete for the check (every input fresh and not `incomplete`, Q11 elements collected, every element the check needs present); an existing finding is never resolved by "cannot decide", "data not collected", an `unknown` verdict or a snapshot without the Q11 elements, it stays and shows "not evaluated since" (test per case: `shadowed-rule` and `mgmt-from-untrusted` findings stay open on such a snapshot and resolve on a complete one); acknowledge with reason and expiry (default and maximum per Q9, proposed 90 and 365 days, named constants tested at maximum and maximum+1) bound to check ID/version, rule UUID and the rule-scoped digest (tests: change to the rule, a referenced object or group member, a covering rule, or the rule's relative position re-opens; an unrelated rule change does not; new check version re-opens); log- and flow-derived evidence stored as references and pruned/reduced with its source (injected time); export carries counts only, no endpoint, destination or flow from logs or the traffic map (test per check); zone trust classes and management targets as audited admin settings; admin-only; device text escaped; strict CSP asserted; explanation chain rendered as text |
| NS-11 | Segmentation proposals `sp-v1` and what-if: `internal/netadvisor/{segment,whatif}.go`, UI | no | NS-07, NS-08, NS-10 | Deterministic grouping by role, tag, kind, then communication; operator overrides; crossing flows aggregated; minimal allow list as text; coverage window stated; what-if on a copied snapshot lists findings mitigated (tier before/after), paths cut, flows broken (traffic map 21 days, log aggregates per Q2) and the ADR 0010 D5 CRITICAL flag (flat network: any deny overlapping `<lab-net>` or `any`); nothing stored as a proposal; no submit to any change path (test) |

### Phase 2: firewall logs

| Ticket | Scope / paths | P | After | Acceptance |
| --- | --- | --- | --- | --- |
| NS-12 | Typed log reads: `internal/panapi/logs.go` (query, job poll, parse), `internal/executor/` dispatch and minimisation, `internal/netdevcontract/` log aggregate contract, device read-lease methods in `internal/schedgrant/` and `internal/permit/` | yes (`internal/executor/`, `internal/permit/`) | NS-01 (Q1 = API), NS-02, NS-03, ND-13 | Parameters only `(device_id, hour)`; fixed query, no caller filter/xpath; every ADR 0012 D5 "dropped always" field absent from every output, one test per field: source-user and every User-ID field, URLs, URL categories, file names, file hashes, packet captures, X-Forwarded-For, host names, device serials of endpoints, session IDs, NAT-translated source ports; hour truncation; per-hour key cap with top-by-sessions and `incomplete` plus dropped count; `nlogs` cap → `incomplete`; XML limits; loopback TLS fixtures; fuzz; lease binds the new methods and budgets; no change dispatch |
| NS-13 | Collector and log store: `internal/netdevcollect/` (schedule the two methods), server migration, new `internal/fwlogstore/` | no | NS-02, NS-12, ND-14, ND-16 | Hourly aggregates; retention and prefix reduction per Q2 (7-day full external addresses then /24 and /48, 30-day aggregates; hit addresses exempt) with injected time; pruning hourly; excluded from the instance backup unless Q2 says otherwise; admin-only access; no export path |
| NS-13b | Syslog receiver (**only if Q1 chooses syslog**): separate ADR amendment first | yes (`deploy/systemd/`) | NS-01 | Not planned unless Q1 changes the recommendation |

### Phase 3: reputation

| Ticket | Scope / paths | P | After | Acceptance |
| --- | --- | --- | --- | --- |
| NS-14 | Agent reputation feeds: new `internal/vulnfeed/reputation/` (inside the ADR 0011 A1.2 import allowlist), agent config for origins and optional keys | no | NS-01, ADR 0011 amendment 1 merged, va-tickets for feed sync | Origin allowlist and A1.5 egress; verified TLS, no cross-origin redirects; size and decompression limits; content dates; normalisation to `(CIDR, category)`; keys only in agent files, never logged; no per-address lookup code path exists (test); `TestVulnAgentImportsOnlyAllowlist` still passes |
| NS-15 | Reputation API and store: `internal/web/api/` (upload endpoint), `internal/serverconfig/` (scope `netsec.reputation.write`), server migration, new `internal/reputation/{validate,store}.go` | no; yes if token handling in `internal/web/auth/` changes | NS-14 (contract), NS-02 | Fixed feed ID list; special, private, CGNAT, documentation, reserved ranges and IPAM/NOS-path overlaps dropped and counted; prefix minimum /16 IPv4 and /32 IPv6 as named constants (tested at /16 and /15, /32 and /31; per-feed override only from server config per Q3, never from the snapshot); per-feed and total caps (refuse, previous stays, "feed stale"); content date high-water mark and future-date refusal; plausibility hold for an admin; scope grants no read; token source-bound and rotatable |
| NS-16 | Matcher, hits and notifications: `internal/reputation/{match,hits}.go`, `internal/notify/`, UI per Q6 | no | NS-13, NS-15 | Prefix trie matcher over log aggregates, flows and endpoints; hits with allowed vs denied, direction, internal endpoints linked to traffic map and assets, first/last seen, snapshot; delisting ends the episode; hit retention per Q2: external address and totals 90 days, internal endpoints and per-endpoint sessions and bytes only as references that follow the source retention (test with injected time: at day 31 the hit shows no internal address, endpoint ID or label, only the endpoint count and totals; at day 91 the hit is pruned); `netsec.reputation_allowed` dedupe per (address, endpoint, feed) episode, 10 per hour plus digest, external address omitted unless enabled (Q8); third-party messages carry only managed-host or IPAM asset labels, otherwise "internal endpoint in zone X", never an observed device name (test); denied-only hits counted daily, no message; `netsec.feed_stale` per feed and episode |

### Phase 4: EDL (only if Q4 explicitly says yes)

| Ticket | Scope / paths | P | After | Acceptance |
| --- | --- | --- | --- | --- |
| NS-17 | EDL lists and entries: server migration, new `internal/edl/` | no | NS-02, NS-15, Q4 | Add with fresh WebAuthn assertion (ADR 0011 Q4 rule), reason, expiry; removal audited; no code path adds an entry from feed data, reputation hits or the agent token (test; a hit only prefills the form); refusals (special ranges, IPAM, NOS path, firewall addresses, protected destinations) on add and publish; size cap → not published, previous stays; deterministic output, ASCII, one entry per line |
| NS-18 | EDL endpoint: `internal/web/` route `/edl/`, credential handling | yes if `internal/web/auth/` changes | NS-17, NS-03 | HTTPS only; basic credential (≥ 32 random bytes, shown once, stored hashed, rotatable) or mTLS per NS-03; no token in URL accepted; no cookies or session; source-address allowlist required (ADR 0012 D7), a pull from any other address refused before the credential check and audited (test); `Content-Type: text/plain; charset=us-ascii`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` (each asserted); every pull audited; "last pulled" shown |

### Phase 5: hardening and documentation

| Ticket | Scope / paths | P | After | Acceptance |
| --- | --- | --- | --- | --- |
| NS-19 | Security and browser tests: `test/security/netsec_test.go`, `test/browser/` | yes | NS-11, NS-16, NS-18 (if built) | No path from any advisor result, what-if, hit or EDL to a proposal, permit or device method; agent token cannot read flows, logs, endpoints or findings; hostile rule names, threat names and feed categories rendered as text; dropped log fields never stored; EDL refusals hold against a crafted feed; pages admin-only, not in the read-only API |
| NS-20 | Operator guide: `docs/operator/network-security.md` | no | NS-19 | Zone trust classes, management targets, how to read verdicts and "not filtered", log permission on the PAN-OS role, retention and personal data (informing household members and guests), feeds and keys, EDL setup only in deny rules on untrusted/WAN zones, what NOS never does |

## Order and release

NS-01 (decision) and NS-03 (lab) first. After acceptance: NS-02 (spec
revision) and the pure libraries NS-04, NS-05 and NS-09 in parallel; NS-02
must be merged before the first ticket that adds a table, migration,
API scope or device method, that is before NS-06, NS-07, NS-10, NS-12,
NS-13, NS-15 and NS-17 (previously: before the first phase-2 ticket,
which let phase-1 migrations land unspecified). Then NS-06 → NS-07,
NS-08, NS-09 → NS-10 → NS-11 (phase 1 needs only ADR 0010 phase-1 data and
ADR 0011 VU-10/VU-22). Phase 2 needs Q1 and ND-13/ND-14. Phase 3 needs
ADR 0011 amendment 1 and its agent tickets. Phase 4 only if Q4 explicitly says yes. NS-04 only if Q11 says yes.
Release placement per Q10.

## Non-goals

As ADR 0012: no device change, no auto-block, no automatic EDL entries
(no feed-driven rule sets; Q4b would need an ADR amendment), no change to ADR 0011 closure rules, no
per-address reputation lookups, no feed egress from the server, no
payload, URL or user identity storage, no host-firewall modelling in
`nr-v1`.
