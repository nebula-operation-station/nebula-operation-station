# ADR 0012: Network security advisor: reachability, rules, segmentation, firewall logs and IP reputation

Status: **Proposed, 2026-11-11** (draft by Claude for the maintainer's
request of 2026-11-11). Not accepted; awaiting the maintainer's answers to
Q1–Q10 below. Do not start tickets after NS-03 before acceptance (see
`docs/implementation/network-security.md`).

History:

- 2026-11-11: first draft (ticket ns00).
- 2026-11-11: review fix round 1 (ticket ns00f): EDL manual entries only,
  feed-driven rule sets moved to Q4b (previously an opt-in rule set in D7);
  agent-token residual in the threat table; `vu-prio-v2` without the 0.3
  own-segment level (previously 1.0/0.7/0.4/0.3/0.2); unowned subnets →
  `unknown`; no export of log- or flow-derived evidence; rule-scoped
  acknowledgement digest (previously the policy `redacted_digest`); feed
  prefix minimum /16 and /32 (previously /8 and /24); Q2 and Q8 extended.

## Context

The maintainer requested a work package "network security advisor" on
2026-11-11. The pieces it builds on are decided:

- **Traffic map (ADR 0009).** Observed endpoints (facts, never inventory),
  hourly flow aggregates keyed by endpoint A, endpoint B, protocol, server
  port and source tier, 21-day retention, hop derivation via the default
  gateway, `bridge -j vlan` and guest NIC VLAN data. The map stores metadata
  only; a communication history is personal data (ADR 0009 D7).
- **Network devices (ADR 0010, accepted 2026-11-09).** Phase 1 reads CBS
  ports, VLANs, MAC and LLDP tables and the PAN-OS firewall policy (security
  rules in order including `disabled`, NAT rules, address/service objects and
  groups, zones, interfaces) and per-rule hit counts with the counter reset
  time (D4). Everything goes executor → collector spool → server
  (`internal/netdevinventory/`, ND-16); credentials and raw configs never
  leave the executor; PAN-OS output passes an element allowlist (D4
  redaction). The lab is **one flat network without a management VLAN**
  (Q4), with a single PA-400-series firewall, single vsys (Q2), management
  on an internal address only (Q5). Writes are phase 2a, only after a
  separate maintainer decision (Q3); CRITICAL changes are refused for good
  (Q6). ADR 0010 D4 names "shadowed-rule analysis" and "segmentation hints"
  as later, separate decisions, and its non-goals say "no shadowed-rule or
  policy-optimization engine; hints only". This ADR is that later decision
  for hints and analysis; it still adds no engine that changes policy.
- **Vulnerability management (ADR 0011, accepted 2026-11-09).** Findings
  are advisory only (D1); NOS computes priority `vu-prio-v1` (D7) with an
  exposure term `expo` that already names "firewall NAT/allow rules (ADR
  0010) when present" as an input; closure only through the D5 closure
  paths 1–6; attack paths (D10) with "assumed" L2 adjacency edges and choke
  points "one edge removed by a rule change". Amendment 1 (PR #444, accepted
  by the maintainer 2026-11-11, *verify* merged before NS-14) replaces
  Hermes with the in-repo `nebula-vuln-agent` on its own host; feed egress
  only from the agent host (A1.5), NOS server never fetches feeds (D1, Q2).

What is missing: NOS can show the rules, but cannot answer "can zone X
reach host Y on port Z, and why", cannot tell the operator which rules are
risky, cannot use the firewall as a compensating control in vulnerability
priority, does not see what the firewall logged, and does not know whether
any of that traffic touched known-bad addresses.

**In a flat network most internal traffic never crosses the firewall.**
Any model that only reads rules would report "denied by default
interzone rule" for traffic that in fact flows freely on one L2 segment.
Making that visible ("not filtered") is the first value of this work.

Constraints carried over unchanged:

- **Advisory only.** Nothing in this ADR changes a device, creates a
  proposal, permit or approval, or blocks traffic on its own. The one
  outbound effect, the optional EDL (D7), contains only entries an operator
  approved and is pulled by the firewall itself.
- Everything from devices, hosts, logs and feeds is untrusted input
  (spec 09): bounded, UTF-8-checked, printable text only, rendered as text.
- Credentials stay in the executor (ADR 0010 D2); the server and collectors
  hold none.
- No new dependencies; no network access in tests.
- Unknown is never rendered as safe, mitigated or green.

## Decisions

### D1: Components and trust boundary

| Component | Does | Never does |
| --- | --- | --- |
| `nebula-server` | Computes the reachability model, advisor findings, segmentation proposals, what-if results, mitigation signals for ADR 0011 and reputation matches in pure packages; stores log aggregates and reputation snapshots; serves the optional EDL | Fetch reputation feeds, contact feed providers or reputation APIs, send observed addresses anywhere, change a device, create proposals or permits from any result |
| `nebula-executor` | Reads PAN-OS logs under a device read lease (new typed methods, D5), minimises and aggregates before anything leaves it | Accept caller-supplied queries, filters or xpaths; return raw log records |
| `nebula-netdev-collector` | Schedules the typed log reads, spools the results (unchanged ADR 0010 role) | Hold credentials, listen on the network |
| `nebula-vuln-agent` (ADR 0011 amendment 1) | Fetches reputation feeds from allowlisted origins, verifies, normalises and uploads prefix lists to NOS (D6) | Receive observed addresses, flows, topology or findings; do per-address lookups at any provider |
| Firewall (PAN-OS) | Pulls the EDL if the operator configured it (D7) | Receive anything pushed by NOS |
| Operator (admin) | Assigns zone trust classes and management targets, adds EDL entries one by one, applies any suggested rule change outside NOS (later perhaps through ND-30+) | — |

**All results are advisory.** Reachability verdicts, advisor findings,
segmentation proposals, what-if results, reputation hits and mitigation
signals never authorize, propose, schedule or approve anything, never feed
the permit path, and never lower an ADR 0010 D5 risk class.

### D2: Reachability model (A)

**Question answered.** For a query `(source, destination, proto, port)`,
where source is a zone, an IPAM subnet, an observed endpoint or an entry
class (`internet`, `netbird`, ADR 0011 D10) and destination is a host or
observed endpoint address with `proto` ∈ {tcp, udp} and a port, the model
returns one **verdict** with an **explanation chain**.

**Inputs (one snapshot).** All read from the server stores, never from
devices directly:

| Input | Source |
| --- | --- |
| Zones, interfaces with units, VLAN tags and addresses | ND-16 firewall policy dataset (ADR 0010 D4) |
| Security rules in order, incl. `disabled`, negation flags, application, service, source-user, schedule | ND-16 (fields beyond the ND-07 allowlist need NS-04, see below) |
| NAT rules in order | ND-16 |
| Address/service objects and groups (static, nested, dynamic) | ND-16 |
| Default security rules (intrazone allow, interzone deny, and their overrides) | ND-16 after NS-04; until then the vendor defaults, labelled "default assumed" (*verify* per release in NS-03) |
| CBS ports, VLAN membership, LLDP | ND-16 (ADR 0010 D4) |
| IPAM networks with VLAN | `internal/ipam` |
| Host-side VLAN and route data, guest NIC bridge/VLAN | ADR 0009 `net.facts`, `internal/trafficstore/guestnics.go` |

The snapshot has a **snapshot hash** over the canonical encoding of every
input dataset version (the ND-16 dataset IDs and the `redacted_digest` of
the policy version, never `raw_digest`) and the model version. Same hash +
same model version → same verdicts (determinism is a test).

**Model version** `nr-v1`, stored with every verdict. Any change to
evaluation semantics creates `nr-v2`.

**Evaluation steps (`nr-v1`).**

1. **Placement.** Map source and destination to an L2 segment (VLAN/IPAM
   subnet) and to a firewall zone through the interface that owns the
   subnet. An address outside every known subnet maps to the zone of the
   route that leads to it (default route → the zone of the WAN interface);
   no route known → `unknown`.
2. **Crossing test.** Source and destination in the **same L2 segment**
   (same VLAN or same IPAM subnet, and no firewall interface between them
   per the data) → verdict **`not_filtered`**: traffic does not cross the
   firewall, its rules are irrelevant. Host firewalls (nftables) are not
   modelled in `nr-v1` and the explanation says so.
3. **NAT.** Destination NAT rules are evaluated first, in order, on the
   pre-NAT packet (PAN-OS semantics: security rules match the **pre-NAT
   address** and the **post-NAT zone**, *verify* in NS-03); the matched NAT
   rule is part of the chain.
4. **Security rules.** In order, first match wins; disabled rules are
   skipped and listed in the chain as "skipped (disabled)". A rule matches
   when zones, addresses (with negation), and service match. Rules with an
   application other than `any`, a `source-user`, a URL category or a
   schedule match only conditionally; such a match yields
   **`conditional`** with the conditions listed (for example "allowed if
   App-ID identifies `ssh`"), and evaluation also continues to the next
   unconditional match to show what happens otherwise.
5. **Default rules.** No match → the default intrazone or interzone rule
   (from the data, else the vendor default labelled "assumed").

**Verdicts.**

| Verdict | Meaning |
| --- | --- |
| `allowed` | An allow rule matches unconditionally; chain names rule and NAT |
| `conditional` | First matching allow depends on App-ID, user, URL category or schedule; counts as reachable for every security use (fail closed) |
| `denied` | A deny/drop/reset rule or the default interzone rule matches |
| `not_filtered` | Same L2 segment; the firewall is not on the path |
| `unknown` | Any input missing, stale (ADR 0010: three missed intervals) or `incomplete` (D3 limits); an object that cannot be evaluated (FQDN, EDL, dynamic group whose members are unknown, region objects); more than one vsys; route ambiguity. The reason is listed |

**Explanation chain.** Every verdict carries the ordered list of steps
with the data that decided each step: segment and zone mapping with their
source dataset and age, NAT rule matched, each rule examined up to the
decision with "no match because …" or "skipped (disabled)", the deciding
rule, snapshot hash and model version. The chain is rendered as text; rule
names and descriptions are device text (spec 09).

**Limits.** The model reuses the ADR 0010 D3 parse limits (named constants
in `internal/netdevcontract/`) for its inputs and adds named limits for
work per computation: queries per batch, expanded address ranges per rule,
group expansion depth (the ND-09 limit), and a wall-clock budget per job
(default 30 s). A computation that hits a limit returns `unknown` for the
affected queries with the reason "limit reached", never a guessed verdict.

**Who computes.** NOS server, pure package (NS-05), recomputed on a new
dataset version of any input and at most hourly. Reason as ADR 0011 D10:
rules, flows and placements are already in NOS, must not leave it (ADR 0011
Q6) and the result must be reproducible.

**Redaction allowlist additions (needs ADR 0010 ND-07 change, protected).**
`nr-v1` and D4 need PAN-OS elements that the ND-07 allowlist does not pass
today: `rulebase/default-security-rules`, the rule fields
`negate-source`, `negate-destination`, `schedule`, `profile-setting`
(profile and group **names** only) and `log-setting` name, and
`zone/<name>/network/zone-protection-profile` name (*verify* exact paths in
NS-03). They carry no secrets; NS-04 adds them through the reviewed
allowlist process with the fail-closed keyword rule unchanged. Until NS-04
lands, checks that need them report "data not collected", never "ok".

### D3: Exposure-aware vulnerability priority (B)

The reachability model feeds ADR 0011 as a **compensating-control signal**.
It changes priority only; it never changes a finding's state.

**Mitigation record per finding.** For each open finding whose affected
service is mapped to a listening port (ADR 0011 D10 mapping; unmapped →
no mitigation, flagged "port unknown"), NOS queries the model from every
entry class and every zone, plus the finding host's own segment, and stores:

- per source: verdict, deciding rule (name and UUID), NAT rule, chain hash;
- the snapshot hash, model version and computation time;
- a summary: "mitigated by rule X from zones Y; still reachable from Z".

**Formula `vu-prio-v2`.** Identical to `vu-prio-v1` (ADR 0011 D7) except
for the exposure term, which the reachability model now determines when a
valid mitigation record exists:

```
reachable(s) = verdict(s) ∈ {allowed, conditional, not_filtered, unknown}
expo = 1.0  if reachable(internet)
       0.7  else if reachable(netbird)
       0.4  else if reachable(any zone other than the host's own segment)
       0.3  else if reachable only from the host's own segment
       0.2  no listening service (unchanged)
```

All other terms, the tier thresholds and the **KEV floor (never below
high)** are unchanged. Weights are named constants; the record names the
formula version. `vu-prio-v1` values stay stored for comparison; the UI
shows both until the maintainer retires v1.

**Fail closed.** The mitigation record is valid only while all of these
hold; otherwise the finding uses its `vu-prio-v1` exposure (unmitigated)
and shows "mitigation unknown: <reason>":

- every input dataset of the snapshot is fresh (not stale, not
  `incomplete`);
- the policy version (`redacted_digest`) and every referenced object are
  unchanged since the computation (**a rule or object change voids every
  mitigation at once**, before recomputation);
- no verdict on a path that the record counts as mitigating is `unknown`;
- **no contradiction**: no observed flow (ADR 0009 flows, D5 log
  aggregates with action allow) in the last 24 h from a source the record
  calls `denied` to the finding's host and port. A contradiction voids the
  record and raises an advisor finding "model contradicted by observed
  traffic" (D4).

**What stays unchanged.** ADR 0011 D5 closure paths 1–6 and their
preconditions, D6 states and retention, and D9 events are untouched. A
mitigated finding stays `open`; mitigation is not a state, not a closure
reason and not evidence for any closure. `accepted_risk` and
`false_positive` remain admin-only with the Q4 assertion rule. A finding
whose tier rises because a mitigation is voided raises
`vuln.critical_new` under the unchanged D9 dedupe.

**Attack paths (ADR 0011 D10).** Network edges from firewall rules are
computed from the reachability model instead of raw allow/NAT rules:
`allowed` and `conditional` → policy edge; `not_filtered` → L2 edge, still
flagged "assumed" in `ap-v1` (host firewalls not modelled); `denied` → no
edge; `unknown` → edge flagged "assumed" (fail closed). Choke-point
candidates "one edge removed by a rule change" are what-if results (D4).
`ap-v1` stays; using the model as edge source is a data-source change,
recorded with the graph snapshot hash.

### D4: Rule and segmentation advisor (C)

**Advisor findings** are a separate store from ADR 0011 findings (different
kind, not subject to ADR 0011 D5). NOS computes them deterministically from
a snapshot, so NOS also resolves them: a check that no longer fires on a
fresh complete snapshot marks its finding `resolved`; a check that cannot be
evaluated leaves it as it was and shows "not evaluated since …". The admin
may `acknowledge` a finding with reason and expiry (default 90 days, maximum
365), bound to the rule UUID and the policy `redacted_digest`; a policy
change touching the rule re-opens it. Every finding names its check ID and
check version (`na-v1`), the snapshot hash and the evidence.

**Checks (`na-v1`).**

| Check | Fires when | Evidence shown |
| --- | --- | --- |
| `shadowed-rule` | An enabled rule can never match because earlier rules together cover its full match space (zones, addresses incl. negation, service, application, user, schedule). Partial overlap is a separate, lower `overlap` hint. Objects that cannot be evaluated → "cannot decide", no finding | Covering rule(s), the shadowed rule, why |
| `any-any` | An allow rule with source **and** destination address `any`, or source **or** destination zone `any`, or service and application both `any` | Rule, which fields are `any` |
| `allow-without-profile` | An allow rule toward or from a zone of trust class `untrusted` or `guest` with no security profile or profile group (needs NS-04) | Rule, zones |
| `zero-hits` | Enabled rule with zero hits since the later of rule creation and counter reset, with **≥ 30 days observed**; the reset time and observed window are shown (same rule as ADR 0010 ND-20); never a delete proposal | Hit count, first/last hit, reset time, window |
| `dns-bypass` | Observed DNS (udp/tcp 53, tcp 853) from internal endpoints to destinations other than the operator-designated resolvers (DNS proxy or internal resolver addresses set in NOS), from flows or log aggregates, or an allow rule that permits DNS from an internal zone to an external zone without restricting the destination | Endpoints, destinations (aggregated), rule |
| `mgmt-from-untrusted` | Reachability (`allowed`, `conditional`, `not_filtered`, `unknown`) from a zone of trust class `untrusted`, `guest` or `iot`, or from `internet`/`netbird`, to a management target on its management ports | Source zone, target, port, verdict chain |
| `model-contradiction` | Observed allowed traffic where the model says `denied` (D3) | Flow, rule chain |

**Zone trust classes and management targets** are operator data in NOS:
each zone gets one of `untrusted`, `guest`, `iot`, `internal`,
`management` (default `unknown`, which counts as `untrusted` for the
checks above); management targets default to the ADR 0010 devices, PVE
nodes (8006/tcp), managed hosts' SSH port, the NOS server and executor
host, and IPMI/BMC assets if IPAM knows them; the operator can add or
remove targets. Setting both is an audited admin action.

**Segmentation proposals.** From the traffic map flows (21 days, ADR 0009
D3), log aggregates (D5) and asset roles (IPAM asset kind, ADR 0011 crown
jewel roles, operator tags), NOS groups endpoints into proposed segments
(for example "IoT", "servers", "clients", "management") and, for a proposed
cut, lists:

- each proposed segment with members and why (role, tag, kind);
- every observed flow that would cross the cut and therefore need an allow
  rule, aggregated by (source segment, destination, proto, port);
- the minimal allow list covering those flows, as **text** for the
  operator;
- the coverage window and its limit: flows rarer than the window (monthly
  backups, yearly jobs) are not seen; endpoints without managed hosts or
  sensor data contribute only what others observed.

Grouping is deterministic (`sp-v1`, rules by role, then by observed
communication), never a learned model, and every assignment can be
overridden by the operator before the result is recomputed.

**What-if.** The operator states a hypothetical deny `(source zone or
subnet → destination host or subnet : proto/port)` and a position (top, or
before rule X). NOS evaluates a copy of the snapshot with the rule inserted
and shows:

- which ADR 0011 findings would become mitigated (with their `vu-prio-v2`
  tier before and after) and which attack paths would be cut (D10 choke
  point arithmetic);
- which observed flows of the last 21 days (traffic map) and 30 days (log
  aggregates, if Q2 keeps 30) would be **broken**, with endpoints and
  volumes;
- whether ADR 0010 D5 would classify the rule as CRITICAL (NOS-path
  overlap; with the flat lab network every deny overlapping `<lab-net>` or
  `any` is CRITICAL) and therefore refused by NOS's own change path.

What-if results are not stored as proposals, have no "apply" button, and
cannot be submitted to any change path in this ADR.

**Applying suggestions.** Always the operator, on the device. If phase 2a
of ADR 0010 is ever started, a later amendment may let the advisor prefill
an ND-35 typed change (never submit it); it would then pass the full
ADR 0010 D5 risk derivation, approval and permit flow. That is not decided
here.

### D5: Firewall logs (D)

**Source: compare and recommend.**

| Aspect | Syslog receiver on the collector host | XML API log query by the executor (netdev read path) |
| --- | --- | --- |
| New network listener | Yes (UDP/TCP 514 or TLS 6514); the collector has none today (ADR 0010 D4), so a new process and port | No; reuses the pinned HTTPS client of ND-08 |
| Authenticity | UDP/TCP syslog unauthenticated and spoofable by any host on the flat network; TLS syslog with a firewall client certificate fixes this (*verify* PAN-OS client-cert support for syslog over SSL) | Pinned TLS to the registered device (ADR 0010 D1/D3) |
| Credential | None in NOS | Read key needs log query permission in the read-only admin role (*verify* in NS-03; separate role/key if it must be wider) |
| Completeness | Near real time; drops under load (UDP) are silent | Pull by time window; per-query cap (`nlogs`, *verify*: max 5,000) and async job; an hour over the cap is marked `incomplete`, never silently partial |
| Load on device | Firewall pushes, low cost | Queries on a weak CPU; one request per device at a time (ADR 0010 D4) |
| Where data is first minimised | Receiver (new code outside the executor) | Executor, before anything leaves it (same place as redaction) |
| Fits existing model | New role, new systemd unit, new spool | New typed read methods under the device read lease |

**Recommendation: XML API log query through the executor**, hourly, for
`traffic` and `threat` logs. It adds no listener, inherits pinning, leases,
budgets and the collector spool, and minimises in the executor. If NS-03
shows the cap cannot cover a lab hour, the next option is a firewall-side
aggregate (PAN-OS custom report via the API, *verify*) before considering
syslog; TLS syslog with client certificates would need its own ADR
amendment (Q1).

**Typed methods.** `panos.log.traffic_hourly` and `panos.log.threat_hourly`,
parameters only `(device_id, hour)`; the executor builds the fixed query
(time window, fixed field selection), polls the job, parses with the ND-09
XML limits, and returns only aggregates. No caller-supplied filter, query
or xpath (ADR 0010 non-goals).

**Minimisation (in the executor).** Kept per record before aggregation:
time (truncated to the hour), source and destination address, destination
port, protocol, application, action, rule name and UUID, source and
destination zone, bytes and sessions; for threat logs additionally threat
ID, threat name (vendor text, spec 09), severity, direction. **Dropped
always:** source-user and any User-ID field, URLs and URL categories per
request, file names and hashes, packet captures, X-Forwarded-For, host
names, device serials of endpoints, session IDs, NAT-translated source
ports.

**Aggregates.** Keyed per hour by `(src, dst, proto, dst_port, action,
rule_uuid)` for traffic and `(src, dst, threat_id, action)` for threats,
with sessions, bytes, first and last seen. Per-hour caps (named constants,
for example 20,000 keys per device and hour); over the cap → top keys by
sessions kept, the hour marked `incomplete` with the dropped count.

**Retention and personal data.** Addresses in firewall logs are personal
data (internal addresses identify household members' and guests' devices;
external addresses reveal who talks to whom). Proposed defaults, decided
in Q2:

- hourly aggregates **30 days**, pruned hourly (longer than ADR 0009's 21
  days; ADR 0009 D3 says a longer retention for flows needs a new decision,
  and this is that decision for this separate dataset only — or align to
  21 days);
- **external addresses without a reputation hit** are kept in full for
  **7 days** (allows matching against a feed that lists them later), then
  reduced to their /24 (IPv4) or /48 (IPv6) prefix inside the aggregate;
- reputation hits (D6) keep the full external address for **90 days** as a
  security record;
- admin-only pages, no export, no read-only API scope; excluded from the
  age-encrypted instance backup unless Q2 decides otherwise;
- the operator guide states what is collected and that the operator is
  responsible for informing household members and guests.

### D6: IP reputation (D)

**Feeds are fetched by the vulnerability agent host only** (ADR 0011
amendment 1, A1.5 egress; D4 feed rules: origin allowlist, verified TLS,
no cross-origin redirects, size and decompression limits, content dates,
maximum snapshot age, plausibility gate, bulk downloads only). The NOS
server never fetches feeds and gains no egress. Candidate feeds (Q3):

| Feed | Kind | Key | Note |
| --- | --- | --- | --- |
| abuse.ch Feodo Tracker IP blocklist | botnet C2 | none | *verify* format, update interval, terms |
| abuse.ch SSLBL IP blacklist | botnet C2 | none | *verify* the list is still published |
| Spamhaus DROP (and EDROP) | hijacked/criminal netblocks | none | *verify* whether EDROP is still separate or merged into DROP; terms of use |
| FireHOL level1 | aggregate | none | contains bogon and private ranges; those are removed on ingest (below) |
| AbuseIPDB blacklist (optional) | reported abusers | API key | bulk blacklist endpoint only; key on the agent host only |
| CrowdSec blocklists (optional) | community signals | API key/enrolment | bulk lists only; key on the agent host only |

**No per-address lookups.** No component sends an observed address to any
provider (no AbuseIPDB "check", no CrowdSec CTI per IP). This keeps the
ADR 0011 rule "bulk downloads only, no inventory sent out" and keeps
personal data inside NOS.

**Upload to NOS.** The agent normalises each feed to a **reputation
snapshot**: feed ID (from a fixed NOS-side list, as ADR 0011 D5 source
IDs), content date, entry count, entries `(CIDR, category)`. It uploads it
through a new API scope `netsec.reputation.write` on `/api/v1`, on a token
separate from the `vuln.*` token (or the same agent identity with the
added scope, Q3). The agent **never** gains a read scope for flows, logs,
endpoints or findings.

**Validation in NOS (fail closed per feed).** Every snapshot is untrusted:

- CIDR syntax, IPv4/IPv6 only; entries in private, loopback, link-local,
  CGNAT, multicast, documentation, reserved or unspecified ranges, or
  overlapping any IPAM network or the NOS path, are **dropped** and counted;
- prefixes shorter than a named minimum (proposed /8 IPv4, /24 IPv6) are
  dropped and counted;
- per-feed and total entry caps (named constants); an over-cap snapshot is
  refused, the previous one stays with "feed stale";
- content date not older than the stored one and not in the future (as ADR
  0011 D5 high-water marks); maximum snapshot age 72 h, then "feed stale";
- plausibility: a snapshot that shrinks or grows by more than a named
  factor against the previous one is held for an admin.

**Matching in NOS.** A pure matcher (prefix trie over the accepted
snapshots) runs over the log aggregates (D5) and the ADR 0009 flows and
observed endpoints. A **reputation hit** records: external address, feed
IDs and categories, first and last seen, sessions and bytes split by
**allowed vs denied**, direction (inbound/outbound), internal endpoints
involved (linked to the ADR 0009 endpoint, IPAM asset or managed host, and
to the traffic-map focus view), and the feed snapshot it rests on. A later
snapshot that delists the address ends the hit episode; the record stays
for its retention.

**Notifications.** Event `netsec.reputation_allowed`: traffic with action
allow (or an observed flow, which implies allow) to or from a listed
address. Dedupe per `(external address, internal endpoint, feed)` episode;
the ADR 0011 D9 rate limit and hourly digest apply (10 per hour). Messages
carry structured fields only (feed, category, internal endpoint label,
direction, allowed sessions), no external address in third-party channels
unless the operator enables it (Q8). Denied-only hits do not notify; they
appear in a daily count. Event `netsec.feed_stale` per feed and episode.

### D7: EDL export (E)

**Optional, off by default** (Q4). NOS can publish one or more curated
**External Dynamic Lists** (IP lists) that the firewall pulls on its own
schedule; the operator references them in deny rules they write. NOS gains
no write access to the firewall.

- **Endpoint.** `GET /edl/<list-id>.txt` on `nebula-server` over HTTPS,
  plain text, one IPv4/IPv6 address or CIDR per line, ASCII only,
  `Content-Type: text/plain`, `Cache-Control: no-store`, no cookies, no
  session, not reachable through the web UI session.
- **Authentication.** HTTP basic credentials generated by NOS (random, at
  least 32 bytes, shown once, stored as a hash, rotatable) or mTLS with a
  client certificate on the firewall, whichever PAN-OS supports for EDL
  pulls (*verify* in NS-03). **No token in the URL** (URLs end up in logs).
  Optional source-address allowlist set to the firewall's registered
  address (ADR 0010 D1).
- **Content only from manually approved entries.** An entry is added by an
  admin with the ADR 0011 Q4 assertion rule (fresh WebAuthn assertion),
  reason and optional expiry; removal is audited. The admin may start an
  add from a reputation hit (the form is prefilled), but every entry needs
  its own add with assertion. **No automatic adds from feeds.** Feed data
  is untrusted (D6); a list fed from it and referenced in a deny rule would
  be an auto-block, which this ADR excludes (non-goals). Feed-driven
  **rule sets** are therefore not part of this ADR; whether they are ever
  wanted is a maintainer question (Q4b) and would need an amendment of this
  ADR that revises the non-goal.
- **Refusals (checked on every add and every publish).** Entries
  overlapping private, reserved and special ranges, any IPAM network, the
  NOS path, the firewall's own addresses, configured protected destinations
  (DNS upstreams, update mirrors, the feed origins, NetBird management,
  operator-listed) are refused; a list over its size cap (named constant,
  default 10,000 entries, below the model's EDL capacity, *verify*) is not
  published and the previous version stays.
- **Audit.** Every add, removal, publish (version number,
  entry count, digest) and every pull (time, source address, result) is
  audited. The UI shows when the firewall last pulled.

**Stated risk.** The EDL is an effect on the firewall that does not pass
the ADR 0010 permit path. A compromised server could serve a list that
blocks external addresses (availability) or empty it (removes blocks).
Bounds: off by default; every entry is a manual admin add with assertion,
so feed data and the agent token cannot reach the list; the refusals
above keep internal and protected
destinations out; the operator guide requires the EDL to be used only in
deny rules on untrusted/WAN zones; the firewall keeps its last fetched list
when a pull fails (*verify*), so an outage of NOS does not unblock; the
audit trail and the "last pulled" view. A compromised server can already
mislead the operator in many ways (ADR 0010 D7); it still cannot change the
policy, NAT or management of the firewall.

### D8: Where it runs, data access and limits

- Model, advisor, proposals, what-if, matcher and EDL generation run in
  `nebula-server` as pure packages plus thin jobs (recommended; Q5). The
  agent host would need topology and flows, which ADR 0011 Q6 withholds.
- All pages are **admin-only** (as the ADR 0010 firewall view and ADR 0011
  attack paths); nothing is in the read-only API; exports of advisor
  findings are admin-only, audited, CSV-injection-safe (ADR 0011 D9).
- Every job has a named wall-clock budget and output caps; truncation is
  stated, never silent.
- UI rendering follows ADR 0009 D4 isolation for any map overlay and the
  existing strict CSP; all device, log and feed text is escaped text.

## Non-goals

- No device change of any kind, no auto-block, no automatic rule, object,
  EDL or NAT change; the EDL contains only entries an admin added one by
  one with assertion. No feed-driven EDL rule sets (open as Q4b; they
  would need an amendment that revises this non-goal).
- No change to ADR 0011 closure paths, states or retention; mitigation
  never closes a finding.
- No per-address reputation lookups at any provider; no feed egress from
  the NOS server.
- No packet capture, payload, URL or user identity storage.
- No host-firewall (nftables) modelling in `nr-v1`; no IDS/IPS of its own.
- No learned anomaly model; segmentation grouping is rule-based.
- No support for multi-vsys, Panorama or HA pairs beyond ADR 0010 (single
  vsys, Q2 there).

## Threat model additions

| Threat | Defence |
| --- | --- |
| Model error makes a reachable service look mitigated | Fail closed: unknown, conditional and stale count as reachable; any policy change voids mitigations; contradiction with observed traffic voids and reports; KEV floor unchanged; mitigation never closes |
| Hostile device text (rule names, descriptions, threat names) | Spec 09 bounds, escaped text, no links from device text |
| Spoofed or flooded logs | API pull over pinned TLS (recommended); per-hour key caps with `incomplete` marking; syslog only with TLS client certs and a separate decision |
| Poisoned reputation feed (false hits, hidden hits, internal ranges) | Feed rules of ADR 0011 D4 on the agent host; NOS-side validation (special/internal ranges dropped, prefix minimum, caps, high-water marks, plausibility hold); hits are advisory; no feed data reaches the EDL (manual entries only, D7) |
| Leak of observed addresses to third parties | No per-address lookups; agent has no read scope for flows, logs or endpoints; notifications omit external addresses and personal endpoint labels by default (Q8) |
| Compromised agent token | Can upload false snapshots within caps and validation: false or hidden reputation hits and notifications (misleading the operator, who may then add or skip EDL entries by hand); cannot read anything; separate scope, rotatable, source-bound. **Residual if Q4b ever allows feed-driven EDL rule sets:** false entries would flow into a list the firewall enforces and block legitimate external destinations (availability impact), bounded only by that amendment's hard limits (minimum prefix, per-rule-set cap, per-source opt-in, refusals); this is why D7 has no rule sets |
| EDL abused to block or unblock | Off by default, manual entries with assertion, refusals, caps, audit, operator guide limits EDL to WAN deny rules; residual stated in D7 |
| EDL credential leak | Basic credential hashed in NOS, rotatable, source allowlist; mTLS if supported; the list content is low sensitivity but reveals what the operator blocks |
| Personal data in logs | Minimisation in the executor, aggregates only, short retention, prefix reduction, admin-only, no export, excluded from backups by default |
| Advisor as a map for an attacker | Admin-only, not in the read-only API, exports audited |

`docs/threat-model.md` is protected and receives these items in NS-02.

## Consequences

- NOS can explain reachability, including "not filtered" in the flat lab
  network, and turns firewall rules into explainable risk reduction in
  vulnerability priority without weakening any ADR 0011 rule.
- The executor gains two typed log read methods and more XML parsing of
  hostile input (bounded, fuzzed, minimised at the source).
- The agent host gains reputation feed origins in its egress allowlist and a
  new upload scope; the server gains a new API scope, stores for log
  aggregates, reputation snapshots, hits and advisor findings, and
  optionally the EDL endpoint.
- The ND-07 PAN-OS redaction allowlist grows by a few non-secret elements
  (protected change, reviewed).
- A new personal-data dataset (firewall log aggregates) exists, with its own
  retention and minimisation.
- Some answers stay "unknown" (App-ID, User-ID, FQDN objects, host
  firewalls). That is intended; unknown is never shown as safe.

## Required specification changes (NS-02)

- `docs/spec/03-processes-and-data.md`: new tables, retention (log
  aggregates, hits, reputation snapshots, advisor findings), EDL endpoint.
- `docs/spec/07-execution-model.md`: typed log read methods in the device
  read profile.
- `docs/spec/09-untrusted-host-data.md`: log fields, limits, feed snapshot
  input rules.
- `docs/spec/12-inventory.md`: zone trust classes, management targets,
  advisor findings, reputation hits.
- `docs/spec/13-notifications.md`: scope `netsec.reputation.write`, events
  `netsec.reputation_allowed`, `netsec.feed_stale`.
- `docs/spec/01-product.md`, `16-milestones.md`, `04-revision-history.md`;
  `docs/threat-model.md`.

Tickets: [docs/implementation/network-security.md](../implementation/network-security.md).

## Open questions for the maintainer

- **Q1: Log source.** XML API log query through the executor
  (recommended, D5) or a syslog receiver (then only TLS with client
  certificates, as a separate process and ADR amendment)? May the
  phase-1 read-only PAN-OS role get log query permission, or is a second
  read key for logs required?
- **Q2: Retention.** Log aggregates 30 days (proposed) or 21 days like the
  traffic map? Full external addresses 7 days, then /24 and /48? Reputation
  hits 90 days? Log aggregates excluded from the instance backup
  (proposed)?
- **Q3: Reputation feeds and keys.** Which of Feodo, SSLBL, Spamhaus DROP
  (EDROP), FireHOL level1 by default? AbuseIPDB and/or CrowdSec with keys on
  the agent host, or none? Separate token for `netsec.reputation.write` or
  the existing agent identity with an added scope?
- **Q4: EDL.** Build D7 at all? If yes: basic credentials or mTLS (subject
  to NS-03) and the default size cap. D7 as drafted has manual entries
  only.
  - **Q4b: Feed-driven rule sets.** Should NOS ever add EDL entries
    automatically from reputation feeds? This draft does not: it would be an
    auto-block from untrusted feed data and conflicts with the non-goal.
    If the maintainer wants it, it needs an amendment of this ADR that
    revises the non-goal and states the residual risk (a compromised agent
    token or poisoned feed blocks legitimate destinations), and at least
    these hard limits, each a named constant the operator cannot exceed:
    a **minimum prefix length** for rule-set entries (single addresses,
    /32 IPv4 and /128 IPv6, unless the maintainer names a shorter one), a
    **per-rule-set entry cap** far below the list size cap, an **explicit
    operator opt-in per entry source** (per feed ID and category, with
    assertion; no "all feeds" option), entries expiring when the source
    delists them or goes stale, and the D7 refusals on every add and
    publish.
- **Q5: Where the advisor runs.** NOS server (recommended) or the agent
  host?
- **Q6: UI placement.** Firewall view (ADR 0010 ND-20) for rule findings
  and what-if; traffic-map overlay (reachability and hits, ADR 0009 TM18
  renderer); vulnerability page for mitigation (ADR 0011 VU-11); or one
  "Network security" page that links into those?
- **Q7: Priority formula.** Accept `vu-prio-v2` exposure levels (1.0 / 0.7
  / 0.4 / 0.3 / 0.2), and show v1 beside v2 until retired?
- **Q8: Notifications.** Include the external address in
  `netsec.reputation_allowed` messages to webhook/ntfy/Telegram, or
  structured fields without it (proposed)? Notify on threat logs with
  action allow/alert at severity critical?
- **Q9: Zone trust classes and management targets.** Defaults as in D4
  (unknown zones count as untrusted)? Which resolvers are the designated
  DNS resolvers for `dns-bypass`?
- **Q10: Release placement.** After ADR 0010 phase 1 (ND-16 and ND-20) and
  ADR 0011 VU-10/VU-22; reputation after the agent (va01–va08)?
