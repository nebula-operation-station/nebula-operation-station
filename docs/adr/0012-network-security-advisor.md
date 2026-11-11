# ADR 0012: Network security advisor: reachability, rules, segmentation, firewall logs and IP reputation

Status: **Accepted 2026-11-11 (previously Proposed)**. The maintainer
(Axel) answered Q1–Q10 on 2026-11-11 09:18 by accepting every
recommendation; the answers are recorded in "Decisions 2026-11-11" below
and in the D-sections. Q11 (ND-07 allowlist additions) stays open; until
it is answered the D2 fail-safe rule applies and NS-04 does not start.
Tickets: `docs/implementation/network-security.md`.

History:

- 2026-11-11: first draft (ticket ns00).
- 2026-11-11: review fix round 1 (ticket ns00f): EDL manual entries only,
  feed-driven rule sets moved to Q4b (previously an opt-in rule set in D7);
  agent-token residual in the threat table; `vu-prio-v2` without the 0.3
  own-segment level (previously 1.0/0.7/0.4/0.3/0.2); unowned subnets →
  `unknown`; no export of log- or flow-derived evidence; rule-scoped
  acknowledgement digest (previously the policy `redacted_digest`); feed
  prefix minimum /16 and /32 (previously /8 and /24); Q2 and Q8 extended.
- 2026-11-11: review fix round 2 (ticket ns00f2): conditional deny rules
  and service `application-default` (previously conditional allow only);
  private and special ranges outside IPAM → `unknown` (previously placed
  via the route, default route → WAN); Q4 asks whether any
  firewall-enforced effect outside the ADR 0010 permit path is allowed;
  ND-07 allowlist additions moved to Q11 (previously decided in D2);
  retention of the internal side of reputation hits; EDL source allowlist
  required; acknowledgement and notification defaults offered in Q8/Q9.
- 2026-11-11: review fix round 3 (ticket ns00f4): one fail-safe rule for
  unevaluable rules in D2 (previously per-field labels such as "default
  assumed" and "negation and default rules not collected" with a shown
  `denied`); `rule-type` and `source-hip`/`destination-hip` added to Q11;
  mitigation voided on `raw_digest` change too; mitigation queried over
  every host address; reputation hits from `incomplete` hours never
  denied-only; NS-05 test duties for these four points.
- 2026-11-11: maintainer decisions Q1–Q10 recorded (ticket ns00g),
  status Accepted (previously Proposed); feed-driven EDL rule sets and
  Q4b removed (previously open as Q4b); syslog receiver dropped
  (previously NS-13b if Q1 chose syslog); the D2 fail-safe rule covers
  NAT rules too (previously security rules and the default-rule step
  only).

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
  proposal, permit or approval, or blocks traffic on its own. The optional
  EDL (D7) is the one exception: a list the firewall enforces, with
  only entries an operator approved, pulled by the firewall itself, but
  **outside the ADR 0010 permit path and its phase-2a write gate** (ADR
  0010 Q3). The maintainer allowed this one firewall-enforced effect, with
  manually approved entries only (Q4, 2026-11-11; previously not decided,
  D7 not built without an explicit yes).
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
| `nebula-executor` | Reads PAN-OS logs under a device read lease (new typed methods, D5) with a separate read-only log role and key (Q1), minimises and aggregates before anything leaves it | Accept caller-supplied queries, filters or xpaths; return raw log records |
| `nebula-netdev-collector` | Schedules the typed log reads, spools the results (unchanged ADR 0010 role) | Hold credentials, listen on the network |
| `nebula-vuln-agent` (ADR 0011 amendment 1) | Fetches reputation feeds from allowlisted origins, verifies, normalises and uploads prefix lists to NOS with the added scope `netsec.reputation.write` on its existing identity (D6, Q3) | Receive observed addresses, flows, topology or findings; do per-address lookups at any provider |
| Firewall (PAN-OS) | Pulls the EDL if the operator configured it (D7; allowed by Q4) | Receive anything pushed by NOS |
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
| Default security rules (intrazone allow, interzone deny, and their overrides) | ND-16 after NS-04; until then not collected, so a decision by a default rule is `unknown` ("Unevaluable rules (fail-safe)" below; previously the vendor defaults labelled "default assumed") |
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
   subnet. A **public** address outside every known subnet maps to the zone
   of the route that leads to it (default route → the zone of the WAN
   interface); no route known → `unknown`. An address in a **private or
   special range** (RFC 1918, CGNAT 100.64/10, loopback, link-local, ULA
   fc00::/7, multicast, documentation, reserved, unspecified) outside every
   known subnet is **never** placed through the default route: in the flat
   lab with incomplete IPAM it is most likely an internal device, so the
   verdict is **`unknown`** with the reason "private address outside known
   subnets", never `denied` by the default interzone rule toward WAN
   (previously: any address outside known subnets followed its route). A
   specific, non-default route the data proves for that range (for example
   a NetBird or site-to-site interface route) still places it in that
   route's zone. A **known IPAM subnet that no firewall
   interface owns** (routed by a host, a hypervisor or another router) has
   no zone: if the crossing test (step 2) does not already give
   `not_filtered`, the verdict is **`unknown`** with the reason "subnet not
   on a firewall interface", never `denied`. The default interzone rule
   applies only between zones the data proves; the firewall may not be on
   that path at all.
   The entry class **`netbird`** is placed on a firewall zone only when the
   data proves that every NetBird path to the destination crosses a
   firewall interface (the destination has no NetBird interface in its
   ADR 0009 `net.facts`, and the overlay range reaches it only through a
   routing peer or route behind a firewall zone). A destination that is a
   NetBird peer itself, or is reached through a routing peer whose path to
   it does not cross the firewall, is reached over the overlay directly:
   verdict **`not_filtered`** with the reason "overlay path bypasses the
   firewall". Anything not proven (no `net.facts` for the host, an
   observed endpoint without host data, unknown routing peers or overlay
   routes) → **`unknown`** "NetBird path not proven". An overlay path that
   bypasses the firewall never gets a firewall `denied` (previously: the
   placement of `netbird` was unspecified).
2. **Crossing test.** Source and destination in the **same L2 segment**
   (same VLAN or same IPAM subnet, and no firewall interface between them
   per the data) → verdict **`not_filtered`**: traffic does not cross the
   firewall, its rules are irrelevant. Host firewalls (nftables) are not
   modelled in `nr-v1` and the explanation says so.
3. **NAT.** Destination NAT rules are evaluated first, in order, on the
   pre-NAT packet (PAN-OS semantics: security rules match the **pre-NAT
   address** and the **post-NAT zone**, *verify* in NS-03); the matched NAT
   rule is part of the chain.
   **Reverse-NAT lookup.** A query whose destination is a host's internal
   address does not stop at that address: the model also looks up every
   destination NAT rule whose translated (post-NAT) address and port cover
   the host's address and the queried port, and evaluates the query once
   more per such rule on its **pre-NAT** packet (the rule's original
   destination address, zone and service, for example the public WAN
   address of a port forward). NAT stays evaluated on the pre-NAT packet;
   the lookup only adds the pre-NAT destinations to try. The verdict for
   the source is the most reachable one over the internal address and all
   pre-NAT destinations, in the order `allowed`, `conditional`,
   `not_filtered`, `unknown`, `denied`; it is `denied` only if every one of
   them is `denied`. A port-forwarded service queried from `internet` is
   therefore `allowed` through the NAT rule and its allow rule, never
   `denied` by the default interzone rule toward the internal address. A
   NAT rule whose translated or original address or port cannot be
   evaluated (FQDN, dynamic or region object, port range the model cannot
   expand within its limits) makes the verdict `unknown`, never `denied`;
   so does an unevaluable NAT rule ("Unevaluable rules (fail-safe)"
   below). The chain lists every pre-NAT destination tried (previously: only the
   internal address was queried, so a port forward could look `denied`).
4. **Security rules.** In order, first match wins; disabled rules are
   skipped and listed in the chain as "skipped (disabled)". A rule matches
   when zones, addresses (with negation), and service match. An enabled
   rule that is **unevaluable** (see "Unevaluable rules (fail-safe)"
   below) ends the evaluation with `unknown` when it is reached. A rule is
   **conditional** when its match depends on data the model does not have:
   an application other than `any`, a `source-user`, a URL category, a
   schedule, or the service `application-default` (the ports then depend
   on the App-ID result). This applies to **allow and deny rules alike**.
   Evaluation records a conditional match with its conditions (for example
   "allowed if App-ID identifies `ssh`", "denied if user is in group X")
   and continues to the next unconditional match to show what happens
   otherwise. The verdict over the conditional matches and the final
   unconditional decision (a rule or the default rule) is then:
   - any of them is an **allow** (a conditional allow, or a conditional
     **deny** followed by a later allow or by the default intrazone allow)
     → `conditional`: the traffic is allowed whenever the conditions fall
     that way; never `denied`;
   - all of them deny (conditional denies whose fall-through ends in an
     unconditional deny or the default interzone deny) → `denied`, because
     the traffic is denied either way;
   - the final decision cannot be determined (for example a conditional
     deny followed by a rule with an object that cannot be evaluated) →
     `unknown`.
   A conditional deny is therefore never counted as `denied` and never as
   a mitigation in `vu-prio-v2` (D3) unless the unconditional fall-through
   denies as well (previously: "conditional" was defined for allow rules
   only).
5. **Default rules.** No match → the default intrazone or interzone rule
   from the data; if the default rules were not collected (Q11) the
   verdict is `unknown` (previously: the vendor default labelled
   "assumed").

**Verdicts.**

| Verdict | Meaning |
| --- | --- |
| `allowed` | An allow rule matches unconditionally; chain names rule and NAT |
| `conditional` | A conditional allow decides, or a conditional deny (App-ID, user, URL category, schedule, service `application-default`) is followed by an allow; counts as reachable for every security use (fail closed) |
| `denied` | An unconditional deny/drop/reset rule or the collected default interzone rule matches, with no earlier conditional allow and no earlier unevaluable rule (a conditional deny counts only if its fall-through denies too) |
| `not_filtered` | Same L2 segment, or a NetBird overlay path that bypasses the firewall; the firewall is not on the path |
| `unknown` | Any input missing, stale (ADR 0010: three missed intervals) or `incomplete` (D3 limits); an object that cannot be evaluated (FQDN, EDL, dynamic group whose members are unknown, region objects), also in a NAT rule found by the reverse-NAT lookup; more than one vsys; route ambiguity; a private or special-range address outside known subnets; a known subnet on no firewall interface; a NetBird path not proven to cross the firewall; an unevaluable security rule reached in rule order (match field outside the collected allowlist, a `<dropped:…>` marker, Q11 rule fields not collected); an unevaluable NAT rule reached in NAT rule order or present during the reverse-NAT lookup; default rules not collected (Q11). The reason is listed |

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

**Redaction allowlist additions (proposed; change to the accepted ADR
0010 ND-07 allowlist, protected; open as Q11).** `nr-v1` and D4 would use
PAN-OS elements that the ND-07 allowlist does not pass today:
`rulebase/default-security-rules`, the rule fields `negate-source`,
`negate-destination`, `rule-type` (universal/intrazone/interzone),
`source-hip`, `destination-hip`, `schedule`, `profile-setting` (profile
and group **names** only) and `log-setting` name, and
`zone/<name>/network/zone-protection-profile` name (*verify* exact paths in
NS-03). They carry no secrets as far as this draft can tell. Whether the
accepted ADR 0010 allowlist may grow by these elements is a maintainer
decision (Q11), not settled here (previously: "NS-04 adds them"). If Q11
says yes, NS-04 adds them through the reviewed allowlist process with the
fail-closed keyword rule unchanged. Until then, and for good if Q11 says
no, checks that need them report "data not collected", never "ok", and
the rules and default rules concerned are unevaluable (below; previously:
every verdict labelled "negation and default rules not collected", a
`denied` shown but not counted as mitigating).

**Unevaluable rules (fail-safe).** One rule covers every rule field the
model cannot evaluate, instead of a label per field. A security rule, a
**NAT rule** (or the default-rule step) is **unevaluable** when any of
these holds:

- it carries a field that can change what the rule matches or, for a NAT
  rule, what it translates to, and that is outside the collected
  allowlist (ND-07, plus the Q11 elements once collected), for example
  `disabled` on a NAT rule if the allowlist does not pass it;
- it, or an object or group it references, carries a `<dropped:…>`
  marker from the ADR 0010 D4 redaction, for example a dropped
  sub-element of a NAT rule's translated address;
- its Q11 elements were not collected: `negate-source`,
  `negate-destination`, `rule-type`, `source-hip`, `destination-hip` for
  every security rule, and `rulebase/default-security-rules` for the
  default-rule step.

Consequences, all fail-safe:

- the reachability verdict of every query that reaches such a rule in
  rule order, or ends at an uncollected default rule, is **`unknown`**
  with the reason "rule <name> unevaluable: <field or marker>", never
  `denied` and never `allowed`; the chain lists the rule;
- for NAT rules (step 3): a query whose NAT step reaches an unevaluable
  NAT rule in NAT rule order is `unknown`; and while any NAT rule is
  unevaluable, the **reverse-NAT lookup** cannot exclude that the rule
  forwards to the queried host and port, so the lookup's result is
  `unknown` and a query to a host's internal address can never fall back
  to `denied` (previously: the fail-safe rule covered only security rules
  and the default-rule step, so an unevaluable NAT rule could hide a port
  forward behind a `denied` on the internal address);
- it never counts as mitigating in `vu-prio-v2` (D3);
- it removes no attack-path edge (ADR 0011 D10; D3);
- a snapshot is **not complete** (D4) for any path or check that touches
  it, so it never resolves a `mgmt-from-untrusted`, `shadowed-rule` or
  other advisor finding.

**Required tests (NS-05).** One test at least per item, with fixtures the
consuming tickets (NS-07, NS-08, NS-10, NS-16) reuse:

1. Fail-safe: a deny rule with `rule-type` intrazone, with a
   `source-hip`/`destination-hip`, with a `<dropped:…>` marker, with
   another field outside the allowlist, and a snapshot without negation
   flags or default rules each give `unknown` (never `denied` or
   `allowed`), no mitigation, no removed attack-path edge, and leave an
   existing `mgmt-from-untrusted` and `shadowed-rule` finding open. The
   same for a NAT rule with a `<dropped:…>` marker (for example a dropped
   translated-address sub-element) or a field outside the allowlist
   (for example `disabled`): the NAT step is `unknown`, and a query to a
   host's internal address that is otherwise `denied` gives `unknown`
   through the reverse-NAT lookup, never `denied`.
2. Mitigation voiding: a policy version that differs only in `raw_digest`
   voids the record with "mitigation unknown: policy changed outside
   collected elements"; a `redacted_digest` change voids it too.
3. Host addresses: a host with two addresses (IPv4 and global IPv6, or two
   NICs) of which one is `denied` and one `allowed` from `internet` is not
   mitigated and keeps expo 1.0; mitigated only when every address is
   `denied`.
4. Incomplete hours: a reputation hit whose only evidence is denied keys
   from an `incomplete` hour is marked "allowed traffic unknown
   (incomplete hour)", is not counted as denied-only and notifies.

### D3: Exposure-aware vulnerability priority (B)

The reachability model feeds ADR 0011 as a **compensating-control signal**.
It changes priority only; it never changes a finding's state.

**Mitigation record per finding.** For each open finding whose affected
service is mapped to a listening port (ADR 0011 D10 mapping; unmapped →
no mitigation, flagged "port unknown"), NOS queries the model from every
entry class and every zone, plus the finding host's own segment, with the
D2 reverse-NAT lookup (a port forward to the host makes the source
`allowed`, never `denied`, and is never counted as mitigated), and stores
the results below. The destination is **every address of the finding
host**: every IPv4 address and every global IPv6 address on every NIC
(ADR 0009 `net.facts`, IPAM). A source counts as `denied` only if the
verdict is `denied` for every one of these addresses; otherwise the most
reachable verdict over the addresses applies (D2 order). If the host's
address set is not known from fresh data, the record is not valid
("mitigation unknown: host addresses unknown") (previously: "the finding
host" without saying which addresses).

- per source and address: verdict, deciding rule (name and UUID), NAT
  rule, chain hash;
- the snapshot hash, the policy version's `redacted_digest` and
  `raw_digest`, model version and computation time;
- a summary: "mitigated by rule X from zones Y; still reachable from Z".

**Formula `vu-prio-v2`.** Identical to `vu-prio-v1` (ADR 0011 D7) except
for the exposure term, which the reachability model now determines when a
valid mitigation record exists:

```
reachable(s) = verdict(s) ∈ {allowed, conditional, not_filtered, unknown}
expo = 1.0  if reachable(internet)
       0.7  else if reachable(netbird)
       0.4  else (listening service reachable from any zone or from the
            host's own segment, or from no source at all)
       0.2  no listening service (unchanged)
```

**`not_filtered` is never a compensating control.** It means the firewall
is not on the path, so nothing filters the traffic. In the flat lab network
the host's own segment holds guest and IoT devices, so reachability from
the own segment is internal reachability and keeps the v1 level 0.4; there
is no level below 0.4 for a listening service.

**Own segment (Q7, decided 2026-11-11).** "Reachable only from the own
segment" counts as **no mitigation** while that segment contains a zone
of trust class `untrusted` or `unknown` (D4; unknown counts as
untrusted, Q9), which in the flat lab network is always the case. There
is **no 0.3 level** in `vu-prio-v2` (previously, in the first draft,
1.0/0.7/0.4/0.3/0.2 with 0.3 for "own segment only"): such a service
keeps 0.4. Introducing a level below 0.4 for a segmented network would
be a new formula version and a new decision. `vu-prio-v2` can therefore
only lower exposure from 1.0 or 0.7 to 0.4 through `denied` verdicts on the
internet and NetBird paths, never below what v1 gives an internal-only
service. A `not_filtered` source never appears as "mitigated" in the
summary; it is listed as "not filtered (firewall not on path)".

All other terms, the tier thresholds and the **KEV floor (never below
high)** are unchanged. Weights are named constants; the record names the
formula version. `vu-prio-v2` is accepted (Q7); `vu-prio-v1` values stay
stored for comparison and the UI shows v1 beside v2 until the maintainer
retires v1.

**Fail closed.** The mitigation record is valid only while all of these
hold; otherwise the finding uses its `vu-prio-v1` exposure (unmitigated)
and shows "mitigation unknown: <reason>":

- every input dataset of the snapshot is fresh (not stale, not
  `incomplete`);
- the policy version and every referenced object are unchanged since the
  computation (**a rule or object change voids every mitigation at once**,
  before recomputation). A change of the `redacted_digest` **or** of the
  `raw_digest` voids; a change of the `raw_digest` alone means a change in
  elements NOS does not collect and gives "mitigation unknown: policy
  changed outside collected elements" (previously: only the
  `redacted_digest`; the snapshot hash still excludes `raw_digest`, D2);
- no verdict on a path that the record counts as mitigating is `unknown`
  (which includes every path through an unevaluable rule or an
  uncollected default rule, D2 "Unevaluable rules (fail-safe)");
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
edge, and only from fresh inputs (a `denied` cannot pass an unevaluable
rule or an uncollected default rule, D2 "Unevaluable rules (fail-safe)";
previously: a `denied` from a snapshot without the Q11 elements kept the
edge flagged "assumed"); `unknown` → edge flagged "assumed" (fail
closed). Choke-point
candidates "one edge removed by a rule change" are what-if results (D4).
`ap-v1` stays; using the model as edge source is a data-source change,
recorded with the graph snapshot hash.

### D4: Rule and segmentation advisor (C)

**Advisor findings** are a separate store from ADR 0011 findings (different
kind, not subject to ADR 0011 D5). NOS computes them deterministically from
a snapshot, so NOS also resolves them: a check that no longer fires on a
fresh complete snapshot marks its finding `resolved`. A snapshot is
**complete** for a check only when every input is fresh and not
`incomplete`, no rule or default rule the check touches is unevaluable
(D2 "Unevaluable rules (fail-safe)"), and every element the check needs
is present (for example profile names for `allow-without-profile`); a
verdict the check relies on that is `unknown` does not count (previously:
"complete" was not defined). A check that cannot be evaluated, answers "cannot decide"
or "data not collected", or runs on a snapshot that is not complete for
it **never resolves an existing finding**: the finding stays as it was
and shows "not evaluated since …". The admin
may `acknowledge` a finding with reason and expiry (default 90 days,
maximum 365, Q9 decided 2026-11-11), bound to the check ID and version, the rule UUID and a
**rule-scoped digest** (not the policy-wide `redacted_digest`, which
changes with every unrelated edit). The rule-scoped digest is computed
over the canonical redacted encoding of exactly what the check's evidence
depends on:

- the rule itself (all matched fields, action, `disabled`, profile and
  log setting names) and its position relative to the other rules in the
  digest;
- every address, service and application object and group the rule
  references, expanded transitively, and the zones it names;
- for `shadowed-rule` and `overlap`, the same for every covering rule;
- for checks without a single rule (`dns-bypass`, `mgmt-from-untrusted`,
  `model-contradiction`), the deciding rules of the verdict chain, the
  zone trust classes and management targets or the designated resolver
  (the firewall, Q9) involved.

A change to any of these, a new check version or the expiry re-opens the
acknowledgement; a change elsewhere in the policy does not. Every finding
names its check ID and check version (`na-v1`), the snapshot hash and the
evidence.

**Checks (`na-v1`).**

| Check | Fires when | Evidence shown |
| --- | --- | --- |
| `shadowed-rule` | An enabled rule can never match because earlier rules together cover its full match space (zones, addresses incl. negation, service, application, user, schedule). Partial overlap is a separate, lower `overlap` hint. Objects that cannot be evaluated, or an unevaluable shadowed or covering rule (D2 fail-safe) → "cannot decide": no new finding, and an existing finding is never resolved by it (stays, "not evaluated since …") | Covering rule(s), the shadowed rule, why |
| `any-any` | An allow rule with source **and** destination address `any`, or source **or** destination zone `any`, or service and application both `any` | Rule, which fields are `any` |
| `allow-without-profile` | An allow rule toward or from a zone of trust class `untrusted` or `guest` with no security profile or profile group (needs NS-04) | Rule, zones |
| `zero-hits` | Enabled rule with zero hits since the later of rule creation and counter reset, with **≥ 30 days observed**; the reset time and observed window are shown (same rule as ADR 0010 ND-20); never a delete proposal | Hit count, first/last hit, reset time, window |
| `dns-bypass` | Observed DNS (udp/tcp 53, tcp 853) from internal endpoints to destinations other than the designated resolver, which is **the firewall only** (its interface addresses from ND-16; Q9, previously operator-set DNS proxy or internal resolver addresses), from flows or log aggregates, or an allow rule that permits DNS from an internal zone to an external zone without restricting the destination | Endpoints, destinations (aggregated), rule |
| `mgmt-from-untrusted` | Reachability (`allowed`, `conditional`, `not_filtered`, `unknown`) from a zone of trust class `untrusted`, `guest` or `iot`, or from `internet`/`netbird`, to a management target on its management ports | Source zone, target, port, verdict chain |
| `model-contradiction` | Observed allowed traffic where the model says `denied` (D3) | Flow, rule chain |

**Zone trust classes and management targets** are operator data in NOS:
each zone gets one of `untrusted`, `guest`, `iot`, `internal`,
`management` (default `unknown`, which counts as `untrusted` for the
checks above and for D3, Q9 decided 2026-11-11); management targets default to the ADR 0010 devices, PVE
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
  aggregates, Q2) would be **broken**, with endpoints and
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
| Credential | None in NOS | Separate read-only log role and key in the executor (Q1; log query permission *verify* in NS-03) |
| Completeness | Near real time; drops under load (UDP) are silent | Pull by time window; per-query cap (`nlogs`, *verify*: max 5,000) and async job; an hour over the cap is marked `incomplete`, never silently partial |
| Load on device | Firewall pushes, low cost | Queries on a weak CPU; one request per device at a time (ADR 0010 D4) |
| Where data is first minimised | Receiver (new code outside the executor) | Executor, before anything leaves it (same place as redaction) |
| Fits existing model | New role, new systemd unit, new spool | New typed read methods under the device read lease |

**Decision (Q1, 2026-11-11): XML API log query through the executor**,
hourly, for `traffic` and `threat` logs, read-only (previously the
recommendation). It adds no listener, inherits pinning, leases, budgets
and the collector spool, and minimises in the executor. **No syslog
receiver** is built. The log queries use a **separate read-only PAN-OS
admin role and API key for logs**, not the phase-1 config read role of
ADR 0010; that key is held by the executor like the other device
credentials (ADR 0010 D2) and is used only by the two log methods below
(previously: the phase-1 read role with log permission, or a second key
if needed). If NS-03 shows the cap cannot cover a lab hour, the next
option is a firewall-side aggregate (PAN-OS custom report via the API,
*verify*) through the same read path; any syslog receiver would need a
new decision and ADR amendment.

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
external addresses reveal who talks to whom). Decided in Q2 on
2026-11-11 (previously proposed defaults):

- hourly aggregates **30 days**, pruned hourly (longer than ADR 0009's 21
  days; ADR 0009 D3 says a longer retention for flows needs a new decision,
  and Q2 is that decision for this separate dataset only);
- **external addresses without a reputation hit** are kept in full for
  **7 days** (allows matching against a feed that lists them later), then
  reduced to their /24 (IPv4) or /48 (IPv6) prefix inside the aggregate;
- reputation hits (D6) keep the full external address for **90 days** as a
  security record. The **internal side of a hit** (internal endpoints,
  per-endpoint sessions and bytes) is stored as references to the
  aggregates and flows and follows **their** retention (30 days for log
  aggregates, 21 days for traffic-map flows), not the 90 days. After the
  source is pruned the hit keeps, until day 90, only the external address,
  feed IDs and categories, first and last seen, direction, total sessions
  and bytes split by allowed vs denied, and the **number** of internal
  endpoints involved; no internal address, endpoint ID or label (the
  proposed split, accepted with Q2);
- admin-only pages, no export, no read-only API scope; log aggregates are
  **excluded** from the age-encrypted instance backup (Q2);
- **the same rules cover evidence derived from logs or flows** in other
  stores (advisor findings, D4; reputation hits, D6): such evidence is
  stored as a reference to the aggregate, flow or endpoint, not as a copy,
  so pruning and prefix reduction of the source apply to what the finding
  shows; where a finding must keep a value (for example a resolved
  finding's last evidence), it keeps it no longer and no more precisely
  than the source would. **No export contains log- or flow-derived
  evidence** (D8);
- the operator guide states what is collected and that the operator is
  responsible for informing household members and guests.

### D6: IP reputation (D)

**Feeds are fetched by the vulnerability agent host only** (ADR 0011
amendment 1, A1.5 egress; D4 feed rules: origin allowlist, verified TLS,
no cross-origin redirects, size and decompression limits, content dates,
maximum snapshot age, plausibility gate, bulk downloads only). The NOS
server never fetches feeds and gains no egress. Feeds (Q3, decided
2026-11-11; previously candidate feeds): the four keyless feeds below
are on by default; **no API keys** are used.

| Feed | Kind | Key | Note |
| --- | --- | --- | --- |
| abuse.ch Feodo Tracker IP blocklist | botnet C2 | none | default; *verify* format, update interval, terms |
| abuse.ch SSLBL IP blacklist | botnet C2 | none | default; *verify* the list is still published |
| Spamhaus DROP (and EDROP) | hijacked/criminal netblocks | none | default; *verify* whether EDROP is still separate or merged into DROP; terms of use |
| FireHOL level1 | aggregate | none | default; contains bogon and private ranges; those are removed on ingest (below) |

AbuseIPDB and CrowdSec (keyed bulk lists; previously optional rows in
this table) come **later**: not in this ADR's tickets; adding them needs
a new decision on keys on the agent host.

**No per-address lookups.** No component sends an observed address to any
provider (no AbuseIPDB "check", no CrowdSec CTI per IP). This keeps the
ADR 0011 rule "bulk downloads only, no inventory sent out" and keeps
personal data inside NOS.

**Upload to NOS.** The agent normalises each feed to a **reputation
snapshot**: feed ID (from a fixed NOS-side list, as ADR 0011 D5 source
IDs), content date, entry count, entries `(CIDR, category)`. It uploads it
through a new API scope `netsec.reputation.write` on `/api/v1`. The
**existing vulnerability agent identity** gets this scope **in addition**
to its `vuln.*` scopes; **no new token** is issued (Q3; previously a
separate token or the added scope). The agent **never** gains a read
scope for flows, logs, endpoints or findings.

**Validation in NOS (fail closed per feed).** Every snapshot is untrusted:

- CIDR syntax, IPv4/IPv6 only; entries in private, loopback, link-local,
  CGNAT, multicast, documentation, reserved or unspecified ranges, or
  overlapping any IPAM network or the NOS path, are **dropped** and counted;
- prefixes shorter than a named minimum (**/16 IPv4, /32 IPv6**, accepted
  with Q3; previously /8 and /24) are dropped and counted, and the dropped entries
  are listed for the admin. Why: the minimum bounds the damage one
  poisoned or erroneous entry can do. A /8 would mark 16.7 million
  addresses, enough to turn ordinary traffic to a large provider into mass
  false hits and notifications; a /16 limits one entry to 65,536
  addresses, and /32 is the usual allocation to a single IPv6 network
  operator. Botnet C2 lists are single addresses; netblock lists
  (Spamhaus DROP) may contain shorter legitimate entries, so NS-03 checks
  the shortest prefix in each candidate feed (*verify*), and a per-feed
  value shorter than the default is a separate maintainer decision after
  NS-03 (not taken with Q3), never set by the feed;
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

**Hits from `incomplete` hours.** Over the D5 key cap only the top keys by
sessions are kept, so an allowed low-volume key can be missing. A hit whose
evidence includes a log hour marked `incomplete` is marked **"allowed
traffic unknown (incomplete hour)"**: it never counts as denied-only, and
it notifies as `netsec.reputation_allowed` with that marker (previously:
such a hit could appear denied-only and not notify).

**Notifications.** Event `netsec.reputation_allowed`: traffic with action
allow (or an observed flow, which implies allow) to or from a listed
address, or a hit marked "allowed traffic unknown (incomplete hour)".
Dedupe per `(external address, internal endpoint, feed)` episode;
the ADR 0011 D9 rate limit and hourly digest apply (10 per hour). Messages
to webhook, ntfy and Telegram carry **structured fields only** (feed,
category, internal endpoint label, direction, allowed sessions) and
**never the external address**; the address is shown only inside NOS
(Q8, decided 2026-11-11; previously: omitted unless the operator enabled
it). The internal endpoint label in third-party channels is the label of
a managed host or IPAM asset only, otherwise "internal endpoint in zone
X"; observed device names (which can name a person) are not sent (Q8).
Denied-only hits do not notify (Q8); they appear in a daily count. Event
`netsec.feed_stale` per feed and episode.

**Threat log notifications (Q8).** Event `netsec.threat_critical`: a
threat log aggregate (D5) with action `allow` or `alert` and severity
`critical`. Same rules as above: structured fields only (threat ID,
threat name as escaped vendor text, severity, action, direction,
internal endpoint label per the label rule), never the external address;
dedupe per `(threat ID, internal endpoint, external address)` episode;
the ADR 0011 D9 rate limit and hourly digest apply.

### D7: EDL export (E)

**Allowed by Q4 (2026-11-11), optional and off by default**, with
**manually operator-approved entries only** (previously: built only if
Q4 explicitly allowed a firewall-enforced effect outside the ADR 0010
permit path). NOS can publish one or more curated
**External Dynamic Lists** (IP lists) that the firewall pulls on its own
schedule; the operator references them in deny rules they write. NOS gains
no write access to the firewall.

- **Endpoint.** `GET /edl/<list-id>.txt` on `nebula-server` over HTTPS,
  plain text, one IPv4/IPv6 address or CIDR per line, ASCII only,
  `Content-Type: text/plain; charset=us-ascii`, `Cache-Control: no-store`,
  `X-Content-Type-Options: nosniff`, no cookies, no session, not reachable
  through the web UI session.
- **Authentication.** HTTP basic credentials generated by NOS (random, at
  least 32 bytes, shown once, stored as a hash, rotatable) or mTLS with a
  client certificate on the firewall, whichever PAN-OS supports for EDL
  pulls (*verify* in NS-03; accepted with Q4). **No token in the URL** (URLs end up in logs).
  **Required** source-address allowlist set to the firewall's registered
  address (ADR 0010 D1); a pull from any other address is refused before
  the credential is checked and audited (previously optional).
- **Content only from manually approved entries.** An entry is added by an
  admin with the ADR 0011 Q4 assertion rule (fresh WebAuthn assertion),
  reason and optional expiry; removal is audited. The admin may start an
  add from a reputation hit (the form is prefilled), but every entry needs
  its own add with assertion. **No automatic adds from feeds.** Feed data
  is untrusted (D6); a list fed from it and referenced in a deny rule would
  be an auto-block, which this ADR excludes (non-goals). **No automatic
  rule sets from feeds** (Q4; previously left open as Q4b).
- **Refusals (checked on every add and every publish).** Entries
  overlapping private, reserved and special ranges, any IPAM network, the
  NOS path, the firewall's own addresses, configured protected destinations
  (DNS upstreams, update mirrors, the feed origins, NetBird management,
  operator-listed) are refused; a list over its size cap (named constant,
  default 10,000 entries, below the model's EDL capacity, *verify*;
  accepted with Q4) is not
  published and the previous version stays.
- **Audit.** Every add, removal, publish (version number,
  entry count, digest) and every pull (time, source address, result) is
  audited. The UI shows when the firewall last pulled.

**Stated risk.** The EDL is an effect on the firewall that does not pass
the ADR 0010 permit path or its phase-2a write gate; the maintainer
accepted it with the bounds below (Q4). A compromised server could serve a list that
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
  `nebula-server` as pure packages plus thin jobs (Q5, decided
  2026-11-11; previously recommended). It needs no internet egress. The
  agent host would need topology and flows, which ADR 0011 Q6 withholds.
- **UI (Q6, decided 2026-11-11).** One admin page **"Network security"**
  gives the overview and links into the existing views: the firewall view
  (ADR 0010 ND-20) for rule findings and what-if, the traffic-map overlay
  (ADR 0009 TM18 renderer) for reachability and reputation hits, and the
  vulnerability page (ADR 0011 VU-11) for mitigation.
- All pages are **admin-only** (as the ADR 0010 firewall view and ADR 0011
  attack paths); nothing is in the read-only API; exports of advisor
  findings are admin-only, audited, CSV-injection-safe (ADR 0011 D9), and
  carry only policy-derived evidence (check ID and version, rule names and
  UUIDs, zones, verdicts, snapshot hash) plus **counts** for log- or
  flow-derived evidence. Endpoint addresses and labels, destinations and
  flows from log aggregates or the traffic map (`dns-bypass`,
  `model-contradiction`, segmentation proposals, what-if broken flows,
  reputation hits) are never exported (D5 "no export"; unchanged by Q2).
  Allowing a redacted export of such evidence would need a new decision.
- Every job has a named wall-clock budget and output caps; truncation is
  stated, never silent.
- UI rendering follows ADR 0009 D4 isolation for any map overlay and the
  existing strict CSP; all device, log and feed text is escaped text.

## Non-goals

- No device change of any kind, no auto-block, no automatic rule, object,
  EDL or NAT change; the EDL (allowed by Q4) contains only entries an
  admin added one by one with assertion. No automatic EDL rule sets from
  feeds (Q4; previously open as Q4b).
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
| Spoofed or flooded logs | API pull over pinned TLS with a separate read-only log key (Q1); no syslog receiver; per-hour key caps with `incomplete` marking |
| Poisoned reputation feed (false hits, hidden hits, internal ranges) | Feed rules of ADR 0011 D4 on the agent host; NOS-side validation (special/internal ranges dropped, prefix minimum, caps, high-water marks, plausibility hold); hits are advisory; no feed data reaches the EDL (manual entries only, D7) |
| Leak of observed addresses to third parties | No per-address lookups; agent has no read scope for flows, logs or endpoints; notifications never carry external addresses and omit personal endpoint labels (Q8) |
| Compromised agent token | Can upload false snapshots within caps and validation: false or hidden reputation hits and notifications (misleading the operator, who may then add or skip EDL entries by hand); cannot read anything; separate scope on the existing agent identity (Q3), rotatable, source-bound; no feed data reaches the EDL (no feed-driven rule sets, Q4) |
| EDL abused to block or unblock | Off by default, manual entries with assertion, refusals, caps, audit, operator guide limits EDL to WAN deny rules; residual stated in D7 |
| EDL credential leak | Basic credential hashed in NOS, rotatable, source allowlist; mTLS if supported; the list content is low sensitivity but reveals what the operator blocks |
| Personal data in logs | Minimisation in the executor, aggregates only, short retention, prefix reduction, admin-only, no export (also not inside advisor finding exports: counts only), derived evidence follows the source's retention, excluded from the instance backup (Q2) |
| Advisor as a map for an attacker | Admin-only, not in the read-only API, exports audited |

`docs/threat-model.md` is protected and receives these items in NS-02.

## Consequences

- NOS can explain reachability, including "not filtered" in the flat lab
  network, and turns firewall rules into explainable risk reduction in
  vulnerability priority without weakening any ADR 0011 rule.
- The executor gains two typed log read methods, a separate read-only
  PAN-OS log key (Q1) and more XML parsing of hostile input (bounded,
  fuzzed, minimised at the source).
- The agent host gains reputation feed origins in its egress allowlist and
  its existing identity an added upload scope (Q3); the server gains a new
  API scope, stores for log aggregates, reputation snapshots, hits and
  advisor findings, and the EDL endpoint (off by default, Q4).
- If Q11 allows it, the ND-07 PAN-OS redaction allowlist grows by a few
  non-secret elements (protected change to an accepted ADR, reviewed);
  otherwise the checks that need them stay "data not collected".
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
  `netsec.reputation_allowed`, `netsec.threat_critical` (Q8),
  `netsec.feed_stale`.
- `docs/spec/01-product.md`, `16-milestones.md`, `04-revision-history.md`;
  `docs/threat-model.md`.

Tickets: [docs/implementation/network-security.md](../implementation/network-security.md).

## Decisions 2026-11-11

The maintainer (Axel) accepted every recommendation of this ADR on
2026-11-11 at 09:18. The questions Q1–Q10 below were open in the
Proposed draft (previously the section "Open questions for the
maintainer"); each answer is recorded as decided and carried into the
D-section named.

| # | Question | Decision | Where |
| --- | --- | --- | --- |
| Q1 | Log source; log permission on the phase-1 read role or a second key | **XML API log query through the executor**, read-only. A **separate PAN-OS read role and key for logs**, not the phase-1 config read role. **No syslog receiver.** | D1, D5 |
| Q2 | Retention, internal side of hits, backup | Log aggregates **30 days**. Full external addresses **7 days**, then truncated to **/24 (IPv4)** and **/48 (IPv6)**. Reputation hits **90 days**; the internal side follows the source retention as proposed. Log aggregates **excluded** from the instance backup. | D5 |
| Q3 | Feeds, keys, token, prefix minimum | **Feodo, SSLBL, Spamhaus DROP/EDROP, FireHOL level1** on by default, **no API keys**; AbuseIPDB and CrowdSec **later**. The **existing vulnerability agent identity** gets the **additional scope `netsec.reputation.write`**; no new token. Minimum prefix /16 IPv4, /32 IPv6 as proposed. | D1, D6 |
| Q4 | Firewall-enforced effect outside the ADR 0010 permit path (EDL) | **Yes** (option b), **manual operator-approved entries only**. **No automatic rule sets from feeds** (Q4b and the rule-set text removed). Authentication and size cap as drafted in D7. | Context, D7, Non-goals |
| Q5 | Where the advisor runs | On the **NOS server**; no internet egress needed. | D8 |
| Q6 | UI placement | One **"Network security"** overview page that links into the firewall view (rule findings, what-if), the traffic-map overlay (reachability, hits) and the vulnerability page (mitigation). | D8 |
| Q7 | Priority formula | **`vu-prio-v2` accepted**; v1 shown beside v2 until retired. "Reachable only from own segment" counts as **no mitigation** while that segment contains untrusted or unknown zones (flat network); no 0.3 level, such a service keeps 0.4. | D3 |
| Q8 | Notifications | **No external address** in webhook, ntfy or Telegram text: structured fields only, the address only inside NOS. Internal endpoint label and denied-only handling as proposed. **Notify on threat logs with action allow/alert at severity critical** (`netsec.threat_critical`). | D6 |
| Q9 | Zone trust classes, DNS resolvers, acknowledgements | **Unknown zones count as untrusted.** Designated DNS resolver = **the firewall only**. Acknowledgement default 90 days, maximum 365 as proposed. | D3, D4 |
| Q10 | Release placement | **After ADR 0010 phase 1 (ND-16, ND-20)**; the reputation part **after the vulnerability agent (va01–va08)**. | Ticket plan |

Points the questions raised but the decision does not answer, kept open
(no recommendation in the draft, so nothing to accept):

- **Earlier minimisation of internal addresses** in log aggregates (Q2):
  not decided; internal addresses are kept for the 30-day aggregate
  retention until a later decision.
- **Shorter per-feed prefix minimum** (Q3, for example Spamhaus DROP):
  needs a separate decision after NS-03.

## Follow-up items (not phase 1)

- **NetBird VPS auth-failure logs as an additional source (open).** The
  IONOS VPS that hosts NetBird runs Fail2Ban and Caddy; their
  authentication-failure logs could serve as an optional, operator-provided
  reputation and attack source. They would be read through the host's
  normal NOS read path once the VPS is enrolled as a managed host, never
  through a new listener or the feed path, and would be untrusted input
  like every host output. Not part of any ticket in this ADR; it needs its
  own decision on data, retention and matching.

## Open questions for the maintainer

- **Q11: ND-07 redaction allowlist additions.** May the allowlist of the
  accepted ADR 0010 (ND-07, protected `internal/netdevredact/`) grow by
  the D2 elements (`rulebase/default-security-rules`, `negate-source`,
  `negate-destination`, `rule-type`, `source-hip`, `destination-hip`,
  `schedule`, `profile-setting` names, `log-setting` name, zone
  protection profile name), through NS-04 with the fail-closed keyword
  rule unchanged? Does that need an amendment note in ADR 0010 itself?
  Without them, `allow-without-profile` stays "data not collected" and
  every rule is unevaluable, so no verdict is `denied` or `allowed` and
  nothing counts as mitigating (D2 fail-safe, D3). Not answered on
  2026-11-11.
