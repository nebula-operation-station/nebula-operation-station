# Network devices plan (ADR 0010)

Status: **ND-01 done; ADR 0010 Accepted 2026-11-09** (previously: plan,
not started, 2026-11-08, ADR 0010 Proposed with Q1 to Q13 open). The
maintainer's answers are recorded in ADR 0010, "Decisions 2026-11-09"; this
plan points to them. ND-03 (lab verification) checks the lab facts of those
answers and every *verify*, and feeds corrections back into the ADR. ND-04
to ND-09 are pure libraries in new packages and may start now that the ADR
is accepted, before the spec revision ND-02 is merged, as in ADR 0009.
Phase 2a waits for the phase-2 decision after phase 1 has run (Q3); phase
2b (ND-40) is not planned (Q6, most restrictive fallback, maintainer may revisit).

It turns [ADR 0010](../adr/0010-network-devices.md) into PR-sized steps, in
the style of [container-updates.md](container-updates.md).

## What the ADR asks for

The numbers N1 to N14 are used by the tickets. The source is ADR 0010.

| # | Rule | ADR section |
| --- | --- | --- |
| N1 | A device is not a managed host; immutable `device_id`, executor-owned endpoints, pins, credential refs, port roles and approved baseline | D1 |
| N2 | CBS: SSH via `x/crypto/ssh` from the executor, pinned host key, spec 08 algorithm policy, no exception without a decision; CBS220 unsupported | D1, D3 |
| N3 | PAN-OS: XML API over HTTPS with pinned leaf or CA, pvetransport rules (no redirects, no proxies, SAN), internal management address only; endpoints stored and dialled as IP literals, re-checked (no public/loopback/link-local/multicast/unspecified) at every dial | D1, D3 |
| N4 | Device credentials are a new vault class: executor only, local CLI entry, read and change credentials separate, API key in `X-PAN-KEY` only | D2 |
| N5 | Every vendor claim marked *verify* is checked in the lab before code depends on it | Context, ND-03 |
| N6 | Phase 1 reads are LOW under a device read lease (ADR 0007 provider profile), collector without credentials, spool to server | D4 |
| N7 | Raw config and any unkeyed digest of it never leave the executor; `raw_digest` and value fingerprints are HMAC-SHA-256 under per-device executor-held keys, no digest oracle; PAN-OS output through an element allowlist, CBS through an allowlist of command keywords built from the ND-03 vocabulary (Q13, decided 2026-11-09; previously: a reviewed keyword list with the limit stated, Q13 open), both plus a fail-closed keyword rule; unparseable or over-limit configs are not stored; no unredacted backups (Q8) | D4 |
| N8 | Config versions by `raw_digest` over the normalized config (volatile lines dropped by a reviewed list), redacted diffs, executor-held approved baseline, retention 400 days / 1,000 versions (Q11, decided 2026-11-09 as proposed) | D4 |
| N8b | Named parse limits (line length, config lines, interfaces, VLANs, MAC, LLDP, rules, NAT rules, objects, groups, members, nesting, XML depth/elements/text); over-limit lists are `incomplete`, over-limit configs refused | D3 |
| N9 | MAC, LLDP and VLAN data feed IPAM and the ADR 0009 traffic map as source-labelled hints, never assets, placements or roles | D4 |
| N10 | Changes are typed operations only; the permit binds device, pin, credential version, exact rendered change, pre-change digest/version, inverse change, risk, expiry | D5 |
| N11 | Risk = max(operation base, port role floor, device criticality, NOS path rule); flat lab network (Q4, decided 2026-11-09): until an ADR amendment records a management VLAN, every port, VLAN and uplink change on a switch that carries the NOS path (or whose path data is stale, incomplete or missing) is CRITICAL, and every firewall rule overlapping `<lab-net>` or `any` overlaps the NOS path; CRITICAL refused for good (Q6); executor-owned port roles with floors independent of MAC age (`nos-path` CRITICAL, `management`/`uplink`/`unknown` HIGH), lowering a role approved at the old floor; device criticality default HIGH for firewalls; unknown = uplink; stale or incomplete path data = CRITICAL; object edits evaluated through every referencing rule (nested and dynamic groups), CRITICAL on NOS-path overlap; CRITICAL refused in phase 2a; a rollback is a change: risk = max(original effective risk, risk re-derived at rollback time), every inverse is a typed operation in the D5 table (rule/object delete only as the inverse of an add) | D5 |
| N12 | CBS: running config only, persist to startup is a separate MEDIUM approval; PAN-OS: locks, precheck repeated under the locks, validate, partial commit, job ID stored durably, revert on failure only while the config lock is held; every rollback has a stated precondition (post-change digest/version match; CBS reload only with running == startup) | D6 |
| N13 | Uncertain changes become `unknown` and block the device; reconciliation by read only; nothing re-sent | D6 |
| N14 | No unattended or scheduled writes, no generic CLI/xpath, the out-of-scope list of D5 | D5, Non-goals |

## Current state and reuse

| What | Where | Use |
| --- | --- | --- |
| Asset kinds `switch` and `firewall`, `Network.VLAN`, `NormalizeMAC` | `internal/ipam/ipam.go` | Device ↔ asset link, VLAN comparison (ND-18) |
| Discovery import | `internal/discovery/` | Suggest device registration only, never dial targets |
| Observed endpoints, guest NIC bridge/VLAN | `internal/trafficstore/{endpoints,guestnics}.go`, `internal/trafficingest/` | MAC → port/VLAN, LLDP port mapping (ND-18) |
| `bridge -j vlan`, neighbor parsers | `internal/netfacts/` | Host-side VLAN data to compare with switch data |
| Pinned HTTPS client (leaf/CA pin, redirect and proxy refusal) | `internal/pvetransport/` | PAN-OS transport (ND-08); generalize or reuse, no copy of the pin logic |
| Pinned SSH, host-key type policy | `internal/sshtransport/` **P** | CBS session driver builds on it (ND-05) |
| Text diff | `internal/textdiff/` | Config version diffs (ND-17) |
| Read leases, provider profile | `internal/schedgrant/`, `internal/permit/` **P** (ADR 0007 E08) | Device read profile (ND-13) |
| PVE collector, spool, importer | `cmd/nebula-pve-collector/`, `internal/pvecollect/` | Pattern for the device collector (ND-14) |
| `batch-v1`, durable intent, reconciliation | `internal/canonical/batch.go` **P**, `internal/executor/durable.go` **P** | Device change members (ND-30, ND-34) |
| Vault | `internal/vault/` **P** | Device credential class (ND-11) |
| Age-encrypted backups | `internal/backup/` | Server tables included; no raw device configs (Q8, decided 2026-11-09: redacted only; previously: only if Q8 says so) |

Gaps: no device registry, no device credential class, no CLI session
driver, no PAN-OS client, no redaction, no device read profile, no device
tables, no port roles, no device change contract.

## Tickets

Each row is one agent job: tests first, `make check`, no new dependencies,
no network access in tests (only loopback TLS/SSH servers and Unix sockets
in temporary directories, with recorded fixtures from ND-03). **P** = touches
a protected path and needs explicit maintainer authorization in that
ticket. Order is the column "After".

### Phase 0: decisions and lab facts

| Ticket | Scope / paths | P | After | Acceptance |
| --- | --- | --- | --- | --- |
| ND-01 | This plan, `docs/adr/0010-network-devices.md` | yes (ADR) | — | **Done 2026-11-09** (previously open): maintainer answered Q1–Q13, ADR accepted (ADR 0010, "Decisions 2026-11-09") |
| ND-02 | Spec revision: `docs/spec/{02,03,04,06,07,08,09,12,16,17}*.md`, `docs/threat-model.md`; `.github/protected-paths.txt` adds `internal/netdevredact/` and `internal/netdevchange/` (Q12, decided 2026-11-09: yes; previously: optionally) | yes | ND-01 (done), ND-03 | Every new authority, credential class, limit and table mapped, including the flat-network path rule (Q4) and "CRITICAL refused for good" (Q6); both packages in the protected-paths list; links resolve |
| ND-03 | Lab verification note `docs/implementation/network-devices-lab.md`; sanitized fixtures under `testdata/` of the parser packages (no secrets, redacted by hand and reviewed; no public names, real subnets, addresses, serial numbers or exact firmware/PAN-OS releases) | no | — (may run now; previously: while ND-01 was under review) | Each *verify* in ADR 0010 answered with device family, firmware train and document version (exact releases only in the private lab notes); ADR corrected first where a claim fails; the decided lab facts confirmed (ADR 0010 Decisions 2026-11-09): management address of the CBS250 switches (Q1), CBS SSH host-key and user-key types and `rsa-sha2-512` (Q1b), PAN-OS single vsys, no HA pair, no Panorama (Q2), firewall management internal only and not reachable from the WAN side (Q5); volatile lines/elements of repeated config reads recorded (two reads without a change give identical normalized text); CBS command vocabulary recorded for the Q13 keyword allowlist; lab counts compared with the D3 parse limits |

### Phase 1: read only

| Ticket | Scope / paths | P | After | Acceptance |
| --- | --- | --- | --- | --- |
| ND-04 | Device contracts and limits: new `internal/netdevcontract/{device,observation,limits}.go`, tests, fuzz | no | ND-01 | Malformed IDs, invalid UTF-8, oversize counts/text, unknown fields rejected; unavailable distinct from empty; every D3 parse limit is a named constant with a test at limit and limit+1 |
| ND-05 | CBS CLI session driver: new `internal/cbscli/{session,prompt}.go`, tests with a loopback `x/crypto/ssh` server | no (uses `internal/sshtransport` API unchanged) | ND-03, ND-04 | Command allowlist, `terminal datadump`, prompt detection, unexpected prompt aborts, byte/time caps, one session per device; pinned key mismatch and auth failure hard-stop |
| ND-05b | Only if Q1b needs it: algorithm change in `internal/sshtransport/` | yes | ND-02, ND-03 | Separate decision; default is "not needed, unsupported" (Q1b, decided 2026-11-09: no algorithm exception by default; ND-03 verifies the key types) |
| ND-06 | CBS parsers: new `internal/cbsparse/{version,vlan,interfaces,mactable,lldp}.go`, fixtures, fuzz | no | ND-03 | Lab fixtures parse; hostile names, oversize tables (D3 limits: MAC, VLANs, interfaces, LLDP per device and port, line length, config lines), malformed lines rejected or marked incomplete |
| ND-07 | Redaction: new `internal/netdevredact/{cbs,panos,fingerprint}.go`, tests, fuzz | yes once ND-02 has added it to the protected paths (Q12, decided 2026-11-09; previously: no, yes if Q12) | ND-03 | CBS: only lines whose command keyword is on the allowlist built from the ND-03 vocabulary pass, every other line is dropped with a marker (Q13, decided 2026-11-09); every listed CBS secret keyword redacted; PAN-OS: only allowlisted element paths and the `name`/`uuid` attributes pass, every other element (also unknown ones from a newer schema) is dropped with a `<dropped:…>` marker; fail-closed unknown rule flags `redacted:unknown`; crypto blocks dropped; unparseable or over-limit input refused; reviewed volatile-line normalization from ND-03 fixtures (two unchanged reads give one digest); `raw_digest` and fingerprints are HMAC-SHA-256 (`crypto/hmac`) under per-device keys passed in by the caller, differ per device and per field (field = full line identity, e.g. CBS keyword plus user name, so one password reused by two users gives two fingerprints), and no unkeyed digest of raw text is in any output; no API hashes caller-supplied text; no secret in any output or error |
| ND-08 | PAN-OS XML API client: new `internal/panapi/{client,request}.go`, tests with a loopback TLS server | no | ND-03, ND-04 | Pinned leaf/CA via pvetransport rules, `X-PAN-KEY` header only, POST bodies, fixed xpath templates with escaping, name validation, response caps, no redirect/proxy, error bodies never logged |
| ND-09 | PAN-OS parsers: new `internal/panapi/{config,rules,nat,objects,zones,hitcount,jobs}.go`, fixtures, fuzz | no | ND-08 | Rule order kept, groups resolved with depth limit, hit-count reset time kept, unknown elements dropped, XML depth/element/text limits and rule/object/group/member counts enforced (D3), oversize marked incomplete |
| ND-10 | Executor device registry: `internal/executordb/` migration and store, `internal/executor/netdev_registry.go` | yes | ND-02, ND-04 | Pins, trust generation, blocks, tombstones; endpoints stored as IP literals (names resolved once at registration, label only), public/loopback/link-local/multicast/unspecified refused at registration and at every dial, no DNS at dial time; duplicate trust identity refused; per-device digest and fingerprint keys generated with `crypto/rand` and kept in the vault; fail-closed DB errors |
| ND-11 | Local credential lifecycle: `cmd/nebula/netdev.go`, `internal/executor/netdev_admin.go`, reuse `internal/vault/` | yes | ND-10 | Probe before credentials, typed `yes`, non-echoing input, read/change credential separation, rotation/remove/repin revoke authority; secrets absent from replies, logs, events |
| ND-12 | RPC and collector role: `proto/` + `make generate`, `internal/peercred/`, `internal/executor/roles.go`, `internal/executorclient/` | yes | ND-10 | Collector UID gets typed device read methods only; no reveal, no generic command/xpath, no change methods |
| ND-13 | Device read-lease profile: `internal/schedgrant/`, `internal/permit/` | yes | ND-12 | Exact device/pin/credential version/methods, 7/30 days, 15-min floor, budgets, lock/repin/rotation pause or revoke; no change dispatch |
| ND-14 | Collector and spool: new `cmd/nebula-netdev-collector/` (separate binary, Q9, decided 2026-11-09; previously: or a PVE collector role), `internal/netdevcollect/{poll,spool}.go` | no | ND-12, ND-13 | Injected time, jitter/backoff, one request per device, atomic spool, symlink/oversize/replay rejection, no network/DB/secret access |
| ND-15 | Deployment: `deploy/systemd/nebula-netdev-collector.service`, `deploy/install.sh`, container compose | yes (systemd) | ND-14 | Own UID, no capabilities, no network, spool permissions; install tests |
| ND-16 | Server store and ingest: new `internal/netdevinventory/{store,ingest}.go`, server migration | no | ND-04, ND-14 | Atomic datasets, stale/partial handling, no silent deletion, retention per Q11 (decided 2026-11-09 as proposed: config versions 400 days / 1,000, MAC/LLDP 21 days, hit-count samples 90 days) |
| ND-17 | Config versions, diff, drift: `internal/netdevinventory/configs.go` (reuse `internal/textdiff`); baseline approval in `internal/executor/` | yes (executor part) | ND-07, ND-16 | New version only on new `raw_digest`, PAN-OS normalization, baseline is executor-held and audited, retention never prunes baseline or change-bound versions |
| ND-18 | IPAM and traffic-map integration: `internal/ipam/`, `internal/trafficstore/`, `internal/trafficingest/` | no | ND-16 | **Part 1 done** (`internal/ipam/netdev.go`, `internal/trafficingest/netdev.go`; previously: open as a whole): VLAN mismatch hints of ADR 0010 D4 (asset MAC on an edge port only in VLANs other than its IPAM network's, switch VLAN without an IPAM network, IPAM network VLAN on no switch); MAC → port endpoints with tier "switch" from dynamic entries on edge ports, one traffic-store lookup per distinct MAC, capped per call (`MaxSwitchEndpointLookups`, map marked partial when hit); asset/host links only from the existing confirmed traffic-store mapping, no new auto-linking; LLDP port mapping source-labelled; no assets/placements/roles created. **Open (follow-up ticket):** confirmed device ↔ asset link by explicit admin choice, MAC as suggestion only; netdevinventory read adapters (`MACTables`, `VLANTables`, `LLDPTables`) and callers in the UI |
| ND-19 | Device pages: new `internal/web/ui/netdev.go`, templates | no | ND-16, ND-17 | Escaped hostile text, admin-only config/firewall pages, staleness labels, deep links built from approved endpoints only (plain links with `rel="noopener noreferrer"`, never embedded or framed); the existing strict CSP applies unchanged: no inline script or style, no external origins, tests assert the header on every new page |
| ND-20 | Firewall view: rules, NAT, objects, hit counts, unused-rule hints in `internal/web/ui/`, templates | no | ND-09, ND-19 | Ordered rules, object usage, hint only with ≥30 days observed and reset time shown, no delete proposal, "changed in elements not displayed" shown for drift outside the allowlist; same strict CSP as ND-19 (no inline script or style, no external origins), asserted in tests |
| ND-21 | Security tests phase 1: `test/security/netdev_test.go` | yes | ND-11 to ND-20 | Compromised server/collector cannot read credentials or raw configs, cannot widen leases, cannot add dial targets; hostile device output rendered as text |
| ND-22 | Operator guide: `docs/operator/network-devices.md` | no | ND-21 | Creating `nos-read` on CBS and PAN-OS, admin role, key generation, pinning, rotation, redaction limits |

### Phase 2a: changes up to HIGH (only after Q3)

Q3 decided 2026-11-09 (previously open): phase 1 runs with read-only
credentials only; whether phase 2a starts at all is decided by the
maintainer after phase 1 has run in the lab. Until then no ticket below
starts and no change credential is provisioned.

| Ticket | Scope / paths | P | After | Acceptance |
| --- | --- | --- | --- | --- |
| ND-30 | Device change contract: `internal/canonical/` (device member type), `internal/permit/` | yes | ND-02, phase 1 | Binds device, pin, credential version, operation/adapter version, parameters, rendered change + digest, pre-change digest/version, inverse change + digest, risk, expiry; substitution and replay rejected |
| ND-31 | Port roles and risk floors: `internal/riskpolicy/`, `internal/executor/netdev_roles.go`, executor DB | yes | ND-30 | Risk = max(base, role floor, device criticality, path rule); role floors on every port operation regardless of MAC age (`nos-path` CRITICAL, `management`/`uplink`/`unknown` HIGH); raising a role MEDIUM, lowering it approved at the old role's floor, `nos-path` removed only via executor CLI; flat-network rule (ADR 0010 D5, Q4): on a switch that carries the NOS path (MAC/LLDP of the NOS machine, its gateway or any managed device in the last 24 h, or stale/incomplete/missing data) every port, VLAN and uplink operation, including port description and persist, is CRITICAL whatever the port role, the single lab VLAN counts as the management VLAN, and firewall rules overlapping `<lab-net>` or `any` count as NOS-path overlap; the rule is not switchable by the server or an executor setting; device criticality default HIGH for firewalls (unreferenced object edits HIGH by default) and MEDIUM for switches; unknown = uplink, NOS-path rule from MAC/LLDP, stale or incomplete data = CRITICAL, firewall path overlap = CRITICAL, disabling or deleting an allow rule on the NOS path and a deny/drop added, moved or enabled above a rule that allows NOS-path traffic = CRITICAL (a deny above an allow off the NOS path is not raised), object edits evaluated through every referencing rule (direct, nested groups, dynamic groups by tag, old and new value) with FQDN/EDL/unresolvable objects counted as overlapping, CRITICAL refused in 2a, never lowered by the server |
| ND-32 | CBS change adapter: new `internal/netdevchange/cbs.go`, executor dispatch | yes (executor) | ND-05, ND-30, ND-31 | Typed ops only, parameter charsets (no newline/control), interface names from device list, running only, post-change digest check, persist step separate and bound to verified digest, persist refused while running differs from the bound digest or a reload timer is pending |
| ND-33 | PAN-OS change adapter: new `internal/netdevchange/panos.go`, executor dispatch | yes (executor) | ND-08, ND-30, ND-31 | Foreign pending changes refuse, config and commit locks, full precheck repeated under the locks (foreign candidate change or changed version/digest after locking → locks released without revert, `not_applied`), candidate read-back, validate, partial commit, job ID stored before reporting, revert and unlock on failure |
| ND-34 | Rollback and reconciliation: `internal/executordb/`, `internal/executor/durable.go` | yes | ND-32, ND-33 | `success` / `not_applied` / `unknown` by read only; `unknown` blocks the device; bound inverse change under its own approval at max(original effective risk, risk re-derived by the ND-31 rules from current roles, criticality and fresh path data at rollback time), never lower than the original, CRITICAL refused in 2a; inverse is a typed operation from the D5 table (PAN-OS rule delete HIGH, object delete only while unreferenced, else refused); a change without such an inverse is refused at proposal; inverse applied only while the running digest (PAN-OS: and config version) equals the verified post-change state, refused otherwise; PAN-OS `revert` only while NOS holds the config lock taken before the under-lock re-check, else `unknown`; on `unknown` the locks are kept for one bounded reconciliation attempt (named limit) and then released without revert; "load version N" only under the same preconditions, refused otherwise; a failed or uncertain rollback is `unknown`; no `success` while a confirm window is open (CBS `show reload`, PAN-OS durable deadline), `rolled_back` after a device reload or applied inverse; nothing re-sent |
| ND-35 | Change UI: propose typed change, show redacted diff and inverse, approval through `batch-v1` | no (UI), RPC parts yes | ND-30 to ND-34 | Full plan view, risk shown, hardened CLI for HIGH, "running differs from startup" banner |
| ND-36 | Security and integration tests phase 2: `test/security/`, `test/integration/` | yes | ND-35 | CLI/XML injection, stale digest, foreign changes, lost response, CRITICAL refusal, no automatic retry |

### Phase 2b and later (each needs its own decision)

ND-40 is **not planned** (Q6, most restrictive fallback 2026-11-09, maintainer may revisit: CRITICAL changes are
refused for good; previously: planned after Q6). Its row stays as the record
of the option not taken, the starting point if the maintainer revisits Q6.

| Ticket | Scope | P | After | Acceptance |
| --- | --- | --- | --- | --- |
| ND-40 | **Not planned** (Q6, most restrictive fallback 2026-11-09, maintainer may revisit). Was: CRITICAL with CBS `reload in` and PAN-OS executor dead-man | yes | — (previously: Q6, phase 2a) | Not applicable. Previously: Spec exception recorded; CBS: refused unless one fresh read shows running == startup (keyed digests) and running == bound pre-change digest, timer confirmed pending and both configs re-read unchanged before any change line, startup digest re-read at least every 60 s in the window, no later than 60 s before the deadline and before `reload cancel` (changed → reload cancelled at once, `unknown`, notification); unconfirmed cancel → `unknown`; persist approval and rollback refused while a reload timer is pending; timer fired → `rolled_back` only if running equals the pre-change digest, else `unknown`; PAN-OS, **one lock rule** (ADR 0010 D6, "Lock rule for the dead-man"): the config and commit locks taken in step 2 are held without a gap for the whole window (step 7 does not release them for CRITICAL), the automatic inverse is sent only if at expiry `nos-change` still holds both locks (read from the device), running version and digest are still NOS's and no foreign candidate change is pending, otherwise nothing written, `unknown`, locks released without revert; the dead-man **never takes fresh locks**, also not after an executor restart (tests: lock removed in the window → no write, `unknown`; restart with locks still held → expiry check runs; restart with a lock gone → no write, no fresh lock request sent); fresh locks only for later admin-approved writes; deadline stored in the durable intent before the commit, executor restart in the window resumes the expiry check from it, confirmation after the deadline refused; vault locked in the window or at expiry → no write, `unknown` with "dead-man not executed", notification; no confirmation → device reload / bound inverse; confirm window bounded; **CRITICAL rollbacks** (risk re-derived per ND-34) get the same protection, tested separately: CBS rollback runs steps 1 to 5 and arms the reload only when running equals the verified post-change digest and startup equals running (CRITICAL rollback of a non-persisted change refused until persisted), unconfirmed → reload into the post-change state, rollback `rolled_back`, original change stays; PAN-OS rollback keeps the locks and the dead-man, unconfirmed → the rollback's bound inverse (the original change) applied under the dead-man preconditions; "load version N" never offered for a CRITICAL rollback |
| ND-50 | pfSense CE read path: read-only config backup over SSH; community REST API not acceptable (Q7, decided 2026-11-09; previously: pfSense read path, Q7 open) | depends | Future: when pfSense CE replaces the current firewall (previously: Q7) | Separate ADR amendment first |

## Order and release

ND-01 is done (ADR accepted 2026-11-09). ND-03 (lab) next, with its
corrections folded into the ADR → ND-02, then the libraries ND-04 to ND-09
in parallel, then the executor chain ND-10 → ND-11 → ND-12 → ND-13, then
ND-14 to ND-22. Per Q10 (decided 2026-11-09; previously: recommendation)
CBS comes before PAN-OS inside phase 1 (ND-05/06 before ND-08/09), because
switch data feeds IPAM and the traffic map. Phase 2a starts only after
phase 1 has run in the lab and the maintainer then decides to start it (Q3,
decided 2026-11-09; previously: "and Q3 is answered"). Phase 2b is not
planned (Q6, most restrictive fallback, maintainer may revisit).

## Risk classes (summary of ADR 0010 D5)

Effective risk = max(operation base, port role floor, device criticality,
NOS path rule), as ADR 0010 D5 (previously: this summary listed only the
base and the port floor). Device criticality is executor-owned, default
**HIGH for firewalls** and MEDIUM for switches, so with the defaults every
PAN-OS change is at least HIGH. Port role floors apply to every operation
on the port, independent of MAC age: `nos-path` CRITICAL, `management`,
`uplink` and `unknown` HIGH (also any uplink, trunk, LAG member or port
carrying the management VLAN), `edge` none. Raising a role is MEDIUM;
lowering one is approved at the old role's floor; `nos-path` is removed only
through the executor CLI.

| Change | Base | Raised to |
| --- | --- | --- |
| Port description | MEDIUM | HIGH on uplink/management/unknown port; CRITICAL on a `nos-path` port or a port where a NOS-path MAC was learned in the last 24 h |
| Access VLAN, shut/no shut on edge port | MEDIUM | HIGH on uplink/management/unknown port; CRITICAL on a `nos-path` port or a port where a NOS-path MAC was learned in the last 24 h |
| Trunk allowed VLANs | HIGH | CRITICAL on NOS path (role, MAC rule, management VLAN) |
| Persist running → startup (CBS) | MEDIUM | device criticality; refused while a reload timer is pending |
| Add / edit unreferenced address object/group (also not via nested or dynamic groups) | MEDIUM | **HIGH by default** (firewall criticality); MEDIUM only if the admin lowered the firewall's criticality |
| Referenced object edit | HIGH | CRITICAL when any referencing rule (direct, nested, dynamic group), with the old or new value, overlaps the NOS path; unevaluable objects (FQDN, EDL) count as overlapping |
| Rule delete / object delete (only as the bound inverse of an add; object delete only while unreferenced) | HIGH / MEDIUM | as rule add / unreferenced object; deleting a rule that allows NOS-path traffic is CRITICAL |
| Rollback (bound inverse) | max(original effective risk, risk re-derived at rollback time) | CRITICAL rollbacks are refused like every CRITICAL change (Q6, most restrictive fallback 2026-11-09, maintainer may revisit; previously: refused in 2a; reload timer / dead-man and confirm window in 2b) |
| Rule add / disable / enable / move | HIGH | CRITICAL on NOS path overlap, when disabling or deleting a rule that allows NOS-path traffic, or when a deny/drop is added, moved or enabled above a rule that allows NOS-path traffic (previously: any deny above allow) |
| Anything on NOS's own management path, or path data stale | CRITICAL | refused for good (Q6, most restrictive fallback 2026-11-09, maintainer may revisit; previously: refused in phase 2a) |
| Flat lab network (Q4, decided 2026-11-09): any port, VLAN or uplink change on a switch that carries the NOS path | CRITICAL | refused for good, until an ADR amendment records a management VLAN |

## Non-goals

As ADR 0010: no generic CLI, xpath or config push, no unattended or
scheduled writes, no management/AAA/SSH/HTTPS/SNMP/certificate/firmware/
routing/VPN/HA changes, no CBS220, no credentials outside the executor, no
SNMP polling, no policy optimizer.
