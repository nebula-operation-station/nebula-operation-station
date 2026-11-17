# Project status

Last updated 2026-11-17

This page is the short, frequently updated view of where Nebula Operation Station stands. The
[README roadmap](../README.md#roadmap) gives the area overview; the ADRs in [docs/adr](adr/) hold
the decisions, and [docs/implementation](implementation/) the per-area plans.

## Where we are

| Area | ADR | State |
| --- | --- | --- |
| Release 0.9 (milestones 0–10) | – | code complete; release draft v0.9.0-beta.1 prepared on 2026-11-04, not yet published; running in the reference lab since then, formal integration run on clean VMs pending |
| Proxmox VE phase 1 / phase 2 | [0006](adr/0006-proxmox-integration.md) | phase 1 merged; phase 2 actions merged, follow-ups ongoing |
| Approval ergonomics | [0007](adr/0007-approval-ergonomics.md) | merged; read-lease pre-check (lg01) queued |
| Guest provisioning | [0008](adr/0008-guest-provisioning.md) | merged; deploy profile limits and round-trip fuzz landed (#618) |
| Traffic map | [0009](adr/0009-traffic-map.md) | proposed; libraries, store and renderer merged; fuzz hardening running (tw) |
| Network devices | [0010](adr/0010-network-devices.md) | accepted; credential/lease ordering fixed (#627), revocation follow-up running (nd21i) |
| Vulnerability management | [0011](adr/0011-vulnerability-management.md) | accepted; device findings from vendor advisories end to end (#606), export fuzz (#635) |
| Network security advisor | [0012](adr/0012-network-security-advisor.md) | accepted; pure libraries for EDL (#601, #625), reputation (#599) and vu-prio-v2 (#597) merged |
| One-step enrollment | [0013](adr/0013-one-step-enrollment.md) | accepted; renderer fuzz merged (#610); dialog not yet wired in nebula-server (#604) |
| Help assistant | [0014](adr/0014-help-assistant.md) | accepted; BM25F field scoring (#607), command checks V1/V6 (#596, #621) merged |
| Integrity monitoring | [0015](adr/0015-integrity-monitoring.md) | accepted; baseline digest as tamper evidence (#579), sshd extraction and symlink resolution libraries (#608, #612, #613, #622, #629) merged |
| Ops agent | ADR 0016 (PR #637) | proposed; implementation chain ag (26 tickets) imported |

### Landed in the last 7 days (223 PRs, 2026-11-10 to 2026-11-17)

Merged per day: 27 (11-10), 60 (11-11), 54 (11-12), 31 (11-13), 25 (11-16), 26 (11-17).

- **Network devices (ADR 0010):** registry store, registration and dial-time address checks
  (#418, #421), admin RPCs and collector role (#423, #426), probe and credential lifecycle (#427),
  read-grant profile and enforcement (#434, #436), config versions, diff and approved baseline
  (#494, #516), device pages and firewall view (#441, #460), acceptance tests (#518, #530),
  credential/lease ordering (#627).
- **Vulnerability management (ADR 0011):** attack paths UI and traffic-map overlay (#412),
  "fix with" links (#411), vulnerability agent API client and tool-calling agent (#464, #514),
  device findings from vendor advisories end to end (#606), export fuzz (#635).
- **Network security advisor (ADR 0012):** reachability engine – snapshot, NAT, rule evaluation,
  explain chain, budgets (#466, #479, #484, #497); rule checks (#501, #507, #515); pure libraries
  for vu-prio-v2, reputation and EDL (#597, #599, #601, #625).
- **One-step enrollment (ADR 0013):** spec revision (#461, #468, #472, #476), script generator with
  pairing code and NetBird section (#474, #480, #485), offer store (#475, #483, #492), permits
  (#495, #498), local config and pairing RPCs (#490, #504, #521), unauthenticated script download
  (#519, #615).
- **Help assistant (ADR 0014):** spec as default-off feature (#553, #557), in-app help under /help
  (#455), fuzzed matcher and sanitizer (#584, #589), command checks (#596, #621), BM25F scoring (#607).
- **Integrity monitoring (ADR 0015):** ADR proposed and accepted (#451, #463, #470), spec revision
  (#502), installed-files manifest (#503, #544), executor-held baseline digest (#579), sshd and
  symlink libraries (#608, #612, #613, #622, #629), escaped path form (#623).
- **Release and signing:** offline staging and draft release builds on tags (#533, #534),
  security-key verifier command (#538), signed root rotation via local admin command (#577).
- **Containers:** private registry reads and private image transfer into docker load
  (#452, #478, #528, #605), member checks (#619, #620, #632).
- **CI and tests:** self-hosted runners on nos-ci (#435), Go toolchain update (#442); fuzz wave
  across parsers and decoders (#586–#595, #609–#611, #615–#618) and limit/limit+1 tests.
- **Docs:** 45 docs PRs, among them security-tests inventory (#602, #634), schedule grants (#603),
  getting-started guide (#614).

Today (2026-11-17): 26 PRs, mainly fuzz and limit tests, integrity libraries and #627; ADR 0016 ops
agent proposed (#637) and its 26-ticket plan (ag01–ag26) imported.

## In progress

| Chain | Topic | Progress | Running now |
| --- | --- | --- | --- |
| ag | Ops agent (ADR 0016) | 0/26 | ag02, ag03; ag01 blocked (see below) |
| tw | Fuzz and edge tests, second wave | 8 merged, 3 running | tw07f (PR #633), tw09f (PR #636), tw11 |
| nd | Network devices follow-ups | 41 merged | nd21i (failed revocation keeps device blocked) |
| ep | Primary and alternate endpoints per host | 0/2 | ep01 |
| lg | Read leases: report all non-LOW items at once | 0/1 | queued (path conflict with ep01) |
| op | Abort operations and reject proposals from the overview | 0/1 | queued (path conflict with ep01) |

## Next

- **ag chain:** ag01 (spec text from ADR 0016) gates ag08, ag09 and ag11–ag14; most of the 26
  tickets depend on it. Unblocks once ADR 0016 is final.
- **ep02** after ep01; **lg01** and **op01** start once ep01 releases its paths.
- **tw:** land #633 and #636, then tw11.
- **Release 0.9 Beta:** publish the draft (or cut beta.2 from current main) after the integration run on clean VMs.

## Blocked / needs maintainer

- **ADR 0016 (PR #637, protected path `docs/adr`):** needs the maintainer's review and merge. ag01 is
  blocked until the final ADR text is on main (or the branch head is confirmed as final).
- **ADR 0009 (traffic map):** still "proposed", awaiting the maintainer's decision on the open
  questions, although large parts are merged.
- **One-step enrollment:** dialog is documented as not wired in nebula-server (#604); decide whether
  wiring is a ticket for 0.9 or later.

## Changelog

- **2026-11-17:** status page created (window: last 7 days). 26 PRs merged today (fuzzing wave, integrity libraries,
  vulnerability findings end to end, ADR 0012 libraries); ADR 0016 ops agent proposed (#637) and
  its 26-ticket chain imported.
