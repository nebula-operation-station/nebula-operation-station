# Project status

Last updated 2026-11-17 (evening)

This page is the short, frequently updated view of where Nebula Operation Station stands. The
[README roadmap](../README.md#roadmap) gives the area overview; the ADRs in [docs/adr](adr/) hold
the decisions, and [docs/implementation](implementation/) the per-area plans.

## Where we are

| Area | ADR | State |
| --- | --- | --- |
| Release 0.9 (milestones 0–10) | – | code complete; release draft v0.9.0-beta.1 prepared on 2026-11-04, not yet published; running in the reference lab since then, formal integration run on clean VMs pending |
| Proxmox VE phase 1 / phase 2 | [0006](adr/0006-proxmox-integration.md) | phase 1 merged; phase 2 actions merged, follow-ups ongoing |
| Approval ergonomics | [0007](adr/0007-approval-ergonomics.md) | merged; read leases now report every non-LOW host/action at once and are checked before submitting (#655) |
| Guest provisioning | [0008](adr/0008-guest-provisioning.md) | merged; deploy profile limits and round-trip fuzz landed (#618) |
| Traffic map | [0009](adr/0009-traffic-map.md) | proposed; libraries, store and renderer merged; hourly split fuzzed and pinned to flowagg (#639) |
| Network devices | [0010](adr/0010-network-devices.md) | accepted; credential/lease ordering (#627) and blocked device after failed revocation (#643) fixed |
| Vulnerability management | [0011](adr/0011-vulnerability-management.md) | accepted; device findings from vendor advisories end to end (#606), export fuzz (#635), SKU matching fixes (#624, #631) |
| Network security advisor | [0012](adr/0012-network-security-advisor.md) | accepted; pure libraries for EDL (#601, #625), reputation (#599) and vu-prio-v2 (#597) merged |
| One-step enrollment | [0013](adr/0013-one-step-enrollment.md) | accepted; renderer fuzz merged (#610); dialog not yet wired in nebula-server (#604) |
| Help assistant | [0014](adr/0014-help-assistant.md) | accepted; BM25F field scoring (#607), command checks (#596, #621), Markdown renderer fuzz (#636, #658) merged |
| Integrity monitoring | [0015](adr/0015-integrity-monitoring.md) | accepted; sshd and symlink libraries (#608, #612, #613, #622, #629), escaped path form (#623), finding classes for baseline deviations (#633) merged |
| Ops agent | [0016](adr/0016-ops-agent.md) | **accepted 2026-11-17** (#637, #640, spec v28); implementation 11/26 tickets merged |

### Landed in the last 24 hours (49 PRs)

- **Ops agent (ADR 0016):** ADR (#637), spec v28, threat model and amendments (#640, #644);
  notification log (#645), lease watch events (#641), daily digest (#646), exclusive ops agent
  token (#651), shared `llmclient` extracted from the vuln agent (#653), "fix with" decision moved
  out of the UI (#650), notes store (#652), settings row (#654), facts projection (#657),
  agent-suggested executions raised to at least MEDIUM with origin (#656).
- **Approval ergonomics:** read leases report all non-LOW items at once (#655).
- **Network devices:** no read between a new credential and the lease revocation (#627); failed
  revocation keeps the device blocked (#643).
- **Vulnerability management:** vendor-advisory device findings end to end (#606), SKU/series
  matching (#624, #631), export fuzz (#635).
- **Integrity monitoring:** retained-record merge, sshd extraction, match budgets, escaped paths and
  finding classes (#613, #612, #622, #629, #623, #633).
- **Containers:** member checks and read-lease grants (#619, #620), tag comparison (#632).
- **Tests (tw wave, 11/11 done):** fuzz and limit/limit+1 tests across server config, enrollment,
  discovery spool, executions, auditlog, pvecollect, traffic, help renderer (#609–#611, #615–#618,
  #626, #628, #630, #636, #639, #658).
- **Docs:** getting-started guide (#614), security-tests inventory (#634), status page (#638).

### Landed in the last 7 days (243 PRs, 2026-11-10 to 2026-11-17)

Merged per day: 27 (11-10), 60 (11-11), 54 (11-12), 31 (11-13), 25 (11-16), 46 (11-17).
Main themes: network devices (ADR 0010) registry, credentials, config baselines and device pages;
vulnerability agent and attack paths (ADR 0011); reachability engine and rule checks (ADR 0012);
one-step enrollment scripts, offers, permits and pairing (ADR 0013); help assistant (ADR 0014);
integrity monitoring ADR, manifest and libraries (ADR 0015); release staging and signed root
rotation; private image transfer for containers; a large fuzz and limit-test wave; ops agent
(ADR 0016) accepted and its implementation chain started.

## In progress

| Chain | Topic | Progress | Running now |
| --- | --- | --- | --- |
| ag | Ops agent (ADR 0016) | 11/26 | ag15, ag17; follow-up ag02h; settings UI #659 (ag19) in fix round ag19f |
| tw | Fuzz and edge tests, second wave | 11/11, follow-ups open | #660 (tw09i) needs fix round tw09j (self-test of the mdsafe linearity check) |
| ty | Limit and fuzz tests, third wave (events, runbooks, ipam, enroll, vulnagent, help) | 0/7 | ty01 |
| ep | Primary and alternate endpoints per host | 0/2 | ep01f (PR #642) |
| op | Abort staged rollouts from the operations overview | 0/1 | op01b queued (path conflict with ag17) |
| lg | Read leases: report all non-LOW items at once | 1/1 | done (#655) |

## Next

- **ag chain:** after ag15 → ag16, ag05, ag19f; after ag17 → ag18, ag06, ag22; then ag20–ag26
  (wiring, UI and acceptance tests).
- **ep02** after ep01f (#642); **op01b** once ag17 releases its paths.
- **ty01–ty07** run as slots free up.
- **Dependabot:** #647, #648, #649 (golang-x group, upload-artifact v7, buf-action) wait for review.
- **Release 0.9 Beta:** publish the draft (or cut beta.2 from current main) after the integration run on clean VMs.

## Blocked / needs maintainer

- **Rejecting pending proposals from the overview:** needs a new executor RPC (`proto/`,
  `internal/executor/`, both protected) plus a spec/ADR decision on who may reject and how it is
  audited. The abort part was re-cut as op01b (staged rollouts only). Decide whether to open a
  ticket and under which ADR.
- **Read-lease refusal reason (#655):** the response names only the level; the risk-policy class
  stays in the audit log (m0 item 20). Showing the class to the admin would need a spec change –
  open question.
- **ADR 0009 (traffic map):** still "proposed", awaiting the maintainer's decision on the open
  questions, although large parts are merged.
- **One-step enrollment:** dialog is documented as not wired in nebula-server (#604); decide whether
  wiring is a ticket for 0.9 or later.

## Changelog

- **2026-11-17 (evening):** ADR 0016 accepted (#640); ag chain 11/26 merged; tw wave done; lg01
  merged (#655); ty wave (7 tickets) imported; op01 re-cut as op01b.
- **2026-11-17:** status page created (window: last 7 days). Fuzzing wave, integrity libraries,
  vulnerability findings end to end, ADR 0012 libraries; ADR 0016 ops agent proposed (#637) and
  its 26-ticket chain imported.
