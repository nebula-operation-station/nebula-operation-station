# Project status

Last updated 2026-11-17

This page is the short, frequently updated view of where Nebula Operation Station stands. The
[README roadmap](../README.md#roadmap) gives the area overview; the ADRs in [docs/adr](adr/) hold
the decisions, and [docs/implementation](implementation/) the per-area plans.

## Where we are

| Area | ADR | State |
| --- | --- | --- |
| Release 0.9 (milestones 0–10) | – | code complete; lab run on real hosts pending; 0.9 Beta in preparation |
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

### Landed in the last 24 hours (52 PRs, #530–#635)

- **Fuzzing and limits (tq/tw):** fuzz targets for registrymeta (#594), PVE live contract (#593),
  netdev spool/ingest (#592), vulnfeed (#591), discovery spool (#611), executions decoders (#609),
  enrollment renderers (#610), server.json (#617), forwarded-header resolver (#615), prelude (#586);
  limit/limit+1 tests (#595, #616, #618, #626, #630); netpolicy zoned-address fix (#590).
- **Integrity (ig, ADR 0015):** #579, #600, #608, #612, #613, #622, #623, #629.
- **Vulnerability management (vu, ADR 0011):** #588, #606, #624, #631, #635.
- **Network security advisor (ns, ADR 0012):** #597, #599, #601, #625.
- **Help assistant (as, ADR 0014):** #596, #607, #621.
- **Network devices (nd, ADR 0010):** #627; security acceptance tests (#530).
- **Containers (cu):** #605, #619, #620, #632.
- **Other:** helpfacts oracles (#589), discovery import (#628), go.sum cleanup (#598).
- **Docs:** #602, #603, #604, #614, #634.

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
- **Release 0.9 Beta:** lab run on real hosts.

## Blocked / needs maintainer

- **ADR 0016 (PR #637, protected path `docs/adr`):** needs the maintainer's review and merge. ag01 is
  blocked until the final ADR text is on main (or the branch head is confirmed as final).
- **ADR 0009 (traffic map):** still "proposed", awaiting the maintainer's decision on the open
  questions, although large parts are merged.
- **One-step enrollment:** dialog is documented as not wired in nebula-server (#604); decide whether
  wiring is a ticket for 0.9 or later.

## Changelog

- **2026-11-17:** status page created. 52 PRs merged in 24 h (fuzzing wave, integrity libraries,
  vulnerability findings end to end, ADR 0012 libraries); ADR 0016 ops agent proposed (#637) and
  its 26-ticket chain imported.
