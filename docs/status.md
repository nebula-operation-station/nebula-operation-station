# Project status

Last updated 2026-11-27 (evening; previously 2026-11-26 evening)

This page is the short, frequently updated view of where Nebula Operation Station stands. The
[README roadmap](../README.md#roadmap) gives the area overview; the ADRs in [docs/adr](adr/) hold
the decisions, and [docs/implementation](implementation/) the per-area plans.

## Where we are

| Area | ADR | State |
| --- | --- | --- |
| Release 0.9 (milestones 0–10) | – | code complete; release draft v0.9.0-beta.1 prepared on 2026-11-04, not yet published; running in the reference lab since then, formal integration run on clean VMs pending |
| Proxmox VE phase 1 / phase 2 | [0006](adr/0006-proxmox-integration.md) | phase 1 wired; PVE inventory retention runs beside the spool import (#786); collector call timeout covers the read budget (#794); phase 2 guest power and snapshot controls wired in nebula-server; backup, migration and node reboot executor code only, no RPC |
| Approval ergonomics | [0007](adr/0007-approval-ergonomics.md) | merged; reject pending proposals complete (#687, #753, #755); read grants with network device targets compare those targets (#795) and need CLI approval in every mode (#813, rule A1-0b) |
| Guest provisioning | [0008](adr/0008-guest-provisioning.md) | merged; amendment 2 (image preparation wiring, PV-03j, D1–D5) merged (#871); **chain pi 10/14**: executor image RPCs in `proto/` (#891, PV-03a); executor persists local image entries and serves add, remove and list (#900, PV-03b part 1); re-preparation rules (#901, D5); propose and commit image preparation handlers and catalog load (#905, D1a, D2a); signed image catalog loaded from the release bundle at start, fail closed (#907, PV-03c); `nebula` CLI for local image entries over the admin socket (#902, PV-03d); executor client methods (#908, PV-03f); server forwarding (pi11, #910, PV-03g) in fix round 1 |
| Traffic map | [0009](adr/0009-traffic-map.md) | proposed; API and pages mounted in nebula-server; end-to-end test from real `net.facts` output to the map API (#798) |
| Network devices | [0010](adr/0010-network-devices.md) | accepted; read chain nx complete (11/11): device importer and device pages mounted in nebula-server (#878), end-to-end test (#886); the executor `ReadNetworkDevice` RPC itself still answers `Unimplemented` (ND-14) |
| Vulnerability management | [0011](adr/0011-vulnerability-management.md) | accepted; package inventory stored on the server and exported (`vuln-inventory-v1`); chains iv (12/12) and img (9/9) complete; host criticality used in the vulnerability tier (#889) and in the ops finding score (#899, uf17g); **security key chain va 3/6: maintainer decisions accepted with a login assertion bound to the decision digest (#903, ADR 0011 Q4, variant A)**; va14 (#909, human states re-checked in every sweep, mark reset notified) in fix round 2; reference lab still needs an approved `package.list_installed` read lease (0 subjects) and an upgrade for image package reads |
| Network security advisor | [0012](adr/0012-network-security-advisor.md) | accepted; pure libraries merged, none imported by nebula-server (not wired) |
| One-step enrollment | [0013](adr/0013-one-step-enrollment.md) | accepted; dialog switched on in nebula-server (#782, #785); public `GET /enroll/<offer-id>` route outside the session gate (#841, ADR 0013 D7); NetBird option still open |
| Help assistant | [0014](adr/0014-help-assistant.md) | accepted; AS-09 libraries merged, service and wiring open |
| Integrity monitoring | [0015](adr/0015-integrity-monitoring.md) | accepted; I1/I2 wiring decided 2026-11-21; **chain fi 7/15**: `fim.scan` limits, catalog and result limit (#870, #881, #879); `fim.scan` from a read lease as a durable job (#884); `fim.scan` proposed and run through read leases with its canonical parameters and a due time per mode (#896, fi05), a dispatched lease run stays `running` until its job outcome is collected (#904, fi05g); `/integrity/status` shows the server self-check and the executor status, each labelled by its source (#893, fi07); integrity notification gate wired to the notifier (#906, fi08); fi06 on hold for a maintainer decision (see Blocked), fi09–fi15 wait behind it |
| Ops agent | [0016](adr/0016-ops-agent.md) | accepted; implementation chain (27/27) and live chain uh (11/11) complete and wired (#880, #883, #887, #894, #895) |

### Landed since the last update (15 PRs, 2026-11-26 19:16 to 2026-11-27 12:59 UTC)

- **Image preparation (chain pi, 3/14 → 10/14):** executor image RPCs in `proto/` (#891, pi04;
  protected path); local image entries persisted, add/remove/list handlers (#900, pi05);
  re-preparation only after a gone, changed or re-pinned template (#901, pi06); propose and commit
  handlers and catalog load (#905, pi07); signed image catalog loaded at executor start, fail
  closed (#907, pi08); CLI for local image entries (#902, pi09); executor client methods (#908,
  pi10).
- **Integrity check (chain fi, 4/15 → 7/15):** `fim.scan` through read leases (#896, fi05) and its
  follow-up for dispatched runs (#904, fi05g); `/integrity/status` with two labelled sources
  (#893, fi07); notification gate wired to the notifier (#906, fi08).
- **Security key for vulnerability decisions (chain va, 2/6 → 3/6):** maintainer decisions with a
  login assertion bound to the decision digest (#903, va13).
- **Follow-ups:** ops finding score uses the host criticality (#899, uf17g); `internal/executions`
  gets its own test timeout (#898, fc06b); status page for 2026-11-26 (#897).

### Landed in the last 7 days

Merged per day (UTC): 42 (11-21), 29 (11-22), 15 (11-23), 13 (11-24), 13 (11-25), 16 (11-26), 10
(11-27 so far). Main themes: ops agent (ADR 0016) complete and wired; network device read chain
(ADR 0010) complete and wired; vulnerability package and image inventory (ADR 0011); image
preparation wiring (ADR 0008 PV-03) in the executor and CLI; integrity check wiring (ADR 0015);
maintainer decisions with a login assertion (ADR 0011 Q4).

## Wired in nebula-server (re-checked 2026-11-21 evening; network devices and ops agent re-checked 2026-11-26; integrity status and image RPCs 2026-11-27)

"Merged" in the table above means code is on `main`, not that the server uses it. Per area:

| Area | Wired in nebula-server? | Evidence |
| --- | --- | --- |
| Proxmox VE phase 1 (read-only pages, inventory, live values) | yes, the `/pve` pages and the PVE part of the chart; inventory retention runs beside the spool import (#786) | `cmd/nebula-server/main.go` (`pveStore`) |
| Proxmox VE guest power and snapshots | yes: `GuestPower: exec`, `GuestSnapshot: exec`; rendering not checked in a browser | `cmd/nebula-server/guestactions_wiring_test.go` |
| Proxmox VE backup now, migration, node reboot | no: executor code only; no RPC for them in `proto/nebula/executor/v1/executor.proto` | grep of `executor.proto`, 2026-11-21 |
| Traffic map API, page and connections tab | yes, mounted; end-to-end test (#798) | `cmd/nebula-server/main.go` |
| Attack paths (vulnerability management) | yes: pages mounted; paths computed from stored data every 15 minutes (#849, ADR 0011 D10); rendering not checked in a browser | `cmd/nebula-server/attackpaths.go`, `cmd/nebula-server/attackpaths_source.go` |
| Vulnerability inventory export | yes: served from the stored package inventory (#792) | PR #792 |
| Network devices (import and device pages) | yes: spool importer started as a server background run and device and PAN-OS firewall pages mounted (#878); end-to-end test (#886). The executor device read RPC still answers `Unimplemented` (ND-14); the decided read path is the collector spool (variant 1) | `cmd/nebula-server/netdev.go` (`startNetDevImport`, `mountNetDevPages`), `internal/executor/netdev_read.go:112` |
| Network security advisor (netreach, netadvisor, edl, reputation) | no: libraries exist, nothing outside their own packages imports them | `internal/netadvisor/`, `internal/edl/`, `internal/reputation/` |
| One-step enrollment | yes, the dialog: `Enroll: exec`, and `lazyExecutor` implements `ui.EnrollOffers` (#785); the executor installs the loaded configuration (#782); the public `GET /enroll/<offer-id>` route sits outside the session gate (#841). The NetBird option still waits for EN-16g | `cmd/nebula-server/main.go`, `cmd/nebula-server/executor_onestep.go` |
| Help assistant | panel routes mounted; the `internal/helpassist` libraries are not imported | `internal/web/ui/assistant.go`, `internal/web/ui/ui.go` |
| Ops agent | yes: API wired; projection gets stored findings (#883) and listeners from stored socket facts (#880); Ops tab set (`o.AssistantOps`, #887); end-to-end test (#895) | `cmd/nebula-server/ops_assistant.go` (`wireOpsAssistant`), `cmd/nebula-server/main.go:672` |
| Integrity monitoring | partly: the server self-check (I1) runs at start and on an interval and serves `/integrity/status` with the executor status labelled by source (#893); `fim.scan` is proposed and run through read leases (#896); the notification gate is wired to the notifier (#906). `fim.scan` result parsing waits on fi06 (D6 key) | `cmd/nebula-server/integrity.go` |
| Image preparation (PV-03) | not yet: executor RPCs, handlers and catalog load are merged (`ProposePVEImagePrepare`, `CommitPVEImagePrepare`, `ListPVEImages`), CLI for local entries merged; server forwarding is #910 (open) | `proto/nebula/executor/v1/executor.proto:573-578` |

Not re-checked in this pass: release 0.9, approval ergonomics. The
[wiring audit](implementation/wiring-audit.md) (2026-11-21) still lists the network device pages
and the Ops tab as gaps; both are closed since #878 and #887.

## In progress

| Chain | Topic | Progress | Running now |
| --- | --- | --- | --- |
| pi | Image preparation wiring (ADR 0008 PV-03) | 10/14 | pi01–pi10 merged (#871, #872, #816, #891, #900, #901, #905, #907, #902, #908); pi11 server forwarding (#910, PV-03g) landing after fix round pi11f (1/2); pi12–pi14 queued behind it |
| fi | Integrity check wiring (ADR 0015 I1/I2) | 7/15 | fi01–fi05, fi07, fi08 merged (#870, #881, #879, #884, #896, #893, #906) plus follow-up fi05g (#904); fi06 on hold (maintainer decision); fi09–fi15 queued behind fi06 |
| va | Security key for vulnerability decisions (ADR 0011 Q4) | 3/6 | va11 (#875), va12 (#876), va13 (#903) merged; va14 (#909) in fix round 2 (va14f2, running, last round); va15, va16 queued behind it |
| uf | Wiring follow-ups and decision papers | complete | uf17 (#889) and follow-up uf17g (#899) merged |
| nx / uh | Network device read chain, ops agent live | complete | nx 11/11, uh 11/11 |
| iv / img / ug / vf | Inventory, image lease, end-to-end tests, feed fixes | complete | iv 12/12, img 9/9, ug 12/12, vf 4/4 |

## Next

- **Image preparation (pi, 10/14):** pi11f lands #910 (server forwards prepare, commit and list to
  the executor), then pi12, pi13 and pi14 in order.
- **Security key (va, 3/6):** va14f2 is the last round for #909; va15 and va16 follow once it is
  merged.
- **Integrity check (fi, 7/15):** fi09–fi15 all wait on fi06, which waits on the D6 installation
  key decision (see Blocked).
- **Release 0.9 Beta:** beta.2 was planned after the iv chain and vf04; both are merged.

## Blocked / needs maintainer

- **fi06 on hold (ADR 0015 D6), blocks fi09–fi15:** `fimscan.Parse` needs the per-host key
  `k_host` derived from a 32-byte installation key that only the executor holds; that key does
  not exist on `main`, and a placeholder key would be unsafe. Decisions needed: (1) build the D6
  installation key now as its own ticket before fi06 (generate and store in the executor, HKDF per
  host, tests)? (2) store the scan mode and profile per run as a column on `runs` (migration) or in
  a separate table?
- **va14 reading of ADR 0011 D6 (please confirm):** in fix round va14f2 a classifier error during
  a sweep keeps the human state (accepted risk, false positive) and the next sweep checks again;
  only a definite "basis changed" reopens it. If D6 is meant as "error = unknown = reopen", say so
  before #909 merges.
- **fi05 follow-ups:** `fim.scan` is missing from `ReadGrantActionIDs`, and the web form needs a
  mode selection; own ticket or not (not re-checked after #896 and #904)?
- **Protected documentation:** `docs/admin/guide.md` lines on vulnerability decisions (follow-up 6
  in [vuln-decisions-assertion.md](implementation/vuln-decisions-assertion.md)) need a separate
  maintainer change once #909 is merged; follow-ups 4 and 5 there are done by #909 and can be
  marked then.
- **Open PRs:** #909 (va14) and #910 (pi11) in fix rounds; dependabot #647, #648, #867 wait for
  review.
- **Vulnerability inventory, open questions Q1–Q3 and Q6:** see
  [vuln-inventory-decisions.md](implementation/vuln-inventory-decisions.md).
- **ADR 0009 (traffic map):** still "proposed".
- **Wiring gaps:** help assistant service; network security advisor libraries; PVE backup,
  migration and node reboot RPCs.
- **Read lease for `package.list_installed` on the reference lab:** needs approval; until then the
  vuln agent reports 0 subjects.
- **Reference lab upgrade for image package reads:** the reference lab still runs the previous
  build; it must be upgraded before image package reads can run there.

## Changelog

- **2026-11-27 (evening):** 15 PRs; pi chain 10/14 (executor image RPCs #891, image entries and
  handlers #900, #901, #905, catalog load at start #907, CLI #902, client #908); fi chain 7/15
  (lease runner #896, #904, `/integrity/status` #893, notification gate #906); va13 merged (#903,
  decisions with login assertion); uf17g (#899), fc06b (#898), status page (#897). va14 and pi11
  in fix rounds; fi06 still on hold.
- **2026-11-26 (evening):** 13 PRs; ops agent wired (uh chain complete: #883, #887, #894, #895);
  network device chain complete (nx10 #878, nx10g #885, nx11 #886, nx12g #888); fi04 merged
  (#884); ADR 0008 amendment 2 merged by the maintainer (#871); host criticality in the tier
  (#889); server test timeout split (#892); stale notes removed (#890); status page (#882). fi06
  on hold for the D6 key decision.
- **2026-11-25 (evening):** 7 PRs; fi01 merged (#870: `fim.scan` limits and read-lease rule);
  pi02 merged (#872); va11 and va12 merged (#875, #876); nx10a and nx10b merged (#874, #877);
  status page for 2026-11-24 late (#873). Maintainer decisions recorded
  on 2026-11-25: `fim.scan` retry and catalog, uh02 listener source (option a), ADR 0008
  amendment 2, device staleness.
- **2026-11-24 (late evening):** 3 PRs; ug chain complete 12/12 (notifications end to end #803);
  nx08g hardening merged (#868); status page (#869); fi01, pi01, pi02 in review (#870–#872);
  README roadmap: attack path computation marked as wired (#849).
- **2026-11-24 (evening):** 10 PRs; img chain complete 9/9 (image observer #864, image subjects in
  the export #861, snapshot fairness #860, end-to-end test #865, admin guide #866); nx chain 9/11
  (device rows from imported metadata #814, device targets in the read-grant preview #858); iv03gg
  (#862) and gd01g (#863) merged; status page for 2026-11-23 (#859).
- **2026-11-23 (evening):** 15 PRs; img chain 5 of 9 numbered (ADR 0011 amendment #852, wording
  #854, image lease propose and page #855, #856, lease runner #857, image inventories in snapshots
  #853); ops notes accept handbook chunk citations (#787); attack paths computed from stored data
  (#849); guide on the inventory and the read-lease start (#851); iv03g (#850) and iv05g (#830)
  merged; vf04 (#842) complete; uf08, uf15g, ug10g (#848, #845, #846) merged; reference lab upgraded
  and vuln agent timer on, still 0 subjects until a read lease is approved.
- **2026-11-22 (late evening):** 3 PRs; iv chain complete (end-to-end test #838, image read per
  execution #844); server config guide keys checked against the strict loader (#828).
- **2026-11-22 (evening):** 27 PRs; iv chain 11/12 (classifier by inventory, maximum read age,
  host inventory status, image inventories); nx chain 7/11 (device grants, device leases, collector
  metadata per device); public `/enroll/` route (#841); server feature registry (#829); ue06h,
  ue07, ue08 merged; vulnerability classifier and kernel closure fixes (#815, #831).
- **2026-11-21 (evening):** 42 PRs; maintainer decisions for PV-03, device read chain, assertion
  binding and integrity wiring (#805), inventory decisions E1–E4 (#776); package inventory stored
  and exported (iv 7/12); one-step enrollment dialog wired; device read grant security fixes
  (#795, #813); many end-to-end tests.
- **2026-11-21:** wiring re-check of README, status and implementation notes (#789); decision
  papers uf04, uf13, uf14.
- **2026-11-20 (evening):** 31 PRs; first live run of the vuln agent: four integration bugs fixed
  and deployed, missing package inventory found (iv chain started); end-to-end and lab-VM tests;
  ops agent chain and reject-pending complete; help assistant AS-09 libraries merged, service and
  wiring open.
- **2026-11-19 (evening):** 31 PRs; ag chain 24/27 (settings, notifications list, admin answers,
  browser tests, operator docs); registry redirect decision resolved by ADR 0006 amendment (#717);
  uc wave 7/8; ud chain (help assistant service) started.
- **2026-11-18 (evening):** 41 PRs; ag chain 18/26 (API, agent oneshot, Assistant panel, admin
  questions, units); reject-pending amendment and RPC merged (op 3/4); ep and ty chains done;
  ua wave 6/7; registry redirect decision opened.
- **2026-11-17 (evening):** ADR 0016 accepted (#640); ag chain 11/26 merged; tw wave done; lg01
  merged (#655); ty wave (7 tickets) imported; op01 re-cut as op01b.
- **2026-11-17:** status page created (window: last 7 days). Fuzzing wave, integrity libraries,
  vulnerability findings end to end, ADR 0012 libraries; ADR 0016 ops agent proposed (#637) and
  its 26-ticket chain imported.
