# Project status

Last updated 2026-11-28 (evening; previously 2026-11-28 morning, PV-03i round 1)

This page is the short, frequently updated view of where Nebula Operation Station stands. The
[README roadmap](../README.md#roadmap) gives the area overview; the ADRs in [docs/adr](adr/) hold
the decisions, and [docs/implementation](implementation/) the per-area plans.

## Where we are

| Area | ADR | State |
| --- | --- | --- |
| Release 0.9 (milestones 0–10) | – | code complete; release draft v0.9.0-beta.1 prepared on 2026-11-04, not yet published; running in the reference lab since then, formal integration run on clean VMs pending |
| Proxmox VE phase 1 / phase 2 | [0006](adr/0006-proxmox-integration.md) | phase 1 wired; PVE inventory retention runs beside the spool import (#786); collector call timeout covers the read budget (#794); phase 2 guest power and snapshot controls wired in nebula-server; backup, migration and node reboot executor code only, no RPC |
| Approval ergonomics | [0007](adr/0007-approval-ergonomics.md) | merged; reject pending proposals complete (#687, #753, #755); read grants with network device targets compare those targets (#795) and need CLI approval in every mode (#813, rule A1-0b) |
| Guest provisioning | [0008](adr/0008-guest-provisioning.md) | image preparation available: amendment 2 (PV-03j, #871) and the PV-03 chain merged (PV-03a–i: #891, #900–#902, #905, #907, #908, #910, #912, #915); the Images page under `/deploy/images` prepares a template with HIGH approval, and the wizard provisions from the prepared records; **chain pi 13/14: the end-to-end acceptance test (pi14) is blocked because the action token policy does not allow the PVE privileges that image preparation needs** (see Blocked); #914 (pi04g, local image RPCs stay integrity-locked, ADR 0008 amendment 2 I1) waits for the maintainer; preset host keys (amendment 1) still proposed (previously: "preset host keys in progress") |
| Traffic map | [0009](adr/0009-traffic-map.md) | proposed; API and pages mounted in nebula-server; end-to-end test from real `net.facts` output to the map API (#798) |
| Network devices | [0010](adr/0010-network-devices.md) | accepted; read chain nx complete (11/11): device importer and device pages mounted in nebula-server (#878), end-to-end test (#886); the executor `ReadNetworkDevice` RPC itself still answers `Unimplemented` (ND-14) |
| Vulnerability management | [0011](adr/0011-vulnerability-management.md) | accepted; package inventory stored on the server and exported (`vuln-inventory-v1`); chains iv (12/12) and img (9/9) complete; host criticality used in the vulnerability tier (#889) and in the ops finding score (#899, uf17g); **security key chain va complete (6/6)**: maintainer decisions accepted with a login assertion bound to the decision digest (#903), human states re-checked in every sweep and mark resets notified (#909), basis errors count as unknown unless they are a named transient error (#916), admin guide updated (#913), end-to-end test over real HTTP with a real executor and a virtual security key (#917); reference lab still needs an approved `package.list_installed` read lease (0 subjects) and an upgrade for image package reads |
| Network security advisor | [0012](adr/0012-network-security-advisor.md) | accepted; pure libraries merged, none imported by nebula-server (not wired) |
| One-step enrollment | [0013](adr/0013-one-step-enrollment.md) | accepted; dialog switched on in nebula-server (#782, #785); public `GET /enroll/<offer-id>` route outside the session gate (#841, ADR 0013 D7); NetBird option still open |
| Help assistant | [0014](adr/0014-help-assistant.md) | accepted; AS-09 libraries merged, service and wiring open |
| Integrity monitoring | [0015](adr/0015-integrity-monitoring.md) | accepted; I1/I2 wiring decided 2026-11-21; **chain fi 7/15**: `fim.scan` limits, catalog and result limit (#870, #881, #879); `fim.scan` from a read lease as a durable job (#884); proposed and run through read leases (#896, #904); `/integrity/status` with two labelled sources (#893); notification gate wired to the notifier (#906); fi06 on hold for a maintainer decision (see Blocked), fi09–fi15 wait behind it |
| Ops agent | [0016](adr/0016-ops-agent.md) | accepted; implementation chain (27/27) and live chain uh (11/11) complete and wired (#880, #883, #887, #894, #895) |

### Landed since the last update (6 PRs, 2026-11-28 01:17 to 09:31 UTC)

- **Security key for vulnerability decisions (chain va, 3/6 → 6/6, complete):** human states
  re-checked in every sweep, applied feed mark reset notified (#909, va14); basis errors treated as
  unknown unless known transient (#916, va14g); admin guide: decisions need a security key
  assertion (#913, va15; protected path); maintainer decisions end to end over real HTTP with
  `runServer`, a real executor and a virtual security key (#917, va16).
- **Image preparation (chain pi, 11/14 → 13/14):** Images page under `/deploy` and wizard
  selections bound to the executor's template records (#912, pi12, PV-03h); operator guide,
  README and status line (#915, pi13, PV-03i). pi14 (end-to-end acceptance) stopped at a PVE
  privilege gap (see Blocked).

### Landed in the last 7 days

Merged per day (UTC): 29 (11-22), 15 (11-23), 13 (11-24), 13 (11-25), 16 (11-26), 12 (11-27), 6
(11-28 so far). Main themes: ops agent (ADR 0016) and network device read chain (ADR 0010)
complete and wired; vulnerability package and image inventory (ADR 0011); image preparation
(ADR 0008 PV-03) available in the UI; integrity check wiring (ADR 0015); maintainer decisions with
a security key assertion complete (ADR 0011 Q4).

## Wired in nebula-server (re-checked 2026-11-21 evening; network devices and ops agent re-checked 2026-11-26; integrity status and image RPCs 2026-11-27; vulnerability decisions 2026-11-28)

"Merged" in the table above means code is on `main`, not that the server uses it. Per area:

| Area | Wired in nebula-server? | Evidence |
| --- | --- | --- |
| Proxmox VE phase 1 (read-only pages, inventory, live values) | yes, the `/pve` pages and the PVE part of the chart; inventory retention runs beside the spool import (#786) | `cmd/nebula-server/main.go` (`pveStore`) |
| Proxmox VE guest power and snapshots | yes: `GuestPower: exec`, `GuestSnapshot: exec`; rendering not checked in a browser | `cmd/nebula-server/guestactions_wiring_test.go` |
| Proxmox VE backup now, migration, node reboot | no: executor code only; no RPC for them in `proto/nebula/executor/v1/executor.proto` | grep of `executor.proto`, 2026-11-21 |
| Traffic map API, page and connections tab | yes, mounted; end-to-end test (#798) | `cmd/nebula-server/main.go` |
| Attack paths (vulnerability management) | yes: pages mounted; paths computed from stored data every 15 minutes (#849, ADR 0011 D10); rendering not checked in a browser | `cmd/nebula-server/attackpaths.go`, `cmd/nebula-server/attackpaths_source.go` |
| Vulnerability inventory export | yes: served from the stored package inventory (#792) | PR #792 |
| Vulnerability maintainer decisions | yes: accepted with a login assertion bound to the decision digest (#903); human states re-checked in every sweep (#909, #916); end-to-end test over real HTTP (#917) | `cmd/nebula-server/vuln.go`, PR #917 |
| Network devices (import and device pages) | yes: spool importer started as a server background run and device and PAN-OS firewall pages mounted (#878); end-to-end test (#886). The executor device read RPC still answers `Unimplemented` (ND-14); the decided read path is the collector spool (variant 1) | `cmd/nebula-server/netdev.go` (`startNetDevImport`, `mountNetDevPages`), `internal/executor/netdev_read.go:112` |
| Network security advisor (netreach, netadvisor, edl, reputation) | no: libraries exist, nothing outside their own packages imports them | `internal/netadvisor/`, `internal/edl/`, `internal/reputation/` |
| One-step enrollment | yes, the dialog: `Enroll: exec`, and `lazyExecutor` implements `ui.EnrollOffers` (#785); the executor installs the loaded configuration (#782); the public `GET /enroll/<offer-id>` route sits outside the session gate (#841). The NetBird option still waits for EN-16g | `cmd/nebula-server/main.go`, `cmd/nebula-server/executor_onestep.go` |
| Help assistant | panel routes mounted; the `internal/helpassist` libraries are not imported | `internal/web/ui/assistant.go`, `internal/web/ui/ui.go` |
| Ops agent | yes: API wired; projection gets stored findings (#883) and listeners from stored socket facts (#880); Ops tab set (`o.AssistantOps`, #887); end-to-end test (#895) | `cmd/nebula-server/ops_assistant.go` (`wireOpsAssistant`), `cmd/nebula-server/main.go:672` |
| Integrity monitoring | partly: the server self-check (I1) runs at start and on an interval and serves `/integrity/status` with the executor status labelled by source (#893); `fim.scan` is proposed and run through read leases (#896); the notification gate is wired to the notifier (#906). `fim.scan` result parsing waits on fi06 (D6 key) | `cmd/nebula-server/integrity.go` |
| Image preparation (PV-03) | yes: the Images page (`/deploy/images`) proposes, approves and runs preparations, and the wizard offers the prepared records; server forwarding (#910, PV-03g) and the Images page (#912, PV-03h) merged; a real PVE refuses the preparation writes under today's action token policy (pi14, see Blocked) | `cmd/nebula-server/executor.go` (`ProposePVEImagePrepare`, `CommitPVEImagePrepare`, `ListPVEImages`), `internal/web/ui/deploy_images.go` |

Not re-checked in this pass: release 0.9, approval ergonomics. The
[wiring audit](implementation/wiring-audit.md) (2026-11-21) still lists the network device pages
and the Ops tab as gaps; both are closed since #878 and #887.

## In progress

| Chain | Topic | Progress | Running now |
| --- | --- | --- | --- |
| pi | Image preparation wiring (ADR 0008 PV-03) | 13/14 | pi01–pi13 merged (#871, #872, #816, #891, #900, #901, #905, #907, #902, #908, #910, #912, #915); follow-up pi04g (#914, protected) open; pi14 blocked (PVE privileges, maintainer decision) |
| fi | Integrity check wiring (ADR 0015 I1/I2) | 7/15 | fi01–fi05, fi07, fi08 merged plus follow-up fi05g (#904); fi06 on hold (maintainer decision); fi09–fi15 queued behind fi06 |
| va | Security key for vulnerability decisions (ADR 0011 Q4) | complete | va11–va16 merged (#875, #876, #903, #909, #913, #917) plus follow-up va14g (#916) |
| uf / nx / uh | Wiring follow-ups, network device read chain, ops agent live | complete | uf17g (#899), nx 11/11, uh 11/11 |
| iv / img / ug / vf | Inventory, image lease, end-to-end tests, feed fixes | complete | iv 12/12, img 9/9, ug 12/12, vf 4/4 |

No ticket for this repository is running right now; every open chain waits on a maintainer
decision or review.

## Next

- **Image preparation (pi, 13/14):** once the privilege question is decided, a protected change to
  spec 06 and `validatePvePermissions`, then pi14 (end-to-end acceptance: `runServer`, Images
  page, wizard provisioning, D5 negatives). #914 lands once the maintainer approves it.
- **Integrity check (fi, 7/15):** fi09–fi15 all wait on fi06, which waits on the D6 installation
  key decision.
- **Release 0.9 Beta:** beta.2 was planned after the iv chain and vf04; both are merged, and the va
  chain is now complete too.

## Blocked / needs maintainer

- **pi14: PVE privileges for image preparation (protected: `docs/spec/`, `internal/executor/`):**
  the preparation steps (storage download, VM creation, template conversion, config writes) need
  `Datastore.AllocateTemplate`/`Datastore.AllocateSpace`, `VM.Allocate` and `VM.Config.*` on the
  action token. Today the executor's profile check refuses such a token at `AddPVERemote`, and a
  real PVE refuses the first write. Decisions needed: (1) which action privileges image
  preparation may use, recorded as a spec 06 amendment (feature profile union); (2) the matching
  change to `validatePvePermissions` and its tests. Until then a test pins the blocker
  (`TestApprovedPrepareStopsAtThePVEPrivileges`).
- **#914 (pi04g, protected):** `AddPVELocalImage`/`RemovePVELocalImage` stay integrity-locked
  (ADR 0008 amendment 2 I1, decided 2026-11-28); local review APPROVE with one LOW finding (a line
  reference in the ADR); needs the maintainer label and merge.
- **fi06 on hold (ADR 0015 D6), blocks fi09–fi15:** `fimscan.Parse` needs the per-host key
  `k_host` derived from a 32-byte installation key that only the executor holds; that key does
  not exist on `main`, and a placeholder key would be unsafe. Decisions needed: (1) build the D6
  installation key now as its own ticket before fi06? (2) store the scan mode and profile per run
  as a column on `runs` (migration) or in a separate table?
- **fi05 follow-ups:** `fim.scan` is missing from `ReadGrantActionIDs`, and the web form needs a
  mode selection; own ticket or not?
- **Open PRs:** #914 (see above); dependabot #647, #648, #867 wait for review.
- **Vulnerability inventory, open questions Q1–Q3 and Q6:** see
  [vuln-inventory-decisions.md](implementation/vuln-inventory-decisions.md).
- **ADR 0009 (traffic map):** still "proposed".
- **ADR 0008 amendment 1 (preset host keys):** still "proposed"; see
  [preset-host-key.md](implementation/preset-host-key.md).
- **Wiring gaps:** help assistant service; network security advisor libraries; PVE backup,
  migration and node reboot RPCs.
- **Read lease for `package.list_installed` on the reference lab:** needs approval; until then the
  vuln agent reports 0 subjects.
- **Reference lab upgrade for image package reads:** the reference lab still runs the previous
  build; it must be upgraded before image package reads can run there.

## Changelog

- **2026-11-28 (evening):** 6 PRs; va chain complete (#909, #913, #916, #917); pi chain 13/14
  (Images page #912, docs #915); pi14 blocked on PVE privileges; #914 (pi04g) waits for the
  maintainer; fi06 still on hold.
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
