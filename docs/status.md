# Project status

Last updated 2026-11-23 (evening; previously 2026-11-22 late evening)

This page is the short, frequently updated view of where Nebula Operation Station stands. The
[README roadmap](../README.md#roadmap) gives the area overview; the ADRs in [docs/adr](adr/) hold
the decisions, and [docs/implementation](implementation/) the per-area plans.

## Where we are

| Area | ADR | State |
| --- | --- | --- |
| Release 0.9 (milestones 0–10) | – | code complete; release draft v0.9.0-beta.1 prepared on 2026-11-04, not yet published; running in the reference lab since then, formal integration run on clean VMs pending |
| Proxmox VE phase 1 / phase 2 | [0006](adr/0006-proxmox-integration.md) | phase 1 wired; PVE inventory retention now runs beside the spool import (#786); collector call timeout covers the read budget (#794); phase 2 guest power and snapshot controls wired in nebula-server; backup, migration and node reboot executor code only, no RPC (previously: "not offered in the chart"; "phase 1 and phase 2 actions merged") |
| Approval ergonomics | [0007](adr/0007-approval-ergonomics.md) | merged; reject pending proposals complete (#687, #753, #755); read grants with network device targets compare those targets (#795) and need CLI approval in every mode (#813, rule A1-0b) |
| Guest provisioning | [0008](adr/0008-guest-provisioning.md) | merged; **amendment 2026-11-21: PV-03 wiring of `pve.image.prepare` decided** (#805, paper #772, #790); chain pi started, the release bundle now stages `image-catalog.json` and its signature (#816) |
| Traffic map | [0009](adr/0009-traffic-map.md) | proposed; API and pages mounted in nebula-server; end-to-end test from real `net.facts` output to the map API (#798) |
| Network devices | [0010](adr/0010-network-devices.md) | accepted; **amendment 2026-11-21: device read chain decided** – variant 1 (collector spools one metadata record per device), device lease only through the local CLI (#805, paper #784); collector probe fix (#796); chain nx 7/11: read grants with device targets checked against the registry (#823) and previewed in the CLI (#821), device grants CLI-only (#813), CLI lease (#835) and admin-proposed leases (#833), collector spools one metadata record per device every cycle (#822, sub-minute #836) |
| Vulnerability management | [0011](adr/0011-vulnerability-management.md) | accepted; **amendment 2026-11-23: decided list for image leases** (#852, wording #854); reference lab upgraded and vuln agent timer on, still 0 subjects until a read lease with `package.list_installed` is approved; **package inventory now stored on the server** (#766, #777, #779, #793) and the `vuln-inventory-v1` export is served from it (#792); open-findings listing fix (#808); maintainer decisions recorded: inventory E1–E4 (#776), assertion binding variant A incl. `discard_hold` (#805, papers #771, #775); chain iv 12/12 complete: classifier closes runs by the inventory (#815, kernel fix #831), decided maximum read age applied (#837), host Vulnerabilities tab shows inventory status (#834), image package inventories kept for the last 3 per image (#832, one read per execution #844), end-to-end test from real script output to a stored finding over real HTTP (#838); follow-ups iv03g (#850) and iv05g (#830) merged, iv05gf and iv13g queued; chain img in progress (img01–img09, 4 numbered tickets merged) |
| Network security advisor | [0012](adr/0012-network-security-advisor.md) | accepted; pure libraries merged, none imported by nebula-server (not wired) |
| One-step enrollment | [0013](adr/0013-one-step-enrollment.md) | accepted; **dialog now switched on in nebula-server**: the executor installs the loaded enrollment configuration (#782) and the server relays the one-step RPCs (#785); **public `GET /enroll/<offer-id>` route outside the session gate** (#841, ADR 0013 D7) |
| Help assistant | [0014](adr/0014-help-assistant.md) | accepted; AS-09 libraries merged, service and wiring open |
| Integrity monitoring | [0015](adr/0015-integrity-monitoring.md) | accepted; libraries merged; **amendment 2026-11-21: I1 status and I2 scan chain wiring decided**, `fim.scan` as a durable job (#805, paper #783); chain fi imported (0/15) |
| Ops agent | [0016](adr/0016-ops-agent.md) | accepted; implementation chain complete (27/27); finding and listener sources merged (#780) but `cmd/nebula-server/ops.go:237` still passes `opsNoFindings` – connecting them is ticket uh02, which waits for a maintainer decision on the listener source; doc chunk citation tests merged (#787); a run without work reports its status, exit codes pinned for systemd (#807); note size limit aligned, pinned CA tested over real TLS (#809); install hint fixed (#811); Ops tab still not set in nebula-server |

### Landed since the last update (20 PRs, 2026-11-22 19:00 to 2026-11-23 19:00)

- **Vulnerability management, image chain (img):** ADR 0011 amendment of 2026-11-23 with the decided
  list for image leases (#852, wording #854); image lease propose and lease page (#855, #856); image
  reads (#853).
- **Vulnerability inventory (chain iv, now 12/12):** end-to-end test from real script output to a
  stored finding through the server inventory service (#838, iv10f); one image read per execution,
  tied to the stored run result (#844, iv12g); snapshot store uses the injected clock (#830, iv05g);
  installed-list facts judged by the facts' start (#850, iv03g).
- **Vulnerability feed:** optional CSAF feeds show as "not configured", stale filter kept (#842, vf04).
- **Ops agent:** fail-closed citation handling of the ops notes tested (#787, uh03).
- **Server configuration:** trusted proxy networks: catch-all and too broad networks rejected (#848,
  uf08); admin guide key checks derived from the strict loader (#828, ue09f).
- **Wiring and tests:** crown jewels page on stored inventory (#840, uf09); attack-path pages tested
  through the server chain on a real database (#849, uf10); registered tickets judged by their named
  document (#845, uf15g); size tests run under the real gRPC server options (#846, ug10g).
- **Docs:** embedded admin guide synced with `docs/admin/guide.md` (#851); status pages for
  2026-11-22 evening and late evening (#843, #847).

### Landed in the evening update (27 PRs, 2026-11-21 19:00 to 2026-11-22 19:00)

- **Vulnerability inventory (chain iv):** classifier closes runs by the stored inventory (#815);
  kernel closure must not ignore a newer partial read (#831); decided maximum read age applied to
  export completeness and the classifier (#837); host Vulnerabilities tab shows the inventory
  status (#834); image package inventories stored, last 3 kept per image (#832, decision E4).
- **Network devices (chain nx):** read grant checks device targets against the registry (#823);
  CLI preview of device targets in the read grant (#821); admin may propose a device read lease,
  device leases are admin-proposed only (#833); CLI lease to propose and approve a device read on
  the executor host (#835); typed spool record for device metadata (#812); collector spools one
  metadata record per device every cycle, also for sub-minute intervals (#822, #836).
- **Enrollment:** public `GET /enroll/<offer-id>` route outside the session gate (#841); enrollment
  offer and uf14 statements corrected in the docs (#824).
- **Wiring:** server feature registry, one file per feature instead of `main.go` (#829); software
  catalog fed from stored host results (#839).
- **Actions through hostrun:** write action classes (#825), `pci.inventory` and `gpu.status` (#826),
  `list_updates` simulation budget at its limit (#820), docker update and rollback as durable jobs
  (#810, follow-up test #827).
- **Ops agent (ADR 0016):** unit sandbox allows every path the shipped configuration names (#818).
- **End-to-end and integration tests:** Proxmox live values with the want-list and the collector's
  watcher on one handoff directory (#804); discovery from the form POST through runServer to the
  imported result (#806); flow key validation fuzz for the traffic store (#749).
- **Docs and decision papers:** status page update for 2026-11-21 (#817); integrity wiring paper,
  remaining review findings (#819).

### Landed in the last 7 days

Merged per day: 31 (11-13), 25 (11-16), 46 (11-17), about 45 (11-18), about 30 (11-19), 31
(11-20), 42 (11-21), 19 (11-22), 10 (11-23). Main themes: vulnerability agent and package inventory (ADR 0011);
ops agent (ADR 0016) complete and partly wired; wiring of one-step enrollment; maintainer decisions
for the remaining wiring gaps (ADR 0008, 0010, 0011, 0015); end-to-end and hostrun classifier tests.

## Wired in nebula-server (re-checked 2026-11-21 evening)

"Merged" in the table above means code is on `main`, not that the server uses it. Per area:

| Area | Wired in nebula-server? | Evidence |
| --- | --- | --- |
| Proxmox VE phase 1 (read-only pages, inventory, live values) | yes, the `/pve` pages and the PVE part of the chart; inventory retention runs beside the spool import (#786) | `cmd/nebula-server/main.go` (`pveStore`) |
| Proxmox VE guest power and snapshots | yes: `GuestPower: exec`, `GuestSnapshot: exec`; rendering not checked in a browser | `cmd/nebula-server/guestactions_wiring_test.go` |
| Proxmox VE backup now, migration, node reboot | no: executor code only; no RPC for them in `proto/nebula/executor/v1/executor.proto` | grep of `executor.proto`, 2026-11-21 |
| Traffic map API, page and connections tab | yes, mounted; end-to-end test (#798) | `cmd/nebula-server/main.go` |
| Attack paths (vulnerability management) | pages mounted, path computation not wired: the source reports no paths | `cmd/nebula-server/attackpaths.go` |
| Vulnerability inventory export | yes: served from the stored package inventory (#792) | PR #792 |
| Network devices (read path and device pages) | no: device read returns `Unimplemented` (ND-14); chain nx (decided 2026-11-21) closes this | `internal/executor/netdev_read.go`, `internal/web/ui/netdev.go` |
| Network security advisor (netreach, netadvisor, edl, reputation) | no: libraries exist, nothing outside their own packages imports them | `internal/netadvisor/`, `internal/edl/`, `internal/reputation/` |
| One-step enrollment | yes, the dialog: `Enroll: exec`, and `lazyExecutor` implements `ui.EnrollOffers` (#785); the executor installs the loaded configuration (#782); the public `GET /enroll/<offer-id>` route sits outside the session gate (#841). Offers are RPCs: the server role creates and relays them, `ListEnrollOffers` is admin only (`internal/executor/roles.go:77-86`). The NetBird option still waits for EN-16g | `cmd/nebula-server/main.go:584`, `cmd/nebula-server/executor_onestep.go` |
| Help assistant | panel routes mounted; the `internal/helpassist` libraries are not imported | `internal/web/ui/assistant.go`, `internal/web/ui/ui.go` |
| Ops agent | API wired; projection still gets empty findings and listeners (`opsNoFindings`); Ops tab not set (no `AssistantOps` in `cmd/nebula-server`) | `cmd/nebula-server/ops.go:237` |

Not re-checked in this pass: release 0.9, approval ergonomics, integrity monitoring.

## In progress

| Chain | Topic | Progress | Running now |
| --- | --- | --- | --- |
| iv | Package inventory for vulnerability management | 12/12 | complete (iv10f #838, iv12g #844); iv03g (#850) and iv05g (#830) merged; follow-ups iv05gf, iv13g queued |
| img | Image package read lease (ADR 0011 amendment 2026-11-23) | 4 of 9 numbered | merged img01 (#852), img01g (#854), img02 (#855), img04 (#856), img06 (#853); img03, img05, img07–img09 not yet merged |
| va | Security key for vulnerability decisions (ADR 0011 Q4) | 0/6 | queued; decision paper merged (#771) |
| ug | End-to-end tests through runServer | 11/12 at the last update | ug10g merged (#846); ug12f queued |
| uh | Ops agent live (sources, docs, deploy sandbox) | 7/11 | uh03 merged (#787); uh02 (connect stored findings) waits for a maintainer decision on the listener source; uh05, uh07, uh10 queued |
| uf | Wiring follow-ups and decision papers | 15/16 | uf08 (#848), uf09 (#840), uf10 (#849) merged, plus follow-up uf15g (#845); uf17 queued |
| ue | Read and control actions through the real hostrun classifier | merged: ue06h (#820), ue07 (#825), ue08 (#826), ue09f (#828) | – |
| nx | Network device read chain (ADR 0010, decided 2026-11-21) | 7/11 | no change since the last update; merged nx01 (#823), nx04 (#821), nx05 (#833), nx06 (#835), nx07 (#812), nx09 (#822); left: nx03, nx08f (#814), nx10, nx11 |
| pi | Image preparation wiring (ADR 0008 PV-03) | 1/14 | no change since the last update; pi03 merged (#816); pi01–pi14 queued (wait for ug12f) |
| fi | Integrity check wiring (ADR 0015 I1/I2) | 0/15 | queued (wait for ug12f and iv/ue follow-ups) |
| vf | Feed fixes from the live run | 4/4 | complete: vf04 merged (#842), optional feeds show "not configured", stale filter kept |

## Next

- **iv chain (complete, 12/12):** follow-ups iv05gf and iv13g remain.
- **Image chain (img):** img03, img05 and img07–img09 remain after the merged img01, img02, img04 and img06.
- **Ops agent live:** after the listener-source decision, connect the stored findings and listeners
  (uh02), then uh05 and uh10 (admin guide section 10.6).
- **Decision implementation:** nx (4 items left), pi (template preparation), fi (integrity
  check), va (security key); pi and fi wait for ug12f; uf17 remains.
- **Release 0.9 Beta:** beta.2 was planned after the iv chain and vf04; both are merged now.

## Blocked / needs maintainer

- **Ops agent listener source (uh02):** choose (a) a real per-host listener source, or (b) leave
  hosts with unknown listeners out of lab groups. Until then `cmd/nebula-server/ops.go:237` still
  passes `opsNoFindings`.
- **Read lease for `package.list_installed` on the reference lab:** needs approval; until then the
  vuln agent reports 0 subjects.

## Changelog

- **2026-11-23 (evening):** 20 PRs; img chain started (ADR 0011 amendment #852, wording #854, image
  lease propose and page #855, #856, image reads #853); iv03g (#850) and iv05g (#830) merged; vf04
  (#842) complete; uh03 doc chunk tests (#787); uf08, uf09, uf10 (#848, #840, #849) merged; reference
  lab upgraded and vuln agent timer on, still 0 subjects until a read lease is approved.
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
