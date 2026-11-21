# Project status

Last updated 2026-11-21 (evening; previously 2026-11-21 wiring re-check)

This page is the short, frequently updated view of where Nebula Operation Station stands. The
[README roadmap](../README.md#roadmap) gives the area overview; the ADRs in [docs/adr](adr/) hold
the decisions, and [docs/implementation](implementation/) the per-area plans.

## Where we are

| Area | ADR | State |
| --- | --- | --- |
| Release 0.9 (milestones 0–10) | – | code complete; release draft v0.9.0-beta.1 prepared on 2026-11-04, not yet published; running in the reference lab since then, formal integration run on clean VMs pending |
| Proxmox VE phase 1 / phase 2 | [0006](adr/0006-proxmox-integration.md) | phase 1 wired; PVE inventory retention now runs beside the spool import (#786); collector call timeout covers the read budget (#794); phase 2 guest power and snapshot controls wired in nebula-server; backup, migration and node reboot executor code only, no RPC |
| Approval ergonomics | [0007](adr/0007-approval-ergonomics.md) | merged; reject pending proposals complete (#687, #753, #755); read grants with network device targets compare those targets (#795) and need CLI approval in every mode (#813, rule A1-0b) |
| Guest provisioning | [0008](adr/0008-guest-provisioning.md) | merged; **amendment 2026-11-21: PV-03 wiring of `pve.image.prepare` decided** (#805, paper #772, #790); chain pi started, the release bundle now stages `image-catalog.json` and its signature (#816) |
| Traffic map | [0009](adr/0009-traffic-map.md) | proposed; API and pages mounted in nebula-server; end-to-end test from real `net.facts` output to the map API (#798) |
| Network devices | [0010](adr/0010-network-devices.md) | accepted; **amendment 2026-11-21: device read chain decided** – variant 1 (collector spools one metadata record per device), device lease only through the local CLI (#805, paper #784); collector probe fix (#796); chain nx started (#813) |
| Vulnerability management | [0011](adr/0011-vulnerability-management.md) | accepted; **package inventory now stored on the server** (#766, #777, #779, #793) and the `vuln-inventory-v1` export is served from it (#792); open-findings listing fix (#808); maintainer decisions recorded: inventory E1–E4 (#776), assertion binding variant A incl. `discard_hold` (#805, papers #771, #775); classifier against the inventory in review (#815) |
| Network security advisor | [0012](adr/0012-network-security-advisor.md) | accepted; pure libraries merged, none imported by nebula-server (not wired) |
| One-step enrollment | [0013](adr/0013-one-step-enrollment.md) | accepted; **dialog now switched on in nebula-server**: the executor installs the loaded enrollment configuration (#782) and the server relays the one-step RPCs (#785) |
| Help assistant | [0014](adr/0014-help-assistant.md) | accepted; AS-09 libraries merged, service and wiring open |
| Integrity monitoring | [0015](adr/0015-integrity-monitoring.md) | accepted; libraries merged; **amendment 2026-11-21: I1 status and I2 scan chain wiring decided**, `fim.scan` as a durable job (#805, paper #783); chain fi imported (0/15) |
| Ops agent | [0016](adr/0016-ops-agent.md) | accepted; implementation chain complete (27/27); finding and listener sources merged (#780) but `cmd/nebula-server/ops.go:237` still passes `opsNoFindings` – connecting them is ticket uh02; a run without work reports its status, exit codes pinned for systemd (#807); note size limit aligned, pinned CA tested over real TLS (#809); install hint fixed (#811); Ops tab still not set in nebula-server |

### Landed since the last update (42 PRs, 2026-11-20 19:00 to 2026-11-21 19:00)

- **Maintainer decisions (#805):** PV-03 image preparation, network device read chain, assertion
  binding for vuln decisions, integrity wiring; inventory decisions E1–E4 (#776). Decision
  papers: #771, #772, #775, #783, #784, #790.
- **Vulnerability inventory (chain iv):** store (#766), parse and store every
  `package.list_installed` result (#777), immutable snapshots (#779), limits and delete-rule
  tests (#793), export served from the inventory (#792), inventory decisions recorded (#776);
  SQLITE_BUSY flake (#791); osv-ubuntu archive caps from the measured file (#768).
- **Wiring:** one-step enrollment (#782, #785); PVE inventory retention (#786) and collector
  call timeout (#794); netdev collector under its own role (#796); ops finding and listener
  sources (#780); wiring guard that fails on internal packages without a production importer
  (#788); README and implementation notes say what is wired (#789).
- **Image preparation and release:** release stages the image catalog and its signature (#816).
- **Ops agent (ADR 0016):** open-findings count (#808), empty-run status (#807), client limits
  and pinned CA (#809), install hints (#811), candidate label (#781).
- **Security fixes:** read grants with network device targets (#795), device read grants need
  CLI approval in every mode (#813).
- **End-to-end and integration tests:** write operation from the HTTP form to the host script
  (#797), backup and restore (#800), read-only API token through runServer (#802), largest run
  results over the real gRPC limits (#801), traffic map (#798), ops agent over real HTTP (#770).
- **Hostrun classifier and parser fixes:** read actions through the real classifier (#773,
  #799), docker reads through hostrun (#760), journal lines with a bad entry (#774), heredoc
  bodies in help text (#778).

### Landed in the last 7 days

Merged per day: 31 (11-13), 25 (11-16), 46 (11-17), about 45 (11-18), about 30 (11-19), 31
(11-20), 42 (11-21). Main themes: vulnerability agent and package inventory (ADR 0011); ops agent
(ADR 0016) complete and partly wired; wiring of one-step enrollment; maintainer decisions for the
remaining wiring gaps (ADR 0008, 0010, 0011, 0015); end-to-end and hostrun classifier tests.

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
| One-step enrollment | yes, the dialog: `Enroll: exec`, and `lazyExecutor` implements `ui.EnrollOffers` (#785); the executor installs the loaded configuration (#782). The NetBird option still waits for EN-16g | `cmd/nebula-server/main.go:584`, `cmd/nebula-server/executor_onestep.go` |
| Help assistant | panel routes mounted; the `internal/helpassist` libraries are not imported | `internal/web/ui/assistant.go`, `internal/web/ui/ui.go` |
| Ops agent | API wired; projection still gets empty findings and listeners (`opsNoFindings`); Ops tab not set (no `AssistantOps` in `cmd/nebula-server`) | `cmd/nebula-server/ops.go:237` |

Not re-checked in this pass: release 0.9, approval ergonomics, integrity monitoring.

## In progress

| Chain | Topic | Progress | Running now |
| --- | --- | --- | --- |
| iv | Package inventory for vulnerability management | 7/12 | iv06 classifier against the inventory (#815, HIGH finding being fixed, prio 1); queued iv08–iv10, iv12; follow-ups iv03g, iv05g |
| va | Security key for vulnerability decisions (ADR 0011 Q4) | 0/6 | queued; decision paper merged (#771) |
| ug | End-to-end tests through runServer | 8/12 | fix round: ug07f (#810), ug13f2 (#804), ug14f (#806); queued ug12f (#803); ug10 merged (#801) |
| uh | Ops agent live (sources, docs, deploy sandbox) | 5/11 | fix round: uh11; queued uh02 (connect stored findings), uh03f (#787), uh05, uh07, uh10 |
| uf | Wiring follow-ups and decision papers | 9/16 | queued uf01 (feature registry), uf07–uf11, uf17, follow-ups uf13g, uf15g, uf16g |
| ue | Read and control actions through the real hostrun classifier | 6/9 | ue06h; queued ue07–ue09 |
| nx | Network device read chain (ADR 0010, decided 2026-11-21) | 1/11 | nx07f blocked (#812), nx08f queued (#814), nx01, nx03–nx06, nx09–nx11 queued |
| pi | Image preparation wiring (ADR 0008 PV-03) | 1/14 | template preparation; pi03 merged (#816); pi01–pi14 queued (wait for ug12f) |
| fi | Integrity check wiring (ADR 0015 I1/I2) | 0/15 | queued (wait for ug12f and iv/ue follow-ups) |
| vf | Feed fixes from the live run | 3/4 | vf04 queued ("not configured" instead of "stale") |

## Next

- **iv chain (critical path):** classifier fix iv06 (#815) → maximum read age (iv08) → host tab
  (iv09) → end-to-end test from script output to a finding (iv10); image inventories (iv12).
- **Ops agent live:** connect the stored findings to the projection (uh02), then uh05 and the
  admin guide section 10.6 (uh10).
- **Decision implementation:** nx (device read chain), pi (template preparation), fi (integrity
  check), va (security key); pi and fi wait for ug12f and the feature registry uf01.
- **Release 0.9 Beta:** cut beta.2 after the iv chain and vf04.

## Blocked / needs maintainer

- **nx07f (#812):** blocked – the local runner's permission layer refused `make test-deploy` and
  `make vuln` (govulncheck); everything else passes. Needs a run with permission or CI, then a
  review of the design choice (superseded metadata removed without a validity check).
- **#815 (iv06):** HIGH finding (kernel findings measured only at the newest read); fix round
  running. No merge with HIGH.
- **Vulnerability inventory, open questions Q1–Q5:** precedence of E1 over D5 and snapshot
  pinning (Q1), E1/E2 reading (Q2), classifier rule for image subjects without `image.packages`
  (Q3), image freshness (Q4) and lease digest parameter (Q5) – see
  [vuln-inventory-decisions.md](implementation/vuln-inventory-decisions.md). E1–E4 are decided
  (#776).
- **ADR 0009 (traffic map):** still "proposed".
- **Dependabot:** #647, #648 wait for review.
- **Wiring gaps:** network device pages and read path, attack path computation, Ops tab and
  projection sources, help assistant service. See [wiring audit](implementation/wiring-audit.md).

## Changelog

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
