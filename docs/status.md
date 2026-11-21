# Project status

Last updated 2026-11-21 (wiring re-check; previously 2026-11-20 (evening))

This page is the short, frequently updated view of where Nebula Operation Station stands. The
[README roadmap](../README.md#roadmap) gives the area overview; the ADRs in [docs/adr](adr/) hold
the decisions, and [docs/implementation](implementation/) the per-area plans.

## Where we are

| Area | ADR | State |
| --- | --- | --- |
| Release 0.9 (milestones 0–10) | – | code complete; release draft v0.9.0-beta.1 prepared on 2026-11-04, not yet published; running in the reference lab since then, formal integration run on clean VMs pending |
| Proxmox VE phase 1 / phase 2 | [0006](adr/0006-proxmox-integration.md) | phase 1 wired; phase 2 guest power and snapshot controls wired in nebula-server (`cmd/nebula-server/main.go:582-583`); backup, migration and node reboot executor code only, no RPC (previously: "not offered in the chart"; "phase 1 and phase 2 actions merged"); **amendment 2026-11-19: registry metadata may follow at most two same-host redirects for anonymous requests** (#717); registry metadata limits pinned (#698); pveapi/pvecollect package comments match the code (#714, #721); spool retry state and SSH telemetry mapping tested (#730, #729) |
| Approval ergonomics | [0007](adr/0007-approval-ergonomics.md) | merged; amendment 2026-11-17 (reject pending proposals) complete: spec, executor `RejectPending` RPC, UI (#687) and CLI `nebula reject` (#755), follow-ups (#753) |
| Guest provisioning | [0008](adr/0008-guest-provisioning.md) | merged; `packlock` testable with its exit codes covered (#715, PV-07) |
| Traffic map | [0009](adr/0009-traffic-map.md) | proposed; libraries, store and renderer merged; API and pages mounted in nebula-server (`cmd/nebula-server/main.go:639-648`, `:699`); `HostNet.Hop` fuzzed (#711) |
| Network devices | [0010](adr/0010-network-devices.md) | accepted; `NormalizePANOSConfig` fuzzed against its bounds (#709, #719) |
| Vulnerability management | [0011](adr/0011-vulnerability-management.md) | accepted; **first live run on 2026-11-20** found four integration bugs, all fixed the same day: token API refused by the browser origin check (#744), Debian feeds without a content date (#743), OSV Ubuntu over the download cap (#746), `package.list_installed` output not one JSON document (#752). The run also showed that **the server does not store package inventories yet** (the export is always empty) – chain iv01–iv10 closes that gap, decision paper merged (#764, #765), lease interval floor (#767). End-to-end tests over real HTTP (#763) and on a lab VM (#757) |
| Network security advisor | [0012](adr/0012-network-security-advisor.md) | accepted; pure libraries merged, none imported by nebula-server (not wired) |
| One-step enrollment | [0013](adr/0013-one-step-enrollment.md) | accepted; renderer and download limits tested; dialog not yet wired in nebula-server (#604) |
| Help assistant | [0014](adr/0014-help-assistant.md) | accepted; AS-09 libraries merged, service and wiring open (previously: "AS-09 parts 1–5 merged"; the parts are in `internal/helpassist`, not imported; the Assistant panel routes are mounted, `internal/web/ui/assistant.go:240-242`) (decoder #737, secret guard #736, limits #738, prompt assembly with a 16,000-token budget #739/#754, follow-up turns #745); shape builder (#740, #750) |
| Integrity monitoring | [0015](adr/0015-integrity-monitoring.md) | accepted; libraries merged |
| Ops agent | [0016](adr/0016-ops-agent.md) | accepted 2026-11-17; **implementation chain complete (27/27)** – today: suggestion event and trigger file (#713, #741), `settings_changed` reason budget (#732), security acceptance tests with a real bug fix: the agent rejected every fix item because of a `sha256:` digest prefix (#742, #756). **Open:** the Ops tab is not set in nebula-server (`internal/web/ui/ui.go:331`, G01 in `out/gaps.md`); projector sources (G02; the projection code is in `internal/opsfacts/project.go`, the sources are not verified here, and `out/gaps.md` is outside this clone) |

### Landed since the last update (31 PRs, 2026-11-19 19:00 to 2026-11-20 19:00)

- **Vulnerability management, live fixes:** origin check no longer blocks the token API (#744);
  Debian tracker, DSA and DLA content dates (#743); OSV Ubuntu download cap (#746);
  `package.list_installed` 1.1.0 returns one JSON document (#752); SQLITE_BUSY flake (#751).
- **Vulnerability inventory (new chain iv):** decision paper (#764, #765); the lease runner honours
  an action's own interval floor (#767). Storage, export and classifier follow (iv02–iv10).
- **End-to-end and integration tests:** vuln agent over real HTTP (#763); `package.list_installed`
  on a lab VM (#757); every read action through the real hostrun classifier (#758, #759, #761) –
  these found real parser bugs (service journal with one invalid UTF-8 line, Docker list cut
  inside a UTF-8 sequence), fixes in progress.
- **Ops agent (ADR 0016):** chain complete (#713, #741, #732, #742, #756).
- **Reject pending proposals:** UI (#687), CLI (#755), follow-ups (#753).
- **Help assistant (ADR 0014):** AS-09 parts 1–5 and the shape builder (#736–#740, #745, #750,
  #754).
- **Attack paths:** fuzzing of the CVSS v3 parser and of node rules (#747, #748); vuln agent test
  memory (#734).

### Landed in the last 7 days

Merged per day: 54 (11-12), 31 (11-13), 25 (11-16), 46 (11-17), about 45 (11-18), about 30
(11-19), 31 (11-20). Main themes: vulnerability agent and attack paths (ADR 0011); one-step enrollment
(ADR 0013); help assistant (ADR 0014); integrity monitoring (ADR 0015); a large fuzz and
limit-test wave; ops agent (ADR 0016) accepted and nearly all of its implementation chain merged.

## Wired in nebula-server (re-checked 2026-11-21)

"Merged" in the table above means code is on `main`, not that the server uses it. Per area:

| Area | Wired in nebula-server? | Evidence |
| --- | --- | --- |
| Proxmox VE phase 1 (read-only pages, inventory, live values) | yes, the `/pve` pages and the PVE part of the chart | `cmd/nebula-server/main.go:278` (`pveStore`), `:571` (`PVE: pveStore`) |
| Proxmox VE guest power and snapshots | yes, set in nebula-server: `GuestPower: exec`, `GuestSnapshot: exec` (`cmd/nebula-server/main.go:582-583`). The routes answer 404 only when the option is nil or, for snapshots, the PVE store lacks `ListSnapshots` (`internal/web/ui/guestactions.go:708-713`, `:1343-1350`; `internal/pveinventory/store.go:732`). The chart shows a Power section on running guests of active remotes (`guestactions.go:193-200`); rendering not checked in a browser | `cmd/nebula-server/guestactions_wiring_test.go` |
| Proxmox VE backup now, migration, node reboot | no: executor code only (`internal/executor/pve_guest_backup.go`, `pve_guest_migrate.go`, `pve_node_reboot.go`); no RPC for them in `proto/nebula/executor/v1/executor.proto` | grep of `executor.proto`, 2026-11-21 |
| Traffic map API, page and connections tab | yes, mounted | `cmd/nebula-server/main.go:639-648`, `:699` |
| Attack paths (vulnerability management) | pages mounted, path computation not wired: the source reports no paths | `cmd/nebula-server/main.go:653`, `cmd/nebula-server/attackpaths.go:19-26` |
| Network devices (read path and device pages) | no: the device read returns `Unimplemented` (ND-14); `NetDevPages` has no caller; `cmd/nebula-server` does not reference netdev | `internal/executor/netdev_read.go:112`, `internal/web/ui/netdev.go:146-160` |
| Network security advisor (netreach, netadvisor, edl, reputation) | no: libraries exist, nothing outside their own packages imports them | `internal/netadvisor/netadvisor.go`, `internal/edl/render.go`, `internal/reputation/match.go` |
| One-step enrollment | no: dialog not wired; the executor's enrollment offers are local start-up configuration, never served over RPC | `cmd/nebula-executor/main.go:82`, `:240-241`, `:269` |
| Help assistant | panel routes mounted; the `internal/helpassist` libraries are not imported | `internal/web/ui/assistant.go:240-242`, `internal/web/ui/ui.go:738` |
| Ops agent | the Ops tab is not set in nebula-server, so the tab is absent | `internal/web/ui/ui.go:331` (no caller sets `assistantOps`) |

Not re-checked in this pass: release 0.9, approval ergonomics, integrity monitoring, vulnerability
server side (other than attack paths).

## In progress

| Chain | Topic | Progress | Running now |
| --- | --- | --- | --- |
| iv | Package inventory for vulnerability management | 4/11 | iv02f (inventory store, review round), queued iv03–iv10 |
| vf | Feed fixes from the live run | 3/4 | vf03f (OSV Ubuntu content date without unpacking more than 4 GiB) |
| ue | Read actions through the real hostrun classifier | 3/9 | ue03f2, ue06f2 (fix rounds), queued ue05, ue07–ue09, ue02h |
| e2e | End-to-end tests | 2/3 | e2e02 (ops agent over real HTTP) |
| ud | Help assistant (AS-09, shape builder, fuzz) | most merged | ud09f, ud04h follow-ups |

## Next

- **iv chain:** store (iv02) → hook after `package.list_installed` (iv03) → immutable snapshots
  (iv04) → real export (iv05) → classifier (iv06) → maximum read age (iv08) → host tab (iv09) →
  end-to-end test from script output to a finding (iv10).
- **Lab:** the reference lab runs 4a1acc10 with the vuln agent installed (timer still off until a
  run produces real findings); a throwaway lab VM is now used for integration runs before every
  lab upgrade.
- **Release 0.9 Beta:** cut beta.2 after the iv chain and the open feed fix.

## Blocked / needs maintainer

- **Vulnerability inventory decisions (iv01):** retention (E1), maximum read age 24 h (E2),
  missing inventory held instead of closed (E3), no image inventory yet (E4), default read-lease
  interval 6 h – recommendations in `docs/implementation/vuln-inventory-decisions.md`, waiting for
  the maintainer.
- **ADR 0009 (traffic map):** still "proposed".
- **One-step enrollment:** dialog not wired in nebula-server (#604).
- **Dependabot:** #647, #648 wait for review.
- **Decision papers uf04, uf13, uf14:** the files do not exist in the tree yet (grep, 2026-11-21), so the open decisions are named here only.
- **Wiring gaps:** network device pages and read path, attack path computation, Ops tab, one-step dialog and help assistant service. See [wiring audit, re-check 2026-11-20](implementation/wiring-audit.md).

## Changelog

- **2026-11-20 (evening):** 31 PRs; first live run of the vuln agent: four integration bugs fixed
  and deployed, missing package inventory found (iv chain started); end-to-end and lab-VM tests;
  ops agent chain and reject-pending complete; help assistant AS-09 libraries merged, service and wiring open (previously: "help assistant AS-09 merged").
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
