# Project status

Last updated 2026-11-19 (evening)

This page is the short, frequently updated view of where Nebula Operation Station stands. The
[README roadmap](../README.md#roadmap) gives the area overview; the ADRs in [docs/adr](adr/) hold
the decisions, and [docs/implementation](implementation/) the per-area plans.

## Where we are

| Area | ADR | State |
| --- | --- | --- |
| Release 0.9 (milestones 0–10) | – | code complete; release draft v0.9.0-beta.1 prepared on 2026-11-04, not yet published; running in the reference lab since then, formal integration run on clean VMs pending |
| Proxmox VE phase 1 / phase 2 | [0006](adr/0006-proxmox-integration.md) | phase 1 and phase 2 actions merged; **amendment 2026-11-19: registry metadata may follow at most two same-host redirects for anonymous requests** (#717); registry metadata limits pinned (#698); pveapi/pvecollect package comments match the code (#714, #721); spool retry state and SSH telemetry mapping tested (#730, #729) |
| Approval ergonomics | [0007](adr/0007-approval-ergonomics.md) | merged; amendment 2026-11-17 (reject pending proposals): spec and executor `RejectPending` RPC merged (#665, #670, #682), UI (#687) and CLI (op04b) open |
| Guest provisioning | [0008](adr/0008-guest-provisioning.md) | merged; `packlock` testable with its exit codes covered (#715, PV-07) |
| Traffic map | [0009](adr/0009-traffic-map.md) | proposed; libraries, store and renderer merged; `HostNet.Hop` fuzzed (#711) |
| Network devices | [0010](adr/0010-network-devices.md) | accepted; `NormalizePANOSConfig` fuzzed against its bounds (#709, #719) |
| Vulnerability management | [0011](adr/0011-vulnerability-management.md) | accepted; export conformance table checked (#716); vuln agent snapshot view and batch packer limits tested – the packer now counts HTML-escaped bytes (#725, #724); attack-path heap checked against a sorted reference (#731) |
| Network security advisor | [0012](adr/0012-network-security-advisor.md) | accepted; pure libraries merged |
| One-step enrollment | [0013](adr/0013-one-step-enrollment.md) | accepted; renderer and download limits tested; dialog not yet wired in nebula-server (#604) |
| Help assistant | [0014](adr/0014-help-assistant.md) | accepted; status table re-checked for AS-03 and AS-05 (#728); assistant service AS-09 (ud01–ud05) and the AS-05 shape builder (ud06) started |
| Integrity monitoring | [0015](adr/0015-integrity-monitoring.md) | accepted; libraries merged |
| Ops agent | [0016](adr/0016-ops-agent.md) | accepted 2026-11-17; **implementation 24/27 tickets merged** – today: admin questions answered with one LLM call (#708, #718), settings page (#659), notifications list and inbox follow-ups (#679, #726), digest holds and server wiring of the notifications page (#723), prefill origin (#695), browser tests (#722), operator docs (#703, #720) |

### Landed since the last update (31 PRs, 2026-11-18 19:00 to 2026-11-19 19:00)

- **Ops agent (ADR 0016):** settings with fresh assertion, audit and `settings_changed` event
  (#659, AG-19); notifications list from the notification log (#679, AG-06) and inbox follow-ups
  for a hanging executor (#726); prefilled forms carry a server-checked origin (#695, AG-18);
  admin questions answered with one LLM call (#708, AG-23) and the question work-item contract
  (#718); lease watch follow-ups (#707); digest holds recorded and the notifications page wired in
  the server (#723); browser tests for the Ops tab (#722, AG-25); operator documentation
  (#703, #720, AG-26).
- **Proxmox VE (ADR 0006):** registry redirect decision resolved by an ADR amendment (#717);
  registry metadata limits (#698); package comments (#714, #721); pvecollect spool retry and SSH
  telemetry fuzz (#730, #729).
- **Vulnerability management (ADR 0011, uc wave 7/8):** export conformance table (#716), snapshot
  view (#725), batch packer at the D5 limits with an HTML-escaping fix (#724), attack-path heap
  (#731).
- **Tests and fuzzing:** PAN-OS config (#709, #719), `HostNet.Hop` (#711), container definition
  and registry client (#710), icon resampler (#712), `packlock` (#715), backup restore follow-ups
  (#706).
- **Docs:** fuzz inventory and developer guide (#727), getting-started notifications (#733), help
  assistant status table (#728).

### Landed in the last 7 days

Merged per day: 54 (11-12), 31 (11-13), 25 (11-16), 46 (11-17), about 45 (11-18), about 30
(11-19). Main themes: vulnerability agent and attack paths (ADR 0011); one-step enrollment
(ADR 0013); help assistant (ADR 0014); integrity monitoring (ADR 0015); a large fuzz and
limit-test wave; ops agent (ADR 0016) accepted and nearly all of its implementation chain merged.

## In progress

| Chain | Topic | Progress | Running now |
| --- | --- | --- | --- |
| ag | Ops agent (ADR 0016) | 24/27 | ag20f (#713, suggestion event and agent trigger file); queued: ag27 (trigger file in the server state directory), ag24 (security acceptance), ag19hf2 (#732, `settings_changed` reason budget, last round) |
| op | Reject pending proposals / abort rollouts | 3/4 | op04f (#687, UI) and op04b (CLI) queued behind ag20f |
| uc | Vulnerability agent and attack-path tests | 7/8 | uc08f (#734, vulnagent run test under 1 GiB memory) |
| ud | Help assistant service (AS-09), shape builder, fuzz | 0/9 | ud01 (strict answer decoder), ud02 (secret-pattern refusal); queued ud03–ud09 |
| ua, ty, ep, tw | Limit and fuzz waves, endpoints | done | – |

## Next

- **ag chain:** ag20f → ag27 → ag24 (security acceptance, needs ag16, ag18, ag20); ag19hf2 after
  ag20f releases `cmd/nebula-server/`.
- **op04:** UI (#687) and CLI `nebula reject` (op04b) after ag20f; op04f is large for one run and
  may need to be split.
- **ud chain:** AS-09 parts 1–5 (decoder, secret guard, limits, prompt assembly, follow-up
  turns), then the AS-05 shape builder (ud06) and fuzz tickets ud07–ud09.
- **Dependabot:** #647 (buf-action 1.7.0), #648 (upload-artifact v7) wait for review.
- **Release 0.9 Beta:** publish the draft (or cut beta.2 from current main) after the integration
  run on clean VMs.

## Blocked / needs maintainer

- **CI runner:** a test job hung for more than 70 minutes on the self-hosted runner on 2026-11-19
  and could not be cancelled; one runner instance was offline and the runner disk was reported
  low. Please check the CI runner host.
- **Protected PRs:** none open at the moment (#713, #687, #732, #734 touch no protected paths).
- **Read-lease refusal reason (#655):** the response names only the level; the risk-policy class
  stays in the audit log (m0 item 20). Showing the class to the admin would need a spec change –
  open question.
- **ADR 0009 (traffic map):** still "proposed", awaiting the maintainer's decision on the open
  questions, although large parts are merged.
- **One-step enrollment:** dialog is documented as not wired in nebula-server (#604); decide whether
  wiring is a ticket for 0.9 or later.
- **README roadmap row "Handbook, FAQ and in-app help: planned"** looks stale (handbook and admin
  guide are embedded in the help assistant since #686); please confirm the wording.

## Changelog

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
