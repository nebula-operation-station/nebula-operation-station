# Project status

Last updated 2026-11-18 (evening)

This page is the short, frequently updated view of where Nebula Operation Station stands. The
[README roadmap](../README.md#roadmap) gives the area overview; the ADRs in [docs/adr](adr/) hold
the decisions, and [docs/implementation](implementation/) the per-area plans.

## Where we are

| Area | ADR | State |
| --- | --- | --- |
| Release 0.9 (milestones 0–10) | – | code complete; release draft v0.9.0-beta.1 prepared on 2026-11-04, not yet published; running in the reference lab since then, formal integration run on clean VMs pending |
| Proxmox VE phase 1 / phase 2 | [0006](adr/0006-proxmox-integration.md) | phase 1 merged; phase 2 actions merged; observation-contract limits (#701) and executor client wrapper tests (#702) landed; registry metadata limits in review (#698) |
| Approval ergonomics | [0007](adr/0007-approval-ergonomics.md) | merged; **amendment 2026-11-17: reject pending proposals** – spec (#665, #670) and executor `RejectPending` RPC (#682) merged, UI (#687) and CLI (op04b) open |
| Guest provisioning | [0008](adr/0008-guest-provisioning.md) | merged |
| Traffic map | [0009](adr/0009-traffic-map.md) | proposed; libraries, store and renderer merged |
| Network devices | [0010](adr/0010-network-devices.md) | accepted; textdiff boundary at MaxEdits pinned (#704) |
| Vulnerability management | [0011](adr/0011-vulnerability-management.md) | accepted; "fix with" decisions and tool-call parsing fuzzed (#690, #669), agent token never printed (#697) |
| Network security advisor | [0012](adr/0012-network-security-advisor.md) | accepted; pure libraries merged, netpolicy host/address rules fuzzed (#685) |
| One-step enrollment | [0013](adr/0013-one-step-enrollment.md) | accepted; renderer and download limits tested (#668); dialog not yet wired in nebula-server (#604) |
| Help assistant | [0014](adr/0014-help-assistant.md) | accepted; admin guide embedded and indexed next to the handbook (#686), shell-word tokenizer and V3 matching (#683), placeholder class table (#672), mdsafe linearity fixes (#660, #680); status table in [help-assistant](implementation/help-assistant.md) (#678) |
| Integrity monitoring | [0015](adr/0015-integrity-monitoring.md) | accepted; libraries merged |
| Ops agent | [0016](adr/0016-ops-agent.md) | accepted 2026-11-17; **implementation 18/26 tickets merged** – API (#666), agent oneshot (#688), Assistant panel with Help and Ops tabs (#667), admin questions (#700), notifications (#675, #681), hardened systemd units (#694) |

### Landed since the last update (41 PRs, 2026-11-17 19:00 to 2026-11-18 19:00)

- **Ops agent (ADR 0016):** `/api/v1/ops` work list, config, notes and status (#666, AG-15);
  `nebula-ops-agent` oneshot with one LLM call per work item (#688, AG-16); Assistant panel with
  Help and Ops tabs and fix suggestion cards (#667, AG-17); admin questions in the Ops tab (#700,
  AG-22); every sent or held-back event in the notification log (#675, AG-05); lease.expiring,
  lease.run_failed and the daily digest (#681, AG-07); hardened agent unit, timer and path unit
  (#694, AG-21); notification log hardening (#662, #671, #693).
- **Approval ergonomics:** reject pending proposals – ADR 0007 amendment and spec (#665, #670),
  executor `RejectPending` RPC (#682).
- **Operations / inventory:** abort staged rollouts from the overview (#674); primary and alternate
  endpoints per host in the web UI (#642) and SSH failover to alternate endpoints (#673).
- **Help assistant (ADR 0014):** #660, #672, #678, #680, #683, #686.
- **Backup:** refusal paths of `backup.Restore` covered, services stay stopped when undo fails (#696).
- **Tests (ty wave 7/7, ua wave 6/7):** events (#663), runbooks (#676), ipam (#677), enroll (#668),
  vulnagent (#669), llmclient decoder (#684), pvetransport (#691), netpolicy (#685), vulnfix (#690),
  PVE observation limits (#701), executor wrappers (#702), textdiff (#704), sshsig fixture (#664),
  icon service data race (#689); fuzz targets for untrusted input now run in `make fuzz` (#692);
  fuzz inventory aligned with the code (#699).
- **Dependencies:** golang-x group (#649).

### Landed in the last 7 days

Merged per day: 27 (11-10), 60 (11-11), 54 (11-12), 31 (11-13), 25 (11-16), 46 (11-17), about
45 (11-18). Main themes: network devices (ADR 0010); vulnerability agent and attack paths
(ADR 0011); reachability and rule checks (ADR 0012); one-step enrollment (ADR 0013); help assistant
(ADR 0014); integrity monitoring (ADR 0015); a large fuzz and limit-test wave; ops agent (ADR 0016)
accepted and most of its implementation chain merged.

## In progress

| Chain | Topic | Progress | Running now |
| --- | --- | --- | --- |
| ag | Ops agent (ADR 0016) | 18/26 | ag18f (#695, prefill origin), ag23 (answer admin questions), ag07h (lease/digest follow-ups); queued: ag19f (#659), ag06f (#679), ag05h, ag20, ag24–ag26f |
| op | Reject pending proposals / abort rollouts | 3/4 | op04f (#687, UI) and op04b (CLI + server forwarding) queued |
| ua | Limit tests and backup follow-ups | 6/7 | ua04g (#698, registry metadata limits), ua02h (restore follow-ups, touches the handbook) |
| ty | Limit and fuzz tests, third wave | 7/7 | done |
| ep | Primary and alternate endpoints per host | 2/2 | done (#642, #673) |
| tw | Fuzz and edge tests, second wave | done | – |

## Next

- **ag chain:** ag18f → ag26f (operator docs #703, must match the merged code); ag07h → ag19f and
  ag20; ag20 → ag24 (security acceptance); ag18 + ag19 → ag25 (browser tests); ag06f → ag05h.
- **op04:** UI (#687) after ag18f releases its paths; CLI `nebula reject` (op04b).
- **Dependabot:** #647 (buf-action 1.7.0), #648 (upload-artifact v7) wait for review.
- **Release 0.9 Beta:** publish the draft (or cut beta.2 from current main) after the integration run on clean VMs.

## Blocked / needs maintainer

- **Registry redirects (ADR 0006, #698):** the ADR says "disable redirects", the code follows up
  to 2 redirects to the same resource for anonymous requests. Decide: change the code to 0
  redirects, or amend ADR 0006. ua04g only documents the deviation.
- **Protected PRs:** #703 (ops agent operator docs) and #679 (notifications list) touch protected
  paths and need the maintainer merge once their fix rounds are green.
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

- **2026-11-18 (evening):** 41 PRs; ag chain 18/26 (API, agent oneshot, Assistant panel, admin
  questions, units); reject-pending amendment and RPC merged (op 3/4); ep and ty chains done;
  ua wave 6/7; registry redirect decision opened.
- **2026-11-17 (evening):** ADR 0016 accepted (#640); ag chain 11/26 merged; tw wave done; lg01
  merged (#655); ty wave (7 tickets) imported; op01 re-cut as op01b.
- **2026-11-17:** status page created (window: last 7 days). Fuzzing wave, integrity libraries,
  vulnerability findings end to end, ADR 0012 libraries; ADR 0016 ops agent proposed (#637) and
  its 26-ticket chain imported.
