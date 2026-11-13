# Production wiring audit (before the 0.9 lab run)

Read-only audit of the real deployment paths: `deploy/install.sh` (tarball),
`.deb` + `install.sh --from-package`, `deploy/quickstart/setup-nebula.sh`,
and the container image with `compose.yaml`. It looks for the gap class of
#278/#285: code that only ever ran with injected test policies or permissive
temp directories. Audited at commit `ff1aa11`.

**Status re-check: 2026-11-13, commit `6db6672c`.** The findings below
(WA-01 to WA-13, sections "Summary", "Findings in detail" and "Fix tickets")
describe the state at `ff1aa11`. The added Status column and the
"Status" lines under each finding give the state at the re-check commit, each
with its code evidence (file:line) and, where `git log` shows it, the PR. A
finding without such evidence stays `open` or `not verified`. The original GAP
text is kept as history ("previously: GAP").

## How to read this

- **OK**: production code path traced, no gap.
- **GAP**: a real install fails or lacks the feature. Each has one ticket in
  [Fix tickets](#fix-tickets).
- **Evidence**: every finding comes from reading the code at the cited lines.
  Nothing here was run on a real install: this environment has no root, no
  Docker daemon, and `systemctl` could not be run in the audit session. Where a
  failure depends on runtime behaviour of systemd, Docker or the kernel, the
  row says so, and [Not verified](#not-verified) lists what to check on the lab.

## Summary

The PVE path does not work end to end on any install, and the two git-checkout
or tarball install paths have their own stoppers.

| Ticket | Severity | Affects | One line | Status (2026-11-13) |
|---|---|---|---|---|
| WA-01 | blocker | all | The server never imports the PVE spool: no production caller of the importers | fixed: `cmd/nebula-server/main.go:419,423`, `pveimport.go:53-84`; PR #327 (previously: GAP) |
| WA-02 | blocker | all | The server calls admin-only `ListPVEAdminRemotes`, so no PVE read grant can be proposed | fixed: `internal/executions/readgrants_provider.go:152` calls `ListPVERemotes`; no caller of `ListPVEAdminRemotes` left in `internal/executions`; PR #317 (previously: GAP) |
| WA-03 | blocker | quickstart | `setup-nebula.sh` does not copy `nebula-pve-collector`; `install.sh` stops | fixed: `deploy/quickstart/setup-nebula.sh:199-201` copies every name in `deploy/quickstart/binaries.txt:11`; PR #318 (previously: GAP) |
| WA-04 | high | tarball, quickstart | `install.sh` installs and enables the unprovisioned iconfetch units | fixed: `deploy/install.sh:733-738` leaves them out, `:998-1003` removes leftovers; PR #320 (previously: GAP) |
| WA-05 | medium | all | Typed guest power and snapshots have no production client | decision needed: wired at `cmd/nebula-server/main.go:505-506`, server role may commit (`internal/executor/roles.go:198-203`); the decision cited in the comment at `main.go:500-504` must be confirmed; PR #356 (previously: GAP) |
| WA-06 | medium | container | Discovery relies on a file capability under `no-new-privileges` | open: `deploy/container/compose.yaml:77-80` and `deploy/container/Dockerfile:11-15` unchanged; `compose.yaml:15` still sets `no-new-privileges` |
| WA-07 | medium | all | No install path provides the built-in release bundle directory | open (partly): `.deb` creates it, `.goreleaser.yaml:181-183`; image, `deploy/container/Dockerfile:35`; tarball still missing (`install.sh` has no reference); PR #369 (previously: GAP) |
| WA-08 | medium | tarball, `.deb` | Upgrades do not restart `nebula-pve-collector` | fixed: `deploy/install.sh:665-670` (restart list) and `:1225-1244`; `.deb` hint `deploy/deb/postinst:196`; PR #329 (previously: GAP) |
| WA-09 | medium | tarball, quickstart | Upgrades never refresh changed unit files | fixed: `deploy/install.sh:778-791` (`units_manifest`), `:889` (`refresh_units`), called at `:990`; PR #332 (previously: GAP) |
| WA-10 | low | all | Private registry reads: authorizer unset, no client | decision needed: authorizer wired at `cmd/nebula-executor/registry_reads.go:28,47`, server client at `cmd/nebula-server/executor.go:482`; profile decision cited at `registry_reads.go:38-41`; PR #452 (previously: GAP) |
| WA-11 | low | tarball, quickstart | `uninstall.sh` leaves the collector binary and does not mention its user | fixed: binary list from `deploy/quickstart/binaries.txt` (`deploy/uninstall.sh:41,48`), user named at `:20,114`; PR #357 (previously: GAP) |
| WA-12 | low | tarball, `.deb`, quickstart | `install.sh` accepts NSS-only admin users the static executor cannot resolve | fixed: `deploy/install.sh:332-358` checks `/etc/passwd`; PR #360 (previously: GAP) |
| WA-13 | low | container | The collector container has a network, unlike its unit | fixed: `deploy/container/compose.yaml:97` (pve-collector `network_mode: none`); PR #357 (previously: GAP) |

WA-01 and WA-02 are one chain. Without WA-02 no grant exists, so `ReadPVE` is
refused and the collector has nothing to spool. Without WA-01 nothing it spools
reaches the pages. Fix both before any PVE lab run. The live values depend on
the same chain, because `ProposeProviderTelemetryGrant` needs both the stored
inventory and the remote listing (`internal/executions/readgrants_telemetry.go:252-256`).

## Peercred roles

`internal/peercred` knows three roles in production. `discovery` and `iconfetch`
hold no role and never touch the socket.

| Role | UID from (`resolveRoles`) | User created by | Status |
|---|---|---|---|
| `server` | `-server-user nebula-server` (`cmd/nebula-executor/main.go:266-276`) | `install.sh:208-211`; `Dockerfile:28` | OK |
| `admin` | `-admin-users` (`main.go:278-296`) | Existing users, validated at `install.sh:130-154`, group at `:229-231`; `Dockerfile:31` with `compose.yaml:34` | OK, except WA-12 |
| `pve-collector` | Default flag value (`main.go:63,298-323`); not passed by the drop-in (`install.sh:332-339`) or compose, default is correct | `install.sh:223-225`; `Dockerfile:30` | OK |

### RPC call sites against `MethodRoles`

Calls with a literal `&pb.XRequest` argument were matched against the table in
`internal/executor/roles.go`. Calls that pass a request variable are not covered
by this search. `TestMethodRolesCoverEveryRPC` (`roles_test.go:335`) covers table
completeness.

| Caller | Result | Status |
|---|---|---|
| Collector (`internal/pvecollect` poll and live watch) | Only `ListPVERemotes`, `ReadPVE`, `ListReadGrants`, all allowed (`roles.go:110,170,171`) | OK |
| CLI (`cmd/nebula`) | No server-only method called | OK |
| Server: `ListPVEAdminRemotes` | Admin-only (`roles.go:147`), called from `internal/executions/readgrants_provider.go:153` | **GAP WA-02** |
| Server UI: `CommitPVEGuestPower`, `CommitPVEGuestSnapshot` | Admin-only (`roles.go:156,160`), called from `internal/web/ui/guestactions.go:1051,1058`; unreachable today because the UI option is unset | **GAP WA-05** |

## Optional dependencies

### Executor (`cmd/nebula-executor`)

| Dependency | Unset behaviour | Wired | Status |
|---|---|---|---|
| `SetPveGuestPowerBindings` | Engine's own bindings | `main.go:183` | OK |
| `SetEventKey` | FailedPrecondition (`internal/executor/events.go:28`) | `main.go:184` | OK |
| `SetBackupDirs` | FailedPrecondition (`backup.go:39`); no provisioner (`pve_rpc.go:342`); batch members refused (`batch_hold.go:211`) | `main.go:185`, before `setupBatchAuthority` at `:195` | OK |
| `SetBuiltinTrust` | Unimplemented (`roles_trust.go:165`) | `builtin_trust.go:42`; failure is logged, not fatal (`:59-61`). Anchor `root-1` is real (`internal/release/rootkeys.txt:15`) | OK; bundle: **GAP WA-07** |
| `SetBatchAuthority` | Unimplemented (`roles_batch.go:29`) | `cmd/nebula-executor/batch.go:55` | OK |
| `EnableBatchExecution` | Unimplemented (`batch_dispatch.go:58`) | `batch.go:56` | OK |
| PVE mutation client and provisioner | FailedPrecondition (`pve_rpc.go:801,1146`) | Built lazily, never nil once data dir is set (`pve_rpc.go:93-96,341-352`) | OK |
| `ReadPVE` method table | Unimplemented (`pve_read.go:165`) | Nine methods mapped (`pve_read.go:51-61`), METRICS at `:161` | OK |
| `SetRegistryReadAuthorizer` | Every read FailedPrecondition (`registry_private.go:115-118,706-707`) | **Never called in production** | **GAP WA-10** (fails closed) |
| `SetJobConfig`, `SetVaultParams` | Production defaults (`service.go:141-142`) | Test-only by design | OK |

### Server (`cmd/nebula-server`)

| Dependency | Unset behaviour | Wired | Status |
|---|---|---|---|
| `ops.SetNotifier`, `SetRunbooks`, `SetModules` | Features off | `main.go:303,306,311` | OK |
| Batch planner and runner | Refused | `main.go:322-329`, gated at `:613-624` | OK |
| `ui.Options` except the two below | Hidden or read-only (`internal/web/ui/ui.go`) | `main.go:387-427`; `ServerIP` and `Now` are nil on purpose | OK |
| `ui.Options.GuestPower`, `GuestSnapshot` | Controls hidden, routes 404 (`ui.go:168-178`) | **Not set**; `lazyExecutor` has no such methods | **GAP WA-05** |
| PVE spool importer | Nothing imported | **Not started** | **GAP WA-01** |
| Guest NIC importer | Tier 2 data missing | **Not started** | **GAP WA-01** |
| Live handoff | Warned, retried | `live.go:278` | OK; root is the constant `live.go:37`, not `server.json` |
| Icon service | Icon routes 404 | Not set; documented (`cmd/nebula-server/software.go:29-31`, `docs/admin/guide.md`, section Icons; `docs/implementation/traffic-map.md:103`) | OK as a known limit; units: **GAP WA-04** |
| Read-only API | Disabled | `main.go:460-467` | OK |

## systemd units

| Unit | User/Group | Paths vs. what the binary writes | Hardening vs. start behaviour | Restart | Status |
|---|---|---|---|---|---|
| `nebula-executor.service` | `nebula-executor`, `nebula-rpc` supplementary (`:10-12`) | `StateDirectory` 0700 passes `fsguard.CheckPrivateDir`; `RuntimeDirectory` 0755 passes `peercred.Listen` (`peercred.go:289-294`) | `chgrp` of the socket works through group membership (`peercred.go:318`); no setgid chmod; `UMask=0077` overridden by explicit socket mode | `on-failure`; no start dependency | OK |
| `nebula-server.service` | `nebula-server`, `nebula-rpc` (`:13-16`) | `StateDirectory`; spool writes through drop-in `install.sh:360,363` | No chmod with setgid; `CapabilityBoundingSet=` empty is fine | `on-failure`; executor is lazy (`main.go:181-184`) so there is no retry dependency | OK; needs a write path for WA-01 |
| `nebula-pve-collector.service` | `nebula-pve-collector`, `nebula-rpc` (`:21-24`) | `ReadWritePaths=/var/lib/nebula/pve` exists before start (`install.sh:251`) | `RestrictSUIDSGID`: `ensureDirMode` skips chmod on exact modes (`spool.go:536-539`) and install provisions those modes; `writeAt` sets 0640 explicitly over `UMask=0077` (`spool.go:223`) | `on-failure`, `RestartSec=5s` | OK |
| `nebula-discovery.service`, `.path`, `.timer` | `nebula-discovery` | `ReadWritePaths` covers results; jobs read through group | `AmbientCapabilities=CAP_NET_RAW` matches `--privileged` (`internal/discoveryjob/job.go:261`); survives `NoNewPrivileges` as ambient, verified per `docs/implementation/m0.md` item 71 | oneshot | OK |
| `nebula-iconfetch*.{service,path,timer}` | `nebula-iconfetch` | User, group, spool, nft file and binary are provisioned by nothing (see WA-04) | Header says provision first (`nebula-iconfetch.service:6-20`) | oneshot | **GAP WA-04** |

The `.deb` ships only executor, server, discovery and collector units
(`.goreleaser.yaml:116-127`) and `--from-package` enables only those
(`install.sh:302`), so it is not affected by WA-04.

## Spool and state directories

| Path | Created by | Owner, mode | Code expects | Status |
|---|---|---|---|---|
| `/var/lib/nebula/executor` | `install.sh:239`, `Dockerfile:33` | executor 0700 | `fsguard.go:23-32` | OK |
| `.../executor/keys` | `Dockerfile:33`; else `main.go:124` | executor 0700 | `fsguard.EnsurePrivateDir` | OK |
| `.../executor/trust` | `trust.Open` at start | under data dir | writable by executor | OK |
| `/var/lib/nebula/server` | `install.sh:238`, `Dockerfile:34` | server 0750 | `server.db` | OK |
| `.../discovery/jobs` | `install.sh:245`, `Dockerfile:36` | server:discovery 2750 | files 0640, group by setgid (`discoveryjob/spool.go:58`) | OK; see [Not verified](#not-verified) for volumes |
| `.../discovery/results` | `install.sh:246`, `Dockerfile:37` | discovery:server 2750 | same | OK; same note |
| `.../pve` | `install.sh:251`, `Dockerfile:38` | collector:rpc 2750 | `spool.go:31` exact | OK |
| `.../pve/results`, `guestnet` | `install.sh:252,255`, `Dockerfile:39-40` | collector:rpc 2770 | `spool.go:32` exact | OK; no reader, WA-01 |
| `.../pve/requests` | `install.sh:260`, `Dockerfile:41` | collector:rpc 2770 | `live_spool.go:25` exact | OK |
| `.../pve/live` | `install.sh:261`, `Dockerfile:42` | collector:rpc 2750 | `live_spool.go:26` exact | OK |
| `/run/nebula` | `RuntimeDirectory`; `Dockerfile:43` | executor 0755 / 0750 group rpc | `peercred.go:289-294` | OK |
| `/var/lib/nebula/iconfetch` | Nobody | none | `nebula-iconfetch.service:10-12` | **GAP WA-04** |
| `/usr/share/nebula/release` | Nobody | none | `cmd/nebula-executor/builtin_trust.go:19` | **GAP WA-07** |

The `install_test.sh` provisioning checks are static (`:172-177`), and its real
runs need root, systemd and the tarball layout (`:207`), so CI exercises neither
WA-03 nor WA-04. CI does not call `install_test.sh` at all: `make test-deploy`
(`.github/workflows/ci.yml:37`) runs only `nebula-iconfetch_test.py` (`Makefile:28-29`).

## Container (compose)

| Service | UID, groups | Volumes vs. code | Status |
|---|---|---|---|
| `executor` | 10001, `group_add` 10010 (`compose.yaml:23-24`) | Data and socket volumes match. No path for the release bundle on a read-only root | OK; **GAP WA-07** |
| `server` | 10002, 10010 | Jobs, results `:ro`, requests, live `:ro`. **No `pve/results` or `guestnet` volume** (`:49-59`) | OK today; WA-01 needs them |
| `discovery` | 10003, `cap_add: [NET_RAW]` (`:64-68`) | Spool matches, `-watch` polling | **GAP WA-06** |
| `pve-collector` | 10004, 10010 (`:78-79`) | `ensureDirMode` group resolves to 10010 through `group_add` (`spool.go:490-505`) and matches the image | OK; **GAP WA-13** |

## Install paths

| Path | Finding | Status |
|---|---|---|
| `.deb` first install | `postinst` only prints; `--from-package` creates users, dirs, drop-ins, enables units; `deploy/systemd/` present for the check at `install.sh:199` (`.goreleaser.yaml:134-135`) | OK |
| `.deb` upgrade | Restart hint omits the collector (`postinst:30`) | **GAP WA-08** |
| Tarball first install | Binary lists complete (`install.sh:191,285`, `.goreleaser.yaml:19-89`) | **GAP WA-04** |
| Tarball upgrade | Units skipped if present; collector not restarted | **GAP WA-08, WA-09** |
| Quickstart | Copies four of five binaries | **GAP WA-03** |
| Container image | All five binaries (`Dockerfile:45`, `.goreleaser.yaml:147`) | OK |
| Uninstall | Collector binary left behind | **GAP WA-11** |

## Findings in detail

### WA-01: the server never imports the PVE spool

**Status (2026-11-13): fixed.** `cmd/nebula-server/main.go:419,423` starts
`newPVEImport` in the background; `pveimport.go:53-84` runs the `Importer` and
the `GuestNetImporter`; `compose.yaml:65-66` mounts server `results` and
`guestnet` writable. PR #327. previously: GAP.

Evidence: `pvecollect.OpenSpool` (`internal/pvecollect/spool.go:76`), `NewImporter`
(`importer.go:75`) and `NewGuestNetImporter` (`guestnet_import.go:64`) are called
only from tests. `IngestObservation` has one production caller, `importer.go:158`.
`cmd/nebula-server/main.go` creates `pveStore` (`:219`) but starts no importer.

A real install shows: empty `/pve` pages, an empty PVE section of the chart, and
no provider guest NIC data, while the collector reports success. Once grants work,
`results/` also grows by one file per remote per poll (`poll.go:224-229`), because
the only remover is the importer (`spool.go:430`, `importer.go:184`). `guestnet/`
stays bounded (`guestnet_spool.go:74`).

The fix needs more than a goroutine in `main.go`:

- `Spool.Remove` unlinks files (`spool.go:444`), but the unit keeps `results/`
  read-only (`install.sh:348-350`), and `install_test.sh:181` pins exactly two
  write paths. `spool.go:28-29` says the server may unlink. The two contradict.
- Compose has no `results` or `guestnet` volume for the server (`compose.yaml:49-59`).
- `server.json` has no PVE spool setting (`internal/serverconfig/config.go`).
- `docs/operator/proxmox.md:27,39` says the import is merged and that `ReadPVE`
  answers `Unimplemented`. The first is true only of the library, and the second
  is out of date (`internal/executor/pve_read.go`).

### WA-02: PVE read grants cannot be proposed

**Status (2026-11-13): fixed.** `internal/executions/readgrants_provider.go:152`
reads remotes through `ListPVERemotes`; `ListPVEAdminRemotes` has no caller
left in `internal/executions` (`grep`). `roles.go:162` still makes it admin-only,
as intended. PR #317. previously: GAP.

Evidence: `ProposeProviderReadGrant` (`internal/executions/readgrants_provider.go:212`),
`ProposeProviderTelemetryGrant` (`readgrants_telemetry.go:256`) and the binding
check (`readgrants_provider.go:365`) all call `ListPVEAdminRemotes`, which is
`{admin}` only (`internal/executor/roles.go:147`). `pve_rpc_test.go:39,52-55`
pins that denial. The tests that pass use a fake lister
(`readgrants_provider_test.go:37`) or a disconnected client
(`cmd/nebula-server/executor_test.go:40`), the same blind spot as #278.

There is no way around it: `ProposeReadGrant` is server-only (`roles.go:101`) and
`cmd/nebula` never calls it. Without a grant, `AuthorizeProviderRead` refuses every
read (`pve_read.go:264-272`).

A real install shows on the lease page (`internal/web/ui/leases_provider.go:209`):
"the executor's PVE remotes could not be listed", with
`provider read grant remotes code=PermissionDenied` in the server log and
`rpc_denied` in the executor log. The collector's polls fail.

The role table does not need to change. `ListPVERemotes` is allowed for the server
(`roles.go:170`) and returns state, trust pin, generation and
`read_credential_version` (`roles.go:281-282`). `providerTarget` only needs
`read_ref` to be non-empty (`readgrants_provider.go:178`), which that version
already covers (`roles.go:262-267`).

### WA-03: quickstart cannot reach a running install

**Status (2026-11-13): fixed.** `deploy/quickstart/setup-nebula.sh:199-201`
copies every name listed in `deploy/quickstart/binaries.txt` (line 11 is
`nebula-pve-collector`). PR #318. previously: GAP.

Evidence: `deploy/quickstart/setup-nebula.sh:185` copies `nebula nebula-server
nebula-executor nebula-discovery`. `install.sh:191-197` requires
`nebula-pve-collector` beside `deploy/` as well. `make build` puts it only in
`bin/` (`Makefile:18-19`). A real run stops at step 5 with
`install.sh: .../nebula-pve-collector not found`.

### WA-04: install.sh enables the unprovisioned iconfetch units

**Status (2026-11-13): fixed.** `deploy/install.sh:733-738` leaves the iconfetch
units out of the install and enable lists; `:998-1003` removes leftovers from
an earlier install. PR #320. previously: GAP.

Evidence: the unit loop globs all of `deploy/systemd/` (`install.sh:308-316`), so
the iconfetch units are installed, and the tarball carries them (`deploy/**`,
`.goreleaser.yaml:94-96`). The enable loop excludes only the executor and discovery
services (`install.sh:400-402`). Nothing provisions the binary (not in
`.goreleaser.yaml:19-89` or the `install.sh:285` list), the user, the groups, the
spool or `/etc/nebula/nebula-iconfetch.nft`: `install.sh` has no iconfetch reference.

`nebula-iconfetch-firewall.service` sorts first among the units `install.sh:401`
starts, and its `ExecStart` needs that missing nft file (`:28`). A failed start
makes `systemctl enable --now` exit non-zero, and `set -e` (`install.sh:37`) then
stops the script before `nebula-server`, the collector or the executor are enabled.

Not reproduced here: neither iconfetch service has an `[Install]` section, and
whether `enable --now` still starts such a unit depends on the systemd version.
If it does not, `install.sh` continues, and the `.timer`, which has `[Install]`,
fires the service, which fails on its dependency. Either way a real install gets
either an aborted script or failed units, on a feature that the server does not
use yet.

### WA-05: typed guest power and snapshots have no production client

**Status (2026-11-13): decision needed.** Wired: `cmd/nebula-server/main.go:505-506`
sets `GuestPower` and `GuestSnapshot`; `cmd/nebula-server/executor.go:179-199`
has the lazy methods; `internal/executor/roles.go:198-203` lets `server` commit.
The comment at `main.go:500-504` cites "decision WA-05 variant (a), 2026-11-07".
That decision record was not found in this check, so the status stays
`decision needed` until it is confirmed. PR #356. previously: GAP.

Evidence: `main.go:387-427` sets neither `GuestPower` nor `GuestSnapshot`.
`lazyExecutor` has neither set of methods, and `cmd/` has no reference to them.
Controls are hidden and `POST /pve/guests/power*` answers 404. Wiring the UI alone
would not work: the UI commits at `guestactions.go:1051,1058`, but commit is
admin-only and "the server can never commit" (`roles.go:151-156`). The design needs
a decision before the code: CLI commit, or a role change like provisioning
(`roles.go:161-168`).

### WA-06: discovery in a container

**Status (2026-11-13): open.** `deploy/container/compose.yaml:77-80` still claims
that `NET_RAW` makes the file capability work under `no-new-privileges`, and
`compose.yaml:15` still sets `no-new-privileges`. Not changed. previously: GAP.

Evidence: `compose.yaml:65-67` says `NET_RAW` makes the file capability work under
`no-new-privileges`, and `Dockerfile:15` sets it. `prctl(2)` documents the opposite:
with `no_new_privs`, file capabilities have no effect on `execve`. The container
runs as non-root 10003 (`:64`) with `no-new-privileges` (`:15`), and `nmap` always
gets `--privileged` (`internal/discoveryjob/job.go:261`). Expected on a real
install: scans end as `nmap failed: ...` in the job result. Not reproduced here, no
Docker daemon. `docs/implementation/m0.md` item 76 verified that the containers
start, not that a scan runs.

### WA-07: no install path provides the built-in bundle

**Status (2026-11-13): open (partly fixed).** The `.deb` creates
`/usr/share/nebula/release` (`.goreleaser.yaml:181-183`, PR #369); the container
image creates it (`deploy/container/Dockerfile:35`), and `compose.yaml:37-39`
documents a bind mount for it. The tarball path is still missing: `install.sh`
has no reference to `/usr/share/nebula/release`. previously: GAP.

Evidence: `-builtin-bundle-dir` defaults to `/usr/share/nebula/release`
(`cmd/nebula-executor/builtin_trust.go:19`). `.goreleaser.yaml:115-137`,
`install.sh` and `Dockerfile` do not create it. `docs/admin/guide.md:630-636`
requires the directory, and when it is missing the command fails and the web
banner says the trust status is unreachable (`internal/executor/roles_trust.go:274-278`).
An admin can create it by hand on a host. The compose executor cannot: its root is
read-only with no volume there (`compose.yaml:13,37-39`). Per-action
`nebula artifact trust` still works.

### WA-08: collector not restarted on upgrade

**Status (2026-11-13): fixed.** `deploy/install.sh:665-670` lists
`nebula-pve-collector.service` among the restart units, and `:1225-1244`
restarts it when binaries or the unit changed. The `.deb` hint at
`deploy/deb/postinst:196` names `nebula-pve-collector`. PR #329, follow-up #345.
previously: GAP.

Evidence: `install.sh:405-425` restarts only the server and executor. The postinst
hint names the same two (`deploy/deb/postinst:30`). The collector exits only on
failure, so it keeps running the old binary against the new executor.

### WA-09: tarball upgrades keep old units

**Status (2026-11-13): fixed.** `deploy/install.sh:778-791` keeps `units_manifest`
(shipped checksums); `:889` `refresh_units` replaces unedited units and keeps
edited ones with a warning; called at `:990`. PR #332. previously: GAP.

Evidence: `install.sh:310-311` skips any existing unit. That protects admin edits,
as documented (`:27-30`), but a shipped fix never arrives, for example the
collector's `RestartSec=5s`. The `.deb` is not affected: it replaces the units in
`/lib/systemd/system`.

### WA-10: private registry reads

**Status (2026-11-13): decision needed.** The authorizer is wired:
`cmd/nebula-executor/registry_reads.go:28,47` (`setupRegistryReads`). A server
client exists: `cmd/nebula-server/executor.go:482` (`ReadPrivateRegistry`) and
`internal/registrymeta/executor_reads.go`. The profile decision is cited at
`registry_reads.go:38-41`. The "never called" statement below is stale. The
open question is the one in the fix ticket: keep the RPCs with the profile, or
remove them. PR #452. previously: GAP.

Evidence: no production call of `SetRegistryReadAuthorizer`, no client in
`cmd/` or `internal/executorclient/client.go`. Fails closed, and the guide says
credentialed registries show as "unknown" (`docs/admin/guide.md:869-870`), so
nothing breaks on a real install. The RPCs are unreachable.

### WA-11: uninstall leaves collector behind

**Status (2026-11-13): fixed.** The binary list comes from
`deploy/quickstart/binaries.txt` (`deploy/uninstall.sh:41,48`), which includes
`nebula-pve-collector`; the header and the closing message name its user
(`:20,114`). PR #357. previously: GAP.

Evidence: the binary loop has four names (`deploy/uninstall.sh:74`); the header and
closing message omit the `nebula-pve-collector` user (`:17-20,81`).

### WA-12: NSS-only admin users

**Status (2026-11-13): fixed.** `deploy/install.sh:332-358` requires each admin
user to match a line in `/etc/passwd` (`grep`), and rejects NSS-only users.
PR #360. previously: GAP.

Evidence: `install.sh:143` validates with `getent`, which uses NSS. The executor
uses `user.Lookup` (`internal/peercred/peercred.go:332`), and all builds are
`CGO_ENABLED=0` (`.goreleaser.yaml:17`, `Makefile:19`), so Go reads only
`/etc/passwd`. An LDAP or SSSD admin passes the installer, then the executor exits
with `admin user "x": ...` and the start-limit stops it.

### WA-13: collector container network

**Status (2026-11-13): fixed.** `deploy/container/compose.yaml:97` sets
`network_mode: none` for `pve-collector` (also `:130` for `netdev-collector`).
PR #357. previously: GAP.

Evidence: `compose.yaml:81-83` says the default bridge is "unused", but it is still
attached. The unit grants `AF_UNIX` only (`nebula-pve-collector.service:58-60`) on
the same "no outbound network" basis.

## Not verified

Check these on the lab. They are not findings, because they rest on runtime
behaviour this audit could not observe.

1. **Setgid on named-volume roots.** `discovery-jobs`, `discovery-results`,
   `pve-requests` and `pve-live` are volume roots with mode 2xxx in the image.
   If Docker's first copy-up drops setgid at the root, server job files keep gid
   10002 and discovery (not a member) cannot read them, and the reverse for
   results. The collector would repair its own directories (`spool.go:540`), but
   discovery has no such repair. Check after first start:
   `docker compose exec server stat -c '%a %U:%G' /var/lib/nebula/discovery/jobs`
   (want `2750 nebula-server:nebula-discovery`).
2. **WA-04 outcome** on Debian 12's systemd: abort or failed units.
3. **WA-06** with one ARP or SYN scan in the discovery container.

## Fix tickets

| ID | Change | Paths | Protected | Size | Status (2026-11-13) |
|---|---|---|---|---|---|
| WA-01 | Start `Importer` and `GuestNetImporter` in the server; add a spool setting; grant unlink on `results/` and `guestnet/`; add compose volumes; correct `proxmox.md` | `cmd/nebula-server/`, `internal/serverconfig/`, `deploy/install.sh`, `deploy/install_test.sh`, `deploy/container/`, `docs/operator/proxmox.md` | no | M | fixed: `cmd/nebula-server/main.go:419,423`, `compose.yaml:65-66`; `docs/operator/proxmox.md:29-30,422-425` describes the import; PR #327 |
| WA-02 | Read remotes through `ListPVERemotes`; drop `lazyExecutor.ListPVEAdminRemotes`; add a test through the real role table | `internal/executions/readgrants_*.go`, `cmd/nebula-server/executor*.go` | no | S | fixed: `internal/executions/readgrants_provider.go:152`; PR #317 |
| WA-03 | Copy all five binaries, or take the list from one place | `deploy/quickstart/setup-nebula.sh` | no | S | fixed: `deploy/quickstart/setup-nebula.sh:199-201` reads `binaries.txt`; PR #318 |
| WA-04 | Install and enable an explicit unit list without iconfetch until the icon service is wired | `deploy/install.sh`, `deploy/install_test.sh` | no | S | fixed: `deploy/install.sh:733-738`, `:998-1003`; PR #320 |
| WA-05 | Decide commit path, then wire | `cmd/nebula-server/`, `internal/web/ui/`, plus `cmd/nebula/` or `internal/executor/roles.go` | **yes** | M | decision needed: wired at `cmd/nebula-server/main.go:505-506`, `roles.go:198-203`; decision to be confirmed (see Findings) |
| WA-06 | Scan-capable discovery container; correct the comment; threat model note | `deploy/container/`, `docs/threat-model.md` | **yes** (threat model) | S | open: `deploy/container/compose.yaml:77-80` unchanged |
| WA-07 | Ship or provision the bundle; add a compose volume | `.goreleaser.yaml`, `deploy/container/compose.yaml`, `docs/admin/guide.md` | no | M | open (partly): `.goreleaser.yaml:181-183`, `deploy/container/Dockerfile:35`; tarball missing |
| WA-08 | Restart the collector when binaries changed; extend the postinst hint | `deploy/install.sh`, `deploy/deb/postinst` | no | S | fixed: `deploy/install.sh:665-670`, `:1225-1244`; `deploy/deb/postinst:196`; PR #329 |
| WA-09 | Refresh unmodified units (compare against a stored checksum), or warn on drift | `deploy/install.sh` | no | M | fixed: `deploy/install.sh:778-791`, `:889`; PR #332 |
| WA-10 | Decide: wire a read-grant profile with a client, or remove the RPCs | `cmd/nebula-executor/`, `internal/executor/` | **yes** | M | decision needed: `cmd/nebula-executor/registry_reads.go:47` wires the authorizer, `cmd/nebula-server/executor.go:482` is the client; keep-or-remove still open; PR #452 |
| WA-11 | Add the binary and the user | `deploy/uninstall.sh` | no | S | fixed: `deploy/uninstall.sh:41,48`, `:20,114`; PR #357 |
| WA-12 | Validate admin users against `/etc/passwd`, like the executor | `deploy/install.sh`, `deploy/install_test.sh` | no | S | fixed: `deploy/install.sh:332-358`; PR #360 |
| WA-13 | `network_mode: none` for the collector | `deploy/container/compose.yaml` | no | S | fixed: `deploy/container/compose.yaml:97`; PR #357 |

Order for the lab run: WA-02 and WA-01 first, as PVE depends on both, then WA-03,
WA-04 and WA-06, then the rest. Add `install_test.sh` to CI with whichever of them
touches it first, so that its static checks run at all.
