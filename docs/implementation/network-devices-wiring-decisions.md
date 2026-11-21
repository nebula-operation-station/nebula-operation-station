# Network devices: wiring decisions for the device read chain

Status: decision paper (no code). Scope: the read chain of ADR 0010 (phase 1,
read only) from the device to the operator's page, tickets ND-14 to ND-20 of
`network-devices.md`. Owner decisions are open until recorded in the ADR
decision log. Nothing in this paper changes behaviour.

Related: `network-devices.md` (plan and rule numbers N1 to N8b),
`docs/adr/0010-network-devices.md` (D4), `wiring-audit.md` (findings WA-01 to
WA-13). `wiring-audit.md` has no entry for the device chain. WA-01 and WA-02
describe the same break pattern for the PVE chain (importer not started, no
grant proposed), which is the precedent for points 3 and 2 below.

## 1. Summary

The chain *device → executor → collector → spool → server → page* is broken
at four places. Each place is small on its own; together they mean that no
network device data reaches an operator today, and that the installed
collector can never be enabled safely (see section 3).

1. **Executor (ND-13/ND-14 boundary).** `ReadNetDevice` checks the request,
   the device and the read lease, spends the lease, and then answers
   `Unimplemented`. No device I/O exists.
2. **Lease (ND-13 producer).** The lease check exists, the lease document
   type exists, and the executor accepts a server-authored device lease. No
   web or CLI path proposes one, and `ProposeReadGrant` does not check device
   targets against the registry (step 16). Approval does not show device
   targets either (section 5). Without an approved lease every read is
   refused, which is the safe state.
3. **Server (ND-16).** The server never starts the importer, has no device
   rows (nothing creates them outside tests), and cannot list devices
   (its role is not allowed `ListNetDevices`). The importer would reject
   every record as `unknown_device` even if it ran.
4. **Pages (ND-19/ND-20).** The device page constructors exist and are
   tested, but nothing registers them on the server mux.

**Security gap in the current tree (priority 1).** The missing device-target
check at proposal (step 16) is exploitable today in default mode. The
server role may propose a device lease (`internal/executor/roles.go:120`),
and the executor accepts it. In default mode the browser approves any grant
the web server has previewed, with a WebAuthn assertion
(`internal/permit/lease.go:682-690`, `:737-758`; web handler
`internal/web/ui/leases_new.go:395` and `:459-466`). The admin is shown no
device targets (section 5). No web or CLI path creates a device lease today,
so the exploit needs a server that proposes one through the web handler's
flow: a compromised server process, or a future server code path. Fix A1-0
(section 8) and the approval rule of section 5 before any device variant
ships; neither depends on the other variants.

## 2. Current chain, with evidence

Every path is relative to the repository root. Line numbers were checked
against the tree at the time of writing; re-check them if the file moved.

| # | Step | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Collector starts its poller and the spool | Works (fake client in tests; real executor client wired) | `cmd/nebula-netdev-collector/main.go:92-93` (spool), `:159-169` (`netdevcollect.Poller` run) |
| 2 | Collector lists devices and reads them over the executor socket | Wired, but every read is refused or unimplemented | `internal/netdevcollect/poll.go:266-273` (cycle), `:432-470` (per-read fetch) |
| 3 | Executor validates the request and the device | Works | `internal/executor/netdev_read.go:75-102` (validation, registry lookup, family check) |
| 4 | Executor checks the device read lease and spends it | Works; denies every read without an approved lease | `internal/executor/netdev_read.go:103`, `internal/executor/netdev_grant.go:24-35`, `:215-220` (required profile), `:256` (`checkNetDeviceGrant`) |
| 5 | Executor performs the device read | **Missing**: answers `Unimplemented` after the spend | `internal/executor/netdev_read.go:110-112` |
| 6 | Lease proposal and approval for a device read | **Missing producer**: `NetDeviceTargets` exists in the lease document; no non-test code sets it. The proposal RPC is open to the server only; the executor's validation accepts a device lease | `internal/permit/lease.go:178-181` (field), `:365` (`NetDeviceReadProfile` validated by `ParseReadGrant`); `internal/executor/roles.go:120` (`ProposeReadGrant`: `{server}` only), `:121` (`CommitReadGrant`: `{server}`), `:122` (`ListPendingReadGrants` and `:123` `ApproveReadGrantCLI`: `{admin}`). Approval depends on the mode: in default mode `CommitReadGrant` verifies a browser WebAuthn assertion for any pending grant (`internal/permit/lease.go:682-690` sets the challenge; `:737-758` verifies it; the web route is `internal/web/ui/leases_new.go:466`); in hardened mode (`cmd/nebula-executor/main.go:157-158`) the requirement is `RequireCLI`, `CommitReadGrant` refuses (`lease.go:746-748`) and only the CLI prompt (`cmd/nebula/readgrant.go:152`) approves. No device-specific rule exists. Nothing in `cmd/` or `internal/executions/` proposes a device lease |
| 7 | Spool accepts only the closed set of typed read names | Works; the set is closed, enforced by `readLimits` | `internal/netdevcollect/spool.go:69` (`readLimits`, the closed set); names at `:43-63` |
| 16 | Proposal checks every target against the registry | **Missing for devices**: `ProposeReadGrant` checks host and provider targets against the registry, not device targets, so a device lease for an unknown, tombstoned or stale device is accepted at proposal and refused only at spend time | `internal/executor/roles_read.go:97-122` (checks at `:105-121` cover `doc.Targets` and `doc.ProviderTargets`; no loop over `NetDeviceTargets`); device lookup exists at `internal/executor/netdev_read.go:90` |
| 8 | Server starts the importer | **Missing**: `Importer` is constructed in tests only | `internal/netdevcollect/import.go:150` (type), `:205` (`Run`), `:101` (`ErrImporterNotConfigured`); no caller outside `import_test.go` |
| 9 | Importer maps a record to a known device | Would reject every record | `internal/netdevcollect/import.go:89` (`unknown_device`), `:505-508` (`ErrDeviceNotFound` → reject) |
| 10 | Store has device rows | **Missing**: `UpsertDevice` has no production caller | `internal/netdevinventory/store.go:286`; callers are `_test.go` files and `test/security/netdev_test.go` |
| 11 | Server role may list devices | **Not allowed**: `ListNetDevices` is open to admin and the collector only | `internal/executor/roles.go:190` (`{admin, peercred.RoleNetDevCollector}`), `:193` (comment: the server calls neither), `:197` (`ReadNetDevice`: collector and admin) |
| 12 | Server mounts the device pages | **Missing**: no registration; `cmd/nebula-server/main.go` has no reference to netdev | `internal/web/ui/netdev.go:146` (`NetDevPages` type), `:160` (constructor), `:182` (`Register`); `internal/web/ui/netdev_firewall.go:88` (`NetDevFirewallPage` type), `:96` (constructor), `:113` (`Register`); only callers are tests and `test/security/netdev_test.go` |
| 13 | Credential-free packages used by the chain | **Not imported**: `cbscli`, `cbsparse`, `panapi` have no importer outside their own package | grep for their import paths over `*.go`: no hits outside the packages |
| 14 | Redaction before the executor returns data (ADR 0010 D4: "returns sanitized records") | **Missing**: `internal/netdevredact/` does not exist (ND-07) | `docs/adr/0010-network-devices.md:275-277`; `network-devices.md:83` |
| 15 | Lab verification of vendor claims | **Missing**: `docs/implementation/network-devices-lab.md` does not exist (ND-03; rule N5) | `network-devices.md:27` (N5), `:73` (ND-03) |

Consequence: steps 1 to 4 run today, so the collector spends a lease
check on each read, but a read can only fail. Step 5 is the first step that
needs a device, and it must not be implemented before rule N5 (step 15) and
redaction (step 14) are in place.

## 3. Installed but not enabled

`deploy/install.sh:984-990` says that `nebula-netdev-collector.service`
(ND-15) is installed and never enabled or started by the script, in either
mode. The reason given there: nothing imports or removes its spool before
the server import (ND-16) is installed, so an enabled collector would fill
the disk. The admin is expected to enable it with
`systemctl enable --now nebula-netdev-collector` once the import is in
place and the devices are registered. The unit is listed in `tarball_units`
only (`deploy/install.sh:991-999`); the enable loop skips it.

This is the right default and this paper does not change it. The unit must
stay disabled until step 8 (import) and step 10 (rows) of section 2 exist.

## 4. Open question A: how does the server learn which devices exist?

The server needs device rows (identity, family, trust generation) to accept
any spooled record. ADR 0010 D4 says only "`nebula-server` imports them"
(`docs/adr/0010-network-devices.md:273-280`) and does not say where the
device list comes from.

### Variant 1: the collector spools one metadata record per device

The collector already lists devices from the executor (`ListNetDeviceInfos`,
`internal/netdevcollect/poll.go:71`), and the collector role is allowed
`ListNetDevices` (`internal/executor/roles.go:190`). It writes one record
per device into the spool; the server imports it like any other read.

- Needs a new typed read name in the closed set (`spool.go:43-63`) and in
  the importer's name table (`import.go:178`). Both are unprotected.
- The server gets no new authority. It still has no executor connection for
  this path.
- The device rows reflect the executor registry as of the last collector
  cycle. Staleness must be shown on the page (ND-16 already has this rule).
- Risk: a compromised collector can write device rows the executor never
  registered. It cannot read a device or widen a lease, because reads stay
  executor-side and the lease check (`netdev_grant.go:256`) does not depend
  on server rows. The server must still show such rows as "reported by
  collector", not as confirmed devices; the confirmed link is an explicit
  admin act (ND-18 part 2).

### Variant 2: the server role gets `ListNetDevices`

`internal/executor/roles.go:190` gets the server role added. The server
then reads the registry directly and creates rows from it.

- A protected path (`internal/executor/`): needs a maintainer review.
- Gives the server a new read of registry metadata over the executor
  socket. The metadata contains no secrets (the RPC comment at
  `roles.go:177-178` says so), but the server gains a permission it does not
  have today, and its importer then depends on the executor being up.
- No change to the spool or the collector.

### Recommendation (for decision)

**Recommended: Variant 1.** Reasons: (a) the server keeps the role it has
(it imports spool records and holds no device authority, as ADR 0006
intends for the collector pattern); (b) no change to a protected path for
this question; (c) the collector already reads this list, so no new
information leaves the executor; (d) the trust that matters for reads stays
in the executor, so a forged device row gives no device read access. It can
still steer what the server proposes under B2 (section 5, "Interaction of
B2 with A1"), so the proposal check (A1-0) and the device approval rule
(A1-0b) are needed in every variant, not only in this one. The cost is an
extra spool record type and a staleness rule on the device list. This is a
recommendation; the owner decides.

## 5. Open question B: who proposes and releases the device read lease?

The executor already has the lease life cycle for other reads:
`ProposeReadGrant`, `CommitReadGrant`, `ApproveReadGrantCLI`, `ListReadGrants`
and `RevokeReadGrant` (`internal/executor/roles_read.go:97`, `:142`,
`:177`, `:193`, `:215`). Provider reads (PVE) are proposed by the server
(`internal/executions/readgrants_provider.go:200`, `ProposeProviderReadGrant`).
Both paths produce the same document type, which already has a
`NetDeviceTargets` field (`internal/permit/lease.go:181`).

### Approval paths in the current code (corrected in round 2)

Approval depends on the executor mode, not on the variant. Round 1 said that
browser approval would need a new executor RPC; that was wrong.

- **Default mode.** `ProposeReadGrant` records any read grant, device grants
  included, with a WebAuthn challenge (`internal/permit/lease.go:682-690`).
  The browser approves it through the server's `CommitReadGrant` call
  (`lease.go:737-758`, `internal/executor/roles.go:121`). The web route
  commits only a grant that the same user previewed through the web handler
  (`internal/web/ui/leases_new.go:395` stores the preview, `:459-466`
  commits it). The authority itself does not check who proposed the grant,
  so a CLI-proposed digest could still be committed by the server role; the
  web UI does not offer it. CLI approval (`ApproveReadGrantCLI`,
  `roles.go:123`) also exists.
- **Hardened mode** (`-hardened`, `cmd/nebula-executor/main.go:157-158`).
  Every read grant gets `RequireCLI` (`lease.go:683-684`), `CommitReadGrant`
  refuses (`lease.go:746-748`), and only the CLI prompt
  (`cmd/nebula/readgrant.go:152`) approves. This covers host and PVE leases
  too.
- **Device targets are shown on neither surface.** The browser preview is
  built by `previewFromResponse` (`internal/executions/readgrants_propose.go:381`),
  which copies hosts, providers and actions but not `NetDeviceTargets`. The
  CLI preview (`cmd/nebula/readgrant.go`, `printReadGrant`) prints hosts and
  providers and has no device line. An approver sees neither the device list
  nor the device reads.
- **No device-specific rule exists.** Device approval can be kept CLI-only
  only with a new rule (ticket A1-0b). The rule must be enforced in
  `CommitReadGrant` (`lease.go:737`), not only at proposal: the `Requirement`
  in the proposal response is advisory, and `CommitReadGrant` does not check
  it today.

"B2 with CLI approval" is therefore not what the code offers. It is either
hardened mode (an existing setting with a wider effect, see B2) or B2 plus
ticket A1-0b.

### Variant B1: a local CLI (`nebula netdev lease …`)

- The admin proposes a lease for exactly one device, pin, credential
  version and read set; the CLI shows the preview; approval uses the
  executor's CLI approval (`ApproveReadGrantCLI`, `cmd/nebula/readgrant.go:152`).
- Matches ND-11, where credentials are also CLI-only. Approval stays off the
  browser only with ticket A1-0b (or in hardened mode). Without it, the
  authority still accepts a commit for a CLI-proposed digest from the server
  role, because `CommitReadGrant` does not check the proposer. The web UI
  does not offer that commit, but the rule belongs in the authority.
- Protected paths: `cmd/nebula/` (the verb), `internal/executor/netdev_admin.go`
  (if the verb's logic lives there), and `internal/executor/roles.go:120`.
  `ProposeReadGrant` is allowed to `server` only, so the admin needs either
  `admin` added to that role (this also lets the admin propose host and
  provider leases through the same RPC) or a new admin-only RPC (a protected
  `proto/` change plus `roles.go`). Either way one protected role change is
  needed. `internal/permit/lease.go` is needed for the device approval rule
  (A1-0b) unless hardened mode is used; `ParseReadGrant` already validates
  the device profile (`lease.go:365`), so the rule is the only permit change.
  The device list in the CLI preview (`cmd/nebula/readgrant.go`) is also
  needed; it is in the protected `cmd/nebula/` tree.

### Variant B2: the web server proposes, the admin approves

- Follows the PVE provider pattern: the server proposes from registry data
  (`internal/executions/readgrants_provider.go:200`).
- The proposal path needs no new permission. The server may already call
  `ProposeReadGrant` (`roles.go:120`), and the executor accepts a
  server-authored device lease (`lease.go:365`). The server does not need a
  new permit or role change to propose.
- What is missing: (a) device targets in the server's view. The server has
  no device rows today (question A, variant 1 supplies them through the
  spool; variant 2 needs `roles.go:190`); (b) device targets in the approval
  preview (both surfaces, see above); (c) a device CLI-only rule (A1-0b), if
  approval should stay off the browser.
- Approval in B2 in default mode is the browser. That is the exposed case
  described in section 1: the server proposes and the browser approves. The
  preview fix and the device rule are therefore preconditions for B2, not
  follow-ups.
- Hardened mode keeps B2 approval CLI-only without new code. Its effect is
  wider: every read grant needs the CLI, so the browser approves no read
  lease at all, including host and PVE leases. This is an operational cost,
  not a device-only rule.
- Protected paths: the proposal path needs none. `internal/executions/`, the
  web route and templates (`internal/web/ui/`) are not protected, since only
  `internal/web/auth/` is on the list (`.github/protected-paths.txt`). The
  device rule (A1-0b) is in `internal/permit/` (protected).

### Interaction of B2 with A1: the server computes targets from collector rows

Under A1 the device rows in the server store come from the collector's spool,
and a compromised collector can write any row (section 4, variant 1). Under
B2 the server builds the lease targets from those rows. A forged row is then
no longer only a row: it can make the server propose a lease for a real
device the admin did not choose.

Section 4 says that a forged row gives no device access. That holds for
reads: the spend-time check uses the executor's registry (`netdev_grant.go:256`).
It does not hold for proposal content:

- A1-0 (device-target check at proposal) refuses unknown, tombstoned, blocked,
  stale-pin and wrong-generation targets. It does not refuse a registered,
  unblocked device whose identity matches. A compromised collector can name
  such a device, because it lists the registry anyway.
- So under A1 + B2 the collector steers which real devices and reads the
  server proposes, and only the approver can stop it. The approver sees
  neither the device list nor the reads today (section 5, approval paths).
  That is why A1-0b (device list in both previews, and a CLI-only device
  rule) is required for A1 + B2, not optional.
- A2 + B2 avoids this interaction. There the server reads the registry
  directly (`roles.go:190`) and not collector rows, at the cost of the
  protected role change.

### Required for all variants: device-target check at proposal (A1-0) and approval rule (A1-0b)

`ProposeReadGrant` checks host and provider targets against the registry
(`roles_read.go:105-121`) but not `NetDeviceTargets`, so a device lease for
an unknown, tombstoned, blocked or stale device is accepted at proposal today
and refused only at spend time (`netdev_read.go:90-101`, `netdev_grant.go:170`).
This is an open security gap in the current tree, not a step for later (see
the priority note in section 1). Ticket A1-0 adds a loop over
`NetDeviceTargets` in `ProposeReadGrant` that compares each device ID, pin and
credential version with the registry, the same way the PVE check does for
remotes. It is in `internal/executor/` (protected).

Ticket A1-0b covers approval. It adds a device rule in `internal/permit/lease.go`
(`ProposeReadGrant` at `:682-690` and `CommitReadGrant` at `:737`): any grant
with `NetDeviceTargets` gets `RequireCLI`, and `CommitReadGrant` refuses it
in default mode too. It also renders the device list and the device reads in
both previews (`internal/executions/readgrants_propose.go:381` and
`cmd/nebula/readgrant.go`). The device rule (`internal/permit/`) and the CLI
preview (`cmd/nebula/`) are protected; the browser preview is not. Hardened
mode can replace the rule, at the cost in section 5.

### Release

Release is the same for both: revoke with the existing `RevokeReadGrant`,
automatic staleness on re-pin, credential rotation or removal (already
enforced by `netdev_grant.go:30-31`), and expiry (7 days default, 30 days
maximum, ADR 0010 D4). The collector must treat "lease expired" as a
stop-and-report state for that device, not as a retry storm.

### Recommendation (for decision)

**Recommended: B1, local CLI, with the device approval rule (A1-0b).** The
reason is the authority placement. In B1 the admin types the exact device,
pin, credential version and read set into a tool that shows the preview, so
the target list is never computed by the web server. It also matches the
credential lifecycle (ND-11). The server already has `ProposeReadGrant` for
other reads, so "the server must not author device leases" is a policy
choice that the owner has to make explicitly; it is not a limit of the code.

B1 is not "off the web" by itself: without A1-0b, or hardened mode, the
authority accepts a commit for an admin-proposed device lease from the
server role (see approval paths). A1-0b is required for B1 as well.

The protected-path count does not clearly favour either side. B1 needs the
protected role change at `roles.go:120` (admin may propose), a new CLI verb
and the device rule. B2 with A1 needs the device rule and the preview, and
the interaction in section 5 is a reason against it. The owner should weigh
the authority argument above first. The cost of B1 is that the admin must
use the CLI to renew a lease; a 7-day default makes that a weekly task at
most. This is a recommendation; the owner decides.

## 6. Open question C: ordering of ND-14, ND-07 and ND-03

- **ND-03 (lab note, rule N5)** has to exist before any vendor claim marked
  *verify* is used by code. Today the lab note does not exist. The parsers
  (ND-06, ND-09) and the redaction allowlists (ND-07, decision Q13) are built
  from its vocabulary.
- **ND-07 (redaction, `internal/netdevredact/`)** is the only place where
  configuration secrets are removed. ADR 0010 D4 says the executor returns
  sanitized records only. The collector spools whatever the executor returns
  (the spool write at `internal/netdevcollect/poll.go:485`; the payload is
  built in `payloadFor` at `:492`), so before real device data flows,
  redaction must be in place.
- **ND-14 (collector and spool)** is already implemented as a poller and a
  spool with a fake client. It can be exercised without a device.

### Options

| Option | Order | Effect |
| --- | --- | --- |
| C1 | ND-03 → ND-07 → executor device I/O (ND-05/06/08/09 and step 5) → ND-14 real reads → ND-16 import | Safest. No device data before redaction and the lab facts. Longest path before the first page. |
| C2 | ND-03 and ND-07 in parallel with ND-16/ND-18 (store, import, staleness) using fixtures; no real device read before ND-07 is merged | Keeps the server side moving. Needs a rule that the executor refuses real reads until ND-07 is present. |
| C3 | ND-14 real reads first, ND-07 later | **Not recommended.** It spools unredacted configuration into the collector's spool, which is outside the executor. |

### Recommendation (for decision)

**Recommended: C2.** ND-03 and ND-07 are not optional for any real read,
so they come first on the device side. The server side (store, import,
staleness, pages) can proceed on fixtures in parallel, because it does not
touch a device. The executor must refuse any real read until ND-07 has
landed. The gate must be fail-closed in code, not by a build tag. A build
tag can be left out of a release build with no runtime signal, and the
default build would then have a real reader. The concrete design:

1. The redactor is a field of the service. `NewService`
   (`internal/executor/service.go:174`) keeps its signature and does not
   take one, so a service without a redactor is valid to build; it is the
   default state. The only constructor that sets the field is an option,
   `WithNetDevRedactor(r)`, which returns an error that wraps
   `ErrNetDevNoRedactor` when `r` is nil. That is the construction-time
   check. The option returns an error rather than panicking, because
   AGENTS.md rule 9 forbids panics in library code (`NewService` already
   panics on its own nil arguments; this paper does not change that).
2. `ReadNetDevice` (`internal/executor/netdev_read.go:75`) checks the field
   again on every call, before the lease is spent. A nil field returns
   `codes.FailedPrecondition`. This handler check is the fail-closed
   backstop for a service built without the option; it is the only check
   that covers that case at run time.
3. The gate runs before the lease is spent. It must sit above
   `checkNetDeviceGrant` (`netdev_read.go:103`); a gate after the spend would
   burn lease budget on every refused read.
4. `cmd/nebula-executor` is the only caller that passes the option. The
   option is set in `cmd/nebula-executor`, not in `NewService`.

Tests (in `internal/executor/`):

- `TestReadNetDeviceRefusesWithoutRedactorAndSpendsNoLease`: a valid request
  against an approved lease, with the service built without the option
  (point 2 covers this case), returns `codes.FailedPrecondition`, and the
  lease's spend counter is unchanged afterwards.
- `TestWithNetDevRedactorRejectsNil`: passing a nil redactor to the option
  returns an error that wraps `ErrNetDevNoRedactor` (point 1).

Both tests are needed before ND-14 lands and must still pass when the real
redactor is wired.

## 7. Pages with an empty state (quick win?)

Mounting `NetDevPages` and `NetDevFirewallPage` now, with the empty store,
would show an empty device list. It gives no value:

- The store has no rows (step 10), so every page would show "no devices",
  which looks like a real answer. ND-04 requires "unavailable" to be
  distinct from "empty"; a page that cannot tell them apart would break that
  rule.
- It unblocks nothing: no test on the real path can pass until the import
  and the lease exist.
- It adds routes and a CSP surface that have to be reviewed again later.

Recommendation: do not mount the pages before the import (step 8) and rows
(step 10) exist. The pages should be mounted in the same change that makes
the first real row appear.

## 8. Ticket list by variant

Pflichttest (required test) for all variants: one end-to-end test over the
real path. Executor RPC against a fake device on loopback, collector
spool, server import into the store, HTTP request to the page with the
expected escaped text. Put it where the packages allow (for example in
`cmd/nebula-server/`); a test under `test/security/` or `test/integration/`
is a protected path and needs a maintainer.

### Variant A1 (device metadata via collector) + B1 (CLI lease)

| Ticket | Change | Paths | Protected | Test |
| --- | --- | --- | --- | --- |
| A1-0 | Device-target check in `ProposeReadGrant` (open gap now, see section 1 and 5) | `internal/executor/roles_read.go` | **yes** | Unknown, tombstoned, blocked, stale-pin and wrong-generation device targets refused at proposal; valid target accepted |
| A1-0b | Approval rule for device grants: `RequireCLI` at proposal and refusal at `CommitReadGrant` in default mode; device list and reads in both previews | `internal/permit/lease.go`; `cmd/nebula/readgrant.go`; `internal/executions/readgrants_propose.go` and the web template (unprotected) | **yes** (permit, CLI) | A device grant gets `RequireCLI`; `CommitReadGrant` refuses its digest in default mode; browser and CLI previews list every device and read; host and PVE grants unchanged |
| A1-1 | New spool read name for device metadata; importer table | `internal/netdevcollect/spool.go`, `import.go` | no | Closed set rejects unknown names; metadata record round trip |
| A1-2 | Collector writes one metadata record per listed device | `internal/netdevcollect/poll.go`, `cmd/nebula-netdev-collector/` | no | Fake client: one record per device, none for blocked/tombstoned |
| A1-3 | Server starts the importer, with a staleness rule | `cmd/nebula-server/`, `internal/netdevcollect/import.go` | no | Import creates rows; unknown device rejected; stale shown |
| A1-4 | Store device rows from import only | `internal/netdevinventory/store.go` | no | No row without a spool record; trust generation regression refused |
| A1-5 | Lease proposal and approval CLI, and admin proposal role | `cmd/nebula/netdev.go`, `internal/executor/netdev_admin.go`, `internal/executor/roles.go:120` | **yes** | Preview shows exact device and read set; approval needed; expiry; admin-only proposal |
| A1-6 | Executor device I/O (step 5) | `internal/executor/netdev_read.go`, `internal/cbscli/`, `internal/panapi/` | **yes** (executor) | Loopback fake device; limits from ADR D3 |
| A1-7 | Redaction (ND-07) before A1-6 reaches the collector | `internal/netdevredact/` (new; add to protected list per ND-02) | **yes** once listed | Allowlist, fail-closed, HMAC fingerprints |
| A1-8 | Mount pages in the server | `cmd/nebula-server/`, `internal/web/ui/netdev*.go` | no | HTTP test: escaped text, CSP header, admin only |
| A1-9 | End-to-end test (Pflichttest) | `cmd/nebula-server/` test | no | The real-path test above |

### Variant A2 (server `ListNetDevices`) + B2 (web lease)

Differences from A1: A2-1 replaces A1-1 and A1-2 (no spool change), and
adds `internal/executor/roles.go:190` (**protected**) for the server role.
B2 adds server lease wiring in `cmd/nebula-server/` (unprotected) that calls
the existing `ProposeReadGrant`. The proposal path needs no permit or role
change (see section 5). Approval is not a separate RPC: `CommitReadGrant`
already exists (round 1 wrongly said a new executor RPC was needed). What
B2 does need is A1-0 and A1-0b, because in default mode the browser approves
the server's proposal. A1-0 and A1-0b apply to both A1 and A2.

### Cost of the variants (protected changes)

| Combination | Protected changes (ticket) |
| --- | --- |
| A1 + B1 | A1-0 (`roles_read.go`), A1-0b (`lease.go`, CLI preview), A1-5 (`cmd/nebula`, `netdev_admin.go`, `roles.go:120`), A1-6 (executor I/O), A1-7 (`netdevredact`) |
| A1 + B2 | A1-0, A1-0b, A1-6, A1-7 (no role change; the section 5 interaction applies, so the admin must see the preview) |
| A2 + B2 | A1-0, A1-0b, A2 (`roles.go:190`), A1-6, A1-7 (no registry-row interaction) |
| hardened mode, any variant | A1-0, A1-6, A1-7; A1-0b is replaced by the mode, at the cost in section 5 (no read lease approval in the browser at all) |

The table lists the device rule (A1-0b) for every variant that keeps device
approval off the browser. Without it, no combination is safe in default mode.

The spool extension in A1 is unprotected, so it can move without waiting
for a maintainer. Variant A1 is not decided by counts either: it is the
choice that keeps the server out of device authority (section 4).

Earlier counts in this paper (three and four protected changes) missed the
role change for B1 and counted `internal/permit/` for B1 and B2. Round 2 adds
the device rule (A1-0b) in `internal/permit/` for every variant that keeps
approval off the browser; `ParseReadGrant` still validates the device profile
without a change. The table above replaces the earlier counts.

## 9. Verification of this paper

- Round 2 re-checked the approval anchors against the tree: `lease.go:682-690`,
  `:737-758`, `:746-748`, `roles.go:120-123`, `cmd/nebula-executor/main.go:157-158`,
  `readgrants_propose.go:381` (no `NetDeviceTargets` copied),
  `leases_new.go:466`, `cmd/nebula/readgrant.go:152` (no device line in
  `printReadGrant`), `service.go:174`, `netdev_read.go:90-101`,
  `netdev_grant.go:256`. Rows of section 2 not listed here were not re-read
  in round 2.
- Round 1 of review re-checked these anchors against the tree:
  `roles.go:120-123`, `roles_read.go:97-122`, `lease.go:365`,
  `readgrant.go:152`, `poll.go:485`, `poll.go:492`, `spool.go:69`,
  `netdev.go:146/160`, `netdev_firewall.go:88/96`. Other anchors were not
  re-read in round 1 and should be checked when the file moves.
- No device addresses, firmware releases or credentials appear in this
  paper. Exact releases belong in the private lab notes (ND-03).
- This is a document only: no Go, shell or YAML file is changed, so the
  Go test suite does not apply. `make check` is run by CI on the pull
  request.
