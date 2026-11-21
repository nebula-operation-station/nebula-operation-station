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
   type exists, and the executor accepts a server-authored device lease. But
   no code path proposes one, and `ProposeReadGrant` does not check device
   targets against the registry (step 16). Without a lease every read is
   refused, which is the safe state.
3. **Server (ND-16).** The server never starts the importer, has no device
   rows (nothing creates them outside tests), and cannot list devices
   (its role is not allowed `ListNetDevices`). The importer would reject
   every record as `unknown_device` even if it ran.
4. **Pages (ND-19/ND-20).** The device page constructors exist and are
   tested, but nothing registers them on the server mux.

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
| 6 | Lease proposal and approval for a device read | **Missing producer**: `NetDeviceTargets` exists in the lease document; no non-test code sets it. The proposal RPC is open to the server only; the executor's validation accepts a device lease | `internal/permit/lease.go:178-181` (field), `:365` (`NetDeviceReadProfile` validated by `ParseReadGrant`); `internal/executor/roles.go:120` (`ProposeReadGrant`: `{server}` only), `:121` (`CommitReadGrant`: `{server}`), `:122` (`ListPendingReadGrants` and `:123` `ApproveReadGrantCLI`: `{admin}`); approval is only the CLI prompt at `cmd/nebula/readgrant.go:152`; nothing in `cmd/` or `internal/executions/` proposes a device lease |
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
information leaves the executor; (d) the trust that matters (reads and
leases) stays in the executor, so a forged device row gives no device
access. The cost is an extra spool record type and a staleness rule on the
device list. This is a recommendation; the owner decides.

## 5. Open question B: who proposes and releases the device read lease?

The executor already has the lease life cycle for other reads:
`ProposeReadGrant`, `CommitReadGrant`, `ApproveReadGrantCLI`, `ListReadGrants`
and `RevokeReadGrant` (`internal/executor/roles_read.go:97`, `:142`,
`:177`, `:193`, `:215`). Provider reads (PVE) are proposed by the server
(`internal/executions/readgrants_provider.go:200`, `ProposeProviderReadGrant`).
Both paths produce the same document type, which already has a
`NetDeviceTargets` field (`internal/permit/lease.go:181`).

### Variant B1: a local CLI (`nebula netdev lease …`)

- The admin proposes a lease for exactly one device, pin, credential
  version and read set; the CLI shows the preview; approval uses the
  executor's CLI approval (`ApproveReadGrantCLI`, `cmd/nebula/readgrant.go:152`).
- Matches ND-11, where credentials are also CLI-only, and keeps approval off
  the web server.
- Protected paths: `cmd/nebula/` (the verb), `internal/executor/netdev_admin.go`
  (if the verb's logic lives there), and `internal/executor/roles.go:120`.
  `ProposeReadGrant` is allowed to `server` only, so the admin needs either
  `admin` added to that role (this also lets the admin propose host and
  provider leases through the same RPC) or a new admin-only RPC (a protected
  `proto/` change plus `roles.go`). Either way one protected role change is
  needed. `internal/permit/` is not needed: `ParseReadGrant` already validates
  the device profile (`internal/permit/lease.go:365`).

### Variant B2: the web server proposes, the admin approves

- Follows the PVE provider pattern: the server proposes from registry data
  (`internal/executions/readgrants_provider.go:200`).
- The proposal path needs no new permission. The server may already call
  `ProposeReadGrant` (`roles.go:120`), and the executor accepts a
  server-authored device lease (`lease.go:365`). The server does not need a
  new permit or role change to propose.
- What is missing: (a) device targets in the server's view. The server has
  no device rows today (question A, variant 1 supplies them through the
  spool; variant 2 needs `roles.go:190`); (b) an approval surface. Approval
  is only `ApproveReadGrantCLI` behind the CLI prompt
  (`cmd/nebula/readgrant.go:152`). "Approve in the browser" needs a new web
  approval route and a new executor approval RPC (protected). With CLI
  approval, B2 adds no protected change of its own.
- Protected paths: none for the proposal path with CLI approval. For browser
  approval, the executor RPC is protected (`internal/executor/`). The web
  route itself sits in `internal/web/ui/` and is not protected, since only
  `internal/web/auth/` is on the list (`.github/protected-paths.txt`).

### Required for both variants: device-target check at proposal

`ProposeReadGrant` checks host and provider targets against the registry
(`roles_read.go:105-121`) but not `NetDeviceTargets`, so a device lease for
an unknown, tombstoned, blocked or stale device can be proposed today and is
refused only at spend time (`netdev_read.go:90-101`, `netdev_grant.go:170`).
This is required work before either variant ships. It adds a loop over
`NetDeviceTargets` in `ProposeReadGrant` that compares each device ID, pin and
credential version with the registry, the same way the PVE check does for
remotes. It is in `internal/executor/` (protected). It is ticket A1-0 in
section 8.

### Release

Release is the same for both: revoke with the existing `RevokeReadGrant`,
automatic staleness on re-pin, credential rotation or removal (already
enforced by `netdev_grant.go:30-31`), and expiry (7 days default, 30 days
maximum, ADR 0010 D4). The collector must treat "lease expired" as a
stop-and-report state for that device, not as a retry storm.

### Recommendation (for decision)

**Recommended: B1, local CLI, with CLI approval.** The reason is the
authority placement, not the path count. In B1 the admin types the exact
device, pin, credential version and read set into a tool that shows the
preview, so the target list is never computed by the web server. It also
matches the credential lifecycle (ND-11) and keeps approval off the web. The
server already has `ProposeReadGrant` for other reads, so "the server must
not author device leases" is a policy choice that the owner has to make
explicitly; it is not a limit of the code.

The protected-path count does not favour B1. B1 needs one protected role
change (`roles.go:120`) that B2 with CLI approval does not need. B2 with CLI
approval also does not need a new verb. The owner should weigh that against
the authority argument above. The cost of B1 is that the admin must use the
CLI to renew a lease; a 7-day default makes that a weekly task at most. This
is a recommendation; the owner decides.

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

1. `ReadNetDevice` (`internal/executor/netdev_read.go:75`) takes its
   redactor from the service. A nil redactor is an error at construction,
   and the handler checks for nil too.
2. The gate runs before the lease is spent. It must sit above
   `checkNetDeviceGrant` (`netdev_read.go:103`); a gate after the spend would
   burn lease budget on every refused read.
3. The redactor is set only through an explicit option that requires a
   non-nil `netdevredact` value. `cmd/nebula-executor` is the only caller
   that sets it. `NewService` (`internal/executor/service.go:174`) keeps its
   signature in this round.

Tests (in `internal/executor/`):

- `TestReadNetDeviceRefusesWithoutRedactorAndSpendsNoLease`: a valid request
  against an approved lease, with the service built without a redactor,
  returns `codes.FailedPrecondition`, and the lease's spend counter is
  unchanged afterwards.
- `TestNetDeviceReaderNeedsRedactor`: building the reader with a nil
  redactor returns an error that wraps a sentinel `ErrNetDevNoRedactor`.

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
| A1-0 | Device-target check in `ProposeReadGrant` (see section 5) | `internal/executor/roles_read.go` | **yes** | Unknown, tombstoned, blocked, stale-pin and wrong-generation device targets refused at proposal; valid target accepted |
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
the existing `ProposeReadGrant`. It needs no permit or role change for the
proposal path (see section 5). With CLI approval, B2 adds no further
protected change. With browser approval it adds an executor approval RPC
(**protected**). A1-0 and the device-target check apply to both.

### Cost of the variants (protected changes)

| Combination | Protected changes (ticket) |
| --- | --- |
| A1 + B1 | A1-0 (`roles_read.go`), A1-5 (`cmd/nebula`, `netdev_admin.go`, `roles.go:120`), A1-6 (executor I/O), A1-7 (`netdevredact`) |
| A2 + B2, CLI approval | A1-0, A2 (`roles.go:190`), A1-6, A1-7 |
| A1 + B2, CLI approval | A1-0, A1-6, A1-7 (no role or CLI change) |
| any + B2, browser approval | the above, plus an executor approval RPC and its `roles.go` entry |

The spool extension in A1 is unprotected, so it can move without waiting
for a maintainer. Variant A1 is not decided by counts either: it is the
choice that keeps the server out of device authority (section 4).

Earlier counts in this paper (three and four protected changes) missed the
role change for B1 and counted `internal/permit/` for B1 and B2, although the
permit already validates device leases. They are replaced by the table above.

## 9. Verification of this paper

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
