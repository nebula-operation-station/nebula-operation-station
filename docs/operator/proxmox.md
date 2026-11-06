# Proxmox VE operator guide

This guide covers the Proxmox VE (PVE) integration as merged in ADR 0006
(`docs/adr/0006-proxmox-integration.md`). It describes what the integration
does today, how to create the least-privilege PVE API tokens, how to manage
remotes with the `nebula` CLI, what the collector reads, how to read the
staleness labels in the web UI, and how to troubleshoot common problems.

Features that are designed but **not merged yet** are marked **planned**.

## What the integration does today

The integration gives Nebula Operation Station a **read-only** view of one or
more Proxmox VE environments:

- A **remote** is exactly one PVE cluster with its ordered node API endpoints,
  or one standalone PVE host with a single endpoint. VPN routing does not
  create another remote.
- The **executor** is the only component that talks to PVE. It owns the
  approved endpoints, the TLS trust pin, the credential references and the
  remote state. The tokens are envelope-encrypted in the executor vault and
  are decrypted only there.
- **`nebula-pve-collector`** runs as its own Unix user and schedules typed
  read requests over the executor socket. It never talks to a PVE endpoint
  itself, opens no network listener, touches no database and holds no
  credentials. It writes sanitized observations to a spool directory.
- **`nebula-server`** imports the spool into its own database and renders the
  PVE pages. It starts the import itself, reads the spool every 30 seconds and
  removes each file once it has processed it. It never performs PVE API calls.
- The web UI shows a remote list (`/pve`) and a detail page per remote
  (`/pve/<id>`) with nodes, guests and per-dataset availability, plus deep
  links into the PVE web UI built only from the approved endpoint metadata.

Everything PVE returns is treated as untrusted input: responses are size- and
schema-bounded, and secret-bearing fields (Cloud-Init passwords, SSH keys,
snippets, descriptions, hook scripts, storage credentials) are discarded
before anything is spooled.

**Phase 1** is read-only inventory. Remote management (add, probe, rotate,
re-pin, remove) and the web pages are merged, and `nebula-server` runs the
spool import from its start on (see [Spool import](#spool-import)). **Live
collection is planned:** the executor's typed `ReadPVE` method still answers
`Unimplemented` (provider read profile, ADR 0007 E08), so a running collector
cannot fill the inventory yet and the PVE pages show no or stale data until
that lands. **Phase 2 (planned)** adds
typed VM/LXC actions (start, graceful shutdown, hard stop, snapshots,
backups, configuration changes, intra-cluster migration, node reboot) with
their own permits and risk classes. The action token can already be stored
(see `--action-token` below) so that phase 2 does not require a second
onboarding pass, but no mutation is exposed today.

## Creating a least-privilege PVE API token

Use separate non-interactive PVE users per remote and per purpose. The
executor enforces the following, so a token that does not match is rejected
before anything is stored:

- Token format `USER@REALM!TOKENID=VALUE` (max 256 characters).
- Password-realm users (`*@pam`), `Administrator@*` and `PVEVMAdmin@*` are
  refused.
- The user must be enabled and not expired; the token must have
  `privsep=1` and must have an expiry (its own or inherited from the user).
- The **effective** permission profile (intersection of the user's and the
  token's ACLs) must match the purpose exactly.

### Read-only token (required)

The read token must have exactly these four audit privileges and nothing
else. Granting a broader built-in role (for example `PVEAuditor`, which
includes additional audit privileges) fails validation. On the PVE side:

```sh
# One role per audit privilege, so that each privilege is granted only on
# its own path. A single role with all four privileges granted on `/` would
# propagate VM.Audit, Datastore.Audit and Pool.Audit to paths the executor
# does not allow, and the token would be rejected.
pveum role add NOSSysAudit       --privs "Sys.Audit"
pveum role add NOSVMAudit        --privs "VM.Audit"
pveum role add NOSDatastoreAudit --privs "Datastore.Audit"
pveum role add NOSPoolAudit      --privs "Pool.Audit"

# Non-interactive user. --expire takes a Unix timestamp (0 = never), so
# compute one in the future, for example one year from now:
EXPIRE=$(date -d '+1 year' +%s)
pveum user add nos-read@pve --expire "$EXPIRE"

# Privilege-separated, expiring API token with the ID nosread1. Note the
# token secret printed once by this command.
pveum user token add nos-read@pve nosread1 --privsep 1 --expire "$EXPIRE"

# Grant every ACL to the user and to the token: with privilege separation
# the effective rights are the intersection, so both need the same entries.
# Token ACLs use --tokens, user ACLs use --users.
pveum acl modify /        --users nos-read@pve --roles NOSSysAudit
pveum acl modify /vms     --users nos-read@pve --roles NOSVMAudit
pveum acl modify /storage --users nos-read@pve --roles NOSDatastoreAudit
pveum acl modify /pool    --users nos-read@pve --roles NOSPoolAudit
pveum acl modify /        --tokens 'nos-read@pve!nosread1' --roles NOSSysAudit
pveum acl modify /vms     --tokens 'nos-read@pve!nosread1' --roles NOSVMAudit
pveum acl modify /storage --tokens 'nos-read@pve!nosread1' --roles NOSDatastoreAudit
pveum acl modify /pool    --tokens 'nos-read@pve!nosread1' --roles NOSPoolAudit
```

The four required entries are `Sys.Audit` on `/`, `VM.Audit` on `/vms`,
`Datastore.Audit` on `/storage` and `Pool.Audit` on `/pool`. Sub-path grants
of the same four privileges are accepted; any other privilege or path is
rejected.

### Action token (optional, for planned phase 2)

The action token must be a **different PVE user** from the read token and may
carry only `VM.PowerMgmt` on explicitly enabled `/vms/<vmid>` paths:

```sh
pveum role add NOSAction --privs "VM.PowerMgmt"
EXPIRE=$(date -d '+1 year' +%s)
pveum user add nos-action@pve --expire "$EXPIRE"
pveum user token add nos-action@pve nosaction1 --privsep 1 --expire "$EXPIRE"
pveum acl modify /vms/101 --users nos-action@pve --roles NOSAction
pveum acl modify /vms/101 --tokens 'nos-action@pve!nosaction1' --roles NOSAction
```

Add one `/vms/<vmid>` entry per guest you want to be able to operate later.
No console, guest exec, guest file access, permission administration,
storage deletion or HA-configuration privileges belong to either token.

### NOS automation key (guest provisioning)

Guest provisioning (ADR 0008) installs exactly one SSH public key into a new
guest: the NOS automation key. The executor accepts only the keyring
credential reference `nos-automation`, so the key must be in the executor
keyring as `keys/nos-automation.key` (same format, mode and passphrase as
every other keyring file; see section 3.4 of the admin guide). A provisioning
that names any other reference is refused with `PermissionDenied`, and one
whose keyring lacks `nos-automation.key` fails with `NotFound`. The file name
is fixed by the implementation, not by the ADR.

## Adding a remote with the nebula CLI

Run these commands on the **executor host** as the configured local admin
UID, through the peer-credential-authenticated executor socket.

- Socket: `NEBULA_EXECUTOR_SOCKET` (default `/run/nebula/executor.sock`).
- The socket must be served by the user in `NEBULA_EXECUTOR_USER`
  (default `nebula-executor`); the CLI verifies this before sending anything.
- Add, rotate, remove and repin need the executor vault **unlocked**:
  `nebula unlock` first. `list` is metadata only and works while locked.

```sh
nebula pve remote add <id> --kind cluster|standalone \
  --endpoint host:port [--endpoint host:port ...] \
  [--name NAME] [--action-token]
```

| Flag | Meaning |
| --- | --- |
| `<id>` | Immutable remote ID (first bare argument). |
| `--kind` | `cluster` (ordered node endpoints) or `standalone` (one endpoint). Required. |
| `--endpoint` | One `host:port` endpoint (normally port 8006). Repeatable; order is the failover order. At least one. |
| `--name` | Display label only; names never authenticate a remote. |
| `--action-token` | Also ask for the action-purpose token (see above). |

### Fingerprint confirmation

The command first probes every endpoint **without credentials** and prints
the presented leaf and CA SHA-256 fingerprints:

```text
presented trust identities (compare out of band):
  pve1.lab:8006  leaf <64 hex chars>
  pve1.lab:8006  ca   <64 hex chars>
Type the trust fingerprint to confirm:
```

Compare the fingerprint out of band (for example over the PVE console or a
second channel) and type it back. It must match exactly; on a mismatch
nothing is stored. For a **cluster** all endpoints must present the same
self-signed CA and the pin is that CA's fingerprint; for a **standalone**
host the served leaf is pinned. A server-supplied CA or an unauthenticated
API response can never establish trust.

After confirmation the CLI asks for the read token (and the action token if
`--action-token` was given) **without echo**. Tokens are never taken from
argv or environment. The executor then validates the token against the
pinned TLS identity and its permission profile and stores it
envelope-encrypted. Success prints:

```text
remote <id> added: active, pin generation 1, read credential <ref>@1
```

## Rotating a token

```sh
nebula pve remote rotate-token <id> --purpose read|action
```

The CLI asks for the new token without echo. The executor validates the new
token against the pinned TLS identity and the permission profile **before**
any change; the old credential version stays authoritative until the new one
is validated and stored (atomic swap). Read grants and permits bound to the
old version are revoked. If the trust pin no longer matches at rotation
time, the remote is blocked and its grants are revoked. After a successful
rotation, revoke the old token in PVE yourself.

## Re-pinning the trust identity

A changed pin, an invalid chain or a SAN mismatch **blocks the whole remote
persistently**, emits an executor event and stops endpoint failover.
Re-pin is an explicit admin operation:

```sh
nebula pve remote repin <id>
```

The CLI re-probes the stored endpoints, prints the presented fingerprints,
then asks you to type (1) the current pin from the registry and (2) the new
trust fingerprint. It creates a **HIGH-risk permit** bound to the exact
remote, old/new fingerprints, endpoints and generations, shows the permit as
seen by the executor (digest, action, parameters, targets, expiry) and asks
for typed `yes` to approve. After commit, the trust generation is
incremented, affected grants and permits are revoked, and the remote is
unblocked.

A leaf renewal that preserves the cluster CA does **not** require a re-pin.

## Removing a remote

```sh
nebula pve remote remove <id>
```

Type `yes` to confirm. The executor then, in order: disables (blocks) the
remote, revokes its authorizations, deletes the vault secrets and writes a
tombstone. Nonsecret audit/tombstone data is kept. Revoking the PVE-side
tokens is still your job. Removal cannot undo PVE tasks that are already
running.

## Recording the site of a remote

```sh
nebula pve remote set-site <id> onsite|offsite
```

Type `yes` to confirm. The marker is executor-owned and set only by the
local admin; it starts unset. A node reboot is refused for a remote marked
`offsite` (ADR 0006: an offsite node reboot is CRITICAL, manual and needs an
agreed recovery path, so NOS does not offer it) and for a remote whose site
is still unset, even when the remote has an action token. Mark offsite hosts
such as `ProxmoxOFS1` `offsite`.

## Listing remotes

```sh
nebula pve remote list
```

Metadata only (ID, kind, site, state, pin prefix with generation, endpoints,
read credential reference and version, updated time). It never prints secrets and
works while the vault is locked.

## What the collector reads

> **Planned:** the collector's reads are answered `Unimplemented` by the
> executor until the provider read profile (ADR 0007 E08) is merged. The
> schedule below is what the collector requests; no live data arrives yet.

`nebula-pve-collector` polls every **active** remote once per interval.
Blocked or removed remotes are skipped. One pass per remote issues two
phases of typed reads:

- Phase 1 (node-scoped): **nodes**, **guests**, **storage**, **cluster**
  (membership, quorum, HA states where readable), **tasks** (bounded
  metadata: actor, type, time, target, exit status — never raw task logs).
- Phase 2 (per guest, only when the guest list is usable): **guest
  configuration** (CPU, RAM, disk/storage references, NIC MAC/bridge/VLAN,
  boot order, `hostpci` passthrough mappings, tags, pool membership),
  **guest agent** data (IP/MAC/hostname/OS/filesystem summary; on PVE 8 the
  informational agent methods are not available with a read-only token, so
  these fields stay unavailable), **snapshots** (names, time, parent, RAM
  flag) and **backups** (available nonsecret `vzdump`/PBS metadata and recent
  task summaries).

Defaults (from the code):

| Setting | Default |
| --- | --- |
| Base interval per remote | 60 s |
| Concurrent reads per remote | 2 |
| Read timeout | 30 s |
| Backoff after a failed poll | exponential from 1 m, capped at 15 m, with jitter |

Collector flags:

```sh
nebula-pve-collector [-socket /run/nebula/executor.sock]
                     [-executor-user nebula-executor]
                     [-spool /var/lib/nebula/pve]
                     [-interval 1m] [-once]
```

`-once` runs a single collection pass and exits (useful for testing). The
collector logs JSON to stderr, including a per-pass report with remote,
polled, skipped, failed and error counts.

A partial poll does not erase unseen guests; only a complete enumeration can
tombstone them. A dataset that could not be read is marked unavailable with a
reason instead of being dropped silently.

The collector is intended to run as its own Unix user with the
`pve-collector` peercred role and no capabilities. A bundled
`deploy/systemd/nebula-pve-collector.service` unit is **planned** (ADR 0006,
P1-14); until it ships, run the binary directly or provide your own unit
with the flags above.

## Spool import

`nebula-server` imports `results/` (observations) and `guestnet/` (guest NIC
records) below the spool root. There is nothing to start: the import runs as
long as the server runs, and a missing spool is logged once and tried again.

`pve_spool_dir` in `/etc/nebula/server.json` names the spool root. It defaults
to `/var/lib/nebula/pve` and must match the collector's `-spool`. The server
keeps a file only until it has processed it, so it needs these rights:

| Path | Mode (owner `nebula-pve-collector`, group `nebula-rpc`) | Server |
| --- | --- | --- |
| `pve/` | 2750 | reads, never writes |
| `pve/results/`, `pve/guestnet/` | 2770 | lists, reads, unlinks |
| `pve/requests/` | 2770 | writes the live want-list |
| `pve/live/` | 2750 | reads only |

- `install.sh` provisions these directories and writes
  `nebula-server.service.d/20-discovery.conf`, whose `ReadWritePaths` open
  `pve/results`, `pve/guestnet` and `pve/requests` for the server under
  `ProtectSystem=strict`. The drop-in names these three default paths, so a
  custom `pve_spool_dir` also needs your own directories with these modes and
  your own drop-in.
- `compose.yaml` shares the `pve-results` and `pve-guestnet` volumes between
  the collector and the server, writable because the server unlinks there.
  When you update an older compose deployment, files still pending in the
  `pve-spool` volume are not imported; the collector publishes fresh ones
  within one interval.

If the server cannot unlink, it logs one warning (`remove spool file`, or
`remove guest nic record`, with `reason=remove_failed` and the number of
files) and keeps importing new files, but `results/` grows until the rights
are fixed. The backlog then drains without a restart.

## Read lease for a remote

**Why it is needed.** The executor answers a collector read for a remote only
when an approved, unexpired **provider read lease** covers that remote and
method. Registering a remote and storing its read token is not enough: without
a lease every read is refused (`read_grant_does_not_cover`) and the PVE pages
keep showing no or stale data. The lease is the operator's explicit approval
of *what* the collector may read and *for how long*.

**How to request it.**

1. Open `/pve/<id>`. For an active remote that no active provider read
   lease lists, the page says "no approved read lease" and offers **Request
   read lease**. When every active read lease that lists the remote is stale
   (the remote was re-pinned or its read token rotated since the approval),
   the page says "Read lease stale" and offers **Renew read lease** instead.
   A live-values lease (see [Live values and their
   lease](#live-values-and-their-lease)) is not a read lease and does not
   hide the request. The same form is at `/leases/new`, scope **Proxmox
   remote**.
2. Choose the remotes (only `active` remotes are offered, at most 16), the
   methods and the lifetime (7 or 30 days). The defaults are what the
   collector reads on every pass: `nodes`, `guests`, `storage`, `cluster`,
   `tasks`. The per-guest methods `guest_config`, `guest_agent`, `snapshots`
   and `backups` are optional; check them only if you want those datasets
   (see [What the collector reads](#what-the-collector-reads)).
3. **Preview** freezes the request and shows the complete lease as the
   executor will hold it: every remote with its full trust pin, trust
   generation and read credential version, the methods, the trigger, the rate
   profile with the per-remote request budget, the expiry and the digest.
   Nothing is approved yet.

**How to approve it.** On the preview page, approve with your security key.
If the executor runs in hardened mode, the page shows the command instead;
run it on the executor host, it shows the complete lease again before it
asks for approval:

```sh
nebula read-grant approve <digest>
```

**What it covers.** Exactly the frozen remotes and methods, nothing else:
no SSH hosts, actions or credentials, no write methods, and no other remote.
A remote that is re-pinned (new trust generation) or whose read token is
rotated (new credential version) is no longer covered; the reads fail with
`read_grant_does_not_cover` until a new lease is approved.

**Renewal and revoke.** `/leases` lists provider leases with their remotes
and methods; the detail page shows each remote with pin prefix, trust
generation, credential version and methods. **Refresh** (on an active or
expired lease) opens the form pre-filled with the same remotes, methods and
lifetime and proposes a *new* lease, which needs its own approval; the old
one stays until it expires or is revoked. **Revoke** ends a lease at once.
Renew before the expiry shown in the list, and after every re-pin or token
rotation. The lease detail page marks a remote whose frozen binding no longer
matches the executor's registry as "Lease stale".

**Budget limit with per-guest methods.** The executor counts every read of
a remote against the lease's per-remote budget per rolling hour. Without
per-guest methods the budget is twice what the 60-second collection needs.
As soon as one per-guest method (`guest_config`, `guest_agent`,
`snapshots`, `backups`) is chosen, the number of guests is not known when
the lease is proposed and the budget is the executor's maximum, **4096
requests per remote per hour** (about 68 per 60-second pass). One pass
spends one request per remote-wide method plus one per guest and chosen
per-guest method, so with all four per-guest methods a remote with more than
about **15 guests** runs out of budget within the hour (about 60 guests with
one per-guest method). Reads past the budget are refused until the rolling
hour frees requests; the affected datasets then show as unavailable or
stale. On larger remotes choose only the per-guest methods you need.

## Live values and their lease

**What they are.** The 10-second live values on a Proxmox node or guest box
are read by `nebula-pve-collector` through
the executor while the box is on screen; the server never reads Proxmox
itself (see the admin guide, "Live values for Proxmox nodes and guests").
They need their own **live-values lease** (a provider telemetry lease): the
inventory read lease above does not cover them, and a live-values lease
covers nothing else.

**How to request it.**

1. Open `/pve/<id>` of an active remote. The **Live values** section and the
   **Live** column of the node and guest tables list every stored node and
   guest with a checkbox. By default every node and every *running* guest is
   checked, at most **64** per lease (the page says so when it had to stop
   there). Change the selection and the lifetime (7 or 30 days).
2. **Enable live values** proposes the lease and opens the same preview page
   as every other lease. Each guest checkbox posts the incarnation
   **generation** the page showed. The server checks the selection against
   the stored inventory: a node must be stored for the remote; a guest must
   have exactly one active incarnation of the chosen kind on the chosen node
   with the posted generation, and is bound with that generation. A guest
   that was removed, moved or recreated (same VMID, new generation) since
   the page was loaded is refused ("reload the page"); it is never bound to
   the new incarnation without you seeing it on a reloaded page.
3. The preview shows the remote with its full trust pin, trust generation
   and read credential version, the single method `metrics`, every node and
   guest (node, kind, VMID, generation), the trigger `on_demand`, the 10 s
   interval and the budget. Nothing is read before you approve it with your
   security key (or `nebula read-grant approve <digest>` in hardened mode).

**What it covers.** Live reads (trigger `on_demand`, no scheduled history
reads) of exactly the listed nodes and guests on that remote, each at most
every 10 seconds. The executor additionally serves at most four live boxes
per remote at once, so the budget is `min(targets, 4) × 360` requests per
remote per hour (at most 1440, below the 4096 limit of the profile). The
server sizes the budget from the same live-box limit the executor enforces,
so the two cannot drift apart.

**When it stops covering.** Like a read lease, a live-values lease no
longer covers anything after the remote is re-pinned or its read token is
rotated. A guest recreated with the same VMID gets a new generation and is
not covered either; other guests of the lease keep working. A guest that
migrates to another node is not covered on the new node. The **Live** column
shows **on** for a node or guest that a current lease covers exactly and
**lease stale, renew** for one that only an outdated lease lists; the
section above the tables counts both.

**Renewal and revoke.** Choose the nodes and guests again on `/pve/<id>` and
**Enable live values**: the new lease is built from the current inventory
and needs its own approval; the old one stays until it expires or is
revoked. **Refresh** on a live-values lease in `/leases` opens `/pve/<id>`
for exactly that. **Revoke** stops the live reads within about 10 seconds.

## Staleness and unknown labels in the UI

The PVE pages show only stored observations, never live API data. Every row
carries a label:

- **no label** — fresh: the observation is recent.
- **`stale`** — the last observation is older than three poll intervals
  (3 minutes for the 60 s default), or the node version details are older
  than 45 minutes.
- **`unknown`** — no observation ever arrived for that remote, node or
  guest.

`unknown` and `stale` are explicit states: they never render as healthy,
running or off, and an expected-off parent cannot mask a known problem in a
child.

- **`/pve`** lists remotes with kind, stored nodes, trust pin, registry
  state (`active`, `blocked`, or `—` when not reported), staleness label,
  last observation age and the collector that made it.
- **`/pve/<id>`** shows the remote's nodes and guests (VMID, kind, name,
  node, status, label, age) and a per-dataset status table. Datasets that
  could not be read show `unavailable` with a reason.
- Deep links into the PVE web UI are built from the approved endpoint
  metadata with encoded identifiers only (never host-provided URLs) and open
  with `noopener noreferrer`. PVE performs its own login and MFA; no token,
  ticket or SSO credential travels in a link. The browser must independently
  trust PVE TLS.

With a read-only token, full backup listings are **not guaranteed**: storage
content is filtered by PVE using `VM.Backup` and `Datastore.AllocateSpace`
checks, so the backup dataset may show `unavailable: insufficient read
privileges`. That is expected and must not be read as "no backups"; task
history is merely evidence of a past run.

## Troubleshooting

| Symptom | Likely cause / action |
| --- | --- |
| `confirmation does not match the presented trust identity; nothing stored` | The typed fingerprint was wrong. Re-run `add`; compare the fingerprint out of band again. |
| Token rejected at `add` or `rotate-token` | Check the effective permission profile: read tokens need exactly the four audit privileges on `/`, `/vms`, `/storage`, `/pool`; action tokens need only `VM.PowerMgmt` on `/vms/<vmid>`. The user must be enabled and not expired; the token needs `privsep=1` and an expiry; `*@pam`, `Administrator@*` and `PVEVMAdmin@*` are refused. Read and action tokens must use different PVE users. |
| Remote state `blocked` in `list` / UI | The trust identity changed (new CA or leaf), the chain is invalid, or a SAN does not match. Verify the presented certificate out of band, then `nebula pve remote repin <id>`. A CA-preserving leaf renewal needs no re-pin. |
| Remote rows labelled `unknown` in the UI | No observation ever arrived: the collector is not running, cannot reach the executor socket, or the remote is not `active`. Check the collector process and its JSON logs, the spool directory, and `nebula pve remote list`. |
| Collector exits at start: `verify executor at /run/nebula/executor.sock: … connection reset by peer` | The executor does not know the collector's UID and drops the connection. The collector must run as the executor's `-pve-collector-user` (default `nebula-pve-collector`): a missing default user leaves the role unassigned (warning `pve-collector user not found` in `journalctl -u nebula-executor`), and a missing non-default user stops the executor at start. Create the user, restart `nebula-executor`, run `nebula unlock` and restart `nebula-pve-collector`. |
| Collector exits at start: `chmod spool root: … operation not permitted` (or the same for `results`, `requests`, `live`, `guestnet`) | A spool directory does not have its final mode. The collector unit forbids setting the setgid bit (`RestrictSUIDSGID=yes`), so the directories must be created with their modes beforehand: re-run `install.sh` (it creates `/var/lib/nebula/pve` 2750, `results`, `guestnet`, `requests` 2770 and `live` 2750, owner `nebula-pve-collector`, group `nebula-rpc`). |
| `read_grant_does_not_cover` in the collector or executor log (`journalctl -u nebula-pve-collector`, `journalctl -u nebula-executor`); PVE page says "no approved read lease" | No active provider read lease covers this remote and method: none was approved, it expired or was revoked, the remote was re-pinned, the read token was rotated, or the method (for example `snapshots`) was not chosen. Request a lease from `/pve/<id>` (**Request read lease**) or refresh the old one on `/leases`, with the methods you need, and approve it (see [Read lease for a remote](#read-lease-for-a-remote)). |
| Rows labelled `stale` | The collector is down, backing off after failures, or the remote is blocked. Backoff is exponential from 1 m to 15 m after failed polls; a single pass can be forced with `nebula-pve-collector -once`. |
| Dataset `unavailable: insufficient read privileges` (backups) | Expected with a read-only token (see above). Do not borrow the action token or add write privileges for inventory. |
| Guest agent fields unavailable on PVE 8 | PVE 8's legacy `VM.Monitor` is too broad for a read-only token; agent-derived fields stay unavailable unless a separately reviewed mechanism is provided. PVE 9 informational agent methods work with the read token. |
| `add`/`rotate-token`/`remove`/`repin` refuse to run | The executor vault is locked: run `nebula unlock` on the executor host first. |
| CLI cannot dial the executor | Check `NEBULA_EXECUTOR_SOCKET` and that the socket is served by the `NEBULA_EXECUTOR_USER` user (default `nebula-executor`). |
