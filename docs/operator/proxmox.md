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
  PVE pages. It never performs PVE API calls.
- The web UI shows a remote list (`/pve`) and a detail page per remote
  (`/pve/<id>`) with nodes, guests and per-dataset availability, plus deep
  links into the PVE web UI built only from the approved endpoint metadata.

Everything PVE returns is treated as untrusted input: responses are size- and
schema-bounded, and secret-bearing fields (Cloud-Init passwords, SSH keys,
snippets, descriptions, hook scripts, storage credentials) are discarded
before anything is spooled.

**Phase 1** is read-only inventory. Remote management (add, probe, rotate,
re-pin, remove), the spool import and the web pages are merged. **Live
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

## Listing remotes

```sh
nebula pve remote list
```

Metadata only (ID, kind, state, pin prefix with generation, endpoints, read
credential reference and version, updated time). It never prints secrets and
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
| Rows labelled `stale` | The collector is down, backing off after failures, or the remote is blocked. Backoff is exponential from 1 m to 15 m after failed polls; a single pass can be forced with `nebula-pve-collector -once`. |
| Dataset `unavailable: insufficient read privileges` (backups) | Expected with a read-only token (see above). Do not borrow the action token or add write privileges for inventory. |
| Guest agent fields unavailable on PVE 8 | PVE 8's legacy `VM.Monitor` is too broad for a read-only token; agent-derived fields stay unavailable unless a separately reviewed mechanism is provided. PVE 9 informational agent methods work with the read token. |
| `add`/`rotate-token`/`remove`/`repin` refuse to run | The executor vault is locked: run `nebula unlock` on the executor host first. |
| CLI cannot dial the executor | Check `NEBULA_EXECUTOR_SOCKET` and that the socket is served by the `NEBULA_EXECUTOR_USER` user (default `nebula-executor`). |
