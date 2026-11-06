# Traffic map (ADR 0009): final state

The traffic map shows the network as a node graph built from the server's
own inventory records plus bounded, validated reports. The operator-facing
walkthrough is in the admin guide, section 9.9; the design decisions and
their rationale are in [`../adr/0009-traffic-map.md`](../adr/0009-traffic-map.md);
the untrusted-input rules are in
[`../spec/09-untrusted-host-data.md`](../spec/09-untrusted-host-data.md).

## What is implemented

### `net.facts` (built-in read-only action)

`internal/executions/actions/scripts/net_facts.sh` collects a fixed network
snapshot on the managed host: endpoints (`ip addr`, `ip link`), routes,
neighbors, sockets (`ss -tinuaH`, including the TCP byte counters) and,
where the tools exist, bridge VLANs, LLDP and conntrack. Every section is
marked `ok`, `unavailable` or `absent`, so a missing tool is distinguishable
from a failure.

- **No process names, no sudo.** `ss` runs without `-p`. The optional sudo
  rule for `ss -p` (ADR 0009, open question Q3) was **not adopted**: the
  action needs no root or sudo on the host, and a sockets report that
  contains a `users:((…))` column — that is, one from a wrapped or replaced
  `ss` — is rejected as `invalid` with an empty table, so a compromised host
  cannot inject process names.
- **Read-only allowlist.** `net.facts` is a built-in LOW-risk action on the
  read-only allowlist (`internal/permit/lease.go`), so it can be leased
  under a read grant (admin guide 9.4): 7- or 30-day duration, 15-minute
  minimum interval per action, 24 runs per host per rolling hour by default
  (max 240), shared across all leased actions, no catch-up. The executor
  re-checks the allowlist and the LOW rating on every run.

### Decoding and ingest

- `internal/netfacts` decodes the report: bounded JSON, explicit section
  schemas, size limits, UTF-8 checks. Anything malformed is rejected, not
  partially accepted.
- `internal/trafficingest` turns an accepted report into store writes:
  endpoint reports (MAC → owner, with the server's own records winning
  disputes), hourly flow buckets and gateway claims. Raw LLDP and conntrack
  sections are not parsed; they stay in the execution result (its normal
  lifecycle), not in the traffic store.

### Store and retention

`internal/trafficstore` (SQLite) holds the tables `net_endpoints`,
`net_endpoint_reporters`, `net_endpoint_addresses`, `flow_buckets`,
`traffic_counts` and `traffic_store_lock`, plus the guest-NIC tables
(migration 0034) that keep Proxmox provider claims separate from observed
tiers.

- **Retention is 21 days** (`flowagg.Retention`,
  `trafficstore.DefaultRetention`). Pruning runs during a full Sync, which
  happens at least once per clock hour (see Server wiring).
- **There is no setting to shorten it yet.** The store constructor accepts
  only a retention in `(0, 21 d]` (configurable lower only, ADR 0009), and
  `nebula-server` currently always opens the store with the 21-day default.
  The map's and the connections pages' windows (1 h / 24 h / 7 d / 21 d,
  default 24 h) are clamped to the store's retention.

### Server wiring

`cmd/nebula-server/trafficmap.go` and `traffic.go` mount the map. A cheap
change check runs every `trafficCheckInterval` (30 s); a full Sync — which
reconciles ownership and prunes — runs only when a `net.facts` host run
finished since the last one, the server's host records changed, or a clock
hour passed.

### Web UI

- `internal/web/api/trafficmap` builds the graph and the per-node
  connections; `internal/web/ui/trafficmap` renders the page at `/traffic`.
  The graph is drawn in a sandboxed iframe without cookies, so the renderer
  cannot read the session.
- `internal/web/ui/connections` renders the *Connections* tab of the host
  page (`/hosts/ID/connections`) and the asset page
  (`/network/a/ID/connections`): peer (linked when the peer is a managed
  host or asset), direction, protocol and port, process name when known,
  bytes in/out, first and last seen, source tier and the reporting host.
  Byte counts from socket snapshots are lower bounds and are marked as
  such; flows whose endpoints are not inventory nodes are counted as
  unmapped, not drawn.

### Data tiers

- **Tier 1 — managed hosts.** `net.facts` reports (above).
- **Tier 2 — Proxmox.** `cmd/nebula-pve-collector` reports each guest NIC's
  bridge, VLAN and MAC; the server maps the MAC to the tap interface. These
  are the provider's claims about guest configuration, not observations of
  traffic (stored in the guest-NIC tables, never in the observed tiers).
- **Tiers 3–4 — sensors and DNS.** Planned, not implemented.

Every stored row names its reporter and its tier, because a host can lie
about its connections (spec 09).

### Software catalog and icons

- `internal/web/ui/software` + `cmd/nebula-server/software.go` serve the
  software catalog (`/software`), the unknown queue
  (`/software/unknown`) and the icon pages (`/software/icon/KEY`, per asset
  `/software/assets/icon?id=ASSET`).
- `cmd/nebula-server/software.go` holds the icon service wiring
  (`newIconWiring`: store in `<data_dir>/icons`, spool, import loop every
  15 s) and `software.Handler` mounts `/icons/` with it. **`run` does not
  start it yet**: until it calls `newIconWiring` and `softwarePagesWith`, the
  icon pages of a running server stay read-only and the icon-change routes
  return 404. The wiring is tested through the full middleware and session
  chain (`cmd/nebula-server/software_icons_test.go`).
- Admin means a web session with a user name: sessions have no roles. The
  change routes are refused without a session (401), without a user name
  (403) and without the public `Origin` (403, the CSRF check of all forms).
- `internal/iconfetch` + `cmd/nebula-iconfetch` is the one-shot fetcher
  (like `nebula-discovery`): spool `/var/lib/nebula/iconfetch`, results kept
  24 h, host allowlist via `-allow` (default `avatars.githubusercontent.com`
  and `upload.wikimedia.org`). The server checks the same URL policy with the
  default list; it has no allowlist setting, so `-allow` can only narrow
  what is fetched. Fetch URLs with a query string are refused: the catalog
  records none (signed URLs carry their secret there).
- `deploy/install.sh` does not provision the spool. Without it a fetch
  answers 503 and uploads and rollbacks still work. Provisioning needs what
  `nebula-iconfetch.service` lists, plus `ReadWritePaths` for `jobs/` in the
  server's drop-in (the server unit is `ProtectSystem=strict`).
- `internal/iconstore` sanitizes every icon: only PNG, JPEG or GIF input up
  to 256 KiB and 1024 px is accepted, re-encoded as fresh 64×64 and 128×128
  PNGs (SVG, WebP, ICO and BMP are rejected), stored and served keyed by
  SHA-256.

## Privacy

The traffic store holds hourly aggregates only: endpoint addresses and MACs,
protocol, port, byte counts, connection counts and the reporting host. It
holds no packet contents, no DNS names, no process names and no
credentials. Host-reported data (names, banners, LLDP text) is untrusted:
size-limited, validated and rendered as text only.

## Not implemented

- Tiers 3–4 (sensors, DNS) and their parsers.
- An admin setting to shorten the 21-day retention (the store API already
  supports a shorter retention; the server does not expose it).
- Starting the icon service in `nebula-server`'s `run` (the fetch, upload
  and rollback routes are built and tested, but not enabled).
- An allowlist setting in the server configuration.
- A sudo rule for `ss -p` (deliberately not adopted; see above).
