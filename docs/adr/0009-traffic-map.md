# ADR 0009: Traffic map, observed endpoints and software symbols

Status: proposed, 2026-11-04. Awaiting the maintainer's decision on the open
questions below; do not merge before that discussion.

## Context

NOS knows managed hosts, Proxmox guests, IPAM assets and Docker containers,
but not who talks to whom. Operators want a zoomable communication view in
the style of industrial network monitors: zoomed out, VLANs and the router
hop with aggregated traffic; one level down, the assets of a VLAN and their
connections; a click on an asset shows its communication paths; a click on a
host opens the inventory with a list of connections and destinations.

The target scale is 100 managed hosts plus the devices they see (about
150–300 nodes and 500–2,000 flows per day). 1,000 managed hosts is the stress
target. Constraints that shape every decision below:

- Agentless: only SSH through the executor, which alone holds keys.
- Reads use the bounded read leases of [ADR 0007](0007-approval-ergonomics.md).
- All host output is untrusted ([spec 09](../spec/09-untrusted-host-data.md)).
- The web UI runs under a strict CSP (`script-src 'self'`, no inline script).
- No new dependencies; `go.mod` and the security-relevant packages are protected.
- Placements are explicit and reviewed, never inferred (ADR 0006, migration
  `0025_pve_service_placements.sql`); unknown is never rendered as healthy.

A working prototype with sample data exists (WebGL2, no libraries; one
self-contained HTML file). It is added to this pull request as
`docs/design/traffic-map-prototype.html` before acceptance and is the
reference for TM18. On a software rasterizer without a GPU (SwiftShader)
it renders 100 hosts (172 nodes, 575 flows, 738 beams, 1,224 particles) at
45–50 frames per second and 1,000 hosts (1,625 nodes, about 5,900 flows,
7,100 beams, 11,600 particles) at about 13 frames per second, with a constant
14 draw calls in both cases. A GPU-backed browser only adds headroom.

## Decisions

### D1: Three tiers of data sources

1. **Snapshot read `net.facts` (agentless, first).** A built-in read-only
   action collects, as bounded base64 sections like `core.facts`:
   `ip -j neigh`, `ip -j addr`, `ip -j -d link`, `ip -j route`,
   `bridge -j vlan`, `ss -tinuaH` (TCP byte counters from `tcp_info`), and,
   when present, `lldpcli -f json show neighbors` and `conntrack -L`.
   Process names (`ss -p`) need root and are off unless the admin installs
   the documented sudo rule (open question Q3). It runs under a read lease
   (ADR 0007); budgets bound the frequency (default every 5 minutes).
2. **Provider enrichment.** The pve-collector adds guest NIC bridge and VLAN
   tag and the MAC-to-tap mapping. As decided for live values (lv00–lv05),
   the collector reads and the server only receives spool files.
3. **Passive sensor `nebula-echo` (optional, later phase).** A separate
   package fed by a mirror/SPAN port or by NetFlow/IPFIX/sFlow exports. It
   records metadata only (5-tuple, bytes, time, passive ARP/DHCP/mDNS/LLDP
   fingerprints), never payload; it runs with `CAP_NET_RAW` only; every
   parser is fuzzed; output goes through a spool like the collector.

Active scanning stays the existing approved discovery job (Nmap). The traffic
map never triggers scans on its own.

### D2: Observed endpoints are facts, not inventory

Every neighbor or peer seen in tier 1–3 becomes an **observed endpoint**
automatically: MAC, addresses, VLAN, OUI vendor, hostname if reported, first
and last seen, source tier and reporting host. Observed endpoints appear on
the map at once, marked as unknown when they match no IPAM asset and no
managed host. Promoting one to an IPAM asset or a managed host stays the
existing explicit flow ("Add to managed hosts", discovery import). Nothing
from this ADR creates placements, assets or hosts by inference.

### D3: Flow model, retention and top connections

- Flows are stored only as **hourly aggregates** keyed by endpoint A,
  endpoint B, protocol, server port and source tier, with bytes A→B and B→A,
  connection count, first and last seen. Raw samples are never stored.
- The server side of a connection is the side with a matching listening
  socket; ephemeral client ports are dropped.
- TCP volumes come from `tcp_info` counter deltas between snapshots (counter
  resets and vanished sockets handled); snapshot volumes are a lower bound and
  are labeled as such. UDP volumes exist only with the sensor tier.
- **Retention is 21 days**, pruned hourly. Admins may shorten it; a longer
  retention needs a new decision.
- **Top connections:** per node, the five largest flows by inbound plus
  outbound bytes in the selected window (1 h, 24 h, 7 d, 21 d). The overview
  shows the union of all per-node top-5 sets, so small devices keep their
  links; a focused node shows exactly its top 5; the complete list is in the
  host's connections tab. The server computes this; the browser never
  receives raw flows.
- **Hops** are derived passively: traffic to another subnet uses the default
  gateway (from the route table and the gateway's MAC in the neighbor table)
  and is drawn A → gateway → B.

### D4: Rendering and visual encoding

- **Own renderer, no third-party library.** WebGL2 by default: instanced
  quads for stars, beams and particles, HDR bloom when
  `EXT_color_buffer_float` is present, one fragment-shader nebula per VLAN.
  A Canvas 2D renderer is the fallback (no WebGL2, context loss, VMs and
  remote desktops without a GPU). WebGPU may be added as an optional backend
  only if a deployment needs more than about 10,000 nodes; GPGPU is not needed
  at the target scale.
- **Layout** is deterministic: zones on a ring around the router, nodes per
  zone on a sunflower (phyllotaxis) spiral ordered by resources. It is O(n),
  and positions stay stable between visits (no force simulation).
- **Encoding:** star size and brightness grow with the logarithm of assigned
  resources (vCPU, RAM, GPUs); star color is the VLAN color; beam width and
  brightness grow with the logarithm of inbound plus outbound bytes; moving
  particles show the direction split; each VLAN is a colored nebula.
- **Health spikes** on managed nodes: top = patches (green current, amber
  pending, red critical; critical also pulses in the overview), left =
  general health (backup freshness, failed units, reachability), bottom =
  disk usage, right = load. A value that is not known is drawn grey or
  omitted, never green. Grey flicker = unreachable, red ring = host-key
  mismatch. Spike length also encodes severity, so color is not the only cue.
- **Semantic zoom:** overview = per-VLAN bundles through the hop; closer =
  individual top connections; focus = one node and its top 5. Software
  symbols appear first aggregated on the Proxmox host, closer under each
  guest, closest as containers under their Docker symbol; symbols grow with
  the zoom level.
- **Isolation:** the renderer runs in a same-origin page loaded into a
  sandboxed iframe (`sandbox="allow-scripts"`, no `allow-same-origin`). The
  parent page sends the bounded JSON model and decoded `ImageBitmap` icons by
  `postMessage`; the iframe has no cookies, no access to the parent DOM and
  no network use of its own. All labels are drawn with `fillText` or set with
  `textContent`; there is no `innerHTML` with host data anywhere.

### D5: Software catalog, observations and unknown software

- **Observations** come from reads NOS already runs: `core.facts`
  (`os-release` ID, Proxmox flag), `docker.list` (image repositories),
  the GPU reader (NVIDIA), `service.list` (systemd units), and optionally a
  package list. Each observation keeps host, guest or container, identifier,
  version, source action and time.
- Identifiers are normalized to catalog keys (`docker.io/library/postgres` →
  `postgres`, `netbirdio/netbird` → `netbird`, `nvidia-driver-550` →
  `nvidia`) by a reviewed seed map. Keys match `[a-z0-9][a-z0-9._-]{0,63}`.
- **Automatic creation:** an identifier without a catalog entry creates one
  in state `observed` with a generic symbol and lands in the "Unknown
  software" queue. The admin can rename, merge into another key, ignore, or
  set a symbol. Observations never create placements.
- The map aggregates symbols per Proxmox host (with counts), per guest, and
  per Docker host (containers nested under the Docker symbol).

### D6: Icon pipeline (no URL or image injection)

- **The browser never loads external images.** Icons are served only as
  `/icons/<sha256>.png` with `Content-Type: image/png`,
  `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src
  'none'` and `Content-Disposition: inline`. Source URLs are stored for audit
  but never rendered as links, attributes or `src` values.
- **Sources:** an admin upload (PNG, JPEG or GIF), or a fetch from an
  allowlisted HTTPS host (default `avatars.githubusercontent.com` and
  `upload.wikimedia.org`). A crawler only proposes candidates for a catalog
  key; an admin confirms. Setting or replacing an icon is an audited admin
  action and possible at any time; previous hashes stay for history and
  one-click rollback. A per-asset override exists for devices.
- **Fetcher:** a one-shot helper `nebula-iconfetch`, started through a spool
  like `nebula-discovery`, without access to the server database or vault.
  URL policy: `https` only, port 443, no user info, no IP literals, host on
  the allowlist. Every resolved address is checked again at dial time against
  loopback, link-local (incl. `169.254.169.254`), private, unique-local,
  multicast and reserved ranges (same classification as `servicecheck`), so
  DNS rebinding fails. At most three redirects, each re-validated; 256 KiB
  response cap; 10 s timeout; no cookies, no credentials, a fixed user agent.
- **Sanitizer:** magic-byte check; `image.DecodeConfig` before decoding
  (at most 1024×1024 pixels); decode with the standard library only;
  re-encode as 64 px and 128 px PNG. Re-encoding drops metadata, polyglot
  content and trailing payloads. **SVG and WebP are rejected in v1**: there
  is no rasterizer without a new dependency.
- **No vendor logos in the repository.** Logos are trademarks; NOS ships
  only generic symbols and fetches or accepts real icons at runtime.

### D7: Privacy and bounds

The map stores metadata only. DNS names from the sensor tier are off by
default (they reveal browsing; open question Q5). Retention is 21 days.
Per-host observation counts, per-node flow counts and the map API response
size are capped; a truncated model says so instead of silently dropping data.

## Open questions for the maintainer

- **Q1: Node symbol.** Keep stars (resource, VLAN and health encoding) and
  show the OS symbol inside the star core when zoomed in close
  (recommended), or offer a switchable symbol mode with OS symbols instead
  of stars?
- **Q2: Release placement.** Proposed as the next version extension after
  the Proxmox work (1.2, after the Proxmox provider in 1.1).
- **Q3:** Allow the optional sudo rule for process names in `ss -p`?
- **Q4:** Sensor input (mirror/SPAN or NetFlow/IPFIX/sFlow) depends on the
  router and switch hardware in the reference lab.
- **Q5:** DNS names from the sensor tier off by default?

## Threat analysis and consequences

- **Hostile host data** (hostnames, mDNS names, neighbor tables, container
  names) reaches the map. Spec 09 applies: bounded, UTF-8-checked,
  printable-only text, rendered as text; the renderer iframe has no
  privileges even if a rendering bug were found. The page where approvals
  happen (WebAuthn) is never the renderer's document.
- **A compromised host can lie** about its connections or invent endpoints.
  The map labels every flow with its reporter and tier; the sensor tier is
  independent of hosts; map data never triggers an action or a permit.
- **SSRF and image attacks** through icon sources are bounded by the URL
  policy, dial-time address checks, the separate fetcher process, size and
  dimension limits and full re-encoding.
- **Supply chain:** no rendering or graph library is added; the renderer is
  first-party code under the existing CSP.
- **Load:** snapshot reads are bound by read-lease budgets; aggregation is
  hourly; the browser draws a bounded, server-computed model.
- **Privacy:** a communication history is personal data in many homes;
  metadata only, 21-day retention, DNS names off by default, no export.

## Required specification changes

- `docs/spec/12-inventory.md`: observed endpoints, software catalog and
  observations, unknown queues, promotion rules.
- `docs/spec/09-untrusted-host-data.md`: `net.facts` fields and limits,
  icon input rules.
- `docs/spec/07-execution-model.md`: `net.facts` in the read-only allowlist.
- `docs/spec/03-processes-and-data.md`: new tables, 21-day retention,
  `nebula-iconfetch` and the sensor as processes.
- `docs/spec/01-product.md`, `16-milestones.md`, `04-revision-history.md`:
  feature and milestone. Afterwards the admin handbook.

## Implementation tickets

Each row is one agent job, tests first and `make check`; no new
dependencies. **P** marks protected paths. Phase 1 builds pure libraries in
new packages and may start before this ADR is accepted; phase 2 starts after
acceptance and after the Proxmox UI and executor tickets have landed.

| Ticket | Scope / paths | Acceptance tests or review |
| --- | --- | --- |
| TM01: this ADR | `docs/adr/0009` **P**, `docs/implementation/traffic-map.md`, prototype | Maintainer decision on Q1–Q5 |
| TM02: neighbor and route parsers | `internal/netfacts/` | `ip -j neigh/route` fixtures, oversize, malformed, fuzz |
| TM03: address, link and VLAN parsers | `internal/netfacts/` | `ip -j addr`, `ip -j -d link`, `bridge -j vlan`, fuzz |
| TM04: socket parser | `internal/netfacts/` | `ss -tinuaH` with `tcp_info` bytes, listeners, IPv6, fuzz |
| TM05: flow aggregation library | `internal/flowagg/` | Deltas, counter resets, server side, hourly keys, top-5 union, 21-day cutoff |
| TM06: icon sanitizer | `internal/iconstore/` | Magic bytes, bombs, polyglots, SVG/WebP rejection, PNG re-encode, fuzz |
| TM07: icon fetch policy | `internal/iconfetch/` | Allowlist, IP literals, rebinding at dial time, redirects, caps |
| TM08: software normalization | `internal/softwarecat/` | Seed map, image/package/unit/os-release keys, unknown handling |
| TM10: `net.facts` read action | built-in action and script, `internal/permit/lease.go` **P** | Bounded output, lease allowlist, no `-p` without the sudo rule |
| TM11: traffic store | server migration, `internal/trafficstore/` | Endpoints, hourly buckets, pruning, caps |
| TM12: ingestion | `internal/trafficingest/` | `net.facts` → endpoints and flows, hop derivation, reporter labels |
| TM13: software observations | migration, `internal/softwarecat/` store | Auto-created `observed` entries, unknown queue, no placements |
| TM14: Proxmox VLAN enrichment | `internal/pvecollect/` | Guest NIC bridge/tag and MAC-to-tap via spool |
| TM15: map API | `internal/web/api/` | Bounded model, top-5 union, windows, truncation flag |
| TM16: icon service | `cmd/nebula-iconfetch/`, server import, `/icons/` | Spool, headers, audit, history, rollback |
| TM16b: helper hardening | `deploy/systemd/` **P** | No DB/vault access, egress only 443 |
| TM17: catalog and icon admin UI | `internal/web/ui/`, templates | Rename, merge, ignore, upload, URL, candidates, override |
| TM18: renderer module | `web/static/trafficmap/` | WebGL2 and Canvas 2D from the prototype, no network, text via `fillText` |
| TM19: map page | page, template, iframe bridge | Sandbox attributes, `postMessage` schema, focus and host navigation |
| TM20: connections tab | host and asset pages | Peer, direction, protocol/port, process, bytes, first/last seen, source |
| TM21: security and browser tests | `test/security/` **P**, `test/browser/` **P** | Hostile names, SSRF, polyglot icons, iframe isolation, fallback |
| TM22: operator documentation | `docs/admin/guide.md` | Sources, sudo rule, retention, icons, privacy |

Later, separate decisions: the passive sensor `nebula-echo`, a learned
baseline with alerts for new connections and segmentation rules (for example
"IoT must not reach Mgmt"), and LLDP switch-port mapping.
