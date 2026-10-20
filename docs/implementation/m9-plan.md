# Milestone 9 plan: network inventory, IPAM, discovery

Status: **in progress 2026-10-19**: M9-1 and M9-2 implemented (decisions 70 and 71 in m0.md); work continues with the defaults below.
It turns spec 12 (inventory, IPAM, discovery) and spec 16 (Milestone 9,
Release 0.5) into a concrete plan.

## What the spec asks for

- Network assets (server, NAS, firewall, switch, printer, IoT, unknown),
  tracked apart from managed hosts; "add to managed hosts" starts SSH
  enrollment and keeps the asset's identity.
- IPAM-light: networks and subnets, simple pools, reservations,
  assignments, exclusions, conflict indication; IP status FREE, RESERVED,
  ASSIGNED, DISCOVERED, CONFLICT, EXCLUDED, UNKNOWN; a free-IP suggestion
  from IPAM state, reservations, discovery and an optional targeted
  reachability test, shown as a suggestion, never as certainty. No DHCP or
  DNS management.
- Discovery with Nmap (optional dependency) in `nebula-discovery`, a
  one-shot systemd service with only `CAP_NET_RAW`, no credentials, no
  database; results land in staging (NEW, EXISTING, POSSIBLE MATCH,
  CONFLICT) and are imported selectively; matching by MAC on the same
  layer-2 segment, else IP plus hostname (POSSIBLE MATCH); scheduling
  manual, once or a user-set interval, no default schedule.
- Global search over hostname, IP, subnet, asset, execution ID, module and
  runbook.

## Parts

### M9-1 Assets and IPAM-light (server)

- `server.db`: assets (kind, name, hostname, MAC, notes, optional managed
  host), asset addresses, networks (CIDR, name, VLAN, gateway), pools
  (first–last range), entries (reservations and exclusions with a note).
- Status per address, computed, never stored: EXCLUDED (an exclusion; for
  IPv4 also the network and broadcast address), CONFLICT (two assets or
  hosts claim it, or discovery saw another MAC than the asset's), ASSIGNED
  (an asset address or a managed host endpoint), RESERVED, DISCOVERED (seen
  by discovery, nobody claims it), FREE; UNKNOWN for networks too large to
  list (IPv4 larger than /22, IPv6).
- **Decision 1 (default):** the free-IP suggestion lists up to 5 FREE
  addresses of the chosen network or pool that discovery has not seen in
  the last 30 days, marked "suggestion"; the reachability test is a
  discovery job (M9-2), not a probe from the server.
- Pages under *Network*: networks with their address grid and entries,
  assets with their addresses; "add to managed hosts" opens the inventory
  form prefilled and links host and asset.

### M9-2 Discovery

- `nebula-discovery` reads one job file from a spool directory the server
  writes (`/var/lib/nebula/discovery/jobs`), runs Nmap with fixed
  arguments per mode, parses its XML and writes one result file
  (`/var/lib/nebula/discovery/results`). Started by a systemd path unit;
  `AmbientCapabilities=CAP_NET_RAW`, no other rights, no network listener.
- **Decision 2 (default):** modes host discovery (`-sn`), selected ports
  (`-sS -p LIST`), service discovery (`-sV --top-ports 100`), full TCP
  (`-sS -p-`); "custom" is a fixed allowlist of Nmap options, never a
  free-form command line. Targets are CIDRs or addresses of known
  networks only, at most a /16.
- The server reads results into staging, classifies them (MAC match on
  the same segment → EXISTING or CONFLICT; IP plus hostname → POSSIBLE
  MATCH; else NEW) and imports what the user selects. Scan output is
  untrusted input (spec 09).
- Scheduling: manual, once at a time, or an interval (at least an hour).

### M9-3 Search and managed-host link

- Global search box over hosts, assets, addresses, networks, executions,
  runbooks and modules; results link to their pages; quick actions go to
  the operation planner (normal approval path).

## Order and release

M9-1 → M9-2 → M9-3, each its own PR with a Hermes review; Release 0.5
after M9-3.
