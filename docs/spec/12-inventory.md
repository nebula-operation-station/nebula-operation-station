<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Inventory, IPAM and discovery

Nebula knows every network asset, manages a subset of them over SSH, and never writes scan results into the inventory without review.

**Assets and managed hosts.** Network assets (server, NAS, firewall, switch, printer, IoT, unknown) are tracked separately. “Add to managed hosts” starts SSH enrollment and keeps the asset's identity. Managed hosts carry environment (DEV, QA, PROD), criticality (LOW to CRITICAL, meaning the impact of a disruption), groups, tags (`role=web`, `gpu=a2000`) and saved selections, static or dynamic.

**Ops State instead of a health score.** READY, WARNING, UNREACHABLE or UNKNOWN, each with `observed_at`, `source` and `reason`, for example “WARNING · 21:13 · reboot required”.

**IPAM-light.** Networks and subnets, simple pools, reservations, assignments, exclusions, conflict indication. IP status: FREE, RESERVED, ASSIGNED, DISCOVERED, CONFLICT, EXCLUDED, UNKNOWN. A free-IP suggestion combines IPAM state, reservations, discovery and an optional targeted reachability test, and is shown as a suggestion, never as certainty. No DHCP or DNS management.

**CSV import.** A mapping screen assigns arbitrary columns, for example `server_name` → display name, `ip` → endpoint 1, `vpn_ip` → endpoint 2.

**Discovery.**

- Nmap modes: host discovery, selected ports, service discovery, full TCP, custom. Nmap is an optional dependency.
- Runs in `nebula-discovery`, a one-shot systemd service with `AmbientCapabilities=CAP_NET_RAW`; neither server nor executor gets raw-socket rights.
- Results land in staging, classified NEW, EXISTING, POSSIBLE MATCH or CONFLICT, then imported selectively or all at once.
- Matching uses the MAC address where the scanner shares the layer-2 segment, otherwise IP plus hostname. Across VPNs and routed networks there is no MAC, so those matches are shown as POSSIBLE MATCH.
- Scheduling is manual, once, or an interval the user sets. There is no default schedule.

**Global search** over hostname, IP, subnet, asset, execution ID, module and runbook. Quick actions from search go through the normal approval path.
