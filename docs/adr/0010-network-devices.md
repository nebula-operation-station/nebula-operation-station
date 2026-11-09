# ADR 0010: Network devices: switch configuration and firewall

Status: **Accepted, 2026-11-09** (previously: proposed, draft by Claude for
maintainer review, 2026-11-08, awaiting the maintainer's answers to the open
questions). The maintainer answered Q1–Q13 in chat on 2026-11-09,
00:07–01:10 UTC+1; the answers are recorded in "Decisions 2026-11-09" below
and at each question. Every *verify* still has to pass the lab verification
ND-03 before code depends on it. Revised after review round 1 (keyed config
digests, PAN-OS allowlist, CBS reload precondition, object edits under the
path rule, parse limits).

## Context

The maintainer asked on 2026-11-08 for a new milestone: NOS manages network
devices next to hosts and Proxmox. The reference lab has:

- Cisco Business switches (CBS series, for example CBS250 and CBS350);
- a Palo Alto Networks firewall running PAN-OS, the edge of the lab
  network (a private /24, written `<lab-net>` here) and of the lab's public
  name (written `<public-name>`); the concrete subnet and domain are kept
  out of this public document (previously named here verbatim);
- later a pfSense firewall (previously OPNsense: the maintainer first wrote
  OPNsense and corrected it to pfSense the same day).

These devices are not Linux hosts. NOS cannot run its SSH actions on them,
and they cannot be enrolled with the `nebula` user and its sudo rule. They
are, however, the devices whose misconfiguration takes the whole lab
offline, including NOS itself. This ADR therefore starts read-only and makes
every change a narrow, typed, approved and reversible operation.

The decisions build on:

- [Spec 06](../spec/06-credentials.md): the executor alone holds keys and
  vault secrets; PVE tokens (v23-06-02 to v23-06-06) are the model for any
  provider credential.
- [Spec 08](../spec/08-ssh-transport.md): host keys pinned per host, pinned key
  type only, hard stop on mismatch or authentication failure.
- [Spec 09](../spec/09-untrusted-host-data.md): everything a device returns is
  untrusted input.
- [Spec 16](../spec/16-milestones.md): network inventory and IPAM are
  milestone 9; Proxmox is the first provider after 1.0. Network devices are
  a new milestone after those.
- [ADR 0006](0006-proxmox-integration.md): provider remotes, pinned HTTPS,
  executor-held credentials, a collector without credentials writing to a
  spool, typed reads, typed actions, durable reconciliation that never
  re-sends a mutation.
- [ADR 0007](0007-approval-ergonomics.md): read leases (7-day default,
  30-day maximum, typed provider profile), `batch-v1` exact plans, no
  automatic rollback, no unattended change.
- [ADR 0009](0009-traffic-map.md): observed endpoints and VLAN zones; its
  "later" list names LLDP switch-port mapping, which this ADR can feed.
- [Threat model](../threat-model.md).

No new dependency is proposed. SSH uses `golang.org/x/crypto/ssh`, HTTPS uses
`net/http`, `crypto/tls`, `crypto/x509`, XML uses `encoding/xml`, diffs use
the existing `internal/textdiff`.

### Source status of vendor claims

No network access and no lab device was available while writing this ADR.
Every vendor claim below comes from memory of the named vendor documents and
is marked *verify*. Ticket ND-03 checks each one against the real lab
devices and the exact document version before any code depends on it. A
claim that fails the check changes the design here first, not the code.

| Family | Documents to check (exact version recorded in ND-03) |
| --- | --- |
| CBS | Cisco *Cisco Business 350 Series Managed Switches CLI Guide* (firmware 3.x); Cisco *Cisco Business 250 Series Smart Switches CLI Guide* (firmware 3.x); Cisco *Cisco Business 220 Series Smart Switches Administration Guide*; the CBS release notes for the installed firmware |
| PAN-OS | Palo Alto Networks *PAN-OS and Panorama API Usage Guide* (XML API and REST API chapters) and *PAN-OS Administrator's Guide* (admin roles, commit, config versions, certificate management) for the installed PAN-OS 11.1 release (Q2, decided 2026-11-09; exact release in the private lab notes; previously: 10.2 or 11.x, open) |
| pfSense | Netgate *pfSense Documentation* (backup and restore, configuration history, user privileges) for CE 2.7.x and Plus 24.x/25.x; the Netgate product pages on the Plus REST API; the community `pfSense-pkg-RESTAPI` project |

## Decisions

### D1: Device model, identity and pinning

- A **device** is one managed network appliance with an immutable local
  `device_id`, a family (`cbs`, `panos`, later `pfsense`), an ordered list of
  management endpoints and one trust pin. Names are labels. A device is not
  a managed host and never gets an SSH action, sudo rule or host-key entry in
  the host registry.
- The executor owns endpoints, pins, trust generation, credential
  references and versions, port and rule criticality, and the last approved
  configuration digest. Server tables are presentation copies (ADR 0006,
  "Remote identity and TLS trust").
- **CBS: pinned SSH host key.** Enrollment probes the endpoint without
  credentials, shows the host-key fingerprint, and stores the pin only after
  the admin types `yes` (spec 08). Every endpoint must present the pin; a
  mismatch blocks the device, emits an executor event and notifies.
- **PAN-OS: pinned TLS certificate.** The management certificate is pinned
  by the SHA-256 of the leaf DER (the PAN-OS default is a self-signed
  management certificate, *verify*), or of an admin-imported issuing CA,
  exactly like a standalone PVE host in ADR 0006, reusing the pin logic of
  `internal/pvetransport` (redirects refused, environment proxies ignored,
  no system-root fallback, SAN checked). No credential is sent before trust.
- **Re-pin** (certificate renewal with a new key, switch reset that
  regenerates the SSH key) is an explicit admin CLI operation showing old and
  new fingerprints, HIGH with user verification; it increments trust
  generation and revokes every lease and permit for the device.
- **Management endpoints are internal only.** NOS reaches the PAN-OS
  firewall on its management interface address inside the lab, never through
  `<public-name>` or a WAN address. Endpoints are **stored and dialled as IP
  literals**: if the admin enters a host name, the executor resolves it once
  at registration, shows the addresses, and stores the confirmed literal; the
  name is kept only as a label and, for PAN-OS, as the expected TLS server
  name for the SAN check. No dial ever resolves DNS, so a later DNS change
  cannot redirect a credentialed connection. The executor also re-checks the
  stored literal at every dial and refuses public, loopback, link-local,
  multicast and unspecified addresses (previously: a public address was
  refused once at registration only). Changing an endpoint is an explicit
  admin CLI operation handled like a re-pin (below).
  The management interface has an internal address only and is not
  reachable from the WAN side (Q5, decided 2026-11-09, verify in ND-03;
  previously open). The address itself is kept out of this repository.
- Discovery (`internal/discovery`) and IPAM never add dial targets for
  devices; they can only suggest that an IPAM asset of kind `switch` or
  `firewall` be registered by the admin.

### D2: Credential custody (new credential class)

Device credentials are a **new credential class** in the executor vault,
handled exactly like PVE tokens (spec 06 v23-06-02, v23-06-05, v23-06-06):

- envelope-encrypted in `executor.db`, decrypted only in the executor after
  unlock; never sent to `nebula-server`, the collector, the browser,
  results, logs, events, spool files, backups in plain text, commit messages
  or test fixtures;
- entered only through `nebula netdev add|rotate-credential|remove|repin`
  on the executor host by the authenticated admin UID, through a
  non-echoing terminal or stdin, never argv, environment, browser or server
  configuration;
- separate credentials per device and per purpose: a **read credential**
  (phase 1) and an optional **change credential** (phase 2, only if the
  maintainer allows one at all, Q3). Q3 decided 2026-11-09 (previously
  open): phase 1 holds the read credential only (CBS user below privilege
  level 15, PAN-OS read-only key); whether a change credential exists at all
  is decided after phase 1 has run. The change credential is never used
  for reads, the read credential never for changes;
- lock wipes them with the rest of the vault and pauses device reads;
  rotation validates the new credential against the pinned transport first,
  then switches the credential version atomically and revokes authority
  bound to the old version; removal disables the device first.

Per family:

| Family | Read credential | Change credential |
| --- | --- | --- |
| CBS | Dedicated local user `nos-read`. Preferred: SSH public-key user authentication with a dedicated executor-held key (CBS supports `ip ssh pubkey-auth` with keys under `crypto key pubkey-chain ssh`, *verify*; which key types, RSA only or also ECDSA/Ed25519, *verify*). Fallback: a password in the vault. Lowest privilege level that can still run `show running-config` (CBS levels 1, 7 and 15; whether level 1 or 7 may show the running config, *verify*). | Dedicated user `nos-change` at privilege level 15 (CBS has no finer command authorization without TACACS+, *verify*). Distinct key or password. |
| PAN-OS | API key of a dedicated administrator `nos-read` with a custom **Admin Role profile**: web UI and CLI disabled, XML API limited to the read operations needed (configuration read, operational requests, no commit, no import, no export of private keys) (*verify* that XML API "Configuration" can be read-only in a custom role, otherwise use the dynamic role "Superuser (read-only)" with web UI and CLI disabled through an authentication profile). The key is generated out of band by the admin (`type=keygen` once, from the admin's own workstation) and pasted into the NOS CLI; NOS never stores the account password. API key lifetime is set on the firewall (*verify*: PAN-OS 9.1+ setting) and is additional to NOS expiry. | API key of a second administrator `nos-change` whose role adds configuration write and commit, still no web UI, no CLI, no import, no software/content install, no certificate or admin-account management. Optional; see Q3. |
| pfSense | Later; see D9. | Later; see D9. |

The PAN-OS API key travels only in the `X-PAN-KEY` request header (*verify*:
supported since PAN-OS 9.0), never in a URL query, so it does not end up in
URL logs. Request bodies are POSTed. No NOS process except the executor ever
holds a header containing it.

Config backups are a second sensitive class: they contain password hashes,
SNMP communities, RADIUS/TACACS+ keys, IKE pre-shared keys and possibly
private-key material. D4 defines how they are redacted before they leave the
executor.

### D3: Transport per family

**CBS (SSH CLI).**

- `golang.org/x/crypto/ssh` from the executor only; never the `ssh` binary,
  never a shell on the NOS side. A small CLI session driver opens one
  interactive session per device at a time (CBS may not support SSH `exec`
  requests, *verify*), disables paging with `terminal datadump` (*verify*),
  waits for a recognised prompt with a bounded deadline, sends one command
  from a fixed allowlist, reads to the next prompt with a byte cap and
  closes. Any unexpected prompt (confirmation, `--More--`, login banner
  change, `(Y/N)`) aborts the session as a failure, never answers it.
- Host-key and algorithm policy is spec 08's. CBS firmware may offer only
  `ssh-rsa` (SHA-1) signatures or small RSA keys (*verify*); spec 08 and
  `internal/sshtransport` accept RSA only as `rsa-sha2-512` with a minimum
  size. If the lab switches cannot meet that, the switch is **unsupported**
  until a reviewed decision (Q1b, decided 2026-11-09, previously open: the
  key types and `rsa-sha2-512` are verified in ND-03; the default stays "no
  algorithm exception", a switch that cannot meet spec 08 is unsupported);
  no silent algorithm downgrade is added for devices.
- **Model support.** CBS350 (managed) has a full CLI over SSH. CBS250 (smart)
  has a CLI over SSH in recent firmware (*verify*). CBS220 (smart) is managed
  through the web UI only and has no SSH CLI (*verify*); a CBS220 is
  **unsupported** in this ADR and appears only as an IPAM asset. Catalyst
  1200/1300 successors are out of scope until checked.
- Read commands (allowlist, exact strings, *verify* each on the lab
  firmware): `show version`, `show system`, `show running-config`,
  `show startup-config`, `show vlan`, `show interfaces status`,
  `show interfaces description`, `show interfaces switchport <if>`,
  `show mac address-table`, `show lldp neighbors`,
  `show lldp neighbors <if>`, `show ip interface`.
- Connect 10 s, command 60 s, 4 MiB per `show running-config`, 1 MiB for
  other commands, one session per device, two commands per second at most.
  Count limits are in "Parse limits" below.

**PAN-OS (XML API over HTTPS).**

- The XML API is the primary interface; the REST API (PAN-OS 9.0+, *verify*)
  covers objects and policies but not commit control, locks, config versions
  or hit counts in a uniform way (*verify*), so phase 1 uses the XML API only.
- Pinned TLS from D1; TLS 1.2 minimum; no redirects; 10 s connect, 60 s
  request; 8 MiB per configuration response, 1 MiB per other response;
  one request in flight per device.
- Read calls (exact forms *verify*):
  - system info: `type=op`, `<show><system><info/></system></show>`;
  - running configuration: `type=config&action=show` on the
    `/config/devices/entry/vsys` and `/config/shared` subtrees, or
    `type=export&category=configuration` (*verify* that the read role may
    use it without export-of-keys rights);
  - candidate status: `type=config&action=get` and
    `<show><config><list><changes/></list></config></show>` (*verify*);
  - config versions: the list of saved running-config versions from
    `<show><config><audit><info/></audit></config></show>` (*verify*);
  - security rules, NAT rules, address and service objects and groups,
    zones, interfaces: subtrees of the running configuration under
    `rulebase/security`, `rulebase/nat`, `address`, `address-group`,
    `service`, `service-group`, `zone`;
  - hit counts: `<show><rule-hit-count><vsys><vsys-name><entry name='vsys1'>
    <rule-base><entry name='security'><rules><all/></rules></entry>
    </rule-base></entry></vsys-name></vsys></rule-hit-count></show>`
    (PAN-OS 8.1+, *verify*), with hit count, first and last hit and the
    counter reset time.
- Requests are built by the executor from typed parameters: rule and object
  names are validated against PAN-OS name rules (63 characters, letters,
  digits, `_.-` and space, *verify*) and inserted with XML escaping into
  fixed xpath templates. No caller can supply an xpath, a `cmd` string or a
  URL.
- Panorama, multi-vsys and HA pairs are out of scope until asked (Q2).
  Q2 decided 2026-11-09 (previously open): the lab has a single PA-400-series
  firewall on PAN-OS 11.1, no HA pair and no Panorama (assumed, verify in
  ND-03). The maintainer did not state the vsys layout; NOS supports a single
  vsys only and refuses a device that shows more than one (verify in ND-03).

**Parse limits (both families).** Every parser enforces named limits next to
its code (ND-04 defines the constants); the values below are upper bounds
far above a lab device and are checked against the ND-03 fixtures. Bytes
are capped before parsing (above); counts and depth while parsing.

| Limit | Value |
| --- | --- |
| Line length (CBS output, any command) | 4 KiB |
| Lines per CBS `show running-config` / `show startup-config` | 100,000 |
| Interfaces per device | 1,024 |
| VLANs per device | 4,094 |
| MAC table entries per device | 8,192 |
| LLDP neighbors per device / per port | 1,024 / 16 |
| XML nesting depth (PAN-OS) | 64 |
| XML elements per response (PAN-OS) | 500,000 |
| Text length of one XML element or attribute (PAN-OS) | 4 KiB |
| Security rules / NAT rules | 10,000 / 5,000 |
| Address and service objects (each) | 20,000 |
| Address and service groups (each) | 5,000 |
| Members per group / group nesting depth | 2,500 / 8 |
| Zones / interfaces (PAN-OS) | 256 / 1,024 |
| Hit-count entries | security-rule limit |

A list over its limit marks the observation `incomplete` (never silently
truncated, never treated as "deleted"); a configuration over a limit, or
an XML document over the depth or element limit, is refused and not stored,
like an unparseable one. Risk derivation (D5) treats incomplete or refused
data as missing, which raises the floor to CRITICAL.

### D4: Phase 1, read only

All phase-1 reads are **LOW** and run under a **device read lease**, a new
provider profile of the ADR 0007 read-grant mechanism (E08): exact
`device_id`, trust generation and pin, read-credential version, typed
methods, minimum intervals, request budget, 7-day default and 30-day
maximum expiry. A lease never authorizes a change.

The collector `nebula-netdev-collector` follows ADR 0006 exactly: its own
Unix user and peercred role, no credentials, no database, no network
listener and no device access. It schedules typed reads over the executor
socket; the executor alone talks to devices, parses, validates and redacts
the results and returns sanitized records; the collector writes them to its
spool; `nebula-server` imports them. It is a **separate binary** with a
shared spool library (Q9, decided 2026-11-09; previously open, with a
second role of the PVE collector as the alternative).

**Data and cadence (defaults).**

| Observation | Default cadence | Content |
| --- | --- | --- |
| Device facts | 60 min | model, serial, firmware/PAN-OS version, uptime, management addresses |
| Configuration | 6 h and on demand | redacted running config and its digests; CBS also startup config and whether it differs from running |
| Ports and VLANs (CBS) | 15 min | port name, admin/oper state, speed, mode access/trunk, access VLAN, allowed/native VLANs, description; VLAN list with names |
| MAC table (CBS) | 15 min | VLAN, MAC, port, type (dynamic/static); capped at 8,192 entries per device |
| LLDP neighbors (CBS) | 15 min | local port, chassis ID, port ID, system name, management address, capabilities |
| Firewall policy (PAN-OS) | 60 min and on demand | security rules in order, NAT rules, address/service objects and groups, zones, interfaces |
| Hit counts (PAN-OS) | 60 min | per rule: hit count, first hit, last hit, counter reset time |

The 15-minute floor of ADR 0007 ordinary reads applies. Device CPUs are
weak: one session or request per device at a time, jitter, exponential
backoff to 15 min, stale after three missed intervals.

**Redaction (in the executor, before anything leaves it).** The raw device
config never leaves the executor, and neither does any unkeyed digest of
it. Per read the executor:

1. **normalizes** the raw config: it drops volatile lines or elements that
   change without a configuration change (CBS header lines with the current
   time or uptime, PAN-OS response timestamps and similar, *verify* in
   ND-03), using a reviewed, family-specific list fixed in ND-07. The list
   only removes content proven volatile in the ND-03 fixtures; it never
   removes a configuration statement. Without this, every read would create
   a new version and every change precheck would fail;
2. computes `raw_digest` = **HMAC-SHA-256** over the normalized raw config
   under the device's **digest key**;
3. redacts the normalized config (rules below) and computes
   `redacted_digest` = SHA-256 of the redacted text (the server holds that
   text anyway);
4. returns only the redacted text and both digests.

**Why keyed (previously: an unkeyed SHA-256).** The server holds the
redacted text, which is the raw config with only the secret tokens
replaced. With an unkeyed SHA-256 of the raw config next to it, a
compromised server (or anyone holding a server backup) could rebuild the
raw config for each guess of a low-entropy secret (SNMP community, RADIUS
or TACACS+ key, PSK, local password) and confirm the guess offline. That
would leak secrets that "never leave the executor". With an HMAC under a key
that exists only in the executor, the server cannot compute or test the
digest of any candidate text.

- **Digest and fingerprint keys.** At device registration the executor
  generates two independent 32-byte keys with `crypto/rand`, the **digest
  key** and the **fingerprint key**, and stores them in the executor vault
  with the device credentials (D2: envelope-encrypted, wiped on lock, never
  exported, never in results, logs or backups in plain text). They are
  per device, so digests and fingerprints cannot be correlated across
  devices. They are not rotated with credentials or pins (a rotation would
  turn every stored version into a "new" one); they are deleted with the
  device. If they are lost (vault restore without them), the next read is
  a new version and the approved baseline must be approved again.
- **No digest oracle.** The executor computes keyed digests and fingerprints
  only over text it read from the device itself or rendered itself for a
  permit; no RPC accepts caller-supplied text to hash, compare or redact.
- CBS (line based, *verify* every keyword against the lab config): replace
  the secret token, keeping the keyword, in lines starting with or
  containing `username ... password`, `enable password`, `enable secret`,
  `snmp-server community`, `snmp-server user`, `snmp-server host ...`
  community fields, `radius-server key`, `radius-server host ... key`,
  `tacacs-server key`, `tacacs-server host ... key`, `encrypted`, `key-string`,
  `password`, `secret`, `passphrase`, `wpa`, and drop entire blocks between
  `crypto key import`/`crypto certificate ... import` and their end marker
  (*verify* whether CBS prints key material in the running config).
- PAN-OS (**allowlist** on the parsed XML; previously a keyword denylist):
  only elements on a reviewed allowlist of known-safe element paths leave
  the executor; every other element is dropped together with its subtree
  and replaced by one marker `<dropped:ELEMENT-NAME count=N>` so the reader
  sees that something was removed. The initial allowlist covers what phase 1
  shows: system info fields (model, serial, sw-version, uptime, management
  addresses); under `vsys`/`shared`: `rulebase/security` and `rulebase/nat`
  rule entries with their name, uuid, from, to, source, destination,
  source-user, application, service, category, action, disabled,
  description, tag, NAT translation fields; `address`, `address-group`
  (static members and dynamic filter), `service`, `service-group`, `tag`,
  `zone` (name and member interfaces only) and the interface names, units,
  VLAN tags and IP addresses under `network/interface` (exact paths
  *verify* against the PAN-OS schema of the installed release, fixed in
  ND-07). Attributes other than `name` and `uuid` are dropped. Everything
  else (`mgt-config`, `shared/certificate`, `ssl-tls-service-profile`,
  `authentication-profile`, `server-profile`, `network/ike`,
  `network/tunnel`, `global-protect`, `deviceconfig`, and every element a
  newer release adds) is dropped by default. Inside allowed elements the
  keyword rule below still applies as defence in depth.
- **Fail closed (keyword rule).** For CBS, and inside allowed PAN-OS
  elements, any line or element whose keyword is not on the reviewed list
  but whose name or content matches `key|pass|secret|community|hash|psk|
  private|token|cert` (case-insensitive) is also redacted and flagged
  `redacted:unknown` so the list gets reviewed. An unparseable config is not
  stored at all.
- **Stated limit for CBS.** CBS redaction stays a keyword denylist plus the
  keyword rule: a secret in a positional field of a command whose keyword is
  not listed and does not match the pattern would pass. ND-03 records the
  full command vocabulary of the lab configs so the list can be reviewed.
  CBS switches to an **allowlist of command keywords** (unlisted lines
  dropped with a marker) once ND-03 has recorded that vocabulary; until then
  the limit stands as stated here (Q13, decided 2026-11-09 per the ADR
  recommendation; previously open).
- Redaction replaces values with `<redacted:FP>`, where FP is the first
  8 hex characters of **HMAC-SHA-256** under the device's fingerprint key
  over the field identity and the value (previously: a salted SHA-256).
  The field identity is the full line identity, not only the keyword: for
  CBS the keyword plus the identifying fields of the line (for example
  `username <name>`, the RADIUS server address), for PAN-OS the element
  path with all names (previously: the CBS keyword only, which gave the
  same fingerprint for one password reused by two local users). A changed secret still shows up as a diff
  line; without the key the server can neither test guesses nor compare
  values across devices or fields. No hand-made salting or other
  construction is used (AGENTS.md rule 4); HMAC comes from `crypto/hmac`.
- PAN-OS drift outside the allowlist changes `raw_digest` but not the
  redacted text; the UI then shows "configuration changed in elements not
  displayed" instead of an empty diff.

**Config versions, diff and drift.**

- Each distinct `raw_digest` becomes a new version; an identical read only
  updates `last_seen`. The server stores the redacted text, both digests,
  the read time and the reading lease ID.
- Diffs between versions use `internal/textdiff` on the redacted text; a
  PAN-OS config is normalized first (stable element order, one element per
  line) so the diff is readable.
- **Approved baseline.** The admin can mark a version as the approved
  baseline: an audited executor operation (MEDIUM, privileged session) that
  stores `raw_digest` in the executor registry. Drift is "current
  `raw_digest` differs from the approved one"; the UI shows the redacted diff
  and who changed it if the device says so (PAN-OS commit admin and time,
  *verify*; CBS has no change author). A compromised server cannot make
  drift disappear in the executor's view; the CLI `nebula netdev drift`
  shows the executor's verdict.
- Retention: every distinct version for 400 days, at most 1,000 versions
  per device; the approved baseline and the versions bound to changes in the
  last 400 days are never pruned (Q11, decided 2026-11-09 as proposed;
  previously open). Unredacted backups are **not** stored, in any phase:
  NOS keeps redacted versions only and the devices keep their own config
  (Q8, decided 2026-11-09; previously open, with age-encrypted raw backups
  in the executor as the alternative).

**Integration points.**

| Data | Where it goes |
| --- | --- |
| Device as an asset | `internal/ipam` `Asset` with kind `KindSwitch` / `KindFirewall` (kinds already exist); device facts link to the asset by explicit admin choice, MAC is a suggestion only (`ipam.NormalizeMAC`) |
| VLANs | `ipam.Network.VLAN`: switch VLAN IDs and names are shown next to IPAM networks; mismatch (VLAN on the switch without an IPAM network, or the reverse) is a hint, never an automatic edit |
| MAC table | ADR 0009 observed endpoints (`internal/trafficstore` endpoints, `internal/trafficingest`): MAC → switch port and VLAN, tier "switch", reporter = device; IPAM `Seen`-style hints for addresses |
| LLDP | ADR 0009 "LLDP switch-port mapping": which managed host or PVE node (`internal/trafficstore/guestnics.go` bridge data) sits on which port; uplinks between switches; source-labelled, never a placement |
| Firewall zones and interfaces | traffic map zones and the hop of ADR 0009 D3 (the firewall becomes the named gateway node of `<lab-net>`) |
| Firewall rules | a new read-only firewall page; later possibly ADR 0009 segmentation hints, which are a separate decision |

Neighbor data from LLDP is doubly untrusted: any device on any port can send
LLDP frames with arbitrary names. It is shown with its source and never
creates assets, hosts, placements or port criticality on its own.

**Firewall view.** Ordered security rules with zones, addresses (objects
resolved, groups expandable), applications, services, action, disabled
flag, NAT rules, objects and where each object is used. Hit counts show
count, first and last hit and "since counter reset at". **Unused-rule hint**:
zero hits since the later of rule creation and counter reset, and at least
30 days observed; it is a hint labelled with the observation window, never a
proposal to delete. Shadowed-rule analysis is not in phase 1.

**Who may read.** Device pages are server-rendered for logged-in users with
the existing inventory read access. Config text is redacted, but it still
reveals the lab's layout, so config versions and the firewall view are
admin-only pages, are included in the age-encrypted instance backup and are
never exported in clear text.

### D5: Phase 2, changes

Phase 2 starts only after the maintainer's answer to Q3 and an accepted spec
revision. Q3 was answered on 2026-11-09 (previously open): phase 2 is
decided only after phase 1 has run in the lab; until that decision no
change credential is provisioned and nothing in this section is
implemented. Rules for every change:

- **Typed operations only.** No free-form CLI line, no xpath, no XML snippet
  and no config file upload. The executor builds the exact device commands
  from typed parameters.
- **Permit binds:** `device_id`, family, trust generation and pin,
  change-credential version, operation and adapter version, typed
  parameters, the **exact rendered change** (CBS command lines; PAN-OS
  xpath and element per call) and its digest, the **expected pre-change
  `raw_digest`** (and for PAN-OS the running config version number), the
  **inverse change** (rollback) and its digest, the effective risk, the
  stage plan and expiry. The admin sees the redacted config diff the change
  will produce and its inverse before approving (ADR 0007 rules for the
  full view; hardened CLI for HIGH and CRITICAL).
- **Precheck:** the executor reads the device again; if `raw_digest` or the
  PAN-OS config version differs from the bound one, or PAN-OS has pending
  candidate changes not made by NOS, the change is refused and needs a new
  proposal.
- **No unattended changes.** No schedules or leases over writes, no
  automatic remediation of drift, no "apply baseline" button that writes.
- **One device change at a time**, durable intent in `executor.db` before
  dispatch (ADR 0006 reconciliation rules).

**Operations in phase 2 (initial set).**

| Operation | Family | Base risk |
| --- | --- | --- |
| Set port description | CBS | MEDIUM |
| Set access VLAN of an access port | CBS | MEDIUM on an edge port, HIGH otherwise |
| Shut / no shut an access port | CBS | MEDIUM on an edge port, HIGH otherwise |
| Add or remove a VLAN on a trunk's allowed list | CBS | HIGH |
| Persist running to startup config (`copy running-config startup-config`, *verify* prompt) | CBS | MEDIUM, separate approval bound to the verified `raw_digest` |
| Add / edit an address object or group not referenced by any rule, before or after the change (also not through nested groups or a dynamic group tag match) | PAN-OS | MEDIUM (effective HIGH under the default firewall criticality, see below) |
| Edit an address object or group referenced by a rule (directly, through nested groups, or through a dynamic group whose filter matches its tags) | PAN-OS | HIGH; CRITICAL through the path rule below |
| Add a security rule at an exact position | PAN-OS | HIGH |
| Disable / enable a security rule | PAN-OS | HIGH |
| Move a security rule to an exact position | PAN-OS | HIGH |
| Delete a security rule, **only as the bound inverse** of an "add a security rule" | PAN-OS | HIGH |
| Delete an address object or group, **only as the bound inverse** of an "add", and only while no rule references it (directly, nested or through a dynamic group); otherwise refused | PAN-OS | MEDIUM (effective HIGH under the default firewall criticality) |

**Inverse operations.** Every bound inverse is itself one of the typed
operations in this table (previously: inverses were bound but not listed,
so "delete rule" had no stated risk). Port description, access VLAN,
shut/no shut, trunk VLAN add/remove, rule disable/enable, rule move and
object edit are their own inverses (the old value, the old state, the old
position); "add" on PAN-OS is undone by the two delete rows above, which are
not offered as standalone operations in phase 2. A change whose inverse
cannot be expressed as an operation in this table is refused.

**A rollback is a change** (previously: "the same risk" as the original).
Its effective risk is the **maximum of the original change's effective risk
and the risk the executor re-derives at rollback time** for the inverse
operation, with the rules below applied to the then-current port roles,
device criticality and a fresh read of MAC, LLDP and firewall policy data.
A rollback is never approved below the original change's risk, and is
raised if the device or the NOS path changed since (for example a rule
whose deletion now removes an allow for NOS-path traffic). Every rule for
changes of that risk applies to the rollback unchanged: CRITICAL is refused
in phase 2a, and in phase 2b it runs only with the same device-side reload
timer (CBS) or executor dead-man (PAN-OS) and confirm window (D6).

**Risk floors (executor-derived, never lowered by the server).**

- **Port roles** are executor-owned, like host criticality: `edge`,
  `uplink`, `management`, `nos-path`, `unknown`. The admin sets them through
  the CLI or an approved change; LLDP or MAC data can only *suggest* a
  role. `unknown` counts as `uplink`. Raising a role (towards a higher
  floor) is a MEDIUM change; lowering one is approved at the floor of the
  **old** role (previously: any role change was MEDIUM, so one MEDIUM
  approval could unlock MEDIUM changes on an uplink), and a `nos-path` role
  is removed only through the executor CLI by the admin UID, never through a
  server-proposed change.
- **Role floors apply to every operation on the port, independent of MAC
  age** (previously: only the 24-hour MAC rule below reached CRITICAL):
  `nos-path` **CRITICAL**; `management` at least **HIGH**; `uplink` and
  `unknown` **HIGH**; `edge` no floor.
- Uplinks, trunks, LAG members and any port carrying the switch's
  management VLAN: **HIGH**, whatever their role.
- **CRITICAL: anything that can cut NOS's own management path**: a port
  where the MAC of the NOS machine, its default gateway or another managed
  switch on NOS's path was learned in the last 24 h; the management VLAN or
  the switch's own IP interface; any firewall rule change whose source or
  destination overlaps the NOS machine's addresses, the management
  networks of devices or the path from NOS to managed hosts (Q4) (the
  **NOS path**); disabling or deleting a rule that allows NOS-path
  traffic; moving,
  adding or enabling a deny/drop rule above a rule that allows NOS-path
  traffic. A deny
  above an allow that does not carry NOS-path traffic is not raised by this
  rule. If the MAC table, LLDP data or firewall policy needed to decide is
  stale, incomplete or missing, the floor is CRITICAL.
- **Flat network: the path rule tightens (Q4, decided 2026-11-09;
  previously open).** The lab is currently **one flat network without a
  management VLAN**; the maintainer plans segmentation. Until a management
  VLAN exists and is recorded by an amendment of this ADR, the executor
  applies these rules unconditionally (they are not an executor setting and
  the server cannot switch them off):
  - A switch **carries the NOS path** if its MAC table or LLDP data shows,
    learned in the last 24 h, the MAC of the NOS machine, of its default
    gateway, or of **any managed device** (managed host, PVE node, managed
    switch or firewall), or if that data is stale, incomplete or missing
    (fail closed). On such a switch **every port, VLAN and uplink change is
    CRITICAL** (and so refused, Q6), whatever the port role, the MAC age of
    the individual port or the operation base; this includes port
    descriptions, access VLAN, shut/no shut, trunk allowed VLANs and
    persisting to startup of such a change. In the lab today this is every
    switch that is not proven off the path.
  - The single VLAN that carries the lab is the management VLAN for every
    CBS rule above (previously: a separate management VLAN was assumed).
  - The management networks of the devices are the whole flat lab network
    `<lab-net>`, so every firewall rule change whose source or destination
    overlaps `<lab-net>` (including `any`) overlaps the NOS path and is
    CRITICAL; this follows from the NOS-path definition above.
  - The PAN-OS management interface sits on the flat network, not on a
    separate management segment, so a switch change can cut NOS's path to
    the firewall too; it is covered by the switch rule above.
  - The rule ends only with an ADR amendment that records the management
    VLAN, the switches and ports that carry it, and the uplinks, after the
    segmentation exists; ND-31 implements the flat-network rule as the
    default until then.
- **Object edits go through the rules that use them** (previously: a
  referenced object edit was fixed at HIGH). An address object or address
  group changes the effective match of every rule that references it.
  Service objects and service groups are **not** in the initial operation
  set; if a later revision adds them, the same rule applies with the NOS
  path's ports and protocols as the overlap test. For such an edit the executor, from its own fresh read
  bound by the precheck digest, finds every security and NAT rule that
  references the object directly, through nested groups (to the group depth
  limit), or through a dynamic address group whose tag filter matches the
  object before or after the edit (a tag edit is an edit of every such
  group). For each referencing rule it evaluates the match with the old and
  the new object value; if either overlaps the NOS path, the edit is
  CRITICAL. An object whose addresses NOS cannot evaluate (FQDN objects,
  external dynamic lists, unresolvable references, depth limit reached)
  counts as overlapping. Only an object that no rule references, directly
  or indirectly, keeps the MEDIUM base.
- Risk is the maximum of operation base, port role, device criticality
  (executor-owned, default HIGH for firewalls and MEDIUM for switches) and
  the path rule above. With the default firewall criticality **every
  PAN-OS change is at least HIGH**, including the MEDIUM-base unreferenced
  object add or edit; that base matters only if the admin lowers the
  firewall's criticality (executor-owned and changed like host
  criticality, never by the server).
  The plan's risk summary repeats exactly these classes.
- **CRITICAL is refused for good** (Q6, decided 2026-11-09; previously:
  refused in phase 2a, with a phase 2b that might allow CRITICAL with the
  dead-man rollback below after the maintainer decides Q6), as ADR 0006
  does for containers. Phase 2b and ND-40 are not planned.

**Out of scope for every phase (non-goals for changes):** AAA, users, SSH
server, HTTPS server, SNMP, management IP or management interface settings,
certificates, firmware/software/content updates, STP, LAG, routing, VPN/IKE,
GlobalProtect, HA, zone and interface definitions, decryption, licensing,
factory reset and reboot. These are exactly the changes that lock NOS or the
admin out, or that need secrets.

### D6: Apply, verify and rollback per family

**Decided 2026-11-09 (Q6):** CRITICAL changes are refused for good, so the
CRITICAL-only parts of this section (CBS reload timer and confirm window,
PAN-OS executor dead-man and its lock rule, CRITICAL rollbacks) are **not
implemented**; they stay here as the record of the option the maintainer
rejected (previously: planned for phase 2b). A CRITICAL change or rollback
is refused at proposal. The non-CRITICAL steps apply if phase 2 is decided
(Q3).

**CBS.**

1. Precheck (D5). Store durable intent.
2. If the change is CRITICAL (phase 2b only) and `reload in <minutes>`
   exists on the firmware (*verify*), arm it first. A reload restores the
   pre-change state only if the startup config **is** the pre-change state,
   so before arming the executor requires, from one fresh read of both
   configs:
   - the running `raw_digest` equals the bound pre-change digest, and
   - the startup config's keyed digest equals the running one (running ==
     startup after normalization; previously assumed, not checked).
   If running differs from startup (unsaved earlier or foreign changes), the
   CRITICAL change is refused; the admin first persists or reverts that
   state through its own approval and proposes again. After arming, the
   executor confirms the timer is pending (`show reload`, *verify*) and
   re-reads running and startup; if either changed, it cancels the reload
   and aborts without sending any change line (`not_applied`). If that
   cancel cannot be confirmed (`show reload` still pending, or the session
   is lost), the change is `unknown` and the admin is notified at once: no
   change line was sent, but the switch may reload.
   **While a NOS reload timer is pending on a switch**, the executor refuses
   every other NOS write to it, in particular a persist approval (step 6)
   and a rollback (step 7): persisting would make the reload boot into the
   changed state, so the rollback would silently stop being one.
3. Enter `configure`, send the exact bound lines, `end`. The startup config
   is **never** written in the same permit.
4. Read the running config again. Success means `raw_digest` equals the
   expected post-change digest the executor computed when it built the
   permit (CBS config is canonical enough for line insertion, *verify*; if
   not, compare the affected interface stanza only, which the ADR then
   records). Postchecks: the device is reachable, port state and VLAN as
   expected, NOS still reaches its own path (gateway ARP, the switch).
5. CRITICAL: `reload cancel` (*verify*) only after the postchecks pass and
   the admin confirms within the confirm window (default 5 min). Without
   confirmation the switch reloads into the startup config, which is the
   rollback. **Precondition of that rollback: startup is still the
   pre-change config.** NOS cannot lock the CBS startup config, so another
   admin (or a `write memory` on the console) can save during the window.
   The executor therefore re-reads the startup digest during the window (at
   least every 60 s and once more no later than 60 s before the deadline,
   named limits) and before any cancel. If the startup digest is no longer
   the pre-change one, the reload would boot into a config nobody approved
   (not the pre-change state, and possibly not the change either), so the
   executor **cancels the reload at once** (previously: the timer stayed
   armed), marks the change `unknown` and notifies; the change stays in
   running and the admin decides. If the executor cannot read the startup
   config or cannot cancel (session lost, vault locked, executor down), the
   timer fires on the device: the switch boots into whatever startup holds,
   and reconciliation afterwards records `rolled_back` only if running
   equals the pre-change digest, otherwise `unknown`. The timer runs on the
   device, so an executor restart or a vault lock does not stop it; after a
   restart the executor reconciles from the durable intent and `show
   reload`.
6. Persisting to startup is the separate MEDIUM approval listed in D5,
   bound to the verified running `raw_digest`. Its precondition: the
   current running `raw_digest` equals the bound one and no reload timer is
   pending (`show reload` shows none, *verify*); otherwise it is refused
   and nothing is written. Until then a power cycle
   also restores the previous state; the UI shows "running differs from
   startup" prominently.
7. **Rollback** of a non-persisted or persisted change is the inverse lines
   bound in the original permit, executed under its own approval (never
   automatic, except the device-side reload in step 5). Its risk is the
   maximum of the original change's effective risk and the risk re-derived
   at rollback time (D5, "A rollback is a change"; previously: "the same
   risk").
   Precondition: the current running `raw_digest` equals the verified
   post-change digest of the original change; otherwise the inverse no
   longer describes the way back and is refused, and a new typed change
   must be proposed. It is also refused while a reload timer is pending
   (step 2). A rollback below CRITICAL runs through steps 1, 3 and 4.
   **A CRITICAL rollback** (phase 2b only) runs through steps 1 to 5 like
   any CRITICAL change (previously: steps 1, 3 and 4 only, so the rollback
   of a CRITICAL change had no reload timer and no confirm window): the
   reload timer is armed first, under the step-2 preconditions applied to
   the rollback's own pre-state, i.e. running equals the verified
   post-change digest **and** startup equals running. The reload must boot
   into the state NOS last confirmed, not into the rollback's target; a
   reload into a startup that already is the rollback's target is no safety
   net if the rollback cuts the path. A CRITICAL rollback of a
   non-persisted change is therefore refused until the admin has persisted
   the confirmed post-change state (step 6); the other way back is a
   reload into the pre-change startup done by the admin on the device
   (NOS never sends `reload` without a timer; reboot is out of scope).
   After arming, the startup re-reads,
   the immediate cancel on a startup change, the confirm window and the
   `reload cancel` only after postchecks and confirmation (step 5) apply
   unchanged. Without confirmation the switch reloads into the post-change
   state: the rollback is undone, its result is `rolled_back`, and the
   original change stays in place. If a line fails or the outcome is
   uncertain, the rollback is `unknown`. The inverse never writes the
   startup config; persisting it is again the separate MEDIUM approval.

If `reload in` does not exist on the lab firmware, CRITICAL CBS changes stay
refused.

**PAN-OS.**

1. Precheck (D5): running config version and `raw_digest` match, no
   pending candidate changes from anyone (*verify* the change-list call),
   no config or commit lock held by another admin. This first check only
   avoids taking locks needlessly; it is not relied on.
2. Take a **config lock** and a **commit lock** for `nos-change`
   (`<request><config-lock><add>` and `<request><commit-lock><add>`,
   *verify*). **Then repeat the whole precheck under the locks** (previously:
   only before the locks, so another admin could add candidate edits in
   between): running config version and `raw_digest` still equal the bound
   ones and the candidate holds no pending change from anyone. Only this
   second check makes the step-7 `revert` safe. If it fails, the executor
   releases both locks **without** a revert (the pending edits belong to
   someone else), sends nothing else and refuses the change (a new proposal
   is needed); nothing was applied, so the result is `not_applied`. If a
   lock cannot be taken, the change is refused the same way.
3. Apply the bound `set`/`edit`/`move`/`delete` calls to the candidate
   config.
4. Read the candidate subtree back and compare it with the bound expected
   result. **Validate** (`<validate><full/></validate>`, *verify*) and poll
   its job.
5. **Partial commit** of only `nos-change`'s changes
   (`<commit><partial><admin><member>nos-change</member></admin></partial>
   </commit>`, *verify*), with a description containing the permit ID. Poll
   the commit job ID; store it durably before reporting.
6. Record the new running config version; read back; verify `raw_digest`
   and the rule/object subtree; postchecks (management reachability, the
   rule appears in order, optional hit-count movement is a hint only).
7. Release both locks. Any failure before commit: `revert` the candidate
   (`<revert><config/></revert>`, PAN-OS 9.0+, *verify*) and release locks.
   Precondition: NOS still holds the config lock taken in step 2, and the
   step-2 re-check showed an empty candidate, so the candidate holds only
   `nos-change`'s edits. If the lock was lost or its state cannot be read,
   the executor does not revert (it could discard another admin's work),
   marks the change `unknown` and notifies. If the revert call itself fails,
   the change is also `unknown`; the executor still tries to release the
   locks.
   **Locks when a change becomes `unknown`** (for example the commit job ID
   was lost): the executor keeps both locks only for one bounded
   reconciliation attempt (default at most 10 minutes, a named limit), so
   no other admin commits while NOS cannot tell what was committed. Then it
   releases both locks without a revert, whatever the outcome, and
   notifies. Releasing does not weaken later rollbacks: every later
   approved NOS write on the device (rollback or corrective change) takes
   fresh locks and re-runs the step-2 check against the then-current state.
   An `unknown` change has no dead-man any more; the automatic inverse never
   takes fresh locks (lock rule for the dead-man, below). If the
   executor cannot release the locks (no session, change credential wiped
   by a vault lock), the UI says so and names the device-side way to
   remove them (a superuser removes the lock on the firewall, *verify*).
8. **Rollback** after a commit: load the previous running config version
   into the candidate (`<load><config><version>N</version></config></load>`,
   *verify*) is coarse: it also reverts changes by other admins made later.
   The default rollback is therefore the bound inverse operation, under its
   own approval at the maximum of the original change's effective risk and
   the risk re-derived at rollback time (D5, "A rollback is a change"), run
   through steps 1 to 7 with the precheck against the
   post-change state: the running config version is the one NOS committed,
   `raw_digest` equals the verified post-change digest, and no foreign
   candidate change is pending (checked again under the locks). If any of
   these fails, the rollback is refused, nothing is written, and a new typed
   change must be proposed. "Load version N" is offered only under the same
   preconditions and is refused the same way. A rollback that fails during
   apply or whose outcome is uncertain is `unknown` like any change.
   **A CRITICAL rollback** (phase 2b only) also uses the executor dead-man
   below with its confirm window and lock rule (previously: steps 1 to 7
   only, so it had no dead-man): step 7 does not release the locks; the
   admin must confirm within the window; without confirmation the executor
   applies the rollback's own bound inverse, which is the original change
   as committed and verified before, under the dead-man preconditions. The
   rollback permit binds that inverse like any change permit (D5). "Load
   version N" is not offered for a CRITICAL rollback, because its inverse
   is not a typed operation.

PAN-OS has no device-side commit-confirmed timer like Junos (*verify*). The
management interface is out of band, and security rules do not apply to
traffic to the dedicated management port (*verify*), so a rule change cannot
cut NOS's path **to the firewall**; it can cut NOS's path to everything
behind it. CRITICAL firewall changes in phase 2b therefore use an
**executor-side dead-man**: after commit and postchecks the admin must
confirm within the window; without confirmation the executor applies the
bound inverse change.

**Lock rule for the dead-man (one rule for the window, the expiry and a
restart).** The automatic inverse is sent only under the config and commit
locks that `nos-change` took in step 2 of the change and held **without a
gap** until expiry; step 7 does not release them for a CRITICAL change, and
they are released only after the admin's confirmation or after the
dead-man has finished. The executor **never takes fresh locks for the
automatic inverse** (previously: the restart rule took fresh locks if NOS
no longer held them, which contradicted this precondition). The locks live
on the firewall, not in the executor process (*verify* that they survive
the end of an API session and an executor restart). Preconditions at
expiry, checked in this order:

1. both locks are still held by `nos-change` (read from the device,
   *verify* the lock list calls); a lock that is missing, held by someone
   else, or whose state cannot be read fails the check;
2. the running config version and `raw_digest` still equal those of the
   NOS commit;
3. no foreign candidate change is pending.

If any precondition fails, the executor writes nothing, marks the change
`unknown` and notifies; it then releases whatever locks it still holds,
without a revert. Fresh locks are taken only for writes an admin approves
afterwards (a step-8 rollback or a corrective change), never by the
dead-man. If the
inverse is applied and verified, the change is `rolled_back`; if applying it
fails or its outcome is uncertain, the change is `unknown`.

The dead-man lives in the executor, not on the device, so it only works
while the executor runs with an unlocked vault. Its rules:

- **Durable deadline.** The absolute deadline (wall-clock time from the
  injected clock) is stored in the durable intent in `executor.db` before
  the commit is sent. It does not live only in memory.
- **Executor restart in the window.** On start the executor finds the open
  dead-man in the durable intent. A confirmation that arrives after the
  deadline is refused. If the deadline has passed or passes later and the
  vault is unlocked, the executor runs the expiry check above under the
  lock rule: it reads whether `nos-change` still holds both locks and does
  **not** take fresh ones (previously: fresh locks, then the step-2 check);
  if a lock is gone, nothing is written and the change is `unknown`. It
  applies the inverse only if every precondition holds. If the vault is still locked
  after the restart, the next point applies.
- **Vault locked in the window, or at expiry.** A vault lock wipes the
  change credential, so the inverse cannot be sent. The executor does not
  wait for an unlock: it marks the change `unknown` at the moment of the
  lock (or at expiry if it finds the vault locked), records "dead-man not
  executed: change credential unavailable", and notifies. The change then
  stays applied. After unlock, the admin reviews and either confirms the
  state as a new baseline or approves the bound inverse as a rollback
  (step 8 preconditions, at its re-derived risk; if that is CRITICAL, the
  rollback again runs under the dead-man). The locks held by `nos-change` cannot be
  released without the credential; the UI states this as in step 7.
- **Stated limit.** The dead-man is fail-open: an executor crash that does
  not come back, a vault lock, or a superuser removing `nos-change`'s locks
  in the window, leaves the CRITICAL change in place. This
  is weaker than the CBS device-side timer and is part of what Q6 decides.

This is an automatic rollback and an explicit,
bounded exception to ADR 0007 ("no automatic rollback"), so it needs the
maintainer's decision Q6 and the spec revision. Q6 decided 2026-11-09
(previously open): the exception is **not** granted; ADR 0007's "no
automatic rollback" stands unchanged.

**What "uncertain" means.** A change is `unknown` when the executor cannot
prove whether it was applied: the session or HTTPS response was lost after
any change line or call was sent, or a commit job ID was not received.
Reconciliation reads the device with the read credential: if `raw_digest`
equals the expected post-change digest, the result is `success`; if it
equals the pre-change digest (and, for PAN-OS, no candidate change and no
NOS commit job exist), it is `not_applied`; anything else stays `unknown`.
A change with an open confirm window (CBS reload timer, PAN-OS dead-man) is
never `success` before the admin's confirmation: reconciliation first
checks the timer (CBS `show reload`, *verify*; PAN-OS the durable deadline),
and while it is pending the change stays "awaiting confirmation". The
rollback outcome governs: after a device reload or an applied inverse,
running equal to the pre-change digest is `rolled_back`.
An `unknown` device is blocked for further changes until the admin reviews
the redacted diff and either accepts the current state as a new baseline or
approves a corrective change. Nothing is ever re-sent automatically and no
other endpoint is tried for a mutation.

### D7: Threat model additions

| Threat | Defence |
| --- | --- |
| New credential class (switch passwords/keys, firewall API keys) leaking | Executor vault only, per device and purpose, read and change credentials separate, local CLI entry, header-only API key, no secret in results/logs/events/spool, rotation and revocation as for PVE tokens |
| Config backups containing hashes, PSKs, communities, private keys | Redaction in the executor before anything leaves it: PAN-OS element allowlist, CBS keyword list (limit stated, Q13), fail-closed keyword rule, unparseable or over-limit configs not stored; config digests and value fingerprints are HMAC-SHA-256 under per-device executor keys, so the server cannot confirm guessed secrets; admin-only pages, age-encrypted instance backups; raw configs never stored in phase 1 |
| Lock-out of NOS's (or the admin's) management path | Read-only first; out-of-scope list in D5; executor-owned port roles and path floor, tightened for the flat lab network (D5, Q4); CRITICAL refused for good (Q6, decided 2026-11-09; previously: refused in phase 2a, device-side reload timer (CBS) or executor dead-man (PAN-OS) only in phase 2b); startup config untouched until a separate approval |
| Compromised or spoofed device feeding the UI (names, descriptions, LLDP, rule comments, banners) | Spec 09: bounded, UTF-8, printable text only, rendered as escaped text; LLDP labelled by source; device data never creates assets, roles, placements or permits |
| Man in the middle on the management path | Pinned SSH host key / TLS certificate, hard stop on mismatch, explicit re-pin |
| CLI or XML injection through parameters (newline in a port description, quote in a rule name) | Typed parameters with strict character sets and length limits, interface names only from the device's own enumerated list, XML built with escaping into fixed xpath templates, no caller-supplied commands or xpaths |
| Compromised server proposing harmful changes | It can only propose typed operations; the executor derives the risk from its own port roles and path data and binds the exact rendered change and its pre-change digest; hardened CLI approval shows the executor's own diff |
| Concurrent manual changes by another admin | Precheck digest and version, PAN-OS locks and partial commit, refusal on foreign pending changes |
| A firewall key with write access is a high-value target | Optional (Q3); dedicated role without web UI, CLI, admin or certificate management; separate from the read key; can be removed while keeping phase 1 |

New "not protected" entries: a malicious admin approving a harmful rule;
a device that lies in its own output (NOS can detect only inconsistency, not
a compromised firewall); the vendor firmware itself.

### D8: Phase plan

- **Phase 1:** CBS and PAN-OS read only (D3, D4), drift and IPAM/traffic-map
  integration, firewall view with hit counts. Order (Q10, decided
  2026-11-09; previously open): CBS read path first, then PAN-OS read.
- **Phase 2a:** typed changes up to HIGH (D5, D6), CRITICAL refused; started
  only if the maintainer decides so after phase 1 has run (Q3, decided
  2026-11-09; previously open).
- **Phase 2b:** not planned (Q6, decided 2026-11-09: CRITICAL refused for
  good; previously: CRITICAL with the dead-man rollback, only after Q6).
- **Later:** pfSense CE (D9, Q7), Catalyst successors, Panorama,
  shadowed-rule analysis, segmentation hints.

### D9: pfSense stays later

- **pfSense CE** has no official REST or XML-RPC management API for third
  parties (*verify*; XML-RPC exists for HA config sync between pfSense
  nodes). The community package `pfSense-pkg-RESTAPI` adds one, but it is
  not from Netgate and installs PHP code on the firewall: a supply-chain and
  update risk NOS would inherit.
- **pfSense Plus** has, per Netgate, an official REST API in recent
  releases (*verify* name, release and authentication model).
- **Read path available on both:** `/cf/conf/config.xml` and the config
  history in `/cf/conf/backup/` over SSH (*verify* the paths and which
  privilege a non-root user needs; the SSH login of `admin`/`root` opens a
  console menu, *verify*). That would give config backup and diff, with
  pfSense-specific redaction (`bcrypt-hash`, `password`, `pre-shared-key`,
  `prv`, `crt`, OpenVPN static keys, *verify*).
- **Writes** on CE would need PHP execution (`pfSsh.php`) or the community
  API; both are effectively arbitrary code and are a non-goal until decided.

Q7 decided 2026-11-09 (previously open: CE or Plus, and whether a
read-only config backup over SSH is enough): **pfSense CE** ("Standard"),
later, as a possible replacement when the current firewall leaves vendor
support. NOS would take a **read-only config backup over SSH**; the
community REST API (`pfSense-pkg-RESTAPI`) is **not acceptable**, and
writes stay a non-goal. ND-50 stays future work and needs its own ADR
amendment first.

## Non-goals

- No generic CLI, no xpath or API proxy, no free-form config push, no config
  file upload or restore of a whole config.
- No unattended or scheduled changes, no automatic drift remediation.
- No firmware, content or license management.
- No device credentials outside the executor, ever; no browser SSO to
  devices; deep links to the vendor UI only (the browser logs in itself).
- No SNMP polling in this ADR (SNMPv3 credentials would be another class;
  separate decision).
- No CBS220 or other web-only models.
- No shadowed-rule or policy-optimization engine; hints only.

## Consequences

- The executor gains a CLI session driver and an XML API client, both
  parsing hostile input. They are new attack surface in the most trusted
  process, as in ADR 0006; parsers are small, typed, bounded and fuzzed.
- A new credential class and a new collector role appear in spec 06, 02 and
  03 and in the threat model.
- Device changes have a stricter flow than host actions: precheck digest,
  separate persist approval (CBS), locks and partial commit (PAN-OS).
- Some useful changes stay impossible (management, AAA, routing). That is
  intended.

## Required specification changes

- `docs/spec/02-architecture.md`, `03-processes-and-data.md`: devices,
  collector role, tables, retention.
- `docs/spec/06-credentials.md`: device credential class, custody, rotation.
- `docs/spec/07-execution-model.md`: device read profile, device change
  permits, persist step, dead-man exception (phase 2b).
- `docs/spec/08-ssh-transport.md`: CLI sessions to devices, algorithm policy.
- `docs/spec/09-untrusted-host-data.md`: device output and redaction rules.
- `docs/spec/12-inventory.md`: devices, ports, VLANs, MAC, LLDP, firewall view.
- `docs/spec/16-milestones.md`, `04-revision-history.md`,
  `17-frozen-decisions.md`; `docs/threat-model.md` (D7).

Tickets: [docs/implementation/network-devices.md](../implementation/network-devices.md).

## Decisions 2026-11-09

The maintainer answered every open question in chat on 2026-11-09,
00:07–01:10 UTC+1, and accepted this ADR. Each answer is also recorded at
the question below and in the section it changes. Lab facts that identify
the lab (exact models, firmware and PAN-OS releases, serial numbers,
addresses, host names) stay in the maintainer's private lab notes, not in
this repository. Every lab fact below is still checked in ND-03.

| Question | Decision 2026-11-09 | Was |
| --- | --- | --- |
| Q1 CBS models and firmware | The lab has Cisco **CBS350** switches (two reachable from the management side) and several small **CBS250** switches (not seen with an address in the lab scan; their management address is confirmed in ND-03). Exact models and firmware stay in the private lab notes. No CBS220 was named | open |
| Q1b SSH key types | Host-key and user-key types and `rsa-sha2-512` support are verified in ND-03; the default stays **no algorithm exception** (a switch that cannot meet spec 08 is unsupported, ND-05b only through a separate decision) | open |
| Q2 PAN-OS | A single **Palo Alto PA-400-series** firewall on **PAN-OS 11.1** (exact release private); no HA pair and no Panorama assumed, verified in ND-03. The vsys layout was not stated: NOS supports a single vsys only (D3), verified in ND-03 | open |
| Q3 Write-capable credentials | Recommendation accepted: phase 1 holds a **read-only key/user only** (CBS privilege level below 15, PAN-OS read-only role); phase 2 is decided after phase 1 has run | open |
| Q4 Management layout | The lab is currently **one flat network without a management VLAN**; the maintainer plans segmentation. Until a management VLAN exists, **every port, VLAN and uplink change on a switch that carries the path between the NOS machine and any managed device is CRITICAL** and therefore refused (Q6). D5 "Flat network" states how the path rule tightens | open |
| Q5 Firewall management address | Management is on an **internal address only** (the address is not in this repository); WAN-side management is not reachable, verified in ND-03 | open |
| Q6 CRITICAL changes | Recommendation accepted: CRITICAL changes are **refused for good**; phase 2b and ND-40 are not planned; no exception to ADR 0007's "no automatic rollback" | open |
| Q7 pfSense | **pfSense CE** ("Standard") later, as a possible replacement when the current firewall leaves vendor support; **read-only config backup over SSH**; the community REST API is **not acceptable**. ND-50 stays future work | open |
| Q8 Raw backups | **Redacted backups only**; no unredacted device configs in NOS, in any phase | open |
| Q9 Collector | **Separate `nebula-netdev-collector`** with a shared spool library | open |
| Q10 Order | **CBS read path first**, then PAN-OS read, then changes (the latter only after Q3's phase-2 decision) | open |
| Q11 Retention | **As proposed**: config versions 400 days / 1,000 versions per device (approved baseline and change-bound versions never pruned); MAC/LLDP history 21 days; hourly hit-count samples 90 days | open |
| Q12 Protected paths | **Yes**: `internal/netdevredact/` and `internal/netdevchange/` are added to `.github/protected-paths.txt` in ND-02 | open |
| Q13 CBS redaction model | Per the ADR recommendation: CBS switches to an **allowlist of command keywords** (unlisted lines dropped with a marker) once ND-03 has recorded the command vocabulary of the lab configs; until then the D4 limit stands | open |

Q13 was answered with "per the ADR recommendation, else the most
restrictive option". Every question in this ADR carried a recommendation or
was answered with a fact, so no fallback to the most restrictive option was
needed here.

## Open questions for the maintainer

All answered on 2026-11-09 (previously open); see "Decisions 2026-11-09".

- **Q1: CBS models and firmware.** Which exact models (CBS250, CBS350,
  CBS220?) and firmware versions are in the lab? **Q1b:** which SSH host-key
  and user-key types do they offer; is `rsa-sha2-512` available, or would
  NOS need an algorithm exception (recommended: no exception, unsupported)?
  **Answered 2026-11-09** (previously open): CBS350 (two reachable from the
  management side) and several CBS250 (management address confirmed in
  ND-03); exact models and firmware private. Q1b verified in ND-03; default
  no algorithm exception.
- **Q2: PAN-OS.** Model, PAN-OS version, single vsys, HA pair or not,
  Panorama or not. **Answered 2026-11-09** (previously open): one
  PA-400-series on PAN-OS 11.1 (exact release private), no HA, no Panorama
  assumed; verified in ND-03; single vsys only.
- **Q3: Write-capable firewall key.** May NOS hold a PAN-OS API key that can
  commit at all? Recommended: phase 1 read-only key only; decide phase 2
  after phase 1 runs. Same question for the CBS level-15 user.
  **Answered 2026-11-09** (previously open): recommendation accepted, phase 1
  read-only key/user only (CBS below level 15); phase 2 decided after phase 1
  runs.
- **Q4: Management layout.** Which VLAN and subnet is management, where do
  the NOS machine and its gateway sit, which switch ports are uplinks, and
  is the PAN-OS management port really out of band? This defines the
  CRITICAL path rule. **Answered 2026-11-09** (previously open): one flat
  network, no management VLAN yet, segmentation planned; until then every
  port/VLAN/uplink change on a switch carrying the NOS path is CRITICAL and
  refused (D5 "Flat network").
- **Q5: Firewall management address.** The internal address of the PAN-OS
  management interface; confirm management is not reachable on the WAN side
  of `<public-name>`. (Answer privately; the ADR records only that the
  address is internal.) **Answered 2026-11-09** (previously open): internal
  address only (not recorded here); WAN-side management not reachable,
  verified in ND-03.
- **Q6: CRITICAL changes.** Refuse them for good, or allow phase 2b with a
  CBS reload timer and a PAN-OS executor dead-man (an exception to ADR
  0007's "no automatic rollback")? **Answered 2026-11-09** (previously
  open): refused for good; ND-40 not planned.
- **Q7: pfSense.** CE or Plus? Is a read-only config backup over SSH enough,
  and is the community REST API acceptable at all (recommended: no)?
  **Answered 2026-11-09** (previously open): CE, later, as a possible
  replacement when the current firewall leaves vendor support; read-only
  config backup over SSH; community REST API not acceptable; ND-50 future.
- **Q8: Raw backups.** Should the executor keep age-encrypted unredacted
  config backups for disaster recovery, or only redacted versions
  (recommended: redacted only; devices keep their own config)?
  **Answered 2026-11-09** (previously open): redacted only.
- **Q9: Collector.** Separate `nebula-netdev-collector` (recommended) or a
  second role in the PVE collector? **Answered 2026-11-09** (previously
  open): separate collector.
- **Q10: Order.** Switch first or firewall first? Recommended: CBS read path
  first (feeds IPAM and the traffic map), then PAN-OS read, then changes.
  **Answered 2026-11-09** (previously open): as recommended.
- **Q11: Retention.** 400 days / 1,000 versions per device for config
  versions; 21 days for MAC/LLDP history (as ADR 0009); 90 days of hourly
  hit-count samples. Acceptable? **Answered 2026-11-09** (previously open):
  as proposed.
- **Q12: Protected paths.** Should the new redaction and device-change
  packages (`internal/netdevredact/`, `internal/netdevchange/`) be added to
  `.github/protected-paths.txt`? Recommended: yes, in ND-02.
  **Answered 2026-11-09** (previously open): yes, in ND-02.
- **Q13: CBS redaction model.** PAN-OS output passes an element allowlist;
  CBS output passes a keyword denylist plus the fail-closed keyword rule,
  which cannot catch a secret in a positional field of an unlisted command.
  Should CBS also switch to an allowlist of command keywords (unlisted lines
  dropped with a marker)? Recommended: yes, once ND-03 has recorded the
  command vocabulary of the lab configs; until then the limit stands as
  stated in D4. **Answered 2026-11-09** (previously open): per the
  recommendation.
