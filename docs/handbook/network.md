# Network

IP address management (IPAM), network discovery, the traffic map, and
registering network devices (Cisco CBS switches, Palo Alto PAN-OS
firewalls). Reference: admin guide
[9.7 to 9.9](../admin/guide.md#97-network-ipam) and
[ADR 0010](../adr/0010-network-devices.md) for network devices.

Nebula never manages DHCP or DNS, and it changes nothing on switches or
firewalls in this release.

## Add a network to IPAM

**Goal:** Nebula knows a subnet, its VLAN, gateway and address pools.

**Steps:**

1. *Network* (`/network`) → **Add network**.
2. Enter the prefix (for example `192.168.10.0/24`), VLAN, gateway and
   pools such as `servers 192.168.10.10-192.168.10.49`.
3. **Save network**.

**Expected result:** the network page (`/network/n/<id>`) shows every
address of networks up to /22 as a grid; larger networks and IPv6 list only
claimed addresses. Each address has a status: ASSIGNED (an asset or a
managed host's endpoint), RESERVED, EXCLUDED, DISCOVERED (seen by
discovery, claimed by nobody) or CONFLICT (two claimants or a different
MAC).

## Find a free IP address

**Goal:** pick an address for a new device.

**Steps:** open the network page (`/network/n/<id>`). It suggests free
addresses of the whole network or one pool that discovery has not seen in 30
days.

**Expected result:** a list of suggestions. Treat them as suggestions, not a
guarantee: a switched-off device is not seen.

## Record a device (asset) in IPAM

**Goal:** keep NAS, printers, switches and other devices in IPAM, managed by
Nebula or not.

**Steps:** *Network* → **Add asset**, enter name, kind, addresses and MAC,
**Save asset**. To turn an asset into a managed host, open it
(`/network/a/<id>`) → **Add to managed hosts**: the inventory form opens
with its values and the new host is linked to the asset. Then enroll it as
in [Hosts](hosts.md).

**Expected result:** the asset's addresses show as ASSIGNED.

## Scan a network with discovery

**Goal:** find devices on a network you added.

**Prerequisites:** the network exists in IPAM; `nmap` installed on the
Nebula machine (`sudo apt install nmap`).

**Steps:**

1. *Network → Discovery* (`/network/discovery`).
2. Choose targets inside a known network (at most a /16 for IPv4, /112 for
   IPv6) and a scan type: host discovery, selected ports, service discovery
   (top 100 ports with versions), all TCP ports, or a custom scan from fixed
   options. There are no free-form Nmap arguments.
3. **Queue scan** now, once, or every N hours (at least one). There is no
   default schedule.
4. Open the scan (`/network/discovery/<id>`) when it finished. Each host is
   NEW, EXISTING (same MAC as an asset), POSSIBLE MATCH (same address, no
   MAC to compare, typical across VPNs) or CONFLICT.
5. Select hosts and **Import selected**. New hosts become assets with kind
   unknown; set the kind afterwards.

**Expected result:** imported devices appear as assets; every host seen
also feeds the address status.

**Common errors:**

- "Discovery shows as not installed": `discovery_dir` is missing or wrong in
  `server.json`, or the spool directories are absent. Run `install.sh` again.
- `nmap is not installed (install the nmap package on the Nebula machine)`:
  `sudo apt install nmap`.
- Results never arrive: check `systemctl status nebula-discovery.path` and
  the spool modes (admin guide
  [15](../admin/guide.md#15-troubleshooting)).
- Conflicts are never imported. Names and banners come from the network and
  may lie.

## See who talks to whom on the traffic map

**Goal:** a graph of flows between managed hosts, assets and networks.

**Prerequisites:** a read lease that includes the built-in read action
`net.facts` (see
[Run read-only checks on a schedule](patching-and-services.md#run-read-only-checks-on-a-schedule-read-lease)).

**Steps:**

1. *Operations → Read leases → New read lease* (`/leases/new`), include
   `net.facts`, 7 or 30 days, approve.
2. Open *Traffic map* in the sidebar (`/traffic`). Choose the window (1 h,
   24 h, 7 d or 21 d).
3. Click a node for its top connections. The *Connections* tab of a host
   (`/hosts/<id>/connections`) or asset (`/network/a/<id>/connections`)
   lists the flows one by one.

**Expected result:** edges with byte counts appear after the first
`net.facts` runs.

**Notes:** byte counts from socket snapshots are lower bounds. Process names
are never collected (`net.facts` runs `ss` without `-p`, so no sudo rule is
needed). Flows to peers outside the inventory are counted as unmapped, not
drawn. Retention is 21 days by default (`"traffic": {"retention_days": N}`
in `server.json`, 1 to 21). Proxmox guest NICs come in through the PVE
collector; network sensors and DNS sources are planned (ADR 0009).

## What works for network devices today

| Capability | Status |
| --- | --- |
| Register a CBS switch or PAN-OS firewall, pin its SSH host key or TLS certificate, store the read credential in the vault | Available: `nebula netdev` |
| Rotate the credential, re-pin, block, unblock, remove, list | Available: `nebula netdev` |
| Device pages (`/netdev`, `/netdev/<id>`) | Available; they show stored device data only |
| Reading device data (version, VLANs, interfaces, MAC table, LLDP, PAN-OS rules) | **Planned** (ADR 0010, tickets ND-13/ND-14): the executor answers "device reads are not implemented yet (ND-14)" |
| SSH public-key login for CBS (`nos-read` with an executor-held key) | **Planned** (ADR 0010 D2, preferred method); today the CBS read credential is a password |
| Any change on a device (VLANs, ports, rules) | **Planned** for phase 2a only after phase 1 has run (ADR 0010 Q3); anything on NOS's own path stays refused |
| Cisco CBS220 | Not supported (no SSH CLI); keep it as an IPAM asset |

Register devices now if you like: the pins and credentials are kept and
used once reads land.

## Create the `nos-read` account on a Cisco CBS switch

**Goal:** a dedicated, least-privilege local account for Nebula on a CBS350
(or CBS250 with SSH CLI).

**Prerequisites:** admin access to the switch CLI; SSH server enabled on
the switch; the switch's management address is private and reachable from
the Nebula machine.

The commands below are **switch-side Cisco syntax**, not Nebula commands.
ADR 0010 marks several of these vendor details as *verify* (lab check
ND-03 is still open). Check them against the CLI guide of your firmware.

**Steps (password login, what Nebula stores today):**

1. Create a dedicated local user `nos-read` with the lowest privilege level
   that can still run `show running-config` (CBS knows levels 1, 7 and 15;
   phase 1 uses a level **below 15**). Use a long random password.
2. Make sure the switch uses the SSH password itself and does not ask
   again inside the session: enable SSH password authentication
   (`ip ssh password-auth`). See the auto-login pitfalls below.
3. Note the SSH host key fingerprint from the switch console
   (`show crypto key mypubkey rsa`, or the equivalent for your firmware) to
   compare when you register the switch.

**SSH public-key login (planned, preferred by ADR 0010 D2):** the user's key
is entered under `crypto key pubkey-chain ssh`, one **`key-string row`** per
line of the base64 key body:

```
configure terminal
ip ssh pubkey-auth auto-login
crypto key pubkey-chain ssh
 user-key nos-read rsa
  key-string row AAAAB3NzaC1yc2EAAAADAQABAAABgQC...
  key-string row ...rest of the base64 body...
  key-string row
 exit
exit
```

Paste only the base64 body (no `ssh-rsa` prefix, no comment), split into
rows the switch accepts, and finish with an empty `key-string row`. Nebula
has no command yet that prints a device key; this block is here so you know
what the switch side will look like.

**Expected result:** an SSH login as `nos-read` from the Nebula machine's
address lands directly at the switch prompt (`switch01>` or `switch01#`),
with no second `User Name:` prompt.

## Avoid CBS auto-login and prompt pitfalls

**Goal:** the switch session looks exactly like Nebula's session driver
expects, so reads do not abort.

Nebula's CBS driver opens one interactive SSH session, waits for a
recognised prompt, sends one allowlisted command and reads to the next
prompt. It **never answers** a question. Any of the following makes it abort
the session as a failure:

- **A second login inside the session.** Many CBS configurations accept the
  SSH login and then print their own `User Name:` / `Password:` prompt. The
  driver treats `user name`, `username`, `password` and `login` prompts as
  unexpected and stops. Fix: `ip ssh password-auth` for password logins, or
  `ip ssh pubkey-auth auto-login` for key logins, so the SSH authentication
  is the only login.
- **`auto-login` without a matching key.** With public-key login,
  `auto-login` only skips the in-band prompt when the key in
  `key-string row` matches. A wrong or truncated row makes the switch fall
  back to the `User Name:` prompt, and the driver aborts.
- **An unusual host name.** The prompt must be a host name of up to 58
  letters, digits, `.`, `_` or `-`, starting with a letter or digit, followed
  by `>` or `#`. Spaces or other characters in the host name make the prompt
  unrecognisable. Configuration-mode prompts (`switch01(config)#`) are never
  accepted.
- **Interactive banners.** A login banner or MOTD whose text contains
  `Press any key`, `(y/n)` or `[confirm]`, or whose last line ends in `:`
  or `?`, looks like a prompt waiting for input. Keep banners plain text. A changed
  banner is also treated as a failure.
- **Paging.** The driver disables paging with `terminal datadump`; a
  `--More--` prompt aborts the read.
- **Key types.** Nebula accepts RSA only as `rsa-sha2-512` with a minimum
  key size (spec 08). A switch that offers only `ssh-rsa` (SHA-1) or a small
  RSA key is **unsupported**; there is no algorithm exception (ADR 0010 Q1b).
- **Regenerated host key.** After `crypto key generate rsa` on the switch
  the pin no longer matches and Nebula blocks the device. Compare the new
  fingerprint on the console, then `nebula netdev repin <device-id>`.

## Create the `nos-read` administrator on a PAN-OS firewall

**Goal:** an API key for a read-only administrator, with no web UI and no
CLI.

**Prerequisites:** admin access to the firewall web UI; the management
interface reachable on an internal address only.

The steps below are **firewall-side**. ADR 0010 marks the exact role
options as *verify*; check them against the PAN-OS Administrator's Guide of
your release.

**Steps:**

1. *Device → Admin Roles → Add*: a custom Admin Role profile, for example
   `nos-read-role`. Disable the **Web UI** and the **Command Line**. Under
   **XML API**, allow only the read operations Nebula needs (configuration
   read, operational requests); disable commit, import and export. If your
   release cannot make XML API configuration access read-only, use the
   dynamic role *Superuser (read-only)* with web UI and CLI disabled
   through an authentication profile instead.
2. *Device → Administrators → Add*: user `nos-read` with that role profile
   and a long random password.
3. Commit.
4. From **your own workstation** (not the Nebula machine), generate the API
   key once with the XML API `type=keygen` request, sending the password in
   the POST body, never in the URL. For example:

   ```
   curl --cacert fw-mgmt-ca.pem -X POST 'https://<firewall-mgmt-ip>/api/' \
     -d type=keygen -d user=nos-read --data-urlencode password@-
   ```

   Type the password, press Ctrl-D, and copy the key from the `<key>`
   element of the answer.
5. Optional: set an API key lifetime on the firewall; Nebula's own expiry
   applies in addition.

**Expected result:** an API key for `nos-read`. Nebula never stores the
account password, only the key.

## Register a network device with Nebula

**Goal:** the executor knows the device, pinned to its SSH host key (CBS)
or TLS certificate (PAN-OS), with the read credential in its vault.

**Prerequisites:** the `nos-read` account (sections above); executor
unlocked (`nebula unlock`); an admin login on the Nebula machine with a
terminal.

**Steps:**

1. Look at the fingerprint first (no credential is sent):

   ```
   nebula netdev probe --family cbs --endpoint 192.168.1.2
   nebula netdev probe --family panos --endpoint 192.168.1.1
   ```

   `--port N` overrides the default (22 for `cbs`, 443 for `panos`).
2. Register it:

   ```
   nebula netdev add sw-core --family cbs --endpoint 192.168.1.2 \
     --label "Core switch" --username nos-read
   ```

   Compare the shown fingerprint with the device console, type `yes`, then
   enter the read credential at the prompt (CBS: the password; PAN-OS: the
   API key). It is never accepted as an argument or from the environment.
   `--no-credential` registers only; set it later with
   `nebula netdev credential set sw-core`.
3. Check: `nebula netdev list` (metadata only, never secrets), and the
   device page `/netdev/sw-core`.

**Expected result:** the device is listed with its pin.

**Common errors:**

- The endpoint is refused: it must be a private address (or a name that
  resolves to one at registration). Public, loopback, link-local,
  multicast and unspecified addresses are refused at registration and at
  every dial.
- `stdin is not a terminal`: the `yes` must be typed on a terminal; a piped
  `yes` is refused. For scripted credential entry use `--secret-fd N`
  (descriptor 3 or higher), for example
  `nebula netdev credential rotate sw-core --secret-fd 3 3< keyfile`.
- The vault is locked: `nebula unlock` first.

## Rotate, block or remove a network device

**Steps:**

```
nebula netdev credential rotate fw-01          # asks for the new password or API key
nebula netdev block fw-01 --reason "maintenance"
nebula netdev unblock fw-01
nebula netdev repin fw-01                      # after a host key or certificate change
nebula netdev remove fw-01
```

`unblock`, `repin` and `remove` ask for a typed `yes` on a terminal.

**Expected result:** `nebula netdev list` shows the new state. After a
PAN-OS key rotation, delete the old API key on the firewall (or let its
lifetime expire).
