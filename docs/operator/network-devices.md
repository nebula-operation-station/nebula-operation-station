# Network devices operator guide

This guide covers network device management as decided in ADR 0010
(`docs/adr/0010-network-devices.md`): Cisco Business switches (family `cbs`)
over an SSH CLI and Palo Alto Networks firewalls (family `panos`) over the
PAN-OS XML API. It describes how to create the read-only `nos-read` account
on each device, how to register a device and manage its credential with the
`nebula netdev` CLI, what NOS will collect and what it never collects, and
the device quirks known from the lab.

Features that are designed but **not merged yet** are marked **planned**.
Code that is merged but that no release build can reach is marked **not
available**. [What you can use today](#what-you-can-use-today) lists both.

Every address, name and value in the examples is a placeholder
(`<switch-ip>`, `<device-id>`, ...). Use your own.

## What the integration does

NOS treats a network device as an appliance, not as a managed host. A
device never gets an SSH action, a sudo rule or a host-key entry in the host
registry. ADR 0010 phase 1 is **read only**; NOS changes nothing on a switch
or firewall, and no change credential exists (ADR 0010 Q3).

- A **device** has an immutable `device_id`, a family (`cbs` or `panos`),
  one management endpoint and one **trust pin**: the SSH host key for
  `cbs`, the TLS certificate for `panos`.
- The **executor** is the only component that talks to a device. It owns
  the registry, the pins, the trust generation and the read credential.
  The credential and two per-device keys (a digest key and a fingerprint
  key, generated at registration) are envelope-encrypted in the executor
  vault and decrypted only there.
- **`nebula-netdev-collector`** runs as its own Unix user, holds no
  credentials, opens no network listener and touches no database. It
  schedules typed reads over the executor socket and writes the sanitized
  results to its spool.
- **`nebula-server`** imports the spool and renders the device pages.

Everything a device returns is untrusted input: output is size-, line- and
count-bounded, must be valid UTF-8, and is rendered as text only.

## What you can use today

| Capability | Status | Where |
| --- | --- | --- |
| Probe, register, re-pin, block, unblock, remove, list | Available | `nebula netdev` on the executor host |
| Store and rotate the read credential | Available | `nebula netdev credential set`, `nebula netdev credential rotate` |
| Device read leases (enforcement in the executor) | Available in the executor; no page or CLI command proposes one yet | none |
| Device reads (CBS CLI, PAN-OS XML API) | **Not available:** the executor authorizes the read and records its spend, then answers `device reads are not implemented yet (ND-14)` | none |
| Collector | **Not available:** the binary, the `nebula-netdev-collector` user and its spool are installed, but the unit stays disabled | `nebula-netdev-collector.service` |
| Configuration redaction and config versions (`<redacted:…>` values, keyed digests) | **Planned** (ND-07) | none |
| Device pages, firewall view, asset links | **Not available:** the page code exists, `nebula-server` does not serve it yet | none |
| Changes of any kind | **Not planned** before the phase-2 decision (ADR 0010 Q3) | none |

Until device reads land, you can prepare everything on the device and in
the executor: the `nos-read` account, the registration with its pin, and
the stored read credential.

## Creating `nos-read` on a Cisco Business switch

Supported are CBS models with an SSH CLI (CBS350, and CBS250 with a firmware
that offers SSH). A CBS220 has no SSH CLI and is **unsupported** (ADR 0010
D3). The exact CLI syntax varies between firmware trains: check each command
against the CLI guide of your firmware before you rely on it.

### What NOS expects from the switch

- **Public-key login only.** The executor's CBS session driver
  (`internal/cbscli`) authenticates with an SSH key. It never answers a
  prompt inside the session: an in-band `User Name:`/`Password:` prompt, a
  pager (`--More--`), a `(Y/N)` question or a changed prompt aborts the
  session. The switch must therefore log the key user straight into the
  EXEC prompt (`ip ssh pubkey-auth auto-login`).
- **Privilege level 1.** The read account must stay below level 15 (ADR
  0010 Q3). Use level 1. Level 1 refuses some `show` commands; see
  [Known quirks](#known-quirks). Never use level 15 for `nos-read`.
- **The host key** must meet spec 08: Ed25519, ECDSA (P-256/384/521) or RSA
  of at least 2048 bits, used with `rsa-sha2-512`. A switch that offers only
  `ssh-rsa` (SHA-1) signatures or a shorter RSA key cannot be pinned and is
  **unsupported**; NOS adds no algorithm exception for devices (ADR 0010
  Q1b).
- **Paging off per session.** The driver sends `terminal datadump` after
  login and requires empty output. The account must be allowed to run it.

### Order of steps for a switch

1. Generate the key pair on the executor host ([Generating the CBS
   key](#generating-the-cbs-key)). Keep the private key file for now.
2. Install the public key on the switch ([Switch
   configuration](#switch-configuration)).
3. Check the login by hand with `ssh -i <key-file>` ([Checking the
   login](#checking-the-login)).
4. Register the device and store the private key through `--secret-fd`
   ([Registering a device](#registering-a-device-with-the-nebula-cli) and
   [Storing the read credential](#storing-the-read-credential)).
5. Delete the private key file ([Deleting the key
   file](#deleting-the-key-file)).

The executor stores a credential only for a registered device, and the
manual login check needs the private key file, so do not change this order.

### Generating the CBS key

No `nebula` command generates device keys. Create the key on the executor
host as the admin, in a private directory, and keep the shell open (or note
the directory) until step 5. `mktemp -d` creates the directory with mode
0700; `umask 077` runs in a subshell so it does not change the mode of
files you create later in the same shell:

```sh
d=$(mktemp -d)
(umask 077 && ssh-keygen -t rsa -b 3072 -N '' -C 'nos-read <device-id>' -f "$d/nos-read")
cat "$d/nos-read.pub"
```

- Use one key per switch. A key shared between switches cannot be revoked
  for one of them.
- Store it without a passphrase: the executor reads unattended and has no
  way to ask for one; the vault envelope protects it at rest.
- RSA keys must be at least 2048 bits (3072 recommended). See the key-type
  note in [Switch configuration](#switch-configuration).
- The public half (`"$d/nos-read.pub"`) is not secret; its second field is
  the Base64 body you enter on the switch next.

### Switch configuration

On the switch console or an existing admin session:

```text
configure terminal
! SSH server on, users may authenticate with a public key and are logged
! in without a second username/password prompt.
ip ssh server
ip ssh pubkey-auth auto-login
! The read account at privilege level 1. CBS requires a password for a
! local user: set a long random one and do not hand it to NOS (NOS logs
! in with the key only). Store it like any other device password.
username nos-read privilege 1 password <long-random-password>
! Bind the public key to the user. key-string row takes the Base64 body
! of the public key (the second field of the .pub line); several rows are
! concatenated.
crypto key pubkey-chain ssh
user-key nos-read rsa
key-string row <base64-part-1>
key-string row <base64-part-2>
exit
exit
end
write memory
```

The `user-key` type must match the key you generated. CBS user keys are
RSA on the firmware this guide was written against; whether a firmware also
accepts ECDSA or Ed25519 user keys is open (ADR 0010 Q1b). Do not use DSA.

### Checking the login

Check the account by hand from the executor host before you register it:
log in with the new key (for example with
`ssh -i "$d/nos-read" nos-read@<switch-ip>` from the same admin shell; NOS
itself never calls the `ssh` binary), confirm you
land at a `>` prompt without a second login prompt, run `terminal datadump`
and each `show` command NOS uses (listed in [What NOS collects](#what-nos-collects)),
then type `exit`. End the session with `exit`, never by killing the client
(see [Known quirks](#known-quirks)). Then register the device (next
sections) while the key file still exists.

## Creating `nos-read` on PAN-OS

NOS reads the firewall through the XML API only, over the internal
management interface, with an API key of a dedicated administrator. NOS
never stores the account password.

### Admin Role profile

In the web UI, **Device > Admin Roles > Add**, role scope **Device**:

| Tab | Setting |
| --- | --- |
| Web UI | Everything disabled |
| XML API | **Configuration** and **Operational Requests** enabled; everything else (Report, Log, Commit, User-ID Agent, Import, Export, IoT Agent and others your release lists) disabled |
| REST API | Everything disabled |
| Command Line | **None** |

The executor sends only these requests, built from fixed templates (no
caller can supply an xpath, a command or a URL):

- `type=op`: system info, the list of pending candidate changes, the config
  audit info and the security rule hit counts;
- `type=config` with `action=show` or `action=get` on fixed xpaths: in
  `vsys1` the security and NAT rules, address and service objects and
  groups, and zones; the `vsys` list of the device (all vsys entries; the
  parser refuses a response with more than one); `shared`; and the device-level
  `network/interface`.

It never commits, imports, exports or writes. ADR 0010 D2 leaves open
whether a custom role with XML API **Configuration** can read without being
able to write on your PAN-OS release. Check it once with the new key from
your workstation: a `type=config&action=show` request must succeed and a
`type=config&action=set` request must be refused. If the custom role cannot
read the configuration, the ADR's fallback is the dynamic role **Superuser
(read-only)** with web UI and CLI access removed through the authentication
profile; record which one you used.

NOS supports a single `vsys1`, no HA pair and no Panorama (ADR 0010 Q2). It
refuses a device that shows more than one vsys.

### Administrator and API key

1. **Device > Administrators > Add**: name `nos-read`, the role profile
   above, a long random password. Commit.
2. Optionally set **API Key Lifetime** under **Device > Setup > Management >
   Authentication Settings**. It applies to all administrators and comes in
   addition to NOS's own lease expiry. A key that expires on the firewall
   must be rotated in NOS (see [Rotating the read
   credential](#rotating-the-read-credential)).
3. Generate the key **out of band**, once, from your own workstation on the
   management network (ADR 0010 D2). Keep the password out of argv and the
   shell history, and verify the management certificate instead of using
   `-k` (for a self-signed certificate export it once and pass it with
   `--cacert`; compare it with the fingerprint `nebula netdev probe` shows).
   Run the snippet in **bash**: `read -s` and the `<(...)` process
   substitution do not exist in a POSIX `sh` or `dash`.

   ```bash
   read -rs -p 'nos-read password: ' PANPW; echo
   curl -s --cacert <mgmt-cert.pem> -X POST "https://<firewall-mgmt-ip>/api/" \
     --data-urlencode type=keygen --data-urlencode user=nos-read \
     --data-urlencode "password@<(printf %s "$PANPW")"
   unset PANPW
   ```

   curl also checks the URL's host against the certificate's subject
   alternative names. A self-signed management certificate often lists
   only a name, not the IP address, and curl then refuses it. In that case
   address the firewall by a DNS name the certificate lists (the probe
   shows them as `tls dns`) and map that name to the management IP with
   `--resolve`, so no DNS lookup is involved:

   ```bash
   read -rs -p 'nos-read password: ' PANPW; echo
   curl -s --cacert <mgmt-cert.pem> --resolve <cert-name>:443:<firewall-mgmt-ip> \
     -X POST "https://<cert-name>/api/" \
     --data-urlencode type=keygen --data-urlencode user=nos-read \
     --data-urlencode "password@<(printf %s "$PANPW")"
   unset PANPW
   ```

   The reply holds the key in `<key>…</key>`. Paste it at the NOS prompt
   (next section) and clear the terminal scrollback. Do not store it in a
   file, a ticket or a chat.

The executor sends the key only in the `X-PAN-KEY` request header and POSTs
every request body, so it never appears in a URL or a URL log.

## Registering a device with the nebula CLI

Run these commands on the **executor host** as the configured local admin
UID, through the peer-credential-authenticated executor socket.

- Socket: `NEBULA_EXECUTOR_SOCKET` (default `/run/nebula/executor.sock`),
  served by the user in `NEBULA_EXECUTOR_USER` (default `nebula-executor`).
- `add`, `credential set`, `credential rotate` and `remove` need the
  executor vault **unlocked**: `nebula unlock` first.
- `add`, `repin`, `unblock` and `remove` read the typed `yes` from a
  terminal on stdin only. A piped `yes` is refused.

```text
nebula netdev probe --family cbs|panos --endpoint <ip-or-name> [--port N]
nebula netdev add <device-id> --family cbs|panos --endpoint <ip-or-name> [--port N]
                  [--label TEXT] [--username NAME] [--no-credential] [--secret-fd N]
nebula netdev credential set <device-id> [--username NAME] [--secret-fd N]
nebula netdev credential rotate <device-id> [--username NAME] [--secret-fd N]
nebula netdev repin <device-id>
nebula netdev block <device-id> --reason TEXT
nebula netdev unblock <device-id>
nebula netdev remove <device-id>
nebula netdev list
```

| Flag | Meaning |
| --- | --- |
| `<device-id>` | Immutable device ID (first bare argument). |
| `--family` | `cbs` (SSH host key pin) or `panos` (TLS certificate pin). Required for `probe` and `add`. |
| `--endpoint` | Private IP literal or host name of the management interface. Required. |
| `--port` | Default 22 for `cbs`, 443 for `panos`. |
| `--label` | Display name only; names never authenticate a device. At most 255 bytes of printable UTF-8. **Required** for an IP literal `--endpoint`. For a host name `--endpoint` the label is always the normalized host name (lower case, no trailing dot): omit `--label` or pass exactly that name; any other label is refused with `invalid network device request`. |
| `--username` | Device account name, for example `nos-read`. Not a secret. |
| `--no-credential` | Register only; store the credential later with `credential set`. |
| `--secret-fd N` | Read the credential once from open descriptor N (3 or higher). Required in practice for a `cbs` key (see [Storing the read credential](#storing-the-read-credential)). |
| `--reason` | Required for `block`: a short admin note of 1 to 512 bytes of printable UTF-8, no secrets. The executor refuses an empty reason. |

### Endpoint rules

The executor stores and dials endpoints as **IP literals**. During `add`
the executor resolves a host name twice: once for the probe (which shows
`(resolved from <name>)`) and once more for the registration. The
registration probes the address it resolved again and stores it only if
the device there presents the fingerprint you confirmed; if the name now
points elsewhere, `add` fails with `network device trust identity does not
match` and registers nothing. The name must resolve to **exactly one**
address: a name with several A/AAAA records, or none, is refused with
`network device name did not resolve to exactly one address`. After
registration only the IP literal is stored and the name is never resolved
again, so a later DNS change cannot redirect a credentialed connection.
The host name becomes the device's label. Only private addresses
are accepted; public, loopback, link-local, multicast and unspecified
addresses are refused at registration and again at every dial. Use the
internal management address, never a public name or a WAN address.

### Pinning

`probe` and `add` connect **without any credential** and print what the
device presented:

```text
probe (no credential sent; compare the fingerprint out of band):
  family       cbs
  endpoint     <switch-ip>:22
  pin kind     <pin kind>
  fingerprint  sha256:<64 hex chars>
  ssh version  <server version string>
  host key     <key type>
```

For `panos` the probe shows `tls subject`, `tls dns`, `tls expires` and,
if the device sends one, `tls ca` instead of the SSH lines. All facts are
untrusted device output, shown as escaped text.

Compare the fingerprint **out of band**: on the switch console
(`show crypto key mypubkey` or the equivalent of your firmware) or in the
firewall's certificate view, never through the same network path. `add`
then asks `Type 'yes' to register <device-id> with this fingerprint:`;
anything other than `yes` registers nothing. On success:

```text
device <device-id> registered: cbs <switch-ip>:22, pin generation 1
```

The executor refuses a second device with the same trust identity.

### Storing the read credential

Unless you passed `--no-credential`, `add` asks for the read credential
right after the `yes`, before it registers anything:

- `cbs`: the OpenSSH private key of `nos-read`, **always through
  `--secret-fd`** (see below);
- `panos`: the API key, at the prompt or through `--secret-fd`.

The credential is asked **without echo** on the terminal, or read once from
`--secret-fd N`. It is never accepted as an argument or from the
environment. The terminal prompt reads **one line** only, which fits a
PAN-OS API key but not a multi-line OpenSSH private key: a pasted key would
store only its first line, and the remaining lines would reach your shell
(and possibly its history). For `cbs`, always pass the key file with
`--secret-fd`:

```sh
nebula netdev add <device-id> --family cbs --endpoint <switch-ip> --label <label> \
  --username nos-read --secret-fd 3 3< "$d/nos-read"
```

With a host name endpoint, leave out `--label` (the label is the name):

```sh
nebula netdev add <device-id> --family cbs --endpoint <switch-name> \
  --username nos-read --secret-fd 3 3< "$d/nos-read"
```

If you registered with `--no-credential`, store the key later with
`nebula netdev credential set <device-id> --username nos-read --secret-fd 3 3< "$d/nos-read"`. `--secret-fd` accepts only a regular file or a pipe that you
redirected (`3< file`); a socket, a closed descriptor or an internal one is
refused before the executor is contacted, and the descriptor is closed
after reading. One trailing newline is removed; the credential must be 1 to
16 KiB, the user name at most 64 bytes of printable UTF-8.

```text
device <device-id>: read credential stored, version 1
```

The executor stores the credential envelope-encrypted under a device-scoped
vault reference. Today it does **not** test the credential against the
device when it stores it: device reads are not merged, so a wrong key or
API key only shows once reads run. Test the account by hand as described
above. `credential set` stores the first credential only; it never
overwrites an existing one (use `rotate`).

### Deleting the key file

Once the CLI reports `read credential stored`, delete the private key file
on the executor host:

```sh
shred -u "$d/nos-read"; rm -f "$d/nos-read.pub"; rmdir "$d"
```

The public half is not secret; if you want to compare it with the switch
later, copy `"$d/nos-read.pub"` elsewhere before you run these commands. The private half then exists only in the executor
vault.

## Rotating the read credential

```sh
nebula netdev credential rotate <device-id> [--username NAME] [--secret-fd N]
```

The CLI looks up the current credential version, asks for the new
credential and replaces it at exactly that version; a concurrent rotation
fails instead of overwriting. Output:

```text
device <device-id>: read credential rotated from version 1 to 2
```

Rotation **revokes every grant of the device**: every read lease bound to
the old credential version stops covering it, and a new lease is needed.
If the revocation fails, the device is blocked (fail closed) and the error
says so; `nebula netdev block <device-id> --reason '<note>'` retries the
revocation (on a device that is already blocked it keeps the existing block
and its reason and only retries the revocation).

Order of steps:

- **CBS**: generate the new key pair as in [Generating the CBS
  key](#generating-the-cbs-key), replace the `user-key nos-read` entry on
  the switch, test the login by hand with `ssh -i "$d/nos-read"`, then run
  `credential rotate` at once, always with the key file on a descriptor
  (the terminal prompt reads one line only):

  ```sh
  nebula netdev credential rotate <device-id> --username nos-read --secret-fd 3 3< "$d/nos-read"
  ```

  Then delete the key file as in [Deleting the key
  file](#deleting-the-key-file). Between the switch change and the rotation
  a read with the old key fails authentication.
- **PAN-OS**: generate a new key with `type=keygen` as above, run
  `credential rotate`, then retire the old key on the firewall (see
  [Revoking access](#revoking-access)).

## Re-pinning the trust identity

A switch reset that regenerates its SSH host key, or a firewall
certificate renewal with a new key, presents a new fingerprint. NOS never
follows it on its own:

```sh
nebula netdev repin <device-id>
```

The CLI probes the **stored** endpoint without credentials, prints the
probe and the stored pin with its generation, and stops with `the device
presents the stored pin; nothing to re-pin` if nothing changed. Otherwise
it asks for `yes`, proposes a **HIGH-risk permit** bound to the device and
the old and new pins, shows the permit as the executor sees it and asks for
your approval. After the commit:

```text
device <device-id> re-pinned to generation 2 (new pin <prefix>)
```

The trust generation is incremented and every grant of the device is
revoked. A block stays in place; lift it separately with `unblock`.
Compare the new fingerprint out of band exactly as for `add`.

## Revoking access

On the NOS side:

| Command | Effect |
| --- | --- |
| `nebula netdev block <device-id> --reason TEXT` | Blocks every dial to the device and revokes its grants at once. Credential and pin stay. No `yes` needed. `--reason` is required: a short admin note of 1 to 512 bytes of printable UTF-8, no secrets. On a device that is already blocked it keeps the block and its reason and retries the revocation. |
| `nebula netdev unblock <device-id>` | Allows dials again after a typed `yes`. Revoked leases stay revoked. |
| `nebula netdev remove <device-id>` | After a typed `yes`, in this order: blocks the device, revokes its grants, deletes its vault entries (read credential, digest key, fingerprint key) and tombstones the ID. A failed step leaves the device blocked; running `remove` again resumes. |

`remove` deletes the credential in NOS but does not touch the device.
There is no NOS command that deletes only the credential; to stop NOS
using it, `block` the device, and to replace it, `rotate`.

On the device, retire the account or key yourself:

- **CBS**: in `crypto key pubkey-chain ssh`, `no user-key nos-read`; to
  remove the account, `no username nos-read`; then `write memory`.
- **PAN-OS**: delete or disable the `nos-read` administrator and commit.
  **Expire All API Keys** under **Device > Setup > Management >
  Authentication Settings** invalidates the keys of every administrator,
  not only `nos-read`. A configured API key lifetime also ends the key on
  its own.

Revoke on the device after every `remove`, after a rotation (the old
PAN-OS key) and whenever the executor host or its vault may be compromised.

## Listing devices

```sh
nebula netdev list
```

Metadata only: ID, family, label, endpoint, pin kind with pin prefix and
generation, state (`active` or `blocked` with its reason) and credential
(`none`, `missing`, or `v<N>`), plus the update time. It never prints a
secret.

## What NOS collects

**Planned:** device reads land with ND-14 and the redaction with ND-07; the
lists below are what ADR 0010 D3/D4 and the merged read allowlists fix.
Every read needs an approved **device read lease** bound to the exact
device, trust pin and generation, credential version and typed read (7-day
default, 30-day maximum). A re-pin, a rotation, a block or a removal ends
the lease's coverage.

**CBS**, one session per device, at most two commands per second, each
command from this fixed allowlist (`internal/cbscli`):

| Command | Cap |
| --- | --- |
| `show version`, `show system` | 1 MiB |
| `show running-config`, `show startup-config` | 4 MiB, 100,000 lines |
| `show vlan`, `show interfaces status`, `show interfaces description` | 1 MiB |
| `show interfaces switchport <if>` | 1 MiB |
| `show mac address-table` | 1 MiB |
| `show lldp neighbors`, `show lldp neighbors <if>` | 1 MiB |
| `show ip interface` | 1 MiB |

Every line is at most 4 KiB; connect and first prompt 10 s each, one
command 60 s.

**PAN-OS**, one request in flight per device, the requests listed in
[Admin Role profile](#admin-role-profile): system info, pending changes,
config audit info, rule hit counts, the rule, object and zone subtrees of
`vsys1`, the device's `vsys` list (all entries), `shared`, and the
interfaces from the device-level `network/interface` xpath.

| Observation | Content |
| --- | --- |
| Device facts | model, serial, firmware/PAN-OS version, uptime, management addresses |
| Configuration | redacted running config and its keyed digests; CBS also the startup config and whether it differs |
| Ports and VLANs (CBS) | port, admin/oper state, speed, access/trunk mode, VLANs, description; VLAN list |
| MAC table (CBS) | VLAN, MAC, port, type; at most 8,192 entries |
| LLDP neighbors (CBS) | local port, chassis ID, port ID, system name, management address, capabilities |
| Firewall policy (PAN-OS) | security rules in order, NAT rules, address/service objects and groups, zones, interfaces |
| Hit counts (PAN-OS) | hit count, first and last hit, counter reset time per rule |

Device facts include the serial number and exact firmware version. They
stay inside NOS (admin pages, age-encrypted instance backup); do not copy
them into public tickets or documents.

## Redaction boundaries

**Planned** (ND-07, ADR 0010 D4), except where marked merged.

What never leaves the executor:

- the raw device configuration, and any unkeyed digest of it;
- the read credential, the digest key and the fingerprint key;
- for PAN-OS, every element outside the reviewed allowlist, for example
  `mgt-config` (administrators and password hashes), `shared/certificate`,
  `ssl-tls-service-profile`, `authentication-profile`, `server-profile`,
  `network/ike`, `network/tunnel`, `global-protect` and `deviceconfig`,
  and every element a newer PAN-OS release adds. Attributes other than
  `name` and `uuid` are dropped.

NOS does **not** keep unredacted configuration backups, in any phase (ADR
0010 Q8). The devices keep their own configuration.

What leaves it, and how it is marked:

| Marker | Meaning |
| --- | --- |
| `<redacted:FP>` | A secret value replaced; the keyword stays. FP is the first 8 hex characters of an HMAC-SHA-256 under the device's fingerprint key over the full line identity and the value. A changed secret shows up as a changed line, but the server cannot test guesses or compare values across devices or lines. |
| `redacted:unknown` | Fail-closed rule: a line or element whose keyword is not on the reviewed list but whose name or content matches `key`, `pass`, `secret`, `community`, `hash`, `psk`, `private`, `token` or `cert` was redacted anyway and flagged for review. |
| `<dropped:ELEMENT-NAME count=N>` | PAN-OS: N elements outside the allowlist were removed with their subtrees. |
| "configuration changed in elements not displayed" | The keyed `raw_digest` changed while the redacted text did not, so the change is outside what NOS shows. (Merged in the page and store code.) |

CBS lines with these keywords keep the keyword and lose the secret token:
`username … password`, `enable password`, `enable secret`,
`snmp-server community`, `snmp-server user`, the community fields of
`snmp-server host`, `radius-server key`, `radius-server host … key`,
`tacacs-server key`, `tacacs-server host … key`, `encrypted`, `key-string`,
`password`, `secret`, `passphrase` and `wpa`. Blocks between `crypto key
import` or `crypto certificate … import` and their end marker are dropped
whole.

**Stated limit for CBS.** Until the CBS command vocabulary of the lab is
recorded and CBS moves to a keyword allowlist (ADR 0010 Q13), CBS redaction
is a keyword denylist plus the fail-closed rule: a secret in a positional
field of a command that is neither listed nor matches the pattern would
pass. Review new switch features before you enable them on a device NOS
reads.

**Merged today** in the PAN-OS parser (`internal/panapi`): only the
allowlisted elements are decoded at all, every other element is skipped
with its subtree, only `name` and `uuid` attributes are read, and a
repeated single-valued element is refused. An unparseable response, or
one over the byte, nesting-depth or element-count limit, is refused; a list
over its count limit is marked incomplete, never silently truncated.

## Known quirks

- **CBS privilege level 1 refuses some `show` commands.** Which ones depends
  on the firmware. Log in as `nos-read` by hand and run every command in
  [What NOS collects](#what-nos-collects). A command the level refuses
  produces no usable output, so that dataset stays unavailable. Do not
  raise `nos-read` to level 15 to fix it; ADR 0010 Q3 keeps the read
  account below 15.
- **Never query a CBS switch in parallel.** The switch's SSH server handles
  concurrent sessions badly. NOS opens one session per device at a time
  (a second one is refused with `a session to this device is already
  open`) and sends at most two commands per second. Do not run your own
  scripts or monitoring logins against the switch while NOS reads it.
- **Never abort a CBS SSH session hard.** Killing the client or dropping
  the TCP connection mid-session can leave the switch's SSH server hanging
  for about 10 minutes, during which no new SSH login (also not yours)
  succeeds. End manual sessions with `exit`. If it happens, wait it out or
  use the console; restarting NOS does not help.
- **CBS without a default gateway cannot reach NTP.** A switch whose
  management interface has no default gateway (`ip default-gateway`)
  cannot reach an NTP server outside its own subnet, so its clock drifts
  and timestamps in `show` output (uptime, LLDP and log times) are wrong.
  Set the gateway and check `show sntp status` (or the equivalent of your
  firmware).
- **CBS in-band login prompt.** Without `ip ssh pubkey-auth auto-login`
  the switch asks for a user name inside the session after the key login;
  the session driver treats that as an unexpected prompt and aborts.
- **PAN-OS with more than one vsys** is refused (single `vsys1` only).

## Troubleshooting

| Symptom | Likely cause / action |
| --- | --- |
| `--family must be cbs or panos` / `--endpoint is required` | Fix the flags; `probe` and `add` need both. |
| `network device name did not resolve to exactly one address` | The host name has no address, or more than one (several A/AAAA records, round-robin DNS), as seen from the executor host. Use the management IP literal with `--label`, or a name with exactly one record. |
| `register: … invalid network device request` at `add` | An IP literal `--endpoint` without `--label`, a `--label` that differs from the host name given as `--endpoint`, or a label that is not printable UTF-8. Nothing was registered; fix the flags and re-run. |
| `register: … network device trust identity does not match` at `add` | The device answering at registration presented another fingerprint than the one you confirmed, for example because the host name now resolves to another address. Nothing was registered; probe again and compare out of band. |
| Endpoint refused at `probe` or `add` | The address is public, loopback, link-local, multicast or unspecified, or the name resolved to such an address. Use the internal management address. |
| `stdin is not a terminal: the typed 'yes' must come from a person at a terminal` | `add`, `repin`, `unblock` and `remove` need an interactive terminal; run them in a terminal, not from a pipe or script. |
| `stdin is not a terminal: the credential is asked without echo on a terminal, or pass --secret-fd N` | Run in a terminal or pass `--secret-fd N` with `N< file`. |
| `--secret-fd must name an open regular file or pipe` | The descriptor was not redirected, or is a socket. Use `--secret-fd 3 3< <file>`. |
| `not confirmed; nothing registered` | Anything other than `yes` was typed. Compare the fingerprint again and re-run. |
| `device registered, credential not stored: …` | Registration worked, storing the credential failed. Fix the cause and run `nebula netdev credential set <device-id>` (for `cbs` with `--username nos-read --secret-fd 3 3< <key-file>`). |
| `add`/`credential`/`remove` refuse with a locked vault | Run `nebula unlock` on the executor host first. |
| `the device presents the stored pin; nothing to re-pin` | Nothing changed; no re-pin needed. |
| Device `blocked` in `list` after a rotation or re-pin | Revoking the device's grants failed and the device was blocked to fail closed. Run `nebula netdev block <device-id> --reason '<note>'` to retry the revocation, then `unblock` if the device should be read again. |
| Device `blocked` in `list` after a failed `remove` | A removal step failed; the device stays blocked on purpose. Fix the cause (for example `nebula unlock`) and run `nebula netdev remove <device-id>` again; it resumes where it stopped. Do not `unblock` a half-removed device. |
| `block` refuses with an invalid-request error | `--reason` is missing, empty, too long or contains control characters. Pass a short printable note. |
| Reads fail with `device reads are not implemented yet (ND-14)` | Expected today; see [What you can use today](#what-you-can-use-today). |
| No SSH login to a CBS switch for several minutes | A session was aborted hard; see [Known quirks](#known-quirks). Wait about 10 minutes or use the console. |
| CBS clock wrong, NTP never syncs | No default gateway on the management interface; see [Known quirks](#known-quirks). |
| CLI cannot dial the executor | Check `NEBULA_EXECUTOR_SOCKET` and that the socket is served by the `NEBULA_EXECUTOR_USER` user (default `nebula-executor`). |
