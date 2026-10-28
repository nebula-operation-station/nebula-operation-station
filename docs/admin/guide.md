# Installation and operations handbook (Release 0.9)

This handbook takes you from an empty machine to daily operation of
Nebula Operation Station and covers everything an operator needs
afterwards: configuration, backups, upgrades, troubleshooting and
removal. Developers building from source start with
[`docs/dev/getting-started.md`](../dev/getting-started.md) instead.

Contents:

1. [What Nebula is](#1-what-nebula-is)
2. [Planning](#2-planning)
3. [Installation](#3-installation)
4. [Reverse proxy and TLS](#4-reverse-proxy-and-tls)
5. [First login and security keys](#5-first-login-and-security-keys)
6. [Configuration reference](#6-configuration-reference)
7. [Adding and enrolling hosts](#7-adding-and-enrolling-hosts)
8. [Trusting actions, signers and modules](#8-trusting-actions-signers-and-modules)
9. [Daily operation](#9-daily-operation)
10. [Notifications, API and history](#10-notifications-api-and-history)
11. [Operating securely](#11-operating-securely)
12. [Backup and restore](#12-backup-and-restore)
13. [Upgrades](#13-upgrades)
14. [Monitoring and logs](#14-monitoring-and-logs)
15. [Troubleshooting](#15-troubleshooting)
16. [Uninstalling](#16-uninstalling)
17. [Reference](#17-reference)
18. [Limits you should know](#18-limits-you-should-know)

## 1. What Nebula is

Nebula is a self-hosted operations control plane for Linux homelabs of
about 5 to 100 hosts: inventory, SSH-based patching and service
operations, staged rollouts, Docker and Compose, runbooks and modules,
IPAM and network discovery, and a signed audit trail. Managed hosts need
no agent; Nebula logs in over SSH.

It runs as three services on one machine, each as its own OS user:

| Service | OS user | Job | Holds |
| --- | --- | --- | --- |
| `nebula-executor` | `nebula-executor` | Decides and runs every privileged step | SSH keys and vault secrets (in memory, only while unlocked), permits, host-key pins, the risk floor, the event key. No network listener: a Unix socket only. |
| `nebula-server` | `nebula-server` | Web UI, inventory, IPAM, planning, history view | No keys. It can only *propose*; it never authorizes. |
| `nebula-discovery` | `nebula-discovery` | Runs queued Nmap scans | Raw sockets only; no credentials, no database, no listener. |

The `nebula` CLI is run by an **admin user** (a normal login on the
Nebula machine) to unlock the executor, approve on the hardened path,
trust scripts, manage signers and run backups.

Every run is bound to a **permit**: the executor computes a digest over
the exact script, parameters, target hosts with their pinned host keys,
credentials and rollout stages, and runs only what a human approved for
that digest, either with a FIDO2 security key in the browser or with
`nebula approve` on the machine. The executor rates each operation
(LOW, MEDIUM, HIGH, CRITICAL) from its own data; the web server cannot
lower that rating.

Release 0.9 covers: inventory (manual, CSV import), SSH enrollment with
host-key pinning, update checks and installation (Debian, Ubuntu, Proxmox
VE), reboots that wait for the host, services, Docker and Compose,
rollouts in stages, scheduled read-only checks, runbooks with typed
parameters and vault secrets, signed modules with declarative UI, the
Safety Scanner, IPAM, network discovery, global search, notifications, a
read-only API, signed executor events, backup and restore, Debian packages
and container images.

## 2. Planning

### The Nebula machine

- A small VM or host running **Debian 12** (Ubuntu 22.04 and 24.04 work
  too) with systemd, used for nothing else. It holds SSH keys that are
  root on every managed host: keep it patched, give it encrypted or no
  swap, and restrict who can log in.
- **A hostname and TLS.** The UI is served over HTTPS under one fixed,
  lowercase hostname, the WebAuthn *RP ID* (for example
  `nebula.lab.example.org`). You need a reverse proxy with a certificate
  for it (section 4). The RP ID cannot be changed later without
  registering every security key again.
- **Security keys.** At least one FIDO2 key with a PIN (user
  verification), better two: the second is your backup.
- **Admin accounts.** One normal login on the Nebula machine for each
  person who unlocks and approves. Not root, and not one of the Nebula
  system users.
- **Passphrases.** One passphrase for the SSH keys (all key files share
  it), and optionally the vault passphrase (at least 32 characters; using
  the same one is recommended). Keep them in your password manager: no
  backup contains them.
- **A backup recipient.** An [age](https://age-encryption.org) key pair
  created on a machine you keep safe, not on the Nebula machine
  (section 12).

### Network flows

Nebula needs no inbound port other than the one of your reverse proxy.

| From | To | Protocol | Purpose |
| --- | --- | --- | --- |
| Browser | Reverse proxy | HTTPS 443 | Web UI under `https://<rp-id>` |
| Reverse proxy | `nebula-server` | HTTP, `127.0.0.1:8080` | Never expose this port itself |
| `nebula-server` | `nebula-executor` | Unix socket `/run/nebula/executor.sock` | Proposals, status, results |
| `nebula-executor` | Managed hosts | SSH, TCP 22 or the endpoint's port | Every action; outbound only |
| `nebula-server` | Webhook, ntfy, Telegram | HTTPS | Notifications, if configured |
| `nebula-discovery` | Your known networks | ICMP, TCP, UDP (Nmap) | Discovery scans you queued |
| Managed hosts | Package mirrors, container registries | HTTPS | Updates, image checks (from the hosts, not from Nebula) |

### Managed hosts

- Debian 12, Ubuntu 22.04 or 24.04, or Proxmox VE, with OpenSSH server,
  `sudo` and systemd. Durable jobs (updates, Compose updates, durable
  runbooks) need `sudo -n` and systemd on the host.
- An endpoint is an IP address or DNS name, optionally with a port
  (`192.168.0.21`, `web-01.lan:2222`, `[fd00::21]:22`). A host may have
  several endpoints, for example LAN and VPN; Nebula tries them in order
  and falls back on a TCP failure.
- *Check image updates* needs `curl` and HTTPS from the host to the
  registries. Attached runbooks with secrets need `$XDG_RUNTIME_DIR` (a
  tmpfs) for the SSH user; otherwise make the runbook durable.
- If you use fail2ban, add the Nebula machine's addresses to `ignoreip`
  (as IPs, not hostnames).

## 3. Installation

**For a lab, the shortest path** is
[`deploy/quickstart/`](../../deploy/quickstart/README.md): one script on the
Nebula machine (packages, Go, build, `install.sh`, backup key, SSH key,
Caddy with an internal CA, unlock, first code) and one on each managed
host. The rest of this section describes the steps it automates.

There are three ways to install. All three create the same separation of
users and data.

| Way | Use it when | Upgrades |
| --- | --- | --- |
| Release tarball and `install.sh` | Default for a dedicated VM | Run `install.sh` from the new tarball |
| Debian package | You run the APT repository | `apt upgrade`, then back up and restart yourself |
| Containers (Compose) | Your Nebula machine runs Docker anyway | New image, volume copy first |

### 3.1 From the release tarball

Download `nebula_<version>_linux_<arch>.tar.gz` and
`nebula_<version>_checksums.txt` from the release, check and extract:

```
sha256sum --ignore-missing -c nebula_<version>_checksums.txt
mkdir nebula && tar -xzf nebula_<version>_linux_amd64.tar.gz -C nebula
cd nebula
sudo ./deploy/install.sh --admin-users alice --rp-id nebula.lab.example.org
```

`--admin-users` is a comma-separated list of existing OS users
(`alice,bob`); `--rp-id` is the lowercase hostname. Both are required. The
script is idempotent and changes nothing on a dry run:
`NEBULA_INSTALL_DRY_RUN=1 ./deploy/install.sh --admin-users alice --rp-id nebula.lab.example.org`.

What it does (details in [section 17](#17-reference)):

- creates the system users `nebula-executor`, `nebula-server`,
  `nebula-discovery` and the group `nebula-rpc`, and adds each admin user
  to `nebula-rpc` (**log out and in again** for that to take effect);
- creates the data directories under `/var/lib/nebula` with their modes;
- installs the four binaries to `/usr/bin` and the units to
  `/etc/systemd/system` (unit files you edited are left alone);
- writes the executor drop-in
  `/etc/systemd/system/nebula-executor.service.d/10-local.conf` with your
  admin users and RP ID (rewritten on every run: never edit it; see
  section 6.2) and the server drop-in `nebula-server.service.d/20-discovery.conf`;
- writes `/etc/nebula/server.json` only if it does not exist yet (later
  runs never overwrite it);
- on an upgrade, makes a backup first (section 13);
- enables and starts `nebula-executor`, `nebula-server` and the discovery
  path unit and timer.

For network discovery also install Nmap (`sudo apt install nmap`);
without it scans fail with a clear message and everything else works.

Continue with [3.4](#34-the-ssh-key-for-managed-hosts).

### 3.2 From the Debian package

Set up the repository with its key in a keyring file of its own (never
`apt-key`), as described in [`deploy/apt/README.md`](../../deploy/apt/README.md),
then:

```
sudo apt update && sudo apt install nebula-operation-station
sudo /usr/share/nebula/deploy/install.sh --from-package --admin-users alice --rp-id nebula.lab.example.org
```

The package installs the binaries to `/usr/bin`, the units to
`/lib/systemd/system`, the deployment scripts to
`/usr/share/nebula/deploy` and this handbook to
`/usr/share/doc/nebula-operation-station/`, and recommends `nmap`. It
starts nothing on its own: the services stay off until
`install.sh --from-package` has created the users, directories, drop-ins
and `server.json`, exactly as the tarball path does.

Continue with [3.4](#34-the-ssh-key-for-managed-hosts).

### 3.3 In containers

`deploy/container/compose.yaml` runs the executor, the server and
discovery as three containers from one image, each with a fixed UID
(executor 10001, server 10002, discovery 10003; group `nebula-rpc` 10010;
the admin `nebula-admin` 10100), read-only, with all capabilities dropped
(discovery keeps `NET_RAW`) and `no-new-privileges`. Read the container
section of [`docs/threat-model.md`](../threat-model.md) first: the
executor and discovery use the host network, and whoever can use Docker
on the machine is root over Nebula.

1. **Get the image.** If the release publishes an image, pull it by
   digest. Otherwise build it yourself from a checked-out release tag (the
   build context holds the four binaries):

   ```
   make build
   docker build -t nebula:<version> -f deploy/container/Dockerfile bin/
   ```

2. **Configure.** In `deploy/container/`, set `public_origin` in
   `server.json` to `https://<rp-id>` and create a file `.env` next to
   `compose.yaml`, so that every later `docker compose` command finds the
   values:

   ```
   NEBULA_RP_ID=nebula.lab.example.org
   NEBULA_IMAGE=nebula:<version>
   ```

3. **Start.** `docker compose up -d`, then `docker compose ps`: all
   three containers run, and `docker compose logs executor` shows
   `"locked":true`.

4. **Install the SSH key.** The image contains no `ssh-keygen`. Create
   the key on the Docker host (section 3.4 explains the requirements) and
   copy it into the executor's volume with a short-lived helper container
   that sets the executor's UID and mode:

   ```
   ssh-keygen -t ed25519 -C nebula-default -f ./nebula-default.key
   docker run --rm -v nebula_executor-data:/data -v "$PWD:/k:ro" debian:12-slim \
     install -o 10001 -g 10001 -m 0600 /k/nebula-default.key /data/keys/nebula-default.key
   shred -u ./nebula-default.key    # the copy in the volume is the one Nebula uses
   ```

   Keep `nebula-default.key.pub`; it is the public key. The volume name is
   `<project>_executor-data`; the project is `nebula`
   (`docker volume ls` shows it).

5. **Use the CLI** inside the executor container as `nebula-admin`, with
   a terminal (`docker compose exec` allocates one; the passphrase prompt
   needs it):

   ```
   docker compose exec -u nebula-admin executor nebula unlock
   docker compose exec -u nebula-admin executor nebula status
   docker compose exec -u nebula-admin executor nebula webauthn code
   ```

The server is published on `127.0.0.1:8080` only; put your reverse proxy
in front (section 4). Discovery runs with `-watch=10s` and picks up queued
scans by itself. Every other `nebula …` command in this handbook runs the
same way, prefixed with `docker compose exec -u nebula-admin executor`.
Backups of a container install are volume copies (section 12.4);
`nebula backup` is for host installs.

### 3.4 The SSH key for managed hosts

The executor logs in to managed hosts with keys in
`/var/lib/nebula/executor/keys/`, one file per credential reference:
`<ref>.key`, where the reference is lowercase letters, digits, `_` and
`-`. The default reference is `nebula-default`. Create it as the executor
user, with the long passphrase from your password manager:

```
sudo -u nebula-executor ssh-keygen -t ed25519 -C nebula-default \
  -f /var/lib/nebula/executor/keys/nebula-default.key
```

The executor refuses a key that does not meet these rules:

- OpenSSH format with a passphrase (`ssh-keygen` creates that; convert
  older PEM keys with `ssh-keygen -p -o -f FILE`). Unencrypted keys are
  refused.
- Owned by the executor user, not accessible by group or others (0600).
- All key files share one passphrase: `nebula unlock` decrypts all of
  them at once and fails if one does not match.

### 3.5 First start

Log out and in again (for the `nebula-rpc` group), then:

```
nebula status        # executor running, locked
nebula unlock        # asks for the key passphrase
nebula vault init    # optional: the vault for runbook secrets (passphrase of at least 32 characters)
nebula events key    # note this fingerprint somewhere outside the machine (section 10.3)
```

**After every restart of the executor** (reboot, upgrade, crash) it
starts locked: nothing runs until an admin runs `nebula unlock` on the
machine. With notifications set up you get a message when that happens.

## 4. Reverse proxy and TLS

`nebula-server` listens on `127.0.0.1:8080` and serves plain HTTP. Put a
TLS proxy in front that serves exactly `https://<rp-id>` and passes
requests unchanged, including the `Origin` header: state-changing
requests whose origin is not `public_origin` are refused, and WebAuthn
works only under the RP ID.

Caddy (obtains and renews the certificate itself):

```
nebula.lab.example.org {
    reverse_proxy 127.0.0.1:8080
}
```

nginx:

```
server {
    listen 443 ssl;
    server_name nebula.lab.example.org;
    ssl_certificate     /etc/ssl/nebula/fullchain.pem;
    ssl_certificate_key /etc/ssl/nebula/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        client_max_body_size 1m;    # Nebula refuses larger request bodies anyway
    }
}
```

Do not expose port 8080. `public_origin` in `/etc/nebula/server.json`
must be `https://<rp-id>`, lowercase, without a path; the installer sets
it. If the proxy runs on another machine, see `allow_remote_listen` in
section 6.1 and restrict port 8080 to the proxy with a firewall.

## 5. First login and security keys

1. On the Nebula machine: `nebula webauthn code` prints a one-time code
   (single use, valid for 15 minutes).
2. Open `https://<rp-id>/setup`, enter the code and register your first
   security key.
3. Log in at `https://<rp-id>/login`.
4. Add a second key in *Settings* → *Sign-in and security keys*:
   *Add a security key* takes a fresh one-time code (run
   `nebula webauthn code` on the Nebula machine) and a label, then asks
   for the new key and confirmation with an already registered one. A
   hardware key (YubiKey) and a passkey (Touch ID, Windows Hello) both
   work; two keys are recommended.
5. Recommended: `nebula totp setup` on the machine. TOTP lets you log in
   when every key is lost; Nebula then forces a new key registration,
   which you confirm on the machine with `nebula totp finish-recovery`.

`nebula webauthn list` shows the registered keys (with the key that
confirmed each one). Removing a key is CLI-only:
`nebula webauthn remove ID` removes one and locks the executor; the
Settings page shows the exact command for every key.

**Recovery.** TOTP setup and removal are CLI-only: `nebula totp setup`,
`nebula totp status`, `nebula totp remove`. The *Recovery* section in
Settings shows the current status and the commands.

**Privileged session.** On the dashboard, *Open privileged session*
(security key with user verification) lets LOW actions run for the
session without a further prompt. The session lasts 60 minutes by
default (`-session-minutes`, section 6.2). *Lock* (or `nebula lock`)
wipes the keys from memory, ends the session and revokes every permit.

## 6. Configuration reference

### 6.1 `/etc/nebula/server.json`

Owned `root:nebula-server`, mode 0640. Restart `nebula-server` after a
change (`sudo systemctl restart nebula-server`). Unknown keys are an
error, and the server lists every problem at once when it refuses to
start.

| Key | Default | Meaning |
| --- | --- | --- |
| `listen` | `127.0.0.1:8080` | Address the server listens on (`host:port`). |
| `allow_remote_listen` | `false` | Must be `true` for a non-loopback `listen` address. Only for a proxy on another machine; firewall the port. |
| `public_origin` | (required) | `https://<rp-id>`: a bare, lowercase https origin (no path, query or fragment). |
| `data_dir` | (required) | Server data, `/var/lib/nebula/server`. |
| `executor_socket` | (required) | `/run/nebula/executor.sock`. |
| `executor_user` | (required) | `nebula-executor`; the server checks that the socket is served by this user. |
| `discovery_dir` | `/var/lib/nebula/discovery` | Discovery spool (`jobs/`, `results/`). Without the directory, discovery shows as not installed. |
| `audit_hash_chain` | `false` | Chain the server's own audit lines by hash (section 10.3). |
| `notifications` | none | Providers, section 10.1. |
| `api` | disabled | Read-only API, section 10.2. |

A file with notification secrets must not be readable or writable by
others; the server refuses to start otherwise (the installer's 0640 is
fine). The keys `listen`, `allow_remote_listen`, `public_origin`,
`data_dir`, `executor_socket` and `executor_user` can also be given as
flags of the same name, which override the file (the other keys have no
flag), for example
`nebula-server -config /etc/nebula/server.json -listen 127.0.0.1:8081`.
Other `nebula-server` flags: `-version`, `-notify-test`,
`-export-actions DIR` and `-api-token NAME:SCOPE[,SCOPE]` (sections 8.1
and 10).

### 6.2 Executor flags

The executor is configured by flags in its unit. `install.sh` writes
`10-local.conf` on every run with these values:

| Flag | Value from `install.sh` | Meaning |
| --- | --- | --- |
| `-data-dir` | `/var/lib/nebula/executor` | Private state, mode 0700 |
| `-socket` | `/run/nebula/executor.sock` | The only interface |
| `-socket-group` | `nebula-rpc` | Group of the socket file |
| `-server-user` | `nebula-server` | Gets the server role |
| `-admin-users` | `--admin-users` | Get the admin role (unlock, approve, trust, backup) |
| `-rp-id` | `--rp-id` | WebAuthn RP ID |
| `-origin` | `https://<rp-id>` | Allowed WebAuthn origin (repeatable) |
| `-hardened` | off | HIGH and CRITICAL operations need `nebula approve` on the machine; trusting from the browser is refused |
| `-session-minutes` | 60 | Length of the privileged session |

Every other caller UID is refused. The executor refuses to start as root,
with root or a Nebula system user as admin, or without `-rp-id` and an
`-origin`.

To change a flag, do not edit the unit or `10-local.conf`. Create
`/etc/systemd/system/nebula-executor.service.d/20-local.conf`, which
`install.sh` never touches and which systemd applies after
`10-local.conf`. It must clear and repeat the whole command line:

```
[Service]
ExecStart=
ExecStart=/usr/bin/nebula-executor \
  -data-dir /var/lib/nebula/executor \
  -socket /run/nebula/executor.sock \
  -socket-group nebula-rpc \
  -server-user nebula-server \
  -admin-users alice,bob \
  -rp-id nebula.lab.example.org \
  -origin https://nebula.lab.example.org \
  -hardened \
  -session-minutes 30
```

Then `sudo systemctl daemon-reload && sudo systemctl restart nebula-executor`
and `nebula unlock`. Keep the admin users and RP ID in it in step with
what you pass to `install.sh`.

### 6.3 Discovery and the CLI

`nebula-discovery` takes `-spool DIR` (default `/var/lib/nebula/discovery`),
`-nmap PATH` (default `/usr/bin/nmap`), `-timeout` (time limit per scan,
default 1 hour) and `-watch INTERVAL` (keep running and poll, used in the
container; on a host, systemd starts it per job).

The `nebula` CLI finds the executor at `/run/nebula/executor.sock`, or at
`$NEBULA_EXECUTOR_SOCKET`.

## 7. Adding and enrolling hosts

Add hosts under **Inventory**, one by one or with **Import CSV**. A host
has an ID, endpoints in the order to try, an environment (used by
DEV → QA → PROD rollouts), a criticality, tags and groups.

### 7.1 The enrollment script

Enrolling gives Nebula a restricted login on the host:

```
nebula host enroll-script --from 192.168.0.10,100.64.0.10 > enroll.sh
```

`--from` lists the addresses (IPs or CIDR ranges) the Nebula machine
connects *from*. The script creates a `nebula` user (`--user` for
another name), installs the executor's public key with
`from="…",no-agent-forwarding,no-port-forwarding,no-X11-forwarding`, adds
a NOPASSWD sudo rule `/etc/sudoers.d/nebula` (checked with `visudo`; this
makes the `nebula` user effectively root, as the specification states)
and a cleanup rule `/etc/tmpfiles.d/nebula.conf` for job directories
older than 14 days. `--no-sudo` leaves out sudo: then only read-only
actions work. `--key REF` uses another credential than `nebula-default`.

If sshd limits logins with `AllowUsers` or `AllowGroups` (hardening
baselines often do), the script adds the user in
`/etc/ssh/sshd_config.d/10-nebula.conf`: `AllowUsers nebula@<each --from
address>` and/or `AllowGroups nebula`, only for the directives already in
use. sshd merges these lists with the existing ones, so everyone allowed
before stays allowed. `AllowGroups` names the user's own group, which the
script creates (also where `USERGROUPS_ENAB=no`); if that group has other
members it adds nothing and tells you. The script checks the result with
`sshd -t` and reloads sshd (it applies to new connections); if sshd does
not read `sshd_config.d` (no `Include`), it prints the line to add
yourself. Restrictions inside a `Match` block (for example `Match Address`)
are only reported: the script checks the configuration sshd applies to
connections from each `--from` address and tells you what to add there.
Delete the drop-in if you later remove `AllowUsers`/`AllowGroups`
elsewhere: on its own it would let only Nebula in. A `DenyUsers`/
`DenyGroups` entry that names the user, and an sshd configuration that
`sshd -T` cannot read, are reported as well.

**Read the script**, copy it to the host and run it there as root.

### 7.2 Pinning host keys

Compare every fingerprint with
`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the host's console
first: that comparison is what protects you from a machine in between.

**In the web UI (many hosts at once):** Inventory → **Enroll hosts**
lists the hosts without a pinned key. Select hosts, pick the endpoint and
SSH user, **Read host keys**: the executor connects to each endpoint and
shows the key it got (no credential is sent). Compare, tick the
confirmation and approve with your security key (an open privileged
session is needed). The executor reads every key once more, pins only
unchanged ones and tries a login, so the table tells you whether the
enrollment script ran. Hosts pinned this way count as HIGH until you set
their criticality on the executor host.

**On the executor host (one host, or from a `known_hosts` file you trust
with `--known-hosts`):**

```
nebula host probe 192.168.0.21                 # shows the key, sends no credential
nebula host pin --criticality MEDIUM web-01 192.168.0.21 100.64.0.21
nebula host test web-01 192.168.0.21           # logs in (keys must be unlocked)
```

The criticality on the executor (`nebula host pin --criticality` or
`nebula host criticality HOST LEVEL`) decides how strong an approval must
be; the inventory's value is only for display. `nebula host keys` lists
pins and blocked hosts, `nebula host list` the criticality records.

### 7.3 A changed host key

If a host presents another key (reinstall, or an attack), Nebula stops
using it, blocks the host, shows it on the dashboard and notifies. Check
the new key on the host's console, then press **Re-pin…** next to the
host on the dashboard: it shows the pinned and the presented key, asks
you to confirm the comparison and needs your security key with user
verification. Nebula reads the key again before it pins it; the host's
criticality stays. On the executor host the same is
`nebula host unpin web-01`, then `nebula host pin` again.

## 8. Trusting actions, signers and modules

The executor treats every script it does not know as at least HIGH. Trust
says who vouches for exact bytes; it is recorded on the executor and
cannot come from the web server.

### 8.1 The built-in actions

To run the built-in actions at their declared risk, read and trust them
once per release (the directory must not exist yet):

```
nebula-server -export-actions ~/nebula-actions-0.9   # writes the scripts, prints one trust command per action
less ~/nebula-actions-0.9/*.sh
# then run the printed `nebula artifact trust ...` commands
```

| Action | Risk | Kind |
| --- | --- | --- |
| `core.facts` Collect facts | LOW | read-only |
| `package.list_updates` Check updates | LOW | read-only |
| `package.refresh` Refresh package lists | LOW | |
| `package.install_security` Install security updates | MEDIUM | durable job |
| `package.install_all` Install all updates (`full-upgrade` on Proxmox VE) | MEDIUM | durable job |
| `system.reboot` Reboot | HIGH | waits for a new boot ID |
| `service.list`, `service.status` | LOW | read-only |
| `service.restart`, `.start`, `.stop`, `.reload` | MEDIUM | one unit |
| `docker.list`, `.logs`, `.inspect`, `.check_updates` | LOW | read-only |
| `docker.start`, `.stop`, `.restart` | MEDIUM | one container |
| `docker.compose_update` Update Compose project | MEDIUM | durable job |

Without this, every operation needs a user-verified approval.
`nebula artifact list` shows what is trusted, `nebula artifact untrust`
withdraws a trust. Trust again after every upgrade that changes an
action's version.

The executor also runs the **Safety Scanner** over every script, trusted
or not: downloading and executing, `eval` or encoded payloads,
destructive disk commands and bootloader changes make a script at least
HIGH; users and groups, firewall and network changes, package removal,
reboots and Docker removals at least MEDIUM; a line it cannot read counts
HIGH. The scanner only ever raises the risk, and a clean scan proves
nothing. The planning and operation pages show its findings; `nebula
approve` shows them and the script's first 40 lines (at most 4 KiB)
before you confirm. The web pages scan the script the server holds; `nebula
approve` shows the executor's own scan of the bytes it will authorize and
says "not scanned by the executor" when the proposal carried no script
bytes (the executor still scans them before the run).

### 8.2 Module signers

Modules signed by someone you trust run at their declared risk. Get the
author's public key (`ssh-ed25519 …`) and its fingerprint on two
different channels, then on the executor host:
`nebula signer add --name "Who" key.pub` and type the fingerprint to
confirm (CRITICAL: every module this key signs is trusted).
`nebula signer list` shows them; `nebula signer remove SHA256:…`
withdraws a key and the trust of every module it signed. If a new version
of a module is signed by another key, Nebula refuses it until you have
checked why and run `nebula module confirm-signer MODULE SHA256:…` (it
shows the current and the new signer and asks you to type the new
fingerprint). Unsigned modules always need your security key (at least
HIGH).

### 8.3 Writing and importing modules

A module bundles actions others wrote. Its author keeps a `module.yaml`
(name, version, title, actions with script, risk, timeout, parameters,
secret slots, declarations) and the scripts, runs
`nebula module pack DIR`, signs the printed lock with
`ssh-keygen -Y sign -f KEY -n nebula-module DIR/module.lock.json` and
builds the archive (at most 1 MiB) with
`nebula module pack --archive OUT.tar.gz DIR`. Import it under
*Runbooks → Modules*. The page shows whether the executor verified it and
every script it runs; plan its actions like any other. A module may also
show a tab on each host's page with values from its actions' latest
results; scripts write their result as one JSON object to the file
`$NEBULA_RESULT` (runbooks can too).

## 9. Daily operation

### 9.1 Patching

1. Dashboard: **Open privileged session** (security key). LOW actions such
   as checking updates run within the session without a further prompt.
2. **Operations → New**: choose **Check updates**, select hosts, plan. The
   inventory then shows `2 security / 9 total, reboot required, checked …`.
3. **Install security updates** (or all updates) on the hosts you want,
   approve with your key. The job runs on the host under systemd with
   prechecks (free space on `/` and `/var`, `dpkg` state, writable disk,
   apt lock) and postchecks (dpkg state, reboot required, newly failed
   units). A precheck failure installs nothing. **Install all updates**
   uses `full-upgrade` on Proxmox VE nodes, as Proxmox requires.
4. **Reboot** where the result says a reboot is required. Nebula waits for
   the host to come back with a new boot ID; after 20 minutes the result
   is `host_not_returned`.

Results stay on the operation page; host output is shown as text only.
The executor never runs anything twice: if Nebula restarts during a job,
it collects the result afterwards. If no endpoint of a host answered
(`network_unreachable`: nothing was sent, nothing ran), read-only actions
are retried automatically after 20 seconds and after 1 minute with the
same approval; other actions report the host as unreachable, and you plan
the operation again. A host that was reached uses up the approval for that
host, whatever the result.

### 9.2 Rollouts in stages

Under *Rollout* on the planning page you choose how the hosts run: all at
once (the default), *canary first* (the first N hosts alone, the rest
only after them), *in waves* of N hosts, or *DEV → QA → PROD* by the
inventory environment. Each stage allows a number of failed and of
unreachable hosts (a canary allows none); a stage with more failed hosts
stops the rollout for good, and the hosts after it do not run. After a
stage passed, the rollout waits for you ("Continue to stage N") or, for a
LOW or MEDIUM operation, continues by itself if you chose so. The stages
are part of what you approve: the executor enforces them, not the web
server. Opening a stage of a HIGH or CRITICAL operation needs your
security key again (in hardened mode `nebula approve --stage N <digest>`
on the executor host). A host that could not be reached can be retried or
skipped (skipping needs the same approval as opening a stage);
*Abort rollout* stops every host that has not run. A restart of the
executor ends the rollout like any approval.

### 9.3 Services and Docker

**Services:** List services, Service status (unit plus last journal
lines) and Restart/Start/Stop/Reload take a unit name such as
`nginx.service`.

**Docker:** List containers shows every container with image, state,
health, published ports and its Compose project, and says when a host has
no Docker. Container logs takes a container name or ID and shows its
state and last 100 log lines; Container details shows its image and
repository digest, state, health, restart policy, mounts, published ports
and networks (never its environment, command line or labels, which often
hold secrets). All three read through the `docker` group if the SSH user
is in it, otherwise through `sudo -n`; both are root on the host. Start,
Stop and Restart container (MEDIUM) run `docker start|stop|restart` of one
container and show its state before and after; nothing is recreated,
pulled or updated, and they are never retried automatically. Check image
updates (LOW) asks each registry, from the host, for the current digest
of every running container's image tag (a manifest HEAD request:
anonymous, nothing is pulled, Docker Hub pull limits are not used) and
lists the images with an update available. Private registries that need
credentials show as "unknown". Update Compose project (MEDIUM, a durable
job) takes the project name, finds its working directory and files from
the container labels, runs `docker compose pull` and then
`docker compose up -d`, and compares the containers before and after:
fewer running containers, a failed command or a container that was
healthy and is not anymore is FAILED; a container that is not healthy,
changed published ports or a different number of containers is a
WARNING. Run Check image updates first to see what will change.

### 9.4 Scheduled checks

*Operations → Scheduled checks* lets Nebula run read-only checks on its
own, for example a daily update check on all hosts. You choose actions,
hosts, an interval (hour, 6 hours, day, week) and a duration (at most 90
days), and approve the schedule once with your security key (hardened
mode: `nebula schedule approve <digest>` on the executor host). The
executor accepts only actions it rates LOW on every chosen host: the
built-in script trusted as LOW (section 8.1) and the host recorded with a
criticality (`nebula host pin --criticality`). It runs each action on
each host at most once per interval and checks the trust again on every
run; *Revoke* (or `nebula schedule revoke <id>`) stops a schedule at
once. Results appear as operations created by "schedule". A schedule
survives restarts of the executor, but nothing runs while it is locked.
Runs with secrets cannot be scheduled.

### 9.5 Runbooks

*Runbooks → New runbook* holds your own scripts (POSIX `sh`). A runbook
has a name (its action becomes `runbook.<name>`), a declared risk, a
timeout (10 seconds to 10 minutes attached, up to 6 hours durable),
attached or durable, and typed parameters: `name` (letters, digits and
`_.@:-`, not starting with `-`), `int`, `path` (absolute) or `choice`
(fixed words). The script reads them as `$NEBULA_P_<NAME>`; before it
starts, the host checks every value again with the same pattern. Its
output goes to the operation log. An attached runbook runs as the SSH user
and calls `sudo -n` where it needs root; a durable one runs as root under
systemd. A script that is not valid shell (`sh -n`) is refused when you
save it, as are scripts with control characters or invisible formatting
characters (such as bidi overrides), so what you review is what runs.

Saving creates a new version; versions never change, and an operation
always runs the version it was planned with. The executor does not know
your script, so a runbook is HIGH (security key each time) until you
trust that exact version on the executor host with the command shown on
its page (download the script, read it, then `nebula artifact trust …`),
or with *Trust this version* on the runbook page and your security key
(standard mode only); the Safety Scanner can raise it further.

### 9.6 Secrets in runbooks

Store a secret in the executor's vault (`nebula secret set <id>` on the
executor host; the value comes from the terminal or stdin, never from an
argument), declare a secret slot in the runbook (for example
`influx_token`) and name the vault secret when you plan the operation.
The executor reads the value and sends it to the host only: an attached
run keeps it in a private file under the SSH user's runtime directory
(`$XDG_RUNTIME_DIR`, which must be a tmpfs), a durable job under
`/run/nebula/<execution>/` (must be a tmpfs too), and both remove it when
the script ends; a killed or interrupted job is cleaned up by the
executor. The script reads the value from the file
`$NEBULA_SECRET_<SLOT>`. A run with secrets is at least MEDIUM and cannot
be scheduled. Known secret values are removed from its log and result (a
safeguard, not the protection); if the vault is locked when a durable job
finishes, the result waits on the host until you unlock, and if a secret
was deleted meanwhile, the output is withheld rather than stored.
`nebula secret list` shows IDs and versions, never values;
`nebula secret rm ID` deletes one.

### 9.7 Network (IPAM)

Under *Network* you keep your networks (prefix, VLAN, gateway, pools such
as `servers 192.168.10.10-192.168.10.49`) and the devices in them
(*assets*: NAS, printer, switch, …, managed or not). Nebula computes each
address's status from what claims it: an asset or a managed host's IP
endpoint (ASSIGNED), your reservation (RESERVED), your exclusion and the
network and broadcast address (EXCLUDED), a discovery sighting nobody
claims (DISCOVERED), or two claimants or a different MAC (CONFLICT).
Networks up to /22 show every address as a grid; larger ones and IPv6
list only the addresses something claims. The network page suggests free
addresses (of the whole network or one pool) that discovery has not seen
in 30 days: a suggestion, not a guarantee, because a device may be
switched off. Nebula never manages DHCP or DNS. **Add to managed hosts**
on an asset opens the inventory form with its values and links the new
host to the asset; enroll it as in section 7.

### 9.8 Discovery

*Network → Discovery* scans known networks with Nmap: host discovery,
selected ports, service discovery (top 100 ports with versions), all TCP
ports, or a custom scan from a fixed set of options (no free-form Nmap
arguments). Targets must lie inside a network you added, at most a /16
(IPv4) or /112 (IPv6) each. Queue a scan now, once at a time, or every N
hours (at least one); there is no default schedule. The scan runs in the
separate `nebula-discovery` service, started when a job is queued (and
every 10 minutes as a fallback). Its results land in staging: each host
is NEW, EXISTING (same MAC as an asset), POSSIBLE MATCH (same address,
but no MAC to compare, as across VPNs and routed networks) or CONFLICT
(the MAC or address belongs to another asset). Select the hosts and
import them: a new host becomes an asset (kind unknown; set its kind
afterwards), an existing one gets the address, MAC or hostname it lacks.
Conflicts are never imported. Every host seen also feeds the address
status. Names and banners come from the network and may lie.

### 9.9 Search

The search box in the navigation finds hosts (ID, name, endpoint, tag
`key=value`, group), assets (name, hostname, MAC, address), networks
(name, prefix, `vlan 10`), an address with its status, executions (ID
prefix, at least 4 characters, or action), runbooks and modules. Quick
actions (*Plan an operation* for a host, *Plan* for a runbook,
*Add to managed hosts* for an asset) only open the page that does the
work; nothing runs without the usual review and approval.

### 9.10 Day-to-day checklist

| Situation | What to do |
| --- | --- |
| Nebula machine rebooted or executor restarted | `nebula unlock` |
| Leaving the UI | Dashboard → **Lock** (or `nebula lock`) |
| A host key changed | Compare on the host console, then dashboard → **Re-pin…** (section 7.3) |
| A security key is lost | `nebula webauthn list`, `nebula webauthn remove ID` (locks the executor) |
| Every security key is lost | Log in with TOTP, register a new key, `nebula totp finish-recovery` |
| Operation shows `precheck_failed` | Read the reason on the operation page; nothing was installed |
| Host `UNREACHABLE` | Check the endpoints; `nebula host test HOST ENDPOINT` |
| Waiting approvals on the hardened path | `nebula pending`, then `nebula approve <digest>` |
| After an upgrade | `nebula unlock`; re-trust actions whose version changed (section 8.1) |
| Weekly | Look at the dashboard and *History*; copy `nebula events list --json` offsite |
| Monthly | Test a restore of the latest backup on a spare VM |

## 10. Notifications, API and history

### 10.1 Notifications

Add a `notifications` block to `/etc/nebula/server.json`, keep the file
0640 `root:nebula-server`, restart `nebula-server` and test with
`nebula-server -config /etc/nebula/server.json -notify-test`:

```json
"notifications": {
  "webhook":  {"url": "https://hooks.example.org/nebula", "secret": "<at least 32 random characters>"},
  "ntfy":     {"url": "https://ntfy.sh", "topic": "<random topic>", "token": "<optional>"},
  "telegram": {"bot_token": "<123456:ABC...>", "chat_id": "<chat id or @channel>"}
}
```

Each provider is optional. The webhook body is JSON, signed with
HMAC-SHA256 using the secret. An ntfy topic is 1 to 64 characters
`A-Za-z0-9_-`. You are notified about: a changed host key, an Ops State
change (worse or recovered), an operation that finished with failed
hosts, and the executor found locked after a restart. Messages never
contain host output.

### 10.2 Read-only API (Home Assistant, status pages)

The API is off by default. Create a token on the Nebula machine:

```
nebula-server -api-token homeassistant:inventory.read
```

It prints the token once and a JSON entry. Add the entry to `server.json`
under `"api": {"enabled": true, "tokens": [ ... ]}` (the file keeps only
the token's SHA-256) and restart `nebula-server`. Clients send
`Authorization: Bearer <token>`:

| Scope | Endpoints |
| --- | --- |
| `inventory.read` | `GET /api/v1/hosts`, `GET /api/v1/hosts/{id}`: Ops State, update counts, reboot required |
| `operations.read` | `GET /api/v1/operations`, `GET /api/v1/operations/{id}`: action, state, result classes |
| `execution_logs.read` | adds host output (result, log) to `/operations/{id}`; give it only where needed |

The API cannot change anything. To revoke a token, remove its entry and
restart. Token names are lowercase letters, digits, `_` and `-`.

**Home Assistant example** (`configuration.yaml`, one host; repeat the
block per host or use `/api/v1/hosts` with a template over the list):

```yaml
rest:
  - resource: https://nebula.lab.example.org/api/v1/hosts/web-01
    scan_interval: 300
    headers:
      Authorization: !secret nebula_api_auth
    sensor:
      - name: "web-01 Ops State"
        value_template: "{{ value_json.ops_state }}"
      - name: "web-01 security updates"
        value_template: "{{ value_json.updates.security if value_json.updates is defined else 0 }}"
        unit_of_measurement: "updates"
    binary_sensor:
      - name: "web-01 reboot required"
        value_template: "{{ value_json.updates.reboot_required if value_json.updates is defined else false }}"
```

with `nebula_api_auth: "Bearer nos_..."` in `secrets.yaml`. Ops State is
`READY`, `WARNING`, `UNREACHABLE` or `UNKNOWN`; an automation on
`WARNING`/`UNREACHABLE` is a cheap second channel next to the
notifications. The update counts are as fresh as the last **Check
updates** run (`checked_at`).

### 10.3 History and events

Every security-relevant step of the executor (unlock, logins, approvals,
runs, trust, signers, host keys, vault) is recorded as an event, signed
with the executor's event key and chained to the one before, so a
changed, reordered or missing event shows.

- `nebula events key` prints the event key's fingerprint. Note it
  outside the machine after installing and compare it with the one on the
  *History* page now and then. A restore onto a new machine starts a new
  event key; the chain records the change, and verification continues
  across it.
- `nebula events verify` checks the whole chain on the Nebula machine
  (it talks to the executor directly, so a compromised web server is not
  in the path).
- `nebula events list --json` writes the events with hashes and
  signatures for an offsite copy (`--after N`, `--limit N`). A body that
  is not valid JSON is written with an `error` field and makes the
  command fail, never a silent gap.

The *History* page also lists what was done in the web UI (the server's
audit lines). They are not signed: a compromised server could write any.
Set `"audit_hash_chain": true` in `server.json` to chain them; the page
then shows the chain's head hash, which you can note elsewhere to detect
a rewrite from the start. Audit lines cannot be updated or deleted in
place.

## 11. Operating securely

- **Hardened mode** (`-hardened`, section 6.2): HIGH and CRITICAL
  operations, opening their stages and approving schedules need the CLI
  on the machine (`nebula pending`, `nebula approve`), which shows what
  the executor will really run: the Safety Scanner's findings and the
  script's first 40 lines (at most 4 KiB), not just its hash. Use it when
  the web server could be exposed to more than you.
- **Lock** when you leave (`nebula lock` or the dashboard). An unlocked
  executor holds keys and secrets in memory.
- **Who is admin** is decided by the executor's `-admin-users`, not by
  group membership alone: membership in `nebula-rpc` only lets a user
  reach the socket. Remove people from both when they leave, then restart
  the executor.
- **Keep the Nebula machine small**: no other services, no shared
  logins, SSH with keys only, automatic security updates, encrypted or no
  swap. Core dumps are disabled for the executor.
- **Never** put secrets on a command line, give the web server's port
  8080 to the network, trust a script you have not read, or add a module
  signer whose fingerprint you got on only one channel.
- **Offsite copies**: back up regularly (section 12) and copy the
  event list offsite (section 10.3). They make a rewrite by root on the
  Nebula machine visible afterwards.
- What Nebula protects against and what not:
  [`docs/threat-model.md`](../threat-model.md).

## 12. Backup and restore

### 12.1 Set up once

On a machine you keep safe (not the Nebula machine):
`age-keygen -o nebula-backup.key`. Put the printed public key (`age1…`)
into `/etc/nebula/backup-recipients` on the Nebula machine (one recipient
per line; several are allowed). Keep `nebula-backup.key` offline, for
example in your password manager.

### 12.2 Back up

```
sudo nebula backup
```

It runs as root through `sudo` from an admin account (it reads the
server's data itself and asks the executor, as that admin, for its part)
and writes an age-encrypted archive to `~/nebula-backups/` of that admin
(`--out FILE` for another place) while everything keeps running. The
archive holds the inventory, history and configuration
(`server.json`, `backup-recipients`, the systemd drop-ins), the server
database (with execution logs and artifacts, so every backup is a full
one) and the executor's database and SSH key files, still protected by
their passphrase. It never holds the passphrases, decrypted keys,
plaintext secrets or the event key. Each database is copied consistently
and checked, and the archive is read back after writing.

Copy the archives off the machine, for example with
`restic backup ~/nebula-backups`. `--no-encrypt` writes an unencrypted
archive (you type `unencrypted` to confirm): it has no integrity
protection of its own (its checksums live inside it), so store and move
it only together with a checksum you keep elsewhere.

### 12.3 Restore

On the same machine, or on a new one after `install.sh` (same
`--admin-users` and `--rp-id`):

```
sudo nebula restore --identity nebula-backup.key FILE
```

It shows when, where and by which version the backup was made, checks the
manifest, every checksum and the schema versions before anything changes
(a backup from a newer Nebula is refused), and asks you to type
`restore`. A backup made on another machine also asks for that machine's
name (or `unknown` if the backup names none). It then stops the services,
moves the current data aside (kept as `*.pre-restore-<time>`), puts the
backup's data in place and starts the services locked. The backup's
configuration is written to `/etc/nebula/from-backup-<time>/` for you to
compare; it is not applied. Finish with `nebula unlock` (the keys need
their passphrase) and check `nebula status` and `nebula events verify`.

### 12.4 Container installs

Back up the volumes with the stack stopped and encrypt them on the way
out, because a volume copy holds everything the executor has, including
its event key. Streaming each volume straight into `age` leaves no
unencrypted copy on disk:

```
cd deploy/container
docker compose stop
for v in executor-data server-data; do
  docker run --rm -v nebula_$v:/v:ro debian:12-slim tar -C /v -cz . \
    | age -r age1… -o nebula-$v-$(date +%F).tar.gz.age
done
docker compose start          # then unlock again
```

To restore, stop the stack and stream each archive back into its empty
volume, then start the stack and unlock:

```
age -d -i nebula-backup.key nebula-executor-data-<date>.tar.gz.age \
  | docker run --rm -i -v nebula_executor-data:/v debian:12-slim tar -C /v -xpz
```

## 13. Upgrades

There is no self-updater; every upgrade is a step you take. Migrations
run when the new version starts, forward only, each in a transaction (a
failure rolls back and stops the start). There is no automatic downgrade:
the backup before the upgrade is the way back. Read the release notes
first.

**Tarball:** extract the new tarball and run
`sudo ./deploy/install.sh --admin-users … --rp-id …` from it, as an
admin user through `sudo`. It makes a backup with the new CLI first and
stops without changing anything if it cannot make one (no backup
recipients, no `sudo` from an admin, an executor older than backups) or
if the backup fails. `NEBULA_SKIP_BACKUP=1` upgrades without a backup.
Then it replaces the binaries and restarts the services whose binaries or
drop-ins changed. Run `nebula unlock`.

**Debian package:** `apt upgrade` installs the new version but never
restarts the services: the backup needs your `sudo`, which the package
manager does not have. The old version keeps running until you do both
steps yourself:

```
sudo nebula backup && sudo systemctl restart nebula-executor nebula-server
nebula unlock
```

**Containers:** build or pull the new image, back up the volumes
(section 12.4), set `NEBULA_IMAGE` in `.env` to the new tag,
`docker compose up -d`, then unlock.

After any upgrade: `nebula status`, `nebula events verify`, and trust the
built-in actions again if their versions changed (section 8.1).

## 14. Monitoring and logs

- **Services:** `systemctl status nebula-executor nebula-server
  nebula-discovery.path nebula-discovery.timer`.
- **Logs:** the services log JSON to the journal:
  `journalctl -u nebula-executor -u nebula-server -u nebula-discovery`.
  Audit lines have `"msg":"audit"` and a `kind` (for example
  `run_finished`, `unlocked`, `store_error`); host output and secret
  values never appear in logs.
- **State:** `nebula status` (locked or unlocked, keys, session, mode,
  permits, vault).
- **From outside:** the read-only API (section 10.2) and notifications
  (section 10.1); an executor found locked after a restart is notified.
- **Disk:** `/var/lib/nebula/server` grows with execution logs and
  history; keep an eye on it and on the backup archives.

## 15. Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `nebula: … permission denied` on the socket, or `peercred: peer UID holds no role` | Your login is not in `nebula-rpc` yet (log out and in) or not in `-admin-users`. Check `id` and the executor drop-ins. |
| `nebula: this needs a terminal` | `unlock` and other passphrase prompts read from the terminal, never from a pipe; in containers use `docker compose exec` without `-T`. |
| Executor does not start: `-admin-users is required`, `root cannot be an admin user`, `admin user … must not be the server user` | Fix the admin list and run `install.sh` again (or your `20-local.conf`). |
| Executor does not start: `executor.db is missing but executor.db.installed says one existed` | The database was deleted. Restore a backup (`sudo nebula restore`). Only to start empty on purpose (counters and spent execution IDs restart), remove the marker file named in the message. |
| `keyring: … is not passphrase-protected` / `has mode …` / `is owned by uid …` / wrong passphrase | See section 3.4: OpenSSH format with a passphrase, 0600, owned by the executor user, one passphrase for all key files. |
| Server does not start: `serverconfig: invalid config: …` | The message lists every problem: lowercase `https://` origin without a path, absolute paths, `allow_remote_listen` for a non-loopback `listen`, notification values, unknown keys. |
| Server does not start: `… contains notification secrets and is readable or writable by others` | `sudo chmod o-rwx /etc/nebula/server.json`. |
| Login or approval fails in the browser | You do not use `https://<rp-id>` exactly, or the proxy changes the `Host`/`Origin`. The RP ID and `public_origin` must match the address in the browser. |
| `vault_locked` when planning a runbook with secrets | `nebula unlock` (the vault opens with the keys). |
| `secret_unavailable: no vault secret …` | `nebula secret list`; set the secret or choose another one. |
| A schedule is refused | Only actions the executor rates LOW on every host: trust the built-in as LOW and record the host's criticality (section 9.4). |
| Discovery shows as not installed | `discovery_dir` missing or wrong, or the spool directories are absent; run `install.sh` again. |
| Discovery scans fail: `nmap is not installed (install the nmap package on the Nebula machine)` | `sudo apt install nmap`. |
| Scan results never arrive | The spool directories must be mode 2750 (`jobs/` `nebula-server:nebula-discovery`, `results/` the reverse); `install.sh` sets that. Check `systemctl status nebula-discovery.path`. |
| `install.sh`: no pre-upgrade backup was made | Add a recipient to `/etc/nebula/backup-recipients` and run it through `sudo` from an admin account, or use `NEBULA_SKIP_BACKUP=1` knowingly. |
| `nebula backup`: `run this with sudo` | Run `sudo nebula backup` from your admin login (not from a root shell). |
| Restore refuses: schema newer than this binary | The backup comes from a newer Nebula; install that version first. |
| Operation result `precheck_failed` | Nothing ran. The reason is on the page: disk space, `dpkg` state, apt lock held (another apt run), read-only disk. |
| Result `network_unreachable` | No endpoint answered; nothing was sent. Check the endpoints and the host's firewall; `nebula host test`. |
| Result `host_not_returned` | The host did not come back within 20 minutes after a reboot; check its console. |
| Host blocked after a host-key change | Section 7.3; never re-pin without comparing on the console. |
| Docker actions say the host has no Docker, or fail with permissions | Docker missing, or the SSH user is neither in the `docker` group nor allowed `sudo -n`. |
| Container: `required variable NEBULA_RP_ID is missing a value` | Create `.env` next to `compose.yaml` (section 3.3). |

## 16. Uninstalling

**Tarball install:** `sudo ./deploy/uninstall.sh` from the tarball stops
and removes the units, the drop-ins written by `install.sh` and the
binaries. It keeps the users, the group, `/var/lib/nebula` and
`/etc/nebula`. Make a backup first if you want to keep anything; then,
for a clean slate:

```
sudo rm -rf /var/lib/nebula /etc/nebula
sudo userdel nebula-server; sudo userdel nebula-executor; sudo userdel nebula-discovery
sudo groupdel nebula-rpc
```

**Package:** `sudo apt remove nebula-operation-station` stops and
disables the units and keeps data, configuration and users; remove them
as above.

**Containers:** `docker compose down` keeps the volumes;
`docker compose down -v` deletes them, with every key and all data.

**Managed hosts:** to release a host, remove the `nebula` user's key line
from `~nebula/.ssh/authorized_keys` (or the user: `userdel -r nebula`),
`/etc/sudoers.d/nebula`, `/etc/tmpfiles.d/nebula.conf` and
`/var/lib/nebula/jobs`, then `nebula host unpin HOST` and
`nebula host clear HOST` on the Nebula machine.

## 17. Reference

### 17.1 Users, files and directories

| Path | Owner, mode | Content |
| --- | --- | --- |
| `/usr/bin/nebula`, `nebula-server`, `nebula-executor`, `nebula-discovery` | root, 0755 | The binaries |
| `/etc/systemd/system/nebula-*.service`, `nebula-discovery.path`, `.timer` | root, 0644 | Units (package: `/lib/systemd/system/`) |
| `/etc/systemd/system/nebula-executor.service.d/10-local.conf` | root, 0644 | Executor flags, rewritten by `install.sh` |
| `/etc/systemd/system/nebula-executor.service.d/20-local.conf` | root, 0644 | Your own executor flags (optional) |
| `/etc/systemd/system/nebula-server.service.d/20-discovery.conf` | root, 0644 | Lets the server write the job spool |
| `/etc/nebula/server.json` | `root:nebula-server`, 0640 | Server configuration |
| `/etc/nebula/backup-recipients` | root | age recipients for backups |
| `/var/lib/nebula/executor/` | `nebula-executor`, 0700 | `executor.db` (permits, pins, counters, vault, events), `executor.db.installed`, `events.key`, `keys/<ref>.key` |
| `/var/lib/nebula/server/` | `nebula-server`, 0750 | `server.db` (inventory, operations, logs, runbooks, modules, IPAM, audit) |
| `/var/lib/nebula/discovery/jobs/` | `nebula-server:nebula-discovery`, 2750 | Queued scans |
| `/var/lib/nebula/discovery/results/` | `nebula-discovery:nebula-server`, 2750 | Scan results |
| `/run/nebula/executor.sock` | `nebula-executor:nebula-rpc`, 0660 | The executor's socket |
| `~<admin>/nebula-backups/` | the admin | Backup archives |

On a managed host: the `nebula` user with its `authorized_keys`,
`/etc/sudoers.d/nebula`, `/etc/tmpfiles.d/nebula.conf`, job directories
in `/var/lib/nebula/jobs/` and run directories (with secrets) in
`/run/nebula/`.

### 17.2 The `nebula` CLI

Run as an admin user on the Nebula machine (`nebula` without a command prints the same list):

| Command | Purpose |
| --- | --- |
| `status`, `unlock`, `lock` | Executor state; decrypt or wipe keys and vault |
| `pending`, `approve <digest>`, `approve --stage N <digest>`, `approve --skip HOST <digest>` | Hardened path: approvals, rollout stages, skipping a host |
| `schedule pending \| approve <digest> \| list \| revoke <id>` | Scheduled checks |
| `artifact trust --action ID --version X.Y.Z --risk LEVEL [--label TEXT] FILE`, `artifact untrust …`, `artifact list` | Trusted scripts |
| `signer add --name NAME FILE \| list \| remove SHA256:…`, `module confirm-signer MODULE SHA256:…` | Module signers |
| `module pack [--archive OUT.tar.gz] DIR` | Build a module (author side; no executor needed) |
| `backup [--out FILE] [--full] [--no-encrypt] [--pre-upgrade]`, `restore [--identity FILE] ARCHIVE` | With `sudo`; section 12 (`--full` only labels the archive, every backup is full; `--pre-upgrade` asks nothing and exits 3 when it makes no backup) |
| `events [--after N] [--limit N] [--json] \| key \| verify` | Signed event chain |
| `host enroll-script \| probe \| pin \| unpin \| keys \| test \| criticality \| clear \| list` | Enrollment, pins, criticality |
| `webauthn code \| list \| remove ID` | Security keys |
| `totp setup \| status \| remove \| finish-recovery` | TOTP recovery |
| `vault init \| status`, `secret set ID \| list \| rm ID` | Vault secrets |
| `version` | Version |

### 17.3 Risk classes

| Class | Approval |
| --- | --- |
| LOW | Within an open privileged session, issued automatically and logged; can be scheduled |
| MEDIUM | Security key per operation (user presence) |
| HIGH | Security key with user verification per operation (and per stage); hardened mode: only `nebula approve` |
| CRITICAL | As HIGH, plus typing the number of targets; hardened mode: only `nebula approve` |

The executor takes the highest of: the declared risk of a trusted script
(untrusted: at least HIGH), the Safety Scanner's findings, the host's
criticality on the executor (unrecorded hosts count as HIGH) and MEDIUM
for any run with secrets.

## 18. Limits you should know

- The security key signs a challenge, not the text you read in the
  browser. A fully compromised web server could show one operation and
  propose another; `nebula approve` on the machine shows what the executor
  will really run. See [`docs/threat-model.md`](../threat-model.md).
- While unlocked, keys and secrets are in the executor's memory. Root on
  the Nebula machine can take them and rewrite the event chain; offsite
  copies make that visible afterwards.
- On an attached timeout, a remote process can outlive the closed session
  (OpenSSH may ignore the signal); long work belongs in a durable job.
- Known gaps and their state: [`docs/implementation/m0.md`](../implementation/m0.md).
