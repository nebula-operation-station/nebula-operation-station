# Operator guide (Release 0.1)

Release 0.1 does one thing: **safe patching of Debian and Ubuntu hosts**
from a web UI, with every privileged step approved by a security key. This
guide takes you from a fresh machine to the first approved update run.

What 0.1 covers: inventory (manual, CSV import), SSH enrollment with host
key pinning, update checks, installing security or all updates (durable
jobs with pre- and postchecks), reboots that wait for the host, service
status and restart, Ops State per host, notifications (webhook, ntfy,
Telegram), listing Docker containers. Not in 0.1: stages and canaries,
runbooks and modules, Docker actions beyond listing,
IPAM, scheduled checks, packages (APT/containers).

## 1. Before you start

- **The Nebula machine.** A small VM or host running Debian 12 (Ubuntu
  22.04/24.04 work too), used for nothing else. It will hold SSH keys
  that are root on every managed host: keep it patched, give it encrypted
  or no swap, and restrict who can log in.
- **A hostname and TLS.** The UI must be served over HTTPS under one fixed
  hostname, the WebAuthn *RP ID* (for example `nebula.lab.example.org`).
  You need a reverse proxy with a certificate for it (section 3).
- **Security keys.** At least one FIDO2 key with a PIN (user
  verification), better two (the second one is your backup).
- **An admin account** on the Nebula machine for each person who unlocks
  and approves (a normal login, not root).

## 2. Install

From the extracted release tarball:

```
sudo ./deploy/install.sh --admin-users alice --rp-id nebula.lab.example.org
```

This creates the system users `nebula-executor` and `nebula-server`, the
group `nebula-rpc` (your admin users join it; log out and in again), the
data directories under `/var/lib/nebula`, both systemd units and
`/etc/nebula/server.json`. It is idempotent: run it again with a newer
tarball to upgrade; it never overwrites your edited unit files or
`server.json`.

Create the SSH key Nebula uses for managed hosts, with a long passphrase
from your password manager:

```
sudo -u nebula-executor ssh-keygen -t ed25519 -C nebula-default \
  -f /var/lib/nebula/executor/keys/nebula-default.key
```

Then:

```
nebula status        # executor running, locked
nebula unlock        # asks for the key passphrase
nebula vault init    # optional; the same passphrase is recommended
```

**After every reboot of the Nebula machine** the executor starts locked:
nothing runs until an admin runs `nebula unlock` on the machine. If
notifications are set up, you get a message that the executor is locked.

## 3. Reverse proxy

`nebula-server` listens on `127.0.0.1:8080`. Put a TLS proxy in front
that serves exactly `https://<rp-id>` and passes the request unchanged
(including the `Origin` header; state-changing requests with another
origin are refused).

Caddy:

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
        client_max_body_size 1m;
    }
}
```

Do not expose port 8080 itself. `public_origin` in
`/etc/nebula/server.json` must be `https://<rp-id>` (the installer sets
it).

## 4. First login

1. On the Nebula machine: `nebula webauthn code` prints a one-time code.
2. Open `https://<rp-id>/setup`, enter the code, register your first
   security key.
3. Log in at `https://<rp-id>/login`. Register the backup key the same
   way; a further key must be confirmed with an already registered one.
4. Optional but recommended: `nebula totp setup` on the machine. TOTP lets
   you log in if every key is lost; Nebula then forces a new key
   registration, which you confirm on the machine with
   `nebula totp finish-recovery`.

## 5. Add and enroll hosts

Add hosts in **Inventory** (one by one or **Import CSV**). A host has an ID,
endpoints (LAN and VPN addresses; Nebula tries them in order and falls
back on TCP failure), environment and criticality.

Enrolling a host gives Nebula a restricted login on it and pins its SSH
host key:

```
nebula host enroll-script --from 192.168.0.10,100.64.0.10 > enroll.sh
```

`--from` lists the addresses the Nebula machine connects *from*. The
script creates a `nebula` user, installs Nebula's public key limited to
those addresses (no forwarding), adds a NOPASSWD sudo rule (checked with
`visudo`; this makes the `nebula` user effectively root, as documented in
the spec) and a cleanup rule for old job directories. **Read it**, copy it
to the host and run it there as root. If you use fail2ban, add the Nebula
addresses to `ignoreip` (as IPs, not hostnames).

Then pin the host keys. Compare every fingerprint with
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
their criticality on the executor host (below).

**On the executor host (one host, or from a `known_hosts` file you trust
with `--known-hosts`):**

```
nebula host pin --criticality HIGH web-01 192.168.0.21 100.64.0.21
nebula host test web-01 192.168.0.21
```

The criticality set on the executor (`nebula host pin --criticality` or
`nebula host criticality HOST LEVEL`) is the one the executor uses to
decide how strong an approval must be; the inventory's value is only for
display.

**Changed host key.** If a host presents another key (reinstall, or an
attack), Nebula stops using it, shows it on the dashboard and notifies.
Check the new key on the host's console, then press **Re-pin…** next to
the host on the dashboard: it shows the pinned and the presented key,
asks you to confirm the comparison and needs your security key with user
verification. Nebula reads the key again before it pins it; the host's
criticality stays. On the executor host the same is
`nebula host unpin web-01`, then `nebula host pin` again.

## 6. Trust the built-in actions (recommended)

The executor treats any script it does not know as at least HIGH. To run
the built-in actions at their declared risk (check updates LOW, install
MEDIUM, reboot HIGH), read and trust them once per release:

```
nebula-server -export-actions /tmp/nebula-actions   # writes the scripts and prints the trust commands
less /tmp/nebula-actions/*.sh
# then run the printed `nebula artifact trust ...` commands
```

Without this, every operation needs a user-verified approval.

## 7. Patch

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
it collects the result afterwards. A host that could not be reached uses
up the approval for that host: plan the operation again.

**Services:** List services, Service status (unit plus last journal lines)
and Restart/Start/Stop/Reload take a unit name such as `nginx.service`.

**Docker:** List containers shows every container with image, state,
health, published ports and its Compose project, and says when a host has
no Docker. It reads through the `docker` group if the SSH user is in it,
otherwise through `sudo -n`; both are root on the host. Nothing is
started, stopped or updated.

## 8. Notifications

Add a `notifications` block to `/etc/nebula/server.json`, keep the file
`0640 root:nebula-server`, restart `nebula-server` and test with
`nebula-server -config /etc/nebula/server.json -notify-test`:

```json
"notifications": {
  "webhook":  {"url": "https://hooks.example.org/nebula", "secret": "<at least 32 random characters>"},
  "ntfy":     {"url": "https://ntfy.sh", "topic": "<random topic>", "token": "<optional>"},
  "telegram": {"bot_token": "<123456:ABC...>", "chat_id": "<chat id>"}
}
```

You are notified about: a changed host key, an Ops State change (worse or
recovered), an operation that finished with failed hosts, and the executor
found locked after a restart. Messages never contain host output.

## 9. Read-only API (Home Assistant, status pages)

The API is off by default. Create a token on the Nebula machine:

```
nebula-server -api-token homeassistant:inventory.read
```

It prints the token once and a JSON entry. Add the entry to `server.json`
under `"api": {"enabled": true, "tokens": [ ... ]}` (the file keeps only the
token's hash) and restart `nebula-server`. Clients send
`Authorization: Bearer <token>`:

| Scope | Endpoints |
| --- | --- |
| `inventory.read` | `GET /api/v1/hosts`, `GET /api/v1/hosts/{id}`: Ops State, update counts, reboot required |
| `operations.read` | `GET /api/v1/operations`, `GET /api/v1/operations/{id}`: action, state, result classes |
| `execution_logs.read` | adds host output (result, log) to `/operations/{id}`; give it only where needed |

The API cannot change anything. To revoke a token, remove its entry and
restart.

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

## 10. Day-to-day

| Situation | What to do |
| --- | --- |
| Nebula machine rebooted | `nebula unlock` |
| Leaving the UI | Dashboard → **Lock** (or `nebula lock`): wipes keys, ends the session, revokes permits |
| A host key changed | Compare on the host console, then dashboard → **Re-pin…** |
| A security key is lost | `nebula webauthn list`, `nebula webauthn remove ID` (locks the executor) |
| Operation shows `precheck_failed` | Read the reason on the operation page; nothing was installed |
| Host `UNREACHABLE` | Check the endpoints; `nebula host test HOST ENDPOINT` |
| Upgrade Nebula | Run `install.sh` from the new tarball, then `nebula unlock`; re-trust the actions if their version changed |

**Backups.** `/var/lib/nebula/executor` holds the encrypted SSH keys,
pins, credentials and the vault; `/var/lib/nebula/server` the inventory
and history. The executor keeps an exclusive lock on its database: back it
up with the executor stopped (`systemctl stop nebula-executor`), and keep
the key passphrase in your password manager. Restore before Release 0.9
is manual.

## Limits you should know

- The security key signs a challenge, not the text you read in the
  browser. A fully compromised web server could show one operation and
  propose another; `nebula approve` on the machine shows what the executor
  will really run. See `docs/threat-model.md`.
- While unlocked, keys and secrets are in the executor's memory.
- Known gaps and their milestones: `docs/implementation/m0.md`.
