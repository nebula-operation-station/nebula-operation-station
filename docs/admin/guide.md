# Operator guide (Release 0.1)

Release 0.1 does one thing: **safe patching of Debian and Ubuntu hosts**
from a web UI, with every privileged step approved by a security key. This
guide takes you from a fresh machine to the first approved update run.

What 0.1 covers: inventory (manual, CSV import), SSH enrollment with host
key pinning, update checks, installing security or all updates (durable
jobs with pre- and postchecks), reboots that wait for the host, service
status and restart, Ops State per host, notifications (webhook, ntfy,
Telegram), Docker (list, logs, details, start/stop/restart, image update
check, Compose update), rollouts in stages (canary, waves, DEV → QA →
PROD), scheduled read-only checks, runbooks (your own scripts). Not in 0.1:
modules, IPAM, packages (APT/containers).

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

This creates the system users `nebula-executor`, `nebula-server` and
`nebula-discovery`, the group `nebula-rpc` (your admin users join it; log
out and in again), the data directories under `/var/lib/nebula`, the
systemd units and `/etc/nebula/server.json`. For network discovery also
install Nmap (`sudo apt install nmap`); without it scans fail with a clear
message and everything else works. It is idempotent: run it again with a newer
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

The executor also runs the **Safety Scanner** over every script, trusted
or not: downloading and executing, `eval` or encoded payloads, destructive
disk commands and bootloader changes make a script at least HIGH; users
and groups, firewall and network changes, package removal, reboots and
Docker removals at least MEDIUM. The scanner only ever raises the risk, and
a clean scan proves nothing. The planning and operation pages show its
findings.

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
it collects the result afterwards. If no endpoint of a host answered
(`network_unreachable`: nothing was sent, nothing ran), read-only actions
are retried automatically after 20 seconds and after 1 minute with the
same approval; other actions report the host as unreachable, and you plan
the operation again. A host that was reached uses up the approval for that
host, whatever the result.

**Rollouts in stages.** Under *Rollout* on the planning page you choose
how the hosts run: all at once (the default), *canary first* (the first N
hosts alone, the rest only after them), *in waves* of N hosts, or *DEV → QA
→ PROD* by the inventory environment. Each stage allows a number of failed
and of unreachable hosts (a canary allows none); a stage with more failed
hosts stops the rollout for good, and the hosts after it do not run. After
a stage passed, the rollout waits for you ("Continue to stage N") or, for a
LOW or MEDIUM operation, continues by itself if you chose so. The stages
are part of what you approve: the executor enforces them, not the web
server. Opening a stage of a HIGH or CRITICAL operation needs your security
key again (in hardened mode `nebula approve --stage N <digest>` on the
executor host). A host that could not be reached can be retried or skipped
(skipping needs the same approval as opening a stage); *Abort rollout*
stops every host that has not run. A restart of the executor ends the
rollout like any approval.

**Services:** List services, Service status (unit plus last journal lines)
and Restart/Start/Stop/Reload take a unit name such as `nginx.service`.

**Docker:** List containers shows every container with image, state,
health, published ports and its Compose project, and says when a host has
no Docker. Container logs takes a container name or ID and shows its
state and last 100 log lines; Container details shows its image and
repository digest, state, health, restart policy, mounts, published ports
and networks (never its environment, command line or labels, which often
hold secrets). All three read through the `docker` group if the
SSH user is in it, otherwise through `sudo -n`; both are root on the host.
These three only read. Start, Stop and Restart container (MEDIUM) run
`docker start|stop|restart` of one container and show its state before
and after; nothing is recreated, pulled or updated, and they are never
retried automatically. Check image updates (LOW) asks each registry, from
the host, for the current digest of every running container's image tag
(a manifest HEAD request: anonymous, nothing is pulled, Docker Hub pull
limits are not used) and lists the images with an update available; it
needs curl and HTTPS from the host to the registries. Private registries
that need credentials show as "unknown". Update Compose project (MEDIUM, a durable job) takes the
project name, finds its working directory and files from the container
labels, runs `docker compose pull` and then `docker compose up -d`, and
compares the containers before and after: fewer running containers, a
failed command or a container that was healthy and is not anymore is
FAILED; a container that is not healthy, changed published ports or a
different number of containers is a WARNING. Run Check image updates
first to see what will change.

**Scheduled checks.** *Operations → Scheduled checks* lets Nebula run
read-only checks on its own, for example a daily update check on all
hosts. You choose actions, hosts, an interval (hour, 6 hours, day, week)
and a duration (at most 90 days), and approve the schedule once with your
security key (hardened mode: `nebula schedule approve <digest>` on the
executor host). The executor accepts only actions it rates LOW on every
chosen host: the built-in script trusted as LOW (section 6) and the host
recorded with a criticality (`nebula host pin --criticality`). It runs
each action on each host at most once per interval and checks the trust
again on every run; *Revoke* (or `nebula schedule revoke <id>`) stops a
schedule at once. Results appear as operations created by "schedule" and
update the inventory like any run. A schedule survives restarts of the
executor, but nothing runs while it is locked.

**Runbooks.** *Runbooks → New runbook* holds your own scripts (POSIX
`sh`). A runbook has a name (its action becomes `runbook.<name>`), a
declared risk, a timeout, attached or durable, and typed parameters:
`name` (letters, digits and `_.@:-`, not starting with `-`), `int`,
`path` (absolute) or `choice` (fixed words). The script reads them as
`$NEBULA_P_<NAME>`; before it starts, the host checks every value again
with the same pattern. Its output goes to the operation log. An attached
runbook runs as the SSH user and calls `sudo -n` where it needs root; a
durable one runs as root under systemd. Saving creates a new version;
versions never change, and an operation always runs the version it was
planned with. The executor does not know your script, so a runbook is
HIGH (security key each time) until you trust that exact version on the
executor host with the command shown on its page (download the script,
read it, then `nebula artifact trust …`), or with *Trust this version*
on the runbook page and your security key (standard mode only); the
Safety Scanner can raise it further. Scripts with control characters or invisible formatting
characters (such as bidi overrides) are refused, so what you review is
what runs.

**Secrets in runbooks.** Store a secret in the executor's vault
(`nebula secret set <id>` on the executor host), declare a secret slot in
the runbook (for example `influx_token`) and name the vault secret when
you plan the operation. The executor reads the value and sends it to the
host only: an attached run keeps it in a private file under the SSH
user's runtime directory (`$XDG_RUNTIME_DIR`, a tmpfs; without one, make
the runbook durable), a durable job under `/run/nebula/<execution>/`, and
both remove it when the script ends. The script reads the value from the
file `$NEBULA_SECRET_<SLOT>`. A run with secrets is at least MEDIUM, cannot
be scheduled, and known secret values are removed from its log and
result (a safeguard, not the protection).

**Module signers.** Modules signed by someone you trust run at their
declared risk. Get the author's public key (`ssh-ed25519 …`) and its
fingerprint on two different channels, then on the executor host:
`nebula signer add --name "Who" key.pub` and type the fingerprint to
confirm (CRITICAL: every module this key signs is trusted). `nebula signer
list` shows them; `nebula signer remove SHA256:…` withdraws a key and the
trust of every module it signed. If a new version of a module is signed by
another key, Nebula refuses it until you have checked why and run
`nebula module confirm-signer MODULE SHA256:…` (it shows the current and the new
signer and asks you to type the new fingerprint). Unsigned modules always
need your security key (at least HIGH).

**Modules.** A module bundles actions others wrote. Its author keeps a
`module.yaml` (name, version, title, actions with script, risk, timeout,
parameters, secret slots, declarations) and the scripts, runs
`nebula module pack DIR`, signs the printed lock with
`ssh-keygen -Y sign -f KEY -n nebula-module DIR/module.lock.json` and
builds the archive with `nebula module pack --archive OUT.tar.gz DIR`.
Import it under *Runbooks → Modules*. The page shows whether the executor
verified it and every script it runs; plan its actions like any other.
A module may also show a tab on each host's page (click the host in the
inventory) with values from its actions' latest results; scripts write
their result as one JSON object to the file `$NEBULA_RESULT` (runbooks
can too).

**Network.** Under *Network* you keep your networks (prefix, VLAN,
gateway, pools such as `servers 192.168.10.10-192.168.10.49`) and the
devices in them (*assets*: NAS, printer, switch, …, managed or not).
Nebula computes each address's status from what claims it: an asset or a
managed host's IP endpoint (ASSIGNED), your reservation (RESERVED), your
exclusion and the network and broadcast address (EXCLUDED), a discovery
sighting nobody claims (DISCOVERED), or two claimants or a different MAC
(CONFLICT). Networks up to /22 show every address as a grid; larger ones
and IPv6 list only the addresses something claims. The network page
suggests free addresses (of the whole network or one pool) that discovery
has not seen in 30 days: a suggestion, not a guarantee, because a device
may be switched off. Nebula never manages DHCP or DNS. **Add to managed
hosts** on an asset opens the inventory form with its values and links
the new host to the asset; enroll it as in section 5.

**Discovery.** *Network → Discovery* scans known networks with Nmap:
host discovery, selected ports, service discovery (top 100 ports with
versions), all TCP ports, or a custom scan from a fixed set of options
(no free-form Nmap arguments). Targets must lie inside a network you
added, at most a /16 each. Queue a scan now, once at a time, or every N
hours (at least one); there is no default schedule. The scan runs in the
separate `nebula-discovery` service (raw sockets only, no credentials, no
database), started when a job is queued. Its results land in staging:
each host is NEW, EXISTING (same MAC as an asset), POSSIBLE MATCH (same
address, but no MAC to compare, as across VPNs and routed networks) or
CONFLICT (the MAC or address belongs to another asset). Select the hosts
and import them: a new host becomes an asset (kind unknown; set its kind
afterwards), an existing one gets the address, MAC or hostname it lacks.
Conflicts are never imported. Every host seen also feeds the address
status (DISCOVERED, or CONFLICT for a different MAC). Names and banners
come from the network and may lie.

**Search.** The search box in the navigation finds hosts (ID, name,
endpoint, tag `key=value`, group), assets (name, hostname, MAC,
address), networks (name, prefix, `vlan 10`), an address with its status,
executions (ID prefix, at least 4 characters, or action), runbooks and
modules. Quick actions (*Plan an operation* for a host, *Plan* for a
runbook, *Add to managed hosts* for an asset) only open the page that
does the work; nothing runs without the usual review and approval.

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

**History and events.** Every security-relevant step of the executor
(unlock, logins, approvals, runs, trust, signers, host keys, vault) is
recorded as an event, signed with the executor's event key and chained to
the one before, so a changed, reordered or missing event shows. Note the
key's fingerprint after installing (`nebula events key`) and compare it
with the one on the *History* page now and then. `nebula events verify`
checks the whole chain on the Nebula machine; `nebula events list --json`
writes the events with hashes and signatures for an offsite copy. The
*History* page also lists what was done in the web UI (the server's audit
lines); set `"audit_hash_chain": true` in `server.json` to chain those too.

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

**Backups.** Once, on a machine you keep safe (not the Nebula machine):
`age-keygen -o nebula-backup.key`, and put the printed public key
(`age1…`) into `/etc/nebula/backup-recipients` on the Nebula machine.
Then `sudo nebula backup` writes an encrypted archive to
`~/nebula-backups/` while everything keeps running: the inventory,
history and configuration, the executor's database and the SSH key files
(still protected by their passphrase). The passphrase, decrypted keys and
secrets are never in a backup, so keep the passphrase in your password
manager. Copy the archives off the machine, for example with
`restic backup ~/nebula-backups`. `install.sh` makes one before every
upgrade. To restore (on the same or a new machine, after `install.sh`):
`sudo nebula restore --identity nebula-backup.key FILE`, type `restore`,
then `nebula unlock`. Your previous data is kept next to it
(`*.pre-restore-<time>`), and the backup's `server.json` lands in
`/etc/nebula/from-backup-<time>/` for you to compare; it is not applied.

## Limits you should know

- The security key signs a challenge, not the text you read in the
  browser. A fully compromised web server could show one operation and
  propose another; `nebula approve` on the machine shows what the executor
  will really run. See `docs/threat-model.md`.
- While unlocked, keys and secrets are in the executor's memory.
- Known gaps and their milestones: `docs/implementation/m0.md`.
