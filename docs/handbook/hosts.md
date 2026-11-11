# Hosts

Adding managed hosts and giving Nebula a pinned, restricted SSH login to
them. Reference: admin guide [7](../admin/guide.md#7-adding-and-enrolling-hosts)
and [17.2](../admin/guide.md#172-the-nebula-cli).

Enrolling a host takes four steps: add it to the inventory, run the
enrollment script on it, pin its host key, test the login.

## Add a host to the inventory

**Goal:** the host appears in the inventory with its endpoints.

**Prerequisites:** logged in to the web UI.

**Steps:**

1. *Inventory* (`/inventory`) → **Add host** (`/inventory/new`).
2. Fill in the ID (for example `web-01`), the endpoints in the order Nebula
   should try them, the environment (DEV, QA or PROD, used by staged
   rollouts), the criticality, tags and groups.
3. Save.

An endpoint is an IP address or DNS name, optionally with a port:
`192.168.0.21`, `web-01.lan:2222`, `[fd00::21]:22`. List several endpoints
(for example LAN first, then VPN) and Nebula falls back to the next one on a
TCP failure.

**Expected result:** the host is listed under *Inventory*, without a pinned
key yet.

**Note:** the criticality in the inventory form is for display. The one that
decides how strong an approval must be is set on the executor (see
[Set the host's criticality](#set-the-hosts-criticality-on-the-executor)).

## Import many hosts from a CSV file

**Goal:** add many hosts at once.

**Prerequisites:** a UTF-8 CSV file with a header row.

**Steps:**

1. *Inventory → Import CSV* (`/inventory/import`).
2. Upload the file and map its columns to the fields `id`, `display_name`,
   `environment`, `criticality`, `tags` and `endpoint1` … `endpoint16`.
3. Check the preview: every row with an error is shown with its problems and
   is not imported.
4. **Import selected rows**.

**Limits:** at most 5 MiB, 10,000 data rows, 64 columns, 1 KiB per cell and
16 endpoints per host. A larger file is refused, never truncated.

**Expected result:** the valid rows appear in the inventory. Enroll them as
below.

## Run the enrollment script on a new host

**Goal:** the host has a restricted `nebula` user with the executor's public
key and a sudo rule.

**Prerequisites:**

- The host runs Debian 12, Ubuntu 22.04/24.04 or Proxmox VE, with OpenSSH,
  `sudo` and systemd.
- You know the addresses the Nebula machine connects **from** (LAN address,
  VPN address, …).
- Executor running and unlocked (the CLI asks the executor for the
  credential's public key and embeds it in the script).

**Steps:**

1. On the Nebula machine:

   ```
   nebula host enroll-script --from 192.168.0.10,100.64.0.10 > enroll.sh
   ```

   Options: `--user NAME` (default `nebula`), `--key REF` (default
   `nebula-default`), `--no-sudo` (no sudo rule: only read-only actions
   work).
2. **Read the script.**
3. Copy it to the host and run it there as root, for example
   `sudo sh enroll.sh`.

**What it does on the host:** creates the user, installs the key with
`from="…",no-agent-forwarding,no-port-forwarding,no-X11-forwarding`, adds
`/etc/sudoers.d/nebula` (NOPASSWD, checked with `visudo`; this makes the
user effectively root) and `/etc/tmpfiles.d/nebula.conf`. If sshd uses
`AllowUsers` or `AllowGroups`, it adds `/etc/ssh/sshd_config.d/10-nebula.conf`
and reloads sshd after `sshd -t`. Details: admin guide
[7.1](../admin/guide.md#71-the-enrollment-script).

**Expected result:** the script finishes without errors; `id nebula` works
on the host.

**Common errors:**

- The script reports a `Match` block, a `DenyUsers`/`DenyGroups` entry or a
  missing `Include` for `sshd_config.d`: add the printed line yourself.
- fail2ban bans the Nebula machine later: add its addresses (as IPs) to
  `ignoreip` on the host.

**Coming:** a one-step enrollment that combines the script, the key pin and
the test is planned. It is not in this release; use the steps on this page.

## Pin host keys for many hosts in the web UI

**Goal:** the executor knows each host's SSH host key, so a machine in
between is detected.

**Prerequisites:** the enrollment script ran on the hosts; an open
privileged session; access to each host's console to compare fingerprints.

**Steps:**

1. On each host's console:
   `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`.
2. *Inventory → Enroll hosts* (`/inventory/enroll`) lists hosts without a
   pinned key.
3. Select hosts, choose the endpoint and SSH user, **Read host keys**. The
   executor connects and shows the key it got (no credential is sent).
4. Compare each fingerprint with the console output, tick the confirmation
   and **Enroll with security key**.

**Expected result:** the table shows each host pinned and whether the test
login worked (that tells you whether the enrollment script ran).

**Note:** hosts pinned this way count as HIGH until you set their
criticality on the executor (next sections).

## Pin a host key on the command line

**Goal:** pin one host from the Nebula machine, and optionally set its
criticality in the same step.

**Prerequisites:** the enrollment script ran; you compared the fingerprint
on the host's console.

**Steps:**

```
nebula host probe 192.168.0.21                 # shows the key, sends no credential
nebula host pin --criticality MEDIUM web-01 192.168.0.21 100.64.0.21
```

Other options of `host pin`: `--user U` (default `nebula`), `--key REF`
(default `nebula-default`), `--known-hosts FILE` (take the key from a
`known_hosts` file you trust instead of probing).

**Expected result:** `nebula host keys` lists the pin; `nebula host list`
shows the criticality record.

## Test the login to a host

**Goal:** confirm that Nebula can log in with its key.

**Prerequisites:** host pinned; executor unlocked.

**Steps:**

```
nebula host test web-01 192.168.0.21
```

**Expected result:** the login succeeds. Run *Check updates* on the host
next (see [Patching and services](patching-and-services.md)) to fill in
its update status.

**Common errors:** authentication fails when the enrollment script did not
run, `--from` did not include the address Nebula connects from, or sshd's
`AllowUsers`/`AllowGroups` still excludes the user. A
`network_unreachable` result means no endpoint answered; check routing and
the host firewall.

## Set the host's criticality on the executor

**Goal:** the executor applies the right minimum risk for this host.

**Prerequisites:** host pinned.

**Steps:**

```
nebula host criticality web-01 MEDIUM
nebula host list
```

The level is `LOW`, `MEDIUM`, `HIGH` or `CRITICAL`. You can also bind it to
a specific key: `nebula host criticality HOST SHA256:FINGERPRINT LEVEL`.

**Expected result:** `nebula host list` shows the record.

**Why it matters:** the executor takes the highest of the script's risk, the
Safety Scanner's findings and the host's criticality. A host without a
record counts as **HIGH**, so every action on it needs a security key with
user verification, and scheduled checks (which accept only LOW) are refused.
See admin guide [17.3](../admin/guide.md#173-risk-classes).

## Re-pin a host whose key changed

**Goal:** get a host that was reinstalled back into service, without
accepting an attacker's key.

**Prerequisites:** console access to the host; your security key.

**Steps:**

1. On the host's console:
   `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`.
2. Dashboard → **Re-pin…** next to the blocked host. It shows the pinned
   and the presented key.
3. Compare, confirm the comparison and **Re-pin with security key** (user
   verification).

On the command line instead: `nebula host unpin web-01`, then
`nebula host pin …` again.

**Expected result:** the host is unblocked; its criticality is kept (web
UI way).

**Never** re-pin without comparing on the console: a changed key is
exactly what a machine in between looks like.

## Enroll a host reachable over a VPN (NetBird, WireGuard, Tailscale)

**Goal:** manage a host that Nebula reaches only, or also, through a VPN.

**Prerequisites:** the Nebula machine is itself a member of the VPN (set up
outside Nebula) and has a VPN address, for example `100.64.0.10`.

**Steps:**

1. Generate the script with **every** source address the Nebula machine may
   use, LAN and VPN:
   `nebula host enroll-script --from 192.168.0.10,100.64.0.10 > enroll.sh`.
2. Run it on the host as root.
3. In the inventory, give the host its endpoints in order of preference,
   for example `192.168.0.21` then `100.64.0.21`.
4. Pin with all endpoints:
   `nebula host pin --criticality MEDIUM web-01 192.168.0.21 100.64.0.21`.
5. Test each endpoint: `nebula host test web-01 100.64.0.21`.

**Expected result:** the host works over either path; Nebula falls back to
the VPN endpoint when the LAN endpoint does not answer.

**Common errors:** the login is refused over the VPN because the VPN source
address was missing from `--from` (the key's `from="…"` restriction and
the sshd drop-in use it). Run the enrollment script again with the full
list.

## Remove a host from Nebula

**Goal:** Nebula no longer has access to the host.

**Steps:**

1. On the host, remove the `nebula` user's key line from
   `~nebula/.ssh/authorized_keys` (or the user: `userdel -r nebula`),
   `/etc/sudoers.d/nebula`, `/etc/tmpfiles.d/nebula.conf`,
   `/var/lib/nebula/jobs` and, if the enrollment added it,
   `/etc/ssh/sshd_config.d/10-nebula.conf` (then reload sshd).
2. On the Nebula machine:

   ```
   nebula host unpin web-01
   nebula host clear web-01
   ```

3. Delete the host in the inventory (host page → **Delete host**).

**Expected result:** `nebula host keys` and `nebula host list` no longer
show the host. Read leases that covered it stop running for it.
