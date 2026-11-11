# FAQ

Short answers with a link to the how-to or the admin guide section that has
the details. Each question is its own section.

## Why does the executor ask for unlock after every reboot?

The executor keeps the SSH keys and vault secrets **only in memory**, and
only while unlocked. Their passphrase is in no file and in no backup. After
a restart (reboot, upgrade, crash) it starts locked, and nothing runs until
an admin runs `nebula unlock` on the Nebula machine. No browser session can
unlock it; that is deliberate, so a compromised web server cannot bring the
keys back. Approved read leases resume after the unlock. See
[Unlock the executor](getting-started.md#unlock-the-executor).

## Can I unlock automatically at boot?

No. There is no option to store the passphrase or to unlock from the web
UI. Set up notifications (admin guide
[10.1](../admin/guide.md#101-notifications)): you get a message when the
executor is found locked after a restart.

## Where are secrets stored?

- **SSH keys** for managed hosts: `/var/lib/nebula/executor/keys/<ref>.key`,
  encrypted with your passphrase, readable only by `nebula-executor`.
- **Vault secrets** (runbook secrets, Proxmox tokens, network device
  credentials): in the executor's database `/var/lib/nebula/executor/executor.db`,
  encrypted, decrypted only inside the executor while unlocked.
- **Notification secrets and API token hashes**: `/etc/nebula/server.json`
  (mode 0640, `root:nebula-server`); the file keeps only each API token's
  SHA-256.
- **Passphrases** (key, vault) and the **age backup identity**: nowhere on
  the Nebula machine. Keep them in your password manager.

The web server holds no keys. See admin guide
[17.1](../admin/guide.md#171-users-files-and-directories).

## Do backups contain my secrets?

They contain the executor's database and the SSH key files **still
encrypted** with their passphrase, and the age-encrypted archive around
them. They never contain the passphrases, decrypted keys, plaintext secrets
or the event key. See [Back up Nebula](backup-restore.md#back-up-nebula).

## How do I enroll a host behind NetBird?

Make the Nebula machine a NetBird peer (outside Nebula). Then generate the
enrollment script with **both** source addresses, LAN and NetBird, for
example `nebula host enroll-script --from 192.168.0.10,100.64.0.10`, give
the host its LAN and NetBird endpoints in order of preference, and pin with
all of them: `nebula host pin --criticality MEDIUM web-01 192.168.0.21 100.64.0.21`.
Nebula falls back to the next endpoint on a TCP failure. See
[Enroll a host reachable over a VPN](hosts.md#enroll-a-host-reachable-over-a-vpn-netbird-wireguard-tailscale).

## Why does a VPN host fail to log in although the LAN works?

The key line on the host carries `from="…"` with the addresses you passed to
`--from`, and the sshd drop-in uses them too. If the NetBird or WireGuard
address of the Nebula machine was missing, logins over the VPN are refused.
Run the enrollment script again with the full `--from` list.

## Why is a finding "closed by Hermes, not confirmed by NOS"?

Hermes (the vulnerability agent) reported the finding as fixed, but Nebula
could not confirm it from its own inventory. Nebula never treats the agent's
word alone as proof: such findings have their own filter and are never
shown as clean. In this release Nebula cannot yet compare findings with its
own package data, so closures a run asks for are usually **held** for an
admin instead. See
[Understand finding states and labels](vulnerabilities.md#understand-finding-states-and-labels).

## Why are there no vulnerability findings although Hermes runs?

The inventory export is still empty in this release (snapshot ID
`nos-empty-<unix time>`, no subjects). Nebula therefore rejects every
finding with "subject not in the run's inventory snapshot". Runs complete,
but nothing is stored until the export carries the inventory (planned,
ADR 0011). See [Vulnerabilities](vulnerabilities.md#what-works-in-this-release).

## Can I accept a vulnerability risk or mark a false positive?

Not yet. The forms are shown to the maintainer, but submitting one fails
with "vulnerability decisions need an executor-verified security key
assertion, which this executor does not offer". The executor call that binds
a security key to such a decision is planned (ADR 0011).

## Does Nebula install fixes for vulnerabilities by itself?

No. Findings are advisory. "Fix with" links open the normal update forms
prefilled and never submit. Every fix needs the usual plan and approval.

## Why does even "Check updates" ask for my security key with PIN?

The action counts as HIGH because the built-in is not trusted yet (after
install or an upgrade) or the host has no criticality record on the
executor (unrecorded hosts count as HIGH). Run
`nebula artifact trust-builtins` and `nebula host criticality HOST LEVEL`.
With a privileged session open, LOW actions then run without a prompt.

## What is the difference between the inventory's criticality and `nebula host criticality`?

The inventory field is for display. Only the executor's record (set with
`nebula host pin --criticality` or `nebula host criticality`) decides how
strong an approval must be. The web server cannot lower it.

## What do LOW, MEDIUM, HIGH and CRITICAL mean for approvals?

LOW: runs within an open privileged session, can be scheduled. MEDIUM:
security key per operation. HIGH: security key with user verification (PIN)
per operation and per stage. CRITICAL: as HIGH, plus typing the number of
targets. In hardened mode HIGH and CRITICAL are approved only with
`nebula approve` on the machine. See admin guide
[17.3](../admin/guide.md#173-risk-classes).

## What is hardened mode and should I use it?

With the executor flag `-hardened`, HIGH and CRITICAL operations, stage
openings, read leases and batch rollouts are approved on the Nebula machine
(`nebula pending`, `nebula approve`, `nebula read-grant approve`,
`nebula batch approve`). The CLI shows what the executor will really run,
not what the web server claims. Use it when the web server may be exposed to
more people than you. See admin guide
[11](../admin/guide.md#11-operating-securely).

## The proposal page says `nebula lease approve`, but that command does not exist

Correct; the page prints the wrong name. Use
`nebula read-grant approve <digest>` with the same full digest
(`nebula read-grant pending` lists it).

## What happens if I lose my YubiKey?

If you registered a second key: log in with it, then remove the lost one
with `nebula webauthn remove ID` (see `nebula webauthn list`). This locks
the executor; run `nebula unlock`. If every key is lost: log in with TOTP
recovery, register a new key, and confirm with `nebula totp finish-recovery`
on the machine. That is why `nebula totp setup` is recommended.

## Can I use a passkey (Touch ID, Windows Hello) instead of a YubiKey?

Yes. Both hardware keys and passkeys work. Register at least two
authenticators.

## Can I change the hostname (RP ID) later?

Not without registering every security key again. The RP ID is fixed at
install (`--rp-id`); WebAuthn keys are bound to it. Choose it carefully.

## Why does the UI say "No release bundle is installed on this executor host"?

The directory `/usr/share/nebula/release` holds none of the signed release
attachments. That is normal for a source or quickstart install. Trust the
built-ins one by one with `nebula-server -export-actions DIR` and the
printed `nebula artifact trust …` commands. See admin guide
[8.2](../admin/guide.md#82-trusting-the-built-ins-together-after-an-upgrade).

## Does Nebula need an agent on managed hosts?

No. It logs in over SSH with the restricted `nebula` user that the
enrollment script creates. Managed hosts need OpenSSH, `sudo` and systemd.

## Which operating systems can Nebula manage?

Debian 12, Ubuntu 22.04 and 24.04, and Proxmox VE (patching uses
`full-upgrade` there). Durable jobs need `sudo -n` and systemd on the host.

## Is the `nebula` user on the host root?

Effectively yes, with the default sudo rule (NOPASSWD in
`/etc/sudoers.d/nebula`). Use `--no-sudo` at enrollment for read-only
hosts. Every run is still bound to a permit you approved.

## What happens to a running update if the Nebula machine restarts?

Updates run as durable jobs under systemd on the host. The executor never
runs anything twice: after the restart (and `nebula unlock`) it collects the
result. A staged rollout, however, ends with the restart.

## Can Nebula manage DHCP or DNS?

No. IPAM records networks, addresses and devices and computes each
address's status; it never changes DHCP or DNS.

## Why are some discovered hosts shown as POSSIBLE MATCH?

The address matches an asset, but there is no MAC to compare. That is
typical for VPN and routed networks, where Nmap cannot see MAC addresses.
Check and import by hand.

## Why does the traffic map show no process names?

`net.facts` runs `ss` without `-p`, so it needs no root and collects no
process names. A report that contains a process column is rejected as
invalid, so a compromised host cannot inject them.

## Can Nebula change VLANs or firewall rules on my switch or firewall?

Not in this release. Network devices can be registered (`nebula netdev`),
and even reading their data is still planned (ADR 0010). Changes are a
later phase that the maintainer decides on after phase 1 has run; anything
on Nebula's own management path stays refused.

## Why does my Cisco CBS switch session abort with a login prompt?

The switch asks for `User Name:` again inside the SSH session. Nebula never
answers prompts. Enable `ip ssh password-auth` (password login) or
`ip ssh pubkey-auth auto-login` (key login) so SSH authentication is the only
login. See [Avoid CBS auto-login and prompt pitfalls](network.md#avoid-cbs-auto-login-and-prompt-pitfalls).

## Is a Cisco CBS220 supported?

No. It has no SSH CLI. Keep it as an IPAM asset.

## Does Nebula change anything on Proxmox?

No, not in this release. The integration is read-only. Guest power,
snapshots and provisioning are not available yet (ADR 0006 phase 2, ADR
0008). See [Proxmox VE](proxmox.md).

## Why does the Proxmox page say "no approved read lease"?

Registering a remote is not enough; the executor answers collector reads
only under an approved lease. Click **Request read lease** on `/pve/<id>`
and approve it. After a token rotation or re-pin, use **Renew read lease**.

## Is there a one-step enrollment?

Coming. Today enrollment is the script, then the pin, then the test (see
[Hosts](hosts.md)).

## How do I give Home Assistant the host status?

Create a read-only token with
`nebula-server -api-token homeassistant:inventory.read`, add the printed
entry to `server.json` under `"api"`, restart `nebula-server`, and query
`GET /api/v1/hosts/{id}` with `Authorization: Bearer <token>`. See admin
guide [10.2](../admin/guide.md#102-read-only-api-home-assistant-status-pages).

## How do I check that nobody rewrote the history?

Note the fingerprint from `nebula events key` outside the machine after
install. Then run `nebula events verify` now and then, compare the key with
the *History* page, and copy `nebula events list --json` offsite weekly.
See admin guide [10.3](../admin/guide.md#103-history-and-events).

## Who can be an admin, and how do I remove one?

Admins are the logins in the executor's `-admin-users` (set by
`install.sh --admin-users`). Membership in `nebula-rpc` only lets a user
reach the socket. When someone leaves, remove them from both, then restart
the executor and run `nebula unlock`.

## How do I uninstall Nebula?

Tarball: `sudo ./deploy/uninstall.sh`; package:
`sudo apt remove nebula-operation-station`; containers:
`docker compose down` (add `-v` to delete all keys and data). Data, users
and configuration are kept until you remove them. Release each managed host
as in [Remove a host from Nebula](hosts.md#remove-a-host-from-nebula). See
admin guide [16](../admin/guide.md#16-uninstalling).
