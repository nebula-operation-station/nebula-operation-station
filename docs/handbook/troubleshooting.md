# Troubleshooting

Symptom first, then the fix. The complete error table is in admin guide
[15](../admin/guide.md#15-troubleshooting); logs and state in
[14](../admin/guide.md#14-monitoring-and-logs).

Three commands answer most questions:

```
nebula status
systemctl status nebula-executor nebula-server nebula-discovery.path nebula-discovery.timer
journalctl -u nebula-executor -u nebula-server -u nebula-discovery
```

## Nothing runs after a reboot or upgrade

**Symptom:** operations stay pending or fail; the dashboard says the
executor is locked; you got a "found locked after a restart" notification.

**Cause:** the executor always starts locked. The SSH keys and the vault are
only in memory after an admin unlocks on the machine.

**Fix:** `nebula unlock` on the Nebula machine. Approved read leases resume;
pending proposals from before the restart were discarded and must be
planned again.

## `nebula` says permission denied or "peer UID holds no role"

**Symptom:** `nebula: … permission denied` on the socket, or
`peercred: peer UID holds no role`.

**Cause:** your login is not in the group `nebula-rpc` yet, or not in the
executor's `-admin-users`.

**Fix:** log out and in again after `install.sh`; check `id`. To add an
admin, run `install.sh` again with the full `--admin-users` list (or edit
your `20-local.conf`, admin guide
[6.2](../admin/guide.md#62-executor-flags)).

## `nebula: this needs a terminal`

**Cause:** `unlock` and other passphrase prompts read from a terminal, never
from a pipe.

**Fix:** run the command in an interactive shell. In containers use
`docker compose exec -u nebula-admin executor nebula unlock` without `-T`.

## Unlock fails because of a key file

**Symptom:** `keyring: … is not passphrase-protected`, `has mode …`,
`is owned by uid …`, or a wrong passphrase.

**Fix:** every file in `/var/lib/nebula/executor/keys/` must be OpenSSH
format with a passphrase, mode 0600, owned by `nebula-executor`, and all of
them must share one passphrase. Convert an old PEM key with
`ssh-keygen -p -o -f FILE`.

## Login or approval fails in the browser

**Symptom:** the security key prompt fails or the request is refused.

**Cause:** you are not on exactly `https://<rp-id>`, or the reverse proxy
changes `Host` or `Origin`.

**Fix:** use the RP ID address; check the proxy passes headers unchanged and
that `public_origin` in `/etc/nebula/server.json` is `https://<rp-id>`.

## The server does not start

**Symptom:** `serverconfig: invalid config: …` or
`… contains notification secrets and is readable or writable by others`.

**Fix:** the first message lists every problem (lowercase `https://`
origin without a path, absolute paths, unknown keys, …); fix them all. For
the second: `sudo chmod o-rwx /etc/nebula/server.json`. Key reference:
admin guide [6.1](../admin/guide.md#61-etcnebulaserverjson).

## A host is UNREACHABLE or the result is `network_unreachable`

**Cause:** no endpoint of the host answered; nothing was sent.

**Fix:** check the endpoints in the inventory, routing (VPN up?) and the
host firewall, then `nebula host test HOST ENDPOINT`. Read-only actions are
retried automatically after 20 seconds and 1 minute; plan other actions
again. If fail2ban runs on the host, add the Nebula machine's IPs to
`ignoreip`.

## A host is blocked after a host-key change

**Cause:** the host presented another SSH host key (reinstall, or an
attack).

**Fix:** compare the new fingerprint on the host's console
(`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`), then dashboard →
**Re-pin…**. See [Hosts](hosts.md#re-pin-a-host-whose-key-changed). Never
re-pin without the console comparison.

## An update fails with `precheck_failed`

**Cause:** a precheck failed and nothing was installed: disk space on `/` or
`/var`, broken `dpkg` state, apt lock held by another apt run, or a
read-only disk.

**Fix:** read the reason on the operation page, fix it on the host, plan
again.

## A reboot ends with `host_not_returned`

**Cause:** the host did not come back with a new boot ID within 20 minutes.

**Fix:** check its console (stuck fsck, boot loader, network).

## Every action asks for a security key with user verification

**Cause:** the action counts as HIGH: the script is not trusted (built-ins
not trusted after install or upgrade), the host has no criticality record
on the executor, or the Safety Scanner raised it.

**Fix:** `nebula artifact trust-builtins` (or per action
`nebula artifact trust`), and `nebula host criticality HOST LEVEL`. See
admin guide [17.3](../admin/guide.md#173-risk-classes).

## A read lease or schedule is refused

**Cause:** the executor accepts only actions it rates LOW on every chosen
host and that are on the read allowlist.

**Fix:** trust the built-in at LOW and record each host's criticality
(`nebula host pin --criticality` or `nebula host criticality`).
`package.refresh`, `docker.logs` and actions with secrets can never be
leased.

## A runbook with secrets fails with `vault_locked` or `secret_unavailable`

**Fix:** `vault_locked`: `nebula unlock` (the vault opens with the keys).
`secret_unavailable: no vault secret …`: `nebula secret list`, then
`nebula secret set ID` or choose another secret.

## Docker actions say "no Docker" or fail with permissions

**Cause:** Docker is missing, or the SSH user is neither in the `docker`
group nor allowed `sudo -n`.

**Fix:** install Docker, or enroll the host with sudo (without `--no-sudo`).

## Discovery shows as not installed or results never arrive

**Fix:**

- Not installed: `discovery_dir` in `server.json` is wrong or the spool
  directories are missing; run `install.sh` again.
- `nmap is not installed …`: `sudo apt install nmap`.
- No results: `systemctl status nebula-discovery.path`; spool modes must be
  2750 (`jobs/` `nebula-server:nebula-discovery`, `results/` the reverse).

## Proxmox pages are empty or show `unavailable`

**Fix:** check in this order: `nebula pve remote list` (remote `active`?),
`systemctl status nebula-pve-collector`, an approved read lease on
`/pve/<id>` (**Request read lease** or **Renew read lease**), and
`journalctl -u nebula-executor` for `read_grant_does_not_cover`. Full table:
[Proxmox troubleshooting](../operator/proxmox.md#troubleshooting).

## A network device shows no data

**Cause:** reading device data is not implemented in this release; the
executor answers "device reads are not implemented yet (ND-14)".

**Fix:** none needed. Registration, pins and credentials are kept for when
reads land (ADR 0010). See [Network](network.md#what-works-for-network-devices-today).

## Vulnerability findings never appear

**Cause:** the inventory export is still empty in this release, so every
finding is rejected with "subject not in the run's inventory snapshot".

**Fix:** none on your side yet. Check Hermes reaches the API (`401` = wrong
token, `403` = wrong source address or scope, both as `audit` lines in
`journalctl -u nebula-server`). See
[Vulnerabilities](vulnerabilities.md#what-works-in-this-release).

## A batch member stays refused with `batch_host_busy`

**Cause:** a previous batch run may still be running on that host, or its
hold expired after 24 hours.

**Fix:** follow "Held batch targets" in admin guide
[9.2](../admin/guide.md#92-rollouts-in-stages): stop the executor, inspect
with `sudo -u nebula-executor nebula-executor batch-holds list`, re-arm only
after checking the host. Never edit `batch-held-targets.json` by hand.

## Backup or restore refuses to run

**Fix:**

- `run this with sudo`: `sudo nebula backup` from your admin login, not a
  root shell.
- `install.sh`: no pre-upgrade backup: add a recipient to
  `/etc/nebula/backup-recipients`.
- Restore: schema newer than this binary: install the Nebula version that
  made the backup first.

## The executor does not start

**Symptom:** `-admin-users is required`, `root cannot be an admin user`,
`admin user … must not be the server user`, or
`executor.db is missing but executor.db.installed says one existed`.

**Fix:** fix the admin list and run `install.sh` again. For a missing
database, restore a backup (`sudo nebula restore`); remove the marker file
named in the message only if you deliberately want to start empty.

## After an I1 integrity alarm

**Symptom:** `nebula integrity status` lists an open I1 finding, or
`nebula unlock` is refused.

**What it means:** NOS found that its own files on the NOS machine differ
from the signed list of the installed release, that a covered file is
missing, or that an unlisted `/usr/bin/nebula*` executable exists. A changed
or missing NOS binary, systemd unit, built-in module file or root key, or an
unlisted executable, locks the executor. A changed web asset is refused by the
server. A changed configuration file is a finding without a lock. An incomplete
check is never reported as clean.

**What is locked:** while a locking finding is open, the executor refuses
`nebula unlock` and all mutation and read-grant dispatch.

**What does not happen:** NOS does not delete, restore or roll back any file.
The lock only withholds authority. Repairing the files is your job.

**Fix:**

1. `nebula integrity status` shows the lock, the last run and the open
   findings with their IDs.
2. Verify offline, from another machine or from read-only boot media with the
   NOS disk mounted elsewhere, against release files that you fetched and
   checked there:

   ```
   nebula integrity verify --offline RELEASE-DIR --root MOUNT --version X.Y.Z --flavour FLAVOUR
   ```

   Both paths must be absolute. `--version` is the version you expect this
   machine to run. Exit status 0 means clean, 5 means deviations were found,
   6 means the check was incomplete. Never treat 6 as clean.
   Run a `nebula` binary from that other machine or boot medium, taken from
   the verified release files, never `MOUNT/usr/bin/nebula` or any other
   binary from the checked disk: a replaced binary can report clean.
3. Reinstall NOS from its package, or install a new signed release.
4. For each open finding, run `nebula integrity ack FINDING`. It shows the
   finding, asks you to type `yes`, and clears only that finding. A later
   check that finds the same deviation locks again. While other locking
   findings are open, unlock and dispatch stay refused.

**Limit:** NOS checks cannot detect a root compromise of the NOS machine;
see ADR 0015. The unlock refusal only withholds authority; it cannot help
when the executor binary itself is the replaced one. Only the offline check
in step 2 does not depend on software on the NOS machine, which is why it is
the check to run after any I1 alarm.

**Distribution:** GitHub is only a distribution channel, never a trust anchor.
Release files are trusted only after `release-manifest.json.sig` verifies
against the root public keys built into the NOS binaries.
