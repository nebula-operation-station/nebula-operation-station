# Quick start (lab)

Two scripts set up a Nebula lab from a git checkout. Everything else is in
the [handbook](../../docs/admin/guide.md); this is the short path.

## What you need

| Machine | System | Size |
| --- | --- | --- |
| Nebula machine | Debian 12 or Ubuntu 24.04 with systemd, nothing else on it | 2 CPU, 4 GB RAM, 32 GB disk; no swap or encrypted swap |
| Each managed host | Debian 12, Ubuntu 22.04/24.04 or Proxmox VE | 1 CPU, 1–2 GB RAM, 16 GB disk |

Plus a normal login (your admin account, not root) with `sudo` on the
Nebula machine, a hostname for the web UI (for example
`nebula.lab.example.org`) and a FIDO2 security key, better two.

## 1. The Nebula machine

Logged in as your admin account:

```
sudo apt install -y git
git clone https://github.com/nebula-operation-station/nebula-operation-station.git
cd nebula-operation-station
sudo ./deploy/quickstart/setup-nebula.sh --rp-id nebula.lab.example.org
```

The script asks you twice for one thing: the **passphrase of the SSH key**
Nebula uses for your hosts (choose a long one and store it in your
password manager; you type it after every reboot). Everything else runs by
itself:

1. checks CPU, RAM, disk and swap (warnings only);
2. installs nmap, age, Caddy, git, make, curl, openssl;
3. installs Go from go.dev (checksum verified) if it is missing or too old;
4. builds Nebula and runs `deploy/install.sh` (users, directories,
   systemd units, `/etc/nebula/server.json`);
5. creates the backup key `~/nebula-backup.key` and
   `/etc/nebula/backup-recipients`;
6. creates the SSH key for managed hosts;
7. sets up Caddy with an internal certificate authority in front of the
   web UI and copies its root certificate to `~/nebula-root-ca.crt`;
8. unlocks Nebula, writes `~/enroll.sh` for your hosts and prints the
   one-time code for your first security key.

At the end it prints what is left, in this order:

1. Make `nebula.lab.example.org` resolve to the Nebula machine (DNS, or a
   hosts entry on your computer).
2. Import `~/nebula-root-ca.crt` as a trusted root certificate on your
   computer, after comparing the fingerprint the script printed.
3. Open `https://nebula.lab.example.org/setup`, enter the code, register
   your security key (then the backup key).
4. Copy `~/nebula-backup.key` into your password manager and delete it on
   the machine (`shred -u ~/nebula-backup.key`). Without it no backup can
   be restored.

Options: `--admin-users a,b` (default: you), `--backup-recipient age1…`
(use a key you already have), `--no-caddy` (your own reverse proxy),
`--no-unlock`.

## 2. Each managed host

Copy two files from the Nebula machine to the host and run one command
there:

```
scp ~/enroll.sh nebula-operation-station/deploy/quickstart/prepare-target.sh USER@HOST:
ssh -t USER@HOST sudo ./prepare-target.sh --nebula-ip NEBULA-IP --enroll enroll.sh
```

(`USER` is any account on the host that may use `sudo`.) Running it again
is harmless.

It installs OpenSSH, sudo and curl, lets the Nebula machine past fail2ban
(if installed), runs the enrollment script and prints the host's SSH key
fingerprints. Then in the web UI: **Inventory** → add the host →
**Enroll hosts** → **Read host keys**, compare the fingerprints, pin.

## Later

| When | What |
| --- | --- |
| After every reboot of the Nebula machine | `nebula unlock` |
| Upgrade | `git pull`, then `sudo ./deploy/quickstart/setup-nebula.sh --rp-id …` again (it backs up first) |
| Backup | `sudo nebula backup`, copy `~/nebula-backups/` off the machine |
| Anything else | [handbook](../../docs/admin/guide.md) |
