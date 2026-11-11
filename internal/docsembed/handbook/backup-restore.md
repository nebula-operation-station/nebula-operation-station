# Backup, restore and upgrades

Encrypted backups, restoring them, and upgrading without losing the way
back. Reference: admin guide [12](../admin/guide.md#12-backup-and-restore)
and [13](../admin/guide.md#13-upgrades).

## Create the backup key (once)

**Goal:** backups are encrypted to a key that does not live on the Nebula
machine.

**Prerequisites:** [age](https://age-encryption.org) on a machine you keep
safe (not the Nebula machine).

**Steps:**

1. On the safe machine: `age-keygen -o nebula-backup.key`. It prints the
   public key (`age1…`).
2. On the Nebula machine, put that public key into
   `/etc/nebula/backup-recipients` (one recipient per line; several are
   allowed).
3. Keep `nebula-backup.key` offline, for example in your password manager.

**Expected result:** `sudo nebula backup` works (next section).

## Back up Nebula

**Goal:** an age-encrypted archive of everything except passphrases and
plaintext secrets.

**Prerequisites:** backup recipients set; an admin login with `sudo` (not a
root shell).

**Steps:**

```
sudo nebula backup
```

`--out FILE` writes somewhere else than `~/nebula-backups/`. Then copy the
archive off the machine, for example `restic backup ~/nebula-backups`.

**Expected result:** a new archive in `~/nebula-backups/` of the admin who
ran `sudo`. Services keep running while it is made.

**What is in it:** inventory, history, configuration (`server.json`,
`backup-recipients`, the systemd drop-ins), the server database with logs
and artifacts, and the executor's database and SSH key files (still
passphrase-protected). **Not** in it: the passphrases, decrypted keys,
plaintext secrets and the event key.

**Common errors:**

- `run this with sudo`: run `sudo nebula backup` from your admin login, not
  from a root shell.
- No recipients: add one to `/etc/nebula/backup-recipients`.
- `--no-encrypt` writes an unencrypted archive (you type `unencrypted`). It
  has no integrity protection of its own; keep a checksum elsewhere.

## Restore a backup

**Goal:** bring back Nebula's state on the same machine or a new one.

**Prerequisites:** on a new machine, `install.sh` ran with the **same**
`--admin-users` and `--rp-id`; the age identity file; the key passphrase.

**Steps:**

```
sudo nebula restore --identity nebula-backup.key FILE
```

1. Read what it shows: when, where and by which version the backup was
   made. It checks the manifest, every checksum and the schema versions
   before anything changes.
2. Type `restore`. For a backup from another machine, also type that
   machine's name (or `unknown`).
3. It stops the services, moves the current data aside
   (`*.pre-restore-<time>`), puts the backup in place and starts the services
   locked.
4. Finish:

   ```
   nebula unlock
   nebula status
   nebula events verify
   ```

**Expected result:** the services run with the restored data. The backup's
configuration is written to `/etc/nebula/from-backup-<time>/` for you to
compare; it is **not** applied.

**Common errors:** "schema newer than this binary": the backup comes from a
newer Nebula; install that version first. A restore on a new machine starts
a new event key; the chain records the change and `nebula events verify`
continues across it.

## Back up and restore a container install

**Goal:** encrypted copies of the Docker volumes.

**Prerequisites:** the age **public** key; `age` on the Docker host.

**Steps (backup):**

```
cd deploy/container
docker compose stop
for v in executor-data server-data; do
  docker run --rm -v nebula_$v:/v:ro debian:12-slim tar -C /v -cz . \
    | age -r age1… -o nebula-$v-$(date +%F).tar.gz.age
done
docker compose start
docker compose exec -u nebula-admin executor nebula unlock
```

**Steps (restore):** stop the stack, stream each archive into its empty
volume, start and unlock:

```
age -d -i nebula-backup.key nebula-executor-data-<date>.tar.gz.age \
  | docker run --rm -i -v nebula_executor-data:/v debian:12-slim tar -C /v -xpz
```

**Note:** a volume copy holds everything the executor has, including its
event key. Never keep it unencrypted. `nebula backup` is for host installs
only.

## Upgrade a tarball install

**Goal:** a new release, with a backup taken first.

**Prerequisites:** backup recipients set; release notes read.

**Steps:**

1. Extract the new tarball and run, from it, as an admin through `sudo`:

   ```
   sudo ./deploy/install.sh --admin-users alice --rp-id nebula.lab.example.org
   ```

   It makes a backup first and stops without changes if it cannot.
2. `nebula unlock`.
3. Trust the built-ins again if their versions changed:
   `nebula artifact trust-builtins`, then `nebula artifact list`.
4. `nebula status` and `nebula events verify`.

**Expected result:** the new version runs; unedited unit files were
replaced; edited ones were kept with a warning and a `diff -u` command.

**Common errors:** "no pre-upgrade backup was made": add a backup recipient
and run through `sudo` from an admin account, or set `NEBULA_SKIP_BACKUP=1`
knowingly. There is no automatic downgrade; the backup is the way back.

## Upgrade a Debian package install

**Goal:** the same, for the APT package.

**Steps:**

```
sudo apt update && sudo apt upgrade
sudo nebula backup && sudo systemctl restart nebula-executor nebula-server
nebula unlock
nebula artifact trust-builtins
nebula status && nebula events verify
```

`apt upgrade` never restarts the services, because the backup needs your
`sudo`. The old version keeps running until you restart. A new
`nebula-pve-collector` needs `sudo systemctl restart nebula-pve-collector`.

## Upgrade a container install

**Steps:** build or pull the new image, back up the volumes (above), set
`NEBULA_IMAGE` in `deploy/container/.env` to the new tag,
`docker compose up -d`, then
`docker compose exec -u nebula-admin executor nebula unlock`.

## Test that a backup can be restored

**Goal:** know the backup works before you need it.

**Steps (monthly):** install the same Nebula version on a spare VM with the
same `--admin-users` and `--rp-id`, copy the latest archive and the age
identity there, run `sudo nebula restore --identity nebula-backup.key FILE`,
then `nebula unlock`, `nebula status` and `nebula events verify`.

**Expected result:** the restored instance unlocks and the event chain
verifies. Shut the spare VM down afterwards: it holds working keys for your
hosts.
