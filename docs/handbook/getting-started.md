# Getting started

From an empty machine to your first login with a security key. Reference:
admin guide sections [2](../admin/guide.md#2-planning) to
[5](../admin/guide.md#5-first-login-and-security-keys).

## Install Nebula on a fresh machine

**Goal:** the three services (`nebula-executor`, `nebula-server`,
`nebula-discovery`) run on a dedicated machine.

**Prerequisites:**

- A small VM or host with Debian 12 (Ubuntu 22.04/24.04 work too), used for
  nothing else.
- One normal login per admin (not root), for example `alice`.
- The lowercase hostname under which the UI will be reached, the WebAuthn
  *RP ID*, for example `nebula.lab.example.org`. It cannot be changed later
  without registering every security key again.

**Steps (release tarball):**

1. Download `nebula_<version>_linux_<arch>.tar.gz` and
   `nebula_<version>_checksums.txt` from the release.
2. Check and extract:

   ```
   sha256sum --ignore-missing -c nebula_<version>_checksums.txt
   mkdir nebula && tar -xzf nebula_<version>_linux_amd64.tar.gz -C nebula
   cd nebula
   ```

3. Install, naming your admin users and RP ID:

   ```
   sudo ./deploy/install.sh --admin-users alice --rp-id nebula.lab.example.org
   ```

   To see what it would do first:
   `NEBULA_INSTALL_DRY_RUN=1 ./deploy/install.sh --admin-users alice --rp-id nebula.lab.example.org`.
4. For network discovery, also `sudo apt install nmap`.
5. **Log out and in again**, so that your login picks up the `nebula-rpc`
   group.

Other ways: the Debian package (`sudo apt install nebula-operation-station`,
then `sudo /usr/share/nebula/deploy/install.sh --from-package --admin-users alice --rp-id nebula.lab.example.org`)
and containers (`deploy/container/compose.yaml`). For a lab, the quickest
path is [`deploy/quickstart/`](../../deploy/quickstart/README.md). Details:
admin guide [3.1 to 3.3](../admin/guide.md#3-installation).

**Expected result:** `nebula status` answers and shows `unlocked: false`.

**Common errors:**

- `permission denied` on the socket, or `peercred: peer UID holds no role`:
  you did not log out and in again, or your login is not in
  `--admin-users`. Check with `id`.
- The installer refuses root or a Nebula system user as admin: pick a normal
  login.

## Create the SSH key Nebula uses for managed hosts

**Goal:** the executor has a passphrase-protected key to log in to your
hosts.

**Prerequisites:** Nebula installed; a long passphrase in your password
manager (all key files share it).

**Steps:**

```
sudo -u nebula-executor ssh-keygen -t ed25519 -C nebula-default \
  -f /var/lib/nebula/executor/keys/nebula-default.key
```

Enter the passphrase when asked. Do not leave it empty.

For a container install, create the key on the Docker host and copy it into
the executor volume as shown in admin guide
[3.3, step 4](../admin/guide.md#33-in-containers).

**Expected result:** `/var/lib/nebula/executor/keys/nebula-default.key`
exists, owned by `nebula-executor`, mode 0600.

**Common errors:** `keyring: … is not passphrase-protected`, `has mode …`
or `is owned by uid …` at unlock: the key must be OpenSSH format with a
passphrase, mode 0600, owned by the executor user. Convert an old PEM key
with `ssh-keygen -p -o -f FILE`. See admin guide
[3.4](../admin/guide.md#34-the-ssh-key-for-managed-hosts).

## Unlock the executor

**Goal:** the executor decrypts the SSH keys (and the vault) into memory so
that operations can run.

**Prerequisites:** an admin login on the Nebula machine with a terminal (the
passphrase is never read from a pipe).

**Steps:**

```
nebula status
nebula unlock
```

`nebula unlock` asks for the key passphrase.

**Expected result:** `nebula status` shows `unlocked: true` and lists the
loaded credentials, for example `credentials: nebula-default`.

**Common errors:**

- `nebula: this needs a terminal`: run it in an interactive shell; in a
  container use `docker compose exec` without `-T`.
- A wrong passphrase, or one key file with a different passphrase: unlock
  fails as a whole. All key files must share one passphrase.

**When to do it:** after **every** restart of the executor (reboot,
upgrade, crash). It always starts locked, and nothing runs until an admin
unlocks it on the machine. No browser session can unlock it. See
admin guide [11.1](../admin/guide.md#111-locking-unlocking-and-restarting).

## Set up the vault and note the event key

**Goal:** a vault for runbook secrets exists, and you have the fingerprint
of the executor's event key stored outside the machine.

**Prerequisites:** executor unlocked.

**Steps:**

```
nebula vault init      # optional; passphrase of at least 32 characters
nebula vault status
nebula events key      # copy the fingerprint to your password manager
```

**Expected result:** `nebula vault status` reports the vault, and you have
the event-key fingerprint written down. Compare it with the *History* page
(`/history`) from time to time.

## Put a reverse proxy with TLS in front

**Goal:** the UI is reachable as `https://<rp-id>`.

**Prerequisites:** a certificate for `<rp-id>` (Caddy can obtain one
itself).

**Steps (Caddy):**

```
nebula.lab.example.org {
    reverse_proxy 127.0.0.1:8080
}
```

The proxy must pass the `Host` and `Origin` headers unchanged. Never expose
port 8080 itself. An nginx example is in admin guide
[4](../admin/guide.md#4-reverse-proxy-and-tls).

**Expected result:** `https://<rp-id>/login` loads in the browser.

**Common errors:** login or approvals fail in the browser when you use
another address than exactly `https://<rp-id>`, or when the proxy rewrites
`Host`/`Origin`. `public_origin` in `/etc/nebula/server.json` must be
`https://<rp-id>`.

## Log in for the first time and register your first security key

**Goal:** you can log in to the web UI with a FIDO2 security key (for
example a YubiKey).

**Prerequisites:** executor running; reverse proxy in place; a security key
with a PIN set.

**Steps:**

1. On the Nebula machine: `nebula webauthn code`. It prints a one-time code,
   valid for 15 minutes and usable once. (`--user NAME` and `--label TEXT`
   are optional.)
2. Open `https://<rp-id>/setup`, enter the code and register the key (touch
   it, enter its PIN).
3. Log in at `https://<rp-id>/login`.

**Expected result:** you see the dashboard. `nebula webauthn list` shows the
new credential.

**Common errors:** the code expired (15 minutes) or was already used: run
`nebula webauthn code` again.

## Register a second security key (YubiKey or passkey)

**Goal:** a backup key, so losing one key does not lock you out.

**Prerequisites:** logged in with a registered key; access to the Nebula
machine.

**Steps:**

1. On the Nebula machine: `nebula webauthn code`.
2. In the UI: *Settings → Sign-in and security keys → Add a security key*
   (`/settings`). Enter the code and a label (for example `yubikey-backup`).
3. Touch the new key, then confirm with an already registered key.

A hardware key (YubiKey) and a passkey (Touch ID, Windows Hello) both work.

**Expected result:** `nebula webauthn list` shows both keys and which key
confirmed the new one.

**Removing a key** is CLI-only: `nebula webauthn remove ID`. It locks the
executor (all permits revoked, pending proposals discarded), so run
`nebula unlock` afterwards. The *Settings* page shows the exact command
for each key.

## Set up TOTP recovery

**Goal:** a way back in when every security key is lost.

**Prerequisites:** an authenticator app; admin login on the Nebula machine.

**Steps:**

```
nebula totp setup            # optional: --account LABEL; asks for a code to confirm
nebula totp status
```

**Recovery when all keys are lost:**

1. Log in with the TOTP code (recovery login on `/login`).
2. Nebula forces you to register a new security key.
3. Confirm it on the Nebula machine: `nebula totp finish-recovery`.

**Expected result:** `nebula totp status` shows TOTP set up and, during a
recovery, that one is pending. `nebula totp remove` removes it again.

## Open a privileged session and lock when you leave

**Goal:** run LOW actions (such as *Check updates*) without a key prompt for
each, and wipe the keys when you are done.

**Prerequisites:** logged in; executor unlocked.

**Steps:**

1. Dashboard (`/dashboard`) → **Open privileged session**: touch your key
   and enter its PIN.
2. Work. LOW actions run without a further prompt for the session (60
   minutes by default, executor flag `-session-minutes`).
3. When you leave: Dashboard → **Lock executor**, or `nebula lock` on the machine.

**Expected result:** after lock, `nebula status` shows `unlocked: false`
and `privileged session: false`; every permit is revoked.

**Note:** `nebula lock` also discards pending proposals and pauses approved
read leases until the next `nebula unlock`. See admin guide
[11.1](../admin/guide.md#111-locking-unlocking-and-restarting).

## Trust the built-in actions after install or upgrade

**Goal:** built-in actions (check updates, install updates, Docker, …) run
at their declared risk instead of at least HIGH.

**Prerequisites:** executor unlocked; the release bundle (`builtins.tar`,
`release-manifest.json`, `release-manifest.json.sig`) of your release in
`/usr/share/nebula/release`. A source or quickstart install has none.

**Steps:**

```
nebula artifact trust-builtins     # as your admin user, not with sudo
nebula artifact list
```

Review the diff, decide `--pin` or `--retire` for old versions if asked,
and type the shown digest to commit.

Without a release bundle, trust the actions one by one instead:

```
nebula-server -export-actions ~/nebula-actions-<version>
less ~/nebula-actions-<version>/*.sh
# then run the printed `nebula artifact trust ...` commands
```

**Expected result:** `nebula artifact list` lists the built-ins; the web
banner no longer says the built-ins are untrusted.

**Common errors:** *No release bundle is installed on this executor host*
is normal for a source install; use the per-action way. *Built-in trust
status is unreachable* means a partial, mixed or unverifiable bundle; the
executor log names the cause. Details: admin guide
[8.1](../admin/guide.md#81-the-built-in-actions) and
[8.2](../admin/guide.md#82-trusting-the-built-ins-together-after-an-upgrade).
