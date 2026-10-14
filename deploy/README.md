# Deployment (Milestone 0 prototype)

Only for trying the security prototype on a test machine. Packaging (APT, containers) comes in Milestone 10.

```
sudo groupadd --system nebula-rpc
sudo useradd --system --home /var/lib/nebula/server  --shell /usr/sbin/nologin -G nebula-rpc nebula-server
sudo useradd --system --home /var/lib/nebula/executor --shell /usr/sbin/nologin nebula-executor
sudo usermod -aG nebula-rpc "$USER"          # your admin account

make build && sudo install -m 0755 bin/nebula-executor bin/nebula /usr/bin/
sudo install -m 0644 deploy/systemd/nebula-executor.service /etc/systemd/system/
sudoedit /etc/systemd/system/nebula-executor.service   # -admin-users, -rp-id, -origin
sudo systemctl daemon-reload && sudo systemctl enable --now nebula-executor

# Key for the managed hosts, passphrase from your password manager:
sudo -u nebula-executor ssh-keygen -t ed25519 -C nebula-default \
  -f /var/lib/nebula/executor/keys/nebula-default.key

nebula status
nebula unlock
```

The public key goes into the `nebula` user's `authorized_keys` on managed hosts once enrollment exists (Milestone 3).

## nebula-server

The web UI server runs as its own unit, `deploy/systemd/nebula-server.service` (installed by `deploy/install.sh` next to the executor unit):

- runs as `nebula-server` (group `nebula-rpc`, so it can reach `/run/nebula/executor.sock`), starts after `nebula-executor.service` (`Wants=` it)
- `ExecStart=/usr/bin/nebula-server -config /etc/nebula/server.json`
- listens on `127.0.0.1:8080` by default and belongs behind a TLS reverse proxy serving `https://<rp-id>`
- `StateDirectory=nebula/server` (0750), `UMask=0027`, `Restart=on-failure`, and the same hardening block as the executor unit (plus `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, since it listens on TCP)

`install.sh` writes `/etc/nebula/server.json` (mode 0640, owner `root:nebula-server`) only if it does not exist yet, using the validated `--rp-id` as `public_origin` (`https://<rp-id>`); later runs leave it untouched. After installing:

```
systemctl enable --now nebula-executor nebula-server
nebula unlock
nebula webauthn code        # first security key: enter the code at https://<rp-id>/setup
```
