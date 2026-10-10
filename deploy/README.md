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
