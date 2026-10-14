# Getting started

This guide gets a contributor from a fresh clone to a green `make check`,
and shows how to run the executor locally. It covers the Milestone 0
security prototype: what exists today, and how to build, test and run it.

## Toolchain

| Tool | Version | Used for |
| --- | --- | --- |
| Go | 1.26 or later (`go.mod` requires 1.26; CI builds with 1.27.x) | build, test, vet |
| [buf](https://buf.build) | any recent release (CI uses v1.6.0) | `buf lint`, `buf generate` |
| protoc-gen-go | v1.36.12 (pinned in CI) | code generation from `proto/` |
| protoc-gen-go-grpc | v1.6.2 (pinned in CI) | code generation from `proto/` |
| staticcheck | v0.8.1, run under Go 1.26.9 (pinned in `Makefile`) | `make lint` |
| govulncheck | v1.8.0 (pinned in `Makefile`) | `make vuln` |

Install the code-generation plugins once (versions must match CI, or
`make generate-check` will fail):

```
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2
```

`make lint` downloads staticcheck itself under the pinned Go 1.26.9
toolchain (staticcheck 2026.2.1 cannot read Go 1.27 export data yet), so
you do not need to install it separately. No CGO is used anywhere; all
builds are static.

## First build

```
git clone <repository>
cd nebula-operation-station
make hooks        # point git at .githooks (protected-path tripwire)
make check        # fmt-check, vet, staticcheck, buf lint, generated-code
                  # check, go test -race, govulncheck
```

`make check` is the gate: it must pass completely before you push.
`make build` then produces the static binaries in `bin/`
(`nebula-server`, `nebula-executor`, `nebula-discovery`, `nebula`).

### Privileged tests

```
sudo -E make test-privileged
```

These are the multi-UID security tests in `test/security/`. They need
root because they start helper processes and drop them to other UIDs to
prove that the executor's Unix socket really identifies callers by their
kernel-reported UID (`SO_PEERCRED`) and that the executor's files are
unreadable to other users. They are tagged `privileged` and are not part
of `make test`; CI runs them with sudo.

## Working on the code

- Read `AGENTS.md` first: its rules (tests first, no new dependencies,
  protected paths, no self-written crypto, no `ssh` binary from Go code)
  apply to human contributors as well.
- `proto/` is the RPC contract. Edit the `.proto` files and run
  `make generate`; never edit the generated code in `internal/rpc/` by
  hand.
- Packages live under `internal/`; one package, one responsibility.
- The frozen specification is in `docs/spec/`; issues name the spec
  sections and acceptance criteria they implement.

## Running the executor locally

This is the Milestone 0 prototype setup from `deploy/README.md`, for a
test machine only:

```
sudo groupadd --system nebula-rpc
sudo useradd --system --home /var/lib/nebula/server  --shell /usr/sbin/nologin -G nebula-rpc nebula-server
sudo useradd --system --home /var/lib/nebula/executor --shell /usr/sbin/nologin nebula-executor
sudo usermod -aG nebula-rpc "$USER"          # your admin account

make build && sudo install -m 0755 bin/nebula-executor bin/nebula /usr/bin/
sudo install -m 0644 deploy/systemd/nebula-executor.service /etc/systemd/system/
sudoedit /etc/systemd/system/nebula-executor.service   # -admin-users, -rp-id, -origin
sudo systemctl daemon-reload && sudo systemctl enable --now nebula-executor
```

What this gives you:

- **Users.** `nebula-executor` runs the executor and owns
  `/var/lib/nebula/executor` (mode 0700). `nebula-server` is the user
  the server would run as. Your own account is added to the
  `nebula-rpc` group so the CLI can talk to the executor socket; you
  must log out and back in for the membership to take effect.
- **Socket.** The executor listens only on the Unix socket
  `/run/nebula/executor.sock` (group `nebula-rpc`), configured via the
  unit's `-socket` and `-socket-group` flags. It never opens a network
  port.
- **Test key.** Create the key the executor will use for managed hosts
  (passphrase from your password manager):

  ```
  sudo -u nebula-executor ssh-keygen -t ed25519 -C nebula-default \
    -f /var/lib/nebula/executor/keys/nebula-default.key
  ```

  After `nebula unlock`, `nebula host enroll-script --from <Nebula IPs>`
  prints a script that installs this key for a `nebula` user on a new
  host (run it there as root after reading it); then pin the host with
  `nebula host pin`.

Then check the state and unlock:

```
nebula status
nebula unlock        # passphrase-protected; the executor starts locked
nebula vault init    # optional: secret vault for API tokens (same passphrase recommended)
```

`nebula-server` has no systemd unit yet; run it directly for
development (`bin/nebula-server`) if you need it.

## Operations and patching

With a pinned host (`nebula host enroll-script`, then `nebula host pin`)
and an unlocked executor, the web UI's **Operations** page runs the
built-in actions on enrolled hosts: collect facts, check updates, refresh
package lists, install security updates, install all updates, reboot.
Open a privileged session on the dashboard first; approve each operation
with your security key.

The executor decides the risk. A script it does not trust counts as at
least HIGH, so every operation needs a fresh user-verified approval. To
trust the built-in scripts at their declared level, read and trust them on
the executor host:

```
nebula-server -export-actions /tmp/nebula-actions   # prints the trust commands
less /tmp/nebula-actions/*.sh
nebula artifact trust --action package.list_updates --version 1.0.0 --risk LOW /tmp/nebula-actions/package_list_updates-1.0.0.sh
```

Installing updates and rebooting run as durable jobs on the host (they
need the `nebula` user's NOPASSWD sudo and systemd); the executor collects
the result even across its own restarts. Nothing is installed or rebooted
unless you start and approve it.

## Notifications (optional)

Add a `notifications` block to `/etc/nebula/server.json` (any subset):

```json
"notifications": {
  "webhook":  {"url": "https://hooks.example.org/nebula", "secret": "<at least 32 random characters>"},
  "ntfy":     {"url": "https://ntfy.sh", "topic": "<random topic>", "token": "<optional access token>"},
  "telegram": {"bot_token": "<123456:ABC...>", "chat_id": "<chat id>"}
}
```

With tokens in it the file must not be readable by others (`chmod 0640`,
owner `root:nebula-server`, as the installer creates it). Check with
`nebula-server -config /etc/nebula/server.json -notify-test`. Today a host
key mismatch is notified (once per block); more events follow.

## What exists and what does not

Milestone 0 (security prototype) is implemented: UID separation,
socket-based caller identification, canonical requests, single-use
permits, executor-side WebAuthn verification, and the CLI unlock flow.
See `docs/implementation/m0.md` for the full status, known gaps and
decisions.

Not yet available: runbooks and modules, the stage engine (canary,
waves), Docker and IPAM (Milestones 6+), packaging (Milestone 10), and the discovery service.
Do not use this in production.
