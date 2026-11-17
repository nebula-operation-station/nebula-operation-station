# Getting started

This guide gets a contributor from a fresh clone to a green `make check`,
and shows how to build, test and run the executor locally. Milestones 0 to
10 are implemented (see "What exists and what does not" at the end); the
operator installation is in [`docs/admin/guide.md`](../admin/guide.md).
(Previously: this guide covered only the Milestone 0 security prototype.)

## Toolchain

| Tool | Version | Used for |
| --- | --- | --- |
| Go | 1.26 or later (`go.mod` requires 1.26; CI builds with 1.27.x) | build, test, vet |
| [buf](https://buf.build) | any recent release; CI installs it with `bufbuild/buf-action` v1.6.0 (the action version, not the buf version) | `buf lint`, `buf generate` |
| python3 | any Python 3; not pinned | `make test-deploy` (deployment policy tests) |
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
make check        # lint, generate-check, test, test-deploy, vuln
```

`make check` is the gate: it must pass completely before you push. It runs:

- `lint`: `gofmt` check, `go vet` (also with the `privileged` and
  `integration` tags), staticcheck under Go 1.26.9, and `buf lint`;
- `generate-check`: regenerates the code from `proto/` and fails if
  `internal/rpc` changed;
- `test`: `go test -race ./...`;
- `test-deploy`: the deployment policy tests (systemd units, nftables
  files, install and quickstart scripts). It needs `python3`; the
  systemd-analyze and kernel `nft` checks skip themselves when those
  tools are missing;
- `vuln`: `govulncheck`.

`make build` compiles every package under `cmd/` into `bin/`. That is more
than Nebula ships: the binaries of the NOS package and image are listed in
[`deploy/quickstart/binaries.txt`](../../deploy/quickstart/binaries.txt),
and the install script reads that same list. The release tarball also
carries `nebula-vuln-agent` (its own `.deb`, installed with
`install.sh --vuln-agent`); see `.goreleaser.yaml`.

Other targets:

- `make test`: the unit tests only, without the deployment tests.
- `make fuzz`: runs a fixed list of fuzz targets (see the `fuzz` target
  in the `Makefile`) for 20 seconds each, a smoke run, not a campaign. Most
  `Fuzz*` functions are not in that list; run one with
  `go test -run='^$' -fuzz='^FuzzName$' ./path/`
  (`docs/implementation/security-tests.md` has the inventory).
- `make test-integration`: runs `test/integration` against SSH test VMs
  (spec 08, H05).
- `make test-browser`: runs the browser tests in `test/browser/run.sh`;
  needs Node.js with Playwright and Chromium.
- `make fmt`: rewrites Go files with `gofmt`.
- `make generate`: runs `buf generate` after you change `proto/`.
- `make clean`: removes `bin/`.
- `make release-stage`: maintainers only; builds unsigned release
  staging, see `docs/admin/release-signing.md`.

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

This is a manual setup for a developer test machine, not for an operator
installation (use `deploy/install.sh` as described in
[`docs/admin/guide.md`](../admin/guide.md)). (Previously: "the Milestone 0
prototype setup from `deploy/README.md`".)

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

`deploy/systemd/nebula-server.service` is the reference unit for the web
server; `deploy/install.sh` installs the shipped units. This manual setup
does not install it, so for development run `bin/nebula-server` directly
(previously: "`nebula-server` has no systemd unit yet").

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
key mismatch is notified (once per block), an Ops State change (worse or
recovered), an operation that finished with failed hosts, and the executor
found locked after a restart.

## What exists and what does not

Milestone 0 (security prototype) is implemented: UID separation,
socket-based caller identification, canonical requests, single-use
permits, executor-side WebAuthn verification, and the CLI unlock flow.
See `docs/implementation/m0.md` for the full status, known gaps and
decisions.

Milestones 1 to 10 (up to Release 0.9) are implemented up to the lab run
on real hosts; operators follow the installation and operations handbook,
[`docs/admin/guide.md`](../admin/guide.md).
