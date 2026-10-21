# Nebula Operation Station

A self-hosted operations control plane for Linux homelabs (about 5 to 100 hosts): inventory, SSH-based patching and service operations, staged rollouts and an audit trail, with credentials held by a separate executor that verifies every privileged action on its own.

> **Status: alpha, working towards Release 0.9.** The code for 0.9 is complete and passes the test suite (patching, services, Docker, rollouts, runbooks, signed modules, IPAM, discovery, signed events, backup and restore, Debian packages and containers); the lab run on real hosts is still pending. Try it in a lab, not in production. Operators start with the [installation and operations handbook](docs/admin/guide.md); the state of every milestone is in [`docs/implementation/m0.md`](docs/implementation/m0.md).

## Screenshots

Taken from the test harness's preview mode with demo data (`go run ./test/browser/harness -preview PORT /absolute/empty/dir`, then open `http://localhost:PORT`).

| Dashboard | Inventory (dark theme) |
| --- | --- |
| ![Dashboard with host overview tiles](docs/screenshots/dashboard-light.png) | ![Inventory with status, updates, containers and key per host](docs/screenshots/inventory-dark.png) |
| **Host: pending updates** | **Host: containers** |
| ![Host page, updates tab](docs/screenshots/host-updates-light.png) | ![Host page, containers tab](docs/screenshots/host-containers-light.png) |

On a phone: [inventory](docs/screenshots/inventory-phone-light.png). Light, dark or system theme under Settings → Appearance.

## Design in one paragraph

`nebula-server` serves the web UI and plans work but holds no keys and cannot execute anything. `nebula-executor` holds the SSH keys in memory, listens only on a Unix socket, identifies callers by their kernel-reported UID, and authorizes each run against a permit bound to the exact artifact, targets, parameters and credentials that a human approved with WebAuthn or the `nebula` CLI. Managed hosts need no agent. Details: [`docs/spec/00-index.md`](docs/spec/00-index.md).

## Repository layout

```
cmd/            nebula-server, nebula-executor, nebula-discovery, nebula (CLI)
internal/       implementation (no exported API)
proto/          executor RPC contract
docs/spec/      frozen specification v2.2, one file per section
docs/adr/       architecture decision records
test/security/  security acceptance tests
```

## Building and testing

```
make build             # static binaries in bin/
make check             # format, vet, staticcheck, buf lint, tests, govulncheck
sudo -E make test-privileged   # multi-UID security tests
```

Requires Go 1.26 or later and `buf` for code generation.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and the
[getting-started guide](docs/dev/getting-started.md) for the toolchain,
`make check`, the privileged tests and running the executor locally.

## License

AGPL-3.0-or-later. See [`LICENSE`](LICENSE).
