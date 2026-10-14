# Nebula Operation Station

A self-hosted operations control plane for Linux homelabs (about 5 to 100 hosts): inventory, SSH-based patching and service operations, staged rollouts and an audit trail, with credentials held by a separate executor that verifies every privileged action on its own.

> **Status: alpha, working towards Release 0.1** (safe patching of Debian/Ubuntu hosts). Enrollment, update checks, installing updates, reboots and service operations work end to end in the test suite; the first runs on real hosts are still pending. Try it in a lab, not in production. Operators start with the [operator guide](docs/admin/guide.md); the state of every milestone is in [`docs/implementation/m0.md`](docs/implementation/m0.md).

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
