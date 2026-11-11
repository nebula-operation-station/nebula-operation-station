<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Open-source project: license, releases, install paths, security process

A tool that holds root keys to someone's lab must be easy to verify and easy to install correctly. These project rules are part of the specification.

**License.** The entire project is licensed under **AGPL-3.0-or-later**, including server, executor, CLI, discovery helper, first-party modules, module SDK, schemas and examples. This intentionally applies one consistent copyleft model to the complete project. Modified versions offered over a network must provide the corresponding source as required by the AGPL.

**Code hosting.** The canonical repository is hosted on **GitHub**, preferably under a dedicated Nebula Operation Station organization. `main` is protected; security advisories, dependency updates, CI, signed release metadata and SBOM generation are enabled.

**Repository layout.**

```
cmd/nebula-server  cmd/nebula-executor  cmd/nebula-discovery  cmd/nebula
internal/          shared packages, no exported API
modules/           first-party modules (os-debian, patching, services, docker, bootstrap)
schemas/           capability contracts, module.yaml schema
deploy/            systemd units, tmpfiles, Caddy example, Docker Compose
docs/              user guide, module SDK, threat model
```

**Web frontend.** V1 uses **server-rendered Go templates with htmx**. A SPA is not required. The application keeps a strict CSP, avoids inline JavaScript, and does not require a Node/npm build for the primary UI. Small static JavaScript files are allowed only where htmx and normal HTML are insufficient.

**Internal RPC.** `nebula-server` and `nebula-executor` communicate using **gRPC + Protobuf over the Unix Domain Socket**. Protobuf contracts are versioned with backward-compatibility rules appropriate to rolling package upgrades.

**Builds and releases.**

- Pure-Go SQLite (`modernc.org/sqlite`), so every binary is static without CGO.
- Reproducible builds (`-trimpath`, pinned toolchain), built by goreleaser into tarballs, `.deb` packages and container images; acceptance criteria [below](#v26-14-01).
- Signed checksums and a CycloneDX SBOM per release; `govulncheck` and dependency updates in CI.
- No telemetry of any kind.

<a id="v26-14-01"></a>
<!-- Spec revision (ADR 0015, IG-01): v26-14-01 -->
**Reproducible-build acceptance criteria (ADR 0015 D2; implementation IG-11).** A signature on `installed-files.json` ([10-modules.md](10-modules.md#v26-10-01)) proves only that the maintainer approved the hashes, not that the build was safe; reproducible builds make the hashes checkable by anyone who rebuilds a tag (previously: "reproducible" without a check or acceptance criterion). Until IG-11 is in place, nobody but the release process can re-derive them.

- **Build flags.** `CGO_ENABLED=0`, `-trimpath`, `-buildvcs` with the tag commit only (a dirty tree fails the build), `-ldflags=-buildid=`, and the exact Go version pinned for releases, not only the `go.mod` minimum.
- **Deterministic packaging.** `SOURCE_DATE_EPOCH` from the tag commit for every file time in `.deb`, tarball, container layer and `builtins.tar`; sorted entries; fixed owner `0:0` and modes; web assets from a locked dependency set.
- **Check.** A CI job rebuilds the tag in a clean container and compares every installed file with `installed-files.json`, and a documented `make reproduce` style procedure lets third parties do the same. Comparison is by installed file, not by `.deb`, because package metadata may still differ.
- **Acceptance.** Two independent rebuilds of one tag produce identical `installed-files.json` hashes; any difference blocks the release.

**Install paths.**

| Path | Notes |
| --- | --- |
| APT repository | Debian/Ubuntu host or LXC; package creates users, sockets, tmpfiles and units |
| Docker Compose | Separate server and executor containers with fixed UIDs, shared volume for the socket, no published executor port; `SO_PEERCRED` works without user-namespace remapping, which the docs require; optional discovery container with `NET_RAW` |
| Static tarball | Binaries plus an install script that sets up users and units |

All paths need a fixed hostname with TLS the browser trusts (public ACME with DNS-01, or an internal CA installed on the admin's devices), because WebAuthn depends on it. A reference Caddy configuration ships in `deploy/`.

**Security process.** `SECURITY.md` with private reporting through GitHub security advisories, a supported-versions policy, and `docs/threat-model.md` stating what is protected (web compromise, host-input attacks, artifact substitution) and what is not (root on the Nebula machine, a malicious admin, a compromised authenticator). The pre-1.0 security tests run in CI.

**Testing.** Integration tests run against real Debian 12, Ubuntu 22.04 and Ubuntu 24.04 VMs, because durable jobs need a real systemd; plain containers are not enough.
