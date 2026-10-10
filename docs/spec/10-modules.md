<!-- Source: Nebula Operation Station Technical Specification v2.2 (Decision-Frozen). Edits need an architecture revision. -->

# Modules, runbooks, OS adapters and trust

Modules extend what Nebula can do on hosts but never run code on the Nebula machine and never bypass the executor.

**OS adapters.** OS-specific commands live only in adapters; the core never calls `apt`, `dnf`, `zypper` or `apk`. V1 ships `os-debian` for Debian and Ubuntu with the capabilities `os.detect`, `os.facts`, `package.refresh`, `package.list_updates`, `package.install_security`, `package.install_all`, `system.reboot_required`, `system.reboot`, `service.list`, `service.status`, `service.restart`. Each capability has a versioned result contract such as `package.list_updates@1`.

**Script contract.** stdout carries exactly one JSON document that matches the contract; stderr carries human-readable diagnostics and goes to the execution log.

**Module contents.** `module.yaml`, host scripts, checks, JSON schemas, declarative UI metadata and templates the module owns.

```yaml
name: telegraf
version: 1.2.0
supported_os: [debian>=12, ubuntu>=22.04]
actions:
  deploy_config:
    script: actions/deploy_config.sh
    risk: medium
    privilege: sudo
    retry: reconcile-first
    durable: true
    timeout: 300s
    params:
      interval: {type: string, pattern: '^[0-9]+s$'}
    secrets: [influx_token]
    prechecks: [telegraf.config_valid]
    postchecks: [telegraf.service_active]
    declares: [writes_config, network_access]
ui:
  host_tab: {title: Telegraf, cards: [status, version]}
```

**Boundaries.** No server-side binaries or Go plugins, no SQL against the core database. Modules that need state use core-managed key/value storage or their own SQLite file under `/var/lib/nebula/server/modules/<name>/`. Declared permissions (`requires root`, `writes_config`, `network_access`) drive warnings and risk; they are not a sandbox, and the UI says so.

**Declarative UI.** Host tabs, tables, forms, cards and buttons from metadata; no module JavaScript. Every privileged confirmation dialog is rendered by the core from core metadata, never from module-provided labels.

**Trust.** Verified (valid signature from a trusted signer), Local (created or imported here), Unverified. Signatures use the SSH signature format (`ssh-keygen -Y sign`, Ed25519), so authors sign with tools they already have. Adding a trusted signer is CRITICAL; a module update signed by a different signer needs manual review. The executor verifies the artifact hash at run time; server-side trust status alone is never enough.

**First-party signing key.** Official releases and first-party signed artifacts are rooted in an **offline Ed25519 signing key**. The private root key is never present in GitHub Actions or another online CI worker. The public key ships in the repository and release/install metadata. Rotation is authorized by signed rotation metadata, old public keys remain available for verification of historical releases, and an encrypted recovery copy of the private key is kept on separate offline media.

**Effective risk** = max(declared risk, scanner finding, trust floor). Unverified scripts running as root are at least HIGH. The Safety Scanner is an advisory pattern list that only raises risk: destructive filesystem commands, network and firewall changes, users and groups, package removal, reboot, bootloader, Docker removal, download-and-execute, `eval`, encoded payloads such as `base64 -d | sh`.

**Runbooks** are local modules with a single action: versioned scripts, parameters, secret parameters, declared risk, pre- and postchecks, OS compatibility. Versions are immutable; editing creates a new version, and every execution keeps a reference to the exact artifact it ran.

**Bootstrap** is an ordinary module (`install`, `verify`, `update`, `uninstall`) that may deliberately install services on a host. Components deployed through Nebula are recorded in `/var/lib/nebula/inventory.json` on the host, without credentials.
