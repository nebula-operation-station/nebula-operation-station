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

<a id="v23-10-01"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-10-01 -->
**Read-only contract allowlist.** Standing grants initially cover `core.facts`, `package.list_updates`, `docker.list`, `docker.inspect`, `docker.check_updates`, `service.list` and `service.status`, only at effective LOW risk with an explicitly approved read-only contract. Bind exact container incarnation/unit parameters for inspection/status; enumeration does not authorize arbitrary follow-ups. Exclude `package.refresh` because it writes package metadata even if declared LOW, and exclude `docker.logs` and all secret-bearing actions. Neither declared LOW nor a clean scanner result proves harmlessness. Typed PVE readers are built-in provider methods, never generic HTTP proxies or server plugins.

<a id="v23-10-02"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-10-02 -->
**Additional observation contracts.** ADR 0006 permits the following reviewed additions, each requiring its own exact parameter/cost/timeout limits and effective LOW eligibility before inclusion in a grant. Unknown tools, drivers or privileges yield unavailable, never a successful zero; reject malformed numbers, unsupported schemas and changed incarnations. Reuse the existing read-only SSH action pipeline, without another SSH collector or guest exec.

<a id="v23-10-03"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-10-03 -->
| Action | Read-only scope |
| --- | --- |
| `host.metrics`, `filesystem.list` | Bounded CPU/RAM percentages and per-filesystem used/total/percent, fullest filesystem plus mount details |
| `pci.inventory`, `gpu.status` | NVIDIA PCI identity; fixed `nvidia-smi --query-gpu` fields for UUID/PCI ID, utilization, VRAM used/total, temperature and power; no arbitrary flags/command or device changes |
| `docker.stats` | One bounded non-streaming CPU/RAM snapshot keyed by full container ID; validated list/inspect hints for Compose grouping |
| `service.check` | Bounded HTTP/TCP health/latency from an enrolled host, exact approved destination/port, no redirects, generic URLs or response bodies; unknown if unconfigured |
| `image.vulnerabilities` (optional) | Sanitized unique CVE counts/severity, immutable local image identity and scanner/database age from operator-installed host-local Trivy; no installation, image pull or database refresh |

<a id="v23-10-04"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-10-04 -->
**Local built-in bundle review.** `nebula artifact trust-builtins` is executor-local admin CLI only in both modes. Read a bounded bundle from a locally verified NOS release under the existing release trust root; a server-exported directory does not establish provenance. The executor hashes exact candidate bytes and retains prior trusted built-in bytes/manifest. Show action-by-action old/new versions, hashes, risks/contracts, full script diffs and executor scanner findings; new actions appear in full, removals explicitly. On first use or missing prior bytes require full review, never infer unchanged. Unchanged actions need no confirmation. Reject same-version changed bytes and invalid provenance. Exact bundle/manifest size limits and provenance packaging remain [open questions](17-frozen-decisions.md).

<a id="v23-10-05"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-10-05 -->
**Atomic built-in trust.** One local confirmation commits all displayed additions/changes atomically, bound to the reviewed manifest digest. Rehash candidate bytes and compare trust-store generation before commit to reject substitution/concurrent changes. No browser bulk-trust endpoint is created; individual trust operations remain available. Record admin UID and every old/new trust tuple. Retain or retire old versions explicitly; retirement revokes affected authority, never retargets it. Scanner/host floors still apply. Trust does not approve a mutation or update an existing lease to new bytes; approve a replacement grant for a new version. The ADRs set no independent trust-record expiry; normal trust withdrawal and per-run checks remain effective.

<a id="v23-10-06"></a>
<!-- Spec v2.3 (ADR 0006, ADR 0007): v23-10-06 -->
**Built-in trust status.** Show the executor-verdict banner “Built-ins are untrusted: every operation using them needs UV until you trust them.” Include the local CLI command and affected versions; distinguish unreachable from untrusted and explain read-lease replacement. Trust may restore declared risk but never bypasses host criticality or the read-only contract requirement.
