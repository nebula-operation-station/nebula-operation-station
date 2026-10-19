# Milestone 7 plan: runbooks and modules

Status: **implemented 2026-10-19** with the defaults below (PRs #41–#47,
decisions 63–69 in m0.md). Each decision can still be changed. Deviation:
module state is the module's own action results per host (decision 69),
not a separate key/value store. It turns spec 10 (modules, runbooks, trust) and spec 16
(Milestone 7, Release 0.3) into a concrete plan.

## What the spec asks for

- Spec 10: modules (`module.yaml`, host scripts, checks, schemas,
  declarative UI), never code on the Nebula machine, never past the
  executor. Trust states Verified / Local / Unverified; SSH signatures
  (`ssh-keygen -Y sign`, Ed25519); adding a trusted signer is CRITICAL; an
  update signed by a different signer needs manual review; the executor
  verifies the artifact hash at run time. Effective risk = max(declared,
  scanner finding, trust floor); unverified root scripts are at least HIGH.
  The Safety Scanner is advisory and only raises risk. Runbooks are local
  single-action modules with versioned, immutable scripts, parameters,
  secret parameters, declared risk, pre- and postchecks, OS compatibility.
- Spec 06: secret parameters travel over the SSH channel, and only as a
  tmpfs file under `/run/nebula/<execution-id>/` (0700/0600), deleted after
  use; never in jobs, results, state, audit or logs.
- Spec 16, Milestone 7: manifest, immutable versions, secret slots, trust
  states, SSH signatures, advisory scanner, declarative UI, module state
  isolation. Accept: *an unverified root script is at least HIGH; a module
  UI cannot inject script.*

## What exists

- The executor already derives a risk floor from data it holds
  (`internal/riskpolicy`): trusted artifacts (`nebula artifact trust`) and
  host criticality; an untrusted artifact is HIGH. The first acceptance
  criterion holds for any script today.
- Actions are a built-in catalog (`internal/executions/actions`); the
  server looks them up in four places. Scripts read parameters from the
  canonical JSON (`$NEBULA_PARAMS`) with the same strict pattern the server
  checks.
- The vault holds secrets (admin CLI); nothing passes them to hosts yet.

## Parts, in order

### M7-1 Safety Scanner (executor and server)

`internal/scanner`: a fixed, versioned pattern list over the script bytes.
Each finding has a category and a risk:

| Category | Examples | Risk |
| --- | --- | --- |
| download and execute | `curl … \| sh`, `wget -O- … \| bash` | HIGH |
| eval / encoded payload | `eval`, `base64 -d \| sh`, `xxd -r -p \| sh` | HIGH |
| destructive filesystem | `rm -rf /`, `mkfs`, `dd of=/dev/…`, `wipefs`, `shred` | HIGH |
| bootloader / kernel | `grub-install`, `update-grub`, `efibootmgr` | HIGH |
| users and groups | `useradd`, `usermod`, `passwd`, `chpasswd`, `visudo`, sudoers | MEDIUM |
| network and firewall | `iptables`, `nft`, `ufw`, `ip route`, `netplan apply` | MEDIUM |
| package removal | `apt-get remove/purge`, `dpkg -r/-P` | MEDIUM |
| reboot / power | `reboot`, `shutdown`, `systemctl reboot/poweroff` | MEDIUM |
| Docker removal | `docker rm`, `docker system prune`, `docker volume rm` | MEDIUM |

- **The executor** adds the scanner as a third floor source in
  `riskpolicy` (it can only raise; the reason names the categories, not the
  server). The server shows the same findings in the UI before approval.
- **Decision 1 (default):** the scanner applies to trusted artifacts too.
  An admin who trusts a reboot script as LOW still gets MEDIUM. Built-in
  read-only scripts must stay clean (a test pins every built-in's findings).

### M7-2 Runbooks (server, UI, execution)

- Storage (`server.db`): `runbooks` and `runbook_versions`. A version is
  never changed or deleted (SQL triggers refuse it); saving creates
  version N+1. Every execution already keeps action ID, version and
  artifact hash, so it always refers to the exact bytes it ran.
- Identity: action ID `runbook.<slug>`, module version `N.0.0`.
- **Decision 2 (default): typed parameters, no free-form strings.** Types
  `name` (`[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}`), `int` (1–9 digits), `path`
  (absolute, `[A-Za-z0-9._/-]`, no `..`), `choice` (fixed list of `name`
  values). The artifact is a generated prelude plus the author's script:
  the prelude re-reads each parameter from `$NEBULA_PARAMS` with the same
  pattern and exports it as `NEBULA_P_<NAME>`, or exits with
  `precheck_failed`. The prelude is part of the hashed, approved bytes.
- Risk: declared by the author; the executor's floor applies as for any
  script. **Decision 3 (default):** a new runbook version is *Local* on the
  server but untrusted on the executor, so it runs at least HIGH (fresh
  security key) until the admin trusts that exact version on the executor
  (`nebula artifact trust`, or later the browser flow in M7-4).
- Attached or durable, timeout, retry class (`never` default,
  `reconcile-first` for durable), OS compatibility (`debian>=12`, …,
  checked against host facts at planning; advisory, not a security
  boundary).
- The operation planner lists runbooks next to built-ins; the server's
  action lookup becomes one function over both.

### M7-3 Secret slots

- A runbook declares secret slots (`influx_token`); planning maps each slot
  to a vault secret **name**. The mapping is part of the canonical
  parameters (`{"params":{…},"secrets":{"influx_token":"telegraf-influx"}}`),
  so it is hashed into the approval and shown on the approval screen.
- **Decision 4 (default):** a request that uses any secret is at least
  MEDIUM on the executor (never auto-approved by a session click).
- The executor reads the secret from the vault at run time and sends it on
  the SSH channel; the host bootstrap writes it to
  `/run/nebula/<execution-id>/secrets/<slot>` (tmpfs, 0700/0600) and
  removes the directory when the script ends, for attached and durable
  runs. The script gets `NEBULA_SECRET_<SLOT>` = the file path, never the
  value. Known secret values are redacted from log and result as an extra
  safeguard.
- The server can list secret names (not values) for the planner; values
  never leave the executor except to the host.

### M7-4 Trust flows

- **Browser trust of a runbook version** (like schedule grants): the
  executor builds a challenge over (artifact hash, action, version, risk);
  a user-verified assertion trusts that exact version at the declared risk.
  Hardened mode: CLI only.
- **Signers.** `nebula signer add` on the executor host only (CRITICAL:
  CLI with a typed confirmation of the key fingerprint). Ed25519 SSH keys;
  the executor verifies `SSHSIG` signatures itself (namespace
  `nebula-module`).

### M7-5 Modules

- A module is a directory or tarball with `module.yaml` (spec 10 shape)
  and its files, plus `module.yaml.sig` for signed modules. The executor
  checks the signature over a canonical manifest that lists every file's
  SHA-256; a verified manifest makes its declared risks the trust floor
  (instead of HIGH), still raised by the scanner and host criticality.
- **Decision 5 (default):** an update signed by a different signer than
  the installed version is treated as Unverified until the admin confirms
  it on the executor host.
- Import through the server UI (upload) or the CLI; versions immutable like
  runbooks; prechecks and postchecks are module actions run by the core
  before and after the main action.

### M7-6 Declarative UI and module state

- Host tabs, cards and tables from `ui:` metadata, rendered by core
  templates only: text cells bound to result JSON paths, no HTML, no
  module JavaScript, no module-provided labels in privileged dialogs.
  Acceptance test: hostile metadata (`<script>`, `javascript:` URLs, event
  attributes, bidi controls) renders inert.
- Module state: a core key/value table namespaced per module, written only
  from a result's `state` object (bounded), read by the module's UI
  metadata. No SQL against the core database.

## Order and releases

M7-1 → M7-2 → M7-3 → M7-4 → M7-5 → M7-6, each its own PR with a Hermes
review; Release 0.3 after M7-6 and the acceptance tests.
