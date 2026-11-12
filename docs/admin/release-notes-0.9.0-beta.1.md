# Release notes: Nebula Operation Station 0.9.0-beta.1

> **Draft, not published.** Maintainer review required before the GitHub draft release `v0.9.0-beta.1` is published. Statements are checked against the repository state on `main` as of 2026-11-12; each one names its source in brackets.

This is a **pre-release (beta)**. Read the open items before you install it. Several parts of the release trust chain are not finished, and this release does not provide the checks described in the final design.

## Trust: what establishes that a file is genuine

**Target design (not implemented in this release):** only the signature counts. The release manifest `release-manifest.json` and its signature `release-manifest.json.sig` are to be checked against the root public keys compiled into the NOS binaries, and only after that is the SHA-256 of `installed-files.json` to be compared with the manifest ([ADR 0015](../adr/0015-integrity-monitoring.md) D2: "GitHub is only a distribution channel, never a trust anchor"; [release-signing.md](release-signing.md) "Publish manifest, signature and installed-files.json on GitHub"). In this release, no process checks `installed-files.json` (see open items 9, 10 and 11).

The following establish **no trust** on their own:

- the GitHub release page, its download URLs and its asset names;
- the checksums file `nebula_0.9.0-beta.1_checksums.txt` ([release-0.9.md](release-0.9.md) section 3: "a convenience file; it establishes no trust");
- SHA-256 values shown beside the files on GitHub, and the staging artifact's `SHA256SUMS` (a transfer check only, [release-0.9.md](release-0.9.md) section 4);
- public keys published beside the files.

A matching hash that is not checked against a valid signature proves nothing. Apart from the bundle review in `nebula artifact trust-builtins` (manifest and `builtins.tar` on an installation, see below), no command in this release compares the files of a download with the signed manifest for you; the comparison of the whole release is the maintainer procedure in [release-signing.md](release-signing.md) and is not yet available to end users.

What this release does check, and how far it goes:

- `ssh-keygen -Y verify` does not enforce user presence and is not a trust check ([release-signing.md](release-signing.md), "Verification limitation").
- The only security-key-aware check in the repository is the executor's admission review in `nebula artifact trust-builtins`. It is a local review on one installation, not a release-wide check. The administrator must put the three bundle files (`release-manifest.json`, `release-manifest.json.sig`, `builtins.tar`) into `/usr/share/nebula/release` and run the command as the admin user. `deploy/install.sh` always creates that directory, but it copies the three files into it only when they sit next to the script or are passed with `--release-bundle-dir` (or `NEBULA_RELEASE_BUNDLE_DIR`). Otherwise the directory stays empty, and the web banner "Built-in trust status is unreachable" remains. `deploy/deb` does not provision the directory; its `postinst` only points to `install.sh`. No `builtins.tar` builder exists, so this release has no bundle files to supply. The executor verifies the manifest signature (user presence required) against its durable root state, which is bootstrapped from the compiled anchors, and `builtins.tar` against the manifest. It covers nothing else, in particular not `installed-files.json` or the other release payloads. The maintainer procedure still describes this step as "on a disposable test installation" ([release-signing.md](release-signing.md) "Executor admission of built-ins" and "Missing" item 4; [release-0.9.md](release-0.9.md) item "OPEN: maintainer verifier").

## What is in the beta

Milestone by milestone, as recorded in the repository on `main`:

- **Milestone 0 (security prototype): implemented.** UID separation, `SO_PEERCRED` method sets, canonical requests (RFC 8785), permit digests, executor-side artifact hashing, executor-side WebAuthn verification, CLI unlock into the in-process keyring. Acceptance criteria are covered by tests in `test/security/`. [m0.md](../implementation/m0.md) ("What exists").
- **Milestones 2 to 5: implemented.** Web UI and login, TOTP recovery, vault, inventory page, notifications, attached and durable runs, operations in the web UI, and the os-debian update check, install and reboot actions. [m0.md](../implementation/m0.md) ("What exists", rows M2 to M5).
- **Milestone 6 (stage engine): no milestone status is recorded as closed.** The closing note under m0.md "Known gaps" (line 145) lists "stages, gates and scheduled checks exist (decisions 59–62)" among the gap items closed since the earlier list ([m0.md](../implementation/m0.md) "Known gaps"). It does not declare the milestone done. Decisions 59 and 60 record the executor stage engine (M6-1) and the server presets and gates (M6-2). Decisions 61 and 62 record schedule grants and scheduled read-only checks ([m0.md](../implementation/m0.md) "Decisions taken during implementation"). [m6-plan.md](../implementation/m6-plan.md) is "approved 2026-10-15"; its "Status" section records only steps 1 and 2 (decisions 59 and 60), not the schedule work of decisions 61 and 62.
- **Milestone 7 (runbooks and modules): implemented 2026-10-19.** [m7-plan.md](../implementation/m7-plan.md).
- **Milestone 8 (Docker): code on `main`; no milestone status is recorded in the repository.** Spec 16 (item 8, "Release 0.4") lists detection, standalone and Compose inventory, logs, start/stop/restart, digest checks and manual Compose update with postflight. The built-in actions on `main` that cover these are `docker.list`, `docker.logs`, `docker.inspect`, `docker.start`, `docker.stop`, `docker.restart`, `docker.check_updates` and `docker.compose_update` (registered as 2.0.0), and also `docker.stats`, `docker.update_preview` and `docker.update_prepare` ([actions.go](../../internal/executions/actions/actions.go)). The operator handbook describes the container operations ([containers.md](../handbook/containers.md)). The README status line lists Docker among the 0.9 code that is complete. m0.md decision 58 ([m0.md](../implementation/m0.md) "Decisions taken during implementation", decision 58) is out of date: it calls `docker.list` "the first part of Milestone 8", documents `docker.compose_update` as 1.0.0, and does not mention `docker.stats`, `docker.update_preview` or `docker.update_prepare`. It records no milestone status, so whether Milestone 8 is complete is an open point for the maintainer.
- **Milestone 9 (network inventory, IPAM and discovery): implemented 2026-10-19.** [m9-plan.md](../implementation/m9-plan.md).
- **Milestone 10 (hardening): implemented 2026-10-19.** The scope is the list in the plan's "What the spec asks for" section (for example executor-signed events, the optional audit hash chain, backup and restore). The plan states that the beta "waits for the reference-lab run" ([m10-plan.md](../implementation/m10-plan.md)). [spec 16](../spec/16-milestones.md) lists the same milestone as "Release 0.9 beta".
- **Release signing, verifying side.** Security-key signature verification (`internal/sshsig`), the release document parsers and verifiers (`internal/release`), and executor admission of the built-in bundle through `nebula artifact trust-builtins` ([release-signing.md](release-signing.md), "Implemented and tested on `main`").
- **Release workflow.** `.github/workflows/release.yml` builds the unsigned payloads on a `v*` tag with a pinned GoReleaser and attaches them to a draft release. Signing and publication stay manual ([release-signing.md](release-signing.md) "Missing" item 3; [release-0.9.md](release-0.9.md) section 3).
- **Proxmox provider actions (P2-01) and tree-staged OS updates (P2-02): done**, per the introduction of [container-updates.md](../implementation/container-updates.md) ("P2-01 … and P2-02 … are done"). These are not container updates.
- **Container update and rollback (ADR 0006 P2-03 to P2-05): not finished.** The plan header reads "decided, cu01 in progress" ([container-updates.md](../implementation/container-updates.md)). The executor actions `docker.update`, `docker.rollback` and `docker.compose_rollback` exist on `main`, but m0.md "Known gaps" (row on standalone containers, [m0.md](../implementation/m0.md) line 143) says standalone updates stay unavailable until a `docker.update` batch planner exists. Which of these actions the beta exposes to users is not recorded in the repository and needs the maintainer's answer before publication.

The [README](../../README.md) roadmap says "Release 0.9 (milestones 0–10): code complete; lab run on real hosts pending". The milestones above agree with that. Two points need the maintainer before publication, and the repository does not settle either one:

- Whether Milestone 6 and Milestone 8 are complete. The repository records no closed status for either. m0.md "Known gaps" (line 145) and decision 58 (line 97) do not record one, and decision 58 is out of date (see Milestone 8 above).
- Whether container updates with rollback (ADR 0006 P2-03 to P2-05) belong to the 0.9 scope.

This draft does not change the README. The lab run on real hosts is pending.

Not finished, per the status lines and the README:

- **Network devices.** [network-devices.md](../implementation/network-devices.md) records ND-01 and ND-18 part 1 as done. The README records the collector, deployment, store and device pages as merged, and ingest, the firewall view and the IPAM and traffic-map integration as in progress. The CBS parsers exist (`internal/cbsparse`). The beta therefore contains read-only network device code, but the server-side ingest and the firewall view are not finished.
- **Vulnerability management.** [vulnerability-management.md](../implementation/vulnerability-management.md) records only VU-01 as done. The code on `main` is further along: the server-side packages (`internal/vuln*`) are wired into the `nebula-server` binary ([vuln.go](../../cmd/nebula-server/vuln.go)), and `cmd/nebula-vuln-agent` exists. The README says "the server side of vulnerability management is merged" and that the in-repo vulnerability agent is in progress. The beta therefore ships server-side vulnerability code. The plan does not record which steps are complete, so these notes do not list a feature set for it.
- **Container updates with rollback** (ADR 0006 P2-03 to P2-05), as described above.

## Ships open

These items are unresolved in this release. None of them is resolved by the beta.

### Signing and release chain

Sources: [release-signing.md](release-signing.md) "Missing" list and [release-0.9.md](release-0.9.md) items marked **OPEN**.

1. **Root-2 is not generated or enrolled.** `rootkeys.txt` holds an empty `root-2` placeholder. If root-1 or its key handle is lost, there is no recovery path ([release-0.9.md](release-0.9.md) section 6).
2. **Rotation admission is missing.** `trust.Store.ApplyRotation` exists, but no RPC or command calls it. An installation cannot admit a `root-rotation.json`, so this release ships without one ([release-signing.md](release-signing.md) "Missing" item 6).
3. **`builtins.tar` has no builder.** Nothing in the repository, and not GoReleaser, produces it. It must be built by hand and checked module by module with `internal/release.ParseModuleTar` before signing ([release-signing.md](release-signing.md) "Missing" item 1; [release-0.9.md](release-0.9.md) section 3).
4. **`installed-files.json` has no producer.** `GenerateInstalledFiles` is a library function only; no command or staging step generates the list for the flavours ([release-signing.md](release-signing.md) "Missing" item 2; [release-0.9.md](release-0.9.md) section 3).
5. **Manifest completeness is not enforced.** Spec 10 makes `installed-files.json` mandatory, but `ParseManifest` and `make-manifest.py` require only `builtins.tar`. The release maintainer checks its presence by hand ([release-signing.md](release-signing.md) "Missing" item 5).
6. **No maintainer-side verifier.** No command outside the executor runs `VerifyManifest` on a staged release ([release-signing.md](release-signing.md) "Missing" item 4; [release-0.9.md](release-0.9.md) section 7).
7. **Open question on bundle files.** `deploy/install.sh` copies the manifest, its signature and `builtins.tar` into `/usr/share/nebula/release` when they are supplied next to it or with `--release-bundle-dir`. `installed-files.json` cannot list them, and how they are treated is not yet decided ([release-0.9.md](release-0.9.md) section 3).
8. **No signed image catalog.** `PveImageCatalog.LoadSigned` is not called by any process, there is no catalog signing procedure, and this release ships no catalog ([release-signing.md](release-signing.md) "Missing" item 8).

### Integrity checks

Source: [release-signing.md](release-signing.md) "Missing" item 7; [ADR 0015](../adr/0015-integrity-monitoring.md) IG-03, IG-04, IG-11.

9. **The I1 self-check is not running.** `internal/integrity` is a library that no process calls.
10. **`nebula verify` does not exist.** There is no such command in `cmd/nebula`. Installations cannot check their installed files against `installed-files.json` (IG-04).
11. **Admission of `installed-files.json` during upgrade does not exist.**
12. **Reproducible builds are not done** (IG-11).

### Testing gaps

Sources: [m0.md](../implementation/m0.md) "Known gaps", risk Medium; [release-0.9.md](release-0.9.md) section 1; [m10-plan.md](../implementation/m10-plan.md).

13. **Real OpenSSH is tested only on the test VMs**, on Debian 12, Ubuntu 22.04 and 24.04. It is not run in CI. The run against the three VMs and the full install in the reference lab are not yet recorded.
14. **The reference-lab run for milestone 10 is pending.**

### Medium-risk gaps in milestone 0

Source: [m0.md](../implementation/m0.md) "Known gaps", rows with risk Medium.

15. **Branch protection** with required code-owner review is not confirmed. The protected-path checks are tripwires only until this is configured on GitHub (maintainer).
16. **A fully compromised server sees the one-time WebAuthn registration code.** This is detection only: the admin's own attempt fails, and `nebula webauthn list` shows it. It is a documented limit of the threat model.
17. **The event chain and the server's audit live on the Nebula machine.** Root there can rewrite them with the event key. Mitigation is offsite copies (`nebula events list --json`) and backups.

### Container image

18. **Maintainer: keep exactly one of the two sentences below and delete the other.**
    - *Option A:* The container image `ghcr.io/nebula-operation-station/nebula:0.9.0-beta.1` is published with this release. It is **amd64 only** (no arm64 image). The container image push stays manual ([release-signing.md](release-signing.md) "Missing" item 3; [release-0.9.md](release-0.9.md) section 8). Under this option `installed-files.json` also needs a `container:amd64` flavour, which is not yet staged ([release-0.9.md](release-0.9.md) section 3, OPEN item for `installed-files.json`).
    - *Option B:* Release 0.9.0-beta.1 ships without a container image. The `container:amd64` flavour then does not apply: [release-0.9.md](release-0.9.md) section 3 lists it "if the image is published".

## Install and verify

- Install instructions: [operator handbook](guide.md), section 3 "Installation" (3.3 "In containers" and section 12.4 "Container installs" for container installs).
- Offline release signing and the verification steps: [release-signing.md](release-signing.md).

This draft adds no new commands. An installation can run `nebula artifact trust-builtins` to check the manifest signature (user presence required) against its durable root state, which is bootstrapped from the compiled anchors, and `builtins.tar` against the manifest. This works only if the three bundle files were placed in `/usr/share/nebula/release` (see Trust above). This is not a check of a downloaded release: it covers only the bundle in `/usr/share/nebula/release`, not `installed-files.json` or the other payloads. The repository does not yet define an end-user command that verifies a whole downloaded release against the compiled root keys (see items 6 and 10 above). Until it does, that verification is the maintainer procedure in [release-signing.md](release-signing.md).
