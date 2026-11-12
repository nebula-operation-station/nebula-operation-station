# Release notes: Nebula Operation Station 0.9.0-beta.1

> **Draft, not published.** Maintainer review required before the GitHub draft release `v0.9.0-beta.1` is published. Statements are checked against the repository state on `main` as of 2026-11-12; each one names its source in brackets.

This is a **pre-release (beta)**. Read the open items before you install it. Several parts of the release trust chain are not finished, and this release does not provide the checks described in the final design.

## Trust: what establishes that a file is genuine

Only the signature counts. The release manifest `release-manifest.json` and its signature `release-manifest.json.sig` are checked against the root public keys compiled into the NOS binaries, and only after that is the SHA-256 of `installed-files.json` compared with the manifest ([ADR 0015](../adr/0015-integrity-monitoring.md) D2: "GitHub is only a distribution channel, never a trust anchor").

The following establish **no trust** on their own:

- the GitHub release page, its download URLs and its asset names;
- the checksums file `nebula_0.9.0-beta.1_checksums.txt` ([release-0.9.md](release-0.9.md) section 3: "a convenience file; it establishes no trust");
- SHA-256 values shown beside the files on GitHub, and the staging artifact's `SHA256SUMS` (a transfer check only, [release-0.9.md](release-0.9.md) section 4);
- public keys published beside the files.

Compare the SHA-256 of each file with the signed manifest. A matching hash that is not checked against a valid signature proves nothing.

The signature check on this release is limited: `ssh-keygen -Y verify` does not enforce user presence and is not a trust check ([release-signing.md](release-signing.md), "Verification limitation"). The only security-key-aware check in the repository is the executor's review in `nebula artifact trust-builtins` on a test installation, and it covers only the manifest and `builtins.tar` ([release-0.9.md](release-0.9.md) section 7; [release-signing.md](release-signing.md) "Missing" item 4).

## What is in the beta

Based on the implementation status lines in the repository:

- **Security prototype (milestone 0).** UID separation, `SO_PEERCRED` method sets, canonical requests (RFC 8785), permit digests, executor-side artifact hashing, executor-side WebAuthn verification, CLI unlock into the in-process keyring. Acceptance criteria are covered by tests in `test/security/`. [m0.md](../implementation/m0.md) ("What exists").
- **Runbooks and modules (milestone 7).** Status: implemented 2026-10-19. [m7-plan.md](../implementation/m7-plan.md).
- **Network inventory, IPAM and discovery (milestone 9).** Status: implemented 2026-10-19. [m9-plan.md](../implementation/m9-plan.md).
- **Hardening (milestone 10).** Status: implemented 2026-10-19. The scope is the list in the plan's "What the spec asks for" section (for example executor-signed events, the optional audit hash chain, backup and restore). The plan states that the beta "waits for the reference-lab run" ([m10-plan.md](../implementation/m10-plan.md)). [spec 16](../spec/16-milestones.md) lists the same milestone as "Release 0.9 beta".
- **Release signing, verifying side.** Security-key signature verification (`internal/sshsig`), the release document parsers and verifiers (`internal/release`), and executor admission of the built-in bundle through `nebula artifact trust-builtins` ([release-signing.md](release-signing.md), "Implemented and tested on `main`").
- **Release workflow.** `.github/workflows/release.yml` builds the unsigned payloads on a `v*` tag with a pinned GoReleaser and attaches them to a draft release. Signing and publication stay manual ([release-signing.md](release-signing.md) "Missing" item 3; [release-0.9.md](release-0.9.md) section 3).
- **Container updates, phase 2 steps P2-01 and P2-02.** Status line: done ([container-updates.md](../implementation/container-updates.md), header). Steps P2-03 to P2-05 are not marked done; the header reads "decided, cu01 in progress".

The [README](../../README.md) states that the code for Release 0.9 is complete and that "the lab run on real hosts is still pending". The status lines above mark only milestones 0, 7, 9 and 10 as implemented. Milestone 6 (stage engine) is approved but has no implementation status line ([m6-plan.md](../implementation/m6-plan.md)); this draft does not claim it as done. The maintainer should reconcile the README with these lines before publication.

Not in the beta, by the status lines: network devices beyond ND-01 (decision only, [network-devices.md](../implementation/network-devices.md)), vulnerability management beyond VU-01 (decision only, [vulnerability-management.md](../implementation/vulnerability-management.md)), and the in-progress container update work above.

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
7. **Open question on bundle files.** `deploy/install.sh` copies the manifest, its signature and `builtins.tar` into `/usr/share/nebula/release`. `installed-files.json` cannot list them, and how they are treated is not yet decided ([release-0.9.md](release-0.9.md) section 3).
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
    - *Option A:* The container image `ghcr.io/nebula-operation-station/nebula:0.9.0-beta.1` is published with this release.
    - *Option B:* Release 0.9.0-beta.1 ships without a container image.

## Install and verify

- Install instructions: [operator handbook](guide.md), section 3 "Installation" (3.3 "In containers" and section 12.4 "Container installs" for container installs).
- Offline release signing and the verification steps: [release-signing.md](release-signing.md).

This draft adds no new commands. The repository does not yet define an end-user command that verifies a downloaded release against the compiled root keys (see items 6 and 10 above). Until it does, verification is the maintainer procedure in [release-signing.md](release-signing.md), and a user cannot independently confirm the signature with the tools in this release.
