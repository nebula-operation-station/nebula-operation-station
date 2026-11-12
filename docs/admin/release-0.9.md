# Release 0.9 (beta) checklist

Maintainer checklist for the first beta, `v0.9.0-beta.1`, from the tag to the published GitHub release. It follows [release signing](release-signing.md) (offline procedure, scripts, rules) and [ADR 0015](../adr/0015-integrity-monitoring.md) D2 (per-version publication of the signed hash list). Where this list and `release-signing.md` disagree, `release-signing.md` and [spec 10](../spec/10-modules.md#release-signing) win.

Items marked **OPEN** are gaps on `main` (state 2026-11-12, re-checked after rl01–rl04; details in [Implementation status](release-signing.md#offline-release-signing)). Items marked [x] with "previously" were OPEN and are closed on `main`. Each one needs either a change or an explicit, recorded maintainer decision before the release is published. Do not work around one by skipping a check.

Names used below: the tag is `v0.9.0-beta.1`; GoReleaser strips the `v`, so the release version in file names, binaries and every signed document is `0.9.0-beta.1`.

## 1. Before tagging

- [ ] CI on the release commit is green (`make check` on the PR, protected-path check).
- [ ] The Release 0.9 items in `docs/implementation/m0.md` ("Known gaps") are done or explicitly accepted, in particular the real-OpenSSH run against the test VMs and the full install in the reference lab.
- [ ] Branch protection with required code-owner review is configured on GitHub (m0.md known gap).
- [ ] Every **OPEN** item below has an owner and a decision (do it for 0.9, or ship 0.9 without it and say so in the release notes).

## 2. Tag

- [ ] A GitHub draft release `v0.9.0-beta.1` already exists (maintainer information; it is not visible from the repository). Make sure it points at this tag and holds no assets the workflow does not produce (the release workflow refuses such a draft).
- [ ] Create the annotated tag `v0.9.0-beta.1` on the reviewed release commit. A human creates and pushes it; agents never push. Pushing the tag starts the release workflow.

## 3. Build

The payloads come from the release workflow `.github/workflows/release.yml` (see [Release workflow](release-signing.md#release-workflow-source-of-the-payloads)); previously they were built on a maintainer machine. It runs `make check` and `make release-stage VERSION=0.9.0-beta.1` (GoReleaser with `.goreleaser.yaml`, config `version: 2`, plus `nebula-release-stage`) on the tag, keeps `staging/` as the workflow artifact `nebula-release-staging-0.9.0-beta.1` (30 days) and attaches `payloads/` to the draft. It never signs and never publishes. `make build` only builds `bin/` for development and produces no release artifacts.

Flow: tag → workflow → artifact checked offline, hashes recomputed → `make-manifest.py` → signature with the YubiKey → `release-manifest.json` and `.sig` attached to the draft → publish.

- [ ] The release workflow run for `v0.9.0-beta.1` is green (both jobs). If it fails, fix on `main` and tag a new version, or re-run it by hand (`workflow_dispatch` with the tag) only while the draft holds no manifest or signature. If the draft job failed or was cancelled, the draft may be partly updated: do not review it, re-run until the draft job is green (see [Release workflow](release-signing.md#release-workflow-source-of-the-payloads)).
- [ ] Record the workflow run URL, the GoReleaser version (`GORELEASER_VERSION` in the workflow, also in the build log) and the Go version (`GO_VERSION` in the workflow, pinned exactly; the build job's `go_version` output, run summary and draft notes show it, e.g. `go1.26.9`). Previously the Go version was not pinned or recorded.
- [ ] The build job ran on a GitHub-hosted runner (`ubuntu-24.04`, fresh VM, no caches), not on a self-hosted runner.
- [ ] Check in the build log and the artifact that GoReleaser produced these files (previously: checked in a local `dist/`):
  - `nebula_0.9.0-beta.1_linux_amd64.tar.gz` and `nebula_0.9.0-beta.1_linux_arm64.tar.gz`: the six binaries (`nebula`, `nebula-server`, `nebula-executor`, `nebula-discovery`, `nebula-pve-collector`, `nebula-netdev-collector`) plus the allowlisted `deploy/` files;
  - `nebula-operation-station_0.9.0-beta.1_amd64.deb` and `..._arm64.deb`;
  - `nebula_0.9.0-beta.1_checksums.txt` (a convenience file; it establishes no trust);
  - the local image `ghcr.io/nebula-operation-station/nebula:0.9.0-beta.1` (amd64 only; not a file, not pushed).
- [x] Release workflow: done (previously **OPEN**: "`.github/workflows/ci.yml` has no release job and runs no GoReleaser; the build runs on a maintainer machine. The GoReleaser version is not pinned in the repository"). `.github/workflows/release.yml` builds on the tag with a pinned GoReleaser. Reproducible builds are ADR 0015 IG-11 and still not done.
- [x] `builtins.tar` (previously **OPEN**: "No tool on `main` builds it, and GoReleaser does not."). `make release-stage VERSION=0.9.0-beta.1` builds it with `internal/release/stage` `BuildBuiltins` (uncompressed ustar, one nested `modules/<name>/<version>.tar` per built-in module, at most 80 MiB) and stages `payloads/builtins.tar` and `module-bytes/`. Before signing, still review each module against the manifest (section 4 and 5); `bin/nebula-release-check` (section 7) validates the bundle with `VerifyBundle`.
- [x] `installed-files.json` (previously **OPEN**: "`internal/release.GenerateInstalledFiles` exists as a library function only"). `make release-stage VERSION=0.9.0-beta.1` stages `installed/<flavour>/` for `deb:amd64`, `deb:arm64`, `tarball:amd64`, `tarball:arm64` and `container:amd64` (the container tree is exported from the locally built image, which need not be pushed) and writes `payloads/installed-files.json` with `GenerateInstalledFiles` (release version `0.9.0-beta.1`). Tests: `internal/release/stage/stage_test.go`.
- [ ] **OPEN question:** `install.sh` copies `release-manifest.json`, its signature and `builtins.tar` into `/usr/share/nebula/release`, a covered prefix. `installed-files.json` cannot list the manifest or the signature (the manifest records the list's hash), so decide how those two files are treated before the I1 checks are switched on.

## 4. Staging for the offline station

Follow "Build and review the release manifest" in `release-signing.md`. The staging is the workflow artifact `nebula-release-staging-0.9.0-beta.1` (previously: assembled by hand on the build machine); download it before it expires after 30 days.

- [ ] `payloads/`: exactly the files to publish: both tarballs, both `.deb`, the checksums file if it is published, `builtins.tar` and `installed-files.json`. Nothing else: no manifest, no signature, no rotation documents.
- [ ] `module-bytes/<name>/<version>.tar`: the exact nested module tars from the reviewed `builtins.tar`, extracted with the strict validator, never with plain `tar -xf`.
- [ ] `installed/<flavour>/`: the staged trees for the offline recheck of `installed-files.json`.
- [ ] Copy the staging to removable media; on the disconnected station recompute every SHA-256 independently and compare with the workflow's build log and the draft's assets (the artifact's `SHA256SUMS` is a transfer check, not a trust anchor). Keep the staging read-only from here on.

## 5. Manifest

- [ ] On the offline station: `python3 make-manifest.py 0.9.0-beta.1` (script in `release-signing.md`). It writes `release-manifest.json` (JCS, no trailing newline) and refuses an existing file.
- [ ] `python3 check-installed-files.py 0.9.0-beta.1` must report a match.
- [ ] `artifacts` lists `installed-files.json` exactly once. `make-manifest.py` refuses a staging without it, and `internal/release.ParseManifest` requires exactly one (previously: neither enforced it, and it had to be checked by hand).
- [ ] Read the whole manifest as text: names, sizes, hashes, every built-in module once, `release_version` `0.9.0-beta.1`.

## 6. Signature (Axel, root-1)

- [ ] Axel connects the root-1 YubiKey only after the review and signs: `ssh-keygen -Y sign -f root-1 -n nebula-release -O hashalg=sha512 release-manifest.json`, touching the key when prompted. Output: `release-manifest.json.sig`.
- [ ] Check root-1's public key against the fingerprint recorded in `release-signing.md` before building `allowed-signers`.
- [ ] Disconnect the token. The key handle file, PIN and passphrase never leave the offline station.
- [ ] **OPEN: root-2.** No backup root is generated or enrolled (`rootkeys.txt` holds an empty `root-2` placeholder). If root-1 or its handle is lost there is no recovery path. Enrolling it also needs rotation admission on installations (`trust.Store.ApplyRotation` has no RPC or command yet), so 0.9 ships without a `root-rotation.json`.

## 7. Verification

- [ ] `ssh-keygen -Y verify` as in `release-signing.md`. This proves the signature, **not** user presence.
- [ ] Maintainer check with `bin/nebula-release-check <staging>` (previously **OPEN**: "No command checks a staged release with the security-key-aware verifier outside the executor."). Run `make build` once, then `bin/nebula-release-check <staging>` on the offline copy of the staging with `release-manifest.json`, `release-manifest.json.sig` and `payloads/`. It checks the signature against the compiled root anchors (security key, user presence required) and the size and SHA-256 of every payload, `builtins.tar` with `VerifyBundle` and `installed-files.json` with `VerifyInstalledFiles`; it exits 0 only when everything matches. It reads only and uses no network. `ssh-keygen -Y verify` above remains a signature check only.
- [ ] Optional, as a separate test of the executor's own review: on a disposable test installation put the three bundle files into `/usr/share/nebula/release` and run `nebula artifact trust-builtins` as the admin user. The executor verifies the manifest against its root state (user presence required) and `builtins.tar` against the manifest before it shows the review; enter nothing at the digest prompt to abort without committing. This covers the manifest and `builtins.tar`, not the other payloads.
- [ ] Recompute the SHA-256 of every payload against the signed manifest once more, on a second machine.

## 8. GitHub release

Follow "Publish manifest, signature and installed-files.json on GitHub" in `release-signing.md`.

- [ ] The release workflow already attached every payload from `payloads/` to the draft `v0.9.0-beta.1` (previously: uploaded by hand). The draft job already downloaded and hashed every asset; still check yourself that the draft's assets are exactly the reviewed bytes (names, sizes, SHA-256), then upload `release-manifest.json` and `release-manifest.json.sig` by hand. Never rebuild or re-sign on the publication machine, and do not re-run the workflow for this tag after signing.
- [ ] Per-version hash manifest (ADR 0015 D2): `release-manifest.json`, `release-manifest.json.sig` and `installed-files.json` are attached to this version's release. They are attached for **every** later version too.
- [ ] Mark the release as a pre-release (beta).
- [ ] Release notes: what is in the beta, the open items that ship unresolved (at least root-2, rotation admission, integrity checks, `nebula verify`), and that GitHub, checksums and keys shown beside the files establish no trust; only the signature against the root compiled into the binaries does.
- [ ] Container image: push `ghcr.io/nebula-operation-station/nebula:0.9.0-beta.1` by hand, or state in the release notes that 0.9 ships without an image.
- [ ] Publish the draft. Then download all assets on a different machine and compare their SHA-256 with the offline copies.
- [ ] Never replace an asset of a published version; a fix is a new version (`v0.9.0-beta.2`).

## 9. After publication

- [ ] Note the release in `docs/implementation/m0.md` and turn every OPEN item that is still open into an issue.
- [ ] Keep the offline staging, the manifest and the signature archived with the release.
