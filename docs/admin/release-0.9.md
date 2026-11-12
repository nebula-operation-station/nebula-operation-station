# Release 0.9 (beta) checklist

Maintainer checklist for the first beta, `v0.9.0-beta.1`, from the tag to the published GitHub release. It follows [release signing](release-signing.md) (offline procedure, scripts, rules) and [ADR 0015](../adr/0015-integrity-monitoring.md) D2 (per-version publication of the signed hash list). Where this list and `release-signing.md` disagree, `release-signing.md` and [spec 10](../spec/10-modules.md#release-signing) win.

Items marked **OPEN** are gaps on `main` (state 2026-11-12; details in [Implementation status](release-signing.md#offline-release-signing)). Each one needs either a change or an explicit, recorded maintainer decision before the release is published. Do not work around one by skipping a check.

Names used below: the tag is `v0.9.0-beta.1`; GoReleaser strips the `v`, so the release version in file names, binaries and every signed document is `0.9.0-beta.1`.

## 1. Before tagging

- [ ] CI on the release commit is green (`make check` on the PR, protected-path check).
- [ ] The Release 0.9 items in `docs/implementation/m0.md` ("Known gaps") are done or explicitly accepted, in particular the real-OpenSSH run against the test VMs and the full install in the reference lab.
- [ ] Branch protection with required code-owner review is configured on GitHub (m0.md known gap).
- [ ] Every **OPEN** item below has an owner and a decision (do it for 0.9, or ship 0.9 without it and say so in the release notes).

## 2. Tag

- [ ] Create the annotated tag `v0.9.0-beta.1` on the reviewed release commit. A human creates and pushes it; agents never push.
- [ ] A GitHub draft release `v0.9.0-beta.1` already exists (maintainer information; it is not visible from the repository). Make sure it points at this tag before anything is uploaded.

## 3. Build

`.goreleaser.yaml` (GoReleaser config `version: 2`) is the release build. `make build` only builds `bin/` for development and produces no release artifacts.

- [ ] On the tagged commit, with a clean tree, run `goreleaser release --clean`. Publishing is disabled in the config (`release.disable: true`) and the image has `skip_push: true`, so nothing leaves the machine.
- [ ] Check that `dist/` holds exactly these payloads:
  - `nebula_0.9.0-beta.1_linux_amd64.tar.gz` and `nebula_0.9.0-beta.1_linux_arm64.tar.gz`: the six binaries (`nebula`, `nebula-server`, `nebula-executor`, `nebula-discovery`, `nebula-pve-collector`, `nebula-netdev-collector`) plus the allowlisted `deploy/` files;
  - `nebula-operation-station_0.9.0-beta.1_amd64.deb` and `..._arm64.deb`;
  - `nebula_0.9.0-beta.1_checksums.txt` (a convenience file; it establishes no trust);
  - the local image `ghcr.io/nebula-operation-station/nebula:0.9.0-beta.1` (amd64 only; not a file, not pushed).
- [ ] **OPEN: release workflow.** `.github/workflows/ci.yml` has no release job and runs no GoReleaser; the build runs on a maintainer machine. The GoReleaser version is not pinned in the repository: record the version used. Reproducible builds are ADR 0015 IG-11 and not done.
- [ ] **OPEN: `builtins.tar`.** No tool on `main` builds it, and GoReleaser does not. Spec 10 requires an uncompressed ustar with exactly one `modules/<name>/<version>.tar` per built-in module (each a nested ustar of `module.lock.json` and the files it references), at most 80 MiB. Until a builder exists it must be produced by hand and checked module by module with `internal/release.ParseModuleTar` before signing.
- [ ] **OPEN: `installed-files.json`.** `internal/release.GenerateInstalledFiles` exists as a library function only; there is no command and no staging of the flavour trees. For each flavour (`deb:amd64`, `deb:arm64`, `tarball:amd64`, `tarball:arm64`, and `container:amd64` if the image is published) stage the installed tree under `installed/<flavour>/` as described in `release-signing.md` and generate the list with release version `0.9.0-beta.1`. How to stage the tarball and container trees is not written down yet.
- [ ] **OPEN question:** `install.sh` copies `release-manifest.json`, its signature and `builtins.tar` into `/usr/share/nebula/release`, a covered prefix. `installed-files.json` cannot list the manifest or the signature (the manifest records the list's hash), so decide how those two files are treated before the I1 checks are switched on.

## 4. Staging for the offline station

Follow "Build and review the release manifest" in `release-signing.md`.

- [ ] `payloads/`: exactly the files to publish: both tarballs, both `.deb`, the checksums file if it is published, `builtins.tar` and `installed-files.json`. Nothing else: no manifest, no signature, no rotation documents.
- [ ] `module-bytes/<name>/<version>.tar`: the exact nested module tars from the reviewed `builtins.tar`, extracted with the strict validator, never with plain `tar -xf`.
- [ ] `installed/<flavour>/`: the staged trees for the offline recheck of `installed-files.json`.
- [ ] Copy the staging to removable media; on the disconnected station recompute every SHA-256 and compare with the build machine. Keep the staging read-only from here on.

## 5. Manifest

- [ ] On the offline station: `python3 make-manifest.py 0.9.0-beta.1` (script in `release-signing.md`). It writes `release-manifest.json` (JCS, no trailing newline) and refuses an existing file.
- [ ] `python3 check-installed-files.py 0.9.0-beta.1` must report a match.
- [ ] Check by hand that `artifacts` lists `installed-files.json`: spec 10 makes it mandatory, but neither `make-manifest.py` nor `internal/release.ParseManifest` enforces it (they only require `builtins.tar`).
- [ ] Read the whole manifest as text: names, sizes, hashes, every built-in module once, `release_version` `0.9.0-beta.1`.

## 6. Signature (Axel, root-1)

- [ ] Axel connects the root-1 YubiKey only after the review and signs: `ssh-keygen -Y sign -f root-1 -n nebula-release -O hashalg=sha512 release-manifest.json`, touching the key when prompted. Output: `release-manifest.json.sig`.
- [ ] Check root-1's public key against the fingerprint recorded in `release-signing.md` before building `allowed-signers`.
- [ ] Disconnect the token. The key handle file, PIN and passphrase never leave the offline station.
- [ ] **OPEN: root-2.** No backup root is generated or enrolled (`rootkeys.txt` holds an empty `root-2` placeholder). If root-1 or its handle is lost there is no recovery path. Enrolling it also needs rotation admission on installations (`trust.Store.ApplyRotation` has no RPC or command yet), so 0.9 ships without a `root-rotation.json`.

## 7. Verification

- [ ] `ssh-keygen -Y verify` as in `release-signing.md`. This proves the signature, **not** user presence.
- [ ] **OPEN: maintainer verifier.** No command checks a staged release with the security-key-aware verifier outside the executor. Until one exists, check on a disposable test installation: put the three bundle files into `/usr/share/nebula/release` and run `nebula artifact trust-builtins` as the admin user. The executor verifies the manifest against its root state (user presence required) and `builtins.tar` against the manifest before it shows the review; enter nothing at the digest prompt to abort without committing. This covers the manifest and `builtins.tar`, not the other payloads.
- [ ] Recompute the SHA-256 of every payload against the signed manifest once more, on a second machine.

## 8. GitHub release

Follow "Publish manifest, signature and installed-files.json on GitHub" in `release-signing.md`.

- [ ] Upload to the draft `v0.9.0-beta.1` the exact reviewed bytes: every payload from `payloads/`, plus `release-manifest.json` and `release-manifest.json.sig`. Never rebuild or re-sign on the publication machine.
- [ ] Per-version hash manifest (ADR 0015 D2): `release-manifest.json`, `release-manifest.json.sig` and `installed-files.json` are attached to this version's release. They are attached for **every** later version too.
- [ ] Mark the release as a pre-release (beta).
- [ ] Release notes: what is in the beta, the open items that ship unresolved (at least root-2, rotation admission, integrity checks, `nebula verify`), and that GitHub, checksums and keys shown beside the files establish no trust; only the signature against the root compiled into the binaries does.
- [ ] Container image: push `ghcr.io/nebula-operation-station/nebula:0.9.0-beta.1` by hand, or state in the release notes that 0.9 ships without an image.
- [ ] Publish the draft. Then download all assets on a different machine and compare their SHA-256 with the offline copies.
- [ ] Never replace an asset of a published version; a fix is a new version (`v0.9.0-beta.2`).

## 9. After publication

- [ ] Note the release in `docs/implementation/m0.md` and turn every OPEN item that is still open into an issue.
- [ ] Keep the offline staging, the manifest and the signature archived with the release.
