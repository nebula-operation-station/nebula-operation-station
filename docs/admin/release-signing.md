# Offline release signing

This is the maintainer procedure for the owner-approved 2026-10-30 decision within [ADR 0001](../adr/0001-frozen-decisions-v2.2.md). The normative schemas, limits, rotation rules and retention policy are in [spec 10](../spec/10-modules.md#release-signing). Only public keys belong in the repository and binaries. Signing secrets stay on the YubiKeys; key handle files, PINs and passphrases stay out of CI, releases, the executor and managed hosts.

**Implementation status** (state of `main`, 2026-11-12; previously: "Implementation gate", which said that `internal/sshsig` accepted only plain Ed25519). The verifying side is implemented, the unsigned staging is produced by `make release-stage` (and by the release workflow on a version tag), and a maintainer check of a staged release exists; signing itself is manual, and several admission paths are not implemented (previously: "the producing side (build tooling, release workflow) and several admission paths are not"). The commands below perform the maintainer's offline OpenSSH signing step. Do not use a software root or omit FIDO checks to work around a missing piece.

Implemented and tested on `main`:

- **Security-key signatures.** `internal/sshsig.VerifySecurityKey` accepts only a plain (non-certificate) `sk-ssh-ed25519@openssh.com` key bound to the expected application, requires the envelope to carry exactly that key, checks the user-presence flag (`flags & 0x01`, otherwise `ErrUserPresence`) and lets `golang.org/x/crypto/ssh` verify the whole FIDO signature including flags and counter; the wrapper is never stripped and the counter is informational. `Verify` (plain Ed25519) rejects security keys. Tests (`internal/sshsig/securitykey_test.go`) sign with a software stand-in in the OpenSSH encoding and check that the real root-1 public key parses; no signature made by the real token is in the test suite.
- **Release documents** (`internal/release`): the compiled anchors `rootkeys.txt` (root-1 set, root-2 an explicit empty placeholder); the strict `nebula-release-v1` manifest parser and verifier (`ParseManifest`, `VerifyManifest`; namespace `nebula-release`, application `ssh:`); root rotation `nebula-root-rotation-v1` (`RootState.ApplyRotation`, at most four active roots); the bounded `builtins.tar` validator (`ReadBundleDir`, `VerifyBundle`, `ParseModuleTar`); `installed-files.json` (`ParseInstalledFiles`, `VerifyInstalledFiles`, `VerifyPublishedInstalledFiles`, `GenerateInstalledFiles`); and the signed image catalog `nebula-image-catalog-v1` (`VerifyCatalog`).
- **Executor admission of built-ins.** `internal/executor/trust` keeps the durable root state (bootstrapped from the compiled anchors), the retained module bytes with their signed provenance, the 90-day floor, version tombstones and the storage ceilings. `nebula artifact trust-builtins` reviews the bundle in `/usr/share/nebula/release` (verified against that durable root state) and commits it after a digest-bound confirmation. `deploy/install.sh` provisions the three bundle files there (adjacent attachments or `--release-bundle-dir`).
- **Not release roots.** `internal/executordb` `trusted_signers` and `nebula signer add|list|remove` (`cmd/nebula/signer.go`) manage third-party *module* signers: plain `ssh-ed25519` keys, namespace `nebula-module`. Release roots never go there and are never added at runtime.
- **`builtins.tar` builder.** `internal/release/stage` `BuildBuiltins` builds `builtins.tar` and its nested `modules/<name>/<version>.tar` objects from the module source tree; `make release-stage VERSION=X.Y.Z` runs it through `cmd/nebula-release-stage`. Tests: `internal/release/stage/builtins_test.go` (`TestBuiltinsPassBundleVerification`, `TestBuiltinsHeadersAreFixed`, `TestBuiltinsRejectBadModules`). Previously: "Nothing in the repository produces `builtins.tar` or its nested objects".
- **`installed-files.json` producer and staging.** `nebula-release-stage` (`cmd/nebula-release-stage`, `internal/release/stage` `Run`) stages `payloads/`, `module-bytes/`, `installed/<flavour>/` and `SHA256SUMS` from the goreleaser packages, the tarball and the exported container image (`container:amd64` is always staged, whether or not the image is pushed), and writes `installed-files.json` with `GenerateInstalledFiles`. Nothing is signed and no manifest is written. Tests: `internal/release/stage/stage_test.go` (`TestStageLayoutMatchesSigningProcedure`, `TestInstalledFilesComeFromThePackages`, `TestStageTwiceIsByteIdentical`, `TestStageRejectsBadPackages`). Previously: "`GenerateInstalledFiles` is a library function only: no command wraps it and nothing stages the per-flavour trees".
- **Maintainer-side verifier.** `cmd/nebula-release-check` (`bin/nebula-release-check STAGING_DIR` after `make build`) checks a staging directory against the compiled root anchors only: manifest signature in namespace `nebula-release` with a security key and user presence required (`VerifyManifest`), size and SHA-256 of every payload, `builtins.tar` with `VerifyBundle` and `installed-files.json` with `VerifyInstalledFiles`. It writes nothing and uses no network. Tests: `cmd/nebula-release-check/main_test.go` (`TestValidStagedReleasePasses`, `TestSignatureWithoutUserPresenceFails`, `TestCompiledAnchorsAreTheOnlyTrust`, `TestModifiedPayloadIsReported`, `TestMissingPayloadIsReported`, `TestManifestWithoutInstalledFilesFails`). Previously: "no command outside the executor runs `VerifyManifest` on a staged release".
- **Manifest lists exactly one `installed-files.json`.** `internal/release` `ParseManifest` rejects a manifest with none or two (`ErrManifestInstalledFiles`, spec 10). Tests: `internal/release/installedfiles_test.go` (table cases `list missing from manifest` and `two lists in signed manifest`) and `internal/release/release_test.go` (`ErrManifestInstalledFiles` with `ErrFormat`). Previously: "`ParseManifest` only requires exactly one `builtins.tar`".

Not covered by a test, so not listed above: the release workflow `.github/workflows/release.yml` builds the unsigned staging on every `v*` tag and attaches `payloads/` to a **draft** release (previously: "`.github/workflows/ci.yml` has no release job and runs no GoReleaser"); its only check is a run on the tag. See [Release workflow](#release-workflow-source-of-the-payloads). Manifest, signature, the container image push and publication stay manual.

Missing (open before or with the first signed release):

1. **Rotation admission.** `trust.Store.ApplyRotation` exists, but no RPC or command calls it, so an installation cannot admit a `root-rotation.json` yet. Root-2 is not generated or enrolled (below).
2. **Integrity checks.** `nebula-server` runs the I1 self-check from `internal/integrity` (ADR 0015 IG-03) at start and every 60 minutes, only logging and showing the result (previously: "a library that no process calls yet"). It re-admits `/usr/share/nebula/release` against the root anchors built into its binary, not against an executor-admitted copy, and applies no rotations; see the known gaps in `docs/implementation/m0.md`. `deploy/install.sh` does not install `installed-files.json` yet, so a release install reports the check as incomplete. Admission of `installed-files.json` during upgrade and `nebula verify` (IG-04) do not exist. Reproducible builds (IG-11) are open.
3. **Signed image catalog.** `PveImageCatalog.LoadSigned` is not called by any process, and there is no catalog signing procedure; releases currently ship no catalog.
4. **Manifest completeness (partly closed).** `ParseManifest` requires exactly one `installed-files.json` (tested, see above). `make-manifest.py` below still requires only `builtins.tar`, so the list is not enforced at signing time; check its presence by hand. The list itself is verified where it is checked (`VerifyInstalledFiles`).

## Prepare the signing station

Use a maintained, offline workstation with reviewed OpenSSH/FIDO support. Install tools while online, then disconnect it before connecting either signing YubiKey or accessing handles. Transfer reviewed build outputs on removable media. Keep the primary and backup keys physically separate; do not forward a signing agent or connect a token to CI. A compromised build can still produce malicious artifacts, so review source/build provenance and recompute all hashes before touching the token.

On macOS install **Homebrew OpenSSH** (the Apple-provided binary did not support the owner's generation procedure). Select that binary explicitly; on Linux use the distribution OpenSSH with FIDO support.

```sh
# macOS, during station preparation while online:
brew install openssh
SSH_KEYGEN="$(brew --prefix openssh)/bin/ssh-keygen"
# Linux instead:
# SSH_KEYGEN="$(command -v ssh-keygen)"

# Disconnect networking before continuing.
umask 077
mkdir -p "$HOME/nebula-release-offline"
cd "$HOME/nebula-release-offline"
```

## Primary root and second-key enrollment

**Do not regenerate root-1.** Axel generated it on 2026-10-30 on a YubiKey. It is a non-resident FIDO2 key with touch required. The canonical primary fingerprint is `SHA256:DMcoE6ngofND0L6+vT1OIPrvzDFSRmBNDPrR3hpy1MY`. Its compiled anchor line in `internal/release/rootkeys.txt` (the public key prefixed with the slot ID `root-1`) is:

```text
root-1 sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIH6DVvY6q6jDyLGQeYjKhNufFKi2jzFHzFO04+ng5mkoAAAABHNzaDo= nebula-release-root-1 (Axel)
```

The original resident-key proposal did not work on this setup: both `-O resident` and `-O verify-required` failed with `invalid format`. The working generation form was equivalent to the following (shown for documentation, not as a command to rerun over the existing key):

```sh
"$SSH_KEYGEN" -t ed25519-sk -f root-1 -C nebula-release-root-1
```

OpenSSH requires touch by default for this key type; never pass `-O no-touch-required`. Enter a strong passphrase interactively to encrypt the key handle file. A FIDO PIN may be requested during generation; this procedure does not promise PIN/UV enforcement for every signature. Do not try to convert the existing key to a resident credential or replace it to make an optional generation flag work.

**Root-2 is pending:** no backup root has been generated or enrolled. On a second YubiKey, disconnected from root-1, generate a distinct backup root with the working non-resident form:

```sh
"$SSH_KEYGEN" -t ed25519-sk -f root-2 -C nebula-release-root-2
"$SSH_KEYGEN" -y -f root-2 > root-2.pub
"$SSH_KEYGEN" -lf root-2.pub -E sha256
```

Export/check root-1's public half from its existing handle in the same way, without generating another credential:

```sh
"$SSH_KEYGEN" -y -f root-1 > root-1.pub
"$SSH_KEYGEN" -lf root-1.pub -E sha256
```

Compare root-1 to the fingerprint above, and independently record root-2's fingerprint. Store the passphrase-encrypted `root-1`/`root-2` key handle files on encrypted offline backup media and test each restored handle with its own token using a disposable signing message. A handle is not an exported signing secret, but it is required to use this non-resident credential: losing it loses the root even if the token survives. `ssh-keygen -K` cannot recover a non-resident handle. A second token cannot be a backup copy of the same hardware secret; it is an independent root that must first be trusted via the signed enrollment below. Never publish handle files or attestation material. Export only `.pub` files, public fingerprints, signed manifests and signed rotation metadata.

Enroll root-2 with root-1 before claiming recovery coverage. Publish its public key only after checking and signing enrollment; compile public trust metadata into subsequent binaries with the signed chain from the original bootstrap root. Do not add an unsigned public key as independent authority for existing installations. Until enrollment, losing root-1 or its handle has no backup-key recovery path.

## Release workflow (source of the payloads)

`.github/workflows/release.yml` is the source of the release payloads. It runs when a maintainer pushes a `v*` tag, or by hand (`workflow_dispatch`) for an existing tag. It signs nothing, writes no manifest, has no access to any key and uses no secret except the automatic `GITHUB_TOKEN`, which is read-only except in the draft job. Its actions are pinned by commit SHA.

1. **Build job** (GitHub-hosted `ubuntu-24.04`, previously the self-hosted `nos` runner; `contents: read`): every run starts on a fresh VM with no shared Go build or module cache, no tool cache from pull-request jobs and no restored actions cache, so leftovers of other jobs cannot reach the payloads. It checks out the tag, verifies that `HEAD` is the tagged commit, installs the exact Go release pinned as `GO_VERSION` in the workflow (previously: newest patch of the `go.mod` minor version), fails if its minor version differs from `go.mod`, forbids toolchain switching (`GOTOOLCHAIN=local`), and records the Go version as job output `go_version`, in the run summary and in the draft's notes. It runs `make check`, then `make release-stage VERSION=<tag without v> RELEASE_STAGE=staging` with a pinned GoReleaser, and checks `staging/SHA256SUMS`. The whole `staging/` tree (`payloads/`, `module-bytes/`, `installed/`, `SHA256SUMS`) is kept as the workflow artifact `nebula-release-staging-<version>` for 30 days.
2. **Draft job** (GitHub-hosted, `contents: write`, `actions: read`; runs no repository code): downloads the artifact, rechecks `SHA256SUMS`, checks that the tag ref `refs/tags/<tag>` (resolved exactly, annotated tags dereferenced; previously any ref of that name) still points at the built commit, and attaches exactly the files of `payloads/` to the tag's GitHub release as a **draft**. Without a release it creates an empty draft first; then it uploads the payloads one at a time, replacing same-named assets, and re-reads the release immediately before each upload and stops if it is no longer a draft (previously: one check before uploading all files). It fails, and changes nothing, when the release is already published, when more than one release carries the tag, or when the draft holds an asset this build does not produce (for example a `release-manifest.json` or `.sig` from an earlier signing: delete it by hand only if that signing is abandoned). Afterwards it checks that the same draft holds exactly the payload names and sizes, compares GitHub's SHA-256 digest where reported, and downloads every asset and compares its SHA-256 with `payloads/`; a mismatch or a failed download fails the run (previously: size only when GitHub reported no digest).

A failed, cancelled or interrupted draft job can leave a **partly updated draft**: some assets replaced by this build, others still from an earlier build or missing. Never review, sign or publish such a draft. Re-run the workflow (re-run the failed jobs of the same run, or `workflow_dispatch` with the tag) until the draft job succeeds, and take the hashes for the offline comparison only from that successful run's log and artifact. A run that stopped because the release was published meanwhile may already have replaced the asset it was uploading; check the published assets against the signed manifest at once and, if any differs, withdraw the version and release a new one.

GitHub, the artifact and its `SHA256SUMS` are a transport, not a trust anchor: the CI runner is trusted only to build. The release then proceeds:

1. Tag (human) → workflow → draft release with the unsigned payloads, plus the `staging/` artifact.
2. Download the artifact, copy it to removable media and, on the disconnected station, recompute every SHA-256 independently and compare with the build job log and the draft's assets. Check `builtins.tar`, `module-bytes/` and `installed/` as described below.
3. `python3 make-manifest.py <version>` and `python3 check-installed-files.py <version>` (below).
4. Sign `release-manifest.json` with the root YubiKey ([Sign offline and verify](#sign-offline-and-verify)).
5. Attach `release-manifest.json` and `release-manifest.json.sig` to the draft by hand; never re-run the workflow for that tag after signing (it refuses a draft that carries them).
6. Publish the draft ([Publish manifest, signature and installed-files.json on GitHub](#publish-manifest-signature-and-installed-filesjson-on-github)).

Prerequisites on the build runner: docker (the GoReleaser image and the container flavour of `make release-stage`), python3, and network access to the Go module proxy; the GitHub-hosted `ubuntu-24.04` image provides them. The container image is built locally and not pushed. To change the Go release used for the payloads, change `GO_VERSION` in `.github/workflows/release.yml` in a reviewed commit before tagging (for example when `govulncheck` in `make check` reports a standard library fix).

## Build and review the release manifest

CI builds the release payloads and the uncompressed `builtins.tar`, without a root token, key handle, PIN or passphrase (the release workflow below). Transfer the outputs to the disconnected station. For this procedure stage:

- `payloads/`: exactly every payload attachment to publish, including `builtins.tar`, binaries, packages and any published source/checksum files. Exclude the manifest, signatures and separately authenticated rotations.
- `module-bytes/<name>/<version>.tar`: the exact nested module tar objects from the reviewed `builtins.tar`. Use the strict bounded bundle validator required by spec 10; do not extract untrusted CI archives with an unrestricted `tar -xf`. Validate the lock, file set and contents, and compare built-ins across all packages/architectures.

The following offline Python 3 recipe constructs the specified manifest from that reviewed staging. Set the actual release version on invocation; the example `0.1.0` is illustrative. It checks manifest-level bounds; it does not replace the required bundle/lock validator or build review. Every emitted string is restricted ASCII and every integer is at most 4 GiB, so Python's sorted-key compact serialization here equals RFC 8785 JCS for this schema. This recipe is not a general-purpose JCS encoder; do not use `jq -S` or a generic JSON pretty-printer as a substitute.

Save this as `make-manifest.py` on the offline station:

```python
import hashlib
import json
from pathlib import Path
import re
import sys


def require(ok, message):
    if not ok:
        raise SystemExit(message)


def file_record(path, maximum):
    require(path.is_file() and not path.is_symlink(), "regular file required")
    size = path.stat().st_size
    require(0 < size <= maximum, "file size out of bounds")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    require(path.stat().st_size == size, "file changed during hashing")
    return {"size": size, "sha256": digest.hexdigest()}


require(len(sys.argv) == 2, "usage: make-manifest.py RELEASE_VERSION")
version = sys.argv[1]
core = r"(0|[1-9][0-9]{0,5})"
module_version = core + r"\." + core + r"\." + core
release_version = module_version + r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
match = re.fullmatch(release_version, version)
require(len(version) <= 64 and match is not None, "invalid release version")
if match.group(4):
    require(all(not (s.isdigit() and len(s) > 1 and s[0] == "0")
                for s in match.group(4).split(".")), "invalid prerelease")

artifacts = []
for path in sorted(Path("payloads").iterdir()):
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", path.name)
            is not None, "invalid artifact name")
    artifacts.append({"name": path.name, **file_record(path, 4 << 30)})
require(1 <= len(artifacts) <= 128, "artifact count out of bounds")
require(sum(a["size"] for a in artifacts) <= 8 << 30, "release too large")
require(any(a["name"] == "builtins.tar" and a["size"] <= 80 << 20
            for a in artifacts), "missing/oversized builtins.tar")

modules = []
for family in sorted(Path("module-bytes").iterdir()):
    require(family.is_dir() and not family.is_symlink(), "invalid module directory")
    require(re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", family.name)
            is not None, "invalid module name")
    files = list(family.iterdir())
    require(len(files) == 1, "one version per module required")
    path = files[0]
    require(path.name.endswith(".tar"), "module tar required")
    v = path.name[:-4]
    require(re.fullmatch(module_version, v) is not None, "invalid module version")
    modules.append({"name": family.name, "version": v, **file_record(path, 4 << 20)})
require(1 <= len(modules) <= 128, "module count out of bounds")
require(sum(m["size"] for m in modules) <= 64 << 20, "module total too large")
manifest = {"format": "nebula-release-v1", "release_version": version,
            "artifacts": artifacts, "modules": modules}
encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False).encode("utf-8")
require(len(encoded) <= 1 << 20, "manifest too large")
with Path("release-manifest.json").open("xb") as output:
    output.write(encoded)  # No trailing newline.
```

```sh
python3 make-manifest.py 0.1.0
```

Review the entire manifest as text and recompute each artifact/module digest independently. Require that `builtins.tar` has exactly the manifest modules, with matching exact bytes and lock identities, and no extra files. Check every built-in shipped in every other artifact against this list. A signature cannot repair an incomplete artifact inventory or a module archive reconstructed differently after hashing. Keep the staging immutable throughout review/signing, and revalidate it before publication.

## installed-files.json

`installed-files.json` ([ADR 0015](../adr/0015-integrity-monitoring.md) D2) lists every file a release installs, per install flavour, so that the executor, the server and `nebula verify` can check an installation against the release. It is an ordinary payload: stage it in `payloads/` **before** running `make-manifest.py`, so the manifest's `artifacts` array carries its exact size and SHA-256 and the YubiKey signature covers it. The list itself has no signature and contains no key.

**Format** (`nebula-installed-files-v1`, RFC 8785 JCS bytes, no trailing newline, at most 4 MiB):

```json
{"flavours":{"deb:amd64":[{"mode":"0755","owner":"root:root","path":"/usr/bin/nebula","sha256":"<64 lowercase hex>","size":123,"type":"file"},{"owner":"root:root","path":"/usr/share/nebula/web/app.css","target":"app.1234.css","type":"symlink"}]},"format":"nebula-installed-files-v1","release_version":"0.1.0"}
```

- `release_version` equals the manifest's.
- `flavours` has 1 to 16 keys `<deb|tarball|container>:<arch>`; each holds 1 to 4,096 entries, sorted by `path` (bytewise) without duplicates. No listed path may also be a directory of another.
- A regular file has exactly `path`, `type` `"file"`, `size` (0 to 1 GiB), `sha256` of the exact bytes, `mode` (four octal digits, setuid/setgid/sticky included) and `owner` (`user:group`). A symlink has exactly `path`, `type` `"symlink"`, the exact `target` (not followed) and `owner`. Directories are implied.
- `path` is absolute, at most 255 bytes of `[A-Za-z0-9/._+-]`, without empty, `.` or `..` components, and under a covered NOS prefix **of its flavour**:
  - every flavour: `/usr/bin/nebula*`; anything under `/usr/share/nebula/`, `/usr/lib/nebula/` and `/usr/share/doc/nebula-operation-station/`;
  - `deb:<arch>`: `nebula-*` units under `/lib/systemd/system` or `/usr/lib/systemd/system`, and drop-ins the package ships beside them, `nebula-<unit>.d/<name>.conf`;
  - `tarball:<arch>`: `nebula-*` units under `/etc/systemd/system`, never a drop-in there;
  - `container:<arch>`: no unit directory.

  A unit path in another flavour's unit directory (for example `/etc/systemd/system/nebula-server.service` in a `deb` flavour) makes the list invalid. That covers binaries, systemd units and package-shipped drop-ins, the built-in module bundle and its files, and web assets.
- **Never listed:** configuration and data. Configuration is `/etc/nebula` and every drop-in under `/etc/systemd/system/nebula-*.service.d/`, including the ones `install.sh` and the deb `postinst` generate (`nebula-executor.service.d/10-local.conf`, `nebula-server.service.d/20-discovery.conf`) and admin-created ones such as `20-local.conf`; data is `/var/lib/nebula`, logs, spools, runtime directories and caches. They change by design; ADR 0015 D3, backups and the audit log cover them. A path outside the prefixes of its flavour makes the list invalid, in the parser and in the generator.
- **nftables.** ADR 0015 D2 and spec 10 name "shipped nftables files" as covered. The only nftables file NOS has, `nebula-iconfetch.nft`, lives at `/etc/nebula/nebula-iconfetch.nft`: it is read from configuration, nothing in a release installs it (see the iconfetch note in `deploy/install.sh`), and the admin may edit it. It is therefore treated as configuration (ADR 0015 D3 lists "the iconfetch nftables file" there) and is **never listed**; a list naming it is invalid. A release that ships an nftables file as code must install it under a covered prefix such as `/usr/share/nebula/`.

Unknown or missing fields, nulls, escapes JCS would not write, duplicate keys and any other non-canonical spelling reject the whole list (`internal/release.ParseInstalledFiles`).

**Producing it.** Release tooling stages each flavour's file tree as it is installed, one directory per flavour named exactly like the flavour (for example `installed/deb:amd64/usr/bin/nebula`, taken from the extracted package data), and calls `internal/release.GenerateInstalledFiles(version, "installed")`. It records modes from the tree and the owner `root:root` (packages and `install.sh` install code as root), records symlinks without following them, and refuses any other file type and any configuration or data file in the staging. A command-line wrapper and the CI wiring are separate changes; until then the generator is a library function only.

**Offline recheck before signing.** Transfer the `installed/` staging with the payloads. On the signing station recompute the list independently and require byte-for-byte agreement with the staged `payloads/installed-files.json`. Save as `check-installed-files.py`:

```python
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


def require(ok, message):
    if not ok:
        raise SystemExit(message)


def entry(path, rel):
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        return {"owner": "root:root", "path": rel, "target": os.readlink(path), "type": "symlink"}
    require(stat.S_ISREG(st.st_mode), "unexpected file type: " + rel)
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    require(os.lstat(path).st_size == st.st_size, "file changed during hashing: " + rel)
    return {"mode": "%04o" % stat.S_IMODE(st.st_mode), "owner": "root:root", "path": rel,
            "sha256": digest.hexdigest(), "size": st.st_size, "type": "file"}


require(len(sys.argv) == 2, "usage: check-installed-files.py RELEASE_VERSION")
listed = Path("payloads/installed-files.json").read_bytes()
flavours = {}
for flavour in sorted(Path("installed").iterdir()):
    require(flavour.is_dir() and not flavour.is_symlink(), "flavour must be a directory")
    entries = []
    for dirpath, dirnames, filenames in os.walk(flavour):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            if os.path.isdir(path) and not os.path.islink(path):
                continue
            entries.append(entry(path, "/" + os.path.relpath(path, flavour)))
    flavours[flavour.name] = sorted(entries, key=lambda e: e["path"].encode())
expected = {"flavours": flavours, "format": "nebula-installed-files-v1",
            "release_version": sys.argv[1]}
encoded = json.dumps(expected, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False).encode("utf-8")
require(encoded == listed, "installed-files.json differs from the staged trees")
print("installed-files.json matches:", hashlib.sha256(listed).hexdigest())
```

```sh
python3 check-installed-files.py 0.1.0
```

The recipe compares only what the trees contain; the path rules above are enforced by the generator and by every verifier, so a list that passes here but breaks them is still rejected. Review the path list as text as well: every file the packages install under a covered prefix must be listed, and nothing else. A signature proves only that the maintainer approved these hashes, not that the build was safe; reproducible builds (ADR 0015 IG-11) are a separate step.

## Sign offline and verify

Connect root-1 only after review. Sign the canonical file bytes using SSHSIG namespace `nebula-release` and SHA-512:

```sh
"$SSH_KEYGEN" -Y sign -f root-1 -n nebula-release -O hashalg=sha512 release-manifest.json
```

Touch the YubiKey when prompted. The output is `release-manifest.json.sig`. As an independent OpenSSH check, create an offline allowed-signers file from the already verified public key (not from the signature or a download):

```sh
printf 'nebula-release namespaces="nebula-release" ' > allowed-signers
cat root-1.pub >> allowed-signers
"$SSH_KEYGEN" -Y verify -f allowed-signers -I nebula-release \
  -n nebula-release -s release-manifest.json.sig < release-manifest.json
```

**Verification limitation.** `ssh-keygen -Y verify` does not enforce user presence: it can accept a valid security-key signature with `flags=0` (reproduced on OpenSSH 9.6). The allowed-signers file has no `no-touch-required` option; signing-time touch defaults do not establish verification policy. A successful command above is not evidence of touch. `-Y check-novalidate` is not a trust check. The security-key-aware check is `bin/nebula-release-check STAGING_DIR` (built by `make build` from the reviewed tag on a trusted, online machine, never from the tree that produced the staging, and transferred to the offline station; see [Prepare the signing station](#prepare-the-signing-station)), which reads a staging directory with `release-manifest.json`, `release-manifest.json.sig` and `payloads/`, and checks the signature (with the FIDO user-presence requirement), every payload, `builtins.tar` and `installed-files.json` against the compiled anchors. It is the tool that covers the requirement stated above; the `ssh-keygen` check is not replaced by it.

Before publication of any release or rotation, a security-key-aware verifier must cryptographically authenticate the FIDO flags/counter and explicitly require `(flags & 0x01) != 0`. If that check is unavailable, do not publish. The production verifier must additionally enforce the spec's canonical/schema/bundle/root-state policy and match the security-key application `ssh:`. It must not strip the wrapper or substitute plain Ed25519 verification. The FIDO counter is not an anti-replay release number and must not prevent verification of older signed releases. See [OpenSSH SSHSIG](https://raw.githubusercontent.com/openssh/openssh-portable/master/PROTOCOL.sshsig), [security-key encoding](https://raw.githubusercontent.com/openssh/openssh-portable/master/PROTOCOL.u2f) and [ssh-keygen](https://man.openbsd.org/ssh-keygen.1).

Disconnect the token. Transfer only the public manifest/signature and reviewed payloads to the publication machine. Attach `release-manifest.json`, `release-manifest.json.sig` and all listed artifacts to the release; verify the downloaded bytes again. Signing secrets and key handles never enter the publication machine or CI. Installation verifies each consumed artifact; built-in trust review copies only the manifest, signature and `builtins.tar` to an executor-local directory and verifies current root state. Signing establishes provenance; a local administrator must still review and confirm the bundle with `nebula artifact trust-builtins` (previously: "once that specified interface is implemented"). It does not approve a host operation or update an existing grant.

## Publish manifest, signature and installed-files.json on GitHub

For **every** version, attach `release-manifest.json`, `release-manifest.json.sig` and `installed-files.json` as assets of that version's GitHub release, next to the other listed artifacts, and attach every published `root-rotation.json` with its signature so that verifiers can advance from their compiled anchors. Upload the exact reviewed bytes; never regenerate or re-sign them on the publication machine or in CI.

**GitHub is only a distribution channel, never a trust anchor.** A verifier accepts the list only after it has verified `release-manifest.json.sig` against the release root public keys compiled into its NOS binaries, advanced by the signed root rotations (spec 10), and the size and SHA-256 of `installed-files.json` against that manifest, and the list's `release_version` against the manifest's. An unsigned manifest, a wrong signature, a signature by a revoked or unknown key, a size or hash mismatch and a non-canonical document are rejected, also when they come from the official GitHub release. A public key, checksum or signature shown beside the files (release notes, `SHA256SUMS`, another web page) establishes no trust. In code this is `internal/release.VerifyPublishedInstalledFiles` (compiled anchors plus the given rotations, nothing else) and, on the NOS machine, `internal/release.VerifyInstalledFiles` with the executor's durable root state.

After the upload, download the three assets on a different machine and compare their SHA-256 with the reviewed offline copies. Never replace an asset of a published version: two validly signed but different manifests for the same `release_version` mean misuse of a root key or a broken release process, and verifiers report that as critical. A corrected build is a new version.

Offline installations get the same three files inside the update bundle; the NOS machine never fetches from GitHub itself. Admitting them into executor-owned storage during upgrade (ADR 0015 IG-03), and the checks on the NOS machine and `nebula verify` from an admin machine (IG-04) are separate changes; this section describes the maintainer procedure they implement. The release workflow attaches only the unsigned payloads (including `installed-files.json`) to the draft; the manifest and its signature are always uploaded by hand (previously: "and the release workflow that uploads the assets are separate changes").

## Enroll, rotate and recover

Use the exact `nebula-root-rotation-v1` schema from [spec 10](../spec/10-modules.md#root-rotation-and-revocation). First enrollment of root-2 uses sequence 1, 64 zeroes for `previous_sha256`, one `add` entry with ID `root-2` and its exported public key without a comment, and an empty `revoke` array. Do this only after root-2 generation and its offline fingerprint/signature test. This offline Python recipe creates that first enrollment document; it deliberately cannot express later rotations:

```python
import base64
import json
from pathlib import Path
import struct

parts = Path("root-2.pub").read_text(encoding="ascii").split()
assert len(parts) >= 2 and parts[0] == "sk-ssh-ed25519@openssh.com"
blob = base64.b64decode(parts[1], validate=True)
assert base64.b64encode(blob).decode("ascii") == parts[1]
fields = []
remaining = blob
for _ in range(3):
    length = struct.unpack(">I", remaining[:4])[0]
    assert len(remaining) >= 4 + length
    fields.append(remaining[4:4 + length])
    remaining = remaining[4 + length:]
assert not remaining
assert fields[0] == b"sk-ssh-ed25519@openssh.com"
assert len(fields[1]) == 32 and fields[2] == b"ssh:"
public_key = " ".join(parts[:2])
assert len(public_key) <= 256
rotation = {"format": "nebula-root-rotation-v1", "sequence": 1,
            "previous_sha256": "0" * 64,
            "add": [{"id": "root-2", "public_key": public_key}], "revoke": []}
with Path("root-rotation.json").open("xb") as output:
    output.write(json.dumps(rotation, sort_keys=True, separators=(",", ":")).encode("ascii"))
```

Review it, then sign with the *currently trusted* root-1. The namespace stays `nebula-release`; the JSON `format` distinguishes rotation from release metadata.

```sh
"$SSH_KEYGEN" -Y sign -f root-1 -n nebula-release -O hashalg=sha512 root-rotation.json
"$SSH_KEYGEN" -Y verify -f allowed-signers -I nebula-release \
  -n nebula-release -s root-rotation.json.sig < root-rotation.json
```

Publish the rotation and signature plus the public key/fingerprint. Existing installations verify root-1's signature and atomically persist the new sequence, document digest and root set before accepting root-2 signatures. Fresh installations validate the published chain from their compiled bootstrap trust metadata. Root-2's self-signature or inclusion in a release is insufficient. Apply rotations in order; retrieve the latest published chain before admitting a release. An offline verifier cannot discover a newer revocation withheld from it.

For later rotation, generate root-3 on another token, export/check its public key and back up its handle. Construct the same schema with the next sequence and SHA-256 of the previous **canonical rotation document** (not its signature). Add root-3 and revoke the old primary in a single transition if retiring it. Sign with a root trusted before the transition: root-1 for routine rotation, or the enrolled backup root-2 for primary loss/compromise. When using root-2, build `allowed-signers` from the checked `root-2.pub`, sign with `-f root-2`, and verify before publishing. Test replacement signing before revoking the usable primary; keep at least one trusted root and a separately held backup. Root IDs/key blobs are never reused.

Revocation overrides compiled anchors. Preserve all old public keys and signed rotation documents for historical verification, labelling revoked signers; reject new release admission under a revoked signer even if its manifest claims an old release version. Keep executor root state across restarts/downgrades; neither a restored old bundle nor an unsigned public-key edit may roll it back. This does not revoke or retarget grants by itself; normal trust withdrawal/per-run policy applies. If root-2 has not been enrolled and root-1 is lost, stop: no unsigned emergency root is authorized by this procedure.

## Executor history and upgrade capacity

The executor must retain active module bytes, the two previous distinct accepted versions and every version superseded within at least 90 days, with their signed provenance. It also keeps immutable version/hash tombstones after eligible byte cleanup to reject same-version substitution. The hard store ceiling is 2 GiB, including 1 GiB historical bytes, with the remaining category/count bounds in spec 10. Reactivating an older retained version preserves its bytes and starts a fresh 90-day floor when it next becomes inactive. Rapid releases may need more than two historical versions during the 90-day window; an update that would exceed quotas or free disk space fails before trust activation. Do not delete required history or shorten retention to force an update. Reclaimed bytes confer no permission to reuse a version, and retained bytes confer no execution authority. First use or missing prior bytes requires full review instead of an unchanged claim.
