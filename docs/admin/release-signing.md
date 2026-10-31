# Offline release signing

This is the maintainer procedure for the owner-approved 2026-10-30 decision within [ADR 0001](../adr/0001-frozen-decisions-v2.2.md). The normative schemas, limits, rotation rules and retention policy are in [spec 10](../spec/10-modules.md#release-signing). Only public keys belong in the repository and binaries. Signing secrets stay on the YubiKeys; key handle files, PINs and passphrases stay out of CI, releases, the executor and managed hosts.

**Implementation gate.** This workflow is not implemented end to end yet. `internal/sshsig` already handles the SSHSIG envelope, but its current verifier accepts only plain Ed25519, not `sk-ssh-ed25519@openssh.com`. Before enabling releases under this policy, implement and test security-key signature verification with an explicit user-presence check, the release/rotation schemas and durable root state, strict bounded bundle validation, and executor retention/admission. The commands below perform the maintainer's offline OpenSSH signing step; they do not establish executor support. Do not use a software root or omit FIDO checks to bypass this gate.

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

**Do not regenerate root-1.** Axel generated it on 2026-10-30 on YubiKey 34718658, a YubiKey 5C NFC running firmware 5.7.4. It is a non-resident FIDO2 key with touch required. The canonical primary fingerprint is `SHA256:DMcoE6ngofND0L6+vT1OIPrvzDFSRmBNDPrR3hpy1MY` and the recorded public key is:

```text
sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIH6DVvY6q6jDyLGQeYjKhNufFKi2jzFHzFO04+ng5mkoAAAABHNzaDo= nebula-release-root-1 (Axel, YubiKey 34718658)
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

## Build and review the release manifest

CI builds the release payloads and the uncompressed `builtins.tar`, without a root token, key handle, PIN or passphrase. Transfer the outputs to the disconnected station. For this procedure stage:

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

**Verification limitation.** `ssh-keygen -Y verify` does not enforce user presence: it can accept a valid security-key signature with `flags=0` (reproduced on OpenSSH 9.6). The allowed-signers file has no `no-touch-required` option; signing-time touch defaults do not establish verification policy. A successful command above is not evidence of touch. `-Y check-novalidate` is not a trust check.

Before publication of any release or rotation, a security-key-aware verifier must cryptographically authenticate the FIDO flags/counter and explicitly require `(flags & 0x01) != 0`. If that check is unavailable, do not publish. The production verifier must additionally enforce the spec's canonical/schema/bundle/root-state policy and match the security-key application `ssh:`. It must not strip the wrapper or substitute plain Ed25519 verification. The FIDO counter is not an anti-replay release number and must not prevent verification of older signed releases. See [OpenSSH SSHSIG](https://raw.githubusercontent.com/openssh/openssh-portable/master/PROTOCOL.sshsig), [security-key encoding](https://raw.githubusercontent.com/openssh/openssh-portable/master/PROTOCOL.u2f) and [ssh-keygen](https://man.openbsd.org/ssh-keygen.1).

Disconnect the token. Transfer only the public manifest/signature and reviewed payloads to the publication machine. Attach `release-manifest.json`, `release-manifest.json.sig` and all listed artifacts to the release; verify the downloaded bytes again. Signing secrets and key handles never enter the publication machine or CI. Installation verifies each consumed artifact; built-in trust review copies only the manifest, signature and `builtins.tar` to an executor-local directory and verifies current root state. Signing establishes provenance; a local administrator must still review/confirm `nebula artifact trust-builtins` once that specified interface is implemented. It does not approve a host operation or update an existing grant.

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
