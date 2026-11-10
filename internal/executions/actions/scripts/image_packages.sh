#!/bin/sh
# image.packages 1.0.0 (Nebula built-in, Docker + Trivy, read-only):
# optional package list of one local image by digest via the host's own,
# operator-provided Trivy (ADR 0011 D3, VU-06). NOS never puts a scanner on
# the host, never fetches an image and never refreshes a Trivy database:
# Trivy runs only if it is already there, with the local-only profile
# --offline-scan --skip-db-update --skip-java-db-update --image-src docker
# and --scanners none --list-all-pkgs, so no vulnerability database is used.
# Without Trivy the result says "absent": the packages are unknown.
# Bounded output (32 MiB from Trivy, stderr counted and dropped); Python 3
# reduces the report on the host to the fields the server parser judges
# (artifact name, repo digests, OS, and per result class, type and the
# package name, version, release, epoch and their source counterparts),
# verbatim, so an invalid entry stays invalid. Image config, layers,
# licences and every other field never leave the host. Nothing is written
# to disk. Parameter: {"image": "<repo>@sha256:<64 hex digest>"}.
set -u
set -f
pre() { printf '{"format":"image-packages-v1","phase":"precheck","reason":"%s"}\n' "$1"; exit 10; }

img=$(sed -n 's|^{\"image\":\"\([a-z0-9][a-z0-9._/:-]\{0,254\}@sha256:[0-9a-f]\{64\}\)\"}$|\1|p' "$NEBULA_PARAMS")
[ -n "$img" ] || pre "the image parameter is missing or invalid"
command -v docker >/dev/null 2>&1 || pre "Docker is missing on this host"
# Same access as docker.list: the docker group, else sudo -n (spec 08).
d="docker"
if [ "$(id -u)" -ne 0 ] && ! docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
	d="sudo -n docker"
fi
$d version --format '{{.Server.Version}}' >/dev/null 2>&1 ||
pre "the Docker daemon is not reachable, or the SSH user may not use it (docker group or sudo)"

# emit STATUS [PRESENT]: a result without a package report.
emit() {
	doc="{\"format\":\"image-packages-v1\",\"phase\":\"done\",\"image\":\"$img\",\"status\":\"$1\""
	[ -n "${2-}" ] && doc="$doc,\"present\":$2"
	printf '%s}\n' "$doc"
	exit 0
}

# The image must already be local; Trivy is never asked to fetch it.
$d image inspect --format '{{.Id}}' -- "$img" >/dev/null 2>&1 || emit notlocal

# Trivy follows the same access as docker: the user's own binary, or the
# root one via sudo -n. It is only ever used if it is already there.
t="trivy"
if [ "$d" = "sudo -n docker" ]; then
	t="sudo -n trivy"
	$t --version >/dev/null 2>&1 || emit absent false
else
	command -v trivy >/dev/null 2>&1 || emit absent false
fi

command -v python3 >/dev/null 2>&1 || pre "Python 3 is required for bounded report reduction"
exec python3 -I - "$img" "$t" <<'PYTHON'
import json
import os
import selectors
import signal
import subprocess
import sys

# MAX_STDOUT is dockerhost.MaxImagePackagesOutput. MAX_REPORT keeps the
# whole result below the 1 MiB result limit (hostrun.MaxResult).
MAX_STDOUT = 33554432
MAX_STDERR = 65536
MAX_REPORT = 1040000
# The server parser walks these objects key by key and rejects more keys,
# longer keys and repeated keys; the reduction must not hide either.
MAX_KEYS = 64
MAX_KEY = 64
TOP_KEYS = ("SchemaVersion", "ArtifactName", "Metadata", "Results")
METADATA_KEYS = ("OS", "RepoDigests")
RESULT_KEYS = ("Class", "Type", "Packages")
ENTRY_KEYS = ("Name", "Version", "Release", "Epoch", "SrcName", "SrcVersion", "SrcRelease", "SrcEpoch")

image, scanner = sys.argv[1:]
command = ["sudo", "-n", "trivy"] if scanner == "sudo -n trivy" else ["trivy"]
env = dict(os.environ, TRIVY_SKIP_VERSION_CHECK="true", TRIVY_DISABLE_TELEMETRY="true", TRIVY_NO_PROGRESS="true")


class Truncated(Exception):
    pass


class Pairs(list):
    """A JSON object as its ordered (key, value) pairs, repeats kept."""


class Number(str):
    """A JSON number as its raw text, so it is emitted unchanged."""


def capture(args):
    # Drain both pipes concurrently; keep bounded stdout in memory, count
    # and drop stderr. Nothing touches disk.
    with subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, start_new_session=True, env=env) as proc:
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ, True)
                selector.register(proc.stderr, selectors.EVENT_READ, False)
                output = bytearray()
                counts = {True: 0, False: 0}
                limits = {True: MAX_STDOUT, False: MAX_STDERR}
                while selector.get_map():
                    for key, _ in selector.select():
                        is_stdout = key.data
                        chunk = os.read(key.fd, min(65536, limits[is_stdout] - counts[is_stdout] + 1))
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        counts[is_stdout] += len(chunk)
                        if counts[is_stdout] > limits[is_stdout]:
                            raise Truncated()
                        if is_stdout:
                            output.extend(chunk)
                return proc.wait(), bytes(output)
        finally:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


def invalid_constant(value):
    raise ValueError("invalid JSON constant")


def walked(value, keep):
    # An object the parser walks key by key: same key limits as the
    # parser, then only the keys it reads.
    if len(value) > MAX_KEYS:
        raise ValueError("too many keys")
    seen = set()
    for key, _ in value:
        if key in seen or len(key.encode("utf-8", "surrogatepass")) > MAX_KEY:
            raise ValueError("repeated or long key")
        seen.add(key)
    return Pairs((k, v) for k, v in value if k in keep)


def only(value, keep):
    # An object whose unknown keys the parser ignores: repeats of a kept
    # key stay, so the parser still sees them.
    return Pairs((k, v) for k, v in value if k in keep)


def reduce_report(raw):
    doc = json.loads(raw.decode("utf-8"), object_pairs_hook=Pairs, parse_constant=invalid_constant,
                     parse_float=Number, parse_int=Number)
    if not isinstance(doc, Pairs):
        raise ValueError("not an object")
    out = Pairs()
    for key, value in walked(doc, TOP_KEYS):
        if key == "Metadata" and isinstance(value, Pairs):
            value = walked(value, METADATA_KEYS)
        elif key == "Results" and isinstance(value, list):
            value = [result(r) for r in value]
        out.append((key, value))
    return out


def result(value):
    if not isinstance(value, Pairs):
        return value
    kept = Pairs()
    for key, val in walked(value, RESULT_KEYS):
        if key == "Packages" and isinstance(val, list):
            val = [only(e, ENTRY_KEYS) if isinstance(e, Pairs) else e for e in val]
        kept.append((key, val))
    return kept


def emit(value, parts):
    if isinstance(value, Pairs):
        parts.append("{")
        for i, (key, val) in enumerate(value):
            if i:
                parts.append(",")
            parts.append(json.dumps(key))
            parts.append(":")
            emit(val, parts)
        parts.append("}")
    elif isinstance(value, list):
        parts.append("[")
        for i, val in enumerate(value):
            if i:
                parts.append(",")
            emit(val, parts)
        parts.append("]")
    elif isinstance(value, Number):
        parts.append(str.__str__(value))
    else:
        parts.append(json.dumps(value))


def frame(fields):
    head = {"format": "image-packages-v1", "phase": "done", "image": image}
    head.update(fields)
    return json.dumps(head, separators=(",", ":"))


def main():
    args = command + ["image", "--offline-scan", "--skip-db-update", "--skip-java-db-update",
                      "--image-src", "docker", "--scanners", "none", "--list-all-pkgs",
                      "--quiet", "--format", "json", "--", image]
    try:
        rc, raw = capture(args)
    except Truncated:
        return frame({"status": "ok", "present": True, "output": "truncated"})
    except OSError:
        return frame({"status": "ok", "present": True, "output": "unparseable"})
    try:
        parts = []
        emit(reduce_report(raw), parts)
        report = "".join(parts)
    except (ValueError, TypeError, RecursionError):
        return frame({"status": "ok", "present": True, "rc": rc, "output": "unparseable"})
    if len(report) > MAX_REPORT:
        return frame({"status": "ok", "present": True, "rc": rc, "output": "toolarge"})
    return frame({"status": "ok", "present": True, "rc": rc, "output": "ok"})[:-1] + ',"report":' + report + "}"


print(main())
PYTHON
