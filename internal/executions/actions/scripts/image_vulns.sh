#!/bin/sh
# image.vulnerabilities 1.0.0 (Nebula built-in, Docker + Trivy, read-only):
# optional CVE observation of one local image by digest via the host's own
# Trivy. Local-only scan profile: --offline-scan --skip-db-update
# --skip-java-db-update --image-src docker --scanners vuln; needs Python 3.
# NOS never installs a scanner, pulls an image or refreshes
# the database (operator-managed). One concurrent scan per host (flock),
# bounded output, and the raw scanner output never leaves the host: it is
# reduced on the host to unique CVE counts by severity, the top 25 CVEs with
# fixed versions, the target count (coverage) and the database age. Cached
# by digest + platform + DB version for at most 24 h. Absent, stale, busy,
# failed or unsupported scans report their status, never "0 CVEs".
# Parameter: {"image": "<repo>@sha256:<64 hex digest>"}.
set -u
set -f
b64() { base64 -w0 2>/dev/null || base64 | tr -d '\n'; }
pre() { printf '{"format":"image-vulns-v1","phase":"precheck","reason":"%s"}\n' "$1"; exit 10; }

img=$(sed -n 's|^{\"image\":\"\([a-z0-9][a-z0-9._/:-]\{0,254\}@sha256:[0-9a-f]\{64\}\)\"}$|\1|p' "$NEBULA_PARAMS")
[ -n "$img" ] || pre "the image parameter is missing or invalid"
command -v docker >/dev/null 2>&1 || pre "Docker is not installed"
# Same access as docker.list: the docker group, else sudo -n (spec 08).
d="docker"
if [ "$(id -u)" -ne 0 ] && ! docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
	d="sudo -n docker"
fi
$d version --format '{{.Server.Version}}' >/dev/null 2>&1 ||
pre "the Docker daemon is not reachable, or the SSH user may not use it (docker group or sudo)"

# emit STATUS: result document from the globals. Every status but ok leaves
# the finding fields empty: the observation is unknown, never zero.
emit() {
	doc="{\"format\":\"image-vulns-v1\",\"phase\":\"done\",\"status\":\"$1\",\"image\":\"$img\""
	[ -n "$present" ] && doc="$doc,\"present\":$present"
	[ -n "$trivyv" ] && doc="$doc,\"trivy\":\"$(printf '%s' "$trivyv" | b64)\""
	[ -n "$dbv" ] && doc="$doc,\"dbver\":\"$(printf '%s' "$dbv" | b64)\""
	[ -n "$dba" ] && doc="$doc,\"dbage\":$dba"
	[ -n "$plat" ] && doc="$doc,\"platform\":\"$(printf '%s' "$plat" | b64)\""
	[ -n "$cached" ] && doc="$doc,\"cached\":true"
	[ -n "$summary" ] && doc="$doc,\"summary\":\"$(printf '%s' "$summary" | b64)\""
	printf '%s}\n' "$doc"
	exit 0
}
present=""; trivyv=""; dbv=""; dba=""; plat=""; cached=""; summary=""

# The image must already be local (never pulled). One call gives presence
# and the platform os/arch[/variant].
plat=$($d image inspect --format '{{.Os}}/{{.Architecture}}{{if .Variant}}/{{.Variant}}{{end}}' -- "$img" 2>/dev/null) || emit notlocal
[ -n "$plat" ] || emit notlocal

# Trivy follows the same access as docker: the user's own binary, or the
# root one via sudo -n (same daemon access). It is only ever used, never
# installed.
t="trivy"
if [ "$d" = "sudo -n docker" ]; then
	t="sudo -n trivy"
	$t --version >/dev/null 2>&1 || { present=false; emit absent; }
else
	command -v trivy >/dev/null 2>&1 || { present=false; emit absent; }
fi
present=true
trivyv=$($t --version 2>/dev/null | sed -n 's/^Version: *//p' | head -n 1 | head -c 100)

# Python's standard library provides strict JSON parsing and bounded pipe
# reads. Without it, the observation stays unknown; nothing is installed.
command -v python3 >/dev/null 2>&1 || pre "Python 3 is required for bounded scan reduction"
# --skip-java-db-update and --image-src docker complete the local-only
# profile: --offline-scan alone still permits registry fallback/Java DB fetches.
exec python3 -I - "$img" "$plat" "$trivyv" "$t" "$(id -u)" "$(date +%s)" <<'PYTHON'
import base64
import datetime
import fcntl
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

MAX_STDOUT = 16777216
MAX_STDERR = 65536
MAX_METADATA = 16384
MAX_SUMMARY = 1048576
MAX_DB_AGE = 86400
MAX_TARGETS = 1000
MAX_CVES = 1000000
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
image, platform, version, scanner, uid, now = sys.argv[1:]
now = int(now)
command = ["sudo", "-n", "trivy"] if scanner == "sudo -n trivy" else ["trivy"]
result = {"format": "image-vulns-v1", "phase": "done", "image": image,
          "present": True}


def encoded(value):
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


result.update(platform=encoded(platform), trivy=encoded(version))


class Truncated(Exception):
    pass


def capture(args, stdout_limit, stderr_limit):
    # Drain both pipes concurrently. Retain only bounded stdout in memory;
    # stderr is counted and discarded. No raw scanner report touches disk.
    with subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, start_new_session=True) as proc:
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ, True)
                selector.register(proc.stderr, selectors.EVENT_READ, False)
                output = bytearray()
                counts = {True: 0, False: 0}
                limits = {True: stdout_limit, False: stderr_limit}
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
                return proc.wait(), output
        finally:
            if proc.poll() is None:
                # Terminate the writer and its children, including a sudo
                # monitor that must forward the signal to its root child.
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON key")
        obj[key] = value
    return obj


def load_json(raw):
    def invalid_constant(value):
        raise ValueError("invalid JSON constant")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                      parse_constant=invalid_constant)


def private_workdir():
    # Walk with directory descriptors and O_NOFOLLOW so no component can
    # redirect root writes. Shared ancestors must be root-owned and sticky
    # (e.g. /tmp); the work directory itself must already be private/ours.
    parent = os.path.abspath(os.environ.get("TMPDIR", "/tmp"))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open("/", flags)
    try:
        for part in parent.split("/")[1:]:
            if not part:
                continue
            try:
                os.mkdir(part, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            shared = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if info.st_uid not in (0, os.geteuid()) or (info.st_mode & 0o022 and not shared):
                raise ValueError("unsafe scan parent")
        name = "nebula-image-vulns." + uid
        try:
            os.mkdir(name, 0o700, dir_fd=fd)
        except FileExistsError:
            pass
        child = os.open(name, flags, dir_fd=fd)
    finally:
        os.close(fd)
    info = os.fstat(child)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(child)
        raise ValueError("unsafe scan work directory")
    # Keep all subsequent operations relative to this verified directory.
    os.fchdir(child)
    os.close(child)
    for name in os.listdir("."):
        if name == "scan.lock" or name.startswith("c-"):
            safe_file(os.stat(name, follow_symlinks=False))


def safe_file(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o022 or info.st_nlink != 1):
        raise ValueError("unsafe existing scan file")


def database():
    # Trivy stores the Bolt database in trivy.db, and its authoritative
    # build time/schema in metadata.json. File mtimes change on provisioning.
    if scanner == "sudo -n trivy":
        path = "/root/.cache/trivy/db"
        rc, _ = capture(["sudo", "-n", "test", "-f", path + "/trivy.db"], MAX_METADATA, MAX_STDERR)
        if rc:
            raise ValueError("missing database")
        rc, raw = capture(["sudo", "-n", "cat", path + "/metadata.json"], MAX_METADATA, MAX_STDERR)
        if rc:
            raise ValueError("missing metadata")
    else:
        path = os.path.join(os.environ.get("TRIVY_CACHE_DIR", os.path.expanduser("~/.cache/trivy")), "db")
        if not os.path.isfile(os.path.join(path, "trivy.db")):
            raise ValueError("missing database")
        with open(os.path.join(path, "metadata.json"), "rb") as metadata:
            raw = metadata.read(MAX_METADATA + 1)
        if len(raw) > MAX_METADATA:
            raise ValueError("oversized metadata")
    meta = load_json(raw)
    if not isinstance(meta, dict) or type(meta.get("Version")) is not int or meta["Version"] != 2:
        raise ValueError("unsupported database schema")
    updated = meta.get("UpdatedAt")
    if not isinstance(updated, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})", updated):
        raise ValueError("invalid database time")
    stamp = datetime.datetime.fromisoformat(updated.replace("Z", "+00:00")).timestamp()
    result["dbver"] = encoded(str(int(stamp)))
    age = max(0, now - stamp)
    result["dbage"] = int(age // 3600)
    return age <= MAX_DB_AGE, updated


def reduce_report(raw):
    report = load_json(raw)
    if (not isinstance(report, dict) or type(report.get("SchemaVersion")) is not int
            or report["SchemaVersion"] != 2 or not isinstance(report.get("Results"), list)
            or len(report["Results"]) > MAX_TARGETS):
        raise ValueError("unsupported scan schema")
    seen = {}
    have_vulnerabilities = False
    for target in report["Results"]:
        if not isinstance(target, dict) or not isinstance(target.get("Target"), str):
            raise ValueError("invalid scan target")
        if "Vulnerabilities" not in target:
            continue
        have_vulnerabilities = True
        vulnerabilities = target["Vulnerabilities"]
        if vulnerabilities is None:
            continue
        if not isinstance(vulnerabilities, list):
            raise ValueError("invalid vulnerabilities")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise ValueError("invalid vulnerability")
            ident = vulnerability.get("VulnerabilityID")
            severity = vulnerability.get("Severity", "UNKNOWN")
            fixed = vulnerability.get("FixedVersion", "")
            if not all(isinstance(field, str) for field in (ident, severity, fixed)):
                raise ValueError("invalid vulnerability fields")
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{1,63}", ident):
                continue
            if severity not in SEVERITIES:
                severity = "UNKNOWN"
            fixed = "".join(c for c in fixed[:200] if " " <= c <= "~")
            if ident in seen:
                prior = seen[ident]
                if SEVERITIES.index(severity) < SEVERITIES.index(prior["severity"]):
                    prior["severity"] = severity
                if not prior["fixed"]:
                    prior["fixed"] = fixed
            else:
                seen[ident] = {"id": ident, "severity": severity, "fixed": fixed}
    if not have_vulnerabilities or len(seen) > MAX_CVES:
        raise ValueError("not a supported vulnerability scan")
    counts = dict.fromkeys(SEVERITIES, 0)
    for item in seen.values():
        counts[item["severity"]] += 1
    top = sorted(seen.values(), key=lambda item: (SEVERITIES.index(item["severity"]), item["id"]))[:25]
    return json.dumps({"severity": counts, "total": len(seen),
                       "targets": len(report["Results"]), "top": top}, separators=(",", ":"))


def scan():
    try:
        private_workdir()
        lock = os.open("scan.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        safe_file(os.fstat(lock))
    except (OSError, ValueError):
        result.clear()
        result.update(format="image-vulns-v1", phase="precheck", reason="unsafe scan work directory or files")
        return 10
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        result["status"] = "busy"
        return 0
    # No shared scan-file cleanup is ever installed. Busy invocations only
    # close their descriptor; unique cache files are cleaned by their owner.
    try:
        fresh, db_version = database()
    except (OSError, ValueError, TypeError, RecursionError, Truncated):
        result["status"] = "stale"
        return 0
    if not fresh:
        result["status"] = "stale"
        return 0
    # Invalidate summaries produced by the former line-based reducer.
    key = "c-" + hashlib.sha256(("json-v2|" + image + "|" + platform + "|" + db_version).encode()).hexdigest()
    try:
        cache = os.open(key, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        cache = None
    if cache is not None:
        with os.fdopen(cache, "rb") as cached:
            info = os.fstat(cached.fileno())
            safe_file(info)
            if 0 <= time.time() - info.st_mtime <= MAX_DB_AGE:
                raw = cached.read(MAX_SUMMARY + 1)
                if len(raw) <= MAX_SUMMARY:
                    summary = load_json(raw)
                    if isinstance(summary, dict) and all(k in summary for k in ("severity", "total", "targets", "top")):
                        result.update(status="ok", cached=True, summary=encoded(raw.decode("utf-8")))
                        return 0
    try:
        rc, raw = capture(command + ["image", "--offline-scan", "--skip-db-update",
                                    "--skip-java-db-update", "--image-src", "docker",
                                    "--scanners", "vuln", "--quiet", "--format", "json", "--", image],
                          MAX_STDOUT, MAX_STDERR)
    except Truncated:
        result["status"] = "truncated"
        return 0
    if rc:
        result["status"] = "failed"
        return 0
    try:
        summary = reduce_report(raw)
    except (ValueError, TypeError, RecursionError):
        result["status"] = "unsupported"
        return 0
    # Only the reduced summary is written, using an exclusive unique file
    # and atomic rename within the verified private parent, after locking.
    fd, temporary = tempfile.mkstemp(prefix=".summary-", dir=".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as cached:
            cached.write(summary)
        os.replace(temporary, key)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    result.update(status="ok", summary=encoded(summary))
    return 0


try:
    code = scan()
except (OSError, ValueError, TypeError, RecursionError):
    result["status"] = "failed"
    code = 0
print(json.dumps(result, separators=(",", ":")))
sys.exit(code)
PYTHON
