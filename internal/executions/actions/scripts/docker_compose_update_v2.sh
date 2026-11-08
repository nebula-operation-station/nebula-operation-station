#!/bin/sh
# docker.compose_update 2.0.0 (Nebula built-in, Docker Compose, durable job,
# batch members only, runs as root; ADR 0006 P2-03, container update plan
# cu02). It recreates exactly the frozen definition of its parameters, the
# update binding the executor rendered from the approved batch member
# ({"container_update": {...}}): the bound project, services, target
# containers and image digests. Nothing is reconstructed from `docker
# inspect`: the host is only read to prove that it still is what the binding
# says, and any difference stops the job before a change (exit 10).
#
# Phases (result format compose-update-v2, one JSON line on stdout):
#   1 precheck   labels, source digest, targets, scale, old tag, pins, NOS
#                override drift (Q2), applied configuration (Q21), ports,
#                old digests, dependency closure; then the baseline snapshot
#   2 resolve    every entry's new tag, anonymously, against the bound index
#                and platform digests (tag_moved, tag_unresolved)
#   3 pull       by bound platform digest only, with an empty DOCKER_CONFIG
#   4 retain     nos-retained:<execution-id>-<entry> for each old image
#   5 recreate   the NOS override gets image repository:new_tag@digest for
#                the frozen services, then `up -d --no-deps --no-build
#                --pull never <frozen services>`
#   6 snapshot   bounded health wait, then the after-snapshot (also after a
#                failed up)
# Every docker and docker compose call is silent (R4): stderr goes to
# /dev/null, stdout is read only where parsed, and the log holds fixed phase
# lines only. Env values, command lines, labels and the unkeyed Compose
# config hash never leave the host.
#
# Host state (root-only, created by docker.update_prepare and this job):
#   /var/lib/nebula/container-updates/salt                the per-host key (Q5)
#   /var/lib/nebula/container-updates/overrides/<p>.yaml  NOS override (Q2)
# Keyed digests (Q5, Q18), HMAC-SHA-256 with the salt as key:
#   configuration_digest = HMAC("nos-configuration-digest-v1\0" +
#       JSON{"Config","HostConfig"} of the container, keys sorted, compact)
#   source_digest = HMAC("nos-source-digest-v1\0" + stdout of `docker compose
#       -p <p> --project-directory <dir> -f <operator files> config`)
# Unkeyed identity hashes (paths only): working_dir_hash = SHA-256 of the
# working_dir label; config_files_hash = SHA-256 of the config_files label
# with the NOS override left out (operator paths joined by ",").
set -u
set -f
pre() { printf '{"format":"compose-update-v2","phase":"precheck","reason":"%s"}\n' "$1"; exit 10; }
[ "$(id -u)" -eq 0 ] || pre not_root
for tool in python3 docker curl timeout; do
	command -v "$tool" >/dev/null 2>&1 || pre tooling_missing
done
exec python3 -I - <<'PYTHON'
import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
import sys
import time
import urllib.parse

FORMAT = "compose-update-v2"
STATE_DIR = "/var/lib/nebula/container-updates"
SALT_FILE = STATE_DIR + "/salt"
OVERRIDE_DIR = STATE_DIR + "/overrides"

# Limits (container update plan cu01/cu02).
MAX_PARAMS_BYTES = 256 * 1024
MAX_IMAGES = 20
MAX_CONTAINERS = 50
MAX_OLD_DIGESTS = 8
MAX_CONFIG_FILES = 16
MAX_CONFIG_FILE_BYTES = 1024 * 1024
MAX_COMPOSE_CONFIG_BYTES = 4 * 1024 * 1024
MAX_INSPECT_BYTES = 1024 * 1024
MAX_INDEX_BYTES = 256 * 1024
MAX_SNAPSHOT_CONTAINER_BYTES = 8 * 1024
MAX_OVERRIDE_BYTES = 256 * 1024
MAX_RUN_REGISTRY_REQUESTS = 120
REGISTRY_SPACING = 1.0

# Phase budgets in seconds (Q25) and per-call bounds.
CHECK_BUDGET = 3 * 60
PULL_BUDGET = 12 * 60
RETAIN_BUDGET = 60
UP_BUDGET = 8 * 60
SNAPSHOT_BUDGET = 5 * 60
HEALTH_WAIT = 3 * 60
HEALTH_POLL = 5
KILL_GRACE = 10
CALL_BOUND = 30
CURL_BOUND = 10

L_PROJECT = "com.docker.compose.project"
L_SERVICE = "com.docker.compose.service"
L_WORKDIR = "com.docker.compose.project.working_dir"
L_FILES = "com.docker.compose.project.config_files"
L_HASH = "com.docker.compose.config-hash"
L_NUMBER = "com.docker.compose.container-number"
L_ONEOFF = "com.docker.compose.oneoff"

HEX64 = re.compile(r"[0-9a-f]{64}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
SERVICE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}")
PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
CNAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}")
PLATFORM = re.compile(r"[a-z0-9]{1,16}/[a-z0-9_]{1,16}(/[a-z0-9]{1,16})?")
POLICY = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
REGHOST = re.compile(r"(localhost|[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*)(:[0-9]{1,5})?")
PATHPART = re.compile(r"[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*")
TOKEN = re.compile(r"[A-Za-z0-9._~+/=-]{1,8192}")

ACCEPT = ",".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
])
INDEX_TYPES = ("application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json")


class Stop(Exception):
    """A typed stop: reason, and the bound service it concerns."""

    def __init__(self, reason, service=""):
        super().__init__(reason)
        self.reason = reason
        self.service = service


def log(line):
    # Fixed phase lines only (R4).
    sys.stderr.write("nos: " + line + "\n")
    sys.stderr.flush()


def fullmatch(rx, v):
    return isinstance(v, str) and rx.fullmatch(v) is not None


def hmac_hex(key, domain, data):
    return hmac.new(key, domain + b"\x00" + data, hashlib.sha256).hexdigest()


def canon(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# --- image references (canonical.ParseImageReference) -----------------------

def parse_ref(ref):
    """Returns (repository, tag, digest) in canonical form, or None."""
    if not isinstance(ref, str) or ref == "" or len(ref) > 512 or ref.startswith("-"):
        return None
    if any(c <= " " or c > "~" for c in ref):
        return None
    if ref.startswith("sha256:") or HEX64.fullmatch(ref):
        return None
    name, at, digest = ref.partition("@")
    if at and not DIGEST.fullmatch(digest):
        return None
    i = name.rfind(":")
    if i > name.rfind("/"):
        name, tag = name[:i], name[i + 1:]
        if not TAG.fullmatch(tag):
            return None
    elif at:
        return None
    else:
        tag = "latest"
    host, path = "docker.io", name
    first, slash, rest = name.partition("/")
    if slash and (("." in first or ":" in first) or first == "localhost"):
        host, path = first, rest
        if not REGHOST.fullmatch(host):
            return None
        if host == "index.docker.io":
            host = "docker.io"
    if host == "docker.io" and "/" not in path:
        path = "library/" + path
    for part in path.split("/"):
        if not PATHPART.fullmatch(part):
            return None
    repo = host + "/" + path
    if len(repo) > 255:
        return None
    return repo, tag, digest


def canonical_repo(repo):
    r = parse_ref(repo + ":latest") if isinstance(repo, str) else None
    return r is not None and r[0] == repo


# --- the binding --------------------------------------------------------------

def need(cond):
    if not cond:
        raise Stop("binding_invalid")


def keys(obj, required, optional=()):
    need(isinstance(obj, dict))
    need(set(required) <= set(obj) <= set(required) | set(optional))


def no_dupes(pairs):
    d = {}
    for k, v in pairs:
        need(k not in d)
        d[k] = v
    return d


def load_binding():
    path = os.environ.get("NEBULA_PARAMS", "")
    need(path.startswith("/"))
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_PARAMS_BYTES + 1)
    except OSError:
        raise Stop("binding_invalid")
    need(len(raw) <= MAX_PARAMS_BYTES)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=no_dupes)
    except (UnicodeDecodeError, ValueError):
        raise Stop("binding_invalid")
    keys(doc, ["container_update"])
    u = doc["container_update"]
    keys(u, ["kind", "form", "images", "targets", "dependencies", "source_digest", "project",
             "working_dir_hash", "config_files_hash"])
    # Only a public compose update: no registry, definition or rollback
    # binding (absent from the required set above, so refused).
    need(u["kind"] == "update" and u["form"] == "compose")
    need(fullmatch(PROJECT, u["project"]))
    for k in ("source_digest", "working_dir_hash", "config_files_hash"):
        need(fullmatch(HEX64, u[k]))
    images = u["images"]
    need(isinstance(images, list) and 1 <= len(images) <= MAX_IMAGES)
    by_service = {}
    prev = None
    for img in images:
        keys(img, ["service", "repository", "platform", "old_tag", "new_tag", "old_digests",
                   "new_platform_digest", "old_image_id"],
             ["new_index_digest", "policy_version", "policy_digest", "major_change"])
        s = img["service"]
        need(fullmatch(SERVICE, s) and (prev is None or prev < s))
        prev = s
        need(canonical_repo(img["repository"]) and fullmatch(PLATFORM, img["platform"]))
        need(fullmatch(TAG, img["old_tag"]) and fullmatch(TAG, img["new_tag"]))
        od = img["old_digests"]
        need(isinstance(od, list) and 1 <= len(od) <= MAX_OLD_DIGESTS)
        for i, d in enumerate(od):
            need(fullmatch(DIGEST, d) and (i == 0 or od[i - 1] < d))
        need(fullmatch(DIGEST, img["new_platform_digest"]) and fullmatch(DIGEST, img["old_image_id"]))
        nid = img.get("new_index_digest", "")
        need(nid == "" or (fullmatch(DIGEST, nid) and nid != img["new_platform_digest"]))
        same = img["old_tag"] == img["new_tag"]
        if same:
            need("policy_version" not in img and "policy_digest" not in img and "major_change" not in img)
            need(img["new_platform_digest"] not in od and (nid == "" or nid not in od))
        else:
            need(fullmatch(POLICY, img.get("policy_version")) and fullmatch(HEX64, img.get("policy_digest")))
            need("major_change" not in img or img["major_change"] is True)
        by_service[s] = img
    targets = u["targets"]
    need(isinstance(targets, list) and len(targets) >= 1)
    seen_ids, seen_names = set(), set()

    def claim(cid, name):
        need(fullmatch(HEX64, cid) and fullmatch(CNAME, name))
        need(cid not in seen_ids and name not in seen_names)
        seen_ids.add(cid)
        seen_names.add(name)

    prev = None
    targeted = set()
    for t in targets:
        keys(t, ["service", "container_id", "container_name", "image_id", "running_reference", "configuration_digest"])
        key = (t["service"], t["container_id"])
        need(isinstance(t["service"], str) and isinstance(t["container_id"], str))
        need(prev is None or prev < key)
        prev = key
        img = by_service.get(t["service"])
        need(img is not None)
        claim(t["container_id"], t["container_name"])
        need(fullmatch(DIGEST, t["image_id"]) and fullmatch(HEX64, t["configuration_digest"]))
        need(t["image_id"] == img["old_image_id"])
        r = parse_ref(t["running_reference"])
        need(r is not None and r[0] == img["repository"] and r[1] == img["old_tag"])
        targeted.add(t["service"])
    need(targeted == set(by_service))
    deps = u["dependencies"]
    need(isinstance(deps, list) and len(deps) <= MAX_CONTAINERS)
    prev = None
    count = len(targets)
    for d in deps:
        keys(d, ["service", "relation", "restart_on_update", "containers"])
        need(fullmatch(SERVICE, d["service"]) and (prev is None or prev < d["service"]))
        prev = d["service"]
        need(d["service"] not in by_service)
        need(d["relation"] in ("requires", "required_by") and isinstance(d["restart_on_update"], bool))
        cs = d["containers"]
        need(isinstance(cs, list) and len(cs) >= 1)
        p = None
        for c in cs:
            keys(c, ["container_id", "container_name", "configuration_digest"])
            need(isinstance(c["container_id"], str) and (p is None or p < c["container_id"]))
            p = c["container_id"]
            claim(c["container_id"], c["container_name"])
            need(fullmatch(HEX64, c["configuration_digest"]))
        count += len(cs)
    need(count <= MAX_CONTAINERS)
    return u


# --- bounded calls -------------------------------------------------------------

class Budget:
    def __init__(self, seconds, reason):
        self.deadline = time.monotonic() + seconds
        self.reason = reason

    def left(self):
        return self.deadline - time.monotonic()


BASE_ENV = {
    "PATH": os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
    "LC_ALL": "C",
    # Remote Compose loaders off (Q23): no git or OCI include from the files.
    "COMPOSE_EXPERIMENTAL_GIT_REMOTE": "false",
    "COMPOSE_EXPERIMENTAL_OCI_REMOTE": "false",
}
if os.environ.get("HOME", "").startswith("/"):
    BASE_ENV["HOME"] = os.environ["HOME"]


def call(args, budget, bound=CALL_BOUND, cap=MAX_INSPECT_BYTES, env=None, cwd=None):
    """Runs args under `timeout -k KILL_GRACE`, silently. The call's bound
    plus its kill grace must fit the budget, or it does not start. Returns
    (exit, stdout, elapsed, limit); stdout is None when it exceeded cap."""
    limit = int(min(bound, budget.left() - KILL_GRACE))
    if limit < 1:
        raise Stop(budget.reason)
    cmd = ["timeout", "-k", str(KILL_GRACE), str(limit)] + args
    start = time.monotonic()
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             env=env or BASE_ENV, cwd=cwd, close_fds=True)
    except OSError:
        raise Stop("tooling_missing")
    try:
        out, _ = p.communicate(timeout=limit + KILL_GRACE + 5)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
        return 137, None, time.monotonic() - start, limit
    if len(out) > cap:
        out = None
    return p.returncode, out, time.monotonic() - start, limit


def text(out, reason):
    if out is None:
        raise Stop(reason)
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        raise Stop(reason)


def inspect_container(cid, budget, reason="target_changed", service=""):
    rc, out, _, _ = call(["docker", "inspect", "--type", "container", "--", cid], budget)
    if rc != 0:
        raise Stop(reason, service)
    try:
        doc = json.loads(text(out, reason))
    except ValueError:
        raise Stop(reason, service)
    if not isinstance(doc, list) or len(doc) != 1 or not isinstance(doc[0], dict):
        raise Stop(reason, service)
    c = doc[0]
    for k in ("Config", "HostConfig", "State"):
        if not isinstance(c.get(k), dict):
            raise Stop(reason, service)
    if not isinstance(c["Config"].get("Labels") or {}, dict):
        raise Stop(reason, service)
    return c


def inspect_image(ref, budget, reason):
    rc, out, _, _ = call(["docker", "image", "inspect", "--", ref], budget)
    if rc != 0:
        raise Stop(reason)
    try:
        doc = json.loads(text(out, reason))
    except ValueError:
        raise Stop(reason)
    if not isinstance(doc, list) or len(doc) != 1 or not isinstance(doc[0], dict):
        raise Stop(reason)
    return doc[0]


def service_containers(project, service, budget):
    """Full IDs of the project's service containers, stopped ones included
    and one-off `run` containers excluded (Compose's own selection)."""
    rc, out, _, _ = call(["docker", "ps", "-a", "--no-trunc", "-q",
                          "--filter", "label=" + L_PROJECT + "=" + project,
                          "--filter", "label=" + L_SERVICE + "=" + service,
                          "--filter", "label=" + L_ONEOFF + "=False"], budget)
    if rc != 0:
        raise Stop("host_unreadable", service)
    ids = text(out, "host_unreadable").split()
    if len(ids) > MAX_CONTAINERS or not all(HEX64.fullmatch(i) for i in ids):
        raise Stop("host_unreadable", service)
    return sorted(set(ids))


def labels(c):
    return c["Config"].get("Labels") or {}


def config_digest(c, salt):
    return hmac_hex(salt, b"nos-configuration-digest-v1", canon({"Config": c["Config"], "HostConfig": c["HostConfig"]}))


def platform_of(img):
    o, a, v = img.get("Os"), img.get("Architecture"), img.get("Variant") or ""
    if not isinstance(o, str) or not isinstance(a, str) or not isinstance(v, str):
        return ""
    return o + "/" + a + ("/" + v if v else "")


def repo_digests(img):
    """The (canonical repository, digest) pairs an image lists."""
    out = set()
    for rd in img.get("RepoDigests") or []:
        if not isinstance(rd, str):
            continue
        name, at, dg = rd.partition("@")
        if not at or not DIGEST.fullmatch(dg):
            continue
        r = parse_ref(name + ":latest")
        if r is not None:
            out.add((r[0], dg))
    return out


# --- snapshots -----------------------------------------------------------------

def s(v, n=512):
    return v[:n] if isinstance(v, str) else ""


def snapshot_entry(c, salt):
    st = c["State"]
    health = st.get("Health") if isinstance(st.get("Health"), dict) else {}
    lb = labels(c)
    ns = c.get("NetworkSettings") if isinstance(c.get("NetworkSettings"), dict) else {}
    ports = []
    pm = ns.get("Ports") if isinstance(ns.get("Ports"), dict) else {}
    for cport, binds in pm.items():
        if not isinstance(binds, list) or not binds:
            ports.append(s(cport, 32))
            continue
        for b in binds:
            if isinstance(b, dict):
                ports.append(s(cport, 32) + "->" + s(b.get("HostIp"), 64) + ":" + s(b.get("HostPort"), 8))
    mounts = []
    for m in c.get("Mounts") or []:
        if isinstance(m, dict):
            mounts.append({"type": s(m.get("Type"), 16), "source": s(m.get("Source"), 1024),
                           "destination": s(m.get("Destination"), 1024), "mode": s(m.get("Mode"), 32),
                           "rw": m.get("RW") is True})
    nets = ns.get("Networks") if isinstance(ns.get("Networks"), dict) else {}
    return {
        "id": s(c.get("Id"), 64),
        "name": s(c.get("Name"), 130).lstrip("/"),
        "service": s(lb.get(L_SERVICE), 63),
        "replica": s(lb.get(L_NUMBER), 8),
        "state": s(st.get("Status"), 16),
        "started_at": s(st.get("StartedAt"), 40),
        "health": s(health.get("Status"), 16) or "none",
        "ports": sorted(ports),
        "mounts": sorted(mounts, key=lambda m: (m["destination"], m["source"])),
        "networks": sorted(s(n, 128) for n in nets),
        "image_id": s(c.get("Image"), 71),
        "running_reference": s(c["Config"].get("Image"), 512),
        "configuration_digest": config_digest(c, salt),
    }


def bounded_entry(c, salt):
    e = snapshot_entry(c, salt)
    if len(canon(e)) > MAX_SNAPSHOT_CONTAINER_BYTES:
        return None
    return e


# --- host state ------------------------------------------------------------------

def owned_private(st, kind):
    return kind(st.st_mode) and st.st_uid == os.geteuid() and (st.st_mode & 0o077) == 0


def read_salt():
    try:
        st = os.lstat(SALT_FILE)
    except FileNotFoundError:
        raise Stop("prepare_required")
    except OSError:
        raise Stop("salt_unsafe")
    if not owned_private(st, stat.S_ISREG) or not 32 <= st.st_size <= 4096:
        raise Stop("salt_unsafe")
    with open(SALT_FILE, "rb") as f:
        return f.read(4097)


def override_path(project):
    return OVERRIDE_DIR + "/" + project + ".yaml"


def read_override(project):
    """The NOS override's entries {service: reference}, or None when the
    project has none. Only this script writes it, so any other shape, owner
    or mode is drift."""
    p = override_path(project)
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return None
    except OSError:
        raise Stop("override_drift")
    if not owned_private(st, stat.S_ISREG) or st.st_size > MAX_OVERRIDE_BYTES:
        raise Stop("override_drift")
    try:
        with open(p, "rb") as f:
            doc = json.loads(f.read(MAX_OVERRIDE_BYTES + 1).decode("utf-8"), object_pairs_hook=no_dupes)
    except (OSError, UnicodeDecodeError, ValueError, Stop):
        raise Stop("override_drift")
    if not isinstance(doc, dict) or set(doc) != {"services"} or not isinstance(doc["services"], dict):
        raise Stop("override_drift")
    entries = {}
    for svc, v in doc["services"].items():
        if not fullmatch(SERVICE, svc) or not isinstance(v, dict) or set(v) != {"image"}:
            raise Stop("override_drift")
        r = parse_ref(v["image"])
        if r is None or not r[2]:
            raise Stop("override_drift")
        entries[svc] = v["image"]
    return entries


def write_override(project, entries):
    for d in (STATE_DIR, OVERRIDE_DIR):
        try:
            os.mkdir(d, 0o700)
        except FileExistsError:
            pass
        except OSError:
            raise Stop("override_write_failed")
        try:
            st = os.lstat(d)
        except OSError:
            raise Stop("override_write_failed")
        if not owned_private(st, stat.S_ISDIR):
            raise Stop("override_write_failed")
    body = json.dumps({"services": {k: {"image": entries[k]} for k in sorted(entries)}}, indent=2, sort_keys=True) + "\n"
    final = override_path(project)
    tmp = OVERRIDE_DIR + "/." + project + ".yaml.tmp"
    try:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, body.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, final)
        dfd = os.open(OVERRIDE_DIR, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        raise Stop("override_write_failed")


# --- phase 1: precheck -------------------------------------------------------------

class Unit:
    pass


def compose_base(unit, with_override):
    args = ["docker", "compose", "-p", unit.project, "--project-directory", unit.workdir]
    for f in unit.files:
        args += ["-f", f]
    if with_override:
        args += ["-f", unit.override]
    return args


def check_identity(unit, c, svc):
    lb = labels(c)
    if lb.get(L_PROJECT) != unit.project or lb.get(L_SERVICE) != svc:
        raise Stop("project_mismatch", svc)
    wd = lb.get(L_WORKDIR)
    files = lb.get(L_FILES)
    if not isinstance(wd, str) or not isinstance(files, str):
        raise Stop("project_mismatch", svc)
    parts = files.split(",")
    names_override = unit.override in parts
    ops = [p for p in parts if p != unit.override]
    if wd != unit.workdir or ops != unit.files:
        raise Stop("project_mismatch", svc)
    return names_override


def locate(u, first):
    """The project's directory and operator files, from the first bound
    target's labels, accepted only when they hash to the bound identities."""
    unit = Unit()
    unit.project = u["project"]
    unit.override = override_path(unit.project)
    lb = labels(first)
    wd, files = lb.get(L_WORKDIR), lb.get(L_FILES)
    if lb.get(L_PROJECT) != unit.project or not isinstance(wd, str) or not isinstance(files, str):
        raise Stop("project_mismatch", u["targets"][0]["service"])
    ops = [p for p in files.split(",") if p != unit.override]
    if hashlib.sha256(wd.encode("utf-8")).hexdigest() != u["working_dir_hash"] or \
            hashlib.sha256(",".join(ops).encode("utf-8")).hexdigest() != u["config_files_hash"]:
        raise Stop("project_mismatch")
    if not wd.startswith("/") or not os.path.isdir(wd):
        raise Stop("project_mismatch")
    if not 1 <= len(ops) <= MAX_CONFIG_FILES:
        raise Stop("unsupported_files")
    for p in ops:
        if not p.startswith("/"):
            raise Stop("unsupported_files")
        try:
            st = os.stat(p)
        except OSError:
            raise Stop("unsupported_files")
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_CONFIG_FILE_BYTES:
            raise Stop("unsupported_files")
    unit.workdir, unit.files = wd, ops
    return unit


def depends(svc_doc):
    """Direct dependencies of a rendered service: depends_on, links and
    volumes_from (Decision 12), with depends_on's restart flags, and the
    services it shares a namespace with."""
    deps, restart, shares = set(), set(), set()
    d = svc_doc.get("depends_on") or {}
    if isinstance(d, list):
        d = {k: {} for k in d}
    if not isinstance(d, dict):
        raise Stop("dependency_unsupported")
    for k, v in d.items():
        deps.add(k)
        if isinstance(v, dict) and v.get("restart") is True:
            restart.add(k)
    for ln in svc_doc.get("links") or []:
        if not isinstance(ln, str):
            raise Stop("dependency_unsupported")
        deps.add(ln.split(":", 1)[0])
    for vf in svc_doc.get("volumes_from") or []:
        if not isinstance(vf, str) or vf.startswith("container:"):
            raise Stop("dependency_unsupported")
        deps.add(vf.split(":", 1)[0])
    for k in ("network_mode", "ipc", "pid"):
        v = svc_doc.get(k)
        if isinstance(v, str) and v.startswith("service:"):
            shares.add(v[len("service:"):])
        elif isinstance(v, str) and v.startswith("container:"):
            raise Stop("dependency_unsupported")
    return deps, restart, shares


def closure(services, frozen):
    """The bound dependency set recomputed from the rendered project:
    {service: (relation, restart_on_update)}."""
    graph, restarts = {}, {}
    for name, doc in services.items():
        if not isinstance(doc, dict):
            raise Stop("dependency_unsupported")
        deps, restart, shares = depends(doc)
        # Namespace sharers must be recreated together.
        for other in shares:
            if (name in frozen) != (other in frozen):
                raise Stop("namespace_sharer", name)
        graph[name] = deps
        restarts[name] = restart
    for name, deps in graph.items():
        if not deps <= set(services):
            raise Stop("dependency_unsupported", name)

    def reach(start, edges):
        seen, todo = set(), list(start)
        while todo:
            n = todo.pop()
            for m in edges.get(n, ()):
                if m not in seen:
                    seen.add(m)
                    todo.append(m)
        return seen

    reverse = {}
    for name, deps in graph.items():
        for d in deps:
            reverse.setdefault(d, set()).add(name)
    requires = reach(frozen, graph) - frozen
    required_by = reach(frozen, reverse) - frozen
    out = {}
    for name in requires:
        out[name] = ("requires", False)
    for name in required_by - requires:
        out[name] = ("required_by", bool(restarts.get(name, set()) & frozen))
    return out


def phase1(u, salt, budget):
    log("phase 1: precheck")
    images = {img["service"]: img for img in u["images"]}
    frozen = set(images)
    tby = {}
    for t in u["targets"]:
        tby.setdefault(t["service"], []).append(t)
    containers = {}
    for t in u["targets"]:
        containers[t["container_id"]] = inspect_container(t["container_id"], budget, "target_changed", t["service"])
    unit = locate(u, containers[u["targets"][0]["container_id"]])
    entries = read_override(unit.project)

    # Labels, identities, state, references and configuration digests.
    names_override = {}
    for t in u["targets"]:
        svc = t["service"]
        c = containers[t["container_id"]]
        names_override[t["container_id"]] = check_identity(unit, c, svc)
        if c.get("Id") != t["container_id"] or c.get("Name") != "/" + t["container_name"] or c.get("Image") != t["image_id"]:
            raise Stop("target_changed", svc)
        if not hmac.compare_digest(config_digest(c, salt), t["configuration_digest"]):
            raise Stop("configuration_changed", svc)
        if c["State"].get("Status") != "running":
            raise Stop("target_not_running", svc)
        # old_tag: the running reference byte for byte (no normalization).
        if c["Config"].get("Image") != t["running_reference"]:
            raise Stop("old_tag_mismatch", svc)
    for svc in sorted(frozen):
        if service_containers(unit.project, svc, budget) != sorted(t["container_id"] for t in tby[svc]):
            raise Stop("target_changed", svc)

    # Operator pins and drift against the NOS override (Q2), per unit.
    for t in u["targets"]:
        svc = t["service"]
        has_digest = "@" in t["running_reference"]
        named = names_override[t["container_id"]]
        if entries is not None and svc in entries:
            if not named or t["running_reference"] != entries[svc]:
                raise Stop("override_drift", svc)
        elif has_digest:
            raise Stop("digest_pinned", svc)
        elif named:
            raise Stop("override_drift", svc)
    if entries is not None:
        for svc in sorted(set(entries) - frozen):
            for cid in service_containers(unit.project, svc, budget):
                c = inspect_container(cid, budget, "override_drift", svc)
                if unit.override not in (labels(c).get(L_FILES) or "").split(",") or c["Config"].get("Image") != entries[svc]:
                    raise Stop("override_drift", svc)
    unit.entries = entries or {}

    # The operator's files render to what the preview saw.
    rc, out, _, _ = call(compose_base(unit, False) + ["config"], budget, cap=MAX_COMPOSE_CONFIG_BYTES, cwd=unit.workdir)
    if rc != 0 or out is None:
        raise Stop("unsupported_files")
    if not hmac.compare_digest(hmac_hex(salt, b"nos-source-digest-v1", out), u["source_digest"]):
        raise Stop("source_changed")

    # The project as phase 5 will apply it (operator files and the override
    # as it is now): structure, scale, ports and dependencies.
    with_override = entries is not None
    rc, out, _, _ = call(compose_base(unit, with_override) + ["config", "--format", "json"], budget,
                         cap=MAX_COMPOSE_CONFIG_BYTES, cwd=unit.workdir)
    if rc != 0:
        raise Stop("unsupported_files")
    try:
        project_doc = json.loads(text(out, "unsupported_files"))
    except ValueError:
        raise Stop("unsupported_files")
    services = project_doc.get("services") if isinstance(project_doc, dict) else None
    if not isinstance(services, dict):
        raise Stop("unsupported_files")
    for svc in sorted(frozen):
        doc = services.get(svc)
        if not isinstance(doc, dict):
            raise Stop("project_mismatch", svc)
        if "build" in doc:
            raise Stop("build_unsupported", svc)
        scale = doc.get("scale")
        if scale is None:
            dep = doc.get("deploy") if isinstance(doc.get("deploy"), dict) else {}
            scale = dep.get("replicas", 1)
        if not isinstance(scale, int) or isinstance(scale, bool) or scale != len(tby[svc]):
            raise Stop("scale_mismatch", svc)
        for p in doc.get("ports") or []:
            pub = p.get("published") if isinstance(p, dict) else None
            if isinstance(pub, int) and not isinstance(pub, bool):
                pub = str(pub)
            if not isinstance(pub, str) or not pub.isdigit() or pub == "0":
                raise Stop("ephemeral_port", svc)

    # Applied configuration (Q21): the unkeyed hash stays on the host.
    order = sorted(frozen)
    rc, out, _, _ = call(compose_base(unit, with_override) + ["config", "--hash=" + ",".join(order)], budget,
                         cwd=unit.workdir)
    if rc != 0:
        raise Stop("config_not_applied")
    hashes = {}
    for line in text(out, "config_not_applied").splitlines():
        f = line.split()
        if len(f) == 2:
            hashes[f[0]] = f[1]
    for t in u["targets"]:
        h = hashes.get(t["service"])
        if not h or labels(containers[t["container_id"]]).get(L_HASH) != h:
            raise Stop("config_not_applied", t["service"])

    # The old image still lists every bound old digest.
    for img in u["images"]:
        im = inspect_image(img["old_image_id"], budget, "old_digest_missing")
        if im.get("Id") != img["old_image_id"]:
            raise Stop("old_digest_missing", img["service"])
        listed = {d for (r, d) in repo_digests(im) if r == img["repository"]}
        if not set(img["old_digests"]) <= listed:
            raise Stop("old_digest_missing", img["service"])

    # The dependency closure and each dependency container.
    want = {d["service"]: (d["relation"], d["restart_on_update"]) for d in u["dependencies"]}
    if closure(services, frozen) != want:
        raise Stop("dependency_set_changed")
    for d in u["dependencies"]:
        svc = d["service"]
        if service_containers(unit.project, svc, budget) != [c["container_id"] for c in d["containers"]]:
            raise Stop("dependency_changed", svc)
        for bc in d["containers"]:
            c = inspect_container(bc["container_id"], budget, "dependency_changed", svc)
            containers[bc["container_id"]] = c
            if c.get("Id") != bc["container_id"] or c.get("Name") != "/" + bc["container_name"] or \
                    labels(c).get(L_PROJECT) != unit.project or labels(c).get(L_SERVICE) != svc:
                raise Stop("dependency_changed", svc)
            if not hmac.compare_digest(config_digest(c, salt), bc["configuration_digest"]):
                raise Stop("dependency_changed", svc)

    # Baseline, in the after-snapshot's format.
    baseline = []
    for cid in [t["container_id"] for t in u["targets"]] + [c["container_id"] for d in u["dependencies"] for c in d["containers"]]:
        e = bounded_entry(containers[cid], salt)
        if e is None:
            raise Stop("snapshot_too_large")
        baseline.append(e)
    return unit, baseline


# --- phase 2: resolve ----------------------------------------------------------------

class Registry:
    def __init__(self, budget):
        self.budget = budget
        self.count = 0
        self.last = {}
        self.tokens = {}

    def curl(self, host, args):
        if self.count >= MAX_RUN_REGISTRY_REQUESTS:
            raise Stop("tag_unresolved")
        wait = self.last.get(host, -1e9) + REGISTRY_SPACING - time.monotonic()
        if wait > 0:
            if self.budget.left() - wait < KILL_GRACE + 1:
                raise Stop("tag_unresolved")
            time.sleep(wait)
        limit = int(min(CURL_BOUND, self.budget.left() - KILL_GRACE))
        if limit < 1:
            raise Stop("tag_unresolved")
        self.count += 1
        self.last[host] = time.monotonic()
        rc, out, _, _ = call(["curl", "--proto", "=https", "--max-redirs", "0", "--connect-timeout", "5",
                              "--max-time", str(limit), "-s", "-i"] + args, self.budget, bound=limit + 1,
                             cap=MAX_INDEX_BYTES + 64 * 1024)
        if rc != 0 or out is None:
            raise Stop("tag_unresolved")
        head, sep, body = out.partition(b"\r\n\r\n")
        if not sep:
            head, sep, body = out.partition(b"\n\n")
        lines = head.decode("latin-1").replace("\r", "").split("\n")
        try:
            code = int(lines[0].split()[1])
        except (IndexError, ValueError):
            raise Stop("tag_unresolved")
        headers = {}
        for ln in lines[1:]:
            k, c, v = ln.partition(":")
            if c:
                headers.setdefault(k.strip().lower(), v.strip())
        if code == 429:
            self.count = MAX_RUN_REGISTRY_REQUESTS  # no later request this run
            raise Stop("tag_unresolved")
        return code, headers, body

    def request(self, host, path, url, head):
        base = ["-H", "Accept: " + ACCEPT]
        if head:
            base = ["-I"] + base
        tok = self.tokens.get((host, path))
        auth = ["-H", "Authorization: Bearer " + tok] if tok else []
        code, h, body = self.curl(host, base + auth + ["--", url])
        if code == 401 and tok is None:
            chal = h.get("www-authenticate", "")
            realm = re.search(r'realm="(https://[^"]{1,512})"', chal)
            service = re.search(r'service="([^"]{0,256})"', chal)
            if not realm:
                raise Stop("tag_unresolved")
            q = urllib.parse.urlencode({"service": service.group(1) if service else "", "scope": "repository:" + path + ":pull"})
            tcode, _, tbody = self.curl(host, ["--", realm.group(1) + "?" + q])
            if tcode != 200:
                raise Stop("tag_unresolved")
            try:
                tdoc = json.loads(tbody[:65536].decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                raise Stop("tag_unresolved")
            tok = tdoc.get("token") or tdoc.get("access_token") if isinstance(tdoc, dict) else None
            if not fullmatch(TOKEN, tok):
                raise Stop("tag_unresolved")
            self.tokens[(host, path)] = tok
            code, h, body = self.curl(host, base + ["-H", "Authorization: Bearer " + tok, "--", url])
        if code != 200:
            raise Stop("tag_unresolved")
        return h, body


def registry_of(repo):
    host, _, path = repo.partition("/")
    return ("registry-1.docker.io" if host == "docker.io" else host), path


def phase2(u, budget):
    log("phase 2: resolve")
    reg = Registry(budget)
    for img in u["images"]:
        svc = img["service"]
        try:
            host, path = registry_of(img["repository"])
            url = "https://" + host + "/v2/" + path + "/manifests/" + img["new_tag"]
            h, _ = reg.request(host, path, url, True)
            dg = h.get("docker-content-digest", "")
            ctype = h.get("content-type", "").split(";")[0].strip()
            if not DIGEST.fullmatch(dg):
                raise Stop("tag_unresolved")
            if ctype in INDEX_TYPES:
                if dg != img.get("new_index_digest", ""):
                    raise Stop("tag_moved")
                _, body = reg.request(host, path, "https://" + host + "/v2/" + path + "/manifests/" + dg, False)
                if len(body) > MAX_INDEX_BYTES or "sha256:" + hashlib.sha256(body).hexdigest() != dg:
                    raise Stop("tag_unresolved")
                try:
                    idx = json.loads(body.decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    raise Stop("tag_unresolved")
                found = ""
                for m in (idx.get("manifests") if isinstance(idx, dict) else None) or []:
                    p = m.get("platform") if isinstance(m, dict) else None
                    if not isinstance(p, dict):
                        continue
                    name = "%s/%s" % (p.get("os"), p.get("architecture"))
                    if p.get("variant"):
                        name += "/" + str(p.get("variant"))
                    if name == img["platform"] and DIGEST.fullmatch(str(m.get("digest"))):
                        found = m["digest"]
                        break
                if not found:
                    raise Stop("tag_unresolved")
                if found != img["new_platform_digest"]:
                    raise Stop("tag_moved")
            else:
                if img.get("new_index_digest", "") or dg != img["new_platform_digest"]:
                    raise Stop("tag_moved")
        except Stop as e:
            e.service = svc
            raise


# --- phase 3: pull, phase 4: retain ------------------------------------------------------

def phase3(u, budget):
    log("phase 3: pull")
    run_dir = os.environ.get("NEBULA_RUN_DIR", "")
    empty = run_dir + "/nos-empty-docker-config"
    try:
        os.mkdir(empty, 0o700)
    except OSError:
        raise Stop("pull_failed")
    env = dict(BASE_ENV)
    env["DOCKER_CONFIG"] = empty
    done = set()
    for img in u["images"]:
        ref = img["repository"] + "@" + img["new_platform_digest"]
        if ref in done:
            continue
        done.add(ref)
        if budget.left() - KILL_GRACE < 1:
            raise Stop("pull_timeout", img["service"])
        rc, _, elapsed, limit = call(["docker", "pull", "-q", "--", ref], budget, bound=PULL_BUDGET, cap=64 * 1024, env=env)
        if rc in (124, 137) and elapsed >= limit:
            raise Stop("pull_timeout", img["service"])
        if rc != 0:
            raise Stop("pull_failed", img["service"])
    pulled = []
    for img in u["images"]:
        ref = img["repository"] + "@" + img["new_platform_digest"]
        im = inspect_image(ref, budget, "pulled_image_mismatch")
        if platform_of(im) != img["platform"] or (img["repository"], img["new_platform_digest"]) not in repo_digests(im):
            raise Stop("pulled_image_mismatch", img["service"])
        iid = im.get("Id")
        if not fullmatch(DIGEST, iid):
            raise Stop("pulled_image_mismatch", img["service"])
        pulled.append({"service": img["service"], "image_id": iid})
    return pulled


def phase4(u, execution, budget):
    log("phase 4: retain")
    retained = []
    for i, img in enumerate(u["images"]):
        tag = "nos-retained:%s-%d" % (execution, i)
        rc, _, _, _ = call(["docker", "tag", img["old_image_id"], tag], budget)
        if rc != 0:
            raise Stop("retain_failed", img["service"])
        im = inspect_image(tag, budget, "retain_failed")
        if im.get("Id") != img["old_image_id"]:
            raise Stop("retain_failed", img["service"])
        retained.append({"service": img["service"], "tag": tag})
    return retained


# --- phase 5: recreate, phase 6: after-snapshot ------------------------------------------

def phase5(u, unit, budget):
    log("phase 5: recreate")
    entries = dict(unit.entries)
    for img in u["images"]:
        entries[img["service"]] = img["repository"] + ":" + img["new_tag"] + "@" + img["new_platform_digest"]
    write_override(unit.project, entries)
    order = sorted(img["service"] for img in u["images"])
    args = compose_base(unit, True) + ["up", "-d", "--no-deps", "--no-build", "--pull", "never"] + order
    try:
        rc, _, elapsed, limit = call(args, budget, bound=UP_BUDGET, cap=64 * 1024, cwd=unit.workdir)
    except Stop:
        return -1, "up_failed"  # up did not start; the override is already written
    if rc == 0:
        return 0, ""
    if rc in (124, 137) and elapsed >= limit:
        return rc, "up_timeout"
    return rc, "up_failed"


def phase6(u, unit, salt, budget):
    log("phase 6: after-snapshot")
    svcs = sorted({img["service"] for img in u["images"]} | {d["service"] for d in u["dependencies"]})
    wait_until = time.monotonic() + min(HEALTH_WAIT, max(0, budget.left() - 60))
    while True:
        found = []
        for svc in svcs:
            for cid in service_containers(unit.project, svc, budget):
                found.append(inspect_container(cid, budget, "snapshot_failed", svc))
        starting = any((c["State"].get("Health") or {}).get("Status") == "starting"
                       for c in found if isinstance(c["State"].get("Health") or {}, dict))
        if not starting or time.monotonic() + HEALTH_POLL > wait_until:
            break
        time.sleep(HEALTH_POLL)
    after = []
    for c in found:
        e = bounded_entry(c, salt)
        after.append(e if e is not None else {"id": s(c.get("Id"), 64), "oversize": True})
    return after


# --- main ------------------------------------------------------------------------------------

def emit(doc, code):
    sys.stdout.write(json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    sys.exit(code)


RESULT = {"format": FORMAT, "phase": "precheck", "reason": ""}
STOPPING_PHASES = ("precheck", "resolve", "pull", "retain")


def main():
    result = RESULT
    try:
        u = load_binding()
    except Stop as e:
        result["reason"] = e.reason
        emit(result, 10)
    result["project"] = u["project"]
    execution = os.environ.get("NEBULA_EXECUTION_ID", "")
    run_dir = os.environ.get("NEBULA_RUN_DIR", "")
    if not UUID.fullmatch(execution) or not run_dir.startswith("/") or not os.path.isdir(run_dir):
        result["reason"] = "environment_invalid"
        emit(result, 10)
    check = Budget(CHECK_BUDGET, "budget_exceeded")
    try:
        salt = read_salt()
        unit, baseline = phase1(u, salt, check)
        result["baseline"] = baseline
        result["phase"] = "resolve"
        check.reason = "tag_unresolved"
        phase2(u, check)
        result["phase"] = "pull"
        result["pulled"] = phase3(u, Budget(PULL_BUDGET, "pull_timeout"))
        result["phase"] = "retain"
        result["retained"] = phase4(u, execution, Budget(RETAIN_BUDGET, "retain_failed"))
        result["phase"] = "recreate"
        result["up_exit"] = -1
        up_exit, reason = phase5(u, unit, Budget(UP_BUDGET, "up_timeout"))
    except Stop as e:
        result["reason"] = e.reason
        if e.service:
            result["service"] = e.service
        emit(result, 10)
    result["up_exit"] = up_exit
    result["reason"] = reason
    result["phase"] = "after_snapshot"
    try:
        result["after"] = phase6(u, unit, salt, Budget(SNAPSHOT_BUDGET, "snapshot_failed"))
    except Stop:
        if not reason:
            result["reason"] = "snapshot_failed"
    emit(result, 0 if up_exit == 0 else 1)


try:
    main()
except SystemExit:
    raise
except Exception:
    # Never a traceback (it could carry host values). The result keeps the
    # phase reached and the baseline; exit 10 only while nothing changed.
    RESULT["reason"] = "internal_error"
    emit(RESULT, 10 if RESULT["phase"] in STOPPING_PHASES else 1)
PYTHON
