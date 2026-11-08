#!/bin/sh
# docker.update_preview 1.0.0 (Nebula built-in, durable job, classic path,
# runs as root; ADR 0006 P2-03, container update plan cu02). A LOW,
# read-only preview of the host's containers for a container update
# binding: identity and image facts, the keyed configuration and source
# digests, the dependency graph, and for each unit the reasons that make
# it unavailable. It writes nothing on the host: it never creates the salt
# (docker.update_prepare does), never pulls, tags, starts, stops or
# recreates, and never touches the NOS override.
#
# Result format docker-update-preview-v1, one JSON line on stdout. Every
# docker and docker compose call is silent (R4): stderr goes to /dev/null,
# stdout is read only where parsed, and the log holds fixed phase lines
# only. Env values, command lines, label values other than the Compose
# identity labels, file paths and the unkeyed Compose config hash never
# leave the host.
#
# Keyed digests: exactly the canonical form and HMAC of
# docker_compose_update_v2.sh (Q5, Q18), with the salt as key:
#   configuration_digest = HMAC("nos-configuration-digest-v1\0" +
#       JSON{"Config","HostConfig"} of the container, keys sorted, compact)
#   source_digest = HMAC("nos-source-digest-v1\0" + stdout of `docker compose
#       -p <p> --project-directory <dir> -f <operator files> config`)
# Unkeyed identity hashes (paths only): working_dir_hash = SHA-256 of the
# working_dir label; config_files_hash = SHA-256 of the config_files label
# with the NOS override left out (operator paths joined by ",").
#
# Parameters: {"target_tags": "<tag>[,<tag>...]"} (may be empty). Each
# image's current tag and every target tag are resolved anonymously to the
# index and platform digests, with the request of docker.compose_update.
set -u
set -f
fail() { printf '{"format":"docker-update-preview-v1","status":"%s","units":[]}\n' "$1"; exit 1; }
[ "$(id -u)" -eq 0 ] || fail not_root
for tool in python3 docker curl timeout; do
	command -v "$tool" >/dev/null 2>&1 || fail tooling_missing
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

FORMAT = "docker-update-preview-v1"
STATE_DIR = "/var/lib/nebula/container-updates"
SALT_FILE = STATE_DIR + "/salt"
OVERRIDE_DIR = STATE_DIR + "/overrides"

# Limits (container update plan cu02; the parser in
# internal/executions/dockerhost enforces the same values).
MAX_PARAMS_BYTES = 4096
MAX_PREVIEW_CONTAINERS = 200
MAX_PREVIEW_PROJECTS = 50
MAX_PREVIEW_TARGET_TAGS = 20
MAX_CONFIG_FILES = 16
MAX_CONFIG_FILE_BYTES = 1024 * 1024
MAX_COMPOSE_CONFIG_BYTES = 4 * 1024 * 1024
MAX_INSPECT_BYTES = 1024 * 1024
MAX_INDEX_BYTES = 256 * 1024
MAX_PREVIEW_RESULT_BYTES = 768 * 1024
MAX_OLD_DIGESTS = 8
MAX_OVERRIDE_BYTES = 256 * 1024
MAX_LIST_BYTES = 1024 * 1024
MAX_RUN_REGISTRY_REQUESTS = 120
REGISTRY_SPACING = 1.0
# The most a truncated unit head takes in the result.
HEAD_RESERVE = 192

# The wall clock of the whole preview: one minute of the 5-minute job is
# left for the result (Q24).
MAX_PREVIEW_WALL_CLOCK = 4 * 60
KILL_GRACE = 10
CALL_BOUND = 30
CURL_BOUND = 10

L_PROJECT = "com.docker.compose.project"
L_SERVICE = "com.docker.compose.service"
L_WORKDIR = "com.docker.compose.project.working_dir"
L_FILES = "com.docker.compose.project.config_files"
L_HASH = "com.docker.compose.config-hash"
L_ONEOFF = "com.docker.compose.oneoff"

HEX64 = re.compile(r"[0-9a-f]{64}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
SERVICE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}")
PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
CNAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}")
PLATFORM = re.compile(r"[a-z0-9]{1,16}/[a-z0-9_]{1,16}(/[a-z0-9]{1,16})?")
TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
REGHOST = re.compile(r"(localhost|[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*)(:[0-9]{1,5})?")
PATHPART = re.compile(r"[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*")
TOKEN = re.compile(r"[A-Za-z0-9._~+/=-]{1,8192}")
STATES = ("created", "running", "paused", "restarting", "removing", "exited", "dead")

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


# --- parameters ---------------------------------------------------------------

def need(cond):
    if not cond:
        raise Stop("params_invalid")


def no_dupes(pairs):
    d = {}
    for k, v in pairs:
        need(k not in d)
        d[k] = v
    return d


def load_params():
    path = os.environ.get("NEBULA_PARAMS", "")
    need(path.startswith("/"))
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_PARAMS_BYTES + 1)
    except OSError:
        raise Stop("params_invalid")
    need(len(raw) <= MAX_PARAMS_BYTES)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=no_dupes)
    except (UnicodeDecodeError, ValueError):
        raise Stop("params_invalid")
    need(isinstance(doc, dict) and set(doc) == {"target_tags"} and isinstance(doc["target_tags"], str))
    v = doc["target_tags"]
    tags = v.split(",") if v else []
    need(len(tags) <= MAX_PREVIEW_TARGET_TAGS and len(set(tags)) == len(tags))
    need(all(TAG.fullmatch(t) for t in tags))
    return tags


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


def pcall(args, budget, reason, cap=MAX_INSPECT_BYTES, cwd=None):
    """A call whose failure is reason, unless the budget ran out meanwhile:
    then the unit is cut off (truncated), never reported half."""
    rc, out, _, _ = call(args, budget, cap=cap, cwd=cwd)
    if rc != 0 or out is None:
        if budget.left() - KILL_GRACE < 1:
            raise Stop(budget.reason)
        raise Stop(reason)
    return out


def text(out, reason):
    if out is None:
        raise Stop(reason)
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        raise Stop(reason)


def inspect_container(cid, budget):
    out = pcall(["docker", "inspect", "--type", "container", "--", cid], budget, "host_unreadable")
    try:
        doc = json.loads(text(out, "host_unreadable"))
    except ValueError:
        raise Stop("host_unreadable")
    if not isinstance(doc, list) or len(doc) != 1 or not isinstance(doc[0], dict):
        raise Stop("host_unreadable")
    c = doc[0]
    for k in ("Config", "HostConfig", "State"):
        if not isinstance(c.get(k), dict):
            raise Stop("host_unreadable")
    if not isinstance(c["Config"].get("Labels") or {}, dict):
        raise Stop("host_unreadable")
    if c.get("Id") != cid:
        raise Stop("host_unreadable")
    return c


def inspect_image(ref, budget):
    """The image, or None when the daemon cannot show it."""
    try:
        out = pcall(["docker", "image", "inspect", "--", ref], budget, "image_unreadable")
        doc = json.loads(text(out, "image_unreadable"))
    except ValueError:
        return None
    except Stop as e:
        if e.reason == "image_unreadable":
            return None
        raise
    if not isinstance(doc, list) or len(doc) != 1 or not isinstance(doc[0], dict):
        return None
    return doc[0]


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


# --- host state (read only) ------------------------------------------------------

def owned_private(st, kind):
    return kind(st.st_mode) and st.st_uid == os.geteuid() and (st.st_mode & 0o077) == 0


def read_private(path, limit):
    """Reads a root-only regular file without following a symlink; the
    checks apply to the opened file itself. FileNotFoundError passes on;
    any other problem is ValueError."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        raise
    except OSError:
        raise ValueError(path)
    try:
        st = os.fstat(fd)
        if not owned_private(st, stat.S_ISREG) or st.st_size > limit:
            raise ValueError(path)
        data = os.read(fd, limit + 1)
    except OSError:
        raise ValueError(path)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise ValueError(path)
    return data


def read_salt():
    try:
        salt = read_private(SALT_FILE, 4096)
    except FileNotFoundError:
        raise Stop("prepare_required")
    except ValueError:
        raise Stop("salt_unsafe")
    if len(salt) < 32:
        raise Stop("salt_unsafe")
    return salt


def override_path(project):
    return OVERRIDE_DIR + "/" + project + ".yaml"


def read_override(project):
    """The NOS override's entries {service: reference}, or None when the
    project has none. Only this script writes it, so any other shape, owner
    or mode is drift."""
    try:
        raw = read_private(override_path(project), MAX_OVERRIDE_BYTES)
    except FileNotFoundError:
        return None
    except ValueError:
        raise Stop("override_drift")
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=no_dupes)
    except (UnicodeDecodeError, ValueError, Stop):
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


# --- Compose project facts -------------------------------------------------------

class Unit:
    pass


def compose_base(unit, with_override):
    args = ["docker", "compose", "-p", unit.project, "--project-directory", unit.workdir]
    for f in unit.files:
        args += ["-f", f]
    if with_override:
        args += ["-f", unit.override]
    return args


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


def locate(project, containers):
    """The project's directory and operator files, from the containers'
    labels, which must agree; the files are checked like the update does."""
    unit = Unit()
    unit.project = project
    unit.override = override_path(project)
    seen = set()
    for c in containers:
        lb = labels(c)
        wd, files = lb.get(L_WORKDIR), lb.get(L_FILES)
        if not isinstance(wd, str) or not isinstance(files, str):
            raise Stop("project_mismatch")
        seen.add((wd, tuple(p for p in files.split(",") if p != unit.override)))
    if len(seen) != 1:
        raise Stop("project_mismatch")
    wd, ops = seen.pop()
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
    unit.workdir, unit.files = wd, list(ops)
    unit.working_dir_hash = hashlib.sha256(wd.encode("utf-8")).hexdigest()
    unit.config_files_hash = hashlib.sha256(",".join(ops).encode("utf-8")).hexdigest()
    return unit


def scale_of(doc):
    scale = doc.get("scale")
    if scale is None:
        dep = doc.get("deploy") if isinstance(doc.get("deploy"), dict) else {}
        scale = dep.get("replicas", 1)
    if not isinstance(scale, int) or isinstance(scale, bool) or scale < 0:
        return -1
    return scale


def ephemeral(doc):
    for p in doc.get("ports") or []:
        pub = p.get("published") if isinstance(p, dict) else None
        if isinstance(pub, int) and not isinstance(pub, bool):
            pub = str(pub)
        if not isinstance(pub, str) or not pub.isdigit() or pub == "0":
            return True
    return False


# --- registry (the request of docker.compose_update phase 2) ------------------------

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
                raise Stop(self.budget.reason)
            time.sleep(wait)
        limit = int(min(CURL_BOUND, self.budget.left() - KILL_GRACE))
        if limit < 1:
            raise Stop(self.budget.reason)
        self.count += 1
        self.last[host] = time.monotonic()
        # -q first: no ~/.curlrc may add a proxy, -L or -k.
        rc, out, _, _ = call(["curl", "-q", "--proto", "=https", "--max-redirs", "0", "--connect-timeout", "5",
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


def resolve(reg, repo, platform, tag):
    """(index_digest, platform_digest) of repo:tag for platform; index_digest
    is "" for a single-platform manifest. Stop("tag_unresolved") otherwise."""
    host, path = registry_of(repo)
    url = "https://" + host + "/v2/" + path + "/manifests/" + tag
    h, _ = reg.request(host, path, url, True)
    dg = h.get("docker-content-digest", "")
    ctype = h.get("content-type", "").split(";")[0].strip()
    if not DIGEST.fullmatch(dg):
        raise Stop("tag_unresolved")
    if ctype not in INDEX_TYPES:
        return "", dg
    _, body = reg.request(host, path, "https://" + host + "/v2/" + path + "/manifests/" + dg, False)
    if len(body) > MAX_INDEX_BYTES or "sha256:" + hashlib.sha256(body).hexdigest() != dg:
        raise Stop("tag_unresolved")
    try:
        idx = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Stop("tag_unresolved")
    for m in (idx.get("manifests") if isinstance(idx, dict) else None) or []:
        p = m.get("platform") if isinstance(m, dict) else None
        if not isinstance(p, dict):
            continue
        name = "%s/%s" % (p.get("os"), p.get("architecture"))
        if p.get("variant"):
            name += "/" + str(p.get("variant"))
        if name == platform and DIGEST.fullmatch(str(m.get("digest"))):
            return dg, m["digest"]
    raise Stop("tag_unresolved")


# --- facts ---------------------------------------------------------------------------

class Preview:
    def __init__(self, salt, tags, budget):
        self.salt = salt
        self.tags = tags
        self.budget = budget
        self.reg = Registry(budget)
        self.resolved = {}

    def resolution(self, repo, platform, tag):
        key = (repo, platform, tag)
        if key not in self.resolved:
            try:
                idx, pd = resolve(self.reg, repo, platform, tag)
                self.resolved[key] = {"tag": tag, "index_digest": idx, "platform_digest": pd, "reason": ""}
            except Stop as e:
                if e.reason != "tag_unresolved":
                    raise
                self.resolved[key] = {"tag": tag, "index_digest": "", "platform_digest": "", "reason": "tag_unresolved"}
        return self.resolved[key]

    def target(self, c, service):
        name = c.get("Name")
        state = c["State"].get("Status")
        ref = c["Config"].get("Image")
        iid = c.get("Image")
        if not isinstance(name, str) or not fullmatch(CNAME, name[1:]) or name[:1] != "/":
            raise Stop("host_unreadable")
        if state not in STATES or not fullmatch(DIGEST, iid) or not isinstance(ref, str) or ref == "" or len(ref) > 512:
            raise Stop("host_unreadable")
        if any(ch <= " " or ch > "~" for ch in ref):
            raise Stop("host_unreadable")
        return {"service": service, "container_id": c["Id"], "container_name": name[1:], "state": state,
                "image_id": iid, "running_reference": ref, "configuration_digest": config_digest(c, self.salt)}

    def image(self, iid, ref):
        """Facts of one (image ID, running reference) pair."""
        e = {"image_id": iid, "running_reference": ref, "repository": "", "tag": "", "platform": "",
             "old_digests": [], "resolved": [], "reason": ""}
        r = parse_ref(ref)
        if r is None:
            e["reason"] = "reference_unsupported"
            return e
        e["repository"], e["tag"] = r[0], r[1]
        im = inspect_image(iid, self.budget)
        if im is None or im.get("Id") != iid:
            e["reason"] = "old_digest_unknown"
            return e
        p = platform_of(im)
        if not fullmatch(PLATFORM, p):
            e["reason"] = "platform_unknown"
            return e
        e["platform"] = p
        od = sorted({d for (rp, d) in repo_digests(im) if rp == r[0]})
        if not od or len(od) > MAX_OLD_DIGESTS:
            e["reason"] = "old_digest_unknown"
            return e
        e["old_digests"] = od
        for tag in [r[1]] + [t for t in self.tags if t != r[1]]:
            e["resolved"].append(self.resolution(r[0], p, tag))
        return e

    def images(self, targets):
        pairs = sorted({(t["image_id"], t["running_reference"]) for t in targets})
        return [self.image(i, r) for (i, r) in pairs]

    def standalone(self, cid):
        c = inspect_container(cid, self.budget)
        t = self.target(c, "")
        return {"form": "standalone", "project": "", "container_id": cid, "reason": "", "targets": [t],
                "images": self.images([t])}

    def compose(self, project, ids):
        containers = [inspect_container(cid, self.budget) for cid in ids]
        for c in containers:
            lb = labels(c)
            if lb.get(L_PROJECT) != project or not fullmatch(SERVICE, lb.get(L_SERVICE)) or lb.get(L_ONEOFF) != "False":
                raise Stop("project_mismatch")
        unit = locate(project, containers)
        by_svc = {}
        for c in containers:
            by_svc.setdefault(labels(c)[L_SERVICE], []).append(c)
        svc_reasons = {s: set() for s in by_svc}

        # NOS override drift (Q2), judged per unit; operator pins per service.
        drift = False
        try:
            entries = read_override(project)
        except Stop:
            drift, entries = True, None
        for svc, cs in by_svc.items():
            for c in cs:
                ref = c["Config"].get("Image")
                named = unit.override in (labels(c).get(L_FILES) or "").split(",")
                if entries is not None and svc in entries:
                    if not named or ref != entries[svc]:
                        drift = True
                elif isinstance(ref, str) and "@" in ref:
                    svc_reasons[svc].add("digest_pinned")
                elif named:
                    drift = True

        # What the operator's files render to (the update's source check).
        out = pcall(compose_base(unit, False) + ["config"], self.budget, "unsupported_files",
                    cap=MAX_COMPOSE_CONFIG_BYTES, cwd=unit.workdir)
        source_digest = hmac_hex(self.salt, b"nos-source-digest-v1", out)

        # The project as the update's phase 5 would apply it.
        with_override = entries is not None
        out = pcall(compose_base(unit, with_override) + ["config", "--format", "json"], self.budget, "unsupported_files",
                    cap=MAX_COMPOSE_CONFIG_BYTES, cwd=unit.workdir)
        try:
            project_doc = json.loads(text(out, "unsupported_files"))
        except ValueError:
            raise Stop("unsupported_files")
        services = project_doc.get("services") if isinstance(project_doc, dict) else None
        if not isinstance(services, dict) or not all(fullmatch(SERVICE, k) and isinstance(v, dict) for k, v in services.items()):
            raise Stop("unsupported_files")
        if not set(by_svc) <= set(services):
            raise Stop("project_mismatch")
        graph = {}
        for name in sorted(services):
            deps, restart, shares = depends(services[name])
            if not (deps | shares) <= set(services):
                raise Stop("dependency_unsupported")
            graph[name] = (deps, restart, shares)
        for svc, cs in by_svc.items():
            doc = services[svc]
            if "build" in doc:
                svc_reasons[svc].add("build_unsupported")
            if scale_of(doc) != len(cs):
                svc_reasons[svc].add("scale_mismatch")
            if ephemeral(doc):
                svc_reasons[svc].add("ephemeral_port")
            if any(c["State"].get("Status") != "running" for c in cs):
                svc_reasons[svc].add("target_not_running")
            if len({c.get("Image") for c in cs}) != 1:
                svc_reasons[svc].add("mixed_images")

        # Applied configuration (Q21), with the update's arguments; the
        # unkeyed hash stays on the host. override_drift takes precedence
        # (Q27): with drift the check is not made.
        if not drift:
            order = sorted(by_svc)
            rc, out, _, _ = call(compose_base(unit, with_override) + ["config", "--hash=" + ",".join(order)], self.budget,
                                 cwd=unit.workdir)
            if (rc != 0 or out is None) and self.budget.left() - KILL_GRACE < 1:
                raise Stop(self.budget.reason)
            hashes = {}
            if rc == 0 and out is not None:
                try:
                    lines = out.decode("utf-8").splitlines()
                except UnicodeDecodeError:
                    lines = []
                for line in lines:
                    f = line.split()
                    if len(f) == 2:
                        hashes[f[0]] = f[1]
            for svc, cs in by_svc.items():
                h = hashes.get(svc)
                if not h or any(labels(c).get(L_HASH) != h for c in cs):
                    svc_reasons[svc].add("config_not_applied")

        targets = sorted((self.target(c, svc) for svc, cs in by_svc.items() for c in cs),
                         key=lambda t: (t["service"], t["container_id"]))
        svc_out = []
        for name in sorted(services):
            deps, restart, shares = graph[name]
            svc_out.append({"service": name, "replicas": len(by_svc.get(name, [])), "scale": scale_of(services[name]),
                            "depends": [{"service": d, "restart": d in restart} for d in sorted(deps)],
                            "shares": sorted(shares), "reasons": sorted(svc_reasons.get(name, ()))})
        return {"form": "compose", "project": project, "container_id": "", "reason": "override_drift" if drift else "",
                "working_dir_hash": unit.working_dir_hash, "config_files_hash": unit.config_files_hash,
                "source_digest": source_digest, "services": svc_out, "targets": targets, "images": self.images(targets)}


def list_containers(budget):
    """[(id, project, oneoff)] of every container; host_unreadable when
    the list cannot be read."""
    fmt = "{{.ID}}\t{{.Label \"" + L_PROJECT + "\"}}\t{{.Label \"" + L_ONEOFF + "\"}}"
    out = pcall(["docker", "ps", "-a", "--no-trunc", "--format", fmt], budget, "host_unreadable", cap=MAX_LIST_BYTES)
    rows = []
    for line in text(out, "host_unreadable").splitlines():
        f = line.split("\t")
        if len(f) != 3 or not HEX64.fullmatch(f[0]):
            raise Stop("host_unreadable")
        rows.append((f[0], f[1], f[2]))
    return rows


def emit(doc, code):
    sys.stdout.write(json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    sys.exit(code)


def size(doc):
    return len(json.dumps(doc, sort_keys=True, separators=(",", ":"))) + 1


def main():
    result = {"format": FORMAT, "status": "ok", "units": []}
    try:
        tags = load_params()
    except Stop as e:
        result["status"] = e.reason
        emit(result, 1)
    budget = Budget(MAX_PREVIEW_WALL_CLOCK, "truncated")
    try:
        salt = read_salt()
    except Stop as e:
        # No salt, no digests: every unit is unavailable (prepare_required).
        result["status"] = e.reason
        emit(result, 0 if e.reason == "prepare_required" else 1)
    log("phase: list")
    try:
        rows = list_containers(budget)
    except Stop as e:
        result["status"] = "host_unreadable" if e.reason != "tooling_missing" else e.reason
        emit(result, 1)
    projects, standalone = {}, []
    for cid, project, oneoff in rows:
        if project == "":
            standalone.append(cid)
        elif fullmatch(PROJECT, project):
            if oneoff == "False":
                projects.setdefault(project, []).append(cid)
        # A container with another project label cannot be bound at all.
    plan = [("compose", p, sorted(set(projects[p]))) for p in sorted(projects)]
    plan += [("standalone", "", [cid]) for cid in sorted(set(standalone))]

    pv = Preview(salt, tags, budget)
    used = size(result)
    containers = 0
    cut = False
    log("phase: units")
    for i, (form, project, ids) in enumerate(plan):
        head = {"form": form, "project": project, "container_id": ids[0] if form == "standalone" else "", "reason": "truncated"}
        if not cut:
            containers += len(ids)
            if containers > MAX_PREVIEW_CONTAINERS or (form == "compose" and i >= MAX_PREVIEW_PROJECTS):
                cut = True
        if not cut:
            try:
                unit = pv.standalone(ids[0]) if form == "standalone" else pv.compose(project, ids)
            except Stop as e:
                if e.reason in ("truncated", "tooling_missing"):
                    cut = True
                    unit = head
                else:
                    unit = dict(head, reason=e.reason)
            n = size(unit) + 1
            # Room stays for the truncated head of every later unit.
            if used + n + HEAD_RESERVE * (len(plan) - i - 1) > MAX_PREVIEW_RESULT_BYTES:
                cut = True
                unit = head
        if cut:
            unit = head
        used += size(unit) + 1
        result["units"].append(unit)
        if used > MAX_PREVIEW_RESULT_BYTES:
            # Not even the truncated heads fit: the result says so.
            result["units"] = []
            result["status"] = "result_too_large"
            emit(result, 1)
    emit(result, 0)


try:
    main()
except SystemExit:
    raise
except Exception:
    # Never a traceback (it could carry host values).
    emit({"format": FORMAT, "status": "internal_error", "units": []}, 1)
PYTHON
