#!/bin/sh
# docker.rollback 1.0.0 (Nebula built-in, standalone container, durable
# job, batch members only, runs as root; ADR 0006 P2-04, container update
# plan cu05). It returns one standalone container to the image a recorded
# docker.update 1.0.0 run replaced, exactly as its parameters bind it: the
# rollback binding the executor rendered from the approved member
# ({"container_update": {...}}, kind rollback, form standalone) after
# checking it against its own recreation row (a recreated or partial
# update with a baseline, inside its rollback window, with the bound
# recovery plan and the same definition ID and version). The container is
# created from that bound definition version, which the executor adds as
# the run secret "definition" (tmpfs, $NEBULA_SECRETS_DIR/definition), and
# the retained image. Nothing is reconstructed from `docker inspect`, and no
# image is resolved, fetched, tagged or deleted.
#
# Phases (result format standalone-rollback-v1, one JSON line on stdout; the
# phase structure of standalone-update-v1 without resolve and fetch):
#   1 precheck   the recorded incarnation (ID, name, image ID, configuration
#                digest and running reference byte for byte, in whatever
#                state, not a Compose container) and the definition's shape;
#                then the baseline snapshot
#   4 retain     nos-retained:<rollback_of>-0 still resolves to the bound
#                prior image, which lists the bound retained digest
#                (retained_image_missing)
#   5 recreate   stop and rename the current container, `docker create`
#                with the definition's options, --env-file=<tmpfs file>,
#                --pull=never, the bound retained_reference and the
#                definition's command, start it and remove the replaced one;
#                a failed create or start puts the replaced one back
#   6 snapshot   bounded health wait, then the after-snapshot of the
#                container with the bound name (also after a failed step)
# Every docker call is silent (R4): stdout and stderr go to a bounded buffer
# or /dev/null and are never returned; stdout is parsed only where a value
# is needed (inspect documents, the new container ID). Only typed reasons
# and exit statuses leave the host. Env values travel in the env file on
# the run's tmpfs, never on a command line.
#
# Host state (root-only, created by docker.update_prepare):
#   /var/lib/nebula/container-updates/salt   the per-host key (Q5)
# Keyed digest as in docker.update 1.0.0 (Q5, Q18).
set -u
set -f
pre() { printf '{"format":"standalone-rollback-v1","phase":"precheck","reason":"%s"}\n' "$1"; exit 10; }
[ "$(id -u)" -eq 0 ] || pre not_root
for tool in python3 docker timeout; do
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

FORMAT = "standalone-rollback-v1"
STATE_DIR = "/var/lib/nebula/container-updates"
SALT_FILE = STATE_DIR + "/salt"
DEFINITION_FORMAT = "nebula-container-definition-v1"
RETAINED_REPOSITORY = "nos-retained"

# Limits (container update plan cu01/cu02/cu05; the definition limits
# repeat internal/executor/containerdef).
MAX_PARAMS_BYTES = 256 * 1024
MAX_OLD_DIGESTS = 8
MAX_INSPECT_BYTES = 1024 * 1024
MAX_SNAPSHOT_CONTAINER_BYTES = 8 * 1024
MAX_DEFINITION_BYTES = 64 * 1024
MAX_OPTIONS = 256
MAX_OPTION_BYTES = 4096
MAX_COMMAND_ARGS = 256
MAX_COMMAND_BYTES = 4096
MAX_ENV = 256
MAX_ENV_NAME_BYTES = 255
MAX_ENV_VALUE_BYTES = 32 * 1024
# What a docker call may print before it is cut; never returned.
MAX_CALL_OUTPUT = 64 * 1024

# Phase budgets in seconds (Q25) and per-call bounds.
CHECK_BUDGET = 3 * 60
RETAIN_BUDGET = 60
RECREATE_BUDGET = 8 * 60
SNAPSHOT_BUDGET = 5 * 60
HEALTH_WAIT = 3 * 60
HEALTH_POLL = 5
KILL_GRACE = 10
CALL_BOUND = 30
STEP_BOUND = 120

L_PROJECT = "com.docker.compose.project"

HEX64 = re.compile(r"[0-9a-f]{64}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
CNAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}")
PLATFORM = re.compile(r"[a-z0-9]{1,16}/[a-z0-9_]{1,16}(/[a-z0-9]{1,16})?")
POLICY = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
REGHOST = re.compile(r"(localhost|[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*)(:[0-9]{1,5})?")
PATHPART = re.compile(r"[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*")
OPTION = re.compile(r"--([a-z][a-z0-9-]{0,63})=")
ENVNAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
PORT = re.compile(r"([0-9]{1,5})(?:-([0-9]{1,5}))?")
IPV4 = re.compile(r"(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}")
IPV6 = re.compile(r"[0-9a-fA-F:.]{2,45}")
MAX_SAFE_INTEGER = 2 ** 53 - 1


class Stop(Exception):
    """A typed stop."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


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

def need(cond, reason="binding_invalid"):
    if not cond:
        raise Stop(reason)


def keys(obj, required, optional=(), reason="binding_invalid"):
    need(isinstance(obj, dict), reason)
    need(set(required) <= set(obj) <= set(required) | set(optional), reason)


def no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate key")
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
    keys(u, ["kind", "form", "images", "targets", "dependencies", "definition_id", "definition_version",
             "rollback_of", "recovery_plan_digest"])
    # Only a public standalone rollback: no registry or compose identity
    # (absent from the required set above, so refused).
    need(u["kind"] == "rollback" and u["form"] == "standalone")
    need(fullmatch(UUID, u["definition_id"]) and fullmatch(UUID, u["rollback_of"]))
    need(fullmatch(HEX64, u["recovery_plan_digest"]))
    v = u["definition_version"]
    need(isinstance(v, int) and not isinstance(v, bool) and 1 <= v <= MAX_SAFE_INTEGER)
    need(u["dependencies"] == [])
    images = u["images"]
    need(isinstance(images, list) and len(images) == 1)
    img = images[0]
    # No fetch digest and no old image: a rollback fetches nothing.
    keys(img, ["service", "repository", "platform", "old_tag", "new_tag", "old_digests", "rollback"],
         ["policy_version", "policy_digest", "major_change"])
    need(img["service"] == "")
    need(canonical_repo(img["repository"]) and fullmatch(PLATFORM, img["platform"]))
    need(fullmatch(TAG, img["old_tag"]) and fullmatch(TAG, img["new_tag"]))
    od = img["old_digests"]
    need(isinstance(od, list) and 1 <= len(od) <= MAX_OLD_DIGESTS)
    for i, d in enumerate(od):
        need(fullmatch(DIGEST, d) and (i == 0 or od[i - 1] < d))
    if img["old_tag"] == img["new_tag"]:
        need("policy_version" not in img and "policy_digest" not in img and "major_change" not in img)
    else:
        need(fullmatch(POLICY, img.get("policy_version")) and fullmatch(HEX64, img.get("policy_digest")))
        need("major_change" not in img or img["major_change"] is True)
    rb = img["rollback"]
    keys(rb, ["prior_image_id", "retained_tag", "retained_reference"])
    need(fullmatch(DIGEST, rb["prior_image_id"]))
    # The tag the recorded update's phase 4 gave the prior image.
    need(rb["retained_tag"] == "%s-0" % u["rollback_of"])
    # repository:prior_tag@digest in canonical form, byte for byte what
    # phase 5 creates the container from.
    r = parse_ref(rb["retained_reference"])
    need(r is not None and r[2] != "" and r[0] == img["repository"] and r[1] == img["new_tag"])
    need(rb["retained_reference"] == r[0] + ":" + r[1] + "@" + r[2])
    targets = u["targets"]
    need(isinstance(targets, list) and len(targets) == 1)
    t = targets[0]
    keys(t, ["service", "container_id", "container_name", "image_id", "running_reference", "configuration_digest"])
    need(t["service"] == "" and fullmatch(HEX64, t["container_id"]) and fullmatch(CNAME, t["container_name"]))
    need(fullmatch(DIGEST, t["image_id"]) and fullmatch(HEX64, t["configuration_digest"]))
    # The recorded running reference: the update's new one, or the old one
    # when the update never reached the container.
    r = parse_ref(t["running_reference"])
    need(r is not None and r[0] == img["repository"])
    return u


# --- the definition (run secret) -------------------------------------------------

def bad_definition(cond):
    need(cond, "definition_invalid")


def port_range(v):
    m = PORT.fullmatch(v)
    bad_definition(m is not None)
    lo = int(m.group(1))
    hi = int(m.group(2)) if m.group(2) else lo
    bad_definition(lo <= 65535 and hi <= 65535 and lo <= hi)
    return lo, hi


def check_publish(v):
    """Only a published port whose host port the definition fixes
    (containerdef.checkPublish): [ip:]host:container[/proto]."""
    bad_definition(v != "")
    if "/" in v:
        v, _, proto = v.rpartition("/")
        bad_definition(proto in ("tcp", "udp", "sctp"))
    if v.startswith("["):
        ip, sep, ports = v[1:].partition("]:")
        bad_definition(sep != "" and ":" in ip and IPV6.fullmatch(ip) is not None)
        parts = ports.split(":")
        bad_definition(len(parts) == 2)
    else:
        parts = v.split(":")
        if len(parts) == 3:
            bad_definition(IPV4.fullmatch(parts[0]) is not None)
            parts = parts[1:]
        bad_definition(len(parts) == 2)
    bad_definition(parts[0] != "")
    hlo, hhi = port_range(parts[0])
    clo, chi = port_range(parts[1])
    bad_definition(hlo != 0 and clo != 0 and hhi - hlo == chi - clo)


def no_control(v):
    return not any(ord(c) < 0x20 or ord(c) == 0x7f for c in v)


def load_definition(name):
    """The operator's definition of the bound container, from the run's
    secret directory (tmpfs). Its shape is checked again here, as the
    executor did before dispatch; a problem is definition_invalid, without
    any value."""
    d = os.environ.get("NEBULA_SECRETS_DIR", "")
    bad_definition(d.startswith("/"))
    try:
        fd = os.open(d + "/definition", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise Stop("definition_missing")
    try:
        st = os.fstat(fd)
        bad_definition(stat.S_ISREG(st.st_mode) and st.st_size <= MAX_DEFINITION_BYTES)
        raw = os.read(fd, MAX_DEFINITION_BYTES + 1)
    except OSError:
        raise Stop("definition_invalid")
    finally:
        os.close(fd)
    bad_definition(len(raw) <= MAX_DEFINITION_BYTES)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=no_dupes)
    except (UnicodeDecodeError, ValueError):
        raise Stop("definition_invalid")
    keys(doc, ["format", "container_name", "options", "command", "env"], reason="definition_invalid")
    bad_definition(doc["format"] == DEFINITION_FORMAT and doc["container_name"] == name)
    opts, cmd, env = doc["options"], doc["command"], doc["env"]
    bad_definition(isinstance(opts, list) and len(opts) <= MAX_OPTIONS)
    names = 0
    for o in opts:
        bad_definition(isinstance(o, str) and len(o.encode("utf-8")) <= MAX_OPTION_BYTES and no_control(o))
        m = OPTION.match(o)
        bad_definition(m is not None)
        flag, value = m.group(1), o[m.end():]
        bad_definition(flag not in ("env", "env-file", "publish-all", "pull", "platform", "disable-content-trust"))
        if flag == "name":
            bad_definition(value == name)
            names += 1
        elif flag == "publish":
            check_publish(value)
    bad_definition(names == 1)
    bad_definition(isinstance(cmd, list) and len(cmd) <= MAX_COMMAND_ARGS)
    for a in cmd:
        bad_definition(isinstance(a, str) and len(a.encode("utf-8")) <= MAX_COMMAND_BYTES and "\x00" not in a)
    bad_definition(isinstance(env, list) and len(env) <= MAX_ENV)
    seen = set()
    for e in env:
        keys(e, ["name", "value"], reason="definition_invalid")
        n, v = e["name"], e["value"]
        bad_definition(fullmatch(ENVNAME, n) and len(n) <= MAX_ENV_NAME_BYTES and n not in seen)
        seen.add(n)
        # The env file is line based: no newline, carriage return or NUL.
        bad_definition(isinstance(v, str) and len(v.encode("utf-8")) <= MAX_ENV_VALUE_BYTES)
        bad_definition("\n" not in v and "\r" not in v and "\x00" not in v)
    return doc


def write_env_file(defn):
    """Writes the env list to a new root-only file in the run's secret
    directory (tmpfs) and returns its path. Only the path reaches a
    command line."""
    path = os.environ.get("NEBULA_SECRETS_DIR", "") + "/env"
    body = "".join(e["name"] + "=" + e["value"] + "\n" for e in defn["env"]).encode("utf-8")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, body)
        finally:
            os.close(fd)
    except OSError:
        raise Stop("create_failed")
    return path


def remove_env_file(path):
    try:
        os.unlink(path)
    except OSError:
        pass


# --- bounded, silent calls -----------------------------------------------------

class Budget:
    def __init__(self, seconds, reason):
        self.deadline = time.monotonic() + seconds
        self.reason = reason

    def left(self):
        return self.deadline - time.monotonic()


BASE_ENV = {
    "PATH": os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
    "LC_ALL": "C",
}
if os.environ.get("HOME", "").startswith("/"):
    BASE_ENV["HOME"] = os.environ["HOME"]


def call(args, budget, bound=CALL_BOUND, cap=MAX_INSPECT_BYTES, env=None):
    """Runs args under `timeout -k KILL_GRACE`, silently: stderr goes to
    /dev/null, stdout to a buffer that is only parsed by the caller and
    never returned. The call's bound plus its kill grace must fit the
    budget, or it does not start. Returns (exit, stdout, elapsed, limit);
    stdout is None when it exceeded cap."""
    limit = int(min(bound, budget.left() - KILL_GRACE))
    if limit < 1:
        raise Stop(budget.reason)
    cmd = ["timeout", "-k", str(KILL_GRACE), str(limit)] + args
    start = time.monotonic()
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             env=env or BASE_ENV, close_fds=True)
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


def inspect_container(ref, budget, reason):
    rc, out, _, _ = call(["docker", "inspect", "--type", "container", "--", ref], budget)
    if rc != 0:
        raise Stop(reason)
    try:
        doc = json.loads(text(out, reason))
    except ValueError:
        raise Stop(reason)
    if not isinstance(doc, list) or len(doc) != 1 or not isinstance(doc[0], dict):
        raise Stop(reason)
    c = doc[0]
    for k in ("Config", "HostConfig", "State"):
        if not isinstance(c.get(k), dict):
            raise Stop(reason)
    if not isinstance(c["Config"].get("Labels") or {}, dict):
        raise Stop(reason)
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


def config_digest(c, salt):
    return hmac_hex(salt, b"nos-configuration-digest-v1", canon({"Config": c["Config"], "HostConfig": c["HostConfig"]}))


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
    """One container in the compose-update-v2 entry shape, with service ""
    and replica "1": a standalone unit is one container, matched by name.
    No env value, label or command line is in it."""
    st = c["State"]
    health = st.get("Health") if isinstance(st.get("Health"), dict) else {}
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
        "service": "",
        "replica": "1",
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

def read_salt():
    try:
        fd = os.open(SALT_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        raise Stop("prepare_required")
    except OSError:
        raise Stop("salt_unsafe")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or (st.st_mode & 0o077) != 0 or st.st_size > 4096:
            raise Stop("salt_unsafe")
        salt = os.read(fd, 4097)
    except OSError:
        raise Stop("salt_unsafe")
    finally:
        os.close(fd)
    if len(salt) < 32 or len(salt) > 4096:
        raise Stop("salt_unsafe")
    return salt




# --- phase 1: precheck -------------------------------------------------------------

def phase1(u, salt, budget):
    log("phase 1: precheck")
    t = u["targets"][0]
    c = inspect_container(t["container_id"], budget, "target_changed")
    if c.get("Id") != t["container_id"] or c.get("Name") != "/" + t["container_name"] or c.get("Image") != t["image_id"]:
        raise Stop("target_changed")
    if L_PROJECT in (c["Config"].get("Labels") or {}):
        raise Stop("compose_managed")
    if not hmac.compare_digest(config_digest(c, salt), t["configuration_digest"]):
        raise Stop("configuration_changed")
    if c["Config"].get("Image") != t["running_reference"]:
        raise Stop("reference_mismatch")
    defn = load_definition(t["container_name"])
    e = bounded_entry(c, salt)
    if e is None:
        raise Stop("snapshot_too_large")
    return defn, [e]


# --- phase 4: retain -----------------------------------------------------------------------

def phase4(u, budget):
    log("phase 4: retain")
    img = u["images"][0]
    rb = img["rollback"]
    im = inspect_image(RETAINED_REPOSITORY + ":" + rb["retained_tag"], budget, "retained_image_missing")
    if im.get("Id") != rb["prior_image_id"]:
        raise Stop("retained_image_missing")
    digest = rb["retained_reference"].rpartition("@")[2]
    if (img["repository"], digest) not in repo_digests(im):
        raise Stop("retained_image_missing")


# --- phase 5: recreate, phase 6: after-snapshot ------------------------------------------

def step(args, budget, bound=STEP_BOUND):
    """One silent recreate step: (exit, stdout or None, timed out)."""
    try:
        rc, out, elapsed, limit = call(args, budget, bound=bound, cap=MAX_CALL_OUTPUT)
    except Stop:
        return -1, None, False
    return rc, out, rc in (124, 137) and elapsed >= limit


def restore(old, name, budget):
    """Best effort: the old container back under its name, started."""
    step(["docker", "rename", old, name], budget, CALL_BOUND)
    step(["docker", "start", old], budget, CALL_BOUND)


def recreate(defn, name, old, image_ref, execution, budget):
    """Replaces container old (named name) with a new one created from the
    definition and image_ref. Returns (exit, reason); exit 0 and reason ""
    only when the new container runs and the old one is removed."""
    log("phase 5: recreate")
    aside = "nos-replaced-" + execution
    rc, _, timed = step(["docker", "stop", "--", old], budget)
    if rc != 0:
        step(["docker", "start", old], budget, CALL_BOUND)
        return rc, "recreate_timeout" if timed else "stop_failed"
    rc, _, timed = step(["docker", "rename", old, aside], budget, CALL_BOUND)
    if rc != 0:
        step(["docker", "start", old], budget, CALL_BOUND)
        return rc, "recreate_timeout" if timed else "rename_failed"
    try:
        env_file = write_env_file(defn)
    except Stop:
        restore(old, name, budget)
        return -1, "create_failed"
    # Exactly the definition and the bound image: no inspect field.
    args = ["docker", "create"] + list(defn["options"]) + ["--env-file=" + env_file, "--pull=never", "--", image_ref] + list(defn["command"])
    rc, out, timed = step(args, budget)
    remove_env_file(env_file)
    new = ""
    if rc == 0 and out is not None:
        try:
            new = out.decode("ascii").strip()
        except UnicodeDecodeError:
            new = ""
    if rc != 0 or not HEX64.fullmatch(new):
        if HEX64.fullmatch(new):
            step(["docker", "rm", "-f", new], budget, CALL_BOUND)
        restore(old, name, budget)
        return (rc if rc != 0 else -1), "recreate_timeout" if timed else "create_failed"
    rc, _, timed = step(["docker", "start", new], budget)
    if rc != 0:
        step(["docker", "rm", "-f", new], budget, CALL_BOUND)
        restore(old, name, budget)
        return rc, "recreate_timeout" if timed else "start_failed"
    rc, _, timed = step(["docker", "rm", old], budget, CALL_BOUND)
    if rc != 0:
        # The new container runs; the stopped old one stays under the
        # aside name for the operator.
        return rc, "recreate_timeout" if timed else "remove_failed"
    return 0, ""


def phase6(name, salt, budget):
    log("phase 6: after-snapshot")
    wait_until = time.monotonic() + min(HEALTH_WAIT, max(0, budget.left() - 60))
    while True:
        try:
            c = inspect_container(name, budget, "snapshot_failed")
        except Stop:
            # No container under the bound name (or none readable).
            return []
        if c.get("Name") != "/" + name:
            return []
        h = c["State"].get("Health")
        starting = isinstance(h, dict) and h.get("Status") == "starting"
        if not starting or time.monotonic() + HEALTH_POLL > wait_until:
            break
        time.sleep(HEALTH_POLL)
    e = bounded_entry(c, salt)
    return [e if e is not None else {"id": s(c.get("Id"), 64), "oversize": True}]


# --- main ------------------------------------------------------------------------------------

def emit(doc, code):
    sys.stdout.write(json.dumps(doc, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    sys.exit(code)


RESULT = {"format": FORMAT, "phase": "precheck", "reason": ""}
STOPPING_PHASES = ("precheck", "retain")


def main():
    result = RESULT
    try:
        u = load_binding()
    except Stop as e:
        result["reason"] = e.reason
        emit(result, 10)
    execution = os.environ.get("NEBULA_EXECUTION_ID", "")
    run_dir = os.environ.get("NEBULA_RUN_DIR", "")
    if not UUID.fullmatch(execution) or not run_dir.startswith("/") or not os.path.isdir(run_dir):
        result["reason"] = "environment_invalid"
        emit(result, 10)
    t, img = u["targets"][0], u["images"][0]
    try:
        salt = read_salt()
        defn, baseline = phase1(u, salt, Budget(CHECK_BUDGET, "budget_exceeded"))
        result["baseline"] = baseline
        result["phase"] = "retain"
        phase4(u, Budget(RETAIN_BUDGET, "retained_image_missing"))
    except Stop as e:
        result["reason"] = e.reason
        emit(result, 10)
    result["phase"] = "recreate"
    result["recreate_exit"] = -1
    image_ref = img["rollback"]["retained_reference"]
    rc, reason = recreate(defn, t["container_name"], t["container_id"], image_ref, execution,
                          Budget(RECREATE_BUDGET, "recreate_timeout"))
    result["recreate_exit"] = rc
    result["reason"] = reason
    result["phase"] = "after_snapshot"
    try:
        result["after"] = phase6(t["container_name"], salt, Budget(SNAPSHOT_BUDGET, "snapshot_failed"))
    except Stop:
        if not reason:
            result["reason"] = "snapshot_failed"
    emit(result, 0 if rc == 0 else 1)


try:
    main()
except SystemExit:
    raise
except Exception:
    # Never a traceback (it could carry host or definition values). The
    # result keeps the phase reached and the baseline; exit 10 only while
    # nothing changed.
    RESULT["reason"] = "internal_error"
    emit(RESULT, 10 if RESULT["phase"] in STOPPING_PHASES else 1)
PYTHON
