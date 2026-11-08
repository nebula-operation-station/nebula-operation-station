#!/bin/sh
# docker.update_prepare 1.0.0 (Nebula built-in, durable job, classic path,
# runs as root; ADR 0006 P2-03, container update plan cu02, Q5). MEDIUM:
# creates the per-host salt that keys the configuration and source digests
# of docker.update_preview and docker.compose_update, as a root-only file,
# if it is absent. It never replaces, rewrites or prints an existing salt,
# and it touches no container.
#
# Result format docker-update-prepare-v1, one JSON line on stdout:
#   {"format":"docker-update-prepare-v1","status":"created"|"present"}
# or a failure status (exit 1). The salt itself never leaves the host: not
# in the result, not in the log (fixed phase lines only), not on a command
# line (it is generated and written inside python3).
#
# Host state (root-only):
#   /var/lib/nebula/container-updates        directory, 0700, owned by root
#   /var/lib/nebula/container-updates/salt   32 random bytes, 0600
#
# The salt is written to a temporary file, synced, and then hard-linked to
# its name: the link fails if a salt exists, so an existing salt is never
# replaced, and a crash leaves no partial salt under the final name.
#
# Parameters: none ({}).
set -u
set -f
fail() { printf '{"format":"docker-update-prepare-v1","status":"%s"}\n' "$1"; exit 1; }
[ "$(id -u)" -eq 0 ] || fail not_root
command -v python3 >/dev/null 2>&1 || fail tooling_missing
exec python3 -I - <<'PYTHON'
import json
import os
import stat
import sys

FORMAT = "docker-update-prepare-v1"
STATE_DIR = "/var/lib/nebula/container-updates"
SALT_FILE = STATE_DIR + "/salt"
SALT_TMP = STATE_DIR + "/.salt.tmp"

MAX_PARAMS_BYTES = 4096
# The salt the preview and the update accept: at least 32 bytes, at most
# 4096 (their read_salt).
SALT_BYTES = 32
MAX_SALT_BYTES = 4096


class Stop(Exception):
    def __init__(self, reason):
        Exception.__init__(self, reason)
        self.reason = reason


def log(line):
    # Fixed phase lines only (R4).
    sys.stderr.write("nos: " + line + "\n")
    sys.stderr.flush()


def emit(status, code):
    sys.stdout.write(json.dumps({"format": FORMAT, "status": status}, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    sys.exit(code)


def load_params():
    path = os.environ.get("NEBULA_PARAMS", "")
    if not path.startswith("/"):
        raise Stop("params_invalid")
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_PARAMS_BYTES + 1)
    except OSError:
        raise Stop("params_invalid")
    if len(raw) > MAX_PARAMS_BYTES:
        raise Stop("params_invalid")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Stop("params_invalid")
    if doc is not None and doc != {}:
        raise Stop("params_invalid")


def owned_private(st, kind):
    return kind(st.st_mode) and st.st_uid == os.geteuid() and (st.st_mode & 0o077) == 0


def state_dir():
    """Creates the state directory if it is absent; an existing one must be
    a real directory owned by root and closed to group and others."""
    try:
        os.mkdir(STATE_DIR, 0o700)
    except FileExistsError:
        pass
    except OSError:
        raise Stop("state_unsafe")
    try:
        st = os.lstat(STATE_DIR)
    except OSError:
        raise Stop("state_unsafe")
    if not owned_private(st, stat.S_ISDIR):
        raise Stop("state_unsafe")


def salt_state():
    """Reports whether a usable salt exists, without reading it into the
    result. Absent is False; a usable salt is True; anything else (a
    symlink, another owner, open modes, a wrong size, not a regular file)
    is salt_unsafe, and the file is left as it is."""
    try:
        fd = os.open(SALT_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return False
    except OSError:
        raise Stop("salt_unsafe")
    try:
        st = os.fstat(fd)
    except OSError:
        raise Stop("salt_unsafe")
    finally:
        os.close(fd)
    if not owned_private(st, stat.S_ISREG) or st.st_size < SALT_BYTES or st.st_size > MAX_SALT_BYTES:
        raise Stop("salt_unsafe")
    return True


def sync_dir():
    dfd = os.open(STATE_DIR, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def create_salt():
    """Writes a new random salt under SALT_FILE unless one appears first.
    Returns True if this run created it."""
    try:
        try:
            os.unlink(SALT_TMP)
        except FileNotFoundError:
            pass
        fd = os.open(SALT_TMP, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            data = os.urandom(SALT_BYTES)
            n = 0
            while n < len(data):
                n += os.write(fd, data[n:])
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(SALT_TMP, SALT_FILE)
            created = True
        except FileExistsError:
            created = False
        os.unlink(SALT_TMP)
        sync_dir()
    except OSError:
        try:
            os.unlink(SALT_TMP)
        except OSError:
            pass
        raise Stop("write_failed")
    return created


def main():
    os.umask(0o077)
    try:
        load_params()
        log("phase: state")
        state_dir()
        if salt_state():
            log("phase: done")
            emit("present", 0)
        log("phase: create")
        created = create_salt()
        # Whoever wrote it, the salt now under the name must be usable.
        if not salt_state():
            raise Stop("write_failed")
    except Stop as e:
        emit(e.reason, 1)
    log("phase: done")
    emit("created" if created else "present", 0)


try:
    main()
except SystemExit:
    raise
except BaseException:
    emit("internal_error", 1)
PYTHON
