# SPDX-License-Identifier: AGPL-3.0-or-later
# Fake docker and curl for the docker.update and docker.rollback 1.0.0
# script tests. The state file (state.json, next to this file) describes
# containers, images and what the registry answers; every call is appended
# to calls.jsonl as one JSON line. Mutating calls (pull, tag, stop, rename,
# create, start, rm) update the state. A failing call prints the planted
# env value (state "planted") on stdout and stderr, which the script must
# keep on the host.
import json
import os
import stat
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(HERE, "state.json")
CALLS = os.path.join(HERE, "calls.jsonl")


def load():
    with open(STATE) as f:
        return json.load(f)


def save(st):
    with open(STATE, "w") as f:
        json.dump(st, f)


def record(tool, argv, extra=None):
    rec = {"tool": tool, "argv": argv}
    dc = os.environ.get("DOCKER_CONFIG")
    if dc is not None:
        rec["docker_config"] = dc
        rec["docker_config_empty"] = os.path.isdir(dc) and not os.listdir(dc)
    if extra:
        rec.update(extra)
    with open(CALLS, "a") as f:
        f.write(json.dumps(rec) + "\n")


def public(obj):
    return {k: v for k, v in obj.items() if not k.startswith("_")}


def find_image(st, ref):
    for im in st["images"]:
        if ref == im["Id"] or ref in im.get("RepoTags", []) or ref in im.get("_refs", []):
            return im
    return None


def find_container(st, ref):
    if ref in st["containers"]:
        return ref, st["containers"][ref]
    for cid, c in st["containers"].items():
        if c["Name"] == "/" + ref:
            return cid, c
    return None, None


def fail(st, verb):
    code = st.get("fail_" + verb)
    if not code:
        return
    v = st.get("planted", "")
    if v:
        sys.stdout.write(v + "\n")
        sys.stderr.write(v + "\n")
    sys.exit(code)


def create(st, argv):
    sep = argv.index("--")
    opts, image, cmd = argv[1:sep], argv[sep + 1], argv[sep + 2:]
    extra = {}
    name = ""
    for o in opts:
        if o.startswith("--name="):
            name = o[len("--name="):]
        if o.startswith("--env-file="):
            path = o[len("--env-file="):]
            st_ = os.lstat(path)
            with open(path) as f:
                lines = f.read().split("\n")
            extra["env_file_mode"] = oct(stat.S_IMODE(st_.st_mode))
            extra["env_file_lines"] = len([ln for ln in lines if ln])
            extra["env_file_names"] = [ln.split("=", 1)[0] for ln in lines if ln]
            # Whether the file holds exactly the planted env value for the
            # planted name (checked without recording the value).
            extra["env_file_has_planted"] = any(ln == st.get("planted_name", "") + "=" + st.get("planted", "") for ln in lines)
    record("docker", ["create"] + opts + ["--", image] + cmd, extra)
    fail(st, "create")
    if find_container(st, name)[1] is not None:
        sys.exit(125)  # name in use
    im = find_image(st, image)
    if im is None:
        sys.exit(125)
    new = st["create"]
    new["Name"] = "/" + name
    new["Image"] = im["Id"]
    new["Config"]["Image"] = image
    new["State"] = {"Status": "created", "StartedAt": ""}
    st["containers"][new["Id"]] = new
    save(st)
    out = st.get("create_output", new["Id"])
    print(out)


def docker(argv):
    st = load()
    if argv[:1] == ["create"]:
        create(st, argv)
        return
    record("docker", argv)
    if argv[:3] == ["inspect", "--type", "container"]:
        _, c = find_container(st, argv[-1])
        if c is None:
            sys.exit(1)
        if st.get("started_health") and c["State"].get("Status") == "running" and c["Id"] == st["create"]["Id"]:
            c["State"]["Health"] = {"Status": st["started_health"]}
        print(json.dumps([public(c)]))
        return
    if argv[:2] == ["image", "inspect"]:
        im = find_image(st, argv[-1])
        if im is None:
            sys.exit(1)
        print(json.dumps([public(im)]))
        return
    if argv[:1] == ["pull"]:
        fail(st, "pull")
        im = st.get("pullable", {}).get(argv[-1])
        if im is None:
            sys.exit(1)
        st["images"].append(im)
        save(st)
        return
    if argv[:1] == ["tag"]:
        fail(st, "tag")
        im = find_image(st, argv[1])
        if im is None:
            sys.exit(1)
        im.setdefault("RepoTags", []).append(argv[2])
        save(st)
        return
    if argv[:1] == ["stop"]:
        fail(st, "stop")
        _, c = find_container(st, argv[-1])
        if c is None:
            sys.exit(1)
        c["State"]["Status"] = "exited"
        save(st)
        return
    if argv[:1] == ["rename"]:
        fail(st, "rename")
        _, c = find_container(st, argv[1])
        if c is None or find_container(st, argv[2])[1] is not None:
            sys.exit(1)
        c["Name"] = "/" + argv[2]
        save(st)
        return
    if argv[:1] == ["start"]:
        _, c = find_container(st, argv[-1])
        if c is None:
            sys.exit(1)
        if c["Id"] == st["create"]["Id"]:
            fail(st, "start")
        c["State"]["Status"] = "running"
        c["State"]["StartedAt"] = "2026-11-08T00:00:00Z"
        save(st)
        return
    if argv[:1] == ["rm"]:
        cid, c = find_container(st, argv[-1])
        if c is None:
            sys.exit(1)
        if c["Id"] != st["create"]["Id"]:
            fail(st, "rm")
        if c["State"]["Status"] == "running" and "-f" not in argv:
            sys.exit(1)
        del st["containers"][cid]
        save(st)
        return
    sys.exit(2)


def curl(argv):
    st = load()
    url = argv[argv.index("--") + 1]
    record("curl", argv, {"url": url, "head": "-I" in argv})
    ans = st.get("registry", {}).get(url)
    if ans is None:
        sys.exit(7)
    sys.stdout.write("HTTP/1.1 %d X\r\n" % ans["status"])
    for k, v in ans.get("headers", {}).items():
        sys.stdout.write("%s: %s\r\n" % (k, v))
    sys.stdout.write("\r\n")
    if "-I" not in argv:
        sys.stdout.write(ans.get("body", ""))


if __name__ == "__main__":
    if sys.argv[1] == "docker":
        docker(sys.argv[2:])
    else:
        curl(sys.argv[2:])
