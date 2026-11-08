# SPDX-License-Identifier: AGPL-3.0-or-later
# Fake docker and curl for the docker.compose_update 2.0.0 script tests. The
# state file (FAKE_STATE, next to this file) describes containers, images,
# what `docker compose` renders and what the registry answers; every call is
# appended to the calls file as one JSON line. Mutating calls (pull, tag,
# up) update the state.
import json
import os
import sys
import time

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
    rec["env_keys"] = sorted(os.environ)
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


def noisy(st):
    # A failing Compose or Docker call prints a planted env value on both
    # streams; the script must keep it on the host.
    v = st.get("planted", "")
    if v:
        sys.stdout.write(v + "\n")
        sys.stderr.write(v + "\n")


def docker(argv):
    st = load()
    record("docker", argv)
    if argv[:3] == ["inspect", "--type", "container"]:
        c = st["containers"].get(argv[-1])
        if c is None:
            sys.exit(1)
        print(json.dumps([public(c)]))
        return
    if argv[:1] == ["ps"] and "--format" in argv:
        # docker.update_preview's listing: ID, project and oneoff labels.
        for cid, c in sorted(st["containers"].items()):
            lb = c["Config"].get("Labels") or {}
            print("%s\t%s\t%s" % (cid, lb.get("com.docker.compose.project", ""), lb.get("com.docker.compose.oneoff", "")))
        for cid, project in sorted(st.get("listed_only", {}).items()):
            print("%s\t%s\tFalse" % (cid, project))
        return
    if argv[:1] == ["ps"]:
        filters = [argv[i + 1][len("label="):] for i, a in enumerate(argv) if a == "--filter"]
        for cid, c in sorted(st["containers"].items()):
            lb = c["Config"].get("Labels") or {}
            if all(lb.get(f.split("=", 1)[0]) == f.split("=", 1)[1] for f in filters):
                print(cid)
        return
    if argv[:2] == ["image", "inspect"]:
        im = find_image(st, argv[-1])
        if im is None:
            sys.exit(1)
        print(json.dumps([public(im)]))
        return
    if argv[:1] == ["pull"]:
        if st.get("fail_pull"):
            noisy(st)
            sys.exit(st["fail_pull"])
        ref = argv[-1]
        im = st.get("pullable", {}).get(ref)
        if im is None:
            sys.exit(1)
        st["images"].append(im)
        save(st)
        return
    if argv[:1] == ["tag"]:
        if st.get("fail_tag"):
            sys.exit(1)
        im = find_image(st, argv[1])
        if im is None:
            sys.exit(1)
        im.setdefault("RepoTags", []).append(argv[2])
        save(st)
        return
    if argv[:1] == ["compose"]:
        files, i = [], 1
        while i < len(argv) and argv[i].startswith("-"):
            if argv[i] == "-f":
                files.append(argv[i + 1])
            i += 2
        sub = argv[i:]
        override = st["override"]
        if sub[:1] == ["config"] and st.get("hang_config"):
            time.sleep(st["hang_config"])
        if sub[:1] == ["config"] and st.get("fail_config"):
            noisy(st)
            sys.exit(st["fail_config"])
        if sub == ["config"]:
            if override in files:
                print("rendered-with-override")
            else:
                sys.stdout.write(st["source_config"])
            return
        if sub == ["config", "--format", "json"]:
            print(json.dumps(st["project"]))
            return
        if len(sub) == 2 and sub[0] == "config" and sub[1].startswith("--hash="):
            for svc in sub[1][len("--hash="):].split(","):
                if svc in st["hashes"]:
                    print(svc, st["hashes"][svc])
            return
        if sub[:1] == ["up"]:
            if st.get("fail_up"):
                noisy(st)
                sys.exit(st["fail_up"])
            with open(override) as f:
                entries = json.load(f)["services"]
            for svc in [a for a in sub[1:] if not a.startswith("-") and a != "never"]:
                for cid in [k for k, c in st["containers"].items() if c["Config"]["Labels"].get("com.docker.compose.service") == svc]:
                    del st["containers"][cid]
                new = st["recreate"][svc]
                new["Config"]["Image"] = entries[svc]
                new["Config"]["Labels"]["com.docker.compose.project.config_files"] = ",".join(files)
                st["containers"][new["Id"]] = new
            # Containers that appear with the up (for after-snapshot bounds).
            for cid, c in st.get("up_adds", {}).items():
                st["containers"][cid] = c
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
    tool = sys.argv[1]
    if tool == "docker":
        docker(sys.argv[2:])
    else:
        curl(sys.argv[2:])
