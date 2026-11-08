// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// The tests of docker.compose_update 2.0.0 run the shipped script against a
// fake host: docker and curl are testdata/compose_v2_fake.py, driven by a
// state file, so every call is recorded and the call order can be pinned.
// The script's host state directory is the only byte rewritten in the copy
// that runs; nothing else of the shipped artifact changes.

const (
	cuStateDirLine = `STATE_DIR = "/var/lib/nebula/container-updates"`
	cuExecution    = "00000000-0000-4000-8000-000000000001"
	cuPlanted      = "planted-env-value-7d1c"
)

func cuHex(c string) string    { return strings.Repeat(c, 64) }
func cuDigest(c string) string { return "sha256:" + cuHex(c) }

type composeV2 struct {
	f                    *fakeHost
	dir, state, run      string
	salt                 []byte
	st                   map[string]any
	u                    canonical.BatchContainerUpdate
	noSalt, rawParams    bool
	beforeRun            func(t *testing.T) // after the salt is written
	params               []byte
	indexBody, idxDigest string
	// previewWallClock, when set, replaces the preview script's wall
	// clock (seconds) in the copy that runs.
	previewWallClock string
}

// cuContainer is one container as `docker inspect` shows it.
func cuContainer(id, name, service, image, ref, hash, dir string) map[string]any {
	return map[string]any{
		"Id": id, "Name": "/" + name, "Image": image,
		"Config": map[string]any{"Image": ref, "Env": []any{"SECRET=" + cuPlanted}, "Labels": map[string]any{
			"com.docker.compose.project": "site", "com.docker.compose.service": service,
			"com.docker.compose.project.working_dir":  dir,
			"com.docker.compose.project.config_files": dir + "/compose.yaml",
			"com.docker.compose.config-hash":          hash, "com.docker.compose.container-number": "1",
			"com.docker.compose.oneoff": "False",
		}},
		"HostConfig": map[string]any{"RestartPolicy": map[string]any{"Name": "always"}},
		"State":      map[string]any{"Status": "running", "StartedAt": "2026-11-01T00:00:00Z"},
		"NetworkSettings": map[string]any{
			"Ports":    map[string]any{"80/tcp": []any{map[string]any{"HostIp": "0.0.0.0", "HostPort": "8080"}}},
			"Networks": map[string]any{"site_default": map[string]any{}},
		},
		"Mounts": []any{},
	}
}

// newComposeV2 is a project "site" with service web (one replica, the
// update target, nginx:1.27) that depends on db (one replica), a salt, and a
// registry whose 1.27 index lists the bound linux/amd64 digest. Its binding
// is consistent with the host, so the update runs through.
func newComposeV2(t *testing.T) *composeV2 {
	t.Helper()
	f := newFakeHost(t, "1")
	c := &composeV2{f: f, dir: filepath.Join(f.dir, "site"), state: filepath.Join(f.dir, "state"), run: filepath.Join(f.dir, "run"),
		salt: []byte("0123456789abcdef0123456789abcdef")}
	for _, d := range []string{c.dir, c.run} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(c.dir, "compose.yaml"), []byte("services: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake, err := os.ReadFile(filepath.Join("testdata", "compose_v2_fake.py"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "fake.py"), fake, 0o600); err != nil {
		t.Fatal(err)
	}
	f.write(t, "docker", `exec python3 -I "`+f.dir+`/fake.py" docker "$@"`)
	f.write(t, "curl", `exec python3 -I "`+f.dir+`/fake.py" curl "$@"`)

	web := cuContainer(cuHex("1"), "site-web-1", "web", cuDigest("d"), "nginx:1.27", "hweb", c.dir)
	db := cuContainer(cuHex("3"), "site-db-1", "db", cuDigest("e"), "postgres:16", "hdb", c.dir)
	newWeb := cuContainer(cuHex("9"), "site-web-1", "web", cuDigest("f"), "", "hweb2", c.dir)
	newWeb["State"] = map[string]any{"Status": "running", "StartedAt": "2026-11-08T00:00:00Z", "Health": map[string]any{"Status": "healthy"}}
	c.indexBody = `{"manifests":[{"digest":"` + cuDigest("7") + `","platform":{"os":"linux","architecture":"arm64"}},` +
		`{"digest":"` + cuDigest("c") + `","platform":{"os":"linux","architecture":"amd64"}}]}`
	sum := sha256.Sum256([]byte(c.indexBody))
	c.idxDigest = "sha256:" + hex.EncodeToString(sum[:])
	reg := "https://registry-1.docker.io/v2/library/nginx/manifests/"
	newRef := "docker.io/library/nginx@" + cuDigest("c")
	c.st = map[string]any{
		"override":      filepath.Join(c.state, "overrides", "site.yaml"),
		"planted":       cuPlanted,
		"source_config": "services:\n  web:\n    image: nginx:1.27\n",
		"containers":    map[string]any{cuHex("1"): web, cuHex("3"): db},
		"images": []any{map[string]any{"Id": cuDigest("d"), "RepoTags": []any{"nginx:1.27"}, "RepoDigests": []any{"nginx@" + cuDigest("a")},
			"Os": "linux", "Architecture": "amd64"}},
		"pullable": map[string]any{newRef: map[string]any{"Id": cuDigest("f"), "RepoDigests": []any{"nginx@" + cuDigest("c")},
			"Os": "linux", "Architecture": "amd64", "_refs": []any{newRef}}},
		"recreate": map[string]any{"web": newWeb},
		"project": map[string]any{"services": map[string]any{
			"web": map[string]any{"image": "nginx:1.27", "ports": []any{map[string]any{"target": 80, "published": "8080", "protocol": "tcp"}},
				"depends_on": map[string]any{"db": map[string]any{"condition": "service_started", "required": true}}},
			"db": map[string]any{"image": "postgres:16"},
		}},
		"hashes": map[string]any{"web": "hweb", "db": "hdb"},
		"registry": map[string]any{
			reg + "1.27": map[string]any{"status": 200, "headers": map[string]any{
				"Docker-Content-Digest": c.idxDigest, "Content-Type": "application/vnd.oci.image.index.v1+json"}},
			reg + c.idxDigest: map[string]any{"status": 200, "headers": map[string]any{
				"Docker-Content-Digest": c.idxDigest, "Content-Type": "application/vnd.oci.image.index.v1+json"}, "body": c.indexBody},
		},
	}
	c.u = canonical.BatchContainerUpdate{
		Kind: canonical.ContainerUpdateKindUpdate, Form: canonical.ContainerUpdateFormCompose,
		Images: []canonical.ContainerUpdateImage{{Service: "web", Repository: "docker.io/library/nginx", Platform: "linux/amd64",
			OldTag: "1.27", NewTag: "1.27", OldDigests: []string{cuDigest("a")}, NewIndexDigest: c.idxDigest,
			NewPlatformDigest: cuDigest("c"), OldImageID: cuDigest("d")}},
		Targets: []canonical.ContainerUpdateTarget{{Service: "web", ContainerID: cuHex("1"), ContainerName: "site-web-1",
			ImageID: cuDigest("d"), RunningReference: "nginx:1.27", ConfigurationDigest: c.configDigest(t, web)}},
		Dependencies: []canonical.ContainerUpdateDependency{{Service: "db", Relation: canonical.ContainerDependencyRequires,
			Containers: []canonical.ContainerDependencyMember{{ContainerID: cuHex("3"), ContainerName: "site-db-1",
				ConfigurationDigest: c.configDigest(t, db)}}}},
		SourceDigest: c.keyed("nos-source-digest-v1", []byte("services:\n  web:\n    image: nginx:1.27\n")),
		Project:      "site", WorkingDirHash: cuSHA(c.dir), ConfigFilesHash: cuSHA(c.dir + "/compose.yaml"),
	}
	return c
}

func cuSHA(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// keyed is the script's HMAC-SHA-256 with a domain prefix (Q5, Q18).
func (c *composeV2) keyed(domain string, data []byte) string {
	m := hmac.New(sha256.New, c.salt)
	m.Write([]byte(domain + "\x00"))
	m.Write(data)
	return hex.EncodeToString(m.Sum(nil))
}

// configDigest is the expected configuration_digest of a container:
// its Config and HostConfig, keys sorted, compact, no HTML escaping.
func (c *composeV2) configDigest(t *testing.T, ctr map[string]any) string {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(map[string]any{"Config": ctr["Config"], "HostConfig": ctr["HostConfig"]}); err != nil {
		t.Fatal(err)
	}
	return c.keyed("nos-configuration-digest-v1", bytes.TrimSuffix(b.Bytes(), []byte("\n")))
}

func (c *composeV2) containers() map[string]any { return c.st["containers"].(map[string]any) }
func (c *composeV2) container(id string) map[string]any {
	return c.containers()[id].(map[string]any)
}
func (c *composeV2) project() map[string]any {
	return c.st["project"].(map[string]any)["services"].(map[string]any)
}

type cuCall struct {
	Tool              string   `json:"tool"`
	Argv              []string `json:"argv"`
	URL               string   `json:"url"`
	Head              bool     `json:"head"`
	DockerConfig      *string  `json:"docker_config"`
	DockerConfigEmpty bool     `json:"docker_config_empty"`
	EnvKeys           []string `json:"env_keys"`
}

func (k cuCall) line() string { return k.Tool + " " + strings.Join(k.Argv, " ") }

type cuRun struct {
	code   int
	out    []byte
	stderr string
	doc    map[string]any
	calls  []cuCall
}

func (r cuRun) has(prefix string) bool {
	return slices.ContainsFunc(r.calls, func(k cuCall) bool { return strings.HasPrefix(k.line(), prefix) })
}

// mutated reports whether any call could have changed the host.
func (r cuRun) mutated() bool {
	return r.has("docker pull") || r.has("docker tag") || slices.ContainsFunc(r.calls, func(k cuCall) bool {
		return k.Tool == "docker" && slices.Contains(k.Argv, "up")
	})
}

// script is the shipped 2.0.0 artifact with its state directory moved into
// the test's directory.
func (c *composeV2) script(t *testing.T) string {
	t.Helper()
	a, ok := Lookup("docker.compose_update")
	if !ok {
		t.Fatal("docker.compose_update missing")
	}
	s := string(a.Script)
	if strings.Count(s, cuStateDirLine) != 1 {
		t.Fatal("the state directory line is not unique in the script")
	}
	return strings.Replace(s, cuStateDirLine, `STATE_DIR = "`+c.state+`"`, 1)
}

func (c *composeV2) exec(t *testing.T) cuRun {
	t.Helper()
	if !c.noSalt {
		if err := os.MkdirAll(c.state, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(c.state, "salt"), c.salt, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if c.beforeRun != nil {
		c.beforeRun(t)
	}
	st, err := json.Marshal(c.st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.f.dir, "state.json"), st, 0o600); err != nil {
		t.Fatal(err)
	}
	params := c.params
	if !c.rawParams {
		if params, _, err = canonical.ContainerUpdateParameters(c.u); err != nil {
			t.Fatal(err)
		}
	}
	pp := filepath.Join(c.f.dir, "params.json")
	if err := os.WriteFile(pp, params, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", c.script(t))
	cmd.Dir = c.f.dir
	cmd.Env = []string{"PATH=" + c.f.bin + ":/usr/bin:/bin", "NEBULA_PARAMS=" + pp, "NEBULA_RUN_DIR=" + c.run,
		"NEBULA_EXECUTION_ID=" + cuExecution, "SHELL_ONLY_VARIABLE=from-the-job-env"}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	r := cuRun{out: out, stderr: stderr.String()}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		r.code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out, &r.doc); err != nil {
		t.Fatalf("result %q (stderr %q): %v", out, r.stderr, err)
	}
	b, err := os.ReadFile(filepath.Join(c.f.dir, "calls.jsonl"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, ln := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if ln == "" {
			continue
		}
		var k cuCall
		if err := json.Unmarshal([]byte(ln), &k); err != nil {
			t.Fatal(err)
		}
		r.calls = append(r.calls, k)
	}
	// R4: whatever happened, no env value reaches result or log, and the
	// log holds fixed phase lines only.
	if strings.Contains(string(out), cuPlanted) || strings.Contains(r.stderr, cuPlanted) {
		t.Fatalf("a planted env value left the host: %q %q", out, r.stderr)
	}
	for _, ln := range strings.Split(strings.TrimSpace(r.stderr), "\n") {
		if ln != "" && !strings.HasPrefix(ln, "nos: phase ") {
			t.Fatalf("log line %q", ln)
		}
	}
	return r
}

func (c *composeV2) override(t *testing.T) (map[string]any, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(c.state, "overrides", "site.yaml"))
	if os.IsNotExist(err) {
		return nil, false
	}
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc, true
}

// The catalog's docker.compose_update is the binding-consuming 2.0.0: a
// durable, reconcile-first, MEDIUM job with the fixed 30-minute timeout and
// no string parameters (its only input is the rendered binding). The
// inspect-based 1.0.0 is gone (Q3).
func TestComposeUpdateCatalogIsVersion2(t *testing.T) {
	a, ok := Lookup("docker.compose_update")
	if !ok || a.Version != "2.0.0" || !a.Durable || a.ReadOnly || a.Retry != RetryReconcileFirst ||
		a.Risk != pb.RiskClass_RISK_CLASS_MEDIUM || a.Timeout.Minutes() != 30 || len(a.Params) != 0 {
		t.Fatalf("%+v", a)
	}
	s := string(a.Script)
	for _, want := range []string{"docker.compose_update 2.0.0", `FORMAT = "compose-update-v2"`, "python3 -I"} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	if strings.Contains(s, "compose-update-v1") || strings.Contains(s, "docker compose pull") {
		t.Error("script still carries the 1.0.0 path")
	}
	n := 0
	for _, b := range Builtin {
		if b.ID == "docker.compose_update" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d docker.compose_update entries", n)
	}
}

// The bound update runs every phase in order and recreates exactly the
// frozen definition: the pull is by the bound platform digest with an empty
// DOCKER_CONFIG, the old image is retained under nos-retained, the override
// names repository:new_tag@digest for the frozen service only, and up
// recreates only that service from the operator files plus the override.
func TestComposeUpdateRecreatesFrozenDefinition(t *testing.T) {
	c := newComposeV2(t)
	r := c.exec(t)
	if r.code != 0 || r.doc["phase"] != "after_snapshot" || r.doc["reason"] != "" || r.doc["up_exit"] != float64(0) ||
		r.doc["format"] != "compose-update-v2" || r.doc["project"] != "site" {
		t.Fatalf("%d %s", r.code, r.out)
	}
	base := r.doc["baseline"].([]any)
	after := r.doc["after"].([]any)
	if len(base) != 2 || base[0].(map[string]any)["id"] != cuHex("1") || base[1].(map[string]any)["id"] != cuHex("3") {
		t.Fatalf("baseline %v", base)
	}
	ids := []string{}
	for _, e := range after {
		ids = append(ids, e.(map[string]any)["id"].(string))
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{cuHex("3"), cuHex("9")}) {
		t.Fatalf("after %v", ids)
	}
	// Baseline and after-snapshot share one format.
	bk, ak := slices.Sorted(maps.Keys(base[0].(map[string]any))), slices.Sorted(maps.Keys(after[0].(map[string]any)))
	if !slices.Equal(bk, ak) {
		t.Fatalf("baseline keys %v, after keys %v", bk, ak)
	}
	if got := base[0].(map[string]any)["configuration_digest"]; got != c.u.Targets[0].ConfigurationDigest {
		t.Fatalf("baseline digest %v", got)
	}
	ov, ok := c.override(t)
	want := map[string]any{"services": map[string]any{"web": map[string]any{"image": "docker.io/library/nginx:1.27@" + cuDigest("c")}}}
	if !ok || !jsonEqual(ov, want) {
		t.Fatalf("override %v", ov)
	}
	fi, err := os.Stat(filepath.Join(c.state, "overrides", "site.yaml"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("override mode %v %v", fi, err)
	}

	// Call order: phases 1..6, nothing mutating before the resolve.
	var order []string
	for _, k := range r.calls {
		switch {
		case k.Tool == "curl":
			order = appendOnce(order, "resolve")
		case k.Argv[0] == "pull":
			order = appendOnce(order, "pull")
		case k.Argv[0] == "tag":
			order = appendOnce(order, "tag")
		case slices.Contains(k.Argv, "up"):
			order = appendOnce(order, "up")
		}
	}
	if !slices.Equal(order, []string{"resolve", "pull", "tag", "up"}) {
		t.Fatalf("order %v", order)
	}
	ovPath := filepath.Join(c.state, "overrides", "site.yaml")
	for _, k := range r.calls {
		l := k.line()
		switch {
		case k.Argv[0] == "pull":
			if !slices.Equal(k.Argv, []string{"pull", "-q", "--", "docker.io/library/nginx@" + cuDigest("c")}) {
				t.Errorf("pull %q", l)
			}
			if k.DockerConfig == nil || !strings.HasPrefix(*k.DockerConfig, c.run+"/") || !k.DockerConfigEmpty {
				t.Errorf("pull without an empty DOCKER_CONFIG in the run dir: %+v", k)
			}
		case k.Argv[0] == "tag":
			if !slices.Equal(k.Argv, []string{"tag", cuDigest("d"), "nos-retained:" + cuExecution + "-0"}) {
				t.Errorf("tag %q", l)
			}
		case slices.Contains(k.Argv, "up"):
			want := []string{"compose", "-p", "site", "--project-directory", c.dir, "-f", c.dir + "/compose.yaml", "-f", ovPath,
				"up", "-d", "--no-deps", "--no-build", "--pull", "never", "web"}
			if !slices.Equal(k.Argv, want) {
				t.Errorf("up %q", l)
			}
		case k.Tool == "docker" && k.Argv[0] != "pull" && k.DockerConfig != nil:
			t.Errorf("DOCKER_CONFIG outside the pull: %q", l)
		}
		// No down, removal, prune, restart-only path, operator flags or
		// Compose pull/build.
		if k.Tool == "docker" {
			for _, bad := range []string{"down", "rm", "prune", "restart", "stop", "kill", "--env-file", "--profile", "build", "-v"} {
				if slices.Contains(k.Argv, bad) {
					t.Errorf("forbidden call %q", l)
				}
			}
			if k.Argv[0] == "compose" && slices.Contains(k.Argv, "pull") {
				t.Errorf("compose pull: %q", l)
			}
		}
		if slices.Contains(k.EnvKeys, "SHELL_ONLY_VARIABLE") {
			t.Errorf("a job env variable reached %q", l)
		}
	}
	// The source digest is taken without the override; the applied
	// configuration check uses phase 5's files (Q21).
	if !r.has("docker compose -p site --project-directory " + c.dir + " -f " + c.dir + "/compose.yaml config") {
		t.Error("no source render")
	}
	if !r.has("docker compose -p site --project-directory " + c.dir + " -f " + c.dir + "/compose.yaml config --hash=web") {
		t.Error("no config hash check")
	}
	// The unkeyed config hash never leaves the host.
	if strings.Contains(string(r.out), "hweb") {
		t.Fatal("config hash in the result")
	}
	// Only the nos-retained tag was added; no local tag moved.
	for _, k := range r.calls {
		if k.Argv[0] == "tag" && !strings.HasPrefix(k.Argv[2], "nos-retained:") {
			t.Fatalf("local tag moved: %q", k.line())
		}
	}
}

func appendOnce(s []string, v string) []string {
	if len(s) > 0 && s[len(s)-1] == v {
		return s
	}
	return append(s, v)
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// A missing, malformed or reshaped binding stops the job before it reads
// the host: no docker or curl call at all.
func TestComposeUpdateRefusesMissingOrMalformedBinding(t *testing.T) {
	good, _, err := canonical.ContainerUpdateParameters(newComposeV2(t).u)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(good, &doc); err != nil {
		t.Fatal(err)
	}
	edit := func(fn func(u map[string]any)) []byte {
		var d map[string]any
		_ = json.Unmarshal(good, &d)
		fn(d["container_update"].(map[string]any))
		b, _ := json.Marshal(d)
		return b
	}
	img := func(u map[string]any) map[string]any { return u["images"].([]any)[0].(map[string]any) }
	tgt := func(u map[string]any) map[string]any { return u["targets"].([]any)[0].(map[string]any) }
	cases := map[string][]byte{
		"empty file":         {},
		"empty object":       []byte(`{}`),
		"old project param":  []byte(`{"project":"site"}`),
		"not json":           []byte(`{"container_update":`),
		"extra top level":    append(bytes.TrimSuffix(slices.Clone(good), []byte("}")), []byte(`,"x":1}`)...),
		"duplicate key":      []byte(`{"container_update":{},"container_update":{}}`),
		"invalid utf-8":      append([]byte(`{"x":"`), 0xff, '"', '}'),
		"rollback kind":      edit(func(u map[string]any) { u["kind"] = "rollback" }),
		"standalone form":    edit(func(u map[string]any) { u["form"] = "standalone" }),
		"registry binding":   edit(func(u map[string]any) { u["registry"] = map[string]any{"registry_id": "r"} }),
		"definition binding": edit(func(u map[string]any) { u["definition_id"] = "x" }),
		"no source digest":   edit(func(u map[string]any) { delete(u, "source_digest") }),
		"bad project":        edit(func(u map[string]any) { u["project"] = "-p" }),
		"no images":          edit(func(u map[string]any) { u["images"] = []any{} }),
		"bad platform digest": edit(func(u map[string]any) {
			img(u)["new_platform_digest"] = "sha256:xyz"
		}),
		"index equals platform": edit(func(u map[string]any) { img(u)["new_index_digest"] = img(u)["new_platform_digest"] }),
		"same tag no change":    edit(func(u map[string]any) { img(u)["new_platform_digest"] = cuDigest("a") }),
		"tag change no policy":  edit(func(u map[string]any) { img(u)["new_tag"] = "1.28" }),
		"unknown image field":   edit(func(u map[string]any) { img(u)["rollback"] = map[string]any{} }),
		"mixed image":           edit(func(u map[string]any) { tgt(u)["image_id"] = cuDigest("8") }),
		"reference not old tag": edit(func(u map[string]any) { tgt(u)["running_reference"] = "nginx:1.26" }),
		"reference other repo":  edit(func(u map[string]any) { tgt(u)["running_reference"] = "httpd:1.27" }),
		"short container id":    edit(func(u map[string]any) { tgt(u)["container_id"] = "abc" }),
		"target without entry":  edit(func(u map[string]any) { tgt(u)["service"] = "api" }),
		"dependency recreated": edit(func(u map[string]any) {
			u["dependencies"].([]any)[0].(map[string]any)["service"] = "web"
		}),
		"dependency without containers": edit(func(u map[string]any) {
			u["dependencies"].([]any)[0].(map[string]any)["containers"] = []any{}
		}),
		"null dependencies": edit(func(u map[string]any) { u["dependencies"] = nil }),
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			c := newComposeV2(t)
			c.rawParams, c.params = true, params
			r := c.exec(t)
			if r.code != 10 || r.doc["phase"] != "precheck" || r.doc["reason"] != "binding_invalid" || len(r.calls) != 0 {
				t.Fatalf("%d %s calls %d", r.code, r.out, len(r.calls))
			}
		})
	}
	t.Run("params file missing", func(t *testing.T) {
		c := newComposeV2(t)
		cmd := exec.Command("/bin/sh", "-c", c.script(t))
		cmd.Env = []string{"PATH=" + c.f.bin + ":/usr/bin:/bin", "NEBULA_PARAMS=" + filepath.Join(c.f.dir, "absent.json"),
			"NEBULA_RUN_DIR=" + c.run, "NEBULA_EXECUTION_ID=" + cuExecution}
		out, err := cmd.Output()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 10 || !strings.Contains(string(out), `"reason":"binding_invalid"`) {
			t.Fatalf("%v %s", err, out)
		}
	})
}

// A well-formed binding that does not match the host (tampered, or the host
// changed since the preview) stops in phase 1 or 2 with a typed reason, and
// nothing is pulled, tagged, written or recreated.
func TestComposeUpdateTamperedBindingStopsBeforeChange(t *testing.T) {
	cases := []struct {
		name, reason string
		edit         func(c *composeV2)
	}{
		{"configuration digest", "configuration_changed", func(c *composeV2) { c.u.Targets[0].ConfigurationDigest = cuHex("2") }},
		{"substituted container", "target_changed", func(c *composeV2) {
			c.u.Targets[0].ContainerID = cuHex("4")
		}},
		{"container name", "target_changed", func(c *composeV2) { c.u.Targets[0].ContainerName = "site-web-2" }},
		{"source digest", "source_changed", func(c *composeV2) { c.u.SourceDigest = cuHex("5") }},
		{"working directory", "project_mismatch", func(c *composeV2) { c.u.WorkingDirHash = cuHex("6") }},
		{"config files", "project_mismatch", func(c *composeV2) { c.u.ConfigFilesHash = cuHex("7") }},
		{"project", "project_mismatch", func(c *composeV2) { c.u.Project = "other" }},
		{"forged old tag", "old_tag_mismatch", func(c *composeV2) {
			// A tag change labelled same-tag: the binding claims 1.26 runs.
			c.u.Images[0].OldTag, c.u.Targets[0].RunningReference = "1.26", "nginx:1.26"
			c.u.Images[0].NewTag = "1.27"
			c.u.Images[0].PolicyVersion, c.u.Images[0].PolicyDigest = "stable-v1", cuHex("8")
		}},
		{"old digest", "old_digest_missing", func(c *composeV2) { c.u.Images[0].OldDigests = []string{cuDigest("b")} }},
		{"dependency set", "dependency_set_changed", func(c *composeV2) { c.u.Dependencies[0].Relation = "required_by" }},
		{"dependency digest", "dependency_changed", func(c *composeV2) {
			c.u.Dependencies[0].Containers[0].ConfigurationDigest = cuHex("4")
		}},
		{"moved tag", "tag_moved", func(c *composeV2) { c.u.Images[0].NewPlatformDigest = cuDigest("b") }},
		{"moved index", "tag_moved", func(c *composeV2) { c.u.Images[0].NewIndexDigest = cuDigest("b") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newComposeV2(t)
			tc.edit(c)
			r := c.exec(t)
			if r.code != 10 || r.doc["reason"] != tc.reason || r.mutated() {
				t.Fatalf("%d %s", r.code, r.out)
			}
			if _, ok := c.override(t); ok {
				t.Fatal("override written")
			}
		})
	}
}

// Host states phase 2 does not support stop in phase 1 with their reason
// (container update plan, "What phase 2 does not support").
func TestComposeUpdateUnsupportedHostStatesRefused(t *testing.T) {
	cases := []struct {
		name, reason string
		edit         func(c *composeV2)
	}{
		{"no salt", "prepare_required", func(c *composeV2) { c.noSalt = true }},
		{"group-readable salt", "salt_unsafe", func(c *composeV2) {
			c.beforeRun = func(t *testing.T) {
				if err := os.Chmod(filepath.Join(c.state, "salt"), 0o640); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"symlinked salt", "salt_unsafe", func(c *composeV2) {
			c.beforeRun = func(t *testing.T) {
				p := filepath.Join(c.state, "salt")
				if err := os.Rename(p, p+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(p+".real", p); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"short salt", "salt_unsafe", func(c *composeV2) { c.salt = []byte("short") }},
		{"symlinked override", "override_drift", func(c *composeV2) {
			c.beforeRun = func(t *testing.T) {
				c.writeOverride(t, map[string]string{})
				p := filepath.Join(c.state, "overrides", "site.yaml")
				if err := os.Rename(p, p+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(p+".real", p); err != nil {
					t.Fatal(err)
				}
			}
		}},
		{"stopped replica", "target_not_running", func(c *composeV2) {
			c.container(cuHex("1"))["State"] = map[string]any{"Status": "exited"}
		}},
		{"extra replica", "target_changed", func(c *composeV2) {
			x := cuContainer(cuHex("5"), "site-web-2", "web", cuDigest("d"), "nginx:1.27", "hweb", c.dir)
			c.containers()[cuHex("5")] = x
		}},
		{"hand-scaled", "scale_mismatch", func(c *composeV2) { c.project()["web"].(map[string]any)["scale"] = 2 }},
		{"ephemeral port", "ephemeral_port", func(c *composeV2) {
			c.project()["web"].(map[string]any)["ports"] = []any{map[string]any{"target": 80}}
		}},
		{"build", "build_unsupported", func(c *composeV2) { c.project()["web"].(map[string]any)["build"] = map[string]any{"context": "."} }},
		{"pending edit", "config_not_applied", func(c *composeV2) { c.st["hashes"].(map[string]any)["web"] = "hchanged" }},
		{"operator pin", "digest_pinned", func(c *composeV2) {
			ref := "nginx:1.27@" + cuDigest("a")
			c.container(cuHex("1"))["Config"].(map[string]any)["Image"] = ref
			c.u.Targets[0].RunningReference = ref
			c.u.Targets[0].ConfigurationDigest = c.configDigest(t, c.container(cuHex("1")))
		}},
		{"override label without entry", "override_drift", func(c *composeV2) {
			lb := c.container(cuHex("1"))["Config"].(map[string]any)["Labels"].(map[string]any)
			lb["com.docker.compose.project.config_files"] = c.dir + "/compose.yaml," + c.st["override"].(string)
			c.u.Targets[0].ConfigurationDigest = c.configDigest(t, c.container(cuHex("1")))
		}},
		{"plain up after an update", "override_drift", func(c *composeV2) {
			c.writeOverride(t, map[string]string{"web": "docker.io/library/nginx:1.27@" + cuDigest("a")})
		}},
		{"drift on a sibling service", "override_drift", func(c *composeV2) {
			c.writeOverride(t, map[string]string{"db": "docker.io/library/postgres:16@" + cuDigest("b")})
		}},
		{"namespace sharer", "namespace_sharer", func(c *composeV2) {
			c.project()["db"].(map[string]any)["network_mode"] = "service:web"
		}},
		{"rate limited", "tag_unresolved", func(c *composeV2) {
			reg := c.st["registry"].(map[string]any)
			reg["https://registry-1.docker.io/v2/library/nginx/manifests/1.27"] = map[string]any{"status": 429}
		}},
		{"unanswered resolve", "tag_unresolved", func(c *composeV2) { c.st["registry"] = map[string]any{} }},
		{"platform missing from index", "tag_unresolved", func(c *composeV2) { c.u.Images[0].Platform = "linux/s390x" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newComposeV2(t)
			tc.edit(c)
			r := c.exec(t)
			if r.code != 10 || r.doc["reason"] != tc.reason || r.mutated() {
				t.Fatalf("%d %s", r.code, r.out)
			}
		})
	}
}

// writeOverride writes a NOS override with entries, as an earlier update did.
func (c *composeV2) writeOverride(t *testing.T, entries map[string]string) {
	t.Helper()
	d := filepath.Join(c.state, "overrides")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	svcs := map[string]any{}
	for k, v := range entries {
		svcs[k] = map[string]any{"image": v}
	}
	b, _ := json.Marshal(map[string]any{"services": svcs})
	if err := os.WriteFile(filepath.Join(d, "site.yaml"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A second update of a service that runs from the NOS override passes, and
// a sibling service with no entry beside the override passes too (Q2).
func TestComposeUpdateFromOverridePasses(t *testing.T) {
	c := newComposeV2(t)
	ref := "docker.io/library/nginx:1.27@" + cuDigest("a")
	c.writeOverride(t, map[string]string{"web": ref})
	web := c.container(cuHex("1"))
	web["Config"].(map[string]any)["Image"] = ref
	web["Config"].(map[string]any)["Labels"].(map[string]any)["com.docker.compose.project.config_files"] =
		c.dir + "/compose.yaml," + c.st["override"].(string)
	c.u.Targets[0].RunningReference = ref
	c.u.Targets[0].ConfigurationDigest = c.configDigest(t, web)
	r := c.exec(t)
	if r.code != 0 || r.doc["reason"] != "" {
		t.Fatalf("%d %s", r.code, r.out)
	}
	ov, _ := c.override(t)
	if got := ov["services"].(map[string]any)["web"].(map[string]any)["image"]; got != "docker.io/library/nginx:1.27@"+cuDigest("c") {
		t.Fatalf("override %v", ov)
	}
	// With the override present, the hash check names it as phase 5 does.
	if !r.has("docker compose -p site --project-directory " + c.dir + " -f " + c.dir + "/compose.yaml -f " + c.st["override"].(string) + " config --hash=web") {
		t.Fatal("config hash without the override")
	}
}

// Failures of pull, pulled image and retention stop before any recreate;
// a failed up still reports the after-snapshot with the raw up_exit.
func TestComposeUpdateLaterPhaseFailures(t *testing.T) {
	t.Run("pull fails", func(t *testing.T) {
		c := newComposeV2(t)
		c.st["fail_pull"] = 1
		r := c.exec(t)
		if r.code != 10 || r.doc["reason"] != "pull_failed" || r.doc["phase"] != "pull" || r.has("docker tag") || r.doc["baseline"] == nil {
			t.Fatalf("%d %s", r.code, r.out)
		}
		if _, ok := c.override(t); ok {
			t.Fatal("override written")
		}
	})
	t.Run("pulled platform differs", func(t *testing.T) {
		c := newComposeV2(t)
		im := c.st["pullable"].(map[string]any)["docker.io/library/nginx@"+cuDigest("c")].(map[string]any)
		im["Architecture"] = "arm64"
		r := c.exec(t)
		if r.code != 10 || r.doc["reason"] != "pulled_image_mismatch" || r.has("docker tag") {
			t.Fatalf("%d %s", r.code, r.out)
		}
	})
	t.Run("retention fails", func(t *testing.T) {
		c := newComposeV2(t)
		c.st["fail_tag"] = true
		r := c.exec(t)
		if r.code != 10 || r.doc["reason"] != "retain_failed" || slices.ContainsFunc(r.calls, func(k cuCall) bool { return slices.Contains(k.Argv, "up") }) {
			t.Fatalf("%d %s", r.code, r.out)
		}
		if _, ok := c.override(t); ok {
			t.Fatal("override written")
		}
	})
	t.Run("up fails", func(t *testing.T) {
		c := newComposeV2(t)
		c.st["fail_up"] = 3
		r := c.exec(t)
		if r.code != 1 || r.doc["reason"] != "up_failed" || r.doc["up_exit"] != float64(3) || r.doc["phase"] != "after_snapshot" ||
			r.doc["after"] == nil || r.doc["baseline"] == nil {
			t.Fatalf("%d %s", r.code, r.out)
		}
		for _, k := range r.calls {
			if k.Argv[0] == "tag" && !strings.HasPrefix(k.Argv[2], "nos-retained:") {
				t.Fatalf("local tag moved: %q", k.line())
			}
		}
	})
	t.Run("up killed at once is not a timeout", func(t *testing.T) {
		for _, code := range []int{124, 137} {
			c := newComposeV2(t)
			c.st["fail_up"] = code
			r := c.exec(t)
			if r.doc["reason"] != "up_failed" || r.doc["up_exit"] != float64(code) || r.doc["after"] == nil {
				t.Fatalf("%d %s", code, r.out)
			}
		}
	})
}

// Not root, or a missing host tool, stops before anything is read.
func TestComposeUpdateHostPrerequisites(t *testing.T) {
	c := newComposeV2(t)
	c.f.write(t, "id", `echo 1000`)
	if r := c.exec(t); r.code != 10 || r.doc["reason"] != "not_root" || len(r.calls) != 0 {
		t.Fatalf("%d %s", r.code, r.out)
	}
	c = newComposeV2(t)
	if err := os.Remove(filepath.Join(c.f.bin, "curl")); err != nil {
		t.Fatal(err)
	}
	// Only the fake bin and a directory without curl.
	empty := t.TempDir()
	for _, tool := range []string{"python3", "timeout", "sh"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Skip(tool + " missing")
		}
		if err := os.Symlink(p, filepath.Join(empty, tool)); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("/bin/sh", "-c", c.script(t))
	cmd.Env = []string{"PATH=" + c.f.bin + ":" + empty}
	out, _ := cmd.Output()
	if !strings.Contains(string(out), `"reason":"tooling_missing"`) {
		t.Fatalf("%s", out)
	}
}

// Every curl call starts with -q, so a ~/.curlrc of the host (HOME is
// passed through) cannot add a proxy, -L or -k and undo --proto =https and
// --max-redirs 0 (review of #358).
func TestComposeUpdateCurlIgnoresCurlrc(t *testing.T) {
	c := newComposeV2(t)
	r := c.exec(t)
	if r.code != 0 {
		t.Fatalf("%d %s", r.code, r.out)
	}
	n := 0
	for _, k := range r.calls {
		if k.Tool != "curl" {
			continue
		}
		n++
		if len(k.Argv) == 0 || k.Argv[0] != "-q" {
			t.Errorf("curl without -q first: %q", k.line())
		}
	}
	if n == 0 {
		t.Fatal("no curl call")
	}
	if strings.Count(c.script(t), `"curl"`) != strings.Count(c.script(t), `["curl", "-q", `) {
		t.Fatal("a curl call of the script does not start with -q")
	}
}

// The after-snapshot is bounded in total, not only per container: entries
// past the bound are left out and the result says so, and the result line
// stays far below the 1 MiB server result limit (review of #358).
func TestComposeUpdateAfterSnapshotIsBoundedInTotal(t *testing.T) {
	// Non-ASCII values count as the result line writes them (\uXXXX), not
	// as their UTF-8 bytes.
	for _, tc := range []struct {
		name   string
		filler string
		mounts int
	}{{"ascii", "x", 3}, {"non-ascii", "ä", 1}} {
		t.Run(tc.name, func(t *testing.T) {
			c := newComposeV2(t)
			long := func(p string, i, j int) string {
				return "/" + p + strings.Repeat(tc.filler, 1000) + fmt.Sprintf("/%d/%d", i, j)
			}
			adds := map[string]any{}
			const extra = 45
			for i := range extra {
				id := fmt.Sprintf("%064x", 0x1000+i)
				ctr := cuContainer(id, fmt.Sprintf("site-db-%d", i+2), "db", cuDigest("e"), "postgres:16", "hdb", c.dir)
				var mounts []any
				for j := range tc.mounts {
					mounts = append(mounts, map[string]any{"Type": "bind", "Source": long("s", i, j), "Destination": long("d", i, j), "RW": true})
				}
				ctr["Mounts"] = mounts
				adds[id] = ctr
			}
			c.st["up_adds"] = adds
			r := c.exec(t)
			if r.code != 0 || r.doc["phase"] != "after_snapshot" || r.doc["reason"] != "" {
				t.Fatalf("%d %.300s", r.code, r.out)
			}
			after := r.doc["after"].([]any)
			if r.doc["after_truncated"] != true {
				t.Fatalf("no truncation marker; %d entries", len(after))
			}
			if len(after) == 0 || len(after) >= extra+2 {
				t.Fatalf("%d after entries", len(after))
			}
			// The after-snapshot as written on the result line.
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(r.out, &raw); err != nil {
				t.Fatal(err)
			}
			if len(raw["after"]) > 256*1024 {
				t.Fatalf("after-snapshot %d bytes", len(raw["after"]))
			}
			if len(r.out) > 512*1024 {
				t.Fatalf("result line %d bytes", len(r.out))
			}
			// Kept entries are whole entries, not cut or oversize ones.
			for _, e := range after {
				if _, ok := e.(map[string]any)["configuration_digest"]; !ok {
					t.Fatalf("partial entry %.200v", e)
				}
			}
		})
	}

	// Below the bound there is no marker.
	c := newComposeV2(t)
	r := c.exec(t)
	if _, ok := r.doc["after_truncated"]; ok || r.code != 0 {
		t.Fatalf("%d %s", r.code, r.out)
	}
}

// A failed override write in phase 5 is a recreate-phase failure (exit 1,
// phase recreate), never the precheck class 10 "nothing changed": the
// override may already be replaced (review of #358).
func TestComposeUpdateOverrideWriteFailureIsRecreateFailure(t *testing.T) {
	c := newComposeV2(t)
	c.beforeRun = func(t *testing.T) {
		// Not private: write_override refuses the directory.
		d := filepath.Join(c.state, "overrides")
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	r := c.exec(t)
	if r.code != 1 || r.doc["phase"] != "recreate" || r.doc["reason"] != "override_write_failed" ||
		r.doc["up_exit"] != float64(-1) || r.doc["baseline"] == nil {
		t.Fatalf("%d %s", r.code, r.out)
	}
	if slices.ContainsFunc(r.calls, func(k cuCall) bool { return k.Tool == "docker" && slices.Contains(k.Argv, "up") }) {
		t.Fatal("up ran without the override")
	}
	// Stops before the recreate keep exit 10.
	c = newComposeV2(t)
	c.st["fail_tag"] = true
	if r := c.exec(t); r.code != 10 || r.doc["phase"] != "retain" {
		t.Fatalf("%d %s", r.code, r.out)
	}
}
