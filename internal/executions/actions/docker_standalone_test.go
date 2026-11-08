// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// The tests of docker.update and docker.rollback 1.0.0 (cu05) run the
// shipped scripts against a fake Docker host (testdata/standalone_fake.py):
// one standalone container "web" (nginx:1.27) and a registry whose 1.27
// index lists the bound linux/amd64 digest. The definition is the run
// secret file $NEBULA_SECRETS_DIR/definition, as the executor delivers it.

const (
	saPlanted     = "planted-env-value-5e2b"
	saPlantedName = "DB_PASSWORD"
	saExecution   = "00000000-0000-4000-8000-000000000002"
	saUpdateExec  = "00000000-0000-4000-8000-0000000000bb"
	// saInspectOnly marks values only `docker inspect` shows; none may
	// reach a create argument.
	saInspectOnly = "inspect-only-7c1d"
)

type standalone struct {
	f                     *fakeHost
	state, run, secrets   string
	salt                  []byte
	st                    map[string]any
	u                     canonical.BatchContainerUpdate
	def                   map[string]any
	actionID              string
	noDefinition, rawDef  bool
	defRaw                []byte
	indexBody, idxDigest  string
	newRef, retainedImage string
}

// saContainer is one standalone container as `docker inspect` shows it,
// with env, labels, binds and a command that exist only in the inspect
// document.
func saContainer(id, name, image, ref string) map[string]any {
	return map[string]any{
		"Id": id, "Name": "/" + name, "Image": image,
		"Config": map[string]any{"Image": ref, "Env": []any{"SECRET=" + saPlanted, "FROM_INSPECT=" + saInspectOnly},
			"Labels": map[string]any{"note": saInspectOnly}, "Cmd": []any{"--" + saInspectOnly}},
		"HostConfig": map[string]any{"RestartPolicy": map[string]any{"Name": "always"}, "Binds": []any{"/" + saInspectOnly + ":/data"}},
		"State":      map[string]any{"Status": "running", "StartedAt": "2026-11-01T00:00:00Z"},
		"NetworkSettings": map[string]any{
			"Ports":    map[string]any{"80/tcp": []any{map[string]any{"HostIp": "0.0.0.0", "HostPort": "8080"}}},
			"Networks": map[string]any{"bridge": map[string]any{}},
		},
		"Mounts": []any{},
	}
}

// saDefinition is a stored definition of container web in its encoding
// (internal/executor/containerdef), with the planted env value.
func saDefinition() map[string]any {
	return map[string]any{
		"format": "nebula-container-definition-v1", "container_name": "web",
		"options": []any{"--name=web", "--restart=unless-stopped", "--publish=8080:80", "--label=note=from-definition"},
		"command": []any{"serve", "--port=80"},
		"env": []any{map[string]any{"name": saPlantedName, "value": saPlanted}, map[string]any{"name": "PORT", "value": "8080"},
			map[string]any{"name": "SPACED", "value": " a b = c "}},
	}
}

func newStandalone(t *testing.T) *standalone {
	t.Helper()
	f := newFakeHost(t, "1")
	c := &standalone{f: f, state: filepath.Join(f.dir, "state"), run: filepath.Join(f.dir, "run"), secrets: filepath.Join(f.dir, "run", "secrets"),
		salt: []byte("0123456789abcdef0123456789abcdef"), actionID: "docker.update"}
	if err := os.MkdirAll(c.secrets, 0o700); err != nil {
		t.Fatal(err)
	}
	fake, err := os.ReadFile(filepath.Join("testdata", "standalone_fake.py"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "fake.py"), fake, 0o600); err != nil {
		t.Fatal(err)
	}
	f.write(t, "docker", `exec python3 -I "`+f.dir+`/fake.py" docker "$@"`)
	f.write(t, "curl", `exec python3 -I "`+f.dir+`/fake.py" curl "$@"`)

	web := saContainer(cuHex("1"), "web", cuDigest("d"), "nginx:1.27")
	created := saContainer(cuHex("9"), "", "", "")
	created["State"] = map[string]any{"Status": "created"}
	c.indexBody = `{"manifests":[{"digest":"` + cuDigest("c") + `","platform":{"os":"linux","architecture":"amd64"}}]}`
	sum := sha256.Sum256([]byte(c.indexBody))
	c.idxDigest = "sha256:" + hex.EncodeToString(sum[:])
	reg := "https://registry-1.docker.io/v2/library/nginx/manifests/"
	pullRef := "docker.io/library/nginx@" + cuDigest("c")
	c.newRef = "docker.io/library/nginx:1.27@" + cuDigest("c")
	c.st = map[string]any{
		"planted": saPlanted, "planted_name": saPlantedName,
		"containers": map[string]any{cuHex("1"): web},
		"images": []any{map[string]any{"Id": cuDigest("d"), "RepoTags": []any{"nginx:1.27"}, "RepoDigests": []any{"nginx@" + cuDigest("a")},
			"Os": "linux", "Architecture": "amd64"}},
		"pullable": map[string]any{pullRef: map[string]any{"Id": cuDigest("f"), "RepoDigests": []any{"nginx@" + cuDigest("c")},
			"Os": "linux", "Architecture": "amd64", "_refs": []any{pullRef, c.newRef}}},
		"create": created,
		"registry": map[string]any{
			reg + "1.27": map[string]any{"status": 200, "headers": map[string]any{
				"Docker-Content-Digest": c.idxDigest, "Content-Type": "application/vnd.oci.image.index.v1+json"}},
			reg + c.idxDigest: map[string]any{"status": 200, "headers": map[string]any{
				"Docker-Content-Digest": c.idxDigest, "Content-Type": "application/vnd.oci.image.index.v1+json"}, "body": c.indexBody},
		},
	}
	c.u = canonical.BatchContainerUpdate{
		Kind: canonical.ContainerUpdateKindUpdate, Form: canonical.ContainerUpdateFormAlone,
		Images: []canonical.ContainerUpdateImage{{Service: "", Repository: "docker.io/library/nginx", Platform: "linux/amd64",
			OldTag: "1.27", NewTag: "1.27", OldDigests: []string{cuDigest("a")}, NewIndexDigest: c.idxDigest,
			NewPlatformDigest: cuDigest("c"), OldImageID: cuDigest("d")}},
		Targets: []canonical.ContainerUpdateTarget{{Service: "", ContainerID: cuHex("1"), ContainerName: "web",
			ImageID: cuDigest("d"), RunningReference: "nginx:1.27", ConfigurationDigest: c.configDigest(t, web)}},
		Dependencies:      []canonical.ContainerUpdateDependency{},
		DefinitionID:      "11111111-2222-4333-8444-555555555555",
		DefinitionVersion: 3,
	}
	c.def = saDefinition()
	return c
}

// newStandaloneRollback is the fake host after a passed docker.update: web
// recreated as cuHex("9") on the pulled image, the prior image retained as
// nos-retained:<update>-0, and the rollback binding that matches it.
func newStandaloneRollback(t *testing.T) *standalone {
	t.Helper()
	c := newStandalone(t)
	c.actionID = "docker.rollback"
	retainedRef := "docker.io/library/nginx:1.27@" + cuDigest("a")
	web := saContainer(cuHex("9"), "web", cuDigest("f"), c.newRef)
	c.st["containers"] = map[string]any{cuHex("9"): web}
	c.st["images"] = []any{
		map[string]any{"Id": cuDigest("d"), "RepoTags": []any{"nginx:1.27", "nos-retained:" + saUpdateExec + "-0"},
			"RepoDigests": []any{"nginx@" + cuDigest("a")}, "Os": "linux", "Architecture": "amd64", "_refs": []any{retainedRef}},
		map[string]any{"Id": cuDigest("f"), "RepoDigests": []any{"nginx@" + cuDigest("c")}, "Os": "linux", "Architecture": "amd64"},
	}
	created := saContainer(cuHex("8"), "", "", "")
	created["State"] = map[string]any{"Status": "created"}
	c.st["create"] = created
	delete(c.st, "pullable")
	delete(c.st, "registry")
	c.u = canonical.BatchContainerUpdate{
		Kind: canonical.ContainerUpdateKindRollback, Form: canonical.ContainerUpdateFormAlone,
		Images: []canonical.ContainerUpdateImage{{Service: "", Repository: "docker.io/library/nginx", Platform: "linux/amd64",
			OldTag: "1.27", NewTag: "1.27", OldDigests: []string{cuDigest("c")},
			Rollback: &canonical.ContainerRollbackImage{PriorImageID: cuDigest("d"), RetainedTag: saUpdateExec + "-0",
				RetainedReference: retainedRef}}},
		Targets: []canonical.ContainerUpdateTarget{{Service: "", ContainerID: cuHex("9"), ContainerName: "web",
			ImageID: cuDigest("f"), RunningReference: c.newRef, ConfigurationDigest: c.configDigest(t, web)}},
		Dependencies:      []canonical.ContainerUpdateDependency{},
		DefinitionID:      "11111111-2222-4333-8444-555555555555",
		DefinitionVersion: 2,
		RollbackOf:        saUpdateExec, RecoveryPlanDigest: cuHex("5"),
	}
	c.retainedImage = retainedRef
	return c
}

// configDigest is the expected configuration_digest of a container.
func (c *standalone) configDigest(t *testing.T, ctr map[string]any) string {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(map[string]any{"Config": ctr["Config"], "HostConfig": ctr["HostConfig"]}); err != nil {
		t.Fatal(err)
	}
	m := hmac.New(sha256.New, c.salt)
	m.Write([]byte("nos-configuration-digest-v1\x00"))
	m.Write(bytes.TrimSuffix(b.Bytes(), []byte("\n")))
	return hex.EncodeToString(m.Sum(nil))
}

func (c *standalone) containers() map[string]any { return c.st["containers"].(map[string]any) }

// exec runs the shipped script of c.actionID once and checks R4 on every
// run: no planted env value and no inspect-only value in the result or
// the log, and the log holds fixed phase lines only.
func (c *standalone) exec(t *testing.T) saRun {
	t.Helper()
	if err := os.MkdirAll(c.state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.state, "salt"), c.salt, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := json.Marshal(c.st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.f.dir, "state.json"), st, 0o600); err != nil {
		t.Fatal(err)
	}
	params, _, err := canonical.ContainerUpdateParameters(c.u)
	if err != nil {
		t.Fatal(err)
	}
	pp := filepath.Join(c.f.dir, "params.json")
	if err := os.WriteFile(pp, params, 0o600); err != nil {
		t.Fatal(err)
	}
	defPath := filepath.Join(c.secrets, "definition")
	_ = os.Remove(defPath)
	if !c.noDefinition {
		raw := c.defRaw
		if !c.rawDef {
			if raw, err = json.Marshal(c.def); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(defPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.Remove(filepath.Join(c.secrets, "env"))
	a, ok := Lookup(c.actionID)
	if !ok {
		t.Fatalf("%s missing", c.actionID)
	}
	s := string(a.Script)
	if strings.Count(s, cuStateDirLine) != 1 {
		t.Fatal("the state directory line is not unique in the script")
	}
	s = strings.Replace(s, cuStateDirLine, `STATE_DIR = "`+c.state+`"`, 1)
	cmd := exec.Command("/bin/sh", "-c", s)
	cmd.Dir = c.f.dir
	cmd.Env = []string{"PATH=" + c.f.bin + ":/usr/bin:/bin", "NEBULA_PARAMS=" + pp, "NEBULA_RUN_DIR=" + c.run,
		"NEBULA_SECRETS_DIR=" + c.secrets, "NEBULA_EXECUTION_ID=" + saExecution}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	r := saRun{cuRun: cuRun{out: out, stderr: stderr.String()}}
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
	_ = os.Remove(filepath.Join(c.f.dir, "calls.jsonl"))
	for _, ln := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if ln == "" {
			continue
		}
		var k cuCall
		if err := json.Unmarshal([]byte(ln), &k); err != nil {
			t.Fatal(err)
		}
		r.calls = append(r.calls, k)
		r.raw = append(r.raw, ln)
	}
	for _, v := range []string{saPlanted, saInspectOnly} {
		if strings.Contains(string(out), v) || strings.Contains(r.stderr, v) {
			t.Fatalf("value %q left the host: %q %q", v, out, r.stderr)
		}
	}
	for _, ln := range strings.Split(strings.TrimSpace(r.stderr), "\n") {
		if ln != "" && !strings.HasPrefix(ln, "nos: phase ") {
			t.Fatalf("log line %q", ln)
		}
	}
	// The env file never outlives the create.
	if _, err := os.Stat(filepath.Join(c.secrets, "env")); err == nil {
		t.Fatal("the env file is left in the secret directory")
	}
	return r
}

// call returns the docker calls whose first argument is verb.
func (r cuRun) docker(verb string) []cuCall {
	var out []cuCall
	for _, k := range r.calls {
		if k.Tool == "docker" && len(k.Argv) > 0 && k.Argv[0] == verb {
			out = append(out, k)
		}
	}
	return out
}

// changedContainers reports whether any call could have changed a container.
func (r cuRun) changedContainers() bool {
	for _, v := range []string{"stop", "rename", "create", "start", "rm"} {
		if len(r.docker(v)) > 0 {
			return true
		}
	}
	return false
}

// The catalog's docker.update and docker.rollback are 1.0.0: durable,
// reconcile-first, MEDIUM jobs with the fixed 30-minute timeout, no string
// parameters and no secret slot (the executor alone adds the definition;
// the planner sees no slot, G8). The rollback resolves and pulls nothing.
func TestStandaloneCatalogEntries(t *testing.T) {
	for id, format := range map[string]string{"docker.update": "standalone-update-v1", "docker.rollback": "standalone-rollback-v1"} {
		a, ok := Lookup(id)
		if !ok || a.Version != "1.0.0" || !a.Durable || a.ReadOnly || a.Retry != RetryReconcileFirst ||
			a.Risk != pb.RiskClass_RISK_CLASS_MEDIUM || a.Timeout.Minutes() != 30 || len(a.Params) != 0 || len(a.Secrets) != 0 {
			t.Fatalf("%s: %+v", id, a)
		}
		s := string(a.Script)
		for _, want := range []string{id + " 1.0.0", `FORMAT = "` + format + `"`, "python3 -I", `"container_update"`,
			`NEBULA_SECRETS_DIR`, `"--env-file=" + env_file`, `"--pull=never"`, "stderr=subprocess.DEVNULL"} {
			if !strings.Contains(s, want) {
				t.Errorf("%s lacks %q", id, want)
			}
		}
		// No shell and no Compose: the definition's arguments are an argv.
		for _, banned := range []string{"shell=True", "os.system", `"docker", "compose"`, "stderr=subprocess.PIPE", "stderr=subprocess.STDOUT"} {
			if strings.Contains(s, banned) {
				t.Errorf("%s contains %q", id, banned)
			}
		}
		n := 0
		for _, b := range Builtin {
			if b.ID == id {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("%d %s entries", n, id)
		}
	}
	rb, _ := Lookup("docker.rollback")
	for _, banned := range []string{"curl", `"docker", "pull"`, `"docker", "tag"`, "rmi", "prune"} {
		if strings.Contains(string(rb.Script), banned) {
			t.Errorf("docker.rollback contains %q", banned)
		}
	}
}

// An update inside the bound state runs all six phases and recreates the
// container from exactly the definition and the bound image: the create's
// arguments are the definition's options, the tmpfs env file, --pull=never,
// the bound repository:new_tag@digest and the definition's command, and no
// field of the inspected container reaches it.
func TestNoInspectReconstruction(t *testing.T) {
	c := newStandalone(t)
	r := c.exec(t)
	if r.code != 0 || r.doc["format"] != "standalone-update-v1" || r.doc["phase"] != "after_snapshot" || r.doc["reason"] != "" ||
		r.doc["recreate_exit"] != float64(0) {
		t.Fatalf("%d %s", r.code, r.out)
	}
	creates := r.docker("create")
	if len(creates) != 1 {
		t.Fatalf("creates %+v", creates)
	}
	want := []string{"create", "--name=web", "--restart=unless-stopped", "--publish=8080:80", "--label=note=from-definition",
		"--env-file=" + filepath.Join(c.secrets, "env"), "--pull=never", "--", c.newRef, "serve", "--port=80"}
	if !slices.Equal(creates[0].Argv, want) {
		t.Fatalf("create argv %q, want %q", creates[0].Argv, want)
	}
	for _, k := range r.calls {
		if strings.Contains(strings.Join(k.Argv, " "), saInspectOnly) {
			t.Fatalf("an inspect-only value reached a call: %q", k.Argv)
		}
	}
	// The order: stop, rename aside, create, start, remove the old one.
	var verbs []string
	for _, k := range r.calls {
		if k.Tool == "docker" && slices.Contains([]string{"stop", "rename", "create", "start", "rm"}, k.Argv[0]) {
			verbs = append(verbs, strings.Join(k.Argv, " "))
		}
	}
	wantVerbs := []string{"stop -- " + cuHex("1"), "rename " + cuHex("1") + " nos-replaced-" + saExecution, strings.Join(want, " "),
		"start " + cuHex("9"), "rm " + cuHex("1")}
	if !slices.Equal(verbs, wantVerbs) {
		t.Fatalf("calls %q, want %q", verbs, wantVerbs)
	}
	base := r.doc["baseline"].([]any)
	after := r.doc["after"].([]any)
	if len(base) != 1 || len(after) != 1 {
		t.Fatalf("snapshots %v %v", base, after)
	}
	b, a := base[0].(map[string]any), after[0].(map[string]any)
	if b["id"] != cuHex("1") || b["name"] != "web" || b["service"] != "" || b["replica"] != "1" ||
		a["id"] != cuHex("9") || a["name"] != "web" || a["running_reference"] != c.newRef || a["image_id"] != cuDigest("f") ||
		a["state"] != "running" {
		t.Fatalf("baseline %v after %v", b, a)
	}
	if p := r.doc["pulled"].([]any); len(p) != 1 || p[0].(map[string]any)["image_id"] != cuDigest("f") {
		t.Fatalf("pulled %v", p)
	}
	if rt := r.doc["retained"].([]any); len(rt) != 1 || rt[0].(map[string]any)["tag"] != "nos-retained:"+saExecution+"-0" {
		t.Fatalf("retained %v", rt)
	}
	if pulls := r.docker("pull"); len(pulls) != 1 || pulls[0].DockerConfig == nil || !pulls[0].DockerConfigEmpty {
		t.Fatalf("pulls %+v", pulls)
	}
}

// Env values travel only in the root-only env file on the run's tmpfs:
// never in an argument of any call, and the file holds exactly the
// definition's entries, unchanged.
func TestDefinitionEnvNotOnCommandLine(t *testing.T) {
	c := newStandalone(t)
	r := c.exec(t)
	if r.code != 0 {
		t.Fatalf("%d %s", r.code, r.out)
	}
	for _, k := range r.calls {
		line := strings.Join(k.Argv, "\x00")
		if strings.Contains(line, saPlanted) || strings.Contains(line, " a b = c ") || slices.Contains(k.Argv, "-e") ||
			slices.ContainsFunc(k.Argv, func(a string) bool { return strings.HasPrefix(a, "--env=") }) {
			t.Fatalf("an env value is on a command line: %q", k.Argv)
		}
	}
	got := r.createExtra(t)
	if got.Mode != "0o600" || got.Lines != 3 || !slices.Equal(got.Names, []string{saPlantedName, "PORT", "SPACED"}) || !got.HasPlanted {
		t.Fatalf("env file %+v", got)
	}
}

type createExtra struct {
	Mode       string   `json:"env_file_mode"`
	Lines      int      `json:"env_file_lines"`
	Names      []string `json:"env_file_names"`
	HasPlanted bool     `json:"env_file_has_planted"`
}

// saRun is one script run with the raw call lines.
type saRun struct {
	cuRun
	raw []string
}

// createExtra is what the fake saw of the env file at create time.
func (r saRun) createExtra(t *testing.T) createExtra {
	t.Helper()
	for _, k := range r.raw {
		var probe struct {
			Argv []string `json:"argv"`
			createExtra
		}
		if err := json.Unmarshal([]byte(k), &probe); err == nil && len(probe.Argv) > 0 && probe.Argv[0] == "create" {
			return probe.createExtra
		}
	}
	t.Fatal("no create call")
	return createExtra{}
}

// A docker call that fails and prints one env value of the definition on
// stdout and stderr (pull, create, start, rm, and the rollback's create,
// start and rm) leaves no trace of it: neither result nor log holds it,
// only a typed reason and an exit status leave. A failed create or start
// puts the old container back under its name and running.
func TestStandaloneFailureOutputHoldsNoEnvValue(t *testing.T) {
	cases := []struct {
		action, fail, reason string
		phase                string
		restored             bool
	}{
		{"docker.update", "pull", "pull_failed", "pull", false},
		{"docker.update", "create", "create_failed", "after_snapshot", true},
		{"docker.update", "start", "start_failed", "after_snapshot", true},
		{"docker.update", "rm", "remove_failed", "after_snapshot", false},
		{"docker.update", "stop", "stop_failed", "after_snapshot", true},
		{"docker.rollback", "create", "create_failed", "after_snapshot", true},
		{"docker.rollback", "start", "start_failed", "after_snapshot", true},
		{"docker.rollback", "rm", "remove_failed", "after_snapshot", false},
	}
	for _, tc := range cases {
		t.Run(tc.action+"/"+tc.fail, func(t *testing.T) {
			c := newStandalone(t)
			old := cuHex("1")
			if tc.action == "docker.rollback" {
				c = newStandaloneRollback(t)
				old = cuHex("9")
			}
			c.st["fail_"+tc.fail] = 3
			r := c.exec(t) // checks result and log for the planted value
			if r.doc["reason"] != tc.reason || r.doc["phase"] != tc.phase || r.code == 0 {
				t.Fatalf("%d %s", r.code, r.out)
			}
			if strings.Contains(string(r.out), saPlanted) {
				t.Fatal("planted value in the result")
			}
			if tc.phase == "after_snapshot" && r.doc["recreate_exit"] == float64(0) {
				t.Fatalf("recreate_exit %v", r.doc["recreate_exit"])
			}
			if tc.restored {
				st := c.readState(t)
				ctr, ok := st["containers"].(map[string]any)[old].(map[string]any)
				if !ok || ctr["Name"] != "/web" || ctr["State"].(map[string]any)["Status"] != "running" {
					t.Fatalf("old container not restored: %v", st["containers"])
				}
				if len(st["containers"].(map[string]any)) != 1 {
					t.Fatalf("a created container is left: %v", st["containers"])
				}
			}
		})
	}
}

func (c *standalone) readState(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(c.f.dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

// The definition is checked again on the host (as the executor did before
// dispatch): a missing one, one for another container, an env value with a
// newline, carriage return or NUL, an env option, an image flag, a
// Docker-chosen host port, an unknown key, a short flag or a positional
// argument stops the job before any change, with a typed reason and
// without the value.
func TestStandaloneDefinitionRefusedOnHost(t *testing.T) {
	envWith := func(v string) func(d map[string]any) {
		return func(d map[string]any) {
			d["env"] = []any{map[string]any{"name": saPlantedName, "value": saPlanted + v}}
		}
	}
	opts := func(o ...any) func(d map[string]any) {
		return func(d map[string]any) { d["options"] = append([]any{"--name=web"}, o...) }
	}
	cases := []struct {
		name   string
		mod    func(d map[string]any)
		raw    string
		none   bool
		reason string
	}{
		{name: "missing", none: true, reason: "definition_missing"},
		{name: "other container", mod: func(d map[string]any) { d["container_name"] = "db" }, reason: "definition_invalid"},
		{name: "name option for another", mod: func(d map[string]any) { d["options"] = []any{"--name=db"} }, reason: "definition_invalid"},
		{name: "newline", mod: envWith("\nX=1"), reason: "definition_invalid"},
		{name: "trailing CR", mod: envWith("\r"), reason: "definition_invalid"},
		{name: "inner CR", mod: envWith("\rx"), reason: "definition_invalid"},
		{name: "NUL", mod: envWith("\x00"), reason: "definition_invalid"},
		{name: "env option", mod: opts("--env=" + saPlantedName + "=" + saPlanted), reason: "definition_invalid"},
		{name: "env-file option", mod: opts("--env-file=/etc/shadow"), reason: "definition_invalid"},
		{name: "pull option", mod: opts("--pull=always"), reason: "definition_invalid"},
		{name: "chosen host port", mod: opts("--publish=80"), reason: "definition_invalid"},
		{name: "empty host port", mod: opts("--publish=:80"), reason: "definition_invalid"},
		{name: "zero host port", mod: opts("--publish=0:80"), reason: "definition_invalid"},
		{name: "range against one port", mod: opts("--publish=8000-8010:80"), reason: "definition_invalid"},
		{name: "publish-all", mod: opts("--publish-all=true"), reason: "definition_invalid"},
		{name: "short flag", mod: opts("-v=/:/host"), reason: "definition_invalid"},
		{name: "positional", mod: opts("alpine"), reason: "definition_invalid"},
		{name: "control character", mod: opts("--label=a\x1bb"), reason: "definition_invalid"},
		{name: "unknown key", mod: func(d map[string]any) { d["image"] = "evil:latest" }, reason: "definition_invalid"},
		{name: "duplicate env", mod: func(d map[string]any) {
			d["env"] = []any{map[string]any{"name": "A", "value": "1"}, map[string]any{"name": "A", "value": saPlanted}}
		}, reason: "definition_invalid"},
		{name: "not JSON", raw: "{" + saPlanted, reason: "definition_invalid"},
		{name: "duplicate key", raw: `{"format":"nebula-container-definition-v1","format":"x"}`, reason: "definition_invalid"},
	}
	for _, action := range []string{"docker.update", "docker.rollback"} {
		for _, tc := range cases {
			t.Run(action+"/"+tc.name, func(t *testing.T) {
				c := newStandalone(t)
				if action == "docker.rollback" {
					c = newStandaloneRollback(t)
				}
				c.noDefinition = tc.none
				if tc.raw != "" {
					c.rawDef, c.defRaw = true, []byte(tc.raw)
				}
				if tc.mod != nil {
					tc.mod(c.def)
				}
				r := c.exec(t)
				if r.code != 10 || r.doc["phase"] != "precheck" || r.doc["reason"] != tc.reason {
					t.Fatalf("%d %s", r.code, r.out)
				}
				if r.changedContainers() || len(r.docker("pull")) > 0 || len(r.docker("tag")) > 0 {
					t.Fatalf("a refused definition changed the host: %+v", r.calls)
				}
			})
		}
	}
}

// Injection through the definition: values that a shell would interpret
// reach Docker as literal arguments (no shell runs anywhere), and the
// definition's option form keeps them inside their own flag.
func TestDefinitionArgumentsAreNotInterpreted(t *testing.T) {
	c := newStandalone(t)
	marker := filepath.Join(c.f.dir, "injected")
	c.def["options"] = []any{"--name=web", "--label=x=$(touch " + marker + ")", "--hostname=`touch " + marker + "`;id"}
	c.def["command"] = []any{"sh", "-c", "touch " + marker, "; touch " + marker}
	r := c.exec(t)
	if r.code != 0 {
		t.Fatalf("%d %s", r.code, r.out)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a definition value was interpreted by a shell")
	}
	argv := r.docker("create")[0].Argv
	if !slices.Contains(argv, "--label=x=$(touch "+marker+")") || argv[len(argv)-1] != "; touch "+marker {
		t.Fatalf("create argv %q", argv)
	}
}

// The update stops before any change when the host is not what the binding
// says: another configuration, a Compose container, a stopped container,
// another running reference, a missing old digest.
func TestStandaloneUpdateStopsBeforeChange(t *testing.T) {
	cases := []struct {
		name, reason string
		mod          func(c *standalone)
	}{
		{"configuration changed", "configuration_changed", func(c *standalone) {
			c.containers()[cuHex("1")].(map[string]any)["HostConfig"].(map[string]any)["Privileged"] = true
		}},
		{"compose container", "compose_managed", func(c *standalone) {
			ctr := c.containers()[cuHex("1")].(map[string]any)
			ctr["Config"].(map[string]any)["Labels"].(map[string]any)["com.docker.compose.project"] = "site"
			c.u.Targets[0].ConfigurationDigest = c.configDigest(t, ctr)
		}},
		{"not running", "target_not_running", func(c *standalone) {
			c.containers()[cuHex("1")].(map[string]any)["State"] = map[string]any{"Status": "exited"}
		}},
		{"other name", "target_changed", func(c *standalone) {
			c.containers()[cuHex("1")].(map[string]any)["Name"] = "/web2"
		}},
		{"old digest missing", "old_digest_missing", func(c *standalone) {
			c.st["images"].([]any)[0].(map[string]any)["RepoDigests"] = []any{}
		}},
		{"tag moved", "tag_moved", func(c *standalone) {
			c.u.Images[0].NewIndexDigest = cuDigest("b")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newStandalone(t)
			tc.mod(c)
			r := c.exec(t)
			if r.code != 10 || r.doc["reason"] != tc.reason {
				t.Fatalf("%d %s", r.code, r.out)
			}
			if r.changedContainers() || len(r.docker("tag")) > 0 {
				t.Fatalf("changed: %+v", r.calls)
			}
		})
	}
	// A compose or registry binding is refused by the standalone script.
	c := newStandalone(t)
	c.u.Form = canonical.ContainerUpdateFormCompose
	if r := c.exec(t); r.code != 10 || r.doc["reason"] != "binding_invalid" {
		t.Fatalf("compose form: %s", r.out)
	}
}

// A rollback recreates the container from the definition and the bound
// retained reference: nothing is resolved, pulled or tagged, and a missing
// retained image stops it before any change.
func TestStandaloneRollbackRecreatesRetainedImage(t *testing.T) {
	c := newStandaloneRollback(t)
	r := c.exec(t)
	if r.code != 0 || r.doc["format"] != "standalone-rollback-v1" || r.doc["phase"] != "after_snapshot" || r.doc["reason"] != "" {
		t.Fatalf("%d %s", r.code, r.out)
	}
	if _, ok := r.doc["pulled"]; ok {
		t.Fatal("a rollback reports pulled images")
	}
	if _, ok := r.doc["retained"]; ok {
		t.Fatal("a rollback reports retained images")
	}
	argv := r.docker("create")[0].Argv
	if argv[len(argv)-3] != c.retainedImage {
		t.Fatalf("create argv %q", argv)
	}
	if len(r.docker("pull")) > 0 || len(r.docker("tag")) > 0 || slices.ContainsFunc(r.calls, func(k cuCall) bool { return k.Tool == "curl" }) {
		t.Fatalf("calls %+v", r.calls)
	}
	a := r.doc["after"].([]any)[0].(map[string]any)
	if a["id"] != cuHex("8") || a["running_reference"] != c.retainedImage || a["image_id"] != cuDigest("d") {
		t.Fatalf("after %v", a)
	}

	c = newStandaloneRollback(t)
	c.st["images"] = c.st["images"].([]any)[1:]
	r = c.exec(t)
	if r.code != 10 || r.doc["phase"] != "retain" || r.doc["reason"] != "retained_image_missing" || r.changedContainers() {
		t.Fatalf("%d %s", r.code, r.out)
	}
	// An update binding is refused by the rollback script.
	c = newStandaloneRollback(t)
	c.u.Kind = canonical.ContainerUpdateKindUpdate
	if r := c.exec(t); r.code != 10 || r.doc["reason"] != "binding_invalid" {
		t.Fatalf("update binding: %s", r.out)
	}
}
