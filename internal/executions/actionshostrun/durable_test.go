// SPDX-License-Identifier: AGPL-3.0-or-later

package actionshostrun_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
)

// The shipped docker.update_prepare, docker.update and docker.rollback 1.0.0
// scripts run as durable jobs: hostrun.Dispatch stores and starts them, the
// test polls hostrun.Check until the job is finished, and hostrun.Collect
// reads the bounded result and log. The job has no sudo and no systemd; its
// directories are temporary. The only substitutions are the one state
// directory line of each script (as in the actions tests) and the fakes:
// docker and curl are the testdata standalone_fake.py, run by python3 -I
// from the fake bin directory, whose state.json and calls.jsonl live in the
// temporary host directory. Nothing touches the network or a registry.

const (
	// duStateDirLine is the one line naming the state directory in the
	// shipped scripts; the test points it at a temporary directory.
	duStateDirLine = `STATE_DIR = "/var/lib/nebula/container-updates"`
	// duDefinitionSlot is the run secret slot of a standalone definition. It
	// must equal the executor's definitionSlot (internal/executor/
	// container_standalone.go), which is unexported; TestDefinitionSlotMatchesExecutor
	// reads that source and fails on any difference, including a rename.
	duDefinitionSlot = "definition"
	// duDefinitionVersion is the bound definition version of the update and
	// of the rollback of it (docker.rollback runs "from the same definition
	// version").
	duDefinitionVersion = 3
	duDefinitionID      = "11111111-2222-4333-8444-555555555555"
	// duPlanted is an env value of the definition; it must never leave the host.
	duPlanted = "planted-env-value-4f0b"
	// duInspectOnly is a value only docker inspect shows; it must not leave either.
	duInspectOnly = "inspect-only-9a2c"
	// duRegistry is the registry answer path the fake curl serves for nginx:1.27.
	duRegistry = "https://registry-1.docker.io/v2/library/nginx/manifests/"
	// Execution IDs of the jobs in these tests (lowercase UUIDs).
	// Each job of a host gets its own ID; the update and rollback IDs are
	// the names the retained tags and the rollback binding refer to.
	duPrepareExec   = "8a6e0804-2bd0-4f6a-8b1e-6d2f1c3a4b01"
	duPrepareAgain  = "8a6e0804-2bd0-4f6a-8b1e-6d2f1c3a4b11"
	duUpdateExec    = "8a6e0804-2bd0-4f6a-8b1e-6d2f1c3a4b02"
	duUpdateAbort   = "8a6e0804-2bd0-4f6a-8b1e-6d2f1c3a4b12"
	duRollbackExec  = "8a6e0804-2bd0-4f6a-8b1e-6d2f1c3a4b03"
	duRollbackAgain = "8a6e0804-2bd0-4f6a-8b1e-6d2f1c3a4b13"
	duSizeExec      = "8a6e0804-2bd0-4f6a-8b1e-6d2f1c3a4b04"
	// duPadBytes is the 2 MiB the size test puts into the inspect output of
	// every docker call (through a padded label of the bound container).
	duPadBytes = 2 << 20
)

func duHex(c string) string    { return strings.Repeat(c, 64) }
func duDigest(c string) string { return "sha256:" + duHex(c) }

// The fake's two registry answers (index and by digest) are built from one
// index body so that its digest is real.
var duIndexBody = `{"manifests":[{"digest":"` + duDigest("c") + `","platform":{"os":"linux","architecture":"amd64"}}]}`

func duIndexDigest() string {
	sum := sha256.Sum256([]byte(duIndexBody))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// duContainer is one standalone container as docker inspect shows it: the
// definition's env value and an inspect-only label are in it.
func duContainer(id, name, image, ref string) map[string]any {
	return map[string]any{
		"Id": id, "Name": "/" + name, "Image": image,
		"Config": map[string]any{"Image": ref, "Env": []any{"SECRET=" + duPlanted, "FROM_INSPECT=" + duInspectOnly},
			"Labels": map[string]any{"note": duInspectOnly}, "Cmd": []any{"--" + duInspectOnly}},
		"HostConfig": map[string]any{"RestartPolicy": map[string]any{"Name": "always"}, "Binds": []any{"/" + duInspectOnly + ":/data"}},
		"State":      map[string]any{"Status": "running", "StartedAt": "2026-11-01T00:00:00Z"},
		"NetworkSettings": map[string]any{
			"Ports":    map[string]any{"80/tcp": []any{map[string]any{"HostIp": "0.0.0.0", "HostPort": "8080"}}},
			"Networks": map[string]any{"bridge": map[string]any{}},
		},
		"Mounts": []any{},
	}
}

// duCreated is the container the fake's create returns (as a template).
func duCreated(id string) map[string]any {
	c := duContainer(id, "", "", "")
	c["State"] = map[string]any{"Status": "created"}
	return c
}

// duDefinition is a stored definition of container web (the encoding of
// internal/executor/containerdef) with the planted env value. It is the run
// secret the executor delivers.
func duDefinition(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"format": "nebula-container-definition-v1", "container_name": "web",
		"options": []any{"--name=web", "--restart=unless-stopped", "--publish=8080:80", "--label=note=from-definition"},
		"command": []any{"serve", "--port=80"},
		"env":     []any{map[string]any{"name": "DB_PASSWORD", "value": duPlanted}, map[string]any{"name": "PORT", "value": "8080"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// duWorld is the host state before any update: web (container 1, nginx:1.27
// on the old digest) and a registry whose 1.27 index lists the bound
// linux/amd64 digest. The update's new container is cuHex 9.
//
// Limit of the fake: its docker tag only appends a RepoTags entry, and its
// create resolves a digest reference only through "_refs". So the prior
// image carries its digest reference (nginx:1.27@a, a repo digest it has
// locally) in _refs from the start, and the update's own docker tag produces
// the nos-retained tag the rollback inspects.
func duWorld(t *testing.T, web map[string]any) map[string]any {
	t.Helper()
	reg := duRegistry + "1.27"
	pullRef := "docker.io/library/nginx@" + duDigest("c")
	newRef := "docker.io/library/nginx:1.27@" + duDigest("c")
	priorRef := "docker.io/library/nginx:1.27@" + duDigest("a")
	return map[string]any{
		"planted": duPlanted, "planted_name": "DB_PASSWORD",
		"containers": map[string]any{duHex("1"): web},
		"images": []any{map[string]any{"Id": duDigest("d"), "RepoTags": []any{"nginx:1.27"},
			"RepoDigests": []any{"nginx@" + duDigest("a")}, "Os": "linux", "Architecture": "amd64",
			"_refs": []any{priorRef}}},
		"pullable": map[string]any{pullRef: map[string]any{"Id": duDigest("f"), "RepoDigests": []any{"nginx@" + duDigest("c")},
			"Os": "linux", "Architecture": "amd64", "_refs": []any{pullRef, newRef}}},
		"create": duCreated(duHex("9")),
		"registry": map[string]any{
			reg: map[string]any{"status": 200, "headers": map[string]any{
				"Docker-Content-Digest": duIndexDigest(), "Content-Type": "application/vnd.oci.image.index.v1+json"}},
			duRegistry + duIndexDigest(): map[string]any{"status": 200, "headers": map[string]any{
				"Docker-Content-Digest": duIndexDigest(), "Content-Type": "application/vnd.oci.image.index.v1+json"}, "body": duIndexBody},
		},
	}
}

// duConfigDigest is the configuration_digest of a container under the
// per-host salt (the scripts' HMAC over the config and host config).
func duConfigDigest(t *testing.T, salt []byte, ctr map[string]any) string {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(map[string]any{"Config": ctr["Config"], "HostConfig": ctr["HostConfig"]}); err != nil {
		t.Fatal(err)
	}
	m := hmac.New(sha256.New, salt)
	m.Write([]byte("nos-configuration-digest-v1\x00"))
	m.Write(bytes.TrimSuffix(b.Bytes(), []byte("\n")))
	return hex.EncodeToString(m.Sum(nil))
}

// duUpdate is the bound update of web (container 1) to the new digest.
func duUpdate(t *testing.T, salt []byte, web map[string]any) canonical.BatchContainerUpdate {
	t.Helper()
	return canonical.BatchContainerUpdate{
		Kind: canonical.ContainerUpdateKindUpdate, Form: canonical.ContainerUpdateFormAlone,
		Images: []canonical.ContainerUpdateImage{{Service: "", Repository: "docker.io/library/nginx", Platform: "linux/amd64",
			OldTag: "1.27", NewTag: "1.27", OldDigests: []string{duDigest("a")}, NewIndexDigest: duIndexDigest(),
			NewPlatformDigest: duDigest("c"), OldImageID: duDigest("d")}},
		Targets: []canonical.ContainerUpdateTarget{{Service: "", ContainerID: duHex("1"), ContainerName: "web",
			ImageID: duDigest("d"), RunningReference: "nginx:1.27", ConfigurationDigest: duConfigDigest(t, salt, web)}},
		Dependencies:      []canonical.ContainerUpdateDependency{},
		DefinitionID:      duDefinitionID,
		DefinitionVersion: duDefinitionVersion,
	}
}

// duRollback is the bound rollback of the update that replaced web with
// container 9 on the new digest and retained the prior image.
func duRollback(t *testing.T, salt []byte, newID, priorImage, retainedTag string) canonical.BatchContainerUpdate {
	t.Helper()
	newRef := "docker.io/library/nginx:1.27@" + duDigest("c")
	retainedRef := "docker.io/library/nginx:1.27@" + duDigest("a")
	web9 := duContainer(newID, "web", duDigest("f"), newRef)
	return canonical.BatchContainerUpdate{
		Kind: canonical.ContainerUpdateKindRollback, Form: canonical.ContainerUpdateFormAlone,
		Images: []canonical.ContainerUpdateImage{{Service: "", Repository: "docker.io/library/nginx", Platform: "linux/amd64",
			OldTag: "1.27", NewTag: "1.27", OldDigests: []string{duDigest("c")},
			Rollback: &canonical.ContainerRollbackImage{PriorImageID: priorImage, RetainedTag: retainedTag, RetainedReference: retainedRef}}},
		Targets: []canonical.ContainerUpdateTarget{{Service: "", ContainerID: newID, ContainerName: "web",
			ImageID: duDigest("f"), RunningReference: newRef, ConfigurationDigest: duConfigDigest(t, salt, web9)}},
		Dependencies:      []canonical.ContainerUpdateDependency{},
		DefinitionID:      duDefinitionID,
		DefinitionVersion: duDefinitionVersion,
		RollbackOf:        duUpdateExec, RecoveryPlanDigest: duHex("5"),
	}
}

// duCall is one logged docker or curl call of the fakes. The env_file_*
// fields are set on a docker create that was given an --env-file: the mode,
// the line count and the names of the variables, and whether the file holds
// the planted value (never the values themselves).
type duCall struct {
	Tool              string   `json:"tool"`
	Argv              []string `json:"argv"`
	EnvFileMode       string   `json:"env_file_mode"`
	EnvFileLines      int      `json:"env_file_lines"`
	EnvFileNames      []string `json:"env_file_names"`
	EnvFileHasPlanted bool     `json:"env_file_has_planted"`
}

// duPhaseLines are the only log lines the shipped scripts write: the phase
// markers of docker.update_prepare, docker.update and docker.rollback
// (the scripts' log helper writes "nos: " plus the line).
var duPhaseLines = map[string]bool{
	"nos: phase: state": true, "nos: phase: create": true, "nos: phase: done": true,
	"nos: phase 1: precheck": true, "nos: phase 2: resolve": true, "nos: phase 3: pull": true,
	"nos: phase 4: retain": true, "nos: phase 5: recreate": true, "nos: phase 6: after-snapshot": true,
}

// duCreates returns the docker create calls of a job, in order.
func duCreates(calls []duCall) []duCall {
	var out []duCall
	for _, c := range calls {
		if c.Tool == "docker" && len(c.Argv) > 0 && c.Argv[0] == "create" {
			out = append(out, c)
		}
	}
	return out
}

// duMap returns the object under key of m, failing the test (not panicking)
// when the shape differs from what the script must have written.
func duMap(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	v, ok := m[key].(map[string]any)
	if !ok {
		t.Fatalf("field %q is not an object: %v", key, m[key])
	}
	return v
}

// duString returns the string under key of m, failing the test when it is not one.
func duString(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	v, ok := m[key].(string)
	if !ok {
		t.Fatalf("field %q is not a string: %v", key, m[key])
	}
	return v
}

// duOne returns the only object of the list under key of doc, failing the
// test unless the list has exactly one object.
func duOne(t *testing.T, doc map[string]any, key string) map[string]any {
	t.Helper()
	list, ok := doc[key].([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("field %q is not a list of one entry: %v", key, doc[key])
	}
	m, ok := list[0].(map[string]any)
	if !ok {
		t.Fatalf("field %q entry is not an object: %v", key, list[0])
	}
	return m
}

// duRun is a job as Collect returned it, with the fakes' calls.
type duRun struct {
	hostrun.Result
	calls []duCall
	raw   string
}

// durable is a temporary host: the fake bin directory and the job directories.
type durable struct {
	t      *testing.T
	h      *fakeHost
	client *ssh.Client
	cfg    hostrun.JobConfig
	state  string
}

func newDurable(t *testing.T) *durable {
	t.Helper()
	h := newFakeHost(t)
	for _, tool := range []string{"python3", "timeout"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Fatalf("test needs %s: %v", tool, err)
		}
		if err := os.Symlink(p, filepath.Join(h.bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	fake, err := os.ReadFile(filepath.Join("..", "actions", "testdata", "standalone_fake.py"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.dir, "fake.py"), fake, 0o600); err != nil {
		t.Fatal(err)
	}
	// Root for the scripts' id -u check; the docker and curl fakes are the
	// standalone one. Nothing else on PATH but the coreutils above.
	h.write(t, "id", `echo 0`)
	h.write(t, "docker", `exec python3 -I "`+h.dir+`/fake.py" docker "$@"`)
	h.write(t, "curl", `exec python3 -I "`+h.dir+`/fake.py" curl "$@"`)
	d := t.TempDir()
	return &durable{t: t, h: h, client: sshClient(t), state: filepath.Join(h.dir, "state"),
		cfg: hostrun.JobConfig{JobRoot: filepath.Join(d, "jobs"), RunRoot: filepath.Join(d, "run")}}
}

// writeState stores the fake host state.
func (d *durable) writeState(st map[string]any) {
	d.t.Helper()
	b, err := json.Marshal(st)
	if err != nil {
		d.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d.h.dir, "state.json"), b, 0o600); err != nil {
		d.t.Fatal(err)
	}
}

// readState returns the fake host state as the last job left it.
func (d *durable) readState() map[string]any {
	d.t.Helper()
	b, err := os.ReadFile(filepath.Join(d.h.dir, "state.json"))
	if err != nil {
		d.t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal(b, &st); err != nil {
		d.t.Fatal(err)
	}
	return st
}

// readCalls returns the fakes' calls since the last job and clears the log.
func (d *durable) readCalls() ([]duCall, string) {
	d.t.Helper()
	p := filepath.Join(d.h.dir, "calls.jsonl")
	b, err := os.ReadFile(p)
	if err != nil && !os.IsNotExist(err) {
		d.t.Fatal(err)
	}
	_ = os.Remove(p)
	var calls []duCall
	for _, ln := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if ln == "" {
			continue
		}
		var c duCall
		if err := json.Unmarshal([]byte(ln), &c); err != nil {
			d.t.Fatal(err)
		}
		calls = append(calls, c)
	}
	return calls, string(b)
}

// job dispatches the shipped script of a as a durable job with params and
// secrets, polls Check until the job has finished, and collects it.
func (d *durable) job(id string, a actions.Action, params []byte, secrets ...hostrun.Secret) duRun {
	t := d.t
	t.Helper()
	s := string(a.Script)
	if strings.Count(s, duStateDirLine) != 1 {
		t.Fatalf("%s: the state directory line is not unique", a.ID)
	}
	s = strings.Replace(s, duStateDirLine, `STATE_DIR = "`+d.state+`"`, 1)
	script := []byte("PATH='" + d.h.bin + "'; export PATH\n" + s)
	ctx := context.Background()
	out, detail, err := hostrun.Dispatch(ctx, d.client, d.cfg, id, params, script, a.Timeout, secrets...)
	if err != nil || out != hostrun.Dispatched {
		t.Fatalf("dispatch %s: outcome %v, %q, %v", a.ID, out, detail, err)
	}
	var st hostrun.JobState
	deadline := time.Now().Add(time.Minute)
	for {
		st, err = hostrun.Check(ctx, d.client, d.cfg, id)
		if err != nil {
			t.Fatal(err)
		}
		if st.Phase == "finished" {
			break
		}
		if st.Phase == "dead" || time.Now().After(deadline) {
			t.Fatalf("job %s: phase %s", a.ID, st.Phase)
		}
		time.Sleep(20 * time.Millisecond)
	}
	r, err := hostrun.Collect(ctx, d.client, d.cfg, id, st.ExitCode)
	if err != nil {
		t.Fatal(err)
	}
	calls, raw := d.readCalls()
	return duRun{Result: r, calls: calls, raw: raw}
}

// doc decodes the one result document of a job into a generic map.
func duDoc(t *testing.T, r hostrun.Result) map[string]any {
	t.Helper()
	oneDocument(t, r.Result)
	var m map[string]any
	if err := json.Unmarshal(r.Result, &m); err != nil {
		t.Fatalf("result %q: %v", r.Result, err)
	}
	return m
}

// duNoLeak fails when the planted or inspect-only value, or the salt in any
// common encoding, is in the result or the log, or in the docker calls. A
// failure names the value by its index in the list below, never its bytes:
// the salt is key material and must not reach test output.
func duNoLeak(t *testing.T, r duRun, salt []byte) {
	t.Helper()
	// Index 0 and 1 are the definition's env value and the inspect-only value;
	// the salt's encodings follow when there is a salt.
	values := []string{duPlanted, duInspectOnly}
	if len(salt) > 0 {
		values = append(values, string(salt), hex.EncodeToString(salt), base64.StdEncoding.EncodeToString(salt))
	}
	for i, v := range values {
		if bytes.Contains(r.Result.Result, []byte(v)) || bytes.Contains(r.Log, []byte(v)) {
			t.Fatalf("secret value #%d (of %d) left the host in the result or the log", i, len(values))
		}
		if strings.Contains(r.raw, v) {
			t.Fatalf("secret value #%d (of %d) reached a docker call", i, len(values))
		}
	}
}

// duLogLines fails unless every log line is one of the fixed phase lines
// (duPhaseLines); nothing else may reach the log.
func duLogLines(t *testing.T, log []byte) {
	t.Helper()
	for _, ln := range strings.Split(strings.TrimSpace(string(log)), "\n") {
		if ln != "" && !duPhaseLines[ln] {
			t.Fatalf("log line %d bytes long is not a phase line", len(ln))
		}
	}
}

// duPrepare runs docker.update_prepare as a durable job and returns the
// salt it left in the state directory.
func (d *durable) prepare(t *testing.T, id string) (duRun, []byte) {
	t.Helper()
	a, ok := actions.Lookup("docker.update_prepare")
	if !ok {
		t.Fatal("docker.update_prepare missing")
	}
	r := d.job(id, a, serverParams(t, a, map[string]string{}))
	salt, err := os.ReadFile(filepath.Join(d.state, "salt"))
	if err != nil {
		t.Fatalf("no salt after prepare: %v", err)
	}
	return r, salt
}

// TestUpdatePrepareDurableJob: the first run creates the salt, the second
// reports present; both are one document of class success, and the salt
// never reaches the result or the log.
func TestUpdatePrepareDurableJob(t *testing.T) {
	d := newDurable(t)
	first, salt := d.prepare(t, duPrepareExec)
	// The leak check runs before any failure message can print the log or result.
	duNoLeak(t, first, salt)
	if first.Class != hostrun.ClassSuccess || first.ExitCode != 0 {
		t.Fatalf("first run: class %s (%s), exit %d", first.Class, first.Detail, first.ExitCode)
	}
	if len(salt) != 32 {
		t.Fatalf("salt has %d bytes, want 32", len(salt))
	}
	p, err := dockerhost.ParseUpdatePrepare(first.Result.Result)
	if err != nil || p.Status != "created" || !p.Prepared() {
		t.Fatalf("first run: %+v, %v", p, err)
	}
	duLogLines(t, first.Log)

	second, again := d.prepare(t, duPrepareAgain)
	duNoLeak(t, second, salt)
	if second.Class != hostrun.ClassSuccess || second.ExitCode != 0 {
		t.Fatalf("second run: class %s, exit %d", second.Class, second.ExitCode)
	}
	p, err = dockerhost.ParseUpdatePrepare(second.Result.Result)
	if err != nil || p.Status != "present" {
		t.Fatalf("second run: %+v, %v", p, err)
	}
	if !bytes.Equal(salt, again) {
		t.Fatal("the second run replaced the salt")
	}
}

// duSecret is the definition as the executor adds it to the run.
func duSecret(t *testing.T) hostrun.Secret {
	t.Helper()
	return hostrun.Secret{Slot: duDefinitionSlot, Value: duDefinition(t)}
}

// TestDefinitionSlotMatchesExecutor: the run secret slot the tests add the
// definition under must be the executor's definitionSlot. That constant is
// unexported and internal/executor cannot be changed here, so the test reads
// its source file, finds the const definitionSlot and requires its string
// literal to equal duDefinitionSlot. A rename of the constant, or a new value,
// fails this test.
func TestDefinitionSlotMatchesExecutor(t *testing.T) {
	const src = "../../executor/container_standalone.go"
	f, err := parser.ParseFile(token.NewFileSet(), src, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", src, err)
	}
	var got string
	found := false
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if name.Name != "definitionSlot" || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Fatalf("%s: definitionSlot is not a string literal", src)
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("%s: definitionSlot: %v", src, err)
				}
				got, found = v, true
			}
		}
	}
	if !found {
		t.Fatalf("%s declares no constant definitionSlot", src)
	}
	if got != duDefinitionSlot {
		t.Fatalf("executor definitionSlot is %q, the tests use %q", got, duDefinitionSlot)
	}
}

// duCheckDefinitionCreate checks the job's one docker create: its argv with
// the job's env-file path replaced by "--env-file=<job secrets>" equals want
// (the definition's options, command and digest reference), and the env file
// the fake read at create was mode 0600 and held the two definition variables,
// the planted value among them. Only names and counts are compared, never values.
func duCheckDefinitionCreate(t *testing.T, calls []duCall, want []string) {
	t.Helper()
	creates := duCreates(calls)
	if len(creates) != 1 {
		t.Fatalf("%d creates, want 1", len(creates))
	}
	c := creates[0]
	argv := slices.Clone(c.Argv)
	envFile := slices.IndexFunc(argv, func(a string) bool { return strings.HasPrefix(a, "--env-file=") })
	if envFile < 0 {
		t.Fatalf("create argv %q has no --env-file", argv)
	}
	argv[envFile] = "--env-file=<job secrets>"
	if !slices.Equal(argv, want) {
		t.Fatalf("create argv %q, want %q", argv, want)
	}
	if c.EnvFileMode != "0o600" || c.EnvFileLines != 2 || !slices.Equal(c.EnvFileNames, []string{"DB_PASSWORD", "PORT"}) || !c.EnvFileHasPlanted {
		t.Fatalf("env file: mode %q, %d lines, names %q, planted %v", c.EnvFileMode, c.EnvFileLines, c.EnvFileNames, c.EnvFileHasPlanted)
	}
}

// duParams builds the update's or rollback's parameters the way the server
// does (canonical form).
func duParams(t *testing.T, u canonical.BatchContainerUpdate) []byte {
	t.Helper()
	params, _, err := canonical.ContainerUpdateParameters(u)
	if err != nil {
		t.Fatal(err)
	}
	return params
}

// TestUpdateDurableJobRecreatesWebFromDefinition: the bound update with the
// definition in its secret slot succeeds as a durable job; the result is
// one document in the standalone-update-v1 shape with one after-snapshot
// and recreate_exit 0; the definition's values stay on the host.
func TestUpdateDurableJobRecreatesWebFromDefinition(t *testing.T) {
	d := newDurable(t)
	_, salt := d.prepare(t, duPrepareExec)
	web := duContainer(duHex("1"), "web", duDigest("d"), "nginx:1.27")
	d.writeState(duWorld(t, web))

	a, _ := actions.Lookup("docker.update")
	r := d.job(duUpdateExec, a, duParams(t, duUpdate(t, salt, web)), duSecret(t))
	duNoLeak(t, r, salt)
	if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
		t.Fatalf("class %s (%s), exit %d", r.Class, r.Detail, r.ExitCode)
	}
	doc := duDoc(t, r.Result)
	if doc["format"] != "standalone-update-v1" || doc["phase"] != "after_snapshot" || doc["reason"] != "" || doc["recreate_exit"] != float64(0) {
		t.Fatalf("result %v", doc)
	}
	duOne(t, doc, "after")
	// The one create must carry the whole definition from the secret slot:
	// its options, its command, the env file built from its env list and the
	// bound digest with --pull=never. The env file path is the job's own, so
	// it is matched by its prefix; every other argv element is exact.
	duCheckDefinitionCreate(t, r.calls, []string{"create", "--name=web", "--restart=unless-stopped", "--publish=8080:80",
		"--label=note=from-definition", "--env-file=<job secrets>", "--pull=never", "--",
		"docker.io/library/nginx:1.27@" + duDigest("c"), "serve", "--port=80"})
	duLogLines(t, r.Log)
	// The survivor is the new container (create template cuHex 9), named /web
	// and running; the old container 1 is gone.
	cs := duMap(t, d.readState(), "containers")
	if len(cs) != 1 {
		t.Fatalf("%d containers after update, want 1", len(cs))
	}
	survivor := duMap(t, cs, duHex("9"))
	if survivor["Name"] != "/web" || duString(t, duMap(t, survivor, "State"), "Status") != "running" {
		t.Fatalf("survivor: name %v, state %v", survivor["Name"], survivor["State"])
	}
}

// TestUpdateDurableJobStopsOrFailsWithRollbackInput covers the two update
// failures of a durable job: a changed container stops before any change
// (exit 10, precheck_failed); a failed removal of the replaced container
// leaves the new one running with the prior image retained, and the result
// names what docker.rollback needs.
func TestUpdateDurableJobStopsOrFailsWithRollbackInput(t *testing.T) {
	a, _ := actions.Lookup("docker.update")

	t.Run("container changed", func(t *testing.T) {
		d := newDurable(t)
		_, salt := d.prepare(t, duPrepareExec)
		web := duContainer(duHex("1"), "web", duDigest("d"), "nginx:1.27")
		u := duUpdate(t, salt, web)
		// The container changed after the binding: a privileged flag the
		// bound configuration digest does not know.
		web["HostConfig"].(map[string]any)["Privileged"] = true
		d.writeState(duWorld(t, web))
		r := d.job(duUpdateExec, a, duParams(t, u), duSecret(t))
		duNoLeak(t, r, salt)
		if r.Class != hostrun.ClassPrecheckFailed || r.ExitCode != hostrun.ExitPrecheckFailed {
			t.Fatalf("class %s, exit %d", r.Class, r.ExitCode)
		}
		doc := duDoc(t, r.Result)
		if doc["phase"] != "precheck" || doc["reason"] != "configuration_changed" {
			t.Fatalf("result %v", doc)
		}
		for _, c := range r.calls {
			if c.Tool == "docker" && len(c.Argv) > 0 && (c.Argv[0] == "create" || c.Argv[0] == "stop" || c.Argv[0] == "rename") {
				t.Fatalf("a change happened before the precheck passed: %q", c.Argv)
			}
		}
	})

	t.Run("failed removal after recreate", func(t *testing.T) {
		d := newDurable(t)
		_, salt := d.prepare(t, duPrepareExec)
		web := duContainer(duHex("1"), "web", duDigest("d"), "nginx:1.27")
		st := duWorld(t, web)
		st["fail_rm"] = 3
		d.writeState(st)
		r := d.job(duUpdateAbort, a, duParams(t, duUpdate(t, salt, web)), duSecret(t))
		duNoLeak(t, r, salt)
		if r.Class != hostrun.ClassScriptFailed || r.ExitCode != 1 {
			t.Fatalf("class %s, exit %d", r.Class, r.ExitCode)
		}
		doc := duDoc(t, r.Result)
		if doc["phase"] != "after_snapshot" || doc["reason"] != "remove_failed" {
			t.Fatalf("result %v", doc)
		}
		// What docker.rollback needs as input: the new container, the prior
		// image's ID and the retained tag. The result must carry them.
		if id := duString(t, duOne(t, doc, "after"), "id"); id != duHex("9") {
			t.Fatalf("after-snapshot id %q, want the new container", id)
		}
		if tag := duString(t, duOne(t, doc, "retained"), "tag"); tag != "nos-retained:"+duUpdateAbort+"-0" {
			t.Fatalf("retained tag %q", tag)
		}
		if img := duString(t, duOne(t, doc, "baseline"), "image_id"); img != duDigest("d") {
			t.Fatalf("baseline image %q, want the prior image", img)
		}
		duLogLines(t, r.Log)
	})

	t.Run("new container not started", func(t *testing.T) {
		d := newDurable(t)
		_, salt := d.prepare(t, duPrepareExec)
		web := duContainer(duHex("1"), "web", duDigest("d"), "nginx:1.27")
		st := duWorld(t, web)
		st["fail_start"] = 3
		d.writeState(st)
		r := d.job(duUpdateExec, a, duParams(t, duUpdate(t, salt, web)), duSecret(t))
		duNoLeak(t, r, salt)
		if r.Class != hostrun.ClassScriptFailed || r.ExitCode != 1 {
			t.Fatalf("class %s, exit %d", r.Class, r.ExitCode)
		}
		doc := duDoc(t, r.Result)
		if doc["phase"] != "after_snapshot" || doc["reason"] != "start_failed" {
			t.Fatalf("result %v", doc)
		}
		// The new container is removed again and the old one is back under
		// its name and running.
		cs := duMap(t, d.readState(), "containers")
		old := duMap(t, cs, duHex("1"))
		if old["Name"] != "/web" || duString(t, duMap(t, old, "State"), "Status") != "running" || len(cs) != 1 {
			t.Fatalf("containers after the failed start: %d, old running %q", len(cs), duString(t, duMap(t, old, "State"), "Status"))
		}
	})
}

// TestRollbackDurableJobRestoresRetainedImage: after an update whose removal
// failed, docker.rollback returns web to the retained prior image (success,
// the fake records the restore on the old image, no pull). A second rollback
// without a recorded container is a precheck failure, not result_missing.
func TestRollbackDurableJobRestoresRetainedImage(t *testing.T) {
	d := newDurable(t)
	_, salt := d.prepare(t, duPrepareExec)
	web := duContainer(duHex("1"), "web", duDigest("d"), "nginx:1.27")
	st := duWorld(t, web)
	st["fail_rm"] = 3
	d.writeState(st)
	upd, _ := actions.Lookup("docker.update")
	ur := d.job(duUpdateExec, upd, duParams(t, duUpdate(t, salt, web)), duSecret(t))
	duNoLeak(t, ur, salt)
	if ur.ExitCode != 1 {
		t.Fatalf("update exit %d, want 1 (remove failed)", ur.ExitCode)
	}
	doc := duDoc(t, ur.Result)
	newID := duString(t, duOne(t, doc, "after"), "id")
	priorImage := duString(t, duOne(t, doc, "baseline"), "image_id")
	// The result reports the tag with its repository (nos-retained:<exec>-0);
	// the rollback binding carries the bare tag, as the executor strips the
	// prefix (internal/executor/container_recreation_rpc.go).
	const retainedPrefix = "nos-retained:"
	retained := duString(t, duOne(t, doc, "retained"), "tag")
	if !strings.HasPrefix(retained, retainedPrefix) {
		t.Fatalf("retained tag %q lacks the %q prefix", retained, retainedPrefix)
	}
	retainedTag := strings.TrimPrefix(retained, retainedPrefix)

	// The update's own retain step (phase 4) must have tagged the prior image
	// under the retained tag; the rollback's inspect of that tag depends on it.
	wantTag := retainedPrefix + duUpdateExec + "-0"
	if !slices.ContainsFunc(ur.calls, func(c duCall) bool {
		return c.Tool == "docker" && slices.Equal(c.Argv, []string{"tag", priorImage, wantTag})
	}) {
		t.Fatalf("the update did not tag the prior image as %q", wantTag)
	}
	// The host as the update left it. The failed removal is over; the fake's
	// next create gets container ID 8. The retained reference is the fake's
	// initial state (see duWorld), not written here.
	st = d.readState()
	delete(st, "fail_rm")
	st["create"] = duCreated(duHex("8"))
	d.writeState(st)
	retainedRef := "docker.io/library/nginx:1.27@" + duDigest("a")

	rb, _ := actions.Lookup("docker.rollback")
	rbParams := duParams(t, duRollback(t, salt, newID, priorImage, retainedTag))
	r := d.job(duRollbackExec, rb, rbParams, duSecret(t))
	duNoLeak(t, r, salt)
	if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
		t.Fatalf("rollback: class %s (%s), exit %d", r.Class, r.Detail, r.ExitCode)
	}
	rdoc := duDoc(t, r.Result)
	if rdoc["format"] != "standalone-rollback-v1" || rdoc["phase"] != "after_snapshot" || rdoc["reason"] != "" {
		t.Fatalf("rollback result %v", rdoc)
	}
	for _, c := range r.calls {
		if c.Tool == "curl" || (c.Tool == "docker" && len(c.Argv) > 0 && (c.Argv[0] == "pull" || c.Argv[0] == "tag")) {
			t.Fatalf("a rollback resolves or pulls: %+v", c)
		}
	}
	// The rollback recreates web from the same definition: its options, its
	// command and the env file, with the retained reference as the image.
	duCheckDefinitionCreate(t, r.calls, []string{"create", "--name=web", "--restart=unless-stopped", "--publish=8080:80",
		"--label=note=from-definition", "--env-file=<job secrets>", "--pull=never", "--", retainedRef, "serve", "--port=80"})
	duLogLines(t, r.Log)
	restored := duMap(t, duMap(t, d.readState(), "containers"), duHex("8"))
	// Failure messages name only the fields compared; the restored container
	// carries the planted and inspect-only values and must not be printed.
	if restored["Name"] != "/web" || duString(t, duMap(t, restored, "State"), "Status") != "running" || restored["Image"] != priorImage {
		t.Fatalf("restored container: name %v, status %v, image %v", restored["Name"], duMap(t, restored, "State")["Status"], restored["Image"])
	}

	// A second rollback: the container it would return from is gone, so
	// the precheck must refuse before any change.
	r2 := d.job(duRollbackAgain, rb, duParams(t, duRollback(t, salt, newID, priorImage, retainedTag)), duSecret(t))
	duNoLeak(t, r2, salt)
	if r2.Class != hostrun.ClassPrecheckFailed || r2.ExitCode != hostrun.ExitPrecheckFailed {
		t.Fatalf("second rollback: class %s, exit %d", r2.Class, r2.ExitCode)
	}
	// The container is gone (its ID is the bound target), so the inspect
	// reports target_changed; the phase alone would also match another refusal.
	if d2 := duDoc(t, r2.Result); d2["phase"] != "precheck" || d2["reason"] != "target_changed" {
		t.Fatalf("second rollback: phase %v, reason %v", d2["phase"], d2["reason"])
	}
	for _, c := range r2.calls {
		if c.Tool == "docker" && len(c.Argv) > 0 && (c.Argv[0] == "stop" || c.Argv[0] == "rename" || c.Argv[0] == "create") {
			t.Fatalf("a change happened before the precheck: %q", c.Argv)
		}
	}
}

// TestDurableJobOutputSizeIsBounded: only the docker inspect of the bound
// container is padded (a 2 MiB label); no other docker or curl call is. The
// bound configuration digest is computed before the padding, so the padded
// inspect would not match it. The script's call() reads the whole stdout and
// drops it above MAX_INSPECT_BYTES (1 MiB; cu05 uses the cu02 phase 1
// inspect). The cap alone turns the output into target_changed, so the test
// pins that reason: without the cap the padded container would fail the
// digest check with configuration_changed instead. The result stays under
// hostrun.MaxResult and the log under hostrun.MaxLog.
func TestDurableJobOutputSizeIsBounded(t *testing.T) {
	d := newDurable(t)
	_, salt := d.prepare(t, duPrepareExec)
	web := duContainer(duHex("1"), "web", duDigest("d"), "nginx:1.27")
	u := duUpdate(t, salt, web)
	web["Config"].(map[string]any)["Labels"].(map[string]any)["pad"] = strings.Repeat("x", duPadBytes)
	d.writeState(duWorld(t, web))

	a, _ := actions.Lookup("docker.update")
	r := d.job(duSizeExec, a, duParams(t, u), duSecret(t))
	duNoLeak(t, r, salt)
	if len(r.Result.Result) > hostrun.MaxResult || len(r.Log) > hostrun.MaxLog {
		t.Fatalf("result %d bytes, log %d bytes", len(r.Result.Result), len(r.Log))
	}
	if r.LogTruncated {
		t.Fatal("the log was truncated")
	}
	doc := duDoc(t, r.Result)
	if r.ExitCode != hostrun.ExitPrecheckFailed || doc["phase"] != "precheck" {
		t.Fatalf("exit %d, phase %v; want the precheck exit", r.ExitCode, doc["phase"])
	}
	if doc["reason"] != "target_changed" {
		t.Fatalf("precheck reason %v, want target_changed (the inspect cap)", doc["reason"])
	}
}
