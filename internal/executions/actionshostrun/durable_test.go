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
	"os"
	"os/exec"
	"path/filepath"
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
	// duDefinitionSlot is the run secret slot of a standalone definition.
	// The executor's definitionSlot is unexported; this is the same value
	// (internal/executor/container_standalone.go).
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
func duWorld(t *testing.T, web map[string]any) map[string]any {
	t.Helper()
	reg := duRegistry + "1.27"
	pullRef := "docker.io/library/nginx@" + duDigest("c")
	newRef := "docker.io/library/nginx:1.27@" + duDigest("c")
	return map[string]any{
		"planted": duPlanted, "planted_name": "DB_PASSWORD",
		"containers": map[string]any{duHex("1"): web},
		"images": []any{map[string]any{"Id": duDigest("d"), "RepoTags": []any{"nginx:1.27"},
			"RepoDigests": []any{"nginx@" + duDigest("a")}, "Os": "linux", "Architecture": "amd64"}},
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

// duCall is one logged docker or curl call of the fakes.
type duCall struct {
	Tool string   `json:"tool"`
	Argv []string `json:"argv"`
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
// common encoding, is in the result or the log, or in the docker calls.
func duNoLeak(t *testing.T, r duRun, salt []byte) {
	t.Helper()
	values := []string{duPlanted, duInspectOnly}
	if len(salt) > 0 {
		values = append(values, string(salt), hex.EncodeToString(salt), base64.StdEncoding.EncodeToString(salt))
	}
	for _, v := range values {
		if bytes.Contains(r.Result.Result, []byte(v)) || bytes.Contains(r.Log, []byte(v)) {
			t.Fatalf("value %q left the host: result %q log %q", v[:4], r.Result.Result, r.Log)
		}
		if strings.Contains(r.raw, v) {
			t.Fatalf("value %q reached a docker call", v[:4])
		}
	}
}

// duLogLines fails unless every log line is a fixed phase line, as the
// scripts write them (nothing else reaches the log).
func duLogLines(t *testing.T, log []byte) {
	t.Helper()
	for _, ln := range strings.Split(strings.TrimSpace(string(log)), "\n") {
		if ln != "" && !strings.HasPrefix(ln, "nos: phase") && !strings.HasPrefix(ln, "nos: ") {
			t.Fatalf("log line %q", ln)
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
	if first.Class != hostrun.ClassSuccess || first.ExitCode != 0 {
		t.Fatalf("class %s (%s), exit %d, log %q", first.Class, first.Detail, first.ExitCode, first.Log)
	}
	if len(salt) != 32 {
		t.Fatalf("salt has %d bytes, want 32", len(salt))
	}
	p, err := dockerhost.ParseUpdatePrepare(first.Result.Result)
	if err != nil || p.Status != "created" || !p.Prepared() {
		t.Fatalf("first run: %+v, %v", p, err)
	}
	duNoLeak(t, first, salt)
	duLogLines(t, first.Log)

	second, again := d.prepare(t, duPrepareAgain)
	if second.Class != hostrun.ClassSuccess || second.ExitCode != 0 {
		t.Fatalf("second run: class %s, exit %d, log %q", second.Class, second.ExitCode, second.Log)
	}
	p, err = dockerhost.ParseUpdatePrepare(second.Result.Result)
	if err != nil || p.Status != "present" {
		t.Fatalf("second run: %+v, %v", p, err)
	}
	if !bytes.Equal(salt, again) {
		t.Fatal("the second run replaced the salt")
	}
	duNoLeak(t, second, salt)
}

// duSecret is the definition as the executor adds it to the run.
func duSecret(t *testing.T) hostrun.Secret {
	t.Helper()
	return hostrun.Secret{Slot: duDefinitionSlot, Value: duDefinition(t)}
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
	if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
		t.Fatalf("class %s (%s), exit %d, log %q, result %q", r.Class, r.Detail, r.ExitCode, r.Log, r.Result.Result)
	}
	doc := duDoc(t, r.Result)
	if doc["format"] != "standalone-update-v1" || doc["phase"] != "after_snapshot" || doc["reason"] != "" || doc["recreate_exit"] != float64(0) {
		t.Fatalf("result %v", doc)
	}
	if after, _ := doc["after"].([]any); len(after) != 1 {
		t.Fatalf("after-snapshot has %d entries", len(after))
	}
	// The create uses the definition's options, the env file and the bound
	// digest with --pull=never; the env value is in the file, not argv.
	creates := 0
	for _, c := range r.calls {
		if c.Tool == "docker" && len(c.Argv) > 0 && c.Argv[0] == "create" {
			creates++
			if !strings.Contains(strings.Join(c.Argv, " "), "--pull=never") || !strings.Contains(strings.Join(c.Argv, " "), "--name=web") {
				t.Fatalf("create argv %q", c.Argv)
			}
		}
	}
	if creates != 1 {
		t.Fatalf("%d creates, want 1", creates)
	}
	duNoLeak(t, r, salt)
	duLogLines(t, r.Log)
	if st := d.readState(); len(st["containers"].(map[string]any)) != 1 {
		t.Fatalf("containers after update: %v", st["containers"])
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
		if r.Class != hostrun.ClassPrecheckFailed || r.ExitCode != hostrun.ExitPrecheckFailed {
			t.Fatalf("class %s, exit %d, log %q", r.Class, r.ExitCode, r.Log)
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
		duNoLeak(t, r, salt)
	})

	t.Run("failed removal after recreate", func(t *testing.T) {
		d := newDurable(t)
		_, salt := d.prepare(t, duPrepareExec)
		web := duContainer(duHex("1"), "web", duDigest("d"), "nginx:1.27")
		st := duWorld(t, web)
		st["fail_rm"] = 3
		d.writeState(st)
		r := d.job(duUpdateAbort, a, duParams(t, duUpdate(t, salt, web)), duSecret(t))
		if r.Class != hostrun.ClassScriptFailed || r.ExitCode != 1 {
			t.Fatalf("class %s, exit %d, log %q", r.Class, r.ExitCode, r.Log)
		}
		doc := duDoc(t, r.Result)
		if doc["phase"] != "after_snapshot" || doc["reason"] != "remove_failed" {
			t.Fatalf("result %v", doc)
		}
		// What docker.rollback needs as input: the new container, the prior
		// image's ID and the retained tag. The result must carry them.
		after, _ := doc["after"].([]any)
		retained, _ := doc["retained"].([]any)
		baseline, _ := doc["baseline"].([]any)
		if len(after) != 1 || len(retained) != 1 || len(baseline) != 1 {
			t.Fatalf("after %d, retained %d, baseline %d", len(after), len(retained), len(baseline))
		}
		if after[0].(map[string]any)["id"] != duHex("9") || retained[0].(map[string]any)["tag"] != "nos-retained:"+duUpdateAbort+"-0" ||
			baseline[0].(map[string]any)["image_id"] != duDigest("d") {
			t.Fatalf("rollback input missing from %v", doc)
		}
		duNoLeak(t, r, salt)
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
		if r.Class != hostrun.ClassScriptFailed || r.ExitCode != 1 {
			t.Fatalf("class %s, exit %d, log %q", r.Class, r.ExitCode, r.Log)
		}
		doc := duDoc(t, r.Result)
		if doc["phase"] != "after_snapshot" || doc["reason"] != "start_failed" {
			t.Fatalf("result %v", doc)
		}
		// The new container is removed again and the old one is back under
		// its name and running.
		cs := d.readState()["containers"].(map[string]any)
		old, ok := cs[duHex("1")].(map[string]any)
		if !ok || old["Name"] != "/web" || old["State"].(map[string]any)["Status"] != "running" || len(cs) != 1 {
			t.Fatalf("containers after the failed start: %v", cs)
		}
		duNoLeak(t, r, salt)
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
	if ur.ExitCode != 1 {
		t.Fatalf("update exit %d, want 1 (remove failed)", ur.ExitCode)
	}
	doc := duDoc(t, ur.Result)
	newID := doc["after"].([]any)[0].(map[string]any)["id"].(string)
	priorImage := doc["baseline"].([]any)[0].(map[string]any)["image_id"].(string)
	// The result reports the tag with its repository (nos-retained:<exec>-0);
	// the rollback binding carries the bare tag, as the executor strips the
	// prefix (internal/executor/container_recreation_rpc.go).
	retainedTag := strings.TrimPrefix(doc["retained"].([]any)[0].(map[string]any)["tag"].(string), "nos-retained:")

	// The host as the update left it: the failed removal is over, the
	// retained image is known to the fake under its reference, and the
	// rollback creates from the fake's next container template.
	st = d.readState()
	delete(st, "fail_rm")
	retainedRef := "docker.io/library/nginx:1.27@" + duDigest("a")
	for _, im := range st["images"].([]any) {
		m := im.(map[string]any)
		if m["Id"] == priorImage {
			m["_refs"] = []any{retainedRef}
		}
	}
	st["create"] = duCreated(duHex("8"))
	d.writeState(st)

	rb, _ := actions.Lookup("docker.rollback")
	rbParams := duParams(t, duRollback(t, salt, newID, priorImage, retainedTag))
	r := d.job(duRollbackExec, rb, rbParams, duSecret(t))
	if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
		t.Fatalf("rollback: class %s (%s), exit %d, log %q, result %q", r.Class, r.Detail, r.ExitCode, r.Log, r.Result.Result)
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
	created := ""
	for _, c := range r.calls {
		if c.Tool == "docker" && len(c.Argv) > 0 && c.Argv[0] == "create" {
			created = c.Argv[len(c.Argv)-3]
		}
	}
	if created != retainedRef {
		t.Fatalf("rollback created from %q, want the retained reference", created)
	}
	duNoLeak(t, r, salt)
	duLogLines(t, r.Log)
	restored := d.readState()["containers"].(map[string]any)[duHex("8")].(map[string]any)
	if restored["Name"] != "/web" || restored["State"].(map[string]any)["Status"] != "running" || restored["Image"] != priorImage {
		t.Fatalf("restored container %v", restored)
	}

	// A second rollback: the container it would return from is gone, so
	// the precheck must refuse before any change.
	r2 := d.job(duRollbackAgain, rb, duParams(t, duRollback(t, salt, newID, priorImage, retainedTag)), duSecret(t))
	if r2.Class != hostrun.ClassPrecheckFailed || r2.ExitCode != hostrun.ExitPrecheckFailed {
		t.Fatalf("second rollback: class %s, exit %d, log %q, result %q", r2.Class, r2.ExitCode, r2.Log, r2.Result.Result)
	}
	if d2 := duDoc(t, r2.Result); d2["phase"] != "precheck" {
		t.Fatalf("second rollback result %v", d2)
	}
	for _, c := range r2.calls {
		if c.Tool == "docker" && len(c.Argv) > 0 && (c.Argv[0] == "stop" || c.Argv[0] == "rename" || c.Argv[0] == "create") {
			t.Fatalf("a change happened before the precheck: %q", c.Argv)
		}
	}
	duNoLeak(t, r2, salt)
}

// TestDurableJobOutputSizeIsBounded: every docker command answers with 2 MiB
// of inspect output (a padded label in the bound container). The scripts
// bound what they read, so the job stops at a precheck with one small
// document; the result stays under hostrun.MaxResult and the log under
// hostrun.MaxLog.
func TestDurableJobOutputSizeIsBounded(t *testing.T) {
	d := newDurable(t)
	_, salt := d.prepare(t, duPrepareExec)
	web := duContainer(duHex("1"), "web", duDigest("d"), "nginx:1.27")
	web["Config"].(map[string]any)["Labels"].(map[string]any)["pad"] = strings.Repeat("x", duPadBytes)
	d.writeState(duWorld(t, web))

	a, _ := actions.Lookup("docker.update")
	r := d.job(duSizeExec, a, duParams(t, duUpdate(t, salt, web)), duSecret(t))
	if len(r.Result.Result) > hostrun.MaxResult || len(r.Log) > hostrun.MaxLog {
		t.Fatalf("result %d bytes, log %d bytes", len(r.Result.Result), len(r.Log))
	}
	if r.LogTruncated {
		t.Fatal("the log was truncated")
	}
	// The 1 MiB inspect bound (MAX_INSPECT_BYTES) drops the output, and the
	// precheck stops with a typed reason. Which reason is the script's
	// choice: the oversize output is reported as target_changed (a finding,
	// see the report); the test pins the shape, not that reason.
	doc := duDoc(t, r.Result)
	if r.ExitCode != hostrun.ExitPrecheckFailed || doc["phase"] != "precheck" {
		t.Fatalf("exit %d, result %v; want the precheck exit", r.ExitCode, doc)
	}
	if reason, _ := doc["reason"].(string); reason == "" {
		t.Fatalf("precheck without a reason: %v", doc)
	}
	duNoLeak(t, r, salt)
}
