// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// The tests of docker.update_preview 1.0.0 run the shipped script against
// the fake host of the docker.compose_update 2.0.0 tests (newComposeV2), so
// both scripts see the same fixture. As there, only the state directory
// line of the copy that runs is rewritten.

// previewScript is the shipped preview artifact with its state directory
// moved into the test's directory.
func (c *composeV2) previewScript(t *testing.T) string {
	t.Helper()
	a, ok := Lookup("docker.update_preview")
	if !ok {
		t.Fatal("docker.update_preview missing")
	}
	s := string(a.Script)
	if strings.Count(s, cuStateDirLine) != 1 {
		t.Fatal("the state directory line is not unique in the preview script")
	}
	s = strings.Replace(s, cuStateDirLine, `STATE_DIR = "`+c.state+`"`, 1)
	if c.previewWallClock != "" {
		if strings.Count(s, pvWallClockLine) != 1 {
			t.Fatal("the wall clock line is not unique in the preview script")
		}
		s = strings.Replace(s, pvWallClockLine, "MAX_PREVIEW_WALL_CLOCK = "+c.previewWallClock, 1)
	}
	return s
}

const pvWallClockLine = "MAX_PREVIEW_WALL_CLOCK = 4 * 60"

// The wall clock is checked before every external call, inside a unit
// too: a Compose call that hangs is killed within the remaining budget,
// and that unit and every later one are truncated without facts. (The
// copy that runs has a 13-second wall clock instead of 4 minutes.)
func TestPreviewWallClockTruncatesRemainingUnits(t *testing.T) {
	c := newComposeV2(t)
	c.previewWallClock = "13"
	c.st["hang_config"] = 60
	solo := cuContainer(cuHex("5"), "solo", "", cuDigest("d"), "nginx:1.27", "", c.dir)
	solo["Config"].(map[string]any)["Labels"] = map[string]any{}
	c.containers()[cuHex("5")] = solo
	start := time.Now()
	r := c.preview(t, "")
	if took := time.Since(start); took > 30*time.Second {
		t.Fatalf("the preview took %s", took)
	}
	if r.code != 0 || r.doc["status"] != "ok" {
		t.Fatalf("%d %s", r.code, r.out)
	}
	units := r.doc["units"].([]any)
	if len(units) != 2 {
		t.Fatalf("%s", r.out)
	}
	for _, x := range units {
		u := x.(map[string]any)
		if u["reason"] != "truncated" || u["targets"] != nil || u["source_digest"] != nil {
			t.Fatalf("unit %v", u)
		}
	}
}

// preview runs the preview script with target_tags tags. Like exec, it
// checks that no planted env value reaches result or log and that the log
// holds fixed phase lines only.
func (c *composeV2) preview(t *testing.T, tags string) cuRun {
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
	_ = os.Remove(filepath.Join(c.f.dir, "calls.jsonl"))
	params := c.params
	if !c.rawParams {
		a, _ := Lookup("docker.update_preview")
		if params, err = a.ParametersJSON(map[string]string{"target_tags": tags}, nil); err != nil {
			t.Fatal(err)
		}
	}
	pp := filepath.Join(c.f.dir, "params.json")
	if err := os.WriteFile(pp, params, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", c.previewScript(t))
	cmd.Dir = c.f.dir
	cmd.Env = []string{"PATH=" + c.f.bin + ":/usr/bin:/bin", "NEBULA_PARAMS=" + pp, "NEBULA_RUN_DIR=" + c.run,
		"NEBULA_EXECUTION_ID=" + cuExecution}
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
	if strings.Contains(string(out), cuPlanted) || strings.Contains(r.stderr, cuPlanted) {
		t.Fatalf("a planted env value left the host: %q %q", out, r.stderr)
	}
	for _, ln := range strings.Split(strings.TrimSpace(r.stderr), "\n") {
		if ln != "" && !strings.HasPrefix(ln, "nos: phase") {
			t.Fatalf("log line %q", ln)
		}
	}
	// Whatever the host showed, the strict parser accepts the result.
	if _, err := dockerhost.ParseUpdatePreview(out); err != nil {
		t.Fatalf("the parser refuses the script's result %s: %v", out, err)
	}
	return r
}

// unit returns the result's unit of a Compose project.
func (r cuRun) unit(t *testing.T, project string) map[string]any {
	t.Helper()
	for _, u := range r.doc["units"].([]any) {
		m := u.(map[string]any)
		if m["form"] == "compose" && m["project"] == project {
			return m
		}
	}
	t.Fatalf("no unit %s in %s", project, r.out)
	return nil
}

func previewService(t *testing.T, u map[string]any, name string) map[string]any {
	t.Helper()
	for _, s := range u["services"].([]any) {
		if m := s.(map[string]any); m["service"] == name {
			return m
		}
	}
	t.Fatalf("no service %s in %v", name, u)
	return nil
}

func previewReasons(t *testing.T, u map[string]any, name string) []string {
	t.Helper()
	var out []string
	for _, r := range previewService(t, u, name)["reasons"].([]any) {
		out = append(out, r.(string))
	}
	return out
}

func previewTarget(t *testing.T, u map[string]any, id string) map[string]any {
	t.Helper()
	for _, x := range u["targets"].([]any) {
		if m := x.(map[string]any); m["container_id"] == id {
			return m
		}
	}
	t.Fatalf("no target %s in %v", id, u)
	return nil
}

// The catalog entry is a LOW, read-only, durable job with the fixed
// 5-minute timeout and one target_tags parameter that may be empty.
func TestUpdatePreviewCatalog(t *testing.T) {
	a, ok := Lookup("docker.update_preview")
	if !ok || a.Version != "1.0.0" || !a.Durable || !a.ReadOnly || a.Risk != pb.RiskClass_RISK_CLASS_LOW ||
		a.Timeout.Minutes() != 5 || len(a.Params) != 1 || a.Params[0].Name != "target_tags" || len(a.Secrets) != 0 {
		t.Fatalf("%+v", a)
	}
	s := string(a.Script)
	for _, want := range []string{"docker.update_preview 1.0.0", `FORMAT = "docker-update-preview-v1"`, "python3 -I"} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	for _, good := range []string{"", "1.27", "1.27,1.28", "latest,v2.0.1-alpine", nTags(20)} {
		if err := a.ValidParams(map[string]string{"target_tags": good}); err != nil {
			t.Errorf("%q refused: %v", good, err)
		}
	}
	for _, bad := range []string{",", "a,", ",a", "a,,b", "-x", ".x", "a b", "a;b", `a"`, strings.Repeat("a", 129),
		nTags(21), "a,a"} {
		if a.ValidParams(map[string]string{"target_tags": bad}) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if a.ValidParams(nil) == nil || a.ValidParams(map[string]string{"target_tags": "", "x": ""}) == nil {
		t.Error("parameter set not enforced")
	}
}

// The functions that make a digest, read the salt and the override, and
// call Compose are byte for byte the ones of docker.compose_update 2.0.0,
// so the preview's digests are the ones the update recomputes.
func TestPreviewSharesDigestCodeWithUpdate(t *testing.T) {
	up, _ := Lookup("docker.compose_update")
	pv, _ := Lookup("docker.update_preview")
	for _, name := range []string{"hmac_hex", "canon", "config_digest", "compose_base", "parse_ref", "repo_digests",
		"owned_private", "read_private", "read_salt", "override_path", "read_override", "depends", "call", "text",
		"platform_of", "labels", "no_dupes", "registry_of"} {
		a, b := pyDef(t, up.Script, name), pyDef(t, pv.Script, name)
		if a != b {
			t.Errorf("def %s differs between the update and the preview script", name)
		}
	}
	for _, block := range []string{"BASE_ENV = {", "class Budget:", "ACCEPT = "} {
		if a, b := pyBlock(t, up.Script, block), pyBlock(t, pv.Script, block); a != b {
			t.Errorf("%s differs between the update and the preview script", block)
		}
	}
	for _, line := range []string{`STATE_DIR = "/var/lib/nebula/container-updates"`, `SALT_FILE = STATE_DIR + "/salt"`,
		`OVERRIDE_DIR = STATE_DIR + "/overrides"`, `L_FILES = "com.docker.compose.project.config_files"`,
		`L_WORKDIR = "com.docker.compose.project.working_dir"`, `L_HASH = "com.docker.compose.config-hash"`,
		"MAX_COMPOSE_CONFIG_BYTES = 4 * 1024 * 1024", "MAX_CONFIG_FILES = 16", "MAX_CONFIG_FILE_BYTES = 1024 * 1024"} {
		if !bytes.Contains(up.Script, []byte(line+"\n")) || !bytes.Contains(pv.Script, []byte(line+"\n")) {
			t.Errorf("line %q is not in both scripts", line)
		}
	}
	// Both scripts call the digest functions with the same domains.
	for _, call := range []string{`hmac_hex(salt, b"nos-configuration-digest-v1", canon({"Config": c["Config"], "HostConfig": c["HostConfig"]}))`,
		`b"nos-source-digest-v1", out)`, `compose_base(unit, False) + ["config"]`} {
		if !bytes.Contains(up.Script, []byte(call)) || !bytes.Contains(pv.Script, []byte(call)) {
			t.Errorf("%q is not in both scripts", call)
		}
	}
}

var pyTopLevel = regexp.MustCompile(`(?m)^\S`)

// pyDef returns the source of the top-level function name.
func pyDef(t *testing.T, script []byte, name string) string {
	t.Helper()
	return pyBlock(t, script, "def "+name+"(")
}

// pyBlock returns the top-level block that starts with the line prefix
// start, up to the next top-level line.
func pyBlock(t *testing.T, script []byte, start string) string {
	t.Helper()
	s := string(script)
	i := strings.Index(s, "\n"+start)
	if i < 0 {
		t.Fatalf("no %q", start)
	}
	body := s[i+1:]
	next := pyTopLevel.FindAllStringIndex(body, 2)
	if len(next) < 2 {
		return strings.TrimSpace(body)
	}
	return strings.TrimSpace(body[:next[1][0]])
}

// The shared test vector: on one fixture, the preview reports exactly the
// digests and identities the update binding of the 2.0.0 tests holds, and
// a binding built only from the preview's facts passes the update's
// precheck and runs through.
func TestPreviewDigestsEqualUpdateScript(t *testing.T) {
	c := newComposeV2(t)
	r := c.preview(t, "")
	if r.code != 0 || r.doc["status"] != "ok" || r.doc["format"] != "docker-update-preview-v1" {
		t.Fatalf("%d %s", r.code, r.out)
	}
	u := r.unit(t, "site")
	if u["reason"] != "" || u["source_digest"] != c.u.SourceDigest || u["working_dir_hash"] != c.u.WorkingDirHash ||
		u["config_files_hash"] != c.u.ConfigFilesHash {
		t.Fatalf("unit %v, want source %s", u, c.u.SourceDigest)
	}
	web := previewTarget(t, u, cuHex("1"))
	db := previewTarget(t, u, cuHex("3"))
	if web["configuration_digest"] != c.u.Targets[0].ConfigurationDigest ||
		db["configuration_digest"] != c.u.Dependencies[0].Containers[0].ConfigurationDigest ||
		web["running_reference"] != "nginx:1.27" || web["image_id"] != cuDigest("d") || web["container_name"] != "site-web-1" ||
		web["state"] != "running" || web["service"] != "web" {
		t.Fatalf("targets %v %v", web, db)
	}
	for _, s := range []string{"web", "db"} {
		if rs := previewReasons(t, u, s); len(rs) != 0 {
			t.Fatalf("%s reasons %v", s, rs)
		}
	}
	dep := previewService(t, u, "web")["depends"].([]any)
	if len(dep) != 1 || dep[0].(map[string]any)["service"] != "db" || dep[0].(map[string]any)["restart"] != false {
		t.Fatalf("depends %v", dep)
	}
	var img map[string]any
	for _, x := range u["images"].([]any) {
		if m := x.(map[string]any); m["image_id"] == cuDigest("d") {
			img = m
		}
	}
	if img == nil || img["repository"] != "docker.io/library/nginx" || img["tag"] != "1.27" || img["platform"] != "linux/amd64" ||
		!jsonEqual(img["old_digests"], []any{cuDigest("a")}) || img["reason"] != "" {
		t.Fatalf("image %v", img)
	}
	res := img["resolved"].([]any)
	if len(res) != 1 || !jsonEqual(res[0], map[string]any{"tag": "1.27", "index_digest": c.idxDigest,
		"platform_digest": cuDigest("c"), "reason": ""}) {
		t.Fatalf("resolved %v", res)
	}

	// The binding built from the preview's facts alone runs through.
	c.u.SourceDigest = u["source_digest"].(string)
	c.u.WorkingDirHash = u["working_dir_hash"].(string)
	c.u.ConfigFilesHash = u["config_files_hash"].(string)
	c.u.Targets[0].ConfigurationDigest = web["configuration_digest"].(string)
	c.u.Dependencies[0].Containers[0].ConfigurationDigest = db["configuration_digest"].(string)
	c.u.Images[0].NewIndexDigest = c.idxDigest
	c.u.Images[0].NewPlatformDigest = cuDigest("c")
	up := c.exec(t)
	if up.code != 0 || up.doc["phase"] != "after_snapshot" || up.doc["reason"] != "" {
		t.Fatalf("update from the preview's binding: %d %s", up.code, up.out)
	}
}

// A different salt gives different digests (the digests are keyed), and
// the keyed digests never equal an unkeyed SHA-256 of the same data.
func TestPreviewDigestsAreKeyed(t *testing.T) {
	c := newComposeV2(t)
	a := c.preview(t, "").unit(t, "site")
	c.salt = []byte("fedcba9876543210fedcba9876543210")
	b := c.preview(t, "").unit(t, "site")
	if a["source_digest"] == b["source_digest"] ||
		previewTarget(t, a, cuHex("1"))["configuration_digest"] == previewTarget(t, b, cuHex("1"))["configuration_digest"] {
		t.Fatal("digests do not depend on the salt")
	}
	if a["source_digest"] == cuSHA(c.st["source_config"].(string)) {
		t.Fatal("source digest is unkeyed")
	}
}

// previewMutators are the docker and compose subcommands that change a
// host; the preview calls none of them.
var previewAllowed = []string{"ps -a --no-trunc --format ", "inspect --type container -- ", "image inspect -- "}

// TestPreviewWritesNothing: with and without a salt, the preview changes
// no file in the fake host's tree (salt, override, project, run directory)
// and makes only reading calls: docker ps, inspect, image inspect, compose
// config, and curl HEAD or GET.
func TestPreviewWritesNothing(t *testing.T) {
	for _, noSalt := range []bool{false, true} {
		c := newComposeV2(t)
		c.noSalt = noSalt
		// An existing override, so its directory and file are in the tree.
		var before map[string]string
		c.beforeRun = func(t *testing.T) {
			writeOverride(t, c, `{"services": {}}`)
			if !noSalt {
				before = treeOf(t, c.f.dir)
			}
		}
		r := c.preview(t, "1.28")
		if noSalt {
			if r.code != 0 || r.doc["status"] != "prepare_required" || len(r.doc["units"].([]any)) != 0 {
				t.Fatalf("no salt: %d %s", r.code, r.out)
			}
			if _, err := os.Stat(filepath.Join(c.state, "salt")); !os.IsNotExist(err) {
				t.Fatalf("the preview created a salt: %v", err)
			}
			if len(r.calls) != 0 {
				t.Fatalf("calls without a salt: %v", r.calls)
			}
			continue
		}
		if r.code != 0 || r.doc["status"] != "ok" {
			t.Fatalf("%d %s", r.code, r.out)
		}
		after := treeOf(t, c.f.dir)
		for p, h := range before {
			if after[p] != h {
				t.Errorf("%s changed", p)
			}
		}
		for p := range after {
			if _, ok := before[p]; !ok {
				t.Errorf("%s created", p)
			}
		}
		for _, k := range r.calls {
			line := strings.Join(k.Argv, " ")
			switch {
			case k.Tool == "curl":
				if !k.Head && !strings.Contains(k.URL, "/manifests/sha256:") {
					t.Errorf("curl GET %s", k.URL)
				}
			case slices.ContainsFunc(previewAllowed, func(p string) bool { return strings.HasPrefix(line, p) }):
			case k.Argv[0] == "compose" && slices.Contains(k.Argv, "config") && !slices.ContainsFunc(k.Argv, func(a string) bool {
				return slices.Contains([]string{"up", "pull", "down", "rm", "stop", "start", "restart", "create", "run", "kill", "build"}, a)
			}):
			default:
				t.Errorf("call %s %s", k.Tool, line)
			}
		}
	}
}

func writeOverride(t *testing.T, c *composeV2, body string) {
	t.Helper()
	d := filepath.Join(c.state, "overrides")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "site.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// treeOf maps every path under dir to its mode and content, except the
// files the test harness itself writes around the run (the fake's state
// and call record, the parameters).
func treeOf(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if dir == filepath.Dir(p) && slices.Contains([]string{"calls.jsonl", "state.json", "params.json"}, filepath.Base(p)) {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		v := fi.Mode().String()
		if d.Type().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			v += " " + string(b)
		}
		out[p] = v
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Every unavailable reason the preview reports, each from one change of
// the fixture. Observed reasons of a complete unit (override_drift and the
// per-service reasons, among them scale_mismatch and target_not_running)
// keep its identity facts; unit-level failures report no facts.
func TestPreviewUnavailableReasons(t *testing.T) {
	pinned := "nginx:1.27@" + cuDigest("a")
	cases := []struct {
		name    string
		mutate  func(t *testing.T, c *composeV2)
		unit    string // the unit's reason
		service string // the service with reasons
		reasons []string
	}{
		{name: "override_drift", unit: "override_drift", mutate: func(t *testing.T, c *composeV2) {
			// The override names web, the container does not follow it.
			c.beforeRun = func(t *testing.T) {
				writeOverride(t, c, `{"services": {"web": {"image": "docker.io/library/nginx:1.27@`+cuDigest("c")+`"}}}`)
			}
		}},
		{name: "override_drift_unreadable", unit: "override_drift", mutate: func(t *testing.T, c *composeV2) {
			c.beforeRun = func(t *testing.T) { writeOverride(t, c, `not json`) }
		}},
		{name: "override_drift_label_without_entry", unit: "override_drift", mutate: func(t *testing.T, c *composeV2) {
			lb := c.container(cuHex("1"))["Config"].(map[string]any)["Labels"].(map[string]any)
			lb["com.docker.compose.project.config_files"] = c.dir + "/compose.yaml," + c.st["override"].(string)
		}},
		{name: "config_not_applied", service: "web", reasons: []string{"config_not_applied"}, mutate: func(t *testing.T, c *composeV2) {
			c.st["hashes"].(map[string]any)["web"] = "pending-edit"
		}},
		{name: "scale_mismatch", service: "web", reasons: []string{"scale_mismatch"}, mutate: func(t *testing.T, c *composeV2) {
			c.project()["web"].(map[string]any)["scale"] = 2
		}},
		{name: "scale_mismatch_replicas", service: "web", reasons: []string{"scale_mismatch"}, mutate: func(t *testing.T, c *composeV2) {
			c.project()["web"].(map[string]any)["deploy"] = map[string]any{"replicas": 3}
		}},
		{name: "target_not_running", service: "web", reasons: []string{"target_not_running"}, mutate: func(t *testing.T, c *composeV2) {
			c.container(cuHex("1"))["State"] = map[string]any{"Status": "exited"}
		}},
		{name: "digest_pinned", service: "web", reasons: []string{"digest_pinned"}, mutate: func(t *testing.T, c *composeV2) {
			c.container(cuHex("1"))["Config"].(map[string]any)["Image"] = pinned
		}},
		{name: "ephemeral_port", service: "web", reasons: []string{"ephemeral_port"}, mutate: func(t *testing.T, c *composeV2) {
			c.project()["web"].(map[string]any)["ports"] = []any{map[string]any{"target": 80, "published": ""}}
		}},
		{name: "build_unsupported", service: "web", reasons: []string{"build_unsupported"}, mutate: func(t *testing.T, c *composeV2) {
			c.project()["web"].(map[string]any)["build"] = map[string]any{"context": "."}
		}},
		{name: "mixed_images", service: "web", reasons: []string{"mixed_images"}, mutate: func(t *testing.T, c *composeV2) {
			w2 := cuContainer(cuHex("2"), "site-web-2", "web", cuDigest("b"), "nginx:1.27", "hweb", c.dir)
			c.containers()[cuHex("2")] = w2
			c.project()["web"].(map[string]any)["scale"] = 2
		}},
		{name: "project_mismatch", unit: "project_mismatch", mutate: func(t *testing.T, c *composeV2) {
			lb := c.container(cuHex("3"))["Config"].(map[string]any)["Labels"].(map[string]any)
			lb["com.docker.compose.project.working_dir"] = "/elsewhere"
		}},
		{name: "unsupported_files", unit: "unsupported_files", mutate: func(t *testing.T, c *composeV2) {
			if err := os.Remove(filepath.Join(c.dir, "compose.yaml")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "dependency_unsupported", unit: "dependency_unsupported", mutate: func(t *testing.T, c *composeV2) {
			c.project()["web"].(map[string]any)["network_mode"] = "container:other"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newComposeV2(t)
			tc.mutate(t, c)
			r := c.preview(t, "")
			if r.code != 0 || r.doc["status"] != "ok" {
				t.Fatalf("%d %s", r.code, r.out)
			}
			u := r.unit(t, "site")
			if u["reason"] != tc.unit {
				t.Fatalf("unit reason %v, want %q: %s", u["reason"], tc.unit, r.out)
			}
			facts := tc.unit == "" || tc.unit == "override_drift"
			if hasFacts := u["source_digest"] != nil && u["source_digest"] != ""; hasFacts != facts {
				t.Fatalf("facts %v, want %v: %v", hasFacts, facts, u)
			}
			if !facts {
				for _, k := range []string{"targets", "services", "images", "working_dir_hash"} {
					if _, ok := u[k]; ok {
						t.Fatalf("%s reported for a unit without facts: %v", k, u)
					}
				}
				return
			}
			if tc.service != "" {
				if got := previewReasons(t, u, tc.service); !slices.Equal(got, tc.reasons) {
					t.Fatalf("%s reasons %v, want %v", tc.service, got, tc.reasons)
				}
			}
			// Complete identity facts of every container.
			for _, x := range u["targets"].([]any) {
				m := x.(map[string]any)
				if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(m["configuration_digest"].(string)) || m["image_id"] == "" {
					t.Fatalf("incomplete target %v", m)
				}
			}
		})
	}
}

// override_drift takes precedence over config_not_applied (Q27): with
// drift, the applied configuration is not judged, and no service reports
// config_not_applied.
func TestPreviewOverrideDriftPrecedesConfigNotApplied(t *testing.T) {
	c := newComposeV2(t)
	c.st["hashes"].(map[string]any)["web"] = "pending-edit"
	c.beforeRun = func(t *testing.T) {
		writeOverride(t, c, `{"services": {"web": {"image": "docker.io/library/nginx:1.27@`+cuDigest("c")+`"}}}`)
	}
	r := c.preview(t, "")
	u := r.unit(t, "site")
	if u["reason"] != "override_drift" || slices.Contains(previewReasons(t, u, "web"), "config_not_applied") {
		t.Fatalf("%s", r.out)
	}
	if r.has("docker compose") && slices.ContainsFunc(r.calls, func(k cuCall) bool {
		return slices.ContainsFunc(k.Argv, func(a string) bool { return strings.HasPrefix(a, "--hash=") })
	}) {
		t.Fatal("config --hash was called despite drift")
	}
}

// A service that follows the NOS override (label and entry equal the
// running reference) is no drift and no operator pin.
func TestPreviewFollowedOverrideIsAvailable(t *testing.T) {
	c := newComposeV2(t)
	ref := "docker.io/library/nginx:1.27@" + cuDigest("c")
	web := c.container(cuHex("1"))
	web["Config"].(map[string]any)["Image"] = ref
	web["Config"].(map[string]any)["Labels"].(map[string]any)["com.docker.compose.project.config_files"] =
		c.dir + "/compose.yaml," + c.st["override"].(string)
	c.beforeRun = func(t *testing.T) { writeOverride(t, c, `{"services": {"web": {"image": "`+ref+`"}}}`) }
	r := c.preview(t, "")
	u := r.unit(t, "site")
	if u["reason"] != "" || len(previewReasons(t, u, "web")) != 0 || u["config_files_hash"] != c.u.ConfigFilesHash {
		t.Fatalf("%s", r.out)
	}
}

// Image-level reasons: an image whose local digest cannot be listed is
// old_digest_unknown, and a tag the registry does not answer is
// tag_unresolved; neither drops the unit's facts.
func TestPreviewImageReasons(t *testing.T) {
	c := newComposeV2(t)
	c.st["images"].([]any)[0].(map[string]any)["RepoDigests"] = []any{}
	r := c.preview(t, "")
	img := previewImage(t, r.unit(t, "site"), cuDigest("d"))
	if img["reason"] != "old_digest_unknown" || len(img["resolved"].([]any)) != 0 {
		t.Fatalf("%v", img)
	}

	c = newComposeV2(t)
	r = c.preview(t, "1.28")
	img = previewImage(t, r.unit(t, "site"), cuDigest("d"))
	res := img["resolved"].([]any)
	if img["reason"] != "" || len(res) != 2 || res[1].(map[string]any)["tag"] != "1.28" ||
		res[1].(map[string]any)["reason"] != "tag_unresolved" || res[1].(map[string]any)["platform_digest"] != "" {
		t.Fatalf("%v", img)
	}
	if r.unit(t, "site")["reason"] != "" {
		t.Fatal("an unresolved tag made the unit unavailable")
	}
}

func previewImage(t *testing.T, u map[string]any, id string) map[string]any {
	t.Helper()
	for _, x := range u["images"].([]any) {
		if m := x.(map[string]any); m["image_id"] == id {
			return m
		}
	}
	t.Fatalf("no image %s in %v", id, u)
	return nil
}

// A requested target tag is resolved to its index and platform digests
// with the request of the update (HEAD of the tag, GET of the index).
func TestPreviewResolvesTargetTag(t *testing.T) {
	c := newComposeV2(t)
	reg := c.st["registry"].(map[string]any)
	base := "https://registry-1.docker.io/v2/library/nginx/manifests/"
	reg[base+"1.28"] = map[string]any{"status": 200, "headers": map[string]any{
		"Docker-Content-Digest": cuDigest("8"), "Content-Type": "application/vnd.oci.image.manifest.v1+json"}}
	r := c.preview(t, "1.28")
	res := previewImage(t, r.unit(t, "site"), cuDigest("d"))["resolved"].([]any)
	if len(res) != 2 || !jsonEqual(res[1], map[string]any{"tag": "1.28", "index_digest": "", "platform_digest": cuDigest("8"), "reason": ""}) {
		t.Fatalf("%v", res)
	}
}

// Over the container limit, the unit and every later unit are truncated,
// with no facts; nothing is reported half.
func TestPreviewTruncatesOverContainerLimit(t *testing.T) {
	c := newComposeV2(t)
	listed := map[string]any{}
	for i := range 201 {
		id := strings.Repeat("0", 61) + strings.Repeat("0", 3-len(itoa(i))) + itoa(i)
		listed[id] = "big"
	}
	c.st["listed_only"] = listed
	r := c.preview(t, "")
	for _, p := range []string{"big", "site"} {
		u := r.unit(t, p)
		if u["reason"] != "truncated" || u["source_digest"] != nil || u["targets"] != nil {
			t.Fatalf("%s: %v", p, u)
		}
	}
	if r.has("docker inspect") {
		t.Fatal("a truncated unit was inspected")
	}
}

// nTags is n distinct tags joined by commas.
func nTags(n int) string {
	tags := make([]string, n)
	for i := range tags {
		tags[i] = "t" + itoa(i)
	}
	return strings.Join(tags, ",")
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

// A standalone container is its own unit, with identity and image facts
// and no source digest.
func TestPreviewStandaloneUnit(t *testing.T) {
	c := newComposeV2(t)
	solo := cuContainer(cuHex("5"), "solo", "", cuDigest("d"), "nginx:1.27", "", c.dir)
	solo["Config"].(map[string]any)["Labels"] = map[string]any{}
	c.containers()[cuHex("5")] = solo
	r := c.preview(t, "")
	var u map[string]any
	for _, x := range r.doc["units"].([]any) {
		if m := x.(map[string]any); m["form"] == "standalone" {
			u = m
		}
	}
	if u == nil || u["container_id"] != cuHex("5") || u["reason"] != "" || u["source_digest"] != nil {
		t.Fatalf("%s", r.out)
	}
	tg := previewTarget(t, u, cuHex("5"))
	if tg["container_name"] != "solo" || tg["service"] != "" || len(tg["configuration_digest"].(string)) != 64 {
		t.Fatalf("%v", tg)
	}
}

// Host states that stop the whole preview: a salt that is not root-only,
// malformed parameters.
func TestPreviewRefusesUnsafeSaltAndParameters(t *testing.T) {
	c := newComposeV2(t)
	c.beforeRun = func(t *testing.T) {
		if err := os.Chmod(filepath.Join(c.state, "salt"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r := c.preview(t, "")
	if r.code == 0 || r.doc["status"] != "salt_unsafe" || len(r.doc["units"].([]any)) != 0 || len(r.calls) != 0 {
		t.Fatalf("%d %s", r.code, r.out)
	}
	for _, p := range []string{`{"target_tags":"a,a"}`, `{"target_tags":"-x"}`, `{"target_tags":1}`, `{}`,
		`{"target_tags":"","x":""}`, `{"target_tags":"","target_tags":""}`} {
		c := newComposeV2(t)
		c.rawParams, c.params = true, []byte(p)
		r := c.preview(t, "")
		if r.code == 0 || r.doc["status"] != "params_invalid" || len(r.calls) != 0 {
			t.Fatalf("%s: %d %s", p, r.code, r.out)
		}
	}
}

// A failing Compose call that prints a planted env value on both streams
// keeps it on the host (R4); the unit reports a reason, not the output.
func TestPreviewComposeFailureLogHoldsNoEnvValue(t *testing.T) {
	c := newComposeV2(t)
	c.st["fail_config"] = 1 // every `compose config` prints the planted value and fails
	r := c.preview(t, "")   // preview fails the test if the value leaves the host
	if r.unit(t, "site")["reason"] != "unsupported_files" {
		t.Fatalf("%s", r.out)
	}
	if bytes.Contains(r.out, []byte(c.dir)) {
		t.Fatal("a host path left the host")
	}
}
