// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// The tests of docker.compose_rollback 1.0.0 run the shipped script against
// the fake host of the 2.0.0 tests, in the state a passed update left: web
// recreated as cuHex("9") on the pulled image under the NOS override entry,
// the prior image retained as nos-retained:<update>-0. The binding is the
// rollback of that update as the executor checks it against its row.

const crUpdateExecution = "00000000-0000-4000-8000-0000000000aa"

// crNewRef is the reference the update's override entry gave web.
var crNewRef = "docker.io/library/nginx:1.27@" + cuDigest("c")

// crRetainedRef is the update's retained_reference (repository:old_tag@
// first old digest).
var crRetainedRef = "docker.io/library/nginx:1.27@" + cuDigest("a")

// newComposeRollback is the fake host after the update and the rollback
// binding that matches it.
func newComposeRollback(t *testing.T) *composeV2 {
	t.Helper()
	c := newComposeV2(t)
	c.actionID = "docker.compose_rollback"
	override := filepath.Join(c.state, "overrides", "site.yaml")
	web := cuContainer(cuHex("9"), "site-web-1", "web", cuDigest("f"), crNewRef, "hweb2", c.dir)
	web["Config"].(map[string]any)["Labels"].(map[string]any)["com.docker.compose.project.config_files"] = c.dir + "/compose.yaml," + override
	delete(c.containers(), cuHex("1"))
	c.containers()[cuHex("9")] = web
	c.st["images"] = []any{
		map[string]any{"Id": cuDigest("d"), "RepoTags": []any{"nginx:1.27", "nos-retained:" + crUpdateExecution + "-0"},
			"RepoDigests": []any{"nginx@" + cuDigest("a")}, "Os": "linux", "Architecture": "amd64"},
		map[string]any{"Id": cuDigest("f"), "RepoDigests": []any{"nginx@" + cuDigest("c")}, "Os": "linux", "Architecture": "amd64"},
	}
	back := cuContainer(cuHex("8"), "site-web-1", "web", cuDigest("d"), "", "hweb3", c.dir)
	back["State"] = map[string]any{"Status": "running", "StartedAt": "2026-11-08T03:00:00Z", "Health": map[string]any{"Status": "healthy"}}
	c.st["recreate"] = map[string]any{"web": back}
	c.st["hashes"] = map[string]any{"web": "hweb2", "db": "hdb"}
	c.beforeRun = func(t *testing.T) {
		t.Helper()
		writeOverride(t, c, overrideBody(t, map[string]string{"web": crNewRef}))
	}
	db := c.container(cuHex("3"))
	c.u = canonical.BatchContainerUpdate{
		Kind: canonical.ContainerUpdateKindRollback, Form: canonical.ContainerUpdateFormCompose,
		Images: []canonical.ContainerUpdateImage{{Service: "web", Repository: "docker.io/library/nginx", Platform: "linux/amd64",
			OldTag: "1.27", NewTag: "1.27", OldDigests: []string{cuDigest("c")},
			Rollback: &canonical.ContainerRollbackImage{PriorImageID: cuDigest("d"), RetainedTag: crUpdateExecution + "-0",
				RetainedReference: crRetainedRef}}},
		Targets: []canonical.ContainerUpdateTarget{{Service: "web", ContainerID: cuHex("9"), ContainerName: "site-web-1",
			ImageID: cuDigest("f"), RunningReference: crNewRef, ConfigurationDigest: c.configDigest(t, web)}},
		Dependencies: []canonical.ContainerUpdateDependency{{Service: "db", Relation: canonical.ContainerDependencyRequires,
			Containers: []canonical.ContainerDependencyMember{{ContainerID: cuHex("3"), ContainerName: "site-db-1",
				ConfigurationDigest: c.configDigest(t, db)}}}},
		SourceDigest: c.u.SourceDigest, Project: "site", WorkingDirHash: c.u.WorkingDirHash, ConfigFilesHash: c.u.ConfigFilesHash,
		RollbackOf: crUpdateExecution, RecoveryPlanDigest: cuHex("5"),
	}
	return c
}

// overrideBody is the NOS override with entries, as the update script
// writes it.
func overrideBody(t *testing.T, entries map[string]string) string {
	t.Helper()
	services := map[string]any{}
	for k, v := range entries {
		services[k] = map[string]any{"image": v}
	}
	b, err := json.Marshal(map[string]any{"services": services})
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

// The catalog's docker.compose_rollback is 1.0.0: durable, reconcile-first,
// MEDIUM, with the fixed 30-minute timeout and no string parameters (its
// only input is the rendered rollback binding), and its own result format.
func TestComposeRollbackCatalogEntry(t *testing.T) {
	a, ok := Lookup("docker.compose_rollback")
	if !ok || a.Version != "1.0.0" || !a.Durable || a.ReadOnly || a.Retry != RetryReconcileFirst ||
		a.Risk != pb.RiskClass_RISK_CLASS_MEDIUM || a.Timeout.Minutes() != 30 || len(a.Params) != 0 || len(a.Secrets) != 0 {
		t.Fatalf("%+v", a)
	}
	s := string(a.Script)
	for _, want := range []string{"docker.compose_rollback 1.0.0", `FORMAT = "compose-rollback-v1"`, "python3 -I", `"container_update"`} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	// Nothing is resolved or pulled, and no registry is contacted.
	for _, banned := range []string{`"pull"`, "curl", "compose pull", `"login"`, `"rmi"`, `"prune"`, `"down"`} {
		if strings.Contains(s, banned) {
			t.Errorf("script contains %q", banned)
		}
	}
	n := 0
	for _, b := range Builtin {
		if b.ID == "docker.compose_rollback" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d docker.compose_rollback entries", n)
	}
}

// A rollback inside the bound state runs phases precheck, retain, recreate
// and after-snapshot: it recreates exactly the bound earlier definition.
// The override entry of each bound service becomes the bound retained
// reference, up recreates only the bound services from the operator files
// plus the override, and nothing is pulled, tagged or resolved.
func TestComposeRollbackRecreatesBoundDefinition(t *testing.T) {
	c := newComposeRollback(t)
	r := c.exec(t)
	if r.code != 0 || r.doc["phase"] != "after_snapshot" || r.doc["reason"] != "" || r.doc["up_exit"] != float64(0) ||
		r.doc["format"] != "compose-rollback-v1" || r.doc["project"] != "site" {
		t.Fatalf("%d %s", r.code, r.out)
	}
	if _, ok := r.doc["pulled"]; ok {
		t.Fatalf("a rollback reports pulled images: %s", r.out)
	}
	if _, ok := r.doc["retained"]; ok {
		t.Fatalf("a rollback reports retained images: %s", r.out)
	}
	base := r.doc["baseline"].([]any)
	if len(base) != 2 || base[0].(map[string]any)["id"] != cuHex("9") || base[1].(map[string]any)["id"] != cuHex("3") {
		t.Fatalf("baseline %v", base)
	}
	var ids []string
	for _, e := range r.doc["after"].([]any) {
		ids = append(ids, e.(map[string]any)["id"].(string))
		if e.(map[string]any)["id"] == cuHex("8") && (e.(map[string]any)["running_reference"] != crRetainedRef || e.(map[string]any)["image_id"] != cuDigest("d")) {
			t.Fatalf("rolled back web %v", e)
		}
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{cuHex("3"), cuHex("8")}) {
		t.Fatalf("after %v", ids)
	}
	ov, ok := c.override(t)
	want := map[string]any{"services": map[string]any{"web": map[string]any{"image": crRetainedRef}}}
	if !ok || !jsonEqual(ov, want) {
		t.Fatalf("override %v", ov)
	}
	if r.has("docker pull") || r.has("docker tag") || slices.ContainsFunc(r.calls, func(k cuCall) bool { return k.Tool == "curl" }) {
		t.Fatalf("a rollback pulled, tagged or resolved: %v", r.calls)
	}
	ovPath := filepath.Join(c.state, "overrides", "site.yaml")
	ups := 0
	for _, k := range r.calls {
		if !slices.Contains(k.Argv, "up") {
			continue
		}
		ups++
		wantArgv := []string{"compose", "-p", "site", "--project-directory", c.dir, "-f", c.dir + "/compose.yaml", "-f", ovPath,
			"up", "-d", "--no-deps", "--no-build", "--pull", "never", "web"}
		if !slices.Equal(k.Argv, wantArgv) {
			t.Fatalf("up %v", k.Argv)
		}
	}
	if ups != 1 {
		t.Fatalf("%d up calls", ups)
	}
	// The retained image is checked before the recreate.
	var tagCheck, up = -1, -1
	for i, k := range r.calls {
		if slices.Equal(k.Argv, []string{"image", "inspect", "--", "nos-retained:" + crUpdateExecution + "-0"}) && tagCheck < 0 {
			tagCheck = i
		}
		if slices.Contains(k.Argv, "up") {
			up = i
		}
	}
	if tagCheck < 0 || tagCheck > up {
		t.Fatalf("retained image check at %d, up at %d", tagCheck, up)
	}
}

// Every refusal before the recreate exits 10 with a typed reason, changes
// nothing (no up, the override as it was) and pulls nothing.
func TestComposeRollbackStopsBeforeAnyChange(t *testing.T) {
	cases := []struct {
		name, phase, reason string
		mut                 func(t *testing.T, c *composeV2)
	}{
		{"retained image gone", "retain", "retained_image_missing", func(_ *testing.T, c *composeV2) {
			im := c.st["images"].([]any)[0].(map[string]any)
			im["RepoTags"] = []any{"nginx:1.27"}
		}},
		{"retained tag moved to another image", "retain", "retained_image_missing", func(_ *testing.T, c *composeV2) {
			c.st["images"].([]any)[0].(map[string]any)["RepoTags"] = []any{"nginx:1.27"}
			c.st["images"].([]any)[1].(map[string]any)["RepoTags"] = []any{"nos-retained:" + crUpdateExecution + "-0"}
		}},
		{"retained image no longer lists the retained digest", "retain", "retained_image_missing", func(_ *testing.T, c *composeV2) {
			c.st["images"].([]any)[0].(map[string]any)["RepoDigests"] = []any{"nginx@" + cuDigest("b")}
		}},
		{"source changed", "precheck", "source_changed", func(_ *testing.T, c *composeV2) {
			c.st["source_config"] = "services:\n  web:\n    image: nginx:1.28\n"
		}},
		{"configuration changed", "precheck", "configuration_changed", func(_ *testing.T, c *composeV2) {
			c.container(cuHex("9"))["HostConfig"] = map[string]any{"RestartPolicy": map[string]any{"Name": "no"}}
		}},
		{"running reference differs from the recorded one", "precheck", "reference_mismatch", func(t *testing.T, c *composeV2) {
			c.container(cuHex("9"))["Config"].(map[string]any)["Image"] = "nginx:1.27"
			c.u.Targets[0].ConfigurationDigest = c.configDigest(t, c.container(cuHex("9")))
		}},
		{"target gone", "precheck", "target_changed", func(_ *testing.T, c *composeV2) {
			delete(c.containers(), cuHex("9"))
		}},
		{"image of the target differs", "precheck", "target_changed", func(_ *testing.T, c *composeV2) {
			c.container(cuHex("9"))["Image"] = cuDigest("e")
		}},
		{"extra container in a bound service", "precheck", "target_changed", func(t *testing.T, c *composeV2) {
			extra := cuContainer(cuHex("7"), "site-web-2", "web", cuDigest("f"), crNewRef, "hweb2", c.dir)
			c.containers()[cuHex("7")] = extra
		}},
		{"project moved", "precheck", "project_mismatch", func(_ *testing.T, c *composeV2) {
			c.u.WorkingDirHash = cuHex("0")
		}},
		{"dependency recreated", "precheck", "dependency_changed", func(_ *testing.T, c *composeV2) {
			c.container(cuHex("3"))["HostConfig"] = map[string]any{"Privileged": true}
		}},
		{"dependency set changed", "precheck", "dependency_set_changed", func(_ *testing.T, c *composeV2) {
			c.project()["web"].(map[string]any)["depends_on"] = map[string]any{}
		}},
		{"no salt", "precheck", "prepare_required", func(_ *testing.T, c *composeV2) { c.noSalt = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newComposeRollback(t)
			tc.mut(t, c)
			r := c.exec(t)
			if r.code != 10 || r.doc["phase"] != tc.phase || r.doc["reason"] != tc.reason || r.doc["format"] != "compose-rollback-v1" {
				t.Fatalf("%d %s", r.code, r.out)
			}
			if r.mutated() || slices.ContainsFunc(r.calls, func(k cuCall) bool { return k.Tool == "curl" }) {
				t.Fatalf("a refused rollback changed or contacted something: %v", r.calls)
			}
			if !c.noSalt {
				ov, _ := c.override(t)
				if !jsonEqual(ov, map[string]any{"services": map[string]any{"web": map[string]any{"image": crNewRef}}}) {
					t.Fatalf("override changed: %v", ov)
				}
			}
		})
	}
}

// The script consumes only a rollback binding: an update binding, a missing
// rollback block or rollback_of, a retained tag that is not the recorded
// update's tag of that entry, a retained reference of another repository,
// pull digests, or an unknown key are refused before anything is read from
// the host.
func TestComposeRollbackRefusesForeignBindings(t *testing.T) {
	cases := map[string]func(c *composeV2){
		"update binding": func(c *composeV2) {
			c.u.Kind = canonical.ContainerUpdateKindUpdate
		},
		"no rollback block": func(c *composeV2) { c.u.Images[0].Rollback = nil },
		"no rollback_of":    func(c *composeV2) { c.u.RollbackOf = "" },
		"no recovery plan":  func(c *composeV2) { c.u.RecoveryPlanDigest = "" },
		"retained tag of another entry": func(c *composeV2) {
			c.u.Images[0].Rollback.RetainedTag = crUpdateExecution + "-1"
		},
		"retained tag of another execution": func(c *composeV2) {
			c.u.Images[0].Rollback.RetainedTag = "00000000-0000-4000-8000-0000000000bb-0"
		},
		"retained tag with a repository": func(c *composeV2) {
			c.u.Images[0].Rollback.RetainedTag = "nos-retained:" + crUpdateExecution + "-0"
		},
		"retained reference of another repository": func(c *composeV2) {
			c.u.Images[0].Rollback.RetainedReference = "docker.io/library/httpd:2@" + cuDigest("a")
		},
		"retained reference without digest": func(c *composeV2) {
			c.u.Images[0].Rollback.RetainedReference = "docker.io/library/nginx:1.27"
		},
		"pull digest on a rollback": func(c *composeV2) {
			c.u.Images[0].NewPlatformDigest = cuDigest("c")
		},
		"old image on a rollback": func(c *composeV2) {
			c.u.Images[0].OldImageID = cuDigest("d")
		},
		"registry": func(c *composeV2) {
			c.u.Registry = &canonical.ContainerUpdateRegistry{RegistryID: "reg", RecordDigest: cuHex("8"), CredentialID: "c", CredentialVersion: 1}
		},
		"no target at all": func(c *composeV2) { c.u.Targets = nil },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			c := newComposeRollback(t)
			mut(c)
			r := c.exec(t)
			if r.code != 10 || r.doc["phase"] != "precheck" || r.doc["reason"] != "binding_invalid" {
				t.Fatalf("%d %s", r.code, r.out)
			}
			if len(r.calls) != 0 {
				t.Fatalf("the host was read for a foreign binding: %v", r.calls)
			}
		})
	}
	c := newComposeRollback(t)
	c.rawParams = true
	params, _, err := canonical.ContainerUpdateParameters(c.u)
	if err != nil {
		t.Fatal(err)
	}
	c.params = []byte(strings.Replace(string(params), `"kind":"rollback"`, `"kind":"rollback","extra":1`, 1))
	if r := c.exec(t); r.code != 10 || r.doc["reason"] != "binding_invalid" {
		t.Fatalf("unknown key: %d %s", r.code, r.out)
	}
}

// A rollback of a partial update: a target that is not running and a
// replica the update never reached (its old reference, no override label,
// while the override entry already names the new digest) are bound by
// their recorded references; phase 1 has no running, override-drift or
// applied-configuration check for them, and the rollback recreates them.
func TestComposeRollbackOfPartialWithUnreachedReplica(t *testing.T) {
	c := newComposeRollback(t)
	c.container(cuHex("9"))["State"] = map[string]any{"Status": "exited", "StartedAt": "2026-11-08T00:00:00Z"}
	old := cuContainer(cuHex("6"), "site-web-2", "web", cuDigest("d"), "nginx:1.27", "hweb", c.dir)
	old["Config"].(map[string]any)["Labels"].(map[string]any)["com.docker.compose.container-number"] = "2"
	c.containers()[cuHex("6")] = old
	c.u.Targets[0].ConfigurationDigest = c.configDigest(t, c.container(cuHex("9")))
	c.u.Targets = append(c.u.Targets, canonical.ContainerUpdateTarget{Service: "web", ContainerID: cuHex("6"), ContainerName: "site-web-2",
		ImageID: cuDigest("d"), RunningReference: "nginx:1.27", ConfigurationDigest: c.configDigest(t, old)})
	slices.SortFunc(c.u.Targets, func(a, b canonical.ContainerUpdateTarget) int { return strings.Compare(a.ContainerID, b.ContainerID) })
	r := c.exec(t)
	if r.code != 0 || r.doc["phase"] != "after_snapshot" || r.doc["reason"] != "" {
		t.Fatalf("%d %s", r.code, r.out)
	}
	if !r.has("docker compose") {
		t.Fatal("no compose call")
	}
}

// An image entry without a target (every container of the service is
// missing) is still restored: the override names its retained reference
// and up names the service. A container of that service on the host is a
// change since the row and stops the rollback.
func TestComposeRollbackRestoresAllMissingService(t *testing.T) {
	c := newComposeRollback(t)
	c.project()["api"] = map[string]any{"image": "ghcr.io/acme/api:2"}
	c.st["source_config"] = "services:\n  web:\n    image: nginx:1.27\n"
	c.st["images"] = append(c.st["images"].([]any), map[string]any{"Id": cuDigest("6"),
		"RepoTags": []any{"nos-retained:" + crUpdateExecution + "-0"}, "RepoDigests": []any{"ghcr.io/acme/api@" + cuDigest("8")},
		"Os": "linux", "Architecture": "amd64"})
	// Entry 0 is api, entry 1 is web: the retained tags follow the index.
	c.st["images"].([]any)[0].(map[string]any)["RepoTags"] = []any{"nginx:1.27", "nos-retained:" + crUpdateExecution + "-1"}
	apiBack := cuContainer(cuHex("5"), "site-api-1", "api", cuDigest("6"), "", "hapi", c.dir)
	c.st["recreate"].(map[string]any)["api"] = apiBack
	c.u.Images[0].Rollback.RetainedTag = crUpdateExecution + "-1"
	c.u.Images = append([]canonical.ContainerUpdateImage{{Service: "api", Repository: "ghcr.io/acme/api", Platform: "linux/amd64",
		OldTag: "2", NewTag: "2", OldDigests: []string{cuDigest("7")},
		Rollback: &canonical.ContainerRollbackImage{PriorImageID: cuDigest("6"), RetainedTag: crUpdateExecution + "-0",
			RetainedReference: "ghcr.io/acme/api:2@" + cuDigest("8")}}}, c.u.Images...)
	c.beforeRun = func(t *testing.T) {
		t.Helper()
		writeOverride(t, c, overrideBody(t, map[string]string{"web": crNewRef, "api": "ghcr.io/acme/api:2@" + cuDigest("7")}))
	}
	r := c.exec(t)
	if r.code != 0 || r.doc["phase"] != "after_snapshot" || r.doc["reason"] != "" {
		t.Fatalf("%d %s", r.code, r.out)
	}
	ov, _ := c.override(t)
	want := map[string]any{"services": map[string]any{"web": map[string]any{"image": crRetainedRef},
		"api": map[string]any{"image": "ghcr.io/acme/api:2@" + cuDigest("8")}}}
	if !jsonEqual(ov, want) {
		t.Fatalf("override %v", ov)
	}
	if !slices.ContainsFunc(r.calls, func(k cuCall) bool {
		n := len(k.Argv)
		return n > 2 && slices.Contains(k.Argv, "up") && k.Argv[n-2] == "api" && k.Argv[n-1] == "web"
	}) {
		t.Fatalf("up does not name every bound service: %v", r.calls)
	}

	// The same binding while api has a container again is refused.
	c = newComposeRollback(t)
	c.project()["api"] = map[string]any{"image": "ghcr.io/acme/api:2"}
	c.u.Images = append([]canonical.ContainerUpdateImage{{Service: "api", Repository: "ghcr.io/acme/api", Platform: "linux/amd64",
		OldTag: "2", NewTag: "2", OldDigests: []string{cuDigest("7")},
		Rollback: &canonical.ContainerRollbackImage{PriorImageID: cuDigest("6"), RetainedTag: crUpdateExecution + "-0",
			RetainedReference: "ghcr.io/acme/api:2@" + cuDigest("8")}}}, c.u.Images...)
	c.u.Images[1].Rollback.RetainedTag = crUpdateExecution + "-1"
	c.containers()[cuHex("5")] = cuContainer(cuHex("5"), "site-api-1", "api", cuDigest("6"), "ghcr.io/acme/api:2", "hapi", c.dir)
	if r := c.exec(t); r.code != 10 || r.doc["reason"] != "target_changed" || r.mutated() {
		t.Fatalf("present container of an all-missing entry: %d %s", r.code, r.out)
	}
}

// A failed up after the override was written exits 1, still with the
// after-snapshot (phase after_snapshot) and up's exit code.
func TestComposeRollbackFailedUpKeepsAfterSnapshot(t *testing.T) {
	c := newComposeRollback(t)
	c.st["fail_up"] = 17
	r := c.exec(t)
	if r.code != 1 || r.doc["phase"] != "after_snapshot" || r.doc["reason"] != "up_failed" || r.doc["up_exit"] != float64(17) {
		t.Fatalf("%d %s", r.code, r.out)
	}
	if _, ok := r.doc["after"]; !ok {
		t.Fatalf("no after-snapshot: %s", r.out)
	}
}
