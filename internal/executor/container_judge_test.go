// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
)

// newIncarnation derives the container ID a recreate gives id.
func newIncarnation(id string) string {
	d := sha256.Sum256([]byte("recreated:" + id))
	return hex.EncodeToString(d[:])
}

// pulledImageID is the image ID the fake host reports for the approved
// platform digest.
var pulledImageID = digestOf("e")

// passingComposeResult is a compose-update-v2 result of a clean update of
// u: every target recreated as the same replica, running and healthy, with
// the same ports, mounts and networks, the pulled image and the approved
// reference; every dependency untouched.
func passingComposeResult(u canonical.BatchContainerUpdate) composeUpdateResult {
	zero := 0
	r := composeUpdateResult{Format: composeUpdateFormat, Phase: phaseAfterSnapshot, Project: u.Project, UpExit: &zero,
		Baseline: []snapshotEntry{}, After: []snapshotEntry{}, Pulled: []resultImage{}, Retained: []resultRetained{}}
	replica := map[string]int{}
	entry := func(id, name, svc, health string) snapshotEntry {
		replica[svc]++
		return snapshotEntry{ID: id, Name: name, Service: svc, Replica: string(rune('0' + replica[svc])), State: "running",
			StartedAt: "2026-11-08T01:00:00Z", Health: health, Ports: []string{"80/tcp->0.0.0.0:8080"},
			Mounts:   []snapshotMount{{Type: "volume", Source: "/var/lib/docker/volumes/site_data/_data", Destination: "/data", Mode: "z", RW: true}},
			Networks: []string{"site_default"}}
	}
	images := map[string]canonical.ContainerUpdateImage{}
	for i, img := range u.Images {
		images[img.Service] = img
		r.Pulled = append(r.Pulled, resultImage{Service: img.Service, ImageID: pulledImageID})
		r.Retained = append(r.Retained, resultRetained{Service: img.Service, Tag: retainedTag("00000000-0000-4000-8000-000000000001", i)})
	}
	for _, t := range u.Targets {
		b := entry(t.ContainerID, t.ContainerName, t.Service, "healthy")
		b.ImageID, b.RunningReference, b.ConfigurationDigest = t.ImageID, t.RunningReference, t.ConfigurationDigest
		a := b
		a.ID, a.StartedAt = newIncarnation(t.ContainerID), "2026-11-08T02:00:00Z"
		a.ImageID, a.RunningReference, a.ConfigurationDigest = pulledImageID, expectedReference(images[t.Service]), hexOf("9")
		a.Ports, a.Mounts, a.Networks = append([]string(nil), b.Ports...), append([]snapshotMount(nil), b.Mounts...), append([]string(nil), b.Networks...)
		r.Baseline, r.After = append(r.Baseline, b), append(r.After, a)
	}
	for _, d := range u.Dependencies {
		for _, c := range d.Containers {
			b := entry(c.ContainerID, c.ContainerName, d.Service, "none")
			b.ImageID, b.RunningReference, b.ConfigurationDigest = digestOf("f"), "postgres:16", c.ConfigurationDigest
			r.Baseline, r.After = append(r.Baseline, b), append(r.After, b)
		}
	}
	return r
}

func (e *containerEnv) writeResult(t *testing.T, r composeUpdateResult) {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.dir, "result.json"), append(b, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustResultJSON(t *testing.T, r composeUpdateResult) []byte {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// twoServiceUpdate binds two recreated services (web with two replicas,
// api with one) and the db dependency.
func twoServiceUpdate() canonical.BatchContainerUpdate {
	u := testComposeUpdate()
	u.Images = append([]canonical.ContainerUpdateImage{{Service: "api", Repository: "ghcr.io/acme/api", Platform: "linux/amd64",
		OldTag: "2", NewTag: "2", OldDigests: []string{digestOf("8")}, NewIndexDigest: digestOf("b"),
		NewPlatformDigest: digestOf("7"), OldImageID: digestOf("6")}}, u.Images...)
	u.Targets = append([]canonical.ContainerUpdateTarget{{Service: "api", ContainerID: hexOf("a"), ContainerName: "site-api-1",
		ImageID: digestOf("6"), RunningReference: "ghcr.io/acme/api:2", ConfigurationDigest: hexOf("b")}}, u.Targets...)
	u.Targets = append(u.Targets, canonical.ContainerUpdateTarget{Service: "web", ContainerID: hexOf("c"), ContainerName: "site-web-2",
		ImageID: digestOf("d"), RunningReference: "nginx:1.27", ConfigurationDigest: hexOf("2")})
	return u
}

func TestJudgeComposeUpdatePostchecks(t *testing.T) {
	u := twoServiceUpdate()
	webAfter := func(r *composeUpdateResult, replica string) *snapshotEntry {
		for i := range r.After {
			if r.After[i].Service == "web" && r.After[i].Replica == replica {
				return &r.After[i]
			}
		}
		t.Fatalf("no web replica %s", replica)
		return nil
	}
	dep := func(r *composeUpdateResult) *snapshotEntry {
		for i := range r.After {
			if r.After[i].Service == "db" {
				return &r.After[i]
			}
		}
		t.Fatal("no db")
		return nil
	}
	cases := []struct {
		name    string
		binding func(*canonical.BatchContainerUpdate)
		mutate  func(*composeUpdateResult)
		finding string
	}{
		{"clean update, replicas matched by number after their IDs changed", nil, func(*composeUpdateResult) {}, ""},
		{"lost mount", nil, func(r *composeUpdateResult) { webAfter(r, "1").Mounts = nil }, "mounts changed"},
		{"changed mount mode", nil, func(r *composeUpdateResult) { webAfter(r, "1").Mounts[0].RW = false }, "mounts changed"},
		{"changed network", nil, func(r *composeUpdateResult) { webAfter(r, "2").Networks = []string{"other"} }, "networks changed"},
		{"lost published port", nil, func(r *composeUpdateResult) { webAfter(r, "1").Ports = []string{} }, "published ports changed"},
		{"changed host port", nil, func(r *composeUpdateResult) { webAfter(r, "1").Ports = []string{"80/tcp->0.0.0.0:8081"} }, "published ports changed"},
		{"replica fewer", nil, func(r *composeUpdateResult) {
			for i := range r.After {
				if r.After[i].Service == "web" && r.After[i].Replica == "2" {
					r.After = append(r.After[:i], r.After[i+1:]...)
					return
				}
			}
		}, "web replica 2 is missing"},
		{"replica more", nil, func(r *composeUpdateResult) {
			x := *webAfter(r, "2")
			x.ID, x.Replica, x.Name = hexOf("5"), "3", "site-web-3"
			r.After = append(r.After, x)
		}, "was not there before"},
		{"not running", nil, func(r *composeUpdateResult) { webAfter(r, "1").State = "restarting" }, "not running"},
		{"wrong digest on one of several services", nil, func(r *composeUpdateResult) {
			webAfter(r, "2").ImageID = digestOf("0")
		}, "does not run the image pulled"},
		{"pulled image missing for a service", nil, func(r *composeUpdateResult) { r.Pulled = r.Pulled[:1] }, "no verified pulled image"},
		{"approved reference not running", nil, func(r *composeUpdateResult) {
			webAfter(r, "1").RunningReference = "docker.io/library/nginx:1.27"
		}, "approved reference"},
		{"starting past the wait", nil, func(r *composeUpdateResult) { webAfter(r, "1").Health = "starting" }, "health healthy before, starting after"},
		{"health regression", nil, func(r *composeUpdateResult) { webAfter(r, "2").Health = "unhealthy" }, "health healthy before, unhealthy after"},
		{"no health check stays none", nil, func(r *composeUpdateResult) {
			for i := range r.Baseline {
				if r.Baseline[i].Service == "api" {
					r.Baseline[i].Health = "none"
				}
			}
		}, "health none before, healthy after"},
		{"dependency recreated", nil, func(r *composeUpdateResult) { dep(r).ID = hexOf("0") }, "was recreated or removed"},
		{"dependency stopped", nil, func(r *composeUpdateResult) { dep(r).State = "exited" }, "was running and is exited"},
		{"dependency configuration changed", nil, func(r *composeUpdateResult) { dep(r).ConfigurationDigest = hexOf("0") }, "changed its configuration"},
		{"dependency restarted without restart_on_update", nil, func(r *composeUpdateResult) { dep(r).StartedAt = "2026-11-08T03:00:00Z" }, "restarted without restart_on_update"},
		{"dependency restarted with restart_on_update", func(u *canonical.BatchContainerUpdate) { u.Dependencies[0].RestartOnUpdate = true },
			func(r *composeUpdateResult) { dep(r).StartedAt = "2026-11-08T03:00:00Z" }, ""},
		{"missing baseline", nil, func(r *composeUpdateResult) { r.Baseline = nil }, "no baseline"},
		{"missing after-snapshot", nil, func(r *composeUpdateResult) { r.After = nil }, "no after-snapshot"},
		{"oversize entry", nil, func(r *composeUpdateResult) { *webAfter(r, "1") = snapshotEntry{ID: hexOf("e"), Oversize: true} }, "too large"},
		{"baseline holds an unbound container", nil, func(r *composeUpdateResult) { r.Baseline[0].ID = hexOf("0") }, "neither a bound target"},
		{"unbound container in a dependency service", nil, func(r *composeUpdateResult) {
			x := *dep(r)
			x.ID, x.Replica = hexOf("0"), "2"
			r.After = append(r.After, x)
		}, "not bound"},
		{"container of an unrelated service", nil, func(r *composeUpdateResult) {
			x := *dep(r)
			x.ID, x.Service = hexOf("0"), "cache"
			r.After = append(r.After, x)
		}, "belongs to no frozen service"},
		{"up failed", nil, func(r *composeUpdateResult) { one := 1; r.UpExit, r.Reason = &one, "up_failed" }, "did not succeed"},
		{"up timeout", nil, func(r *composeUpdateResult) { x := 124; r.UpExit, r.Reason = &x, "up_timeout" }, "up_timeout"},
		{"snapshot failed reason", nil, func(r *composeUpdateResult) { r.Reason = "snapshot_failed" }, "snapshot_failed"},
		{"stopped before recreate", nil, func(r *composeUpdateResult) { r.Phase, r.Reason = phasePull, "pull_failed" }, "ended in phase pull"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bu := twoServiceUpdate()
			if tc.binding != nil {
				tc.binding(&bu)
			}
			r := passingComposeResult(bu)
			tc.mutate(&r)
			v := judgeComposeUpdate(bu, r)
			if tc.finding == "" {
				if !v.Passed || len(v.Findings) != 0 {
					t.Fatalf("clean case failed: %v", v.Findings)
				}
				return
			}
			if v.Passed || !strings.Contains(strings.Join(v.Findings, "|"), tc.finding) {
				t.Fatalf("passed=%v findings %v, want %q", v.Passed, v.Findings, tc.finding)
			}
		})
	}
	// The judge has no rule for kinds it does not know: a rollback binding
	// never passes this update postcheck.
	rb := u.Clone()
	rb.Kind = canonical.ContainerUpdateKindRollback
	if v := judgeComposeUpdate(rb, passingComposeResult(u)); v.Passed {
		t.Fatal("a rollback passed the update judge")
	}
}

func TestComposeResultParserRejectsHostileInput(t *testing.T) {
	good := mustResultJSON(t, passingComposeResult(testComposeUpdate()))
	if _, err := parseComposeUpdateResult(good); err != nil {
		t.Fatalf("good result refused: %v", err)
	}
	mut := func(f func(*composeUpdateResult)) []byte {
		r := passingComposeResult(testComposeUpdate())
		f(&r)
		return mustResultJSON(t, r)
	}
	cases := map[string][]byte{
		"empty":            nil,
		"oversize":         append(append([]byte(nil), good...), []byte(strings.Repeat(" ", maxJudgedResultBytes))...),
		"invalid utf-8":    []byte("{\"format\":\"compose-update-v2\",\"phase\":\"precheck\",\"reason\":\"\xff\"}"),
		"unknown field":    []byte(`{"format":"compose-update-v2","phase":"precheck","reason":"x","env":"SECRET=1"}`),
		"trailing doc":     append(append([]byte(nil), good...), []byte(`{}`)...),
		"other format":     []byte(`{"format":"compose-update-v1","phase":"precheck"}`),
		"unknown phase":    []byte(`{"format":"compose-update-v2","phase":"rm"}`),
		"free-text reason": []byte(`{"format":"compose-update-v2","phase":"precheck","reason":"Error: PASSWORD=hunter2"}`),
		"short id":         mut(func(r *composeUpdateResult) { r.After[0].ID = "abc" }),
		"bad image id":     mut(func(r *composeUpdateResult) { r.After[0].ImageID = "nginx" }),
		"bad state":        mut(func(r *composeUpdateResult) { r.After[0].State = "running; rm -rf /" }),
		"bad health":       mut(func(r *composeUpdateResult) { r.After[0].Health = "fine" }),
		"zero replica":     mut(func(r *composeUpdateResult) { r.After[0].Replica = "0" }),
		"unsafe reference": mut(func(r *composeUpdateResult) { r.After[0].RunningReference = "nginx" + string(rune(0x202e)) }),
		"control in port":  mut(func(r *composeUpdateResult) { r.After[0].Ports = []string{"80\n"} }),
		"too many ports": mut(func(r *composeUpdateResult) {
			r.After[0].Ports = make([]string, maxSnapshotPorts+1)
		}),
		"too many entries": mut(func(r *composeUpdateResult) {
			for len(r.After) <= maxSnapshotEntries {
				r.After = append(r.After, r.After[0])
			}
		}),
		"oversize entry with fields": mut(func(r *composeUpdateResult) { r.After[0].Oversize = true }),
		"bad pulled image":           mut(func(r *composeUpdateResult) { r.Pulled[0].ImageID = "x" }),
		"bad retained tag":           mut(func(r *composeUpdateResult) { r.Retained[0].Tag = "latest" }),
	}
	for name, b := range cases {
		if _, err := parseComposeUpdateResult(b); !errors.Is(err, errComposeResult) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}

func TestRecreationCompletionStates(t *testing.T) {
	u := testComposeUpdate()
	run := testDispatchRun(t, u)
	row, err := recreationIntent(run, "web-1", "SHA256:k")
	if err != nil {
		t.Fatal(err)
	}
	pass := mustResultJSON(t, passingComposeResult(u))
	failing := passingComposeResult(u)
	failing.After[0].Ports = nil
	partialUp := passingComposeResult(u)
	one := 1
	partialUp.UpExit, partialUp.Reason = &one, "up_failed"
	partialUp.After = partialUp.After[1:] // web replica gone, db still there
	noAfter := passingComposeResult(u)
	noAfter.After, noAfter.Phase = nil, phaseRecreate
	stopped := composeUpdateResult{Format: composeUpdateFormat, Phase: phaseResolve, Reason: "tag_moved", Baseline: passingComposeResult(u).Baseline}
	cases := []struct {
		name, class, state string
		result             []byte
		passed, baseline   bool
	}{
		{"clean", hostrun.ClassSuccess, "recreated", pass, true, true},
		{"verdict failed", hostrun.ClassSuccess, "partial", mustResultJSON(t, failing), false, true},
		{"passing snapshot, failed class", hostrun.ClassScriptFailed, "partial", pass, false, true},
		{"up failed, replica missing", hostrun.ClassScriptFailed, "partial", mustResultJSON(t, partialUp), false, true},
		{"no after-snapshot", hostrun.ClassScriptFailed, "uncertain", mustResultJSON(t, noAfter), false, true},
		{"stopped in resolve", hostrun.ClassPrecheckFailed, "not_recreated", mustResultJSON(t, stopped), false, true},
		{"exit 10 without a result", hostrun.ClassPrecheckFailed, "not_recreated", nil, false, false},
		{"unreadable result", hostrun.ClassSuccess, "uncertain", []byte(`{"format":"test"}`), false, false},
		{"unknown", classUnknown, "uncertain", pass, false, false},
		{"interrupted", hostrun.ClassScriptInterrupted, "uncertain", nil, false, false},
		{"timeout", hostrun.ClassExecutionTimeout, "uncertain", nil, false, false},
	}
	for _, tc := range cases {
		c := recreationCompletion(row, tc.class, tc.result)
		if c.State != tc.state || c.Verdict.Passed != tc.passed || (len(c.Baseline) > 0) != tc.baseline {
			t.Errorf("%s: state %s passed %v baseline %d findings %v", tc.name, c.State, c.Verdict.Passed, len(c.Baseline), c.Verdict.Findings)
		}
	}
	// A partly recreated project records its incarnations (R13): the
	// missing web replica as missing, the db as unchanged.
	c := recreationCompletion(row, hostrun.ClassScriptFailed, mustResultJSON(t, partialUp))
	status := map[string]string{}
	for _, x := range c.Containers {
		status[x.Service] = x.Status
	}
	if status["web"] != "missing" || status["db"] != "unchanged" {
		t.Fatalf("containers %+v", c.Containers)
	}
	c = recreationCompletion(row, hostrun.ClassSuccess, pass)
	for _, x := range c.Containers {
		if x.Service == "web" && (x.Status != "recreated" || x.IDAfter != newIncarnation(hexOf("1")) || x.ImageAfter != pulledImageID) {
			t.Fatalf("recreated web %+v", x)
		}
	}
	if c.Images[0].NewImageID != pulledImageID {
		t.Fatalf("images %+v", c.Images)
	}
}

func TestRecreationIntentKeepsPriorImageAndDefinition(t *testing.T) {
	u := twoServiceUpdate()
	u.Targets[0].RunningReference = "ghcr.io/acme/api:2@" + digestOf("8") // runs under the NOS override
	run := testDispatchRun(t, u)
	row, err := recreationIntent(run, "web-1", "SHA256:k")
	if err != nil {
		t.Fatal(err)
	}
	if row.State != "" || row.Kind != "update" || row.Unit != "site" || row.HostKey != "SHA256:k" || len(row.Images) != 2 {
		t.Fatalf("row %+v", row)
	}
	api, web := row.Images[0], row.Images[1]
	if api.PriorImageID != digestOf("6") || api.RetainedTag != "nos-retained:"+run.ExecutionID+"-0" ||
		api.RetainedReference != "ghcr.io/acme/api:2@"+digestOf("8") || web.RetainedTag != "nos-retained:"+run.ExecutionID+"-1" ||
		web.RetainedReference != "docker.io/library/nginx:1.27@"+digestOf("a") {
		t.Fatalf("images %+v", row.Images)
	}
	var def recreationDefinition
	if err := json.Unmarshal(row.Definition, &def); err != nil {
		t.Fatal(err)
	}
	if def.SourceDigest != u.SourceDigest || len(def.Services) != 2 || def.Services[0].PriorOverrideEntry != u.Targets[0].RunningReference ||
		def.Services[1].ReplicasBefore != 2 || def.Services[1].PriorOverrideEntry != "" || len(def.Dependencies) != 1 {
		t.Fatalf("definition %+v", def)
	}
	// The definition holds identities and digests only.
	for _, banned := range []string{"env", "Env", "password", "content"} {
		if strings.Contains(string(row.Definition), banned) {
			t.Fatalf("definition holds %q: %s", banned, row.Definition)
		}
	}
}

func TestContainerPostcheckHashIsPerMember(t *testing.T) {
	a, b := containerPostcheckHash("member-0"), containerPostcheckHash("member-1")
	if a == b || len(a) != 64 || a != containerPostcheckHash("member-0") {
		t.Fatalf("%s %s", a, b)
	}
}
