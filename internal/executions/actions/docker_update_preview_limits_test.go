// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The preview against a hostile or broken host (container update plan
// cu02, "preview limits"): every limit holds, the result stays parseable
// and below its bound, and no unit is reported half. The fake host is the
// one of the docker.compose_update 2.0.0 tests (newComposeV2).

// pvHeadKeys are the keys of a unit without facts.
var pvHeadKeys = []string{"container_id", "form", "project", "reason"}

// requireNoPartialUnits fails if a unit without facts carries any fact.
func requireNoPartialUnits(t *testing.T, r cuRun) {
	t.Helper()
	units, _ := r.doc["units"].([]any)
	for _, x := range units {
		u := x.(map[string]any)
		if u["reason"] == "" || u["reason"] == "override_drift" {
			continue
		}
		for k := range u {
			if !slices.Contains(pvHeadKeys, k) {
				t.Fatalf("unit with reason %v carries %s: %v", u["reason"], k, u)
			}
		}
	}
}

// standaloneUnit returns the result's unit of standalone container id.
func (r cuRun) standaloneUnit(t *testing.T, id string) map[string]any {
	t.Helper()
	for _, x := range r.doc["units"].([]any) {
		if m := x.(map[string]any); m["form"] == "standalone" && m["container_id"] == id {
			return m
		}
	}
	t.Fatalf("no standalone unit %s in %s", id, r.out)
	return nil
}

// addStandalone adds a standalone container id named name, running ref
// as image imageID, and that image with one repository digest.
func (c *composeV2) addStandalone(id, name, imageID, ref, repoDigest string) {
	ctr := cuContainer(id, name, "", imageID, ref, "", c.dir)
	ctr["Config"].(map[string]any)["Labels"] = map[string]any{}
	c.containers()[id] = ctr
	c.st["images"] = append(c.st["images"].([]any), map[string]any{"Id": imageID, "RepoDigests": []any{repoDigest},
		"Os": "linux", "Architecture": "amd64"})
}

// pvID is the n-th full container or image hex ID of a test.
func pvID(n int) string { return fmt.Sprintf("%064x", n+0x1000) }

// A host whose docker lacks the Compose plugin reports tooling_missing
// (Q18) for the whole preview, not unsupported_files per project; and a
// tool that disappears during the run (a call ending 127, command not
// found) keeps tooling_missing instead of truncating the rest.
func TestPreviewComposePluginMissingIsToolingMissing(t *testing.T) {
	for name, key := range map[string]string{"plugin missing": "no_compose", "plugin gone mid-run": "compose_exit"} {
		t.Run(name, func(t *testing.T) {
			c := newComposeV2(t)
			c.st[key] = 1
			if key == "compose_exit" {
				c.st[key] = 127
			}
			r := c.preview(t, "")
			if r.code == 0 || r.doc["status"] != "tooling_missing" || len(r.doc["units"].([]any)) != 0 {
				t.Fatalf("%d %s", r.code, r.out)
			}
		})
	}
}

// Well-formed but unexpected JSON for one unit (a non-scalar image ID
// among a service's containers, a links value that is not a list) marks
// that unit host_unreadable; the other units keep their facts and the
// preview is not an internal_error.
func TestPreviewUnexpectedJSONMarksOnlyThatUnit(t *testing.T) {
	cases := map[string]func(c *composeV2){
		"non-scalar image": func(c *composeV2) {
			w2 := cuContainer(cuHex("2"), "site-web-2", "web", cuDigest("b"), "nginx:1.27", "hweb", c.dir)
			w2["Image"] = map[string]any{"x": 1}
			c.containers()[cuHex("2")] = w2
			c.project()["web"].(map[string]any)["scale"] = 2
		},
		"links not a list": func(c *composeV2) {
			c.project()["web"].(map[string]any)["links"] = 5
		},
		"depends_on entry not a string": func(c *composeV2) {
			c.project()["web"].(map[string]any)["depends_on"] = []any{map[string]any{"db": 1}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := newComposeV2(t)
			c.addStandalone(cuHex("5"), "solo", cuDigest("d"), "nginx:1.27", "nginx@"+cuDigest("a"))
			mutate(c)
			r := c.preview(t, "")
			if r.code != 0 || r.doc["status"] != "ok" {
				t.Fatalf("%d %s", r.code, r.out)
			}
			if u := r.unit(t, "site"); u["reason"] != "host_unreadable" {
				t.Fatalf("site %v", u)
			}
			if u := r.standaloneUnit(t, cuHex("5")); u["reason"] != "" || u["targets"] == nil {
				t.Fatalf("the other unit lost its facts: %v", u)
			}
			requireNoPartialUnits(t, r)
		})
	}
}

// TestPreviewBoundsHostileHost: one case over each limit of the preview;
// the limit holds with the reason the plan names, and no unit is
// reported half.
func TestPreviewBoundsHostileHost(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, c *composeV2)
		check  func(t *testing.T, c *composeV2, r cuRun)
	}{
		{name: "MAX_PREVIEW_CONTAINERS", mutate: func(t *testing.T, c *composeV2) {
			listed := map[string]any{}
			for i := range 200 {
				listed[pvID(i)] = "big"
			}
			c.st["listed_only"] = listed
		}, check: func(t *testing.T, c *composeV2, r cuRun) {
			// big (200) fits; site's two more do not.
			if u := r.unit(t, "big"); u["reason"] != "host_unreadable" {
				t.Fatalf("big %v", u)
			}
			if u := r.unit(t, "site"); u["reason"] != "truncated" {
				t.Fatalf("site %v", u)
			}
		}},
		{name: "MAX_PREVIEW_PROJECTS", mutate: func(t *testing.T, c *composeV2) {
			listed := map[string]any{}
			for i := range 50 {
				listed[pvID(i)] = fmt.Sprintf("p%02d", i)
			}
			c.st["listed_only"] = listed
		}, check: func(t *testing.T, c *composeV2, r cuRun) {
			// p00..p49 are the first 50 projects; site is the 51st.
			for i := range 50 {
				if u := r.unit(t, fmt.Sprintf("p%02d", i)); u["reason"] != "host_unreadable" {
					t.Fatalf("p%02d %v", i, u)
				}
			}
			if u := r.unit(t, "site"); u["reason"] != "truncated" {
				t.Fatalf("site %v", u)
			}
			if r.has("docker inspect --type container -- " + cuHex("1")) {
				t.Fatal("the 51st project was inspected")
			}
		}},
		{name: "MAX_CONFIG_FILES", mutate: func(t *testing.T, c *composeV2) {
			var files []string
			for i := range 17 {
				p := filepath.Join(c.dir, fmt.Sprintf("c%02d.yaml", i))
				if err := os.WriteFile(p, []byte("services: {}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				files = append(files, p)
			}
			for _, id := range []string{cuHex("1"), cuHex("3")} {
				c.container(id)["Config"].(map[string]any)["Labels"].(map[string]any)["com.docker.compose.project.config_files"] =
					strings.Join(files, ",")
			}
		}, check: unitReason("site", "unsupported_files")},
		{name: "MAX_CONFIG_FILE_BYTES", mutate: func(t *testing.T, c *composeV2) {
			if err := os.WriteFile(filepath.Join(c.dir, "compose.yaml"), make([]byte, 1<<20+1), 0o600); err != nil {
				t.Fatal(err)
			}
		}, check: unitReason("site", "unsupported_files")},
		{name: "MAX_COMPOSE_CONFIG_BYTES", mutate: func(t *testing.T, c *composeV2) {
			c.st["source_config"] = strings.Repeat("x", 4<<20+1)
		}, check: unitReason("site", "unsupported_files")},
		{name: "MAX_INSPECT_BYTES", mutate: func(t *testing.T, c *composeV2) {
			c.container(cuHex("3"))["Config"].(map[string]any)["Cmd"] = []any{strings.Repeat("x", 1<<20)}
		}, check: unitReason("site", "host_unreadable")},
		{name: "MAX_LIST_BYTES", mutate: func(t *testing.T, c *composeV2) {
			c.st["listed_only"] = map[string]any{pvID(0): strings.Repeat("x", 1<<20)}
		}, check: func(t *testing.T, c *composeV2, r cuRun) {
			if r.code == 0 || r.doc["status"] != "host_unreadable" || len(r.doc["units"].([]any)) != 0 {
				t.Fatalf("%d %s", r.code, r.out)
			}
		}},
		{name: "MAX_OLD_DIGESTS", mutate: func(t *testing.T, c *composeV2) {
			var rd []any
			for i := range 9 {
				rd = append(rd, "nginx@sha256:"+fmt.Sprintf("%064x", i+1))
			}
			c.st["images"].([]any)[0].(map[string]any)["RepoDigests"] = rd
		}, check: imageReason("old_digest_unknown")},
		{name: "image inspect over MAX_INSPECT_BYTES", mutate: func(t *testing.T, c *composeV2) {
			c.st["images"].([]any)[0].(map[string]any)["Comment"] = strings.Repeat("x", 1<<20)
		}, check: imageReason("old_digest_unknown")},
		{name: "MAX_OVERRIDE_BYTES", mutate: func(t *testing.T, c *composeV2) {
			c.beforeRun = func(t *testing.T) {
				writeOverride(t, c, `{"services": {}}`+strings.Repeat(" ", 256<<10))
			}
		}, check: unitReason("site", "override_drift")},
		{name: "MAX_PREVIEW_TARGET_TAGS", mutate: func(t *testing.T, c *composeV2) {
			c.rawParams, c.params = true, []byte(`{"target_tags":"`+nTags(21)+`"}`)
		}, check: statusOnly("params_invalid")},
		{name: "MAX_PARAMS_BYTES", mutate: func(t *testing.T, c *composeV2) {
			c.rawParams, c.params = true, []byte(`{"target_tags":""}`+strings.Repeat(" ", 4096))
		}, check: statusOnly("params_invalid")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newComposeV2(t)
			tc.mutate(t, c)
			r := c.preview(t, "")
			tc.check(t, c, r)
			requireNoPartialUnits(t, r)
		})
	}
}

func unitReason(project, reason string) func(t *testing.T, c *composeV2, r cuRun) {
	return func(t *testing.T, c *composeV2, r cuRun) {
		t.Helper()
		if r.code != 0 || r.doc["status"] != "ok" {
			t.Fatalf("%d %s", r.code, r.out)
		}
		if u := r.unit(t, project); u["reason"] != reason {
			t.Fatalf("%s: reason %v, want %s", project, u["reason"], reason)
		}
	}
}

func imageReason(reason string) func(t *testing.T, c *composeV2, r cuRun) {
	return func(t *testing.T, c *composeV2, r cuRun) {
		t.Helper()
		u := r.unit(t, "site")
		if u["reason"] != "" {
			t.Fatalf("site %v", u)
		}
		if img := previewImage(t, u, cuDigest("d")); img["reason"] != reason || len(img["resolved"].([]any)) != 0 {
			t.Fatalf("image %v, want %s", img, reason)
		}
	}
}

func statusOnly(status string) func(t *testing.T, c *composeV2, r cuRun) {
	return func(t *testing.T, c *composeV2, r cuRun) {
		t.Helper()
		if r.code == 0 || r.doc["status"] != status || len(r.doc["units"].([]any)) != 0 || len(r.calls) != 0 {
			t.Fatalf("%d %s", r.code, r.out)
		}
	}
}

// An index over MAX_INDEX_BYTES leaves the tag unresolved even when its
// digest matches and it lists the platform; so does one too large for
// the response cap. The unit keeps its facts.
func TestPreviewOversizeIndexIsUnresolved(t *testing.T) {
	for name, size := range map[string]int{"over the index limit": 256<<10 + 1, "over the response cap": 400 << 10} {
		t.Run(name, func(t *testing.T) {
			c := newComposeV2(t)
			head := `{"manifests":[{"digest":"` + cuDigest("c") + `","platform":{"os":"linux","architecture":"amd64"}}],"pad":"`
			body := head + strings.Repeat("x", size-len(head)-2) + `"}`
			sum := sha256.Sum256([]byte(body))
			dg := "sha256:" + hex.EncodeToString(sum[:])
			reg := c.st["registry"].(map[string]any)
			base := "https://registry-1.docker.io/v2/library/nginx/manifests/"
			ct := "application/vnd.oci.image.index.v1+json"
			reg[base+"1.27"] = map[string]any{"status": 200, "headers": map[string]any{"Docker-Content-Digest": dg, "Content-Type": ct}}
			reg[base+dg] = map[string]any{"status": 200, "headers": map[string]any{"Docker-Content-Digest": dg, "Content-Type": ct}, "body": body}
			r := c.preview(t, "")
			u := r.unit(t, "site")
			res := previewImage(t, u, cuDigest("d"))["resolved"].([]any)
			if u["reason"] != "" || len(res) != 1 || res[0].(map[string]any)["reason"] != "tag_unresolved" ||
				res[0].(map[string]any)["platform_digest"] != "" {
				t.Fatalf("%v", res)
			}
		})
	}
}

// TestPreviewResultStaysUnderLimit: a host where every field is at its
// maximum (128-character names and tags, 255-character repositories, 8
// old digests, 21 resolutions per image) would give more than
// MAX_PREVIEW_RESULT_BYTES; the result stays below it, later units are
// truncated whole, and the parser accepts it.
func TestPreviewResultStaysUnderLimit(t *testing.T) {
	c := newComposeV2(t)
	c.previewLines = map[string]string{"REGISTRY_SPACING = 1.0": "REGISTRY_SPACING = 0.0"}
	var tags []string
	for i := range 20 {
		tags = append(tags, fmt.Sprintf("t%02d", i)+strings.Repeat("x", 125))
	}
	for i := range 160 {
		id := pvID(i)
		path := fmt.Sprintf("p%03d/", i) + strings.Repeat("a", 255-len("r.example/")-5)
		ref := "r.example/" + path + ":" + strings.Repeat("v", 128)
		name := fmt.Sprintf("n%03d", i) + strings.Repeat("n", 124)
		img := "sha256:" + pvID(i+5000)
		c.addStandalone(id, name, img, ref, "r.example/"+path+"@"+cuDigest("a"))
		var rd []any
		for j := range 8 {
			rd = append(rd, "r.example/"+path+"@sha256:"+fmt.Sprintf("%064x", j+1))
		}
		imgs := c.st["images"].([]any)
		imgs[len(imgs)-1].(map[string]any)["RepoDigests"] = rd
	}
	r := c.preview(t, strings.Join(tags, ","))
	if r.code != 0 || r.doc["status"] != "ok" {
		t.Fatalf("%d status %v", r.code, r.doc["status"])
	}
	if len(r.out) > 768<<10 {
		t.Fatalf("result of %d bytes", len(r.out))
	}
	var full, truncated int
	for _, x := range r.doc["units"].([]any) {
		switch x.(map[string]any)["reason"] {
		case "":
			if truncated > 0 {
				t.Fatal("a complete unit after a truncated one")
			}
			full++
		case "truncated":
			truncated++
		default:
			t.Fatalf("unit %v", x)
		}
	}
	if full == 0 || truncated == 0 || full+truncated != 161 {
		t.Fatalf("%d complete, %d truncated", full, truncated)
	}
	requireNoPartialUnits(t, r)
}

// A Compose call that ignores SIGTERM is killed after the kill grace;
// the unit and every later one are truncated, and the result comes well
// within the job's timeout. (The copy that runs has a 13-second wall
// clock instead of 4 minutes; the grace stays 10 seconds.)
func TestPreviewSigtermIgnoringCallIsKilled(t *testing.T) {
	c := newComposeV2(t)
	c.previewWallClock = "13"
	c.st["hang_config"] = 120
	c.st["ignore_term"] = 1
	c.addStandalone(cuHex("5"), "solo", cuDigest("d"), "nginx:1.27", "nginx@"+cuDigest("a"))
	start := time.Now()
	r := c.preview(t, "")
	if took := time.Since(start); took > 40*time.Second {
		t.Fatalf("the preview took %s", took)
	}
	if r.code != 0 || r.doc["status"] != "ok" {
		t.Fatalf("%d %s", r.code, r.out)
	}
	for _, x := range r.doc["units"].([]any) {
		if u := x.(map[string]any); u["reason"] != "truncated" {
			t.Fatalf("unit %v", u)
		}
	}
	requireNoPartialUnits(t, r)
	raw, err := os.ReadFile(filepath.Join(c.f.dir, "hung.pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("the SIGTERM-ignoring call %d is still there: %v", pid, err)
	}
}

// TestPreviewRequestCapGivesTagUnresolved: no run makes more than
// MAX_RUN_REGISTRY_REQUESTS registry requests; the resolutions beyond
// the cap are tag_unresolved without a request. A 429 stops every later
// request of the run.
func TestPreviewRequestCapGivesTagUnresolved(t *testing.T) {
	for name, answer := range map[string]map[string]any{"cap": nil, "429": {"status": 429}} {
		t.Run(name, func(t *testing.T) {
			c := newComposeV2(t)
			c.previewLines = map[string]string{"REGISTRY_SPACING = 1.0": "REGISTRY_SPACING = 0.0"}
			if answer != nil {
				c.st["registry_default"] = answer
				c.st["registry"] = map[string]any{}
			}
			// 6 images with 21 tags each: 126 resolutions of distinct tags.
			for i := range 6 {
				path := fmt.Sprintf("r.example/app%d", i)
				c.addStandalone(pvID(i), fmt.Sprintf("app%d", i), "sha256:"+pvID(i+100), path+":1.0", path+"@"+cuDigest("a"))
			}
			r := c.preview(t, nTags(20))
			if r.code != 0 || r.doc["status"] != "ok" {
				t.Fatalf("%d %s", r.code, r.out)
			}
			want := 120
			if answer != nil {
				want = 1
			}
			var n int
			for _, k := range r.calls {
				if k.Tool == "curl" {
					n++
				}
			}
			if n != want {
				t.Fatalf("%d registry requests, want %d", n, want)
			}
			for i := range 6 {
				u := r.standaloneUnit(t, pvID(i))
				img := previewImage(t, u, "sha256:"+pvID(i+100))
				if u["reason"] != "" || img["reason"] != "" || len(img["resolved"].([]any)) != 21 {
					t.Fatalf("unit %v", u)
				}
				for _, x := range img["resolved"].([]any) {
					if x.(map[string]any)["reason"] != "tag_unresolved" {
						t.Fatalf("resolution %v", x)
					}
				}
			}
		})
	}
}
