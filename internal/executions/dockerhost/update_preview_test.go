// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func pvHex(c string) string    { return strings.Repeat(c, 64) }
func pvDigest(c string) string { return "sha256:" + pvHex(c) }

// pvSample is a valid docker-update-preview-v1 result: project "site" with
// web (depends on db) and db, one truncated project and a standalone
// container.
func pvSample() map[string]any {
	img := func(id, ref, repo, tag string, res ...any) map[string]any {
		return map[string]any{"image_id": id, "running_reference": ref, "repository": repo, "tag": tag, "platform": "linux/amd64",
			"old_digests": []any{pvDigest("a")}, "resolved": res, "reason": ""}
	}
	tgt := func(svc, id, name, image, ref string) map[string]any {
		return map[string]any{"service": svc, "container_id": id, "container_name": name, "state": "running", "image_id": image,
			"running_reference": ref, "configuration_digest": pvHex("c")}
	}
	return map[string]any{
		"format": "docker-update-preview-v1", "status": "ok",
		"units": []any{
			map[string]any{"form": "compose", "project": "big", "container_id": "", "reason": "truncated"},
			map[string]any{"form": "compose", "project": "site", "container_id": "", "reason": "",
				"working_dir_hash": pvHex("1"), "config_files_hash": pvHex("2"), "source_digest": pvHex("3"),
				"services": []any{
					map[string]any{"service": "db", "replicas": 1, "scale": 1, "depends": []any{}, "shares": []any{}, "reasons": []any{}},
					map[string]any{"service": "web", "replicas": 1, "scale": 1, "depends": []any{map[string]any{"service": "db", "restart": false}},
						"shares": []any{}, "reasons": []any{}},
				},
				"targets": []any{
					tgt("db", pvHex("3"), "site-db-1", pvDigest("e"), "postgres:16"),
					tgt("web", pvHex("1"), "site-web-1", pvDigest("d"), "nginx:1.27"),
				},
				"images": []any{
					img(pvDigest("d"), "nginx:1.27", "docker.io/library/nginx", "1.27",
						map[string]any{"tag": "1.27", "index_digest": pvDigest("8"), "platform_digest": pvDigest("9"), "reason": ""},
						map[string]any{"tag": "1.28", "index_digest": "", "platform_digest": "", "reason": "tag_unresolved"}),
					img(pvDigest("e"), "postgres:16", "docker.io/library/postgres", "16",
						map[string]any{"tag": "16", "index_digest": "", "platform_digest": pvDigest("7"), "reason": ""}),
				}},
			map[string]any{"form": "standalone", "project": "", "container_id": pvHex("5"), "reason": "",
				"targets": []any{tgt("", pvHex("5"), "solo", pvDigest("d"), "nginx:1.27")},
				"images": []any{img(pvDigest("d"), "nginx:1.27", "docker.io/library/nginx", "1.27",
					map[string]any{"tag": "1.27", "index_digest": pvDigest("8"), "platform_digest": pvDigest("9"), "reason": ""})}},
		},
	}
}

func pvMarshal(t *testing.T, doc any) []byte {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// pvAt walks doc by keys and indexes ("units", 1, "targets", 0).
func pvAt(doc any, path ...any) any {
	for _, p := range path {
		switch k := p.(type) {
		case string:
			doc = doc.(map[string]any)[k]
		case int:
			doc = doc.([]any)[k]
		}
	}
	return doc
}

func pvSite(doc map[string]any) map[string]any { return pvAt(doc, "units", 1).(map[string]any) }

func TestParseUpdatePreviewSample(t *testing.T) {
	p, err := ParseUpdatePreview(pvMarshal(t, pvSample()))
	if err != nil {
		t.Fatal(err)
	}
	if p.Status != PreviewOK || len(p.Units) != 3 {
		t.Fatalf("%+v", p)
	}
	big, site, solo := p.Units[0], p.Units[1], p.Units[2]
	if big.HasFacts() || big.Reason != PreviewTruncated || len(big.Targets) != 0 {
		t.Fatalf("big %+v", big)
	}
	if !site.HasFacts() || site.SourceDigest != pvHex("3") || len(site.Targets) != 2 || len(site.Images) != 2 ||
		site.Images[0].Resolved[0].PlatformDigest != pvDigest("9") || site.Images[0].Resolved[1].Reason != "tag_unresolved" ||
		site.Services[1].Depends[0] != (PreviewDependency{Service: "db"}) {
		t.Fatalf("site %+v", site)
	}
	if !site.Available("web") || !site.Available("db") || site.Available("cache") {
		t.Fatal("availability")
	}
	if solo.Form != "standalone" || solo.Targets[0].ContainerID != pvHex("5") || solo.SourceDigest != "" || solo.Available("") {
		t.Fatalf("solo %+v", solo)
	}
	for _, s := range []string{PreviewPrepareRequired, "salt_unsafe", "tooling_missing", "not_root", "params_invalid",
		"host_unreadable", "result_too_large", "internal_error"} {
		p, err := ParseUpdatePreview([]byte(`{"format":"docker-update-preview-v1","status":"` + s + `","units":[]}`))
		if err != nil || p.Status != s || len(p.Units) != 0 {
			t.Fatalf("%s: %+v %v", s, p, err)
		}
	}
}

// Service and unit reasons decide availability; observed reasons keep the
// facts.
func TestParseUpdatePreviewReasons(t *testing.T) {
	for _, r := range []string{"build_unsupported", "config_not_applied", "digest_pinned", "ephemeral_port", "mixed_images",
		"scale_mismatch", "target_not_running"} {
		doc := pvSample()
		pvAt(pvSite(doc), "services", 1).(map[string]any)["reasons"] = []any{r}
		p, err := ParseUpdatePreview(pvMarshal(t, doc))
		if err != nil {
			t.Fatalf("%s: %v", r, err)
		}
		if p.Units[1].Available("web") || !p.Units[1].Available("db") || !p.Units[1].HasFacts() {
			t.Fatalf("%s: availability", r)
		}
	}
	doc := pvSample()
	pvSite(doc)["reason"] = PreviewOverrideDrift
	p, err := ParseUpdatePreview(pvMarshal(t, doc))
	if err != nil || !p.Units[1].HasFacts() || p.Units[1].Available("web") || p.Units[1].Available("db") {
		t.Fatalf("drift: %+v %v", p, err)
	}
	doc = pvSample()
	img := pvAt(pvSite(doc), "images", 0).(map[string]any)
	img["reason"], img["old_digests"], img["resolved"] = "old_digest_unknown", []any{}, []any{}
	p, err = ParseUpdatePreview(pvMarshal(t, doc))
	if err != nil || p.Units[1].Available("web") || !p.Units[1].Available("db") {
		t.Fatalf("image reason: %v", err)
	}
	for _, r := range []string{"project_mismatch", "unsupported_files", "dependency_unsupported", "host_unreadable", "truncated"} {
		doc := map[string]any{"format": "docker-update-preview-v1", "status": "ok", "units": []any{
			map[string]any{"form": "compose", "project": "site", "container_id": "", "reason": r}}}
		if p, err := ParseUpdatePreview(pvMarshal(t, doc)); err != nil || p.Units[0].HasFacts() {
			t.Fatalf("%s: %v", r, err)
		}
	}
	if len(PreviewReasons()) < 15 {
		t.Fatalf("%v", PreviewReasons())
	}
}

// Every rule of the format refuses the whole result.
func TestParseUpdatePreviewRefuses(t *testing.T) {
	cases := map[string]func(doc map[string]any){
		"format":             func(d map[string]any) { d["format"] = "docker-update-preview-v2" },
		"status":             func(d map[string]any) { d["status"] = "fine" },
		"units with failure": func(d map[string]any) { d["status"] = PreviewPrepareRequired },
		"unknown member":     func(d map[string]any) { d["extra"] = 1 },
		"missing units":      func(d map[string]any) { delete(d, "units") },
		"unit order": func(d map[string]any) {
			u := d["units"].([]any)
			u[0], u[1] = u[1], u[0]
		},
		"standalone first": func(d map[string]any) {
			u := d["units"].([]any)
			d["units"] = []any{u[2], u[0], u[1]}
		},
		"unknown unit reason":  func(d map[string]any) { pvSite(d)["reason"] = "flaky" },
		"facts with truncated": func(d map[string]any) { pvSite(d)["reason"] = PreviewTruncated },
		"head with facts":      func(d map[string]any) { pvAt(d, "units", 0).(map[string]any)["source_digest"] = pvHex("3") },
		"missing source":       func(d map[string]any) { delete(pvSite(d), "source_digest") },
		"unkeyed-looking hash": func(d map[string]any) { pvSite(d)["source_digest"] = "sha256:" + pvHex("3") },
		"project name":         func(d map[string]any) { pvSite(d)["project"] = "Site" },
		"compose container id": func(d map[string]any) { pvSite(d)["container_id"] = pvHex("1") },
		"standalone project":   func(d map[string]any) { pvAt(d, "units", 2).(map[string]any)["project"] = "x" },
		"standalone services":  func(d map[string]any) { pvAt(d, "units", 2).(map[string]any)["services"] = []any{} },
		"standalone id differs": func(d map[string]any) {
			pvAt(d, "units", 2, "targets", 0).(map[string]any)["container_id"] = pvHex("6")
		},
		"service order": func(d map[string]any) {
			s := pvSite(d)["services"].([]any)
			s[0], s[1] = s[1], s[0]
		},
		"service reason": func(d map[string]any) { pvAt(pvSite(d), "services", 1).(map[string]any)["reasons"] = []any{"maybe"} },
		"reasons unsorted": func(d map[string]any) {
			pvAt(pvSite(d), "services", 1).(map[string]any)["reasons"] = []any{"scale_mismatch", "digest_pinned"}
		},
		"reasons duplicated": func(d map[string]any) {
			pvAt(pvSite(d), "services", 1).(map[string]any)["reasons"] = []any{"scale_mismatch", "scale_mismatch"}
		},
		"drift and not applied": func(d map[string]any) {
			pvSite(d)["reason"] = PreviewOverrideDrift
			pvAt(pvSite(d), "services", 1).(map[string]any)["reasons"] = []any{"config_not_applied"}
		},
		"depends unknown": func(d map[string]any) {
			pvAt(pvSite(d), "services", 1, "depends", 0).(map[string]any)["service"] = "cache"
		},
		"shares unknown":    func(d map[string]any) { pvAt(pvSite(d), "services", 1).(map[string]any)["shares"] = []any{"cache"} },
		"replicas mismatch": func(d map[string]any) { pvAt(pvSite(d), "services", 1).(map[string]any)["replicas"] = 2 },
		"target service":    func(d map[string]any) { pvAt(pvSite(d), "targets", 1).(map[string]any)["service"] = "cache" },
		"target short id": func(d map[string]any) {
			pvAt(pvSite(d), "targets", 1).(map[string]any)["container_id"] = "111111111111"
		},
		"target state": func(d map[string]any) { pvAt(pvSite(d), "targets", 1).(map[string]any)["state"] = "up" },
		"target reference": func(d map[string]any) {
			pvAt(pvSite(d), "targets", 1).(map[string]any)["running_reference"] = "nginx 1.27"
		},
		"target digest":   func(d map[string]any) { pvAt(pvSite(d), "targets", 1).(map[string]any)["configuration_digest"] = "x" },
		"target name dup": func(d map[string]any) { pvAt(pvSite(d), "targets", 1).(map[string]any)["container_name"] = "site-db-1" },
		"target missing member": func(d map[string]any) {
			delete(pvAt(pvSite(d), "targets", 1).(map[string]any), "state")
		},
		"target order": func(d map[string]any) {
			s := pvSite(d)["targets"].([]any)
			s[0], s[1] = s[1], s[0]
		},
		"container in two units": func(d map[string]any) {
			pvAt(d, "units", 2).(map[string]any)["container_id"] = pvHex("1")
			pvAt(d, "units", 2, "targets", 0).(map[string]any)["container_id"] = pvHex("1")
		},
		"image missing": func(d map[string]any) { pvSite(d)["images"] = pvSite(d)["images"].([]any)[:1] },
		"image repository not canonical": func(d map[string]any) {
			pvAt(pvSite(d), "images", 0).(map[string]any)["repository"] = "nginx"
		},
		"image old digests unsorted": func(d map[string]any) {
			pvAt(pvSite(d), "images", 0).(map[string]any)["old_digests"] = []any{pvDigest("b"), pvDigest("a")}
		},
		"image too many old digests": func(d map[string]any) {
			var ds []any
			for _, c := range []string{"0", "1", "2", "3", "4", "5", "6", "7", "8"} {
				ds = append(ds, pvDigest(c))
			}
			pvAt(pvSite(d), "images", 0).(map[string]any)["old_digests"] = ds
		},
		"image facts beside reason": func(d map[string]any) { pvAt(pvSite(d), "images", 0).(map[string]any)["reason"] = "old_digest_unknown" },
		"first resolution not current tag": func(d map[string]any) {
			r := pvAt(pvSite(d), "images", 0, "resolved").([]any)
			r[0], r[1] = r[1], r[0]
		},
		"resolution digests beside unresolved": func(d map[string]any) {
			pvAt(pvSite(d), "images", 0, "resolved", 1).(map[string]any)["platform_digest"] = pvDigest("9")
		},
		"resolution index equals platform": func(d map[string]any) {
			pvAt(pvSite(d), "images", 0, "resolved", 0).(map[string]any)["index_digest"] = pvDigest("9")
		},
		"resolution reason": func(d map[string]any) {
			pvAt(pvSite(d), "images", 0, "resolved", 1).(map[string]any)["reason"] = "tag_moved"
		},
		"resolution tag duplicated": func(d map[string]any) {
			pvAt(pvSite(d), "images", 0, "resolved", 1).(map[string]any)["tag"] = "1.27"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			doc := pvSample()
			mutate(doc)
			if _, err := ParseUpdatePreview(pvMarshal(t, doc)); !errors.Is(err, ErrPreviewFormat) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	for name, b := range map[string][]byte{
		"two values":   append(pvMarshal(t, pvSample()), []byte(` {}`)...),
		"not utf-8":    []byte("{\"format\":\"\xff\"}"),
		"oversize":     []byte(`{"format":"docker-update-preview-v1","status":"ok","units":[]` + strings.Repeat(" ", MaxPreviewResultBytes) + `}`),
		"null units":   []byte(`{"format":"docker-update-preview-v1","status":"ok","units":null}`),
		"string units": []byte(`{"format":"docker-update-preview-v1","status":"ok","units":"x"}`),
	} {
		if _, err := ParseUpdatePreview(b); !errors.Is(err, ErrPreviewFormat) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

// More containers with facts than the script may report is not a result
// of the script.
func TestParseUpdatePreviewContainerLimit(t *testing.T) {
	var units []any
	for i := range MaxPreviewContainers + 1 {
		id := strings.Repeat("0", 61) + strconv.Itoa(100+i)
		units = append(units, map[string]any{"form": "standalone", "project": "", "container_id": id, "reason": "",
			"targets": []any{map[string]any{"service": "", "container_id": id, "container_name": "c" + strconv.Itoa(i), "state": "exited",
				"image_id": pvDigest("d"), "running_reference": "nginx:1.27", "configuration_digest": pvHex("c")}},
			"images": []any{map[string]any{"image_id": pvDigest("d"), "running_reference": "nginx:1.27", "repository": "",
				"tag": "", "platform": "", "old_digests": []any{}, "resolved": []any{}, "reason": "reference_unsupported"}}})
	}
	doc := map[string]any{"format": "docker-update-preview-v1", "status": "ok", "units": units}
	if _, err := ParseUpdatePreview(pvMarshal(t, doc)); !errors.Is(err, ErrPreviewFormat) {
		t.Fatalf("accepted: %v", err)
	}
	doc["units"] = units[:MaxPreviewContainers]
	if _, err := ParseUpdatePreview(pvMarshal(t, doc)); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
}

// The parser's limits are the script's (container update plan cu03, Q11:
// the scripts' limits and the Go constants stay in agreement).
func TestPreviewLimitsMatchScript(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "actions", "scripts", "docker_update_preview.sh"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for name, want := range map[string]int{
		"MAX_PREVIEW_CONTAINERS": MaxPreviewContainers, "MAX_PREVIEW_PROJECTS": MaxPreviewProjects,
		"MAX_PREVIEW_TARGET_TAGS": MaxPreviewTargetTags, "MAX_CONFIG_FILES": MaxPreviewConfigFiles,
		"MAX_CONFIG_FILE_BYTES": MaxPreviewConfigFileBytes, "MAX_COMPOSE_CONFIG_BYTES": MaxPreviewComposeConfigBytes,
		"MAX_INDEX_BYTES": MaxPreviewIndexBytes, "MAX_PREVIEW_RESULT_BYTES": MaxPreviewResultBytes,
		"MAX_OLD_DIGESTS": MaxPreviewOldDigests, "MAX_RUN_REGISTRY_REQUESTS": MaxRunRegistryRequests,
		"MAX_PREVIEW_WALL_CLOCK": int(MaxPreviewWallClock / time.Second),
	} {
		m := regexp.MustCompile(`(?m)^` + name + ` = ([0-9* ]+)$`).FindStringSubmatch(s)
		if m == nil {
			t.Errorf("%s not in the script", name)
			continue
		}
		got := 1
		for _, f := range strings.Split(m[1], "*") {
			n, err := strconv.Atoi(strings.TrimSpace(f))
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			got *= n
		}
		if got != want {
			t.Errorf("%s: script %d, parser %d", name, got, want)
		}
	}
	if MaxPreviewResultBytes >= 1<<20 {
		t.Error("the result limit must stay below hostrun.MaxResult")
	}
}

// Results come from managed hosts: no input panics the parser, and what it
// accepts keeps the format's invariants.
func FuzzParseUpdatePreview(f *testing.F) {
	f.Add([]byte(`{"format":"docker-update-preview-v1","status":"ok","units":[]}`))
	f.Add([]byte(`{"format":"docker-update-preview-v1","status":"prepare_required","units":[]}`))
	b, _ := json.Marshal(pvSample())
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ParseUpdatePreview(b)
		if err != nil {
			return
		}
		if p.Status != PreviewOK && len(p.Units) != 0 {
			t.Fatal("units beside a failure status")
		}
		n := 0
		for _, u := range p.Units {
			if !u.HasFacts() && (len(u.Targets) != 0 || u.SourceDigest != "") {
				t.Fatal("facts without HasFacts")
			}
			n += len(u.Targets)
		}
		if n > MaxPreviewContainers {
			t.Fatal("container limit")
		}
	})
}
