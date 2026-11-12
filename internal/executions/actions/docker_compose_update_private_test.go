// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

// A private registry binding (cu06): the executor resolved the tag and
// loaded the image over SSH before the job, so the host job asks no
// registry and pulls nothing; it only verifies that the bound
// repository@digest is local (the containerd store's evidence) and then
// recreates as for a public image.

func privateComposeV2(t *testing.T, loaded bool) *composeV2 {
	t.Helper()
	c := newComposeV2(t)
	c.u.Registry = &canonical.ContainerUpdateRegistry{RegistryID: "corp", RecordDigest: cuHex("5"), CredentialID: strings.Repeat("6", 32),
		CredentialVersion: 3}
	if loaded {
		ref := "docker.io/library/nginx@" + cuDigest("c")
		im := c.st["pullable"].(map[string]any)[ref]
		c.st["images"] = append(c.st["images"].([]any), im)
	}
	delete(c.st, "pullable")
	delete(c.st, "registry")
	return c
}

func TestComposeUpdatePrivateVerifiesLoadedImageWithoutRegistry(t *testing.T) {
	c := privateComposeV2(t, true)
	r := c.exec(t)
	if r.code != 0 || r.doc["phase"] != "after_snapshot" || r.doc["reason"] != "" {
		t.Fatalf("%d %s", r.code, r.out)
	}
	pulled, _ := json.Marshal(r.doc["pulled"])
	if !strings.Contains(string(pulled), cuDigest("f")) {
		t.Fatalf("pulled %s", pulled)
	}
	for _, k := range r.calls {
		if k.Tool == "curl" || (k.Tool == "docker" && (k.Argv[0] == "pull" || k.Argv[0] == "login")) || k.DockerConfig != nil {
			t.Fatalf("a private job reached for a registry: %q", k.line())
		}
	}
	ov, ok := c.override(t)
	want := map[string]any{"services": map[string]any{"web": map[string]any{"image": "docker.io/library/nginx:1.27@" + cuDigest("c")}}}
	if !ok || !jsonEqual(ov, want) {
		t.Fatalf("override %v", ov)
	}
	if strings.Contains(string(r.out), strings.Repeat("6", 32)) || strings.Contains(string(r.out), cuHex("5")) {
		t.Fatal("the registry binding was echoed into the result")
	}
}

// Without the loaded image (a classic load, a rewritten manifest, or no
// transfer at all) the job stops before any change: nothing is pulled.
func TestComposeUpdatePrivateWithoutLoadedImageStops(t *testing.T) {
	c := privateComposeV2(t, false)
	r := c.exec(t)
	if r.code != 10 || r.doc["phase"] != "pull" || r.doc["reason"] != "pulled_image_mismatch" {
		t.Fatalf("%d %s", r.code, r.out)
	}
	for _, k := range r.calls {
		if k.Tool == "curl" || (k.Tool == "docker" && (k.Argv[0] == "pull" || k.Argv[0] == "tag" || strings.Contains(k.line(), " up "))) {
			t.Fatalf("call after a missing private image: %q", k.line())
		}
	}
}

func TestComposeUpdatePrivateMalformedRegistryBindingRefused(t *testing.T) {
	good := map[string]any{"registry_id": "corp", "record_digest": cuHex("5"), "credential_id": strings.Repeat("6", 32), "credential_version": 3}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for a, b := range good {
			m[a] = b
		}
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	for name, reg := range map[string]any{
		"extra key":         with("secret", "x"),
		"missing version":   with("credential_version", nil),
		"zero version":      with("credential_version", 0),
		"bool version":      with("credential_version", true),
		"string version":    with("credential_version", "3"),
		"bad record digest": with("record_digest", "abc"),
		"bad registry id":   with("registry_id", "Corp!"),
		"bad credential id": with("credential_id", "-x"),
		"not an object":     "corp",
	} {
		t.Run(name, func(t *testing.T) {
			c := privateComposeV2(t, true)
			params, _, err := canonical.ContainerUpdateParameters(c.u)
			if err != nil {
				t.Fatal(err)
			}
			var d map[string]any
			_ = json.Unmarshal(params, &d)
			d["container_update"].(map[string]any)["registry"] = reg
			c.rawParams = true
			c.params, _ = json.Marshal(d)
			r := c.exec(t)
			if r.code != 10 || r.doc["reason"] != "binding_invalid" || len(r.calls) != 0 {
				t.Fatalf("%d %s calls %d", r.code, r.out, len(r.calls))
			}
		})
	}
}
