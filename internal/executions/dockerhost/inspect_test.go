// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// testdata/docker29-inspect.json is docker.inspect on Docker 29.8.2 for a
// running, unhealthy container with a bind and a volume mount, a TCP port
// on 127.0.0.1 and a UDP port on all addresses, restart policy
// unless-stopped and an environment variable SECRET_PASSWORD=hunter2 that
// must not be in the result.
func TestParseRealInspect(t *testing.T) {
	b, err := os.ReadFile("testdata/docker29-inspect.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "hunter2") {
		t.Fatal("the environment is in the result")
	}
	in, err := ParseInspect(b)
	if err != nil {
		t.Fatal(err)
	}
	if in.Container != "full" || in.Name != "full" || in.ID != "b46feb47000b" ||
		in.FullID != "b46feb47000b8c2913bfcb3beab51cebd2a6729630f1f1b857a31f6fdae3e347" || in.Image != "nos-test/sleeper:2" ||
		!strings.HasPrefix(in.ImageID, "sha256:1c39e3d3") || len(in.Digests) != 1 ||
		in.Digests[0] != "nos-test/sleeper@sha256:7f2a9c4e1d8b3f6a0c5e9d2b7a4f8c1e3d6b9a2f5c8e1d4b7a0f3c6e9d2b5a8f" ||
		in.ImageDigestIndex != "" || in.ImageDigestPlatform != "" ||
		in.Created != "2026-10-14T19:06:42Z" || in.ImageCreated != "2026-09-01T12:00:00Z" || in.Platform != "linux/amd64" ||
		in.Status != "running" || in.Started == "" || in.Finished != "" || in.RestartPolicy != "unless-stopped" ||
		in.Health != "unhealthy" || in.FailingStreak < 1 {
		t.Fatalf("%+v", in)
	}
	if len(in.Mounts) != 2 || in.Mounts[0] != (Mount{Type: "bind", Source: "/tmp", Destination: "/data", ReadOnly: true}) ||
		in.Mounts[1].Name != "nosvol" || in.Mounts[1].ReadOnly {
		t.Fatalf("mounts %+v", in.Mounts)
	}
	if len(in.Ports) != 2 || in.Ports[0] != (PortMap{Container: "90/tcp", Host: "127.0.0.1:9090"}) || in.Ports[1] != (PortMap{Container: "91/udp", Host: "0.0.0.0:9091"}) {
		t.Fatalf("ports %+v", in.Ports)
	}
	if len(in.Networks) != 1 || in.Networks[0] != (Network{Name: "bridge", IP: "172.17.0.2"}) {
		t.Fatalf("networks %+v", in.Networks)
	}

	// A created container: no health check (docker's template cannot even
	// name .State.Health then), never started.
	b, err = os.ReadFile("testdata/docker29-inspect-created.json")
	if err != nil {
		t.Fatal(err)
	}
	in, err = ParseInspect(b)
	if err != nil || in.Status != "created" || in.Health != "" || in.Started != "" || in.RestartPolicy != "no" || len(in.Mounts) != 0 {
		t.Fatalf("%+v %v", in, err)
	}
	if in.Created != "2026-10-14T19:06:40Z" || in.ImageCreated != "2026-08-15T08:30:00Z" || in.Platform != "linux/amd64" ||
		in.FullID != "a58f9bc117914e03de9c322d90d61bedffc5f34cfd32af76a063544df3e2ce0f" ||
		len(in.Digests) != 1 || in.Digests[0] != "nos-test/sleeper@sha256:3e8b1c5f9a2d4e7b0c3f6a9d2b5e8c1f4a7d0b3e6c9f2a5d8b1e4c7f0a3d6b9e" ||
		in.ImageDigestIndex != "" || in.ImageDigestPlatform != "" {
		t.Fatalf("%+v", in)
	}
}

func TestParseInspectIsDefensive(t *testing.T) {
	inner := `{"id":"zz","name":"/-x","image":"img\u202e","image_id":"sha256:short",` +
		`"state":{"Status":"zombie","ExitCode":-99,"StartedAt":"not a time","Health":{"Status":"great","FailingStreak":-1}},` +
		`"restarts":-5,"restart_policy":"sometimes",` +
		`"mounts":[{"Type":"bind","Source":"/a\nb","Destination":"/ok","RW":true},{"Type":"weird","Destination":"/x"},{"Type":"bind","Destination":"rel"}],` +
		`"ports":{"80/tcp":[{"HostIp":"1.2.3.4","HostPort":"8080"},{"HostIp":"<b>","HostPort":"1"}],"x/tcp":[{"HostIp":"","HostPort":"1"}],"443/tcp":null,"53/udp":[{"HostIp":"::","HostPort":"53"}]},` +
		`"networks":{"-bad":{"IPAddress":"1.1.1.1"},"good":{"IPAddress":"<script>","GlobalIPv6Address":"fd00::2"}}}`
	digests := `["repo@sha256:` + strings.Repeat("a", 64) + `","evil\u202e@sha256:` + strings.Repeat("b", 64) + `","nodigest"]`
	res := `{"format":"docker-inspect-v1","phase":"done","container":"c1","inspect":"` + base64.StdEncoding.EncodeToString([]byte(inner)) +
		`","digests":"` + base64.StdEncoding.EncodeToString([]byte(digests)) + `"}`
	in, err := ParseInspect([]byte(res))
	if err != nil {
		t.Fatal(err)
	}
	if in.ID != "" || in.Name != "" || in.Image != "" || in.ImageID != "" || in.Status != "" || in.ExitCode != 0 || in.Started != "" ||
		in.Health != "" || in.Restarts != 0 || in.RestartPolicy != "" {
		t.Fatalf("%+v", in)
	}
	if len(in.Mounts) != 1 || in.Mounts[0].Source != "" || in.Mounts[0].Destination != "/ok" {
		t.Fatalf("mounts %+v", in.Mounts)
	}
	want := []PortMap{{"80/tcp", "1.2.3.4:8080"}, {"443/tcp", ""}, {"53/udp", "[::]:53"}}
	if len(in.Ports) != len(want) {
		t.Fatalf("ports %+v", in.Ports)
	}
	for i := range want {
		if in.Ports[i] != want[i] {
			t.Fatalf("ports %+v", in.Ports)
		}
	}
	if len(in.Networks) != 1 || in.Networks[0] != (Network{Name: "good", IP: "fd00::2"}) {
		t.Fatalf("networks %+v", in.Networks)
	}
	if len(in.Digests) != 1 {
		t.Fatalf("digests %v", in.Digests)
	}
	for _, bad := range []string{`{"format":"docker-inspect-v1","phase":"done","inspect":"%%"}`,
		`{"format":"docker-inspect-v1","phase":"done","inspect":"` + base64.StdEncoding.EncodeToString([]byte("[1,2]")) + `"}`,
		`{"format":"docker-logs-v1","phase":"done"}`} {
		if _, err := ParseInspect([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	in, err = ParseInspect([]byte(`{"format":"docker-inspect-v1","phase":"precheck","reason":"no such container"}`))
	if err != nil || in.Reason != "no such container" {
		t.Fatalf("%+v %v", in, err)
	}
}

func TestParseInspectImageDefensive(t *testing.T) {
	inner := `{"id":"` + strings.Repeat("a", 64) + `","name":"/ok","image":"img","image_id":"sha256:` +
		strings.Repeat("c", 64) + `","created":"2026-01-02T03:04:05Z","state":{"Status":"running","StartedAt":"2026-01-01T00:00:00Z"}}`
	enc := base64.StdEncoding.EncodeToString

	// Valid image metadata: platform, image creation time and untyped digest.
	goodImage := `{"id":"sha256:` + strings.Repeat("c", 64) + `","created":"2026-01-01T00:00:00Z",` +
		`"os":"linux","architecture":"arm64","variant":"v8","repo_digests":["repo@sha256:` + strings.Repeat("d", 64) + `"]}`
	in, err := ParseInspect([]byte(`{"format":"docker-inspect-v1","phase":"done","container":"c1","inspect":"` +
		enc([]byte(inner)) + `","image":"` + enc([]byte(goodImage)) + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if in.Platform != "linux/arm64/v8" || in.ImageCreated != "2026-01-01T00:00:00Z" ||
		in.Created != "2026-01-02T03:04:05Z" || len(in.Digests) != 1 ||
		in.Digests[0] != "repo@sha256:"+strings.Repeat("d", 64) || in.ImageDigestIndex != "" || in.ImageDigestPlatform != "" {
		t.Fatalf("%+v", in)
	}

	// A malformed image field is ignored; the container still parses.
	in, err = ParseInspect([]byte(`{"format":"docker-inspect-v1","phase":"done","container":"c1","inspect":"` +
		enc([]byte(inner)) + `","image":"` + enc([]byte("not json")) + `"}`))
	if err != nil || in.Platform != "" || in.ImageCreated != "" || len(in.Digests) != 0 || in.ImageDigestIndex != "" {
		t.Fatalf("%+v %v", in, err)
	}

	// An oversize image field is rejected.
	in, err = ParseInspect([]byte(`{"format":"docker-inspect-v1","phase":"done","container":"c1","inspect":"` +
		enc([]byte(inner)) + `","image":"` + enc([]byte(strings.Repeat("x", maxImage+1))) + `"}`))
	if err != nil || in.Platform != "" || len(in.Digests) != 0 {
		t.Fatalf("%+v %v", in, err)
	}

	// Extra fields in the image object (e.g. environment) are never copied out.
	leaky := `{"id":"sha256:` + strings.Repeat("c", 64) + `","os":"linux","architecture":"amd64",` +
		`"repo_digests":["repo@sha256:` + strings.Repeat("d", 64) + `"],"env":["TOKEN=hunter2"]}`
	in, err = ParseInspect([]byte(`{"format":"docker-inspect-v1","phase":"done","container":"c1","inspect":"` +
		enc([]byte(inner)) + `","image":"` + enc([]byte(leaky)) + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{in.Platform, in.ImageCreated, in.ImageDigestIndex, in.ImageID, in.Created} {
		if strings.Contains(s, "hunter2") {
			t.Fatalf("secret leaked: %q", s)
		}
	}
}

func inspectImage(t *testing.T, image []byte) Inspect {
	t.Helper()
	inner := `{"id":"` + strings.Repeat("a", 64) + `","image_id":"sha256:` + strings.Repeat("c", 64) + `","state":{"Status":"running"}}`
	in, err := ParseInspect([]byte(`{"format":"docker-inspect-v1","phase":"done","inspect":"` + enc(inner) + `","image":"` + base64.StdEncoding.EncodeToString(image) + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func TestParseInspectDigestKinds(t *testing.T) {
	config := "sha256:" + strings.Repeat("c", 64)
	digest := "sha256:" + strings.Repeat("d", 64)
	repo := "repo@" + digest
	for _, tc := range []struct {
		name, mediaType, digest string
		index                   bool
		platform                bool
	}{
		{"untyped repository digest", "", "", false, false},
		{"OCI index", "application/vnd.oci.image.index.v1+json", digest, true, false},
		{"Docker index", "application/vnd.docker.distribution.manifest.list.v2+json", digest, true, false},
		{"OCI platform manifest", "application/vnd.oci.image.manifest.v1+json", digest, false, true},
		{"Docker platform manifest", "application/vnd.docker.distribution.manifest.v2+json", digest, false, true},
		{"configuration descriptor", "application/vnd.oci.image.config.v1+json", digest, false, false},
		{"unknown descriptor type", "application/vnd.example.unknown+json", digest, false, false},
		{"invalid descriptor digest", "application/vnd.oci.image.index.v1+json", "sha256:short", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			image, err := json.Marshal(map[string]any{
				"id": config, "repo_digests": []string{repo},
				"descriptor": map[string]string{"mediaType": tc.mediaType, "digest": tc.digest},
			})
			if err != nil {
				t.Fatal(err)
			}
			in := inspectImage(t, image)
			var wantIndex, wantPlatform string
			if tc.index {
				wantIndex = digest
			}
			if tc.platform {
				wantPlatform = digest
			}
			if in.ImageID != config || in.ImageDigestIndex != wantIndex || in.ImageDigestPlatform != wantPlatform || len(in.Digests) != 1 || in.Digests[0] != repo {
				t.Fatalf("digest kinds conflated or untyped digest lost: %+v", in)
			}
		})
	}
	// Old results containing only repository digests retain their unknown kind.
	in, err := ParseInspect([]byte(`{"format":"docker-inspect-v1","phase":"done","inspect":"` + enc(`{}`) + `","digests":"` + enc(`["`+repo+`"]`) + `"}`))
	if err != nil || in.ImageID != "" || in.ImageDigestIndex != "" || in.ImageDigestPlatform != "" || len(in.Digests) != 1 || in.Digests[0] != repo {
		t.Fatalf("legacy digest kind: %+v %v", in, err)
	}
}

func TestParseInspectImageRejectsInvalidUTF8(t *testing.T) {
	image := []byte(`{"id":"sha256:` + strings.Repeat("d", 64) + `","created":"2026-01-01T00:00:00Z","os":"linux","architecture":"amd64","variant":"` + "\xff" + `","repo_digests":["repo@sha256:` + strings.Repeat("e", 64) + `"]}`)
	in := inspectImage(t, image)
	if in.ImageID != "sha256:"+strings.Repeat("c", 64) || in.ImageCreated != "" || in.Platform != "" || len(in.Digests) != 0 || in.ImageDigestIndex != "" || in.Status != "running" {
		t.Fatalf("invalid UTF-8 image metadata accepted: %+v", in)
	}
}

func TestParseInspectPlatformSchema(t *testing.T) {
	for _, tc := range []struct {
		name, os, arch, variant, want string
	}{
		{"amd64", "linux", "amd64", "", "linux/amd64"},
		{"arm variant", "linux", "arm", "v7", "linux/arm/v7"},
		{"dotted variant", "linux", "arm64", "v8.1", "linux/arm64/v8.1"},
		{"missing OS", "", "amd64", "", ""},
		{"missing architecture", "linux", "", "v8", ""},
		{"missing both", "", "", "v8", ""},
		{"OS separator", "linux/other", "amd64", "", ""},
		{"architecture separator", "linux", "amd64/other", "", ""},
		{"variant separator", "linux", "arm64", "v8/other", ""},
		{"OS whitespace", " linux", "amd64", "", ""},
		{"architecture whitespace", "linux", "amd 64", "", ""},
		{"variant markup", "linux", "arm64", "<v8>", ""},
		{"non ASCII", "linux", "аmd64", "", ""},
		{"control character", "linux", "arm64", "v8\n", ""},
		{"oversize OS", strings.Repeat("a", 33), "amd64", "", ""},
		{"oversize architecture", "linux", strings.Repeat("a", 33), "", ""},
		{"oversize variant", "linux", "arm64", strings.Repeat("v", 33), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			image, err := json.Marshal(map[string]string{"os": tc.os, "architecture": tc.arch, "variant": tc.variant})
			if err != nil {
				t.Fatal(err)
			}
			if in := inspectImage(t, image); in.Platform != tc.want {
				t.Fatalf("platform = %q, want %q", in.Platform, tc.want)
			}
		})
	}
}
