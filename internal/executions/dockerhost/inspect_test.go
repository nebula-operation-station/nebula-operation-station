// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"encoding/base64"
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
	if in.Container != "full" || in.Name != "full" || in.ID != "b46feb47000b" || in.Image != "nos-test/sleeper:2" ||
		!strings.HasPrefix(in.ImageID, "sha256:1c39e3d3") || len(in.Digests) != 1 ||
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
