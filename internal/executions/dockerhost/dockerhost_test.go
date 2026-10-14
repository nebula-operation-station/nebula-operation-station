// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func enc(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func result(version, lines string) []byte {
	return []byte(`{"format":"docker-ps-v1","phase":"done","present":true,"version":"` + enc(version) + `","containers":"` + enc(lines) + `"}`)
}

// testdata/docker29.json is docker.list on Docker 29.8.2 with four
// containers: created, exited (3), running, running and unhealthy in a
// Compose project with a published port.
func TestParseRealOutput(t *testing.T) {
	b, err := os.ReadFile("testdata/docker29.json")
	if err != nil {
		t.Fatal(err)
	}
	l, err := ParseList(b)
	if err != nil {
		t.Fatal(err)
	}
	if !l.Present || l.Version != "29.8.2" || len(l.Containers) != 4 {
		t.Fatalf("%+v", l)
	}
	// Standalone containers first (empty project), by name.
	if l.Containers[0].Name != "done" || l.Containers[3].Name != "web" {
		t.Fatalf("order %+v", l.Containers)
	}
	web := l.Containers[3]
	if web.ID != "c1bfa1cc4a9a" || web.Project != "site" || web.Service != "web" || web.Dir != "/srv/site" ||
		web.Health != "unhealthy" || web.Ports != "127.0.0.1:8080->80/tcp" || !web.Running() {
		t.Fatalf("web %+v", web)
	}
	s := l.Summary()
	if s.Total != 4 || s.Running != 2 || s.Stopped != 2 || s.Unhealthy != 1 || len(s.Projects) != 1 || s.Projects[0] != "site" {
		t.Fatalf("summary %+v", s)
	}
}

func TestParseDropsWhatDoesNotFit(t *testing.T) {
	id := strings.Repeat("ab", 32)
	lines := strings.Join([]string{
		id + "\tok\timg:1\trunning\tUp 1 hour (healthy)\t\t\t\t",
		id + "\t-opt\timg\trunning\tUp\t\t\t\t",                     // name
		"XYZ\tbadid\timg\trunning\tUp\t\t\t\t",                      // id
		id + "\tweird\timg\tzombie\tUp\t\t\t\t",                     // state
		id + "\tctl\timg\u202e\trunning\tUp\t\t\t\t",                // bidi override in the image
		id + "\tfew\timg\trunning",                                  // field count
		id + "\tproj\timg\texited\tExited (0)\t\tBad Project\tx\t/", // project dropped, container kept
	}, "\n")
	l, err := ParseList(result("27.0", lines))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Containers) != 2 || l.Containers[0].Name != "ok" || l.Containers[0].Health != "healthy" ||
		l.Containers[1].Name != "proj" || l.Containers[1].Project != "" || l.Containers[1].Service != "" {
		t.Fatalf("%+v", l.Containers)
	}
}

func TestParseOtherResults(t *testing.T) {
	l, err := ParseList([]byte(`{"format":"docker-ps-v1","phase":"done","present":false}`))
	if err != nil || l.Present || len(l.Containers) != 0 {
		t.Fatalf("%+v %v", l, err)
	}
	l, err = ParseList([]byte(`{"format":"docker-ps-v1","phase":"precheck","reason":"the Docker daemon is not reachable"}`))
	if err != nil || l.Phase != "precheck" || l.Reason == "" {
		t.Fatalf("%+v %v", l, err)
	}
	l, _ = ParseList([]byte(`{"format":"docker-ps-v1","phase":"precheck","reason":"a\nb"}`))
	if l.Reason != "" {
		t.Fatalf("reason with a newline kept: %q", l.Reason)
	}
	for _, bad := range []string{`{}`, `{"format":"systemd-units-v1","phase":"done"}`, `{"format":"docker-ps-v1","phase":"later"}`,
		`{"format":"docker-ps-v1","phase":"done","present":true,"containers":"%%%"}`, `not json`} {
		if _, err := ParseList([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestParseCapsTheList(t *testing.T) {
	id := strings.Repeat("0", 64)
	var b strings.Builder
	for i := 0; i < maxContainers+10; i++ {
		b.WriteString(id + "\tc\timg\trunning\tUp\t\t\t\t\n")
	}
	l, err := ParseList(result("27.0", b.String()))
	if err != nil || len(l.Containers) != maxContainers {
		t.Fatalf("%d %v", len(l.Containers), err)
	}
}
