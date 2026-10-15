// SPDX-License-Identifier: AGPL-3.0-or-later

package dockerhost

import (
	"encoding/base64"
	"os"
	"strconv"
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
		id + "\trlm\timg\u200f\trunning\tUp\t\t\t\t",                // right-to-left mark
		id + "\tc1\timg\trunning\tUp\u0085\t\t\t\t",                 // C1 control (NEL)
		id + "\tsep\timg\trunning\tUp\t\u2028\t\t\t",                // line separator in the ports
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

// testdata/docker29-logs.json is docker.logs on Docker 29.8.2 for a
// container that wrote 150 lines, then a line with invalid UTF-8 and one
// with an ANSI colour escape and a right-to-left override.
func TestParseRealLogs(t *testing.T) {
	b, err := os.ReadFile("testdata/docker29-logs.json")
	if err != nil {
		t.Fatal(err)
	}
	l, err := ParseLogs(b)
	if err != nil {
		t.Fatal(err)
	}
	if l.Container != "talker" || l.State != "running" || len(l.Lines) != maxLogLines {
		t.Fatalf("%s %s %d", l.Container, l.State, len(l.Lines))
	}
	last := l.Lines[len(l.Lines)-1]
	if !strings.HasSuffix(last, "warn: über \uFFFD[31mred\uFFFD[0m and \uFFFDgnp.exe") || !strings.HasSuffix(l.Lines[0], " line 53 ok") {
		t.Fatalf("first %q last %q", l.Lines[0], last)
	}
}

func TestParseLogsIsDefensive(t *testing.T) {
	long := strings.Repeat("x", 5000)
	res := `{"format":"docker-logs-v1","phase":"done","container":"-bad","state":"` + enc("zombie") + `","logs":"` +
		base64.StdEncoding.EncodeToString([]byte(long+"\r\n\xff\x00tail\u0085\u200f\n")) + `"}`
	l, err := ParseLogs([]byte(res))
	if err != nil {
		t.Fatal(err)
	}
	if l.Container != "" || l.State != "" || len(l.Lines) != 2 || len(l.Lines[0]) != maxLogLineLen || l.Lines[1] != "\uFFFD\uFFFDtail\uFFFD\uFFFD" {
		t.Fatalf("%+v", l)
	}
	l, err = ParseLogs([]byte(`{"format":"docker-logs-v1","phase":"done","container":"c","state":"","logs":""}`))
	if err != nil || len(l.Lines) != 0 {
		t.Fatalf("empty logs %+v %v", l, err)
	}
	for _, bad := range []string{`{"format":"docker-ps-v1","phase":"done"}`, `{"format":"docker-logs-v1","phase":"done","logs":"%%"}`} {
		if _, err := ParseLogs([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestParseRealControl(t *testing.T) {
	b, err := os.ReadFile("testdata/docker29-start.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseControl(b)
	if err != nil || c.Verb != "start" || c.Container != "plain" || c.Exit != 0 || c.Before != "exited" || c.After != "running" ||
		len(c.Output) != 1 || c.Output[0] != "plain" {
		t.Fatalf("%+v %v", c, err)
	}
	c, err = ParseControl([]byte(`{"format":"docker-control-v1","phase":"done","verb":"rm","container":"-x","exit":999,"before":"` + enc("zombie") +
		`","after":"%%","output":"` + enc("a\x1b[2Jb\n") + `"}`))
	if err != nil || c.Verb != "" || c.Container != "" || c.Exit != 0 || c.Before != "" || c.After != "" || c.Output[0] != "a\uFFFD[2Jb" {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := ParseControl([]byte(`{"format":"docker-logs-v1","phase":"done"}`)); err == nil {
		t.Fatal("other format accepted")
	}
	c, _ = ParseControl([]byte(`{"format":"docker-control-v1","phase":"precheck","reason":"no such container"}`))
	if c.Reason != "no such container" {
		t.Fatalf("%+v", c)
	}
}

func TestParseImageUpdates(t *testing.T) {
	a, b := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	lines := "reg.example:5000/app:1\tcurrent\t" + a + "\t\n" +
		"nginx:1.27\tupdate\t" + b + "\tlocal " + a + "\n" +
		"private/x:1\tunknown\t\tauthentication required\n" +
		"busybox@" + a + "\tpinned\t\tthe image is pinned by digest\n" +
		"evil\u202e:1\tcurrent\t" + a + "\t\n" + // bidi in the name: dropped
		"x:1\tupdate\tnot-a-digest\t\n" + // no valid digest: unknown
		"y:1\tmaybe\t\t\n" // unknown status: dropped
	u, err := ParseImageUpdates([]byte(`{"format":"docker-updates-v1","phase":"done","images":7,"lines":"` + enc(lines) + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Images) != 5 || u.Updates != 1 || u.Images[1].Status != "update" || u.Images[1].Remote != b ||
		u.Images[2].Note != "authentication required" || u.Images[4].Status != "unknown" || u.Images[4].Remote != "" {
		t.Fatalf("%+v", u)
	}
	if _, err := ParseImageUpdates([]byte(`{"format":"docker-ps-v1","phase":"done"}`)); err == nil {
		t.Fatal("other format accepted")
	}
	u, _ = ParseImageUpdates([]byte(`{"format":"docker-updates-v1","phase":"precheck","reason":"curl is not installed"}`))
	if u.Reason != "curl is not installed" {
		t.Fatalf("%+v", u)
	}
}

func TestParseRealComposeUpdate(t *testing.T) {
	b, err := os.ReadFile("testdata/docker29-compose.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseComposeUpdate(b)
	if err != nil || c.Project != "site" || len(c.Before) != 3 || len(c.After) != 3 || c.Verdict != "WARNING" ||
		len(c.Findings) != 1 || !strings.Contains(c.Findings[0], "site-web-1 (unhealthy)") {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestComposePostflightVerdicts(t *testing.T) {
	list := func(lines ...string) string { return enc(strings.Join(lines, "\n")) }
	res := func(pull, up int, before, after string) []byte {
		return []byte(`{"format":"compose-update-v1","phase":"done","project":"p","pull_exit":` + strconv.Itoa(pull) + `,"up_exit":` +
			strconv.Itoa(up) + `,"before":"` + before + `","after":"` + after + `"}`)
	}
	web := "web\tp-web-1\trunning\tUp 1 hour (healthy)\t0.0.0.0:80->80/tcp\tnginx:1"
	webNew := "web\tp-web-1\trunning\tUp 5 seconds (healthy)\t0.0.0.0:80->80/tcp\tnginx:2"
	db := "db\tp-db-1\trunning\tUp 1 hour\t\tpostgres:16"
	cases := []struct {
		name, verdict, finding string
		raw                    []byte
	}{
		{"clean", "OK", "", res(0, 0, list(web, db), list(webNew, db))},
		{"pull failed", "FAILED", "pull exited with 1", res(1, -1, list(web, db), list(web, db))},
		{"up failed", "FAILED", "up -d exited with 2", res(0, 2, list(web, db), list(webNew, db))},
		{"fewer running", "FAILED", "2 containers ran before, 1 after", res(0, 0, list(web, db), list(webNew, "db\tp-db-1\texited\tExited (1)\t\tpostgres:16"))},
		{"healthy became unhealthy", "FAILED", "was healthy before", res(0, 0, list(web, db), list("web\tp-web-1\trunning\tUp 5 seconds (unhealthy)\t0.0.0.0:80->80/tcp\tnginx:2", db))},
		{"port gone", "WARNING", "published ports", res(0, 0, list(web, db), list("web\tp-web-1\trunning\tUp 5 seconds (healthy)\t\tnginx:2", db))},
		{"count changed", "WARNING", "2 containers before, 3 after", res(0, 0, list(web, db), list(webNew, db, "cache\tp-cache-1\trunning\tUp 2 seconds\t\tredis:7"))},
	}
	for _, tc := range cases {
		c, err := ParseComposeUpdate(tc.raw)
		if err != nil || c.Verdict != tc.verdict || (tc.finding != "" && !strings.Contains(strings.Join(c.Findings, "|"), tc.finding)) {
			t.Errorf("%s: %+v %v", tc.name, c, err)
		}
	}
	c, _ := ParseComposeUpdate([]byte(`{"format":"compose-update-v1","phase":"precheck","reason":"no containers of this Compose project"}`))
	if c.Verdict != "FAILED" || c.Reason == "" {
		t.Fatalf("%+v", c)
	}
}
