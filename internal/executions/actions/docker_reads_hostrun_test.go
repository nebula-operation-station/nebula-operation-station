// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
)

// The four Docker read actions, run through the executor's own path:
// hostrun.Attached over SSH, so the one-JSON-document rule and MaxResult
// are enforced by the real classifier, and the result is parsed by the
// dockerhost parser the server uses. The fake docker prints fixture files
// from the host directory, so each test controls the exact bytes.

const (
	dockerHostrunExecution = "8a6e0804-2bd0-4f6a-8b1e-6d2f1c3a4b5c"
	dockerHostrunID        = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	dockerHostrunImageID   = "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	dockerHostrunDigest    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	// dockerWeirdLabel is a valid UTF-8 Compose project name with a quote,
	// a backslash and non-ASCII letters: the characters that break a
	// hand-written JSON string.
	dockerWeirdLabel = `proj "ü" \x`
)

// installDockerFake writes a docker on the fake host's PATH. The subcommand
// the script uses prints the matching fixture file; an inspect with the
// full-ID or image format prints the ID values the script expects.
func installDockerFake(t *testing.T, f *fakeHost) {
	t.Helper()
	f.write(t, "docker", `echo "$@" >> "`+f.calls+`"
case "$1" in
version) echo 27.3.1 ;;
ps) cat "`+f.dir+`/ps" ;;
stats) cat "`+f.dir+`/stats" ;;
logs) cat "`+f.dir+`/logs" ;;
image) cat "`+f.dir+`/image" ;;
inspect) case "$5" in
  '{{.Id}}') echo `+dockerHostrunID+` ;;
  '{{.Image}}') echo `+dockerHostrunImageID+` ;;
  '{{.State.Status}}') echo running ;;
  *) cat "`+f.dir+`/inspect" ;;
  esac ;;
esac`)
}

// runDockerRead runs the action's script with params through hostrun.Attached.
// path is the PATH the script sees ahead of the real system tools.
func runDockerRead(t *testing.T, action string, path string, params string) hostrun.Result {
	t.Helper()
	a, ok := Lookup(action)
	if !ok {
		t.Fatalf("%s is not registered", action)
	}
	script := "PATH='" + path + "'; export PATH\n" + string(a.Script)
	r, err := hostrun.Attached(context.Background(), hostrunClient(t), dockerHostrunExecution, []byte(params), []byte(script), a.Timeout)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// writeDockerFixture writes a fixture file the fake docker prints.
func writeDockerFixture(t *testing.T, f *fakeHost, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(f.dir+"/"+name, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// requireOneBoundedResult asserts what the executor needs from every
// result: class success, exit 0, and a result within MaxResult.
func requireOneBoundedResult(t *testing.T, r hostrun.Result) {
	t.Helper()
	if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
		t.Fatalf("class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
	}
	if len(r.Result) == 0 || len(r.Result) > hostrun.MaxResult {
		t.Fatalf("result %d bytes, limit %d", len(r.Result), hostrun.MaxResult)
	}
}

func dockerID(i int) string { return fmt.Sprintf("%064x", i+1) }

// dockerPSLine is one docker.list row in the script's column order: ID,
// names, image, state, status, ports, Compose project, service, working
// directory, creation time.
func dockerPSLine(i int, project string) string {
	return strings.Join([]string{
		dockerID(i), fmt.Sprintf("svc-%03d", i), "registry.example/app:1.27", "running",
		"Up 2 hours (healthy)", fmt.Sprintf("0.0.0.0:%d->80/tcp", 8000+i),
		project, fmt.Sprintf("svc-%03d", i), "/srv/stack", "2026-01-02 03:04:05 +0000 UTC",
	}, "\t")
}

func projectFor(i int) string {
	switch {
	case i%5 == 0:
		return "" // standalone container
	case i%11 == 0:
		return dockerWeirdLabel
	}
	return fmt.Sprintf("stack-%02d", i%7)
}

func TestDockerListThroughHostrunReadsAllContainers(t *testing.T) {
	const n = 300
	f := newFakeHost(t, "1")
	installDockerFake(t, f)
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(dockerPSLine(i, projectFor(i)) + "\n")
	}
	writeDockerFixture(t, f, "ps", []byte(b.String()))
	r := runDockerRead(t, "docker.list", f.bin+":/usr/bin:/bin", `{}`)
	requireOneBoundedResult(t, r)
	l, err := dockerhost.ParseList(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if !l.Present || l.Phase != "done" || len(l.Containers) != n {
		t.Fatalf("present=%v phase=%s containers=%d, want %d", l.Present, l.Phase, len(l.Containers), n)
	}
	byName := map[string]dockerhost.Container{}
	for _, c := range l.Containers {
		byName[c.Name] = c
	}
	// A project name that is not a valid Compose identifier is dropped by
	// the parser, but the container itself is still read.
	if weird := byName["svc-011"]; weird.Project != "" || weird.FullID != dockerID(11) || weird.Ports != "0.0.0.0:8011->80/tcp" {
		t.Fatalf("container svc-011 = %+v", weird)
	}
	if ok := byName["svc-012"]; ok.Project != "stack-05" || ok.Service != "svc-012" || ok.Dir != "/srv/stack" {
		t.Fatalf("container svc-012 = %+v", ok)
	}
}

// A single container with a 2 MiB label must not push the result past
// MaxResult or make it two documents: the containers before it are kept,
// the cut row is left out, and the result stays one bounded document.
func TestDockerListThroughHostrunOversizedLabelStaysBounded(t *testing.T) {
	const n = 300
	f := newFakeHost(t, "1")
	installDockerFake(t, f)
	var b strings.Builder
	for i := 0; i < n-1; i++ {
		b.WriteString(dockerPSLine(i, projectFor(i)) + "\n")
	}
	huge := dockerPSLine(n-1, strings.Repeat("L", 2<<20))
	b.WriteString(huge + "\n")
	writeDockerFixture(t, f, "ps", []byte(b.String()))
	r := runDockerRead(t, "docker.list", f.bin+":/usr/bin:/bin", `{}`)
	requireOneBoundedResult(t, r)
	l, err := dockerhost.ParseList(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Containers) != n-1 {
		t.Fatalf("%d containers, want the %d before the oversized row", len(l.Containers), n-1)
	}
}

// A host without Docker is a success with "present":false: the script
// stops at command -v before any docker call, and PATH holds no docker.
func TestDockerListThroughHostrunWithoutDocker(t *testing.T) {
	f := newFakeHost(t, "1")
	r := runDockerRead(t, "docker.list", f.bin, `{}`)
	requireOneBoundedResult(t, r)
	l, err := dockerhost.ParseList(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if l.Present || l.Phase != "done" || len(l.Containers) != 0 {
		t.Fatalf("present=%v phase=%s containers=%d", l.Present, l.Phase, len(l.Containers))
	}
}

// Docker stats for 300 running containers: one bounded result, keyed by
// the full container ID.
func TestDockerStatsThroughHostrunKeysByFullID(t *testing.T) {
	const n = 300
	f := newFakeHost(t, "1")
	installDockerFake(t, f)
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, `{"id":%q,"name":"svc-%03d","cpu":"%d.25%%","mem":"12.5MiB / 1.5GiB","memp":"0.80%%"}`+"\n", dockerID(i), i, i%9)
	}
	writeDockerFixture(t, f, "stats", []byte(b.String()))
	r := runDockerRead(t, "docker.stats", f.bin+":/usr/bin:/bin", `{}`)
	requireOneBoundedResult(t, r)
	s, err := dockerhost.ParseStats(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Present || len(s.Containers) != n {
		t.Fatalf("present=%v containers=%d, want %d", s.Present, len(s.Containers), n)
	}
	if s.Containers[0].FullID != dockerID(0) || s.Containers[n-1].FullID != dockerID(n-1) {
		t.Fatalf("keys %q .. %q", s.Containers[0].FullID, s.Containers[n-1].FullID)
	}
}

// One stats row of 2 MiB after 300 normal rows: the executor must still see
// one document within MaxResult, and the 300 rows before the oversized row.
func TestDockerStatsThroughHostrunOversizedRowStaysBounded(t *testing.T) {
	const n = 300
	f := newFakeHost(t, "1")
	installDockerFake(t, f)
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, `{"id":%q,"name":"svc-%03d","cpu":"0.10%%","mem":"1MiB / 2GiB","memp":"0.05%%"}`+"\n", dockerID(i), i)
	}
	fmt.Fprintf(&b, `{"id":%q,"name":"%s","cpu":"0.10%%","mem":"1MiB / 2GiB","memp":"0.05%%"}`+"\n", dockerID(n), strings.Repeat("N", 2<<20))
	writeDockerFixture(t, f, "stats", []byte(b.String()))
	r := runDockerRead(t, "docker.stats", f.bin+":/usr/bin:/bin", `{}`)
	requireOneBoundedResult(t, r)
	s, err := dockerhost.ParseStats(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Containers) != n {
		t.Fatalf("%d containers, want the %d before the oversized row", len(s.Containers), n)
	}
}

// docker.logs with 100 lines of 8 KiB, each with ANSI sequences, NUL and
// other control bytes, and invalid UTF-8. The result is one bounded
// document with no raw control byte, and the parser reads the last 100
// lines, not the first ones.
func TestDockerLogsThroughHostrunHostileOutput(t *testing.T) {
	f := newFakeHost(t, "1")
	installDockerFake(t, f)
	const chunk = "\x1b[1;31mE\x1b[0m\x01\x07\x7f\xc3\x28\xff\x00"
	var b strings.Builder
	for i := 0; i < 100; i++ {
		head := fmt.Sprintf("2026-01-02T03:04:05.000000000Z line %03d ", i)
		b.WriteString(head + strings.Repeat(chunk, (8192-len(head))/len(chunk)) + "\n")
	}
	writeDockerFixture(t, f, "logs", []byte(b.String()))
	writeDockerFixture(t, f, "ps", nil)
	r := runDockerRead(t, "docker.logs", f.bin+":/usr/bin:/bin", `{"container":"web-1"}`)
	requireOneBoundedResult(t, r)
	for _, c := range r.Result {
		if c < 0x20 && c != '\n' || c == 0x7f {
			t.Fatalf("result has raw control byte %#x", c)
		}
	}
	l, err := dockerhost.ParseLogs(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if l.Phase != "done" || l.Container != "web-1" || l.State != "running" {
		t.Fatalf("phase=%s container=%q state=%q", l.Phase, l.Container, l.State)
	}
	if len(l.Lines) != 100 || !strings.Contains(l.Lines[99], "line 099") || !strings.Contains(l.Lines[0], "line 000") {
		t.Fatalf("%d lines; first %.60q, last %.60q", len(l.Lines), l.Lines[0], l.Lines[len(l.Lines)-1])
	}
}

// docker.inspect of a container with 64 mounts and 32 networks: one
// bounded result, read in full by the parser.
func TestDockerInspectThroughHostrunReadsMountsAndNetworks(t *testing.T) {
	f := newFakeHost(t, "1")
	installDockerFake(t, f)
	mounts := make([]map[string]any, 0, 64)
	for i := 0; i < 64; i++ {
		mounts = append(mounts, map[string]any{"Type": "bind", "Name": "", "Source": fmt.Sprintf("/srv/data/%02d", i),
			"Destination": fmt.Sprintf("/data/%02d", i), "RW": i%2 == 0})
	}
	networks := map[string]any{}
	for i := 0; i < 32; i++ {
		networks[fmt.Sprintf("net-%02d", i)] = map[string]any{"IPAddress": fmt.Sprintf("172.18.0.%d", i+2), "GlobalIPv6Address": ""}
	}
	inspect := map[string]any{
		"id": dockerHostrunID, "name": "/web-1", "image": "registry.example/app:1.27", "image_id": dockerHostrunImageID,
		"created": "2026-01-02T03:04:05.123456789Z",
		"state": map[string]any{"Status": "running", "ExitCode": 0, "StartedAt": "2026-01-02T03:04:06Z",
			"FinishedAt": "0001-01-01T00:00:00Z", "Health": map[string]any{"Status": "healthy", "FailingStreak": 0}},
		"restarts": 0, "restart_policy": "unless-stopped", "mounts": mounts,
		"ports": map[string]any{}, "networks": networks,
	}
	ib, err := json.Marshal(inspect)
	if err != nil {
		t.Fatal(err)
	}
	image := map[string]any{"id": dockerHostrunImageID, "created": "2026-01-01T00:00:00Z", "os": "linux", "architecture": "amd64",
		"variant": "", "repo_digests": []string{"registry.example/app@" + dockerHostrunDigest},
		"descriptor": map[string]any{"digest": dockerHostrunDigest, "mediaType": "application/vnd.docker.distribution.manifest.v2+json"}}
	imb, err := json.Marshal(image)
	if err != nil {
		t.Fatal(err)
	}
	writeDockerFixture(t, f, "inspect", ib)
	writeDockerFixture(t, f, "image", imb)
	r := runDockerRead(t, "docker.inspect", f.bin+":/usr/bin:/bin", `{"container":"web-1"}`)
	requireOneBoundedResult(t, r)
	in, err := dockerhost.ParseInspect(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if in.Phase != "done" || in.FullID != dockerHostrunID || in.Container != "web-1" {
		t.Fatalf("phase=%s container=%q full=%q", in.Phase, in.Container, in.FullID)
	}
	if len(in.Mounts) != 64 || len(in.Networks) != 32 {
		t.Fatalf("%d mounts, %d networks; want 64 and 32", len(in.Mounts), len(in.Networks))
	}
}

// A container parameter that starts with "-" is refused by the script
// itself, not only by ValidParams: the result is a precheck failure and
// docker is never called.
func TestDockerReadScriptsRefuseDashContainerThroughHostrun(t *testing.T) {
	for _, action := range []string{"docker.logs", "docker.inspect"} {
		t.Run(action, func(t *testing.T) {
			f := newFakeHost(t, "1")
			installDockerFake(t, f)
			r := runDockerRead(t, action, f.bin+":/usr/bin:/bin", `{"container":"-f"}`)
			if r.Class != hostrun.ClassPrecheckFailed || r.ExitCode != hostrun.ExitPrecheckFailed {
				t.Fatalf("class %s, exit %d (%s)", r.Class, r.ExitCode, r.Detail)
			}
			if calls := f.readCalls(t); calls != "" {
				t.Fatalf("docker was called: %q", calls)
			}
		})
	}
}
