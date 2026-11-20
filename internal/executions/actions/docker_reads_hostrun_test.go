// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

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
	return dockerPSRow(i, project, "/srv/stack")
}

// dockerPSRow is dockerPSLine with the working directory (column 9) given.
func dockerPSRow(i int, project, dir string) string {
	return strings.Join(dockerPSFields(i, project, dir), "\t")
}

func dockerPSFields(i int, project, dir string) []string {
	return []string{
		dockerID(i), fmt.Sprintf("svc-%03d", i), "registry.example/app:1.27", "running",
		"Up 2 hours (healthy)", fmt.Sprintf("0.0.0.0:%d->80/tcp", 8000+i),
		project, fmt.Sprintf("svc-%03d", i), dir, "2026-01-02 03:04:05 +0000 UTC",
	}
}

// dockerListCut is the raw byte bound of the awk row filter in docker_list.sh
// (max=524288). A row that would take the total past it is skipped whole; the
// script never cuts inside a row.
const dockerListCut = 524288

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

// docker ps lists the newest containers first, so the oversized row can sit in
// the middle. Only that row is skipped: the rows before it and the rows after
// it (which the filter must not stop at) are all read.
func TestDockerListThroughHostrunOversizedRowInMiddleKeepsLaterRows(t *testing.T) {
	const n = 300
	const huge = 150
	f := newFakeHost(t, "1")
	installDockerFake(t, f)
	var b strings.Builder
	for i := 0; i < n; i++ {
		project := projectFor(i)
		if i == huge {
			project = strings.Repeat("L", 2<<20)
		}
		b.WriteString(dockerPSLine(i, project) + "\n")
	}
	writeDockerFixture(t, f, "ps", []byte(b.String()))
	r := runDockerRead(t, "docker.list", f.bin+":/usr/bin:/bin", `{}`)
	requireOneBoundedResult(t, r)
	l, err := dockerhost.ParseList(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Containers) != n-1 {
		t.Fatalf("%d containers, want %d: only the oversized row is skipped", len(l.Containers), n-1)
	}
	names := map[string]bool{}
	for _, c := range l.Containers {
		names[c.Name] = true
	}
	if names[fmt.Sprintf("svc-%03d", huge)] {
		t.Fatalf("the oversized row svc-%03d is in the list", huge)
	}
	for _, i := range []int{0, huge - 1, huge + 1, n - 1} {
		if name := fmt.Sprintf("svc-%03d", i); !names[name] {
			t.Fatalf("%s is hidden by the oversized row before it", name)
		}
	}
}

// A 2 MiB Compose label of "ü" (2-byte characters) makes its row too big for
// the bound. The awk filter skips that row whole, so no character is ever cut
// and the parser accepts the payload; the 299 rows before it stay readable.
func TestDockerListThroughHostrunOversizedMultiByteLabelDropsOnlyThatRow(t *testing.T) {
	const n = 300
	f := newFakeHost(t, "1")
	installDockerFake(t, f)
	var b strings.Builder
	for i := 0; i < n-1; i++ {
		b.WriteString(dockerPSLine(i, projectFor(i)) + "\n")
	}
	row := dockerPSRow(n-1, strings.Repeat("ü", 1<<20), "/srv/stack")
	// Precondition: the row alone does not fit in what is left of the bound,
	// so the filter must skip it.
	if b.Len()+len(row)+1 <= dockerListCut {
		t.Fatalf("fixture fits the bound: %d bytes, bound %d", b.Len()+len(row)+1, dockerListCut)
	}
	b.WriteString(row + "\n")
	writeDockerFixture(t, f, "ps", []byte(b.String()))
	r := runDockerRead(t, "docker.list", f.bin+":/usr/bin:/bin", `{}`)
	requireOneBoundedResult(t, r)
	l, err := dockerhost.ParseList(r.Result)
	if err != nil {
		t.Fatalf("one oversized non-ASCII label must not empty the list: %v", err)
	}
	if len(l.Containers) != n-1 {
		t.Fatalf("%d containers, want the %d before the cut row", len(l.Containers), n-1)
	}
	for _, c := range l.Containers {
		if c.Name == fmt.Sprintf("svc-%03d", n-1) {
			t.Fatalf("the cut row svc-%03d is in the list", n-1)
		}
	}
}

// When the row's working directory (column 9) or creation time (column 10)
// is the part that crosses the bound, the whole last row is skipped. A byte
// cut would leave a 9-field row with a truncated directory, or a 10-field row
// with a truncated creation time, which the parser would accept.
func TestDockerListThroughHostrunCutInLastColumnsDropsTheRow(t *testing.T) {
	const n = 300
	cases := []struct {
		name string
		// dirLen returns the working-directory length for a cut at offset
		// k bytes into that column.
		dirLen func(k int) int
	}{
		{"cut in column 9", func(k int) int { return k + 100 }},
		{"cut in column 10", func(k int) int { return k - 3 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeHost(t, "1")
			installDockerFake(t, f)
			var b strings.Builder
			for i := 0; i < n-1; i++ {
				b.WriteString(dockerPSLine(i, projectFor(i)) + "\n")
			}
			// Offset of the working directory in the stream: all earlier rows
			// plus the first eight columns and their tabs.
			head := strings.Join(dockerPSFields(n-1, "", "")[:8], "\t") + "\t"
			k := dockerListCut - (b.Len() + len(head))
			dir := "/" + strings.Repeat("d", tc.dirLen(k)-1)
			b.WriteString(dockerPSRow(n-1, "stack-01", dir) + "\n")
			writeDockerFixture(t, f, "ps", []byte(b.String()))
			r := runDockerRead(t, "docker.list", f.bin+":/usr/bin:/bin", `{}`)
			requireOneBoundedResult(t, r)
			l, err := dockerhost.ParseList(r.Result)
			if err != nil {
				t.Fatal(err)
			}
			if len(l.Containers) != n-1 {
				t.Fatalf("%d containers, want the %d before the cut row", len(l.Containers), n-1)
			}
			for _, c := range l.Containers {
				if c.Name == fmt.Sprintf("svc-%03d", n-1) {
					t.Fatalf("the cut row is in the list with dir %q, created %v", c.Dir, c.Created)
				}
				if c.Dir != "/srv/stack" && c.Dir != "" {
					t.Fatalf("container %s has a truncated dir %q", c.Name, c.Dir)
				}
			}
		})
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
	l, err := dockerhost.ParseLogs(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if l.Phase != "done" || l.Container != "web-1" || l.State != "running" {
		t.Fatalf("phase=%s container=%q state=%q", l.Phase, l.Container, l.State)
	}
	// The parsed lines are what the UI shows: no control byte (ESC, NUL, BEL,
	// DEL and the rest) and no invalid UTF-8 may survive the parser.
	for i, line := range l.Lines {
		if !utf8.ValidString(line) {
			t.Fatalf("line %d is not valid UTF-8: %q", i, line)
		}
		for _, c := range line {
			if c < 0x20 && c != '\t' || c == 0x7f || (c >= 0x80 && c <= 0x9f) {
				t.Fatalf("line %d has control rune %#x: %.80q", i, c, line)
			}
		}
	}
	if len(l.Lines) != 100 || !strings.Contains(l.Lines[99], "line 099") || !strings.Contains(l.Lines[0], "line 000") {
		t.Fatalf("%d lines; first %.60q, last %.60q", len(l.Lines), l.Lines[0], l.Lines[len(l.Lines)-1])
	}
}

// A 2 MiB log line with no newline after 99 normal lines: each line is cut to
// 2 KiB before the last 100 are kept, so the huge line arrives as a 2 KiB line
// and the result stays one bounded document. The parser keeps the 100 lines.
func TestDockerLogsThroughHostrunHugeUnterminatedLineIsCut(t *testing.T) {
	f := newFakeHost(t, "1")
	installDockerFake(t, f)
	var b strings.Builder
	for i := 0; i < 99; i++ {
		fmt.Fprintf(&b, "2026-01-02T03:04:05.000000000Z line %03d\n", i)
	}
	b.WriteString("2026-01-02T03:04:05.000000000Z " + strings.Repeat("X", 2<<20))
	writeDockerFixture(t, f, "logs", []byte(b.String()))
	writeDockerFixture(t, f, "ps", nil)
	r := runDockerRead(t, "docker.logs", f.bin+":/usr/bin:/bin", `{"container":"web-1"}`)
	requireOneBoundedResult(t, r)
	l, err := dockerhost.ParseLogs(r.Result)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Lines) != 100 || !strings.Contains(l.Lines[98], "line 098") {
		t.Fatalf("%d lines; line 98 = %.60q", len(l.Lines), l.Lines[len(l.Lines)-2])
	}
	if last := l.Lines[99]; len(last) > 2048 || !strings.HasPrefix(last, "2026-01-02T03:04:05") || !strings.Contains(last, "XXXX") {
		t.Fatalf("huge line not cut to 2 KiB: %d bytes", len(last))
	}
}

// docker.inspect with a 600 KiB mount source: the inspect document is cut at
// 512 KiB, so its JSON is truncated. The script still returns one bounded
// document, and the parser refuses the truncated inspect as a whole instead
// of returning a partial mount list.
func TestDockerInspectThroughHostrunTruncatedInspectIsRefused(t *testing.T) {
	f := newFakeHost(t, "1")
	installDockerFake(t, f)
	inspect := dockerInspectDoc(map[string]any{
		"Type": "bind", "Name": "", "Source": strings.Repeat("s", 600<<10), "Destination": "/data", "RW": true,
	})
	ib, err := json.Marshal(inspect)
	if err != nil {
		t.Fatal(err)
	}
	if len(ib) <= 512<<10 {
		t.Fatalf("fixture %d bytes does not exceed the 512 KiB inspect cut", len(ib))
	}
	writeDockerFixture(t, f, "inspect", ib)
	writeDockerFixture(t, f, "image", []byte(`{}`))
	r := runDockerRead(t, "docker.inspect", f.bin+":/usr/bin:/bin", `{"container":"web-1"}`)
	requireOneBoundedResult(t, r)
	if _, err := dockerhost.ParseInspect(r.Result); !errors.Is(err, dockerhost.ErrInspectFormat) {
		t.Fatalf("truncated inspect: err %v, want ErrInspectFormat", err)
	}
}

// docker.inspect with an image document over the 64 KiB image cut: the cut
// image JSON does not parse, so the parser keeps the container and its
// mounts, and drops the image fields that were only in the cut part.
func TestDockerInspectThroughHostrunTruncatedImageKeepsContainer(t *testing.T) {
	f := newFakeHost(t, "1")
	installDockerFake(t, f)
	ib, err := json.Marshal(dockerInspectDoc(map[string]any{"Type": "bind", "Source": "/srv/data", "Destination": "/data", "RW": true}))
	if err != nil {
		t.Fatal(err)
	}
	digests := make([]string, 0, 2000)
	for i := 0; i < 2000; i++ {
		digests = append(digests, "registry.example/app@"+dockerHostrunDigest)
	}
	image := map[string]any{"id": dockerHostrunImageID, "created": "2026-01-01T00:00:00Z", "os": "linux", "architecture": "amd64",
		"variant": "", "repo_digests": digests,
		"descriptor": map[string]any{"digest": dockerHostrunDigest, "mediaType": "application/vnd.docker.distribution.manifest.v2+json"}}
	imb, err := json.Marshal(image)
	if err != nil {
		t.Fatal(err)
	}
	if len(imb) <= 64<<10 {
		t.Fatalf("image fixture %d bytes does not exceed the 64 KiB image cut", len(imb))
	}
	writeDockerFixture(t, f, "inspect", ib)
	writeDockerFixture(t, f, "image", imb)
	r := runDockerRead(t, "docker.inspect", f.bin+":/usr/bin:/bin", `{"container":"web-1"}`)
	requireOneBoundedResult(t, r)
	in, err := dockerhost.ParseInspect(r.Result)
	if err != nil {
		t.Fatalf("a cut image must not fail the inspect: %v", err)
	}
	if in.Phase != "done" || in.FullID != dockerHostrunID || len(in.Mounts) != 1 {
		t.Fatalf("phase=%s full=%q mounts=%d", in.Phase, in.FullID, len(in.Mounts))
	}
	if len(in.Digests) != 0 || in.ImageDigestPlatform != "" || in.ImageDigestIndex != "" || in.ImageCreated != "" {
		t.Fatalf("image fields from a cut document: digests=%d platform=%q index=%q created=%v",
			len(in.Digests), in.ImageDigestPlatform, in.ImageDigestIndex, in.ImageCreated)
	}
}

// dockerInspectDoc is a small docker.inspect document with one mount, the
// shape the script's inspect template produces.
func dockerInspectDoc(mount map[string]any) map[string]any {
	return map[string]any{
		"id": dockerHostrunID, "name": "/web-1", "image": "registry.example/app:1.27", "image_id": dockerHostrunImageID,
		"created": "2026-01-02T03:04:05.123456789Z",
		"state": map[string]any{"Status": "running", "ExitCode": 0, "StartedAt": "2026-01-02T03:04:06Z",
			"FinishedAt": "0001-01-01T00:00:00Z"},
		"restarts": 0, "restart_policy": "unless-stopped", "mounts": []map[string]any{mount},
		"ports": map[string]any{}, "networks": map[string]any{},
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
