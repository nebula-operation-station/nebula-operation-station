// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
)

// docker.check_updates and docker.update_preview through the executor's
// own path: hostrun.Attached over SSH, so the classifier decides the class
// and the one-JSON-document rule, and the result is read by the dockerhost
// parser the server uses. docker, curl and the Compose fake are local
// fakes, so no registry is ever reached.

// chkPattern is the state of image i by i%12: six current, two
// update, then a 401, a 404, a timeout and a digest of the wrong form.
var chkPattern = [12]int{chkCurrent, chkCurrent, chkCurrent, chkCurrent, chkCurrent, chkCurrent,
	chkUpdate, chkUpdate, chkAuth, chkNotFound, chkTimeout, chkBadDigest}

const (
	chkCurrent = iota
	chkUpdate
	chkAuth
	chkNotFound
	chkTimeout
	chkBadDigest
)

// chkWant is what the parser must read for one image.
type chkWant struct{ status, remote, note string }

// chkDigest is a well-formed digest for n.
func chkDigest(n int) string { return fmt.Sprintf("sha256:%064x", n) }

// writeChkFakes writes the docker and curl fakes of check_updates. Their
// state is read from three tables in dir: ps.txt (the image of every
// container), local.txt (image and its RepoDigests) and reg.txt (registry
// key, HTTP code, digest). Keys are compared through ENVIRON, so no awk
// escape processing touches a hostile image name.
func writeChkFakes(t *testing.T, f *fakeHost) {
	t.Helper()
	f.write(t, "docker", `case "$1" in
version) echo 27.3.1 ;;
ps) cat "`+f.dir+`/ps.txt" ;;
image) for last; do :; done; K="$last" awk -F'\t' '$1==ENVIRON["K"]{print $2; exit}' "`+f.dir+`/local.txt" ;;
*) exit 1 ;;
esac`)
	f.write(t, "curl", `for u; do :; done
case "$u" in
https://auth.test/token) echo '{}'; exit 0 ;;
esac
rest=${u#https://}; host=${rest%%/v2/*}; rest=${rest#*/v2/}; repo=${rest%/manifests/*}; tag=${rest##*/manifests/}
line=$(K="$host|$repo|$tag" awk -F'\t' '$1==ENVIRON["K"]{print; exit}' "`+f.dir+`/reg.txt")
[ -n "$line" ] || exit 6
code=$(printf '%s' "$line" | cut -f2); dg=$(printf '%s' "$line" | cut -f3)
case "$code" in
timeout) exit 28 ;;
401) printf 'HTTP/2 401\r\nwww-authenticate: Bearer realm="https://auth.test/token",service="registry.test"\r\n\r\n' ;;
404) printf 'HTTP/2 404\r\n\r\n' ;;
*) printf 'HTTP/2 %s\r\ndocker-content-digest: %s\r\n\r\n' "$code" "$dg" ;;
esac`)
}

// runHostrunAction runs script over hostrun with PATH set to path in front
// of the unchanged script, as the existing hostrun tests do.
func runHostrunAction(t *testing.T, path string, script []byte, params string) hostrun.Result {
	t.Helper()
	pre := "PATH='" + path + "'; export PATH\n"
	r, err := hostrun.Attached(context.Background(), hostrunClient(t), dockerHostrunExecution, []byte(params), append([]byte(pre), script...), 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// requireNoRawControl fails if result holds a control byte other than the
// final newline, or is not valid UTF-8: the script must print JSON only.
func requireNoRawControl(t *testing.T, result []byte) {
	t.Helper()
	if !utf8.Valid(result) {
		t.Fatalf("the result is not valid UTF-8: %q", result)
	}
	for i, b := range result {
		if b < 0x20 && !(b == '\n' && i == len(result)-1) {
			t.Fatalf("raw control byte %#x at %d in %q", b, i, result)
		}
	}
}

// TestCheckUpdatesHostrunReadsEveryImageState: 200 running containers on
// 120 images, one state per image. The result is one document of class
// success below MaxResult, and the parser reads exactly the state the fake
// gives for each of the images the script reports (at most 50).
func TestCheckUpdatesHostrunReadsEveryImageState(t *testing.T) {
	f := newFakeHost(t, "1")
	writeChkFakes(t, f)
	var ps, local, reg strings.Builder
	want := map[string]chkWant{}
	for i := range 120 {
		ref := fmt.Sprintf("registry.test/team/svc%03d:1.0", i)
		key := fmt.Sprintf("registry.test|team/svc%03d|1.0", i)
		remote, old := chkDigest(i+1), chkDigest(i+0x1000)
		switch chkPattern[i%12] {
		case chkCurrent:
			fmt.Fprintf(&reg, "%s\t200\t%s\n", key, remote)
			fmt.Fprintf(&local, "%s\t%s@%s \n", ref, ref, remote)
			want[ref] = chkWant{"current", remote, ""}
		case chkUpdate:
			fmt.Fprintf(&reg, "%s\t200\t%s\n", key, remote)
			fmt.Fprintf(&local, "%s\t%s@%s \n", ref, ref, old)
			want[ref] = chkWant{"update", remote, "local " + old}
		case chkAuth:
			fmt.Fprintf(&reg, "%s\t401\t\n", key)
			fmt.Fprintf(&local, "%s\t%s@%s \n", ref, ref, remote)
			want[ref] = chkWant{"unknown", "", "authentication required"}
		case chkNotFound:
			fmt.Fprintf(&reg, "%s\t404\t\n", key)
			fmt.Fprintf(&local, "%s\t%s@%s \n", ref, ref, remote)
			want[ref] = chkWant{"unknown", "", "registry answered 404"}
		case chkTimeout:
			fmt.Fprintf(&reg, "%s\ttimeout\t\n", key)
			fmt.Fprintf(&local, "%s\t%s@%s \n", ref, ref, remote)
			want[ref] = chkWant{"unknown", "", "registry not reachable"}
		case chkBadDigest:
			fmt.Fprintf(&reg, "%s\t200\tsha256:abc\n", key)
			fmt.Fprintf(&local, "%s\t%s@%s \n", ref, ref, remote)
			want[ref] = chkWant{"unknown", "", "no digest in the answer"}
		}
	}
	for c := range 200 {
		fmt.Fprintf(&ps, "registry.test/team/svc%03d:1.0\n", c%120)
	}
	for name, body := range map[string]string{"ps.txt": ps.String(), "local.txt": local.String(), "reg.txt": reg.String()} {
		if err := os.WriteFile(filepath.Join(f.dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a, ok := Lookup("docker.check_updates")
	if !ok {
		t.Fatal("docker.check_updates missing")
	}
	r := runHostrunAction(t, f.bin+":/usr/bin:/bin", a.Script, "{}")
	if r.Class != hostrun.ClassSuccess {
		t.Fatalf("class %s (%s), result %q", r.Class, r.Detail, r.Result)
	}
	if len(r.Result) > hostrun.MaxResult {
		t.Fatalf("result of %d bytes is over MaxResult", len(r.Result))
	}
	res, err := dockerhost.ParseImageUpdates(r.Result)
	if err != nil {
		t.Fatalf("the parser refuses the result: %v", err)
	}
	if res.Phase != "done" || len(res.Images) != 50 {
		t.Fatalf("phase %q, %d images; want done and the 50 the script reports", res.Phase, len(res.Images))
	}
	seen := map[string]bool{}
	updates := 0
	for _, im := range res.Images {
		w, ok := want[im.Image]
		if !ok || seen[im.Image] {
			t.Fatalf("unexpected or repeated image %q", im.Image)
		}
		seen[im.Image] = true
		if im.Status != w.status || im.Remote != w.remote || im.Note != w.note {
			t.Errorf("%s: got %s %q %q, want %s %q %q", im.Image, im.Status, im.Remote, im.Note, w.status, w.remote, w.note)
		}
		if im.Status == "update" {
			updates++
		}
	}
	if res.Updates != updates {
		t.Fatalf("Updates %d, counted %d", res.Updates, updates)
	}
	// The first 50 images in sort order cover every state.
	if updates == 0 {
		t.Fatal("no update reached the parser")
	}
}

// TestCheckUpdatesHostrunPrecheckIsOneDocument: without docker, and with
// docker but without curl, the script stops in its precheck: one precheck
// document, class precheck_failed (exit 10), and the parser reads its reason.
func TestCheckUpdatesHostrunPrecheckIsOneDocument(t *testing.T) {
	a, ok := Lookup("docker.check_updates")
	if !ok {
		t.Fatal("docker.check_updates missing")
	}
	empty := t.TempDir()
	cases := map[string]struct{ path, reason string }{
		"no docker and no curl": {empty, "Docker is not installed"},
	}
	withDocker := newFakeHost(t, "1")
	withDocker.write(t, "docker", `echo 27.3.1`)
	cases["docker without curl"] = struct{ path, reason string }{withDocker.bin, "curl is not installed"}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := runHostrunAction(t, tc.path, a.Script, "{}")
			if r.Class != hostrun.ClassPrecheckFailed || r.ExitCode != 10 {
				t.Fatalf("class %s exit %d (%s), result %q", r.Class, r.ExitCode, r.Detail, r.Result)
			}
			res, err := dockerhost.ParseImageUpdates(r.Result)
			if err != nil || res.Phase != "precheck" || res.Reason != tc.reason || len(res.Images) != 0 {
				t.Fatalf("parser: %+v, %v (result %q)", res, err, r.Result)
			}
		})
	}
}

// TestCheckUpdatesHostrunHostileImageNames: image references and local
// digests with quotes, a backslash, non-ASCII letters and invalid UTF-8.
// The result stays one JSON document with no raw control byte, the hostile
// references are left out by the parser (they are not references), and a
// local digest with hostile bytes stays in its own note field.
func TestCheckUpdatesHostrunHostileImageNames(t *testing.T) {
	f := newFakeHost(t, "1")
	writeChkFakes(t, f)
	hostile := []string{`registry.test/we"ird\x:1.0`, "registry.test/ü/svc:1.0", "registry.test/bad\xff\xfe:1.0"}
	var ps strings.Builder
	for _, h := range hostile {
		fmt.Fprintf(&ps, "%s\n", h)
	}
	ps.WriteString("registry.test/team/plain:1.0\n")
	hostileLocal := `sha256:"\ü`
	local := "registry.test/team/plain:1.0\tregistry.test/team/plain@" + hostileLocal + " \n"
	reg := "registry.test|team/plain|1.0\t200\t" + chkDigest(7) + "\n"
	for name, body := range map[string]string{"ps.txt": ps.String(), "local.txt": local, "reg.txt": reg} {
		if err := os.WriteFile(filepath.Join(f.dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a, _ := Lookup("docker.check_updates")
	r := runHostrunAction(t, f.bin+":/usr/bin:/bin", a.Script, "{}")
	if r.Class != hostrun.ClassSuccess {
		t.Fatalf("class %s (%s), result %q log %q", r.Class, r.Detail, r.Result, r.Log)
	}
	requireNoRawControl(t, r.Result)
	res, err := dockerhost.ParseImageUpdates(r.Result)
	if err != nil {
		t.Fatalf("the parser refuses the result: %v", err)
	}
	if len(res.Images) != 1 {
		t.Fatalf("want only the plain reference, got %+v", res.Images)
	}
	im := res.Images[0]
	if im.Image != "registry.test/team/plain:1.0" || im.Status != "update" || im.Remote != chkDigest(7) {
		t.Fatalf("plain reference: %+v", im)
	}
	if !strings.HasPrefix(im.Note, "local ") || strings.ContainsAny(im.Note, "\n\t") {
		t.Fatalf("note %q holds a foreign or control value", im.Note)
	}
	// The hostile references must not reach the result in any form the
	// parser keeps: none of them is an image in the parsed list.
	for _, h := range hostile {
		for _, got := range res.Images {
			if got.Image == h {
				t.Fatalf("hostile reference %q reached the parsed list", h)
			}
		}
	}
	if bytes.Contains(r.Result, []byte("\xff")) {
		t.Fatal("raw invalid UTF-8 byte in the result")
	}
}
