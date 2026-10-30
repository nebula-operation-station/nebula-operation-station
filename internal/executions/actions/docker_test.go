// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The docker.list script asks the daemon once for the version and once for
// the containers, through the docker group or sudo -n, and reports a host
// without Docker or without access as such.
func TestDockerListScript(t *testing.T) {
	a, ok := Lookup("docker.list")
	if !ok || !a.ReadOnly || len(a.Params) != 0 {
		t.Fatalf("docker.list %+v", a)
	}
	line := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\tweb\tnginx:1.27\trunning\tUp 2 hours (healthy)\t0.0.0.0:80->80/tcp\tsite\tweb\t/srv/site\t2026-01-02 03:04:05 +0000 UTC"
	docker := func(f *fakeHost, group bool) {
		f.write(t, "docker", `echo "$@" >> "`+f.calls+`"
[ -e "`+f.dir+`/no-daemon" ] && exit 1
case "$1" in
  version) echo "27.3.1" ;;
  ps) printf '%s\n' "`+line+`" ;;
esac`)
		if !group {
			// Without the group the user's own docker calls fail; sudo works.
			f.write(t, "docker", `[ -z "${SUDO:-}" ] && { echo "permission denied" >&2; exit 1; }
echo "$@" >> "`+f.calls+`"
case "$1" in version) echo "27.3.1" ;; ps) printf '%s\n' "`+line+`" ;; esac`)
		}
		f.write(t, "sudo", `[ "$1" = "-n" ] || exit 1; shift; echo "sudo $*" >> "`+f.calls+`"; SUDO=1 exec "$@"`)
	}

	t.Run("root", func(t *testing.T) {
		f := newFakeHost(t, "1")
		docker(f, true)
		code, doc := f.run(t, a.Script)
		if code != 0 || doc["present"] != true || b64(t, doc, "version") != "27.3.1" || !strings.Contains(b64(t, doc, "containers"), "\tsite\tweb\t/srv/site") {
			t.Fatalf("%d %v", code, doc)
		}
		calls := f.readCalls(t)
		if strings.Contains(calls, "sudo") || !strings.Contains(calls, "ps -a --no-trunc --format") || !strings.Contains(calls, "{{.CreatedAt}}") {
			t.Fatalf("calls %q", calls)
		}
	})
	t.Run("sudo", func(t *testing.T) {
		f := newFakeHost(t, "1")
		f.write(t, "id", `echo 1000`)
		docker(f, false)
		code, doc := f.run(t, a.Script)
		if code != 0 || doc["present"] != true || !strings.Contains(f.readCalls(t), "sudo docker ps -a") {
			t.Fatalf("%d %v %q", code, doc, f.readCalls(t))
		}
	})
	t.Run("no daemon", func(t *testing.T) {
		f := newFakeHost(t, "1")
		docker(f, true)
		f.touch(t, "no-daemon")
		code, doc := f.run(t, a.Script)
		if code != 10 || doc["phase"] != "precheck" || !strings.Contains(doc["reason"].(string), "not reachable") {
			t.Fatalf("%d %v", code, doc)
		}
	})
	t.Run("no docker", func(t *testing.T) {
		// Only the tools the script needs, so a docker on this machine
		// stays out of reach.
		f := newFakeHost(t, "1")
		for _, tool := range []string{"base64", "head", "tr"} {
			p, err := exec.LookPath(tool)
			if err != nil {
				t.Skip(tool + " missing")
			}
			if err := os.Symlink(p, filepath.Join(f.bin, tool)); err != nil {
				t.Fatal(err)
			}
		}
		code, doc := f.runPath(t, a.Script, f.bin)
		if code != 0 || doc["present"] != false || doc["phase"] != "done" {
			t.Fatalf("%d %v", code, doc)
		}
	})
}

func (f *fakeHost) readCalls(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(f.calls)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

func (f *fakeHost) touch(t *testing.T, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, name), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDockerLogsScript(t *testing.T) {
	a, ok := Lookup("docker.logs")
	if !ok || !a.ReadOnly || a.ValidParams(map[string]string{"container": "web-1"}) != nil {
		t.Fatalf("docker.logs %+v", a)
	}
	for _, bad := range []map[string]string{nil, {"container": "-f"}, {"container": "a b"}, {"container": "a/b"}, {"container": `x"`},
		{"container": strings.Repeat("a", 129)}, {"container": "ok", "tail": "5"}} {
		if a.ValidParams(bad) == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	run := func(t *testing.T, f *fakeHost, params string) (int, map[string]any) {
		t.Helper()
		p := filepath.Join(f.dir, "params")
		if err := os.WriteFile(p, []byte(params), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("/bin/sh", "-c", string(a.Script))
		cmd.Env = []string{"PATH=" + f.bin + ":/usr/bin:/bin", "NEBULA_PARAMS=" + p}
		out, err := cmd.Output()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		var doc map[string]any
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatalf("result %q: %v", out, err)
		}
		return code, doc
	}
	f := newFakeHost(t, "1")
	f.write(t, "id", `echo 1000`)
	f.write(t, "sudo", `[ "$1" = "-n" ] || exit 1; shift; echo "sudo $*" >> "`+f.calls+`"; SUDO=1 exec "$@"`)
	f.write(t, "docker", `[ -z "${SUDO:-}" ] && exit 1
echo "$@" >> "`+f.calls+`"
case "$1" in
  version) echo 27 ;;
  inspect) [ "$7" = web ] || exit 1; echo running ;;
  logs) echo "out line"; echo "err line" >&2 ;;
esac`)
	code, doc := run(t, f, `{"container":"web"}`)
	if code != 0 || doc["container"] != "web" || b64(t, doc, "state") != "running" || b64(t, doc, "logs") != "out line\nerr line\n" {
		t.Fatalf("%d %v", code, doc)
	}
	if calls := f.readCalls(t); !strings.Contains(calls, "sudo docker logs --tail 100 --timestamps -- web") {
		t.Fatalf("calls %q", calls)
	}
	for params, reason := range map[string]string{`{"container":"gone"}`: "no such container", `{"container":"-f"}`: "invalid",
		`{"container":"web","x":1}`: "invalid", `{"container":"we b"}`: "invalid"} {
		code, doc := run(t, f, params)
		if code != 10 || !strings.Contains(doc["reason"].(string), reason) {
			t.Errorf("%s: %d %v", params, code, doc)
		}
	}
}

// docker.inspect reads only the fields of its template (never the
// environment, command line or labels) and the image's repository digests.
func TestDockerInspectScript(t *testing.T) {
	a, ok := Lookup("docker.inspect")
	if !ok || !a.ReadOnly || a.ValidParams(map[string]string{"container": "web"}) != nil || a.ValidParams(map[string]string{"container": "-f"}) == nil {
		t.Fatalf("docker.inspect %+v", a)
	}
	for _, field := range []string{".Config.Env", ".Config.Cmd", ".Args", ".Config.Labels", ".Config.Entrypoint", ".Path", "{{json .}}"} {
		if strings.Contains(string(a.Script), field) {
			t.Fatalf("the script reads %s", field)
		}
	}
	f := newFakeHost(t, "1")
	f.write(t, "docker", `echo "$@" >> "`+f.calls+`"
case "$1 $2" in
  "version "*) echo 27 ;;
  "inspect --type") for x in "$@"; do last=$x; done; [ "$last" = web ] || exit 1
     case "$*" in *'{{.Image}}'*) echo sha256:abc ;; *'{{.Id}}'*) echo abc ;; *) echo '{"id":"abc"}' ;; esac ;;
  "image inspect") echo '{"id":"sha256:abc","created":"2026-01-01T00:00:00Z","os":"linux","architecture":"amd64","variant":"","repo_digests":["repo@sha256:abc"]}' ;;
esac`)
	p := filepath.Join(f.dir, "params")
	run := func(params string) (int, map[string]any) {
		if err := os.WriteFile(p, []byte(params), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("/bin/sh", "-c", string(a.Script))
		cmd.Env = []string{"PATH=" + f.bin + ":/usr/bin:/bin", "NEBULA_PARAMS=" + p}
		out, err := cmd.Output()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		var doc map[string]any
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatalf("result %q: %v", out, err)
		}
		return code, doc
	}
	code, doc := run(`{"container":"web"}`)
	wantImage := `{"id":"sha256:abc","created":"2026-01-01T00:00:00Z","os":"linux","architecture":"amd64","variant":"","repo_digests":["repo@sha256:abc"]}` + "\n"
	if code != 0 || doc["container"] != "web" || b64(t, doc, "inspect") != `{"id":"abc"}` || b64(t, doc, "image") != wantImage {
		t.Fatalf("%d %v", code, doc)
	}
	if calls := f.readCalls(t); !strings.Contains(calls, "image inspect --format") || !strings.Contains(calls, "{{json .RepoDigests}}") || !strings.Contains(calls, "-- sha256:abc") {
		t.Fatalf("calls %q", calls)
	}
	code, doc = run(`{"container":"gone"}`)
	if code != 10 || doc["reason"] != "no such container" {
		t.Fatalf("%d %v", code, doc)
	}
}

// docker.start/stop/restart are MEDIUM, never retried, and run exactly
// `docker <verb> -- <container>` after the same parameter check.
func TestDockerControlScripts(t *testing.T) {
	for _, verb := range []string{"start", "stop", "restart"} {
		a, ok := Lookup("docker." + verb)
		if !ok || a.ReadOnly || a.Retry != RetryNever || a.Risk.String() != "RISK_CLASS_MEDIUM" || strings.Contains(string(a.Script), "@VERB@") {
			t.Fatalf("docker.%s %+v", verb, a)
		}
		f := newFakeHost(t, "1")
		f.write(t, "id", `echo 1000`)
		f.write(t, "sudo", `[ "$1" = "-n" ] || exit 1; shift; echo "sudo $*" >> "`+f.calls+`"; SUDO=1 exec "$@"`)
		f.write(t, "docker", `[ -z "${SUDO:-}" ] && exit 1
echo "$@" >> "`+f.calls+`"
case "$1" in
  version) echo 27 ;;
  inspect) for x in "$@"; do last=$x; done; [ "$last" = web ] || exit 1; echo running ;;
  `+verb+`) echo web; exit 3 ;;
esac`)
		p := filepath.Join(f.dir, "params")
		if err := os.WriteFile(p, []byte(`{"container":"web"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("/bin/sh", "-c", string(a.Script))
		cmd.Env = []string{"PATH=" + f.bin + ":/usr/bin:/bin", "NEBULA_PARAMS=" + p}
		out, err := cmd.Output()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 3 {
			t.Fatalf("%s: %v", verb, err)
		}
		var doc map[string]any
		if err := json.Unmarshal(out, &doc); err != nil || doc["verb"] != verb || doc["exit"] != float64(3) || b64(t, doc, "after") != "running" {
			t.Fatalf("%s: %s %v", verb, out, err)
		}
		if !strings.Contains(f.readCalls(t), "sudo docker "+verb+" -- web") {
			t.Fatalf("%s: calls %q", verb, f.readCalls(t))
		}
		if err := os.WriteFile(p, []byte(`{"container":"-f"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		out, _ = exec.Command("/bin/sh", "-c", "NEBULA_PARAMS="+p+" PATH="+f.bin+":/usr/bin:/bin /bin/sh -c \"$0\"", string(a.Script)).Output()
		if !strings.Contains(string(out), "invalid") || strings.Contains(f.readCalls(t), verb+" -- -f") {
			t.Fatalf("%s: %s", verb, out)
		}
	}
}

// docker.compose_update finds the project by its labels, passes every
// config file as its own -f argument, pulls, and runs up -d only after a
// successful pull.
func TestDockerComposeUpdateScript(t *testing.T) {
	a, ok := Lookup("docker.compose_update")
	if !ok || !a.Durable || a.Retry != RetryReconcileFirst || a.ValidParams(map[string]string{"project": "site"}) != nil ||
		a.ValidParams(map[string]string{"project": "-p"}) == nil || a.ValidParams(map[string]string{"project": "Site"}) == nil {
		t.Fatalf("%+v", a)
	}
	run := func(t *testing.T, f *fakeHost, params string) (int, map[string]any) {
		t.Helper()
		p := filepath.Join(f.dir, "params")
		if err := os.WriteFile(p, []byte(params), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("/bin/sh", "-c", string(a.Script))
		cmd.Env = []string{"PATH=" + f.bin + ":/usr/bin:/bin", "NEBULA_PARAMS=" + p}
		out, err := cmd.Output()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
		var doc map[string]any
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatalf("result %q: %v", out, err)
		}
		return code, doc
	}
	setup := func(t *testing.T, pullExit string) *fakeHost {
		f := newFakeHost(t, "1")
		dir := filepath.Join(f.dir, "site dir")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{"compose.yaml", "override,x.yaml"} {
			if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		f.write(t, "docker", `echo "$@" >> "`+f.calls+`"
case "$1 $2" in
  "compose version") echo v2 ;;
  "compose -p") case "$*" in *" pull") exit `+pullExit+` ;; esac; exit 0 ;;
  "ps -a")
    case "$*" in *" -q "*) echo c1 ;; *) printf 'web\tsite-web-1\trunning\tUp 1 hour (healthy)\t\tnginx:1\n' ;; esac ;;
  "inspect --type")
    case "$*" in *working_dir*) echo "`+dir+`" ;; *config_files*) echo "`+dir+`/compose.yaml,`+dir+`/override.yaml" ;; esac ;;
esac`)
		return f
	}
	f := setup(t, "0")
	// override.yaml is missing: precheck.
	code, doc := run(t, f, `{"project":"site"}`)
	if code != 10 || !strings.Contains(doc["reason"].(string), "config file") {
		t.Fatalf("%d %v", code, doc)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "site dir", "override.yaml"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	code, doc = run(t, f, `{"project":"site"}`)
	if code != 0 || doc["pull_exit"] != float64(0) || doc["up_exit"] != float64(0) || !strings.Contains(b64(t, doc, "after"), "site-web-1") {
		t.Fatalf("%d %v", code, doc)
	}
	calls := f.readCalls(t)
	dir := filepath.Join(f.dir, "site dir")
	for _, want := range []string{
		"compose -p site --project-directory " + dir + " -f " + dir + "/compose.yaml -f " + dir + "/override.yaml pull",
		"compose -p site --project-directory " + dir + " -f " + dir + "/compose.yaml -f " + dir + "/override.yaml up -d",
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("missing %q in %q", want, calls)
		}
	}
	// A failed pull restarts nothing.
	f = setup(t, "1")
	if err := os.WriteFile(filepath.Join(f.dir, "site dir", "override.yaml"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	code, doc = run(t, f, `{"project":"site"}`)
	if code == 0 || doc["pull_exit"] != float64(1) || doc["up_exit"] != float64(-1) || strings.Contains(f.readCalls(t), "up -d") {
		t.Fatalf("%d %v", code, doc)
	}
	for _, bad := range []string{`{"project":"-p"}`, `{"project":"a b"}`, `{"project":"site","x":1}`} {
		if code, doc := run(t, f, bad); code != 10 || !strings.Contains(doc["reason"].(string), "parameter") {
			t.Errorf("%s: %d %v", bad, code, doc)
		}
	}
}
