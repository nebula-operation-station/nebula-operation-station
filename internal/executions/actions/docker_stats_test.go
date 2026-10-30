// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
)

// docker.stats is a LOW, read-only, non-streaming snapshot: no parameters,
// bounded, and it never reads the environment, labels or command line.
func TestDockerStatsAction(t *testing.T) {
	a, ok := Lookup("docker.stats")
	if !ok || !a.ReadOnly || len(a.Params) != 0 || a.Risk.String() != "RISK_CLASS_LOW" || a.Retry != RetrySafe {
		t.Fatalf("docker.stats %+v", a)
	}
	if !strings.Contains(string(a.Script), "--no-stream") || !strings.Contains(string(a.Script), "--no-trunc") ||
		!strings.Contains(string(a.Script), "head -n 2000") {
		t.Fatalf("script not a bounded non-streaming snapshot: %s", a.Script)
	}
	for _, field := range []string{".Config.Env", ".Config.Cmd", ".Args", ".Config.Labels", ".Config.Entrypoint", "{{json .}}"} {
		if strings.Contains(string(a.Script), field) {
			t.Fatalf("the script reads %s", field)
		}
	}
}

func TestDockerStatsScript(t *testing.T) {
	a, ok := Lookup("docker.stats")
	if !ok || !a.ReadOnly || len(a.Params) != 0 {
		t.Fatalf("docker.stats %+v", a)
	}
	line := `{"id":"c1bfa1cc4a9a2109aa190e758a09c75ffa9cc9caf9fb653a143fb27e9e299cf2","name":"web","cpu":"12.34%","mem":"512MB / 8GB","memp":"6.25%"}`
	docker := func(f *fakeHost, group bool) {
		f.write(t, "docker", `[ -e "`+f.dir+`/no-daemon" ] && exit 1
echo "$@" >> "`+f.calls+`"
case "$1" in
  version) echo "27.3.1" ;;
  stats) printf '%s\n' '`+line+`' ;;
esac`)
		if !group {
			// Without the group the user's own docker calls fail; sudo works.
			f.write(t, "docker", `[ -z "${SUDO:-}" ] && { echo "permission denied" >&2; exit 1; }
[ -e "`+f.dir+`/no-daemon" ] && exit 1
echo "$@" >> "`+f.calls+`"
case "$1" in version) echo "27.3.1" ;; stats) printf '%s\n' '`+line+`' ;; esac`)
		}
		f.write(t, "sudo", `[ "$1" = "-n" ] || exit 1; shift; echo "sudo $*" >> "`+f.calls+`"; SUDO=1 exec "$@"`)
	}

	t.Run("root", func(t *testing.T) {
		f := newFakeHost(t, "1")
		docker(f, true)
		code, doc := f.run(t, a.Script)
		if code != 0 || doc["present"] != true || b64(t, doc, "version") != "27.3.1" || !strings.Contains(b64(t, doc, "stats"), `"name":"web"`) {
			t.Fatalf("%d %v", code, doc)
		}
		calls := f.readCalls(t)
		if strings.Contains(calls, "sudo") || !strings.Contains(calls, "stats --no-stream --no-trunc --format") || !strings.Contains(calls, "{{json .MemUsage}}") {
			t.Fatalf("calls %q", calls)
		}
	})
	t.Run("sudo", func(t *testing.T) {
		f := newFakeHost(t, "1")
		f.write(t, "id", `echo 1000`)
		docker(f, false)
		code, doc := f.run(t, a.Script)
		if code != 0 || doc["present"] != true || !strings.Contains(f.readCalls(t), "sudo docker stats --no-stream") {
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
		// Only the tools the script needs, so a docker on this machine stays out of reach.
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
	// Execute the actual requested template: canned Docker output alone
	// cannot detect a field the script forgot or an unrequested one it added.
	t.Run("round trip", func(t *testing.T) {
		f := newFakeHost(t, "1")
		docker(f, true)
		if code, doc := f.run(t, a.Script); code != 0 {
			t.Fatalf("%d %v", code, doc)
		}
		var format string
		for line := range strings.SplitSeq(f.readCalls(t), "\n") {
			if strings.HasPrefix(line, "stats --no-stream --no-trunc --format ") {
				format = strings.TrimPrefix(line, "stats --no-stream --no-trunc --format ")
				break
			}
		}
		if format == "" {
			t.Fatal("stats template was not requested")
		}
		tmpl, err := template.New("stats").Option("missingkey=error").Funcs(template.FuncMap{
			"json": func(v any) (string, error) {
				b, err := json.Marshal(v)
				return string(b), err
			},
		}).Parse(format)
		if err != nil {
			t.Fatal(err)
		}
		input := map[string]any{
			"ID":       "c1bfa1cc4a9a2109aa190e758a09c75ffa9cc9caf9fb653a143fb27e9e299cf2",
			"Name":     "web",
			"CPUPerc":  "12.34%",
			"MemUsage": "512MB / 8GB",
			"MemPerc":  "6.25%",
			"NetIO":    "1.2kB / 3.4kB",
			"BlockIO":  "0B / 0B",
			"PIDs":     "5",
		}
		var out bytes.Buffer
		if err := tmpl.Execute(&out, input); err != nil {
			t.Fatal(err)
		}
		want := `{"id":"c1bfa1cc4a9a2109aa190e758a09c75ffa9cc9caf9fb653a143fb27e9e299cf2","name":"web","cpu":"12.34%","mem":"512MB / 8GB","memp":"6.25%"}`
		if out.String() != want {
			t.Fatalf("template output %s, want %s", out.String(), want)
		}
	})
}
