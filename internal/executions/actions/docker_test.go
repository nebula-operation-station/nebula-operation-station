// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
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
	line := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\tweb\tnginx:1.27\trunning\tUp 2 hours (healthy)\t0.0.0.0:80->80/tcp\tsite\tweb\t/srv/site"
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
		if strings.Contains(calls, "sudo") || !strings.Contains(calls, "ps -a --no-trunc --format") {
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
