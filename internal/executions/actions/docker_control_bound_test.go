// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// G5b (container update plan cu07): docker.start, stop and restart 1.1.0
// act on the container the approved binding names. The script checks the
// container ID and the image ID before the verb and stops with the fixed
// code container_changed when either differs or the container is gone.

const (
	boundCID = "1111111111111111111111111111111111111111111111111111111111111111"
	boundIID = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	otherCID = "3333333333333333333333333333333333333333333333333333333333333333"
	otherIID = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
)

// boundFake is a fake docker with one container: ctr holds "<id> <image>"
// (absent means no such container). Inspect by an ID other than the
// container's fails, as docker does; restart, stop and start succeed.
func boundFake(t *testing.T, ctrID, ctrImage string) (*fakeHost, string) {
	t.Helper()
	f := newFakeHost(t, "1")
	if err := os.WriteFile(filepath.Join(f.dir, "ctr"), []byte(ctrID+" "+ctrImage+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.write(t, "docker", `echo "$@" >> "`+f.calls+`"
for x in "$@"; do last=$x; done
case "$1" in
  version) echo 27 ;;
  inspect)
    read id img < "`+f.dir+`/ctr" 2>/dev/null || exit 1
    [ "$last" = "$id" ] || exit 1
    case "$*" in *'{{.Id}}'*) echo "$id $img" ;; *) echo running ;; esac ;;
  restart|stop|start) echo done; exit 0 ;;
esac
exit 0`)
	return f, filepath.Join(f.dir, "params")
}

// runBound runs the script of docker.<verb> 1.1.0 with the given params
// line and returns its exit code, stdout and the docker calls.
func runBound(t *testing.T, f *fakeHost, paramsFile, verb string, line string) (int, map[string]any) {
	t.Helper()
	a, ok := LookupVersion("docker."+verb, "1.1.0")
	if !ok {
		t.Fatalf("docker.%s 1.1.0 not in the catalog", verb)
	}
	if err := os.WriteFile(paramsFile, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", string(a.Script))
	cmd.Env = []string{"PATH=" + f.bin + ":/usr/bin:/bin", "NEBULA_PARAMS=" + paramsFile}
	out, _ := cmd.Output()
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("%s: output %q: %v", verb, out, err)
	}
	return cmd.ProcessState.ExitCode(), doc
}

func boundLine(cid, iid string) string {
	return `{"container_id":"` + cid + `","image_id":"` + iid + `"}`
}

func TestBoundControlActsOnMatchingContainer(t *testing.T) {
	for _, verb := range []string{"start", "stop", "restart"} {
		t.Run(verb, func(t *testing.T) {
			f, p := boundFake(t, boundCID, boundIID)
			code, doc := runBound(t, f, p, verb, boundLine(boundCID, boundIID))
			if code != 0 || doc["phase"] != "done" || doc["verb"] != verb || doc["container"] != boundCID {
				t.Fatalf("%d %v", code, doc)
			}
			calls := f.readCalls(t)
			if !strings.Contains(calls, verb+" -- "+boundCID) {
				t.Fatalf("calls %q: the verb must act on the bound ID", calls)
			}
		})
	}
}

func TestBoundControlStopsOnChangedContainer(t *testing.T) {
	cases := []struct {
		name, ctrID, ctrImage, cid, iid string
	}{
		{"other container ID", otherCID, boundIID, boundCID, boundIID},
		{"other image ID", boundCID, otherIID, boundCID, boundIID},
		{"container missing", "", "", boundCID, boundIID},
		{"bound image not the container's", boundCID, boundIID, boundCID, otherIID},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, p := boundFake(t, c.ctrID, c.ctrImage)
			if c.ctrID == "" {
				if err := os.Remove(filepath.Join(f.dir, "ctr")); err != nil {
					t.Fatal(err)
				}
			}
			for _, verb := range []string{"start", "stop", "restart"} {
				code, doc := runBound(t, f, p, verb, boundLine(c.cid, c.iid))
				if code != 10 || doc["phase"] != "precheck" || doc["code"] != "container_changed" {
					t.Fatalf("%s: %d %v", verb, code, doc)
				}
				if strings.Contains(f.readCalls(t), verb+" -- ") {
					t.Fatalf("%s: a verb ran after the check failed: %q", verb, f.readCalls(t))
				}
			}
		})
	}
}

func TestBoundControlRejectsHostileParams(t *testing.T) {
	hostile := []string{
		`{"container_id":"web","image_id":"` + boundIID + `"}`,
		`{"container_id":"-f","image_id":"` + boundIID + `"}`,
		`{"container_id":"` + boundCID + `; touch pwned","image_id":"` + boundIID + `"}`,
		`{"container_id":"$(touch pwned)` + boundCID[:50] + `","image_id":"` + boundIID + `"}`,
		`{"container_id":"` + strings.Repeat("A", 64) + `","image_id":"` + boundIID + `"}`,
		`{"container_id":"` + boundCID[:63] + `","image_id":"` + boundIID + `"}`,
		`{"container_id":"` + boundCID + `","image_id":"` + boundIID[7:] + `"}`,
		`{"container_id":"` + boundCID + `","image_id":"sha256:` + "../../etc" + `"}`,
		`{"container_id":"` + boundCID + `"}`,
		`{"container_id":"` + boundCID + `","image_id":"` + boundIID + `","container":"web"}`,
	}
	for _, line := range hostile {
		t.Run(line, func(t *testing.T) {
			f, p := boundFake(t, boundCID, boundIID)
			code, doc := runBound(t, f, p, "restart", line)
			if code != 10 || doc["phase"] != "precheck" || doc["code"] != nil {
				t.Fatalf("%d %v", code, doc)
			}
			if !strings.Contains(doc["reason"].(string), "invalid") {
				t.Fatalf("reason %v", doc["reason"])
			}
			if strings.Contains(f.readCalls(t), "restart") || strings.Contains(f.readCalls(t), "inspect") {
				t.Fatalf("docker was called for a rejected parameter: %q", f.readCalls(t))
			}
		})
	}
}

func TestBoundControlCatalogAndPinnedOldVersion(t *testing.T) {
	for _, verb := range []string{"start", "stop", "restart"} {
		a, ok := LookupVersion("docker."+verb, "1.1.0")
		if !ok || a.ReadOnly || a.Retry != RetryNever || a.Risk.String() != "RISK_CLASS_MEDIUM" || len(a.Params) != 2 ||
			a.Params[0].Name != "container_id" || a.Params[1].Name != "image_id" {
			t.Fatalf("docker.%s 1.1.0: %+v", verb, a)
		}
		if strings.Contains(string(a.Script), "@VERB@") || strings.Contains(string(a.Script), "Config") {
			t.Fatalf("docker.%s 1.1.0 must not render placeholders or read the configuration", verb)
		}
		if err := a.ValidParams(map[string]string{"container_id": boundCID, "image_id": boundIID}); err != nil {
			t.Fatalf("docker.%s 1.1.0 rejects a bound pair: %v", verb, err)
		}
		if err := a.ValidParams(map[string]string{"container_id": "web", "image_id": boundIID}); err == nil {
			t.Fatalf("docker.%s 1.1.0 accepts a name", verb)
		}
		old, ok := LookupVersion("docker."+verb, "1.0.0")
		if !ok || len(old.Params) != 1 || old.Params[0].Name != "container" || strings.Contains(string(old.Script), "container_id") {
			t.Fatalf("docker.%s 1.0.0 must stay as it was: %+v", verb, old)
		}
	}
}
