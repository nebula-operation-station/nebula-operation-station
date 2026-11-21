// SPDX-License-Identifier: AGPL-3.0-or-later

package actionshostrun_test

import (
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
)

// Scripts that the server runs through hostrun.Attached, with the parameters
// the server builds. The tests check the classification (class, exit code,
// one document, the parser's reading of it), not the effect on Docker.

const (
	boundCID = "1111111111111111111111111111111111111111111111111111111111111111"
	boundIID = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	otherCID = "3333333333333333333333333333333333333333333333333333333333333333"
	otherIID = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
)

// Standalone docker.start, stop and restart 1.0.0 (scripts/docker_control.sh.tmpl).
func TestStandaloneDockerControlThroughHostrun(t *testing.T) {
	for _, verb := range []string{"start", "stop", "restart"} {
		t.Run(verb, func(t *testing.T) {
			a, ok := actions.Lookup("docker." + verb)
			if !ok || a.Version != "1.0.0" {
				t.Fatalf("docker.%s is not the 1.0.0 built-in: %+v", verb, a)
			}
			params := serverParams(t, a, map[string]string{"container": "web"})

			t.Run("success", func(t *testing.T) {
				h := newFakeHost(t)
				h.docker(t, boundCID+" "+boundIID, false)
				r := attach(t, h.script(a), params, a.Timeout)
				if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
					t.Fatalf("class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
				}
				oneDocument(t, r.Result)
				c, err := dockerhost.ParseControl(r.Result)
				if err != nil || c.Phase != "done" || c.Verb != verb || c.Container != "web" || c.Exit != 0 {
					t.Fatalf("ParseControl: %+v, %v", c, err)
				}
				if !verbCalled(h.readCalls(t), verb) {
					t.Fatalf("calls %q: the verb did not run on web", h.readCalls(t))
				}
			})

			t.Run("docker missing", func(t *testing.T) {
				h := newFakeHost(t) // no docker fake: PATH holds no docker
				r := attach(t, h.script(a), params, a.Timeout)
				if r.Class != hostrun.ClassPrecheckFailed || r.ExitCode != hostrun.ExitPrecheckFailed {
					t.Fatalf("class %s, exit %d, log %q", r.Class, r.ExitCode, r.Log)
				}
				oneDocument(t, r.Result)
				c, err := dockerhost.ParseControl(r.Result)
				if err != nil || c.Phase != "precheck" || !strings.Contains(c.Reason, "not installed") || c.Code != "" {
					t.Fatalf("ParseControl: %+v, %v", c, err)
				}
			})

			t.Run("daemon unreachable", func(t *testing.T) {
				h := newFakeHost(t)
				h.docker(t, boundCID+" "+boundIID, true)
				r := attach(t, h.script(a), params, a.Timeout)
				if r.Class != hostrun.ClassPrecheckFailed || r.ExitCode != hostrun.ExitPrecheckFailed {
					t.Fatalf("class %s, exit %d, log %q", r.Class, r.ExitCode, r.Log)
				}
				oneDocument(t, r.Result)
				c, err := dockerhost.ParseControl(r.Result)
				if err != nil || c.Phase != "precheck" || !strings.Contains(c.Reason, "not reachable") {
					t.Fatalf("ParseControl: %+v, %v", c, err)
				}
				if verbCalled(h.readCalls(t), verb) {
					t.Fatalf("the verb ran without a daemon: %q", h.readCalls(t))
				}
			})

			t.Run("container unknown", func(t *testing.T) {
				h := newFakeHost(t)
				h.docker(t, "", false)
				r := attach(t, h.script(a), params, a.Timeout)
				if r.Class != hostrun.ClassPrecheckFailed || r.ExitCode != hostrun.ExitPrecheckFailed {
					t.Fatalf("class %s, exit %d, log %q", r.Class, r.ExitCode, r.Log)
				}
				oneDocument(t, r.Result)
				c, err := dockerhost.ParseControl(r.Result)
				if err != nil || c.Phase != "precheck" || c.Reason != "no such container" || c.Code != "" {
					t.Fatalf("ParseControl: %+v, %v", c, err)
				}
				if verbCalled(h.readCalls(t), verb) {
					t.Fatalf("the verb ran for an unknown container: %q", h.readCalls(t))
				}
			})
		})
	}
}

// Bound docker.start, stop and restart 1.1.0 (scripts/docker_control_bound.sh.tmpl),
// with the parameters batchplan.go builds from the approved binding.
func TestBoundDockerControlThroughHostrun(t *testing.T) {
	for _, verb := range []string{"start", "stop", "restart"} {
		t.Run(verb, func(t *testing.T) {
			a, ok := actions.LookupBatchMember("docker."+verb, "1.1.0")
			if !ok {
				t.Fatalf("docker.%s 1.1.0 is not a batch member", verb)
			}
			binding := map[string]string{"container_id": boundCID, "image_id": boundIID}

			t.Run("success", func(t *testing.T) {
				h := newFakeHost(t)
				h.docker(t, boundCID+" "+boundIID, false)
				r := attach(t, h.script(a), serverParams(t, a, binding), a.Timeout)
				if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
					t.Fatalf("class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
				}
				oneDocument(t, r.Result)
				c, err := dockerhost.ParseControl(r.Result)
				if err != nil || c.Phase != "done" || c.Verb != verb || c.Container != boundCID || c.Exit != 0 {
					t.Fatalf("ParseControl: %+v, %v", c, err)
				}
				if !verbCalled(h.readCalls(t), verb) {
					t.Fatalf("calls %q: the verb did not run on the bound container", h.readCalls(t))
				}
			})

			// The script exits 11 (postcheck_failed in the classifier) with
			// code container_changed; the verb never runs.
			changed := map[string]struct {
				ctr   string
				image string // image in the binding; boundIID when unchanged
			}{
				"container gone":                {ctr: "", image: boundIID},
				"other container ID":            {ctr: otherCID + " " + boundIID, image: boundIID},
				"other image ID":                {ctr: boundCID + " " + otherIID, image: boundIID},
				"binding image not the one run": {ctr: boundCID + " " + boundIID, image: otherIID},
			}
			for name, tc := range changed {
				t.Run(name, func(t *testing.T) {
					h := newFakeHost(t)
					h.docker(t, tc.ctr, false)
					r := attach(t, h.script(a), serverParams(t, a, map[string]string{"container_id": boundCID, "image_id": tc.image}), a.Timeout)
					if r.Class != hostrun.ClassPostcheckFailed || r.ExitCode != hostrun.ExitPostcheckFailed {
						t.Fatalf("class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
					}
					oneDocument(t, r.Result)
					c, err := dockerhost.ParseControl(r.Result)
					if err != nil {
						t.Fatalf("ParseControl: %v (result %q)", err, r.Result)
					}
					if c.Phase != "precheck" || c.Code != dockerhost.CodeContainerChanged || c.Reason == "" {
						t.Fatalf("ParseControl: %+v", c)
					}
					if verbCalled(h.readCalls(t), verb) {
						t.Fatalf("the verb ran after the check failed: %q", h.readCalls(t))
					}
				})
			}
		})
	}
}

// The bound script reads its parameters with a sed pattern that expects the
// canonical key order (container_id, then image_id). The server sends that
// form; the same values in the other order must stop before any docker call.
func TestBoundDockerControlNeedsCanonicalKeyOrder(t *testing.T) {
	a, ok := actions.LookupBatchMember("docker.stop", "1.1.0")
	if !ok {
		t.Fatal("docker.stop 1.1.0 is not a batch member")
	}
	canon := serverParams(t, a, map[string]string{"container_id": boundCID, "image_id": boundIID})
	want := `{"container_id":"` + boundCID + `","image_id":"` + boundIID + `"}`
	if string(canon) != want {
		t.Fatalf("canonical parameters = %s, want %s", canon, want)
	}

	swapped := []byte(`{"image_id":"` + boundIID + `","container_id":"` + boundCID + `"}`)
	h := newFakeHost(t)
	h.docker(t, boundCID+" "+boundIID, false)
	r := attach(t, h.script(a), swapped, a.Timeout)
	if r.Class != hostrun.ClassPrecheckFailed || r.ExitCode != hostrun.ExitPrecheckFailed {
		t.Fatalf("swapped order: class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
	}
	oneDocument(t, r.Result)
	if c, err := dockerhost.ParseControl(r.Result); err != nil || c.Phase != "precheck" || c.Code != "" {
		t.Fatalf("ParseControl: %+v, %v", c, err)
	}
	if calls := h.readCalls(t); calls != "" {
		t.Fatalf("docker was called with swapped parameters: %q", calls)
	}

	// The same canonical bytes pass the check (the control for the probe above).
	r = attach(t, h.script(a), canon, a.Timeout)
	if r.Class != hostrun.ClassSuccess || !verbCalled(h.readCalls(t), "stop") {
		t.Fatalf("canonical order: class %s (%s), calls %q", r.Class, r.Detail, h.readCalls(t))
	}
}

// package.install_all 1.0.0 (scripts/package_install.sh.tmpl, durable job),
// classified as an attached run for the document only.
func TestInstallAllThroughHostrun(t *testing.T) {
	a, ok := actions.Lookup("package.install_all")
	if !ok || a.Version != "1.0.0" {
		t.Fatalf("package.install_all is not the 1.0.0 built-in: %+v", a)
	}
	params := serverParams(t, a, map[string]string{})

	t.Run("success", func(t *testing.T) {
		h := newFakeHost(t)
		h.installTools(t, `case " $* " in
  *" -s "*) echo "Inst vim [1] (2 Debian:12/stable [amd64])" ;;
  *) echo "Setting up vim" ;;
esac
exit 0`)
		r := attach(t, h.script(a), params, a.Timeout)
		if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
			t.Fatalf("class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
		}
		oneDocument(t, r.Result)
		i, err := osdebian.ParseInstall(r.Result)
		if err != nil {
			t.Fatalf("ParseInstall: %v (result %q)", err, r.Result)
		}
		if i.Phase != "done" || i.Mode != "install_all" || i.AptExit != 0 || !i.AuditClean || len(i.Packages) != 1 || i.Packages[0] != "vim" {
			t.Fatalf("ParseInstall: %+v", i)
		}
		if !strings.Contains(h.readCalls(t), "--force-confold upgrade\n") {
			t.Fatalf("apt-get calls %q: the upgrade did not run", h.readCalls(t))
		}
	})

	t.Run("apt-get fails with 2 MiB on stderr", func(t *testing.T) {
		h := newFakeHost(t)
		h.installTools(t, `case " $* " in
  *" -s "*) exit 0 ;;
esac
head -c 2097152 /dev/zero | tr '\0' 'x' >&2
exit 100`)
		r := attach(t, h.script(a), params, a.Timeout)
		if r.Class != hostrun.ClassScriptFailed || r.ExitCode != 100 {
			t.Fatalf("class %s (%s), exit %d", r.Class, r.Detail, r.ExitCode)
		}
		if len(r.Log) < 2<<20 || len(r.Log) > hostrun.MaxLog || r.LogTruncated {
			t.Fatalf("log %d bytes, truncated %v, limit %d", len(r.Log), r.LogTruncated, hostrun.MaxLog)
		}
		if r.Result != nil {
			oneDocument(t, r.Result)
			i, err := osdebian.ParseInstall(r.Result)
			if err != nil || i.Phase != "done" || i.AptExit != 100 {
				t.Fatalf("ParseInstall: %+v, %v", i, err)
			}
		}
	})

	t.Run("no apt-get on PATH", func(t *testing.T) {
		h := newFakeHost(t)
		h.installTools(t, "")
		r := attach(t, h.script(a), params, a.Timeout)
		if r.Class != hostrun.ClassPrecheckFailed || r.ExitCode != hostrun.ExitPrecheckFailed {
			t.Fatalf("class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
		}
		oneDocument(t, r.Result)
		i, err := osdebian.ParseInstall(r.Result)
		if err != nil || i.Phase != "precheck" || !strings.Contains(i.Reason, "apt-get") {
			t.Fatalf("ParseInstall: %+v, %v", i, err)
		}
	})
}
