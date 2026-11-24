// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
)

// Write actions (service control, package.refresh, system.reboot) run as
// attached runs through hostrun.Attached, so the class the executor reports
// is the one hostrun.go derives from the exit status and the document. The
// tools are fakes in front of PATH; every fake appends its call to a log.
// Nothing real (sudo, systemctl, apt-get, systemd-run, shutdown) is reachable
// from these tests: where a tool must be absent, /usr/bin is not on PATH.

// wsRunID is the execution ID of the attached runs in this file.
const wsRunID = "7e1c2b4d-5f60-4a8b-9c3d-0e1f2a3b4c5d"

// wsBootID is the boot ID the fake head prints for system.reboot.
const wsBootID = "0b1c2d3e-4f50-4617-8899-aabbccddeeff"

// wsHost is a directory with fake programs in bin and the call log in calls.
type wsHost struct{ dir, bin, calls string }

// newWSHost starts with a root fake id, a passthrough fake sudo that logs,
// and a quiet fake journalctl. Tests overwrite what they need.
func newWSHost(t *testing.T) *wsHost {
	t.Helper()
	d := t.TempDir()
	h := &wsHost{dir: d, bin: filepath.Join(d, "bin"), calls: filepath.Join(d, "calls")}
	if err := os.Mkdir(h.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	h.fake(t, "id", `echo 0`)
	h.fake(t, "sudo", `echo "sudo $*" >> "`+h.calls+`"; [ "$1" = -n ] && shift; "$@"`)
	h.fake(t, "journalctl", `echo "journal line"`)
	return h
}

// fake writes an executable fake program into bin.
func (h *wsHost) fake(t *testing.T, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(h.bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// logged returns the recorded calls of all fakes ("" when none were made).
func (h *wsHost) logged(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(h.calls)
	if errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// systemctlFake answers show with activeState and exits with rc for every
// other call; every call is logged.
func (h *wsHost) systemctlFake(t *testing.T, rc int, activeState string) {
	t.Helper()
	h.fake(t, "systemctl", `echo "systemctl $*" >> "`+h.calls+`"
case "$1" in show) echo "ActiveState=`+activeState+`" ;; esac
exit `+strconv.Itoa(rc))
}

// attached runs the action's script through hostrun.Attached with params
// and the given PATH. PATH is set in front of the unchanged script, as the
// other hostrun tests do.
func (h *wsHost) attached(t *testing.T, a Action, params, path string) hostrun.Result {
	t.Helper()
	script := "PATH='" + path + "'; export PATH\n" + string(a.Script)
	r, err := hostrun.Attached(context.Background(), hostrunClient(t), wsRunID, []byte(params), []byte(script), a.Timeout)
	if err != nil {
		t.Fatalf("attached run was not started: %v", err)
	}
	if len(r.Log) > hostrun.MaxLog {
		t.Errorf("log %d bytes, limit %d", len(r.Log), hostrun.MaxLog)
	}
	return r
}

// fullPath is the fake directory followed by the system directories that
// the scripts need for head, printf, base64 and the other shell tools.
func (h *wsHost) fullPath() string { return h.bin + ":/usr/bin:/bin" }

// oneDoc parses the result as exactly one JSON document.
func oneDoc(t *testing.T, r hostrun.Result) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(r.Result, &doc); err != nil {
		t.Fatalf("result %q is not exactly one JSON object: %v", r.Result, err)
	}
	return doc
}

// Service control: the template's verb is one of these four.
var wsServiceVerbs = []string{"restart", "start", "stop", "reload"}

func wsServiceAction(t *testing.T, verb string) Action {
	t.Helper()
	a, ok := Lookup("service." + verb)
	if !ok {
		t.Fatalf("service.%s is not registered", verb)
	}
	return a
}

// The verb succeeds and the unit is active afterwards: the script's document
// has the verb and the systemctl show output, class success, exit 0.
func TestServiceVerbsThroughHostrunSucceed(t *testing.T) {
	for _, verb := range wsServiceVerbs {
		for _, uid := range []string{"0", "1000"} {
			t.Run(verb+" uid "+uid, func(t *testing.T) {
				h := newWSHost(t)
				h.fake(t, "id", `echo `+uid)
				h.systemctlFake(t, 0, "active")
				r := h.attached(t, wsServiceAction(t, verb), `{"unit":"nginx.service"}`, h.fullPath())
				if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
					t.Fatalf("class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
				}
				doc := oneDoc(t, r)
				if doc["verb"] != verb || doc["phase"] != "done" || doc["exit"] != 0.0 {
					t.Fatalf("document %v", doc)
				}
				if !strings.Contains(b64(t, doc, "show"), "ActiveState=active") {
					t.Fatalf("show %q", b64(t, doc, "show"))
				}
				want := "systemctl " + verb + " -- nginx.service"
				if uid == "1000" {
					want = "sudo -n systemctl " + verb + " -- nginx.service"
				}
				if !strings.Contains(h.logged(t), want) {
					t.Fatalf("calls %q, want %q", h.logged(t), want)
				}
			})
		}
	}
}

// service_control.sh.tmpl has no postcheck: its exit status is the verb's
// (systemctl) status, and a unit that is failed afterwards is only visible
// in the show text. So the class is success, not postcheck_failed, and exit
// 11 is never produced by this script. Ist-Verhalten, see the report.
func TestServiceVerbWithFailedUnitAfterwardIsStillSuccess(t *testing.T) {
	for _, verb := range wsServiceVerbs {
		t.Run(verb, func(t *testing.T) {
			h := newWSHost(t)
			h.systemctlFake(t, 0, "failed")
			r := h.attached(t, wsServiceAction(t, verb), `{"unit":"nginx.service"}`, h.fullPath())
			if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
				t.Fatalf("class %s (%s), exit %d", r.Class, r.Detail, r.ExitCode)
			}
			if !strings.Contains(b64(t, oneDoc(t, r), "show"), "ActiveState=failed") {
				t.Fatal("the failed state is not in the document")
			}
		})
	}
}

// A systemctl failure is the script's own exit status. It is not one of the
// adapter codes 10 and 11, so the class is script_failed.
func TestServiceVerbFailureIsScriptFailed(t *testing.T) {
	for _, verb := range wsServiceVerbs {
		t.Run(verb, func(t *testing.T) {
			h := newWSHost(t)
			h.systemctlFake(t, 1, "inactive")
			r := h.attached(t, wsServiceAction(t, verb), `{"unit":"nginx.service"}`, h.fullPath())
			if r.Class != hostrun.ClassScriptFailed || r.ExitCode != 1 {
				t.Fatalf("class %s, exit %d", r.Class, r.ExitCode)
			}
			if doc := oneDoc(t, r); doc["exit"] != 1.0 {
				t.Fatalf("document %v", doc)
			}
		})
	}
}

// The script refuses parameters it must not act on: exit 10, a precheck
// document, and no systemctl or sudo call at all.
func TestServiceVerbPrecheckRefusalsRunNoCommand(t *testing.T) {
	bad := []string{`{"unit":"-x"}`, `{"unit":"a;b"}`, `{"unit":"nginx","extra":"y"}`}
	for _, verb := range wsServiceVerbs {
		for _, params := range bad {
			t.Run(verb+" "+params, func(t *testing.T) {
				h := newWSHost(t)
				h.systemctlFake(t, 0, "active")
				r := h.attached(t, wsServiceAction(t, verb), params, h.fullPath())
				if r.Class != hostrun.ClassPrecheckFailed || r.ExitCode != hostrun.ExitPrecheckFailed {
					t.Fatalf("class %s (%s), exit %d", r.Class, r.Detail, r.ExitCode)
				}
				if doc := oneDoc(t, r); doc["phase"] != "precheck" {
					t.Fatalf("document %v", doc)
				}
				if calls := h.logged(t); calls != "" {
					t.Fatalf("a refused parameter still ran: %q", calls)
				}
			})
		}
	}
}

// package.refresh: a successful apt-get update gives refreshed true, exit 0
// and the lists mtime, class success.
func TestPackageRefreshSucceedsThroughHostrun(t *testing.T) {
	h := newWSHost(t)
	h.fake(t, "apt-get", `echo "apt-get $*" >> "`+h.calls+`"; exit 0`)
	a, _ := Lookup("package.refresh")
	r := h.attached(t, a, `{}`, h.fullPath())
	if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
		t.Fatalf("class %s (%s), exit %d", r.Class, r.Detail, r.ExitCode)
	}
	doc := oneDoc(t, r)
	if doc["refreshed"] != true || doc["exit"] != 0.0 {
		t.Fatalf("document %v", doc)
	}
	if _, ok := doc["lists_mtime"].(float64); !ok {
		t.Fatalf("lists_mtime missing: %v", doc)
	}
	if !strings.Contains(h.logged(t), "apt-get -q -o DPkg::Lock::Timeout=480 update") {
		t.Fatalf("calls %q", h.logged(t))
	}
}

// apt-get fails with 100 after writing 2 MiB to stderr. The class is
// script_failed, the document says refreshed false with exit 100, and the
// log keeps the 2 MiB below the log limit (not truncated).
func TestPackageRefreshAptFailureWithLargeStderr(t *testing.T) {
	h := newWSHost(t)
	h.fake(t, "apt-get", `head -c 2097152 /dev/zero | tr '\0' x >&2; exit 100`)
	a, _ := Lookup("package.refresh")
	r := h.attached(t, a, `{}`, h.fullPath())
	if r.Class != hostrun.ClassScriptFailed || r.ExitCode != 100 {
		t.Fatalf("class %s (%s), exit %d", r.Class, r.Detail, r.ExitCode)
	}
	doc := oneDoc(t, r)
	if doc["refreshed"] != false || doc["exit"] != 100.0 {
		t.Fatalf("document %v", doc)
	}
	if len(r.Log) < 2<<20 || r.LogTruncated || len(r.Log) > hostrun.MaxLog {
		t.Fatalf("log %d bytes, truncated %v", len(r.Log), r.LogTruncated)
	}
}

// Without apt-get the script exits 3 before it prints a document. Ist-Verhalten:
// the result is empty and the class is script_failed (exit 3). The spec's
// "refreshed:false" document is only written once apt-get has run.
func TestPackageRefreshWithoutAptGetHasNoDocument(t *testing.T) {
	h := newWSHost(t)
	a, _ := Lookup("package.refresh")
	// Only the fake directory on PATH: no apt-get is reachable.
	r := h.attached(t, a, `{}`, h.bin)
	if r.Class != hostrun.ClassScriptFailed || r.ExitCode != 3 {
		t.Fatalf("class %s (%s), exit %d", r.Class, r.Detail, r.ExitCode)
	}
	if len(r.Result) != 0 {
		t.Fatalf("result %q, want none", r.Result)
	}
	if !strings.Contains(string(r.Log), "no apt-get") {
		t.Fatalf("log %q", r.Log)
	}
}

// system.reboot 1.0.0 refuses to run without root: one precheck document,
// and systemd-run is never called.
func TestSystemRebootRefusesWithoutRoot(t *testing.T) {
	h := newWSHost(t)
	h.fake(t, "id", `echo 1000`)
	h.fake(t, "head", `echo `+wsBootID)
	h.fake(t, "systemd-run", `echo "systemd-run $*" >> "`+h.calls+`"; exit 0`)
	a, _ := Lookup("system.reboot")
	r := h.attached(t, a, `{}`, h.fullPath())
	if r.Class != hostrun.ClassPrecheckFailed || r.ExitCode != hostrun.ExitPrecheckFailed {
		t.Fatalf("class %s (%s), exit %d", r.Class, r.Detail, r.ExitCode)
	}
	if doc := oneDoc(t, r); doc["reason"] != "not running as root" || doc["format"] != "reboot-v1" {
		t.Fatalf("document %v", doc)
	}
	if calls := h.logged(t); calls != "" {
		t.Fatalf("a refused reboot still ran: %q", calls)
	}
}

// Without systemd-run, the check fails before anything is scheduled. PATH
// has no /usr/bin here, so a real systemd-run cannot be found.
func TestSystemRebootWithoutSystemdRun(t *testing.T) {
	h := newWSHost(t)
	a, _ := Lookup("system.reboot")
	r := h.attached(t, a, `{}`, h.bin)
	if r.Class != hostrun.ClassPrecheckFailed || r.ExitCode != hostrun.ExitPrecheckFailed {
		t.Fatalf("class %s (%s), exit %d", r.Class, r.Detail, r.ExitCode)
	}
	if doc := oneDoc(t, r); doc["reason"] != "no systemd-run" {
		t.Fatalf("document %v", doc)
	}
}

// A boot ID that is not a UUID is a precheck failure. The fake head prints
// junk instead of /proc/sys/kernel/random/boot_id.
func TestSystemRebootUnreadableBootID(t *testing.T) {
	h := newWSHost(t)
	h.fake(t, "head", `echo nope`)
	h.fake(t, "systemd-run", `echo "systemd-run $*" >> "`+h.calls+`"; exit 0`)
	a, _ := Lookup("system.reboot")
	r := h.attached(t, a, `{}`, h.fullPath())
	if r.Class != hostrun.ClassPrecheckFailed || r.ExitCode != hostrun.ExitPrecheckFailed {
		t.Fatalf("class %s (%s), exit %d", r.Class, r.Detail, r.ExitCode)
	}
	if doc := oneDoc(t, r); doc["reason"] != "unreadable boot ID" {
		t.Fatalf("document %v", doc)
	}
	if calls := h.logged(t); calls != "" {
		t.Fatalf("a reboot was scheduled after a bad boot ID: %q", calls)
	}
}

// Ist-Verhalten, system.reboot is a durable job (its header says so). The
// attached path is only a check: hostrun.Attached refuses an execution ID
// that is not a lowercase UUID before any remote command runs, so the
// script's own "no execution ID" precheck is never reached through it.
func TestSystemRebootAttachedRefusesMissingExecutionID(t *testing.T) {
	h := newWSHost(t)
	h.fake(t, "systemd-run", `echo "systemd-run $*" >> "`+h.calls+`"; exit 0`)
	a, _ := Lookup("system.reboot")
	script := "PATH='" + h.fullPath() + "'; export PATH\n" + string(a.Script)
	_, err := hostrun.Attached(context.Background(), hostrunClient(t), "", []byte(`{}`), []byte(script), a.Timeout)
	if err == nil {
		t.Fatal("an empty execution ID was accepted")
	}
	if calls := h.logged(t); calls != "" {
		t.Fatalf("a run started: %q", calls)
	}
}

// The script's own check of NEBULA_EXECUTION_ID, run with /bin/sh directly
// (no hostrun): exit 10, "no execution ID", and no systemd-run call.
func TestSystemRebootScriptRefusesMissingExecutionID(t *testing.T) {
	h := newWSHost(t)
	h.fake(t, "head", `echo `+wsBootID)
	h.fake(t, "systemd-run", `echo "systemd-run $*" >> "`+h.calls+`"; exit 0`)
	a, _ := Lookup("system.reboot")
	p := filepath.Join(h.dir, "action.sh")
	if err := os.WriteFile(p, a.Script, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", p)
	cmd.Dir = h.dir
	cmd.Env = []string{"PATH=" + h.fullPath()}
	out, _ := cmd.Output()
	if cmd.ProcessState.ExitCode() != hostrun.ExitPrecheckFailed {
		t.Fatalf("exit %d, output %q", cmd.ProcessState.ExitCode(), out)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil || doc["reason"] != "no execution ID" {
		t.Fatalf("output %q: %v", out, err)
	}
	if calls := h.logged(t); calls != "" {
		t.Fatalf("a reboot was scheduled without an execution ID: %q", calls)
	}
}

// The scheduling step hands systemd-run the timer and the reboot command and
// starts nothing itself. The attached run ends with class success, one
// "scheduled" document and the boot ID.
func TestSystemRebootSchedulesThroughHostrun(t *testing.T) {
	h := newWSHost(t)
	h.fake(t, "head", `echo `+wsBootID)
	h.fake(t, "systemd-run", `echo "systemd-run $*" >> "`+h.calls+`"; exit 0`)
	a, _ := Lookup("system.reboot")
	r := h.attached(t, a, `{}`, h.fullPath())
	if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
		t.Fatalf("class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
	}
	doc := oneDoc(t, r)
	if doc["phase"] != "scheduled" || doc["await_reboot"] != true || doc["boot_id"] != wsBootID {
		t.Fatalf("document %v", doc)
	}
	want := "systemd-run --quiet --on-active=15s --unit=nebula-reboot-" + wsRunID + " /bin/systemctl reboot"
	if !strings.Contains(h.logged(t), want) {
		t.Fatalf("calls %q, want %q", h.logged(t), want)
	}
}

// systemd-run fails: the script reports "could not schedule the reboot" with
// exit 10 and one precheck document, class precheck_failed.
func TestSystemRebootSchedulingFailureIsPrecheck(t *testing.T) {
	h := newWSHost(t)
	h.fake(t, "head", `echo `+wsBootID)
	h.fake(t, "systemd-run", `echo "Failed to connect to bus" >&2; exit 1`)
	a, _ := Lookup("system.reboot")
	r := h.attached(t, a, `{}`, h.fullPath())
	if r.Class != hostrun.ClassPrecheckFailed || r.ExitCode != hostrun.ExitPrecheckFailed {
		t.Fatalf("class %s (%s), exit %d", r.Class, r.Detail, r.ExitCode)
	}
	if doc := oneDoc(t, r); doc["reason"] != "could not schedule the reboot" {
		t.Fatalf("document %v", doc)
	}
}
