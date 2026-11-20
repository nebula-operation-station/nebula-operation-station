// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/servicecheck"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
)

// serviceRunID is the execution ID the attached runs in this file use.
const serviceRunID = "3f0c9e52-7d1a-4b8e-9c2f-5a6d7e8f9a0b"

// serviceFakes is a directory of fake systemctl, journalctl and sudo
// programs. The fakes print the files the test writes into the directory
// and append every call to calls. sudo only drops -n and runs its command.
// The directory is put in front of PATH; nothing else is set for the script.
type serviceFakes struct{ dir string }

func newServiceFakes(t *testing.T) *serviceFakes {
	t.Helper()
	f := &serviceFakes{dir: t.TempDir()}
	shim := func(name, body string) {
		t.Helper()
		body = strings.ReplaceAll(body, "@DIR@", f.dir)
		if err := os.WriteFile(filepath.Join(f.dir, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	shim("systemctl", `#!/bin/sh
echo "systemctl $*" >> '@DIR@/calls'
case $1 in
list-units) cat '@DIR@/units' ;;
show) cat '@DIR@/show' ;;
*) exit 1 ;;
esac
`)
	shim("journalctl", `#!/bin/sh
echo "journalctl $*" >> '@DIR@/calls'
cat '@DIR@/journal'
`)
	shim("sudo", `#!/bin/sh
[ "$1" = -n ] && shift
exec "$@"
`)
	for _, name := range []string{"calls", "units", "show", "journal"} {
		f.set(t, name, "")
	}
	return f
}

// set writes one data file of the fakes.
func (f *serviceFakes) set(t *testing.T, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// calls returns the recorded calls of the systemd fakes (empty when none).
func (f *serviceFakes) calls(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.dir, "calls"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// prefix is the only text put in front of the unchanged script.
func (f *serviceFakes) prefix() string {
	return "PATH='" + f.dir + "':${PATH:-/usr/bin:/bin}; export PATH\n"
}

// runServiceAction runs the registered action's script as an attached run
// through hostrun.Attached, with params as the canonical parameter document
// and prefix in front of the script.
func runServiceAction(t *testing.T, id string, params []byte, prefix string) hostrun.Result {
	t.Helper()
	a, ok := Lookup(id)
	if !ok {
		t.Fatalf("%s is not registered", id)
	}
	script := []byte(prefix + string(a.Script))
	r, err := hostrun.Attached(context.Background(), hostrunClient(t), serviceRunID, params, script, a.Timeout)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// canonicalServiceParams checks params against the action's parameters
// (ValidParams, as the server does) and returns them as the canonical
// JSON object: compact, keys sorted.
func canonicalServiceParams(t *testing.T, id string, params map[string]string) []byte {
	t.Helper()
	a, ok := Lookup(id)
	if !ok {
		t.Fatalf("%s is not registered", id)
	}
	if err := a.ValidParams(params); err != nil {
		t.Fatalf("%s: ValidParams: %v", id, err)
	}
	b, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// assertOneCleanLine checks that a result is one line of ASCII JSON: no raw
// control bytes, no raw non-ASCII bytes, one trailing newline at most.
func assertOneCleanLine(t *testing.T, result []byte) {
	t.Helper()
	if n := strings.Count(string(result), "\n"); n > 1 {
		t.Errorf("result has %d newlines, want one document", n)
	}
	for _, b := range result {
		if (b < 0x20 && b != '\n') || b == 0x7f || b > 0x7e {
			t.Fatalf("result has raw byte %#x:\n%q", b, result)
		}
	}
}

// TestServiceListThroughHostrunReadsAllUnits: a host with 400 service units,
// some with \x2d escapes and @ instances, gives one accepted document that
// the systemd parser reads back completely.
func TestServiceListThroughHostrunReadsAllUnits(t *testing.T) {
	f := newServiceFakes(t)
	var units strings.Builder
	for i := 0; i < 400; i++ {
		switch i % 4 {
		case 0:
			fmt.Fprintf(&units, "getty@tty%d.service loaded active running Getty on tty%d\n", i, i)
		case 1:
			fmt.Fprintf(&units, "app\\x2dsvc\\x2d%04d.service loaded active running App \\x2d service %d\n", i, i)
		case 2:
			fmt.Fprintf(&units, "systemd-fsck@dev-disk\\x2dby\\x2duuid\\x2d%04d.service loaded inactive dead File system check %d\n", i, i)
		default:
			fmt.Fprintf(&units, "plain-unit-%04d.service loaded failed failed Plain unit %d\n", i, i)
		}
	}
	f.set(t, "units", units.String())

	r := runServiceAction(t, "service.list", []byte(`{}`), f.prefix())
	if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
		t.Fatalf("class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
	}
	if len(r.Result) > hostrun.MaxResult {
		t.Fatalf("result %d bytes, limit %d", len(r.Result), hostrun.MaxResult)
	}
	assertOneCleanLine(t, r.Result)
	got, err := osdebian.ParseUnits(r.Result)
	if err != nil {
		t.Fatalf("ParseUnits: %v", err)
	}
	if len(got) != 400 {
		t.Fatalf("%d units, want 400", len(got))
	}
	names := map[string]bool{}
	for _, u := range got {
		names[u.Name] = true
	}
	for _, want := range []string{`getty@tty0.service`, `app\x2dsvc\x2d0001.service`, `systemd-fsck@dev-disk\x2dby\x2duuid\x2d0002.service`, `plain-unit-0003.service`} {
		if !names[want] {
			t.Errorf("unit %q missing from the parsed list", want)
		}
	}
}

// TestServiceStatusThroughHostrunHostileJournal: 50 journal lines with quotes,
// a backslash, control bytes, DEL, a tab and valid UTF-8 give one accepted
// document; the parser returns the same 50 lines.
func TestServiceStatusThroughHostrunHostileJournal(t *testing.T) {
	f := newServiceFakes(t)
	f.set(t, "show", "Id=nginx.service\nDescription=A high performance web server\nLoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\nActiveEnterTimestamp=Fri 2026-11-20 08:00:00 UTC\nMainPID=1234\n")
	var journal []string
	for i := 0; i < 50; i++ {
		journal = append(journal, fmt.Sprintf("2026-11-20T08:%02d:00+00:00 host nginx[1234]: \"quoted\" back\\slash ctl\x01\x1b[31mred\x7f tab\there ü %d", i, i))
	}
	f.set(t, "journal", strings.Join(journal, "\n")+"\n")

	params := canonicalServiceParams(t, "service.status", map[string]string{"unit": "nginx.service"})
	r := runServiceAction(t, "service.status", params, f.prefix())
	if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
		t.Fatalf("class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
	}
	assertOneCleanLine(t, r.Result)
	st, err := osdebian.ParseServiceStatus(r.Result)
	if err != nil {
		t.Fatalf("ParseServiceStatus: %v", err)
	}
	if st.Phase != "done" {
		t.Errorf("phase %q, want done", st.Phase)
	}
	if len(st.Props) != 8 || st.Props[0] != (osdebian.Prop{Name: "Id", Value: "nginx.service"}) {
		t.Errorf("props = %+v", st.Props)
	}
	if len(st.Journal) != 50 {
		t.Fatalf("%d journal lines, want 50", len(st.Journal))
	}
	for i := range journal {
		if st.Journal[i] != journal[i] {
			t.Fatalf("journal line %d = %q, want %q", i, st.Journal[i], journal[i])
		}
	}
}

// TestServiceStatusThroughHostrunInvalidUTF8Journal: a journal line that is not
// UTF-8 still gives one accepted document and a parsed "done" status. The
// journal lines themselves are not asserted: the production parser drops the
// whole journal block when any line is not valid UTF-8 (see the report).
func TestServiceStatusThroughHostrunInvalidUTF8Journal(t *testing.T) {
	f := newServiceFakes(t)
	f.set(t, "show", "Id=nginx.service\nActiveState=active\n")
	f.set(t, "journal", "2026-11-20T08:00:00+00:00 host nginx: ok\n2026-11-20T08:00:01+00:00 host nginx: bad \xff\xc3 bytes\n")

	params := canonicalServiceParams(t, "service.status", map[string]string{"unit": "nginx.service"})
	r := runServiceAction(t, "service.status", params, f.prefix())
	if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
		t.Fatalf("class %s (%s), exit %d", r.Class, r.Detail, r.ExitCode)
	}
	assertOneCleanLine(t, r.Result)
	st, err := osdebian.ParseServiceStatus(r.Result)
	if err != nil || st.Phase != "done" || len(st.Props) != 2 {
		t.Fatalf("parse: %v, %+v", err, st)
	}
	t.Logf("journal lines the parser kept for invalid UTF-8 input: %d", len(st.Journal))
}

// TestServiceStatusScriptRejectsUnitBeforeSystemctl: a unit the script itself
// refuses (passed past ValidParams, straight to hostrun.Attached) exits with
// the precheck status, is classed as a precheck failure, and never calls
// systemctl.
func TestServiceStatusScriptRejectsUnitBeforeSystemctl(t *testing.T) {
	f := newServiceFakes(t)
	r := runServiceAction(t, "service.status", []byte(`{"unit":"-x"}`), f.prefix())
	if r.ExitCode != hostrun.ExitPrecheckFailed || r.Class != hostrun.ClassPrecheckFailed {
		t.Fatalf("class %s, exit %d (%s), result %q", r.Class, r.ExitCode, r.Detail, r.Result)
	}
	if calls := f.calls(t); calls != "" {
		t.Fatalf("systemd was called: %q", calls)
	}
	st, err := osdebian.ParseServiceStatus(r.Result)
	if err != nil || st.Phase != "precheck" {
		t.Fatalf("parse: %v, %+v", err, st)
	}
}

// TestServiceCheckThroughHostrunTCPAndHTTP runs service.check over
// hostrun.Attached against loopback listeners in the test, with the parameters
// ValidParams accepts. Only the destination is approved as internal (127.0.0.1
// is a reserved address). The probe needs python3, as the existing test does.
func TestServiceCheckThroughHostrunTCPAndHTTP(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tcpPort := tcpLn.Addr().(*net.TCPAddr).Port
	httpPort := srv.Listener.Addr().(*net.TCPAddr).Port
	for _, tc := range []struct {
		name     string
		protocol string
		port     int
		want     servicecheck.Status
		status   int
	}{
		{"tcp", "tcp", tcpPort, servicecheck.StatusOK, 0},
		{"http", "http", httpPort, servicecheck.StatusOK, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			params := canonicalServiceParams(t, "service.check", map[string]string{
				"destination": "127.0.0.1",
				"port":        strconv.Itoa(tc.port),
				"protocol":    tc.protocol,
				"internal":    "yes",
			})
			r := runServiceAction(t, "service.check", params, "")
			if r.Class != hostrun.ClassSuccess || r.ExitCode != 0 {
				t.Fatalf("class %s (%s), exit %d, log %q", r.Class, r.Detail, r.ExitCode, r.Log)
			}
			assertOneCleanLine(t, r.Result)
			res, err := servicecheck.ParseResult(r.Result)
			if err != nil {
				t.Fatalf("ParseResult: %v (%q)", err, r.Result)
			}
			if res.Status != tc.want || res.HTTPStatus != tc.status {
				t.Fatalf("status %s http %d, want %s http %d", res.Status, res.HTTPStatus, tc.want, tc.status)
			}
		})
	}
}
