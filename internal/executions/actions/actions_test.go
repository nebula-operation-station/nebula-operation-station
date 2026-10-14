// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeHost is a PATH with stand-ins for the commands the install script
// uses, so its logic can be tested without touching the system.
type fakeHost struct {
	dir, bin, calls string
}

func newFakeHost(t *testing.T, availKB string) *fakeHost {
	t.Helper()
	d := t.TempDir()
	f := &fakeHost{dir: d, bin: filepath.Join(d, "bin"), calls: filepath.Join(d, "calls")}
	if err := os.Mkdir(f.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	f.write(t, "id", `echo 0`)
	f.write(t, "df", `echo "Filesystem 1K-blocks Used Available Use% Mounted"; echo "/dev/x 1 1 `+availKB+` 1% $2"`)
	f.write(t, "systemctl", `exit 0`)
	f.write(t, "dpkg-query", `cat "`+d+`/pkgstate" 2>/dev/null; echo "openssl 2 ii"`)
	f.write(t, "dpkg", `[ -e "`+d+`/audit-dirty" ] && echo "broken: foo"; exit 0`)
	f.write(t, "apt-get", `echo "$@" >> "`+f.calls+`"
case "$*" in
  *" -s "*|-s*) printf '%s\n' "Inst openssl [1] (2 Debian-Security:12/stable-security [amd64])" "Inst vim [1] (2 Debian:12/stable [amd64])" ;;
  *install*|*upgrade*)
    [ -e "`+d+`/lock-held" ] && { echo "E: Could not get lock /var/lib/dpkg/lock-frontend" >&2; exit 100; }
    [ -e "`+d+`/lock-after-change" ] && { echo "openssl 3" > "`+d+`/pkgstate"; echo "E: Could not get lock /var/lib/dpkg/lock" >&2; exit 100; }
    [ -e "`+d+`/break-after" ] && : > "`+d+`/audit-dirty"
    echo "Setting up openssl" ;;
esac
exit 0`)
	return f
}

func (f *fakeHost) write(t *testing.T, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func (f *fakeHost) run(t *testing.T, script []byte) (int, map[string]any) {
	t.Helper()
	p := filepath.Join(f.dir, "action.sh")
	if err := os.WriteFile(p, script, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", p)
	cmd.Dir = f.dir
	cmd.Env = []string{"PATH=" + f.bin + ":/usr/bin:/bin"}
	out, err := cmd.Output()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("result %q: %v", out, err)
	}
	return code, doc
}

func b64(t *testing.T, doc map[string]any, key string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(doc[key].(string))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestInstallSecurityInstallsOnlySecurityPackages(t *testing.T) {
	f := newFakeHost(t, "9999999")
	code, doc := f.run(t, installScript("install_security"))
	if code != 0 || doc["phase"] != "done" || doc["apt_exit"] != 0.0 || b64(t, doc, "packages") != "openssl" {
		t.Fatalf("%d %v", code, doc)
	}
	calls, _ := os.ReadFile(f.calls)
	if !strings.Contains(string(calls), "-q -y -o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confold install --only-upgrade openssl\n") ||
		strings.Contains(string(calls), "only-upgrade openssl vim") {
		t.Fatalf("apt calls:\n%s", calls)
	}
}

func TestInstallAllUpgrades(t *testing.T) {
	f := newFakeHost(t, "9999999")
	code, doc := f.run(t, installScript("install_all"))
	calls, _ := os.ReadFile(f.calls)
	if code != 0 || b64(t, doc, "packages") != "openssl\nvim" || !strings.Contains(string(calls), "--force-confold upgrade\n") {
		t.Fatalf("%d %v\n%s", code, doc, calls)
	}
}

func TestInstallChecks(t *testing.T) {
	for name, tc := range map[string]struct {
		avail, marker, phase, want string
		code                       int
	}{
		"low space":    {avail: "1000", phase: "precheck", want: "less than 500 MB", code: 10},
		"dirty dpkg":   {avail: "9999999", marker: "audit-dirty", phase: "precheck", want: "dpkg --audit", code: 10},
		"lock held":    {avail: "9999999", marker: "lock-held", phase: "precheck", want: "package lock", code: 10},
		"broken after": {avail: "9999999", marker: "break-after", phase: "done", code: 11},
		// apt changed packages, then failed with the lock text: not a
		// precheck failure, the install is reported as it happened.
		"lock text after a change": {avail: "9999999", marker: "lock-after-change", phase: "done", code: 100},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeHost(t, tc.avail)
			if tc.marker != "" {
				if err := os.WriteFile(filepath.Join(f.dir, tc.marker), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			code, doc := f.run(t, installScript("install_security"))
			if code != tc.code || doc["phase"] != tc.phase || (tc.want != "" && !strings.Contains(doc["reason"].(string), tc.want)) {
				t.Fatalf("%d %v", code, doc)
			}
			if name == "broken after" && doc["dpkg_audit_clean"] != false {
				t.Fatalf("%v", doc)
			}
		})
	}
}

func TestBuiltinScriptsAreDistinctAndValid(t *testing.T) {
	seen := map[string]string{}
	for _, a := range Builtin {
		if prev, ok := seen[a.SHA256()]; ok {
			t.Fatalf("%s and %s have the same script", a.ID, prev)
		}
		seen[a.SHA256()] = a.ID
		if out, err := exec.Command("/bin/sh", "-n", "-c", string(a.Script)).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v %s", a.ID, err, out)
		}
		if strings.Contains(string(a.Script), "@MODE@") {
			t.Fatalf("%s: template not rendered", a.ID)
		}
	}
}

func TestServiceParamsAreStrict(t *testing.T) {
	a, _ := Lookup("service.restart")
	for _, bad := range []map[string]string{nil, {}, {"unit": "-x"}, {"unit": "a b"}, {"unit": "x\"; rm -rf /"}, {"unit": "ok", "more": "x"}, {"other": "x"}} {
		if a.ValidParams(bad) == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	if err := a.ValidParams(map[string]string{"unit": "nginx.service"}); err != nil {
		t.Fatal(err)
	}
}

func TestServiceControlScript(t *testing.T) {
	f := newFakeHost(t, "1")
	f.write(t, "id", `echo 1000`)
	f.write(t, "sudo", `[ "$1" = "-n" ] && shift; echo "sudo $*" >> "`+f.calls+`"; "$@"`)
	f.write(t, "systemctl", `echo "systemctl $*" >> "`+f.calls+`"; [ "$1" = show ] && echo "ActiveState=active"; exit 0`)
	f.write(t, "journalctl", `echo "journal line"`)
	a, _ := Lookup("service.restart")
	params := filepath.Join(f.dir, "params.json")
	run := func(p string) (int, map[string]any) {
		if err := os.WriteFile(params, []byte(p), 0o600); err != nil {
			t.Fatal(err)
		}
		script := filepath.Join(f.dir, "action.sh")
		if err := os.WriteFile(script, a.Script, 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("/bin/sh", script)
		cmd.Dir = f.dir
		cmd.Env = []string{"PATH=" + f.bin + ":/usr/bin:/bin", "NEBULA_PARAMS=" + params}
		out, err := cmd.Output()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		var doc map[string]any
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatalf("%q: %v", out, err)
		}
		return code, doc
	}
	code, doc := run(`{"unit":"nginx.service"}`)
	calls, _ := os.ReadFile(f.calls)
	if code != 0 || doc["verb"] != "restart" || !strings.Contains(string(calls), "sudo systemctl restart -- nginx.service") {
		t.Fatalf("%d %v\n%s", code, doc, calls)
	}
	// Anything but the canonical one-key document is refused by the script.
	for _, p := range []string{`{"unit":"-x"}`, `{"unit":"a;b"}`, `{"unit":"x","y":"z"}`, `{"unit":"$(id)"}`} {
		if code, doc := run(p); code != 10 || doc["phase"] != "precheck" {
			t.Errorf("%s: %d %v", p, code, doc)
		}
	}
}

// The security package list comes from the host's apt output; a hostile
// host must not turn it into apt-get options or a glob (Hermes review).
func TestInstallSecurityRefusesHostileSimulationOutput(t *testing.T) {
	for name, line := range map[string]string{
		"option":     "Inst -o (x foo-security [amd64])",
		"apt option": "Inst Dpkg::Pre-Install-Pkgs::=/tmp/evil (y foo-security [amd64])",
		"glob":       "Inst * (1 Debian-Security:12/stable-security [amd64])",
		"upper":      "Inst EVIL (1 Debian-Security:12/stable-security [amd64])",
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeHost(t, "9999999")
			f.write(t, "apt-get", `echo "$@" >> "`+f.calls+`"
case "$*" in *" -s "*|-s*) printf '%s\n' '`+line+`' "Inst openssl [1] (2 Debian-Security:12/stable-security [amd64])" ;; esac
exit 0`)
			code, doc := f.run(t, installScript("install_security"))
			calls, _ := os.ReadFile(f.calls)
			if code != 10 || doc["phase"] != "precheck" || strings.Contains(string(calls), "only-upgrade") {
				t.Fatalf("%d %v\n%s", code, doc, calls)
			}
		})
	}
}
