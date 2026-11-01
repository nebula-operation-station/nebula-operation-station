// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestTimezoneVerifyLive runs the real prelude artifact of
// timezone/verify on the test host and checks the exit-code and result
// semantics against the host's actual state: a consistent host passes,
// a drifted host fails with the drifted parts named, a wrong zone fails,
// and a value the type pattern rejects dies in the precheck. The test is
// read-only and skips where the host has no /etc/localtime symlink.
func TestTimezoneVerifyLive(t *testing.T) {
	ms, err := Load(treeRoot)
	if err != nil {
		t.Fatal(err)
	}
	var m Module
	for _, x := range ms {
		if x.Name == "timezone" {
			m = x
		}
	}
	if m.Name == "" {
		t.Fatal("timezone module not loaded")
	}
	body := m.Scripts["actions/verify.sh"]
	art, _, err := m.Lock.Artifact("verify", body)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "verify.sh")
	if err := os.WriteFile(f, art, 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(zone string) (int, string) {
		params := filepath.Join(t.TempDir(), "params.json")
		if err := os.WriteFile(params, []byte(`{"zone":"`+zone+`"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(f)
		cmd.Env = append(os.Environ(), "NEBULA_PARAMS="+params)
		out, err := cmd.CombinedOutput()
		if err == nil {
			return 0, string(out)
		}
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), string(out)
		}
		t.Fatalf("run: %v", err)
		return -1, ""
	}
	link, err := os.Readlink("/etc/localtime")
	if err != nil {
		t.Skipf("no /etc/localtime symlink: %v", err)
	}
	actual := strings.TrimPrefix(strings.TrimSpace(link), "/usr/share/zoneinfo/")
	fileZone := ""
	if raw, err := os.ReadFile("/etc/timezone"); err == nil {
		fileZone = strings.TrimSpace(string(raw))
	}
	// The zone /etc/localtime points at: the script passes only when
	// /etc/timezone agrees with it.
	rc, out := run("/" + actual)
	t.Logf("host zone %q (file %q): rc=%d out=%s", actual, fileZone, rc, out)
	if actual == fileZone {
		if rc != 0 || !strings.Contains(out, `"ok":true`) {
			t.Errorf("consistent host: want rc 0 and ok:true")
		}
	} else {
		if rc == 0 || !strings.Contains(out, `"ok":false`) {
			t.Errorf("inconsistent host: want rc 1 and ok:false")
		}
	}
	// A zone the host does not have -> ok:false, rc 1.
	wrong := "/Asia/Tokyo"
	if actual == "Asia/Tokyo" {
		wrong = "/America/New_York"
	}
	rc, out = run(wrong)
	t.Logf("mismatch: rc=%d out=%s", rc, out)
	if rc == 0 || !strings.Contains(out, `"ok":false`) {
		t.Error("mismatch case: want rc 1 and ok:false")
	}
	// A value the type pattern rejects -> precheck_failed, rc 10.
	rc, out = run("Europe Berlin")
	t.Logf("precheck: rc=%d out=%s", rc, out)
	if rc != 10 || !strings.Contains(out, "precheck") {
		t.Error("precheck case: want rc 10 and precheck_failed")
	}
}
