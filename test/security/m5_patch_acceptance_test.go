// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
)

// fakeAPT puts stand-ins for apt-get, dpkg, df, id and systemctl first in
// PATH: the test host is this machine, which must not be patched.
func fakeAPT(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	calls := filepath.Join(bin, "calls")
	files := map[string]string{
		"id":        `echo 0`,
		"df":        `echo "Filesystem 1K-blocks Used Available Use% Mounted"; echo "/dev/x 1 1 99999999 1% $2"`,
		"systemctl": `exit 0`,
		"dpkg":      `exit 0`,
		"apt-get": `echo "$@" >> ` + calls + `
case "$*" in
  *" -s "*|-s*) echo "Inst openssl [1] (2 Debian-Security:12/stable-security [amd64])"; echo "Inst vim [1] (2 Debian:12/stable [amd64])" ;;
  *) echo "Setting up openssl" ;;
esac`,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	return calls
}

// M5: security updates are installed as a durable job; only the packages
// from the security archive, with the spec 11 apt options.
func TestM5_InstallSecurityRunsAsDurableJob(t *testing.T) {
	calls := fakeAPT(t)
	a, ok := actions.Lookup("package.install_security")
	if !ok || !a.Durable {
		t.Fatal("package.install_security is not a durable built-in")
	}
	h := newHarness(t, harnessOptions{})
	h.unlock()
	host := h.pinnedRunHost("runhost")
	d := h.approvedScript(host, a.Script)
	r, err := h.client.StartDurable(h.ctx(), durableReq(d, host, a.Script))
	if err != nil {
		t.Fatal(err)
	}
	st := h.reconcileUntil(r.GetRun().GetExecutionId(), "runhost")
	if st.GetClass() != "success" {
		t.Fatalf("%+v", st)
	}
	in, err := osdebian.ParseInstall(st.GetResult())
	if err != nil || in.Phase != "done" || strings.Join(in.Packages, ",") != "openssl" || !in.AuditClean {
		t.Fatalf("%+v %v", in, err)
	}
	b, _ := os.ReadFile(calls)
	if !strings.Contains(string(b), "-o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confold install --only-upgrade openssl") {
		t.Fatalf("apt calls:\n%s", b)
	}
}

// M5: a reboot ends when the host is back with a new boot ID; a host that
// does not reboot in time is host_not_returned.
func TestM5_RebootWaitsForANewBoot(t *testing.T) {
	bin := t.TempDir()
	for name, body := range map[string]string{"id": "echo 0", "systemd-run": "exit 0"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	a, _ := actions.Lookup("system.reboot")

	for name, tc := range map[string]struct {
		newBoot bool
		timeout uint32
		class   string
	}{
		"back":         {newBoot: true, timeout: 120, class: "success"},
		"not returned": {newBoot: false, timeout: 1, class: "host_not_returned"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := privateDir(t)
			h := newHarness(t, harnessOptions{dataDir: dir})
			boot := "/proc/sys/kernel/random/boot_id"
			if tc.newBoot {
				boot = filepath.Join(dir, "boot_id")
				if err := os.WriteFile(boot, []byte("0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1a99\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			h.svc.SetJobConfig(hostrun.JobConfig{JobRoot: filepath.Join(dir, "remote", "jobs"), RunRoot: filepath.Join(dir, "remote", "run"), BootIDFile: boot})
			h.unlock()
			host := h.pinnedRunHost("runhost")
			d := h.approvedScript(host, a.Script)
			req := durableReq(d, host, a.Script)
			req.TimeoutSeconds = tc.timeout
			r, err := h.client.StartDurable(h.ctx(), req)
			if err != nil {
				t.Fatal(err)
			}
			if !tc.newBoot {
				time.Sleep(1500 * time.Millisecond)
			}
			st := h.reconcileUntil(r.GetRun().GetExecutionId(), "runhost")
			if st.GetClass() != tc.class || !strings.Contains(string(st.GetResult()), `"await_reboot":true`) {
				t.Fatalf("%+v", st)
			}
			h.requireAudit("run_awaits_reboot")
		})
	}
}
