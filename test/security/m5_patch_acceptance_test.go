// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/osdebian"
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
