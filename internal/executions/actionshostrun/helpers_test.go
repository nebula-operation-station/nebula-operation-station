// SPDX-License-Identifier: AGPL-3.0-or-later

package actionshostrun_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun/hostruntest"
)

// testExecutionID is a lowercase UUID, as hostrun requires.
const testExecutionID = "8a6e0804-2bd0-4f6a-8b1e-6d2f1c3a4b5c"

// hostTools are the coreutils and text tools the scripts under test use.
// Each is linked into the fake bin directory, which is the only PATH the
// script gets; docker, sudo, apt-get, id and the rest exist only when a test
// writes a fake for them.
var hostTools = []string{"awk", "base64", "cat", "cksum", "grep", "head", "mktemp", "rm", "sed", "sort", "tr"}

// fakeHost is a temporary host: a bin directory with fake tools and a log of
// the calls they received.
type fakeHost struct {
	dir, bin, calls string
}

func newFakeHost(t *testing.T) *fakeHost {
	t.Helper()
	d := t.TempDir()
	h := &fakeHost{dir: d, bin: filepath.Join(d, "bin"), calls: filepath.Join(d, "calls")}
	if err := os.Mkdir(h.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tool := range hostTools {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Fatalf("test needs %s: %v", tool, err)
		}
		if err := os.Symlink(p, filepath.Join(h.bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

// write installs a fake tool with the given shell body.
func (h *fakeHost) write(t *testing.T, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(h.bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// readCalls returns the logged calls, "" when nothing was called.
func (h *fakeHost) readCalls(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(h.calls)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

// script returns the action's script with PATH set to the fake bin directory
// only, so the script sees nothing the test did not put there.
func (h *fakeHost) script(a actions.Action) []byte {
	return []byte("PATH='" + h.bin + "'; export PATH\n" + string(a.Script))
}

// docker installs a fake docker. ctr is the one container the fake knows, as
// "<full ID> <image ID>"; "" means no container. down makes the daemon
// unreachable. The fake logs every call.
func (h *fakeHost) docker(t *testing.T, ctr string, down bool) {
	t.Helper()
	h.write(t, "id", `echo 1000`)
	// Without the docker group the script falls back to sudo -n.
	h.write(t, "sudo", `[ "$1" = -n ] || exit 1; shift; exec "$@"`)
	if ctr != "" {
		if err := os.WriteFile(filepath.Join(h.dir, "ctr"), []byte(ctr+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if down {
		if err := os.WriteFile(filepath.Join(h.dir, "down"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h.write(t, "docker", `echo "$*" >> "`+h.calls+`"
case "$1" in
  version)
    [ -e "`+h.dir+`/down" ] && exit 1
    echo 27 ;;
  inspect)
    [ -e "`+h.dir+`/ctr" ] || exit 1
    read -r id img < "`+h.dir+`/ctr"
    case "$*" in
      *'{{.Id}} {{.Image}}'*) echo "$id $img" ;;
      *'{{.Id}} {{.State.Status}}'*) echo "$id running" ;;
      *) echo running ;;
    esac ;;
  start|stop|restart) echo "$3" ;;
esac
exit 0`)
}

// installTools installs fakes for the package.install_all script: root, a
// roomy disk, a clean dpkg, no failed units and apt-get with the given body
// (after the call is logged). An empty aptBody installs no apt-get at all.
func (h *fakeHost) installTools(t *testing.T, aptBody string) {
	t.Helper()
	h.write(t, "id", `echo 0`)
	h.write(t, "df", `echo "Filesystem 1K-blocks Used Available Use% Mounted"; echo "/dev/x 1 1 9999999 1% /"`)
	h.write(t, "dpkg", `exit 0`)
	h.write(t, "dpkg-query", `exit 0`)
	h.write(t, "systemctl", `exit 0`)
	if aptBody != "" {
		h.write(t, "apt-get", `echo "$*" >> "`+h.calls+`"
`+aptBody)
	}
}

// sshClient connects to an in-process hostrun test server on loopback.
func sshClient(t *testing.T) *ssh.Client {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	srv := hostruntest.Start(t, signer.PublicKey())
	c, err := ssh.Dial("tcp", srv.Addr, &ssh.ClientConfig{User: "nebula", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(srv.HostKey.PublicKey()), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// attach runs script as an attached run through the executor's classifier
// (hostrun.Attached) over SSH. Errors mean nothing started; everything else
// comes back as a result class.
func attach(t *testing.T, script, params []byte, timeout time.Duration) hostrun.Result {
	t.Helper()
	r, err := hostrun.Attached(context.Background(), sshClient(t), testExecutionID, params, script, timeout)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// serverParams builds the parameters document the way the server does: the
// parameter map goes through the action's ParametersJSON (as in
// executions.Batches for batch members and in the single-action path), then
// the RFC 8785 form the permit stores and hashes.
func serverParams(t *testing.T, a actions.Action, params map[string]string) []byte {
	t.Helper()
	if err := a.ValidParams(params); err != nil {
		t.Fatalf("%s: %v", a.ID, err)
	}
	raw, err := a.ParametersJSON(params, nil)
	if err != nil {
		t.Fatal(err)
	}
	canon, _, err := canonical.CanonicalParameters(raw)
	if err != nil {
		t.Fatal(err)
	}
	return canon
}

// oneDocument fails the test unless b is exactly one JSON document on one
// line with no control bytes: the host's output is text, never a terminal
// sequence or a second document.
func oneDocument(t *testing.T, b []byte) {
	t.Helper()
	body := strings.TrimSuffix(string(b), "\n")
	if !json.Valid([]byte(body)) {
		t.Fatalf("result is not one JSON document: %q", b)
	}
	for i := 0; i < len(body); i++ {
		if c := body[i]; c < 0x20 || c == 0x7f {
			t.Fatalf("result has control byte %#x at %d: %q", c, i, b)
		}
	}
}

// verbCalled reports whether a logged call runs verb on a container (the
// bound and standalone scripts both use "verb -- <container>").
func verbCalled(calls, verb string) bool {
	for _, line := range strings.Split(calls, "\n") {
		if strings.HasPrefix(line, verb+" -- ") {
			return true
		}
	}
	return false
}
