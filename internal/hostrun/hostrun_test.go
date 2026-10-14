// SPDX-License-Identifier: AGPL-3.0-or-later

package hostrun_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun/hostruntest"
)

const execID = "0b9c2f7e-4a51-4c8e-9a51-6f0d3c2b1a00"

func client(t *testing.T) *ssh.Client {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	srv := hostruntest.Start(t, signer.PublicKey())
	c, err := ssh.Dial("tcp", srv.Addr, &ssh.ClientConfig{User: "nebula", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(srv.HostKey.PublicKey()), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func run(t *testing.T, c *ssh.Client, params, script string, timeout time.Duration) hostrun.Result {
	t.Helper()
	r, err := hostrun.Attached(context.Background(), c, execID, []byte(params), []byte(script), timeout)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSuccessGetsParametersAndExecutionID(t *testing.T) {
	c := client(t)
	params := `{"note":"it's a \"quote\"\nand ünïcode $(id) ` + "`id`" + `"}`
	r := run(t, c, params, `printf '%s' "$NEBULA_EXECUTION_ID" >&2; echo "dir=$PWD" >&2; cat "$NEBULA_PARAMS"`, 0)
	if r.Class != hostrun.ClassSuccess || string(r.Result) != params || !strings.HasPrefix(string(r.Log), execID) {
		t.Fatalf("%+v log %q", r, r.Log)
	}
	// The private temporary directory is gone afterwards.
	dir := strings.TrimSpace(strings.SplitN(string(r.Log), "dir=", 2)[1])
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("%s still exists: %v", dir, err)
	}
}

func TestPrivateFilesAndNoStdin(t *testing.T) {
	c := client(t)
	r := run(t, c, `{}`, `ls -ld . action.sh params.json | cut -c1-10 >&2; cat; echo '{"ok":true}'`, 0)
	if r.Class != hostrun.ClassSuccess {
		t.Fatalf("%+v %q", r, r.Log)
	}
	for _, l := range strings.Split(strings.TrimSpace(string(r.Log)), "\n") {
		if l != "drwx------" && l != "-rw-------" {
			t.Fatalf("permissions %q", r.Log)
		}
	}
}

func TestClasses(t *testing.T) {
	c := client(t)
	big := strings.Repeat("x", hostrun.MaxResult)
	for name, tc := range map[string]struct {
		script, class string
		exit          int
	}{
		"failure":                  {`echo boom >&2; exit 3`, hostrun.ClassScriptFailed, 3},
		"no result":                {`true`, hostrun.ClassResultMissing, 0},
		"not json":                 {`echo hello`, hostrun.ClassScriptFailed, 0},
		"two documents":            {`echo '{}'; echo '{}'`, hostrun.ClassScriptFailed, 0},
		"invalid utf-8":            {`printf '"\377"'`, hostrun.ClassScriptFailed, 0},
		"too large":                {`printf '"'; head -c ` + strconv.Itoa(len(big)) + ` /dev/zero | tr '\0' x; printf '"'`, hostrun.ClassScriptFailed, 0},
		"own 122 is not bootstrap": {`exit 122`, hostrun.ClassScriptFailed, 122},
		"killed":                   {`kill -TERM $$`, hostrun.ClassScriptInterrupted, -1},
		"precheck":                 {`echo '{"reason":"no space"}'; exit 10`, hostrun.ClassPrecheckFailed, 10},
		"postcheck":                {`echo '{"x":1}'; exit 11`, hostrun.ClassPostcheckFailed, 11},
	} {
		t.Run(name, func(t *testing.T) {
			r := run(t, c, `{}`, tc.script, 0)
			if r.Class != tc.class || (tc.exit >= 0 && r.ExitCode != tc.exit) {
				t.Fatalf("%+v log %q", r, r.Log)
			}
			if (tc.class == hostrun.ClassPrecheckFailed || tc.class == hostrun.ClassPostcheckFailed) && len(r.Result) == 0 {
				t.Fatalf("check result dropped for %s", name)
			}
			if tc.class == hostrun.ClassScriptFailed && len(r.Result) > 0 && name != "failure" {
				t.Fatalf("result kept for %s: %d bytes", name, len(r.Result))
			}
		})
	}
}

func TestLogIsTruncatedVisibly(t *testing.T) {
	c := client(t)
	r := run(t, c, `{}`, `head -c 11534336 /dev/zero | tr '\0' a >&2; echo '{}'`, 0)
	if r.Class != hostrun.ClassSuccess || !r.LogTruncated || len(r.Log) != hostrun.MaxLog+len(hostrun.TruncationMarker) ||
		!bytes.HasSuffix(r.Log, []byte(hostrun.TruncationMarker)) {
		t.Fatalf("class %s truncated %v len %d", r.Class, r.LogTruncated, len(r.Log))
	}
}

func TestTimeout(t *testing.T) {
	c := client(t)
	start := time.Now()
	r := run(t, c, `{}`, `sleep 30; echo '{}'`, 300*time.Millisecond)
	if r.Class != hostrun.ClassExecutionTimeout || time.Since(start) > 10*time.Second {
		t.Fatalf("%+v after %s", r, time.Since(start))
	}
	// The connection is still usable for the next run.
	if r := run(t, c, `{}`, `echo '{}'`, 0); r.Class != hostrun.ClassSuccess {
		t.Fatalf("next run: %+v", r)
	}
}

func TestCommandIsFixed(t *testing.T) {
	for _, id := range []string{"", "x", strings.ToUpper(execID), execID + "'; rm -rf /; '"} {
		if _, err := hostrun.Command(id); err == nil {
			t.Errorf("execution ID %q accepted", id)
		}
	}
	a, _ := hostrun.Command(execID)
	if !strings.HasPrefix(a, "exec /bin/sh -c '") || strings.Count(a, execID) != 1 {
		t.Fatalf("command %q", a)
	}
}
