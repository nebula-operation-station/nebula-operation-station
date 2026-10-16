// SPDX-License-Identifier: AGPL-3.0-or-later

package hostrun_test

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
)

var tokens = []hostrun.Secret{{Slot: "token", Value: []byte("s3cr3t-value\n'\"$(id)")}, {Slot: "other", Value: []byte{0, 1, 2, 255}}}

const readSecrets = `ls -l "$NEBULA_SECRETS_DIR" | cut -c1-10 >&2; echo "dir=$NEBULA_SECRETS_DIR" >&2; od -An -c "$NEBULA_SECRETS_DIR/other" >&2; printf '{"t":"%s"}' "$(base64 -w0 < "$NEBULA_SECRETS_DIR/token")"`

var wantResult = `{"t":"` + base64.StdEncoding.EncodeToString(tokens[0].Value) + `"}`

// Spec 06: attached secrets live in a private directory on the user's
// runtime tmpfs, only while the script runs.
func TestAttachedSecrets(t *testing.T) {
	if fs, err := os.Stat("/dev/shm"); err != nil || !fs.IsDir() {
		t.Skip("no /dev/shm")
	}
	rt, err := os.MkdirTemp("/dev/shm", "xdg")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { os.RemoveAll(rt) })
	t.Setenv("XDG_RUNTIME_DIR", rt)
	c := client(t)
	r, err := hostrun.Attached(context.Background(), c, execID, []byte(`{}`), []byte(readSecrets), time.Minute, tokens...)
	if err != nil || r.Class != hostrun.ClassSuccess {
		t.Fatalf("%+v %v %q", r, err, r.Log)
	}
	if string(r.Result) != wantResult {
		t.Fatalf("result %q log %q", r.Result, r.Log)
	}
	log := string(r.Log)
	if strings.Count(log, "-rw-------") != 2 || !strings.Contains(log, `\0 001 002 377`) {
		t.Fatalf("log %q", log)
	}
	dir := strings.TrimSpace(strings.SplitN(strings.SplitN(log, "dir=", 2)[1], "\n", 2)[0])
	if !strings.HasPrefix(dir, rt+"/nebula-secrets.") {
		t.Fatalf("secrets in %s", dir)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("%s still exists", dir)
	}
	// Without a runtime directory the run does not start.
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	c2 := client(t)
	r, _ = hostrun.Attached(context.Background(), c2, execID, []byte(`{}`), []byte("echo ran"), time.Minute, tokens...)
	if strings.Contains(string(r.Result), "ran") || !strings.Contains(string(r.Log), "not a tmpfs") {
		t.Fatalf("%+v %q", r, r.Log)
	}
	t.Setenv("XDG_RUNTIME_DIR", "")
	c3 := client(t)
	r, _ = hostrun.Attached(context.Background(), c3, execID, []byte(`{}`), []byte("echo ran"), time.Minute, tokens...)
	if strings.Contains(string(r.Result), "ran") || !strings.Contains(string(r.Log), "no runtime directory") {
		t.Fatalf("%+v %q", r, r.Log)
	}
	// Bad slots are refused before anything is sent.
	for _, bad := range [][]hostrun.Secret{{{Slot: "Token", Value: []byte("x")}}, {{Slot: "a", Value: nil}}, {{Slot: "a", Value: []byte("x")}, {Slot: "a", Value: []byte("y")}},
		{{Slot: "a b", Value: []byte("x")}}} {
		if _, err := hostrun.Attached(context.Background(), c, execID, []byte(`{}`), []byte("true"), time.Minute, bad...); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestDurableSecrets(t *testing.T) {
	c := client(t)
	cfg := jobConfig(t)
	ctx := context.Background()
	out, detail, err := hostrun.Dispatch(ctx, c, cfg, execID, []byte(`{}`), []byte(readSecrets), time.Minute, tokens...)
	if err != nil || out != hostrun.Dispatched {
		t.Fatalf("dispatch: %v %s %v", out, detail, err)
	}
	st := waitPhase(t, func() hostrun.JobState { s, _ := hostrun.Check(ctx, c, cfg, execID); return s }, "finished")
	r, err := hostrun.Collect(ctx, c, cfg, execID, st.ExitCode)
	if err != nil || string(r.Result) != wantResult || !strings.Contains(string(r.Log), "dir="+filepath.Join(cfg.RunRoot, execID, "secrets")) {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := os.Stat(filepath.Join(cfg.RunRoot, execID)); !os.IsNotExist(err) {
		t.Fatal("secrets left on the host")
	}
	// Nothing in the job directory holds a secret.
	for _, f := range []string{"action.sh", "state.json", "execution.log"} {
		b, _ := os.ReadFile(filepath.Join(cfg.JobRoot, execID, f))
		if strings.Contains(string(b), "s3cr3t") {
			t.Fatalf("%s holds the secret", f)
		}
	}
}

func TestRedact(t *testing.T) {
	got := string(hostrun.Redact([]byte("a s3cr3t-value\n'\"$(id) b \x00\x01\x02\xff"), tokens))
	if got != "a [secret token redacted] b [secret other redacted]" {
		t.Fatalf("%q", got)
	}
}
