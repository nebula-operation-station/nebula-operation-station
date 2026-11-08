// SPDX-License-Identifier: AGPL-3.0-or-later

package actions

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/dockerhost"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// The tests of docker.update_prepare 1.0.0 run the shipped script on the
// fake host of the docker.compose_update 2.0.0 tests; as there, only the
// state directory line of the copy that runs is rewritten (lines, when a
// test names them, replace whole lines to reach a race the host cannot be
// made to show).

type prepareRun struct {
	out, stderr string
	code        int
	status      string
}

func (c *composeV2) prepareScript(t *testing.T, lines map[string]string) string {
	t.Helper()
	a, ok := Lookup("docker.update_prepare")
	if !ok {
		t.Fatal("docker.update_prepare missing")
	}
	s := string(a.Script)
	if strings.Count(s, cuStateDirLine) != 1 {
		t.Fatal("the state directory line is not unique in the prepare script")
	}
	s = strings.Replace(s, cuStateDirLine, `STATE_DIR = "`+c.state+`"`, 1)
	for old, repl := range lines {
		if strings.Count(s, "\n"+old+"\n") != 1 {
			t.Fatalf("line %q is not unique in the prepare script", old)
		}
		s = strings.Replace(s, "\n"+old+"\n", "\n"+repl+"\n", 1)
	}
	return s
}

// prepare runs the prepare script with params (nil is the catalog's {}).
func (c *composeV2) prepare(t *testing.T, params []byte, lines map[string]string) prepareRun {
	t.Helper()
	if params == nil {
		a, _ := Lookup("docker.update_prepare")
		var err error
		if params, err = a.ParametersJSON(map[string]string{}, nil); err != nil {
			t.Fatal(err)
		}
	}
	pp := filepath.Join(c.f.dir, "params.json")
	if err := os.WriteFile(pp, params, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", c.prepareScript(t, lines))
	cmd.Dir = c.f.dir
	cmd.Env = []string{"PATH=" + c.f.bin + ":/usr/bin:/bin", "NEBULA_PARAMS=" + pp, "NEBULA_RUN_DIR=" + c.run,
		"NEBULA_EXECUTION_ID=" + cuExecution}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	r := prepareRun{out: string(out), stderr: stderr.String()}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		r.code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	p, err := dockerhost.ParseUpdatePrepare(out)
	if err != nil {
		t.Fatalf("the parser refuses the script's result %q (stderr %q): %v", out, r.stderr, err)
	}
	r.status = p.Status
	if (r.code == 0) != p.Prepared() {
		t.Fatalf("exit %d with status %s", r.code, p.Status)
	}
	for _, ln := range strings.Split(strings.TrimSpace(r.stderr), "\n") {
		if ln != "" && !strings.HasPrefix(ln, "nos: phase") {
			t.Fatalf("log line %q", ln)
		}
	}
	// Whatever salt is on the host now, neither result nor log holds it
	// in any common encoding.
	if salt, err := os.ReadFile(filepath.Join(c.state, "salt")); err == nil && len(salt) > 0 {
		for _, enc := range []string{string(salt), hex.EncodeToString(salt), base64.StdEncoding.EncodeToString(salt),
			base64.RawURLEncoding.EncodeToString(salt), string(salt[:8]), hex.EncodeToString(salt[:8])} {
			if strings.Contains(r.out, enc) || strings.Contains(r.stderr, enc) {
				t.Fatalf("the salt left the host: %q %q", r.out, r.stderr)
			}
		}
	}
	return r
}

func TestUpdatePrepareCatalog(t *testing.T) {
	a, ok := Lookup("docker.update_prepare")
	if !ok || a.Version != "1.0.0" || !a.Durable || a.ReadOnly || a.Risk != pb.RiskClass_RISK_CLASS_MEDIUM ||
		a.Timeout.Minutes() != 2 || len(a.Params) != 0 || len(a.Secrets) != 0 || a.Retry != RetryReconcileFirst {
		t.Fatalf("%+v", a)
	}
	s := string(a.Script)
	for _, want := range []string{"docker.update_prepare 1.0.0", `FORMAT = "docker-update-prepare-v1"`, "python3 -I", "os.urandom"} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	// The salt is generated and written inside python3, never on a
	// command line or through a shell tool.
	for _, bad := range []string{"openssl", "head -c", "/dev/urandom", "dd ", "subprocess", ">&2"} {
		if strings.Contains(s, bad) {
			t.Errorf("script uses %q", bad)
		}
	}
	if err := a.ValidParams(map[string]string{}); err != nil {
		t.Fatal(err)
	}
	if a.ValidParams(map[string]string{"salt": "x"}) == nil {
		t.Fatal("a parameter was accepted")
	}
}

func readSalt(t *testing.T, c *composeV2) ([]byte, os.FileInfo) {
	t.Helper()
	p := filepath.Join(c.state, "salt")
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b, fi
}

// The first run creates a 32-byte root-only salt in a root-only
// directory; every later run reports present and leaves it byte for byte.
func TestPrepareCreatesSaltOnce(t *testing.T) {
	c := newComposeV2(t)
	r := c.prepare(t, nil, nil)
	if r.code != 0 || r.status != dockerhost.PrepareCreated {
		t.Fatalf("%d %s %s", r.code, r.out, r.stderr)
	}
	salt, fi := readSalt(t, c)
	if len(salt) != 32 || fi.Mode() != 0o600 || !fi.Mode().IsRegular() {
		t.Fatalf("salt %d bytes, mode %v", len(salt), fi.Mode())
	}
	if di, err := os.Lstat(c.state); err != nil || di.Mode() != os.ModeDir|0o700 {
		t.Fatalf("state directory %v %v", di.Mode(), err)
	}
	if _, err := os.Lstat(filepath.Join(c.state, ".salt.tmp")); !os.IsNotExist(err) {
		t.Fatalf("temporary salt left: %v", err)
	}
	for range 2 {
		r = c.prepare(t, nil, nil)
		if r.code != 0 || r.status != dockerhost.PreparePresent {
			t.Fatalf("re-run: %d %s", r.code, r.out)
		}
		again, _ := readSalt(t, c)
		if !bytes.Equal(again, salt) {
			t.Fatal("a re-run changed the salt")
		}
	}
	// A second host (another state directory) gets its own salt.
	d := newComposeV2(t)
	if r := d.prepare(t, nil, nil); r.status != dockerhost.PrepareCreated {
		t.Fatal(r.out)
	}
	other, _ := readSalt(t, d)
	if bytes.Equal(other, salt) {
		t.Fatal("two hosts got the same salt")
	}
}

// A salt the operator or an earlier version put there is kept as it is.
func TestPrepareKeepsExistingSalt(t *testing.T) {
	c := newComposeV2(t)
	if err := os.Mkdir(c.state, 0o700); err != nil {
		t.Fatal(err)
	}
	old := []byte(strings.Repeat("k", 48))
	if err := os.WriteFile(filepath.Join(c.state, "salt"), old, 0o600); err != nil {
		t.Fatal(err)
	}
	r := c.prepare(t, nil, nil)
	if r.code != 0 || r.status != dockerhost.PreparePresent {
		t.Fatalf("%d %s", r.code, r.out)
	}
	if got, _ := readSalt(t, c); !bytes.Equal(got, old) {
		t.Fatal("the existing salt was replaced")
	}
}

// Even when a salt appears between the check and the write (another
// prepare run, the operator), the link refuses to replace it: the run
// reports present and the salt that was there first stays.
func TestPrepareNeverReplacesSaltThatAppears(t *testing.T) {
	c := newComposeV2(t)
	if err := os.Mkdir(c.state, 0o700); err != nil {
		t.Fatal(err)
	}
	first := []byte(strings.Repeat("f", 32))
	if err := os.WriteFile(filepath.Join(c.state, "salt"), first, 0o600); err != nil {
		t.Fatal(err)
	}
	// The run does not see the salt in its first check.
	r := c.prepare(t, nil, map[string]string{"        if salt_state():": "        if False:"})
	if r.code != 0 || r.status != dockerhost.PreparePresent || !strings.Contains(r.stderr, "phase: create") {
		t.Fatalf("%d %s %s", r.code, r.out, r.stderr)
	}
	if got, _ := readSalt(t, c); !bytes.Equal(got, first) {
		t.Fatal("the salt was replaced")
	}
	if _, err := os.Lstat(filepath.Join(c.state, ".salt.tmp")); !os.IsNotExist(err) {
		t.Fatalf("temporary salt left: %v", err)
	}
}

// Anything unexpected at the salt's place or in the state directory is
// refused and left as it is: the salt is never replaced, and a link or
// open modes are not trusted.
func TestPrepareRefusesUnsafeState(t *testing.T) {
	cases := []struct {
		name, status string
		setup        func(t *testing.T, c *composeV2)
	}{
		{"group-readable salt", "salt_unsafe", func(t *testing.T, c *composeV2) {
			writeSalt(t, c, strings.Repeat("s", 32), 0o640)
		}},
		{"short salt", "salt_unsafe", func(t *testing.T, c *composeV2) { writeSalt(t, c, "short", 0o600) }},
		{"empty salt", "salt_unsafe", func(t *testing.T, c *composeV2) { writeSalt(t, c, "", 0o600) }},
		{"oversize salt", "salt_unsafe", func(t *testing.T, c *composeV2) { writeSalt(t, c, strings.Repeat("s", 4097), 0o600) }},
		{"symlinked salt", "salt_unsafe", func(t *testing.T, c *composeV2) {
			mkState(t, c, 0o700)
			target := filepath.Join(c.f.dir, "elsewhere")
			if err := os.WriteFile(target, []byte(strings.Repeat("e", 32)), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(c.state, "salt")); err != nil {
				t.Fatal(err)
			}
		}},
		{"dangling symlink salt", "salt_unsafe", func(t *testing.T, c *composeV2) {
			mkState(t, c, 0o700)
			if err := os.Symlink(filepath.Join(c.f.dir, "nowhere"), filepath.Join(c.state, "salt")); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory salt", "salt_unsafe", func(t *testing.T, c *composeV2) {
			mkState(t, c, 0o700)
			if err := os.Mkdir(filepath.Join(c.state, "salt"), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"open state directory", "state_unsafe", func(t *testing.T, c *composeV2) { mkState(t, c, 0o755) }},
		{"symlinked state directory", "state_unsafe", func(t *testing.T, c *composeV2) {
			real := filepath.Join(c.f.dir, "real-state")
			if err := os.Mkdir(real, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, c.state); err != nil {
				t.Fatal(err)
			}
		}},
		{"state is a file", "state_unsafe", func(t *testing.T, c *composeV2) {
			if err := os.WriteFile(c.state, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newComposeV2(t)
			tc.setup(t, c)
			before := treeOf(t, c.f.dir)
			r := c.prepare(t, nil, nil)
			if r.code != 1 || r.status != tc.status {
				t.Fatalf("%d %s", r.code, r.out)
			}
			after := treeOf(t, c.f.dir)
			for p, h := range after {
				if before[p] != h {
					t.Errorf("%s changed or created", p)
				}
			}
			if len(after) != len(before) {
				t.Errorf("tree changed: %d -> %d entries", len(before), len(after))
			}
		})
	}
}

func mkState(t *testing.T, c *composeV2, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(c.state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(c.state, mode); err != nil {
		t.Fatal(err)
	}
}

func writeSalt(t *testing.T, c *composeV2, body string, mode os.FileMode) {
	t.Helper()
	mkState(t, c, 0o700)
	p := filepath.Join(c.state, "salt")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

// A stale temporary file of a crashed run neither blocks nor becomes the
// salt.
func TestPrepareReplacesStaleTemporaryFile(t *testing.T) {
	c := newComposeV2(t)
	mkState(t, c, 0o700)
	stale := []byte(strings.Repeat("t", 32))
	if err := os.WriteFile(filepath.Join(c.state, ".salt.tmp"), stale, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := c.prepare(t, nil, nil); r.status != dockerhost.PrepareCreated {
		t.Fatal(r.out)
	}
	if got, _ := readSalt(t, c); bytes.Equal(got, stale) {
		t.Fatal("the stale temporary file became the salt")
	}
	if _, err := os.Lstat(filepath.Join(c.state, ".salt.tmp")); !os.IsNotExist(err) {
		t.Fatalf("temporary salt left: %v", err)
	}
}

func TestPrepareRefusesWithoutRootOrWithParameters(t *testing.T) {
	c := newComposeV2(t)
	for name, params := range map[string][]byte{
		"member":    []byte(`{"salt":"x"}`),
		"not json":  []byte(`salt`),
		"list":      []byte(`[]`),
		"too large": []byte(`{"x":"` + strings.Repeat("a", 5000) + `"}`),
	} {
		if r := c.prepare(t, params, nil); r.code != 1 || r.status != "params_invalid" {
			t.Errorf("%s: %d %s", name, r.code, r.out)
		}
	}
	c.f.write(t, "id", `echo 1000`)
	if r := c.prepare(t, nil, nil); r.code != 1 || r.status != "not_root" {
		t.Fatalf("%d %s", r.code, r.out)
	}
	if _, err := os.Lstat(c.state); !os.IsNotExist(err) {
		t.Fatalf("a refused run created the state directory: %v", err)
	}
}

// The preview reports prepare_required (the host is not prepared) and no
// digests until docker.update_prepare has run; afterwards it reports the
// host's units with digests keyed by the salt prepare created, which are
// the digests docker.compose_update recomputes.
func TestPreviewBeforeAndAfterPrepare(t *testing.T) {
	c := newComposeV2(t)
	c.noSalt = true
	r := c.preview(t, "")
	if r.code != 0 || r.doc["status"] != dockerhost.PreviewPrepareRequired || len(r.doc["units"].([]any)) != 0 {
		t.Fatalf("before prepare: %d %s", r.code, r.out)
	}
	p, err := dockerhost.ParseUpdatePreview(r.out)
	if err != nil || !p.PrepareRequired() {
		t.Fatalf("%+v %v", p, err)
	}
	if pr := c.prepare(t, nil, nil); pr.status != dockerhost.PrepareCreated {
		t.Fatal(pr.out)
	}
	salt, _ := readSalt(t, c)
	c.salt = salt
	r = c.preview(t, "")
	if r.code != 0 || r.doc["status"] != dockerhost.PreviewOK {
		t.Fatalf("after prepare: %d %s", r.code, r.out)
	}
	p, err = dockerhost.ParseUpdatePreview(r.out)
	if err != nil || p.PrepareRequired() {
		t.Fatalf("%+v %v", p, err)
	}
	u := r.unit(t, "site")
	want := c.keyed("nos-source-digest-v1", []byte(c.st["source_config"].(string)))
	if u["source_digest"] != want {
		t.Fatalf("source digest %v, want the one keyed by the prepared salt %s", u["source_digest"], want)
	}
	web := previewTarget(t, u, cuHex("1"))
	if web["configuration_digest"] != c.configDigest(t, c.container(cuHex("1"))) {
		t.Fatalf("configuration digest %v not keyed by the prepared salt", web["configuration_digest"])
	}
	// The preview neither changes nor shows the salt.
	again, _ := readSalt(t, c)
	if !bytes.Equal(again, salt) {
		t.Fatal("the preview changed the salt")
	}
	for _, enc := range []string{hex.EncodeToString(salt), base64.StdEncoding.EncodeToString(salt), string(salt)} {
		if strings.Contains(string(r.out), enc) || strings.Contains(r.stderr, enc) {
			t.Fatal("the preview showed the salt")
		}
	}
}
