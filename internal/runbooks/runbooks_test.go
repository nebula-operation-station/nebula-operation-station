// SPDX-License-Identifier: AGPL-3.0-or-later

package runbooks

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/serverdb"
)

func draft() Draft {
	return Draft{Slug: "restart_web", Title: "Restart web", Description: "Restarts the web stack.\nTwo lines.", Risk: "MEDIUM",
		TimeoutS: 60, Params: []Param{
			{Name: "unit", Label: "Unit", Type: TypeName},
			{Name: "count", Label: "Count", Type: TypeInt},
			{Name: "dir", Label: "Directory", Type: TypePath},
			{Name: "mode", Label: "Mode", Type: TypeChoice, Choices: []string{"soft", "hard-reset"}},
		},
		Body: "echo \"unit=$NEBULA_P_UNIT count=$NEBULA_P_COUNT dir=$NEBULA_P_DIR mode=$NEBULA_P_MODE\"\necho to-stderr >&2\nexit \"${RC:-0}\"\n"}
}

func store(t *testing.T) *Store {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db)
}

func TestValidate(t *testing.T) {
	if err := Validate(draft()); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*Draft){
		"slug upper":      func(d *Draft) { d.Slug = "Web" },
		"slug dot":        func(d *Draft) { d.Slug = "a.b" },
		"no title":        func(d *Draft) { d.Title = "" },
		"bidi title":      func(d *Draft) { d.Title = "a\u202eb" },
		"newline title":   func(d *Draft) { d.Title = "a\nb" },
		"control desc":    func(d *Draft) { d.Description = "a\x1b[2J" },
		"cr desc":         func(d *Draft) { d.Description = "a\r\nb" },
		"risk":            func(d *Draft) { d.Risk = "SEVERE" },
		"timeout low":     func(d *Draft) { d.TimeoutS = 5 },
		"timeout high":    func(d *Draft) { d.TimeoutS = 3600 },
		"no body":         func(d *Draft) { d.Body = "" },
		"nul body":        func(d *Draft) { d.Body = "a\x00b" },
		"big body":        func(d *Draft) { d.Body = strings.Repeat("x", MaxBody+1) },
		"bad utf8":        func(d *Draft) { d.Body = "\xff" },
		"param name":      func(d *Draft) { d.Params[0].Name = "Unit" },
		"param dup":       func(d *Draft) { d.Params[1].Name = "unit" },
		"param type":      func(d *Draft) { d.Params[0].Type = "string" },
		"param label":     func(d *Draft) { d.Params[0].Label = "" },
		"choice none":     func(d *Draft) { d.Params[3].Choices = nil },
		"choice dot":      func(d *Draft) { d.Params[3].Choices = []string{"a.b"} },
		"choice quote":    func(d *Draft) { d.Params[3].Choices = []string{"a'"} },
		"choice dup":      func(d *Draft) { d.Params[3].Choices = []string{"a", "a"} },
		"choices on name": func(d *Draft) { d.Params[0].Choices = []string{"a"} },
		// An unpaired "}" would close the prelude's function early and let
		// the rest write the result document (review m72, finding 1).
		"brace breakout": func(d *Draft) {
			d.Body = "}\necho '{\"format\":\"runbook-v1\",\"phase\":\"done\",\"exit\":0}'\nexit 0\n"
		},
		"balanced breakout": func(d *Draft) { d.Body = "}\nexit 0\nf() {\n" },
		"syntax error":      func(d *Draft) { d.Body = "if true; then\n" },
		"nebula param":      func(d *Draft) { d.Params[0].Name = "nebula_secrets" },
		"slot upper":        func(d *Draft) { d.Secrets = []string{"Token"} },
		"slot dup":          func(d *Draft) { d.Secrets = []string{"token", "token"} },
		"slot is param":     func(d *Draft) { d.Secrets = []string{"unit"} },
		"slot nebula":       func(d *Draft) { d.Secrets = []string{"nebula_x"} },
		"many slots":        func(d *Draft) { d.Secrets = []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"} },
	} {
		d := draft()
		d.Params = append([]Param(nil), d.Params...)
		mut(&d)
		var ie *InvalidError
		if err := Validate(d); !errors.As(err, &ie) {
			t.Errorf("%s: %v", name, err)
		}
	}
	d := draft()
	d.Durable, d.TimeoutS = true, 3600
	if err := Validate(d); err != nil {
		t.Fatal("durable runbooks may run an hour:", err)
	}
}

func TestVersionsAreImmutable(t *testing.T) {
	s := store(t)
	ctx := context.Background()
	v1, err := s.Save(ctx, "axel", draft())
	if err != nil {
		t.Fatal(err)
	}
	d := draft()
	d.Body = "echo two\n"
	d.Params = nil
	v2, err := s.Save(ctx, "axel", d)
	if err != nil || v1.Version != 1 || v2.Version != 2 || v1.ArtifactSHA256 == v2.ArtifactSHA256 {
		t.Fatalf("%v %d %d", err, v1.Version, v2.Version)
	}
	got, err := s.Get(ctx, "restart_web", 1)
	if err != nil || got.Body != draft().Body || len(got.Params) != 4 || got.Action().Version != "1.0.0" || got.Action().ID != "runbook.restart_web" {
		t.Fatalf("%+v %v", got, err)
	}
	if latest, _ := s.Get(ctx, "restart_web", 0); latest.Version != 2 {
		t.Fatal(latest.Version)
	}
	if all, _ := s.Latest(ctx); len(all) != 1 || all[0].Version != 2 {
		t.Fatal(all)
	}
	if vs, _ := s.Versions(ctx, "restart_web"); len(vs) != 2 || vs[0].Version != 2 {
		t.Fatal(vs)
	}
	if _, err := s.Get(ctx, "nope", 0); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	// The database refuses changes; a version changed behind its back does
	// not verify.
	if _, err := s.db.Exec(`UPDATE runbook_versions SET body = 'rm -rf /' WHERE version = 1`); err == nil {
		t.Fatal("version changed")
	}
	if _, err := s.db.Exec(`DELETE FROM runbook_versions`); err == nil {
		t.Fatal("versions deleted")
	}
	if _, err := s.db.Exec(`DROP TRIGGER runbook_versions_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE runbook_versions SET body = 'echo changed' WHERE version = 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "restart_web", 1); err == nil {
		t.Fatal("a changed version verified")
	}
	if _, err := s.Save(ctx, "bad user", draft()); err == nil {
		t.Fatal("user with a space")
	}
}

func TestParseActionVersion(t *testing.T) {
	for in, ok := range map[[2]string]bool{
		{"runbook.web", "3.0.0"}: true, {"runbook.web", ""}: true, {"runbook.web", "3.1.0"}: false,
		{"runbook.web", "03.0.0"}: false, {"runbook.web", "0.0.0"}: false, {"core.facts", "1.0.0"}: false, {"runbook.Web", "1.0.0"}: false,
	} {
		if _, _, got := ParseActionVersion(in[0], in[1]); got != ok {
			t.Errorf("%v: %v", in, got)
		}
	}
}

// The prelude checks each parameter on the host with the server's pattern.
func TestArtifactOnTheHost(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	v := Version{Draft: draft(), Version: 1}
	art := Artifact(v)
	a := v.Action()
	dir := t.TempDir()
	script := filepath.Join(dir, "action.sh")
	if err := os.WriteFile(script, art, 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(params string, env ...string) (string, string, int) {
		t.Helper()
		pf := filepath.Join(dir, "params.json")
		if err := os.WriteFile(pf, []byte(params), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(sh, script)
		cmd.Env = append([]string{"NEBULA_PARAMS=" + pf, "PATH=" + os.Getenv("PATH")}, env...)
		var out, errb strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
		return out.String(), errb.String(), code
	}
	good := `{"count":"42","dir":"/srv/www","mode":"hard-reset","unit":"nginx.service"}`
	if err := a.ValidParams(map[string]string{"count": "42", "dir": "/srv/www", "mode": "hard-reset", "unit": "nginx.service"}); err != nil {
		t.Fatal(err)
	}
	out, log, code := run(good)
	if code != 0 || out != `{"format":"runbook-v1","phase":"done","exit":0}`+"\n" ||
		!strings.Contains(log, "unit=nginx.service count=42 dir=/srv/www mode=hard-reset") || !strings.Contains(log, "to-stderr") {
		t.Fatalf("%d %q %q", code, out, log)
	}
	if out, _, code := run(good, "RC=3"); code != 3 || !strings.Contains(out, `"exit":3`) {
		t.Fatalf("%d %q", code, out)
	}
	for _, bad := range []string{
		`{"count":"4x","dir":"/srv","mode":"soft","unit":"a"}`,
		`{"count":"1","dir":"srv","mode":"soft","unit":"a"}`,
		`{"count":"1","dir":"/srv","mode":"medium","unit":"a"}`,
		`{"count":"1","dir":"/srv","mode":"soft","unit":"-rf"}`,
		`{"count":"1","dir":"/srv","mode":"soft","unit":"a b"}`,
		`{"count":"1","dir":"/srv","mode":"soft","unit":"a\"b"}`,
		`{"count":"1","dir":"/srv","mode":"soft"}`,
	} {
		out, log, code := run(bad)
		if code != 10 || !strings.Contains(out, `"phase":"precheck"`) || strings.Contains(log, "unit=") {
			t.Errorf("%s: %d %q %q", bad, code, out, log)
		}
	}
}

// Go (the server) and grep -E (the host) accept exactly the same values.
func TestPatternsAgree(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	vals := []string{"a", "A9", "-a", "1", "007", "1234567890", "/x", "/a/b.c_d-e", "x/y", "a.b", "a@b:c", "soft", "hard-reset",
		"x y", "a*", "a+b", "", ".", "/", strings.Repeat("a", 128), strings.Repeat("a", 129), "/" + strings.Repeat("a", 200), "/" + strings.Repeat("a", 201)}
	for _, p := range draft().Params {
		v := Version{Draft: Draft{Slug: "p", Params: []Param{p}, Body: "true"}, Version: 1}
		script := filepath.Join(dir, p.Name+".sh")
		if err := os.WriteFile(script, Artifact(v), 0o600); err != nil {
			t.Fatal(err)
		}
		re := v.Action().Params[0].Pattern
		for _, val := range vals {
			pf := filepath.Join(dir, "p.json")
			if err := os.WriteFile(pf, []byte(`{"`+p.Name+`":"`+val+`"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(sh, script)
			cmd.Env = []string{"NEBULA_PARAMS=" + pf, "PATH=" + os.Getenv("PATH")}
			host := cmd.Run() == nil
			if host != re.MatchString(val) {
				t.Errorf("%s %q: host %v, server %v", p.Type, val, host, !host)
			}
		}
	}
}

// An empty or comment-only script is still valid shell.
func TestArtifactWithCommentOnlyScript(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	v := Version{Draft: Draft{Slug: "x", Body: "# nothing yet"}, Version: 2}
	if out, err := exec.Command(sh, "-n", "-c", string(Artifact(v))).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
}

// Secret slots: the prelude needs each file and gives the script its path.
func TestArtifactSecretSlots(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	v := Version{Draft: Draft{Slug: "s", Secrets: []string{"token"}, Body: `echo "path=$NEBULA_SECRET_TOKEN"; cat "$NEBULA_SECRET_TOKEN"`}, Version: 1}
	if a := v.Action(); len(a.Secrets) != 1 || a.Secrets[0] != "token" {
		t.Fatal(a.Secrets)
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "a.sh")
	pf := filepath.Join(dir, "p.json")
	sd := filepath.Join(dir, "secrets")
	_ = os.WriteFile(script, Artifact(v), 0o600)
	_ = os.WriteFile(pf, []byte(`{"nebula_secrets":{"token":"app.token"}}`), 0o600)
	_ = os.Mkdir(sd, 0o700)
	run := func() (string, string, error) {
		cmd := exec.Command(sh, script)
		cmd.Env = []string{"NEBULA_PARAMS=" + pf, "NEBULA_SECRETS_DIR=" + sd, "PATH=" + os.Getenv("PATH")}
		var out, errb strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		return out.String(), errb.String(), err
	}
	if out, _, err := run(); err == nil || !strings.Contains(out, "secret token is not available") {
		t.Fatalf("ran without the secret: %q %v", out, err)
	}
	_ = os.WriteFile(filepath.Join(sd, "token"), []byte("v4lue"), 0o600)
	out, log, err := run()
	if err != nil || !strings.Contains(log, "path="+sd+"/token") || !strings.Contains(log, "v4lue") || !strings.Contains(out, `"exit":0`) {
		t.Fatalf("%q %q %v", out, log, err)
	}
}
