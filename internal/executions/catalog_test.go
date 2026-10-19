// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/modules"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/runbooks"
)

// Runbooks are planned like built-ins, and an execution runs exactly the
// version it was planned with, even after a newer one is saved.
func TestRunbookExecutionRunsItsVersion(t *testing.T) {
	f := &fakeExec{}
	s, db := setup(t, f)
	rb := runbooks.New(db)
	s.SetRunbooks(rb)
	ctx := context.Background()
	d := runbooks.Draft{Slug: "hello", Title: "Hello", Risk: "MEDIUM", TimeoutS: 60,
		Params: []runbooks.Param{{Name: "who", Label: "Who", Type: runbooks.TypeName}}, Body: "echo hello $NEBULA_P_WHO\n"}
	v1, err := rb.Save(ctx, "axel", d)
	if err != nil {
		t.Fatal(err)
	}
	all, err := s.Catalog(ctx)
	if err != nil || all[len(all)-1].ID != "runbook.hello" || all[len(all)-1].Version != "1.0.0" {
		t.Fatalf("%v %v", err, all[len(all)-1])
	}
	var pe *ParamError
	if _, err := s.Create(ctx, "axel", "runbook.hello", []string{"web"}, map[string]string{"who": "-rf"}); !errors.As(err, &pe) {
		t.Fatal(err)
	}
	c, err := s.Create(ctx, "axel", "runbook.hello", []string{"web"}, map[string]string{"who": "world"})
	if err != nil {
		t.Fatal(err)
	}
	r := f.proposed.GetRequest()
	if r.GetActionId() != "runbook.hello" || r.GetModuleVersion() != "1.0.0" || r.GetArtifactSha256() != v1.ArtifactSHA256 ||
		string(f.proposed.GetArtifact()) != string(v1.Artifact) {
		t.Fatalf("%v", r)
	}
	d.Body = "echo version two\n"
	if _, err := rb.Save(ctx, "axel", d); err != nil {
		t.Fatal(err)
	}
	if err := s.Approve(ctx, "axel", c.ID, []byte("good"), 0); err != nil {
		t.Fatal(err)
	}
	waitState(t, s, c.ID, "finished")
	if run := f.attached[0].GetRun(); string(run.GetArtifact()) != string(v1.Artifact) || !strings.Contains(string(run.GetArtifact()), "echo hello") {
		t.Fatal("ran another version")
	}
	if a, ok, err := s.Action(ctx, "runbook.hello", ""); err != nil || !ok || a.Version != "2.0.0" {
		t.Fatalf("%v %v %v", a.Version, ok, err)
	}
	if _, ok, _ := s.Action(ctx, "runbook.hello", "3.0.0"); ok {
		t.Fatal("a version that does not exist")
	}
	if _, err := s.Create(ctx, "axel", "runbook.nope", []string{"web"}, nil); !errors.Is(err, ErrUnknownAction) {
		t.Fatal(err)
	}
	// Without a runbook store, runbooks are unknown.
	s.SetRunbooks(nil)
	if _, ok, _ := s.Action(ctx, "runbook.hello", ""); ok {
		t.Fatal("runbook without a store")
	}
}

// M7-3: a runbook's secret slots are mapped to vault secret IDs in the
// approved parameters; the executor resolves them.
func TestRunbookSecretsAreInTheParameters(t *testing.T) {
	f := &fakeExec{}
	s, db := setup(t, f)
	rb := runbooks.New(db)
	s.SetRunbooks(rb)
	ctx := context.Background()
	if _, err := rb.Save(ctx, "axel", runbooks.Draft{Slug: "push", Title: "Push", Risk: "MEDIUM", TimeoutS: 60, Secrets: []string{"token"},
		Body: "cat \"$NEBULA_SECRET_TOKEN\" >/dev/null\n"}); err != nil {
		t.Fatal(err)
	}
	var pe *ParamError
	for _, bad := range []map[string]string{nil, {"other": "app.token"}, {"token": "../x"}, {"token": "a", "x": "b"}} {
		if _, err := s.CreateStaged(ctx, "axel", "runbook.push", []string{"web"}, nil, Plan{Secrets: bad}); !errors.As(err, &pe) {
			t.Errorf("%v: %v", bad, err)
		}
	}
	if _, err := s.CreateStaged(ctx, "axel", "runbook.push", []string{"web"}, nil, Plan{Secrets: map[string]string{"token": "app.token"}}); err != nil {
		t.Fatal(err)
	}
	if got := string(f.proposed.GetParametersJson()); got != `{"nebula_secrets":{"token":"app.token"}}` {
		t.Fatal(got)
	}
	if actions.SecretsKey != permit.SecretsKey {
		t.Fatal("server and executor disagree on the secrets member")
	}
	// Built-ins have no slots and take no mapping.
	if _, err := s.CreateStaged(ctx, "axel", "core.facts", []string{"web"}, nil, Plan{Secrets: map[string]string{"token": "x"}}); !errors.As(err, &pe) {
		t.Fatal(err)
	}
}

// M7-5: module actions are planned like built-ins, at their version.
func TestModuleActionsArePlannable(t *testing.T) {
	f := &fakeExec{}
	s, db := setup(t, f)
	ms := modules.New(db, nil)
	s.SetModules(ms)
	ctx := context.Background()
	read := func(n string) []byte {
		b, err := os.ReadFile("../../test/security/testdata/module/" + n)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, b := range map[string][]byte{"module.lock.json": read("lock-1.0.0.json"), "actions/hello.sh": read("hello.sh"), "actions/restart.sh": read("restart.sh")} {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(b)
	}
	_ = tw.Close()
	_ = zw.Close()
	if _, err := ms.Import(ctx, "axel", buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	all, _ := s.Catalog(ctx)
	found := false
	for _, a := range all {
		found = found || (a.ID == "demo.hello" && a.Version == "1.0.0")
	}
	if !found {
		t.Fatal("module action not in the catalog")
	}
	if _, err := s.Create(ctx, "axel", "demo.hello", []string{"web"}, map[string]string{"who": "you"}); err != nil {
		t.Fatal(err)
	}
	if r := f.proposed.GetRequest(); r.GetActionId() != "demo.hello" || r.GetModuleVersion() != "1.0.0" {
		t.Fatal(r)
	}
	if _, ok, _ := s.Action(ctx, "demo.hello", "9.9.9"); ok {
		t.Fatal("unknown version found")
	}
	if _, ok, _ := s.Action(ctx, "docker.nope", ""); ok {
		t.Fatal("unknown built-in family action found")
	}
}
