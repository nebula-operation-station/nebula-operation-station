// SPDX-License-Identifier: AGPL-3.0-or-later

package executions

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Staged deployment plans (ADR 0008 section 5, PV-08): bootstrap modules
// and runbooks become batch members at the exact version the profile
// names, resolved through the action catalog.

// fakeCatalog resolves module and runbook actions by exact version.
type fakeCatalog struct {
	acts  map[string]actions.Action // by id + "@" + version
	calls []string
	err   error
}

func (f *fakeCatalog) Action(_ context.Context, id, version string) (actions.Action, bool, error) {
	f.calls = append(f.calls, id+"@"+version)
	if f.err != nil {
		return actions.Action{}, false, f.err
	}
	a, ok := f.acts[id+"@"+version]
	return a, ok, nil
}

func catalogAction(id, version string, secrets ...string) actions.Action {
	return actions.Action{ID: id, Version: version, Title: "Catalog " + id, Risk: pb.RiskClass_RISK_CLASS_MEDIUM,
		Durable: true, Timeout: 5 * time.Minute, Script: []byte("#!/bin/sh\n# " + id + " " + version + "\n"),
		Params:  []actions.Param{{Name: "zone", Label: "Zone", Pattern: regexp.MustCompile(`^[A-Za-z/_]{1,40}$`)}},
		Secrets: secrets}
}

func newFakeCatalog() *fakeCatalog {
	return &fakeCatalog{acts: map[string]actions.Action{
		"timezone.install@1.0.0":    catalogAction("timezone.install", "1.0.0"),
		"runbook.harden@3.0.0":      catalogAction("runbook.harden", "3.0.0"),
		"netbird.install@1.0.0":     catalogAction("netbird.install", "1.0.0", "setup_key"),
		"timezone.install@2.0.0":    catalogAction("timezone.install", "2.0.0"),
		"package.install_all@9.9.9": catalogAction("package.install_all", "9.9.9"),
	}}
}

func TestBatchPlanResolvesCatalogActionsAtExactVersion(t *testing.T) {
	f := &fakeBatchExec{}
	cat := newFakeCatalog()
	b, _ := batchSetup(t, f, func(o *BatchOptions) { o.Actions = cat })
	ctx := context.Background()
	req := BatchRequest{Stages: []BatchStageSpec{
		{Gate: "automatic", Members: []BatchMemberSpec{{ActionID: "timezone.install", Version: "1.0.0", HostID: "h01", Params: map[string]string{"zone": "Europe/Berlin"}}}},
		{Gate: "automatic", Members: []BatchMemberSpec{{ActionID: "runbook.harden", Version: "3.0.0", HostID: "h01", Params: map[string]string{"zone": "UTC"}}}},
	}}
	c, err := b.ProposeBatch(ctx, "axel", req)
	if err != nil {
		t.Fatal(err)
	}
	v, err := b.Batch(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Members) != 2 || v.Members[0].ActionID != "timezone.install" || v.Members[0].ModuleVersion != "1.0.0" ||
		v.Members[1].ActionID != "runbook.harden" || v.Members[1].ModuleVersion != "3.0.0" ||
		v.Members[0].Stage != 1 || v.Members[1].Stage != 2 {
		t.Fatalf("members %+v", v.Members)
	}
	// The executor receives exactly the resolved artifact of that version.
	in := f.proposed[0].GetMembers()
	if string(in[0].GetArtifact()) != string(cat.acts["timezone.install@1.0.0"].Script) ||
		string(in[1].GetArtifact()) != string(cat.acts["runbook.harden@3.0.0"].Script) {
		t.Fatal("member artifacts are not the resolved versions")
	}
}

func TestBatchPlanRefusesCatalogActionsItCannotPinExactly(t *testing.T) {
	ctx := context.Background()
	one := func(m BatchMemberSpec) BatchRequest {
		return BatchRequest{Stages: []BatchStageSpec{{Gate: "manual", Members: []BatchMemberSpec{m}}}}
	}
	zone := map[string]string{"zone": "UTC"}
	cases := map[string]struct {
		req     BatchRequest
		catalog bool
		want    string
	}{
		"no version":             {one(BatchMemberSpec{ActionID: "timezone.install", HostID: "h01", Params: zone}), true, "exact version"},
		"unknown version":        {one(BatchMemberSpec{ActionID: "timezone.install", Version: "7.0.0", HostID: "h01", Params: zone}), true, "unknown action"},
		"no catalog":             {one(BatchMemberSpec{ActionID: "timezone.install", Version: "1.0.0", HostID: "h01", Params: zone}), false, "unknown action"},
		"secret slots":           {one(BatchMemberSpec{ActionID: "netbird.install", Version: "1.0.0", HostID: "h01", Params: zone}), true, "secrets"},
		"built-in other version": {one(BatchMemberSpec{ActionID: "package.install_all", Version: "9.9.9", HostID: "h01"}), true, "built-in"},
		"bad catalog params":     {one(BatchMemberSpec{ActionID: "timezone.install", Version: "1.0.0", HostID: "h01", Params: map[string]string{"zone": "a b"}}), true, "timezone.install"},
	}
	for name, c := range cases {
		f := &fakeBatchExec{}
		cat := newFakeCatalog()
		b, _ := batchSetup(t, f, func(o *BatchOptions) {
			if c.catalog {
				o.Actions = cat
			}
		})
		_, err := b.ProposeBatch(ctx, "axel", c.req)
		var ie *BatchInputError
		if !errors.As(err, &ie) || !strings.Contains(ie.Reason, c.want) {
			t.Errorf("%s: %v, want input error containing %q", name, err, c.want)
		}
		if len(f.proposed) != 0 {
			t.Errorf("%s: proposed to the executor", name)
		}
	}
}

func TestBatchPlanCatalogErrorIsNotAnInputError(t *testing.T) {
	f := &fakeBatchExec{}
	cat := newFakeCatalog()
	cat.err = errors.New("db down")
	b, _ := batchSetup(t, f, func(o *BatchOptions) { o.Actions = cat })
	_, err := b.ProposeBatch(context.Background(), "axel", BatchRequest{Stages: []BatchStageSpec{{Gate: "manual",
		Members: []BatchMemberSpec{{ActionID: "timezone.install", Version: "1.0.0", HostID: "h01", Params: map[string]string{"zone": "UTC"}}}}}})
	var ie *BatchInputError
	if err == nil || errors.As(err, &ie) {
		t.Fatalf("err = %v, want a non-input error", err)
	}
	if len(f.proposed) != 0 {
		t.Fatal("proposed to the executor")
	}
}
