// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// The pin is the digest of the docker.update_prepare 1.0.0 script the
// server ships. Changing the script without a reviewed pin update fails
// here.
func TestShippedUpdatePreparePinMatchesEmbeddedScript(t *testing.T) {
	a, ok := actions.Lookup(updatePrepareAction)
	if !ok {
		t.Fatal("docker.update_prepare is not in the catalog")
	}
	if a.Version != updatePrepareVersion || !a.Durable || a.ReadOnly || a.Risk != pb.RiskClass_RISK_CLASS_MEDIUM || a.Timeout != updatePrepareTimeout {
		t.Fatalf("catalog has %s %s (durable %v, read-only %v, %v, %s), the executor pins %s for %s",
			a.ID, a.Version, a.Durable, a.ReadOnly, a.Risk, a.Timeout, updatePrepareVersion, updatePrepareTimeout)
	}
	if got := sha256Hex(a.Script); got != updatePrepareArtifactSHA256 || a.SHA256() != updatePrepareArtifactSHA256 {
		t.Fatalf("the embedded docker.update_prepare %s script has digest %s, the executor pins %q: update updatePrepareArtifactSHA256 after review",
			a.Version, got, updatePrepareArtifactSHA256)
	}
	if s := string(a.Script); !strings.Contains(s, "docker.update_prepare 1.0.0") || !strings.Contains(s, "docker-update-prepare-v1") {
		t.Fatal("the pinned script is not prepare 1.0.0")
	}
	if err := checkPrepareArtifact(updatePrepareVersion, a.Script); err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), a.Script...)
	tampered[len(tampered)-2] ^= 1
	preview, _ := actions.Lookup(updatePreviewAction)
	for name, err := range map[string]error{
		"tampered":      checkPrepareArtifact(updatePrepareVersion, tampered),
		"other version": checkPrepareArtifact("1.0.1", a.Script),
		"no artifact":   checkPrepareArtifact(updatePrepareVersion, nil),
		"preview bytes": checkPrepareArtifact(updatePrepareVersion, preview.Script),
		"declared":      checkPreparePin(updatePrepareVersion, strings.Repeat("0", 64)),
		"empty":         checkPreparePin("", ""),
	} {
		if !errors.Is(err, errPrepareArtifact) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The two pins are distinct: neither artifact passes the other's pin.
	if checkPreviewArtifact(updatePreviewVersion, a.Script) == nil {
		t.Fatal("prepare passes the preview pin")
	}
}

func requirePrepareRefused(t *testing.T, err error, want error) {
	t.Helper()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "update_prepare_refused") ||
		!strings.Contains(err.Error(), want.Error()) {
		t.Fatalf("want update_prepare_refused (%v), got %v", want, err)
	}
}

// prepareProposal is a proposal of the pinned prepare artifact at risk.
func prepareProposal(t *testing.T, seq int, risk pb.RiskClass) *pb.ProposeExecutionRequest {
	t.Helper()
	a, _ := actions.Lookup(updatePrepareAction)
	p := listPendingRequest(t, seq, a.Script)
	p.Request.ActionId, p.Request.ModuleVersion, p.Request.RiskClass = updatePrepareAction, updatePrepareVersion, risk
	return p
}

// Prepare is approved only for its pinned artifact and never below
// MEDIUM: it writes the host's salt, so it is a host change, whatever
// risk an operator registered for the artifact.
func TestUpdatePrepareProposalNeedsPinAndMedium(t *testing.T) {
	e := newReconcileEnv(t)
	// An operator registered the artifact as LOW on a recorded LOW host:
	// the executor's floor alone would allow a LOW permit.
	a, _ := actions.Lookup(updatePrepareAction)
	trustBuiltin(t, e.db, a.Script, updatePrepareAction, updatePrepareVersion, canonical.RiskLow)
	setCrit(t, e.db, canonical.Target{HostID: "dockerflux", HostKeyFingerprint: testFingerprint}, canonical.RiskLow)
	bad := listPendingRequest(t, 1, []byte("echo not prepare\n"))
	bad.Request.ActionId = updatePrepareAction
	_, err := e.svc.ProposeExecution(context.Background(), bad)
	requirePrepareRefused(t, err, errPrepareArtifact)

	wrongVersion := prepareProposal(t, 2, pb.RiskClass_RISK_CLASS_HIGH)
	wrongVersion.Request.ModuleVersion = "2.0.0"
	_, err = e.svc.ProposeExecution(context.Background(), wrongVersion)
	requirePrepareRefused(t, err, errPrepareArtifact)

	_, err = e.svc.ProposeExecution(context.Background(), prepareProposal(t, 3, pb.RiskClass_RISK_CLASS_LOW))
	requirePrepareRefused(t, err, errPrepareRisk)
	// Raising to the executor's minimum does not help either: the declared
	// class is checked before.
	low := prepareProposal(t, 4, pb.RiskClass_RISK_CLASS_LOW)
	low.RaiseToMinimum = true
	_, err = e.svc.ProposeExecution(context.Background(), low)
	requirePrepareRefused(t, err, errPrepareRisk)

	for i, r := range []pb.RiskClass{pb.RiskClass_RISK_CLASS_MEDIUM, pb.RiskClass_RISK_CLASS_HIGH} {
		resp, err := e.svc.ProposeExecution(context.Background(), prepareProposal(t, 5+i, r))
		if err != nil {
			t.Fatalf("pinned prepare at %v refused: %v", r, err)
		}
		if resp.GetRiskClass() != r {
			t.Fatalf("risk %v, want %v", resp.GetRiskClass(), r)
		}
	}
}

func TestCheckPrepareProposalRisk(t *testing.T) {
	for risk, ok := range map[canonical.Risk]bool{
		"": false, canonical.RiskLow: false, canonical.RiskMedium: true, canonical.RiskHigh: true, canonical.RiskCritical: true,
	} {
		err := checkPrepareProposal(canonical.Request{ModuleVersion: updatePrepareVersion, ArtifactSHA256: updatePrepareArtifactSHA256, RiskClass: risk})
		if (err == nil) != ok {
			t.Errorf("%q: %v", risk, err)
		}
	}
}

// Prepare never runs attached.
func TestUpdatePrepareNeverRunsAttached(t *testing.T) {
	e := newReconcileEnv(t)
	a, _ := actions.Lookup(updatePrepareAction)
	_, err := e.svc.RunAttached(context.Background(), &pb.RunAttachedRequest{
		Run: &pb.AuthorizeRunRequest{HostId: e.host, ActionId: updatePrepareAction, ModuleVersion: updatePrepareVersion,
			Artifact: a.Script, ParametersJson: []byte(`{}`)},
		TimeoutSeconds: 60,
	})
	requirePrepareRefused(t, err, errPrepareTransport)
}

// A durable prepare run with another artifact or version is refused
// before a run is recorded.
func TestUpdatePrepareDurableNeedsPinnedArtifact(t *testing.T) {
	e := newReconcileEnv(t)
	a, _ := actions.Lookup(updatePrepareAction)
	other := append([]byte("# other\n"), a.Script...)
	for name, run := range map[string]*pb.AuthorizeRunRequest{
		"artifact": {HostId: e.host, ActionId: updatePrepareAction, ModuleVersion: updatePrepareVersion, Artifact: other},
		"version":  {HostId: e.host, ActionId: updatePrepareAction, ModuleVersion: "0.9.0", Artifact: a.Script},
	} {
		run.ExecutionDigest = strings.Repeat("a", 64)
		_, err := e.svc.StartDurable(context.Background(), &pb.StartDurableRequest{Run: run, TimeoutSeconds: 3600})
		requirePrepareRefused(t, err, errPrepareArtifact)
		_ = name
	}
	runs, err := e.db.OpenRuns()
	if err != nil || len(runs) != 0 {
		t.Fatalf("a run was recorded: %v %v", runs, err)
	}
}

// Prepare never runs as a batch member.
func TestUpdatePrepareNeverRunsAsBatchMember(t *testing.T) {
	e := newDispatchEnv(t, "web-1")
	d, members, n := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: "web-1", action: updatePrepareAction})
	_, err := e.server.RunBatchMember(context.Background(), e.runReq(d, n, 0, "web-1"))
	e.requireRefused(t, err, codes.FailedPrecondition, members[0], 0)
	if !strings.Contains(err.Error(), "update_prepare_refused") {
		t.Fatal(err)
	}
}

// An accepted durable prepare start records action_id and the fixed
// 2-minute timeout, whatever the request asked for.
func TestUpdatePrepareDurableStartRecordsActionAndTimeout(t *testing.T) {
	e := newReconcileEnv(t)
	e.pin(mustReadSigner(t))
	a, _ := actions.Lookup(updatePrepareAction)
	params := []byte(`{}`)
	prop := prepareProposal(t, 7, pb.RiskClass_RISK_CLASS_HIGH)
	prop.Request.CredentialRefs = []string{"cred"}
	prop.Request.ResolvedTargets = []*pb.Target{{HostId: e.host, HostKeyFingerprint: e.fp}}
	resp, err := e.svc.ProposeExecution(context.Background(), prop)
	if err != nil {
		t.Fatal(err)
	}
	d, err := canonical.ParseDigest(resp.GetExecutionDigest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.auth.ApproveCLI(d, 0, "admin"); err != nil {
		t.Fatal(err)
	}
	st, err := e.svc.StartDurable(context.Background(), &pb.StartDurableRequest{
		Run: &pb.AuthorizeRunRequest{ExecutionDigest: resp.GetExecutionDigest(), HostId: e.host, HostKeyFingerprint: e.fp,
			ActionId: updatePrepareAction, ModuleVersion: updatePrepareVersion, Artifact: a.Script, ParametersJson: params,
			CredentialRef: "cred"},
		Endpoints: []string{"127.0.0.1:1"}, TimeoutSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	r := e.getRun(st.GetRun().GetExecutionId())
	if r.ActionID != updatePrepareAction || r.MemberID != "" || r.Timeout != updatePrepareTimeout {
		t.Fatalf("runs row action %q member %q timeout %s, want %s and %s", r.ActionID, r.MemberID, r.Timeout,
			updatePrepareAction, updatePrepareTimeout)
	}
}

// Prepare's result is no Resolve evidence and holds no salt: ReleaseRun
// releases it like any run, also while the host has an uncertain row, and
// it does not displace a kept preview.
func TestReleaseRunReleasesPrepareResult(t *testing.T) {
	e := newReconcileEnv(t)
	e.uncertainRow()
	preview := e.finishedRun(updatePreviewAction, "")
	if st := e.release(preview); len(st.GetResult()) == 0 || st.GetReleased() {
		t.Fatalf("preview %+v", st)
	}
	prep := e.finishedRun(updatePrepareAction, "")
	if st := e.release(prep); len(st.GetResult()) == 0 {
		t.Fatal("first status lacks the result")
	}
	if r := e.getRun(prep); !r.Released || r.Result != nil {
		t.Fatal("the prepare result was kept")
	}
	if r := e.getRun(preview); r.Released || len(r.Result) == 0 {
		t.Fatal("releasing prepare released the kept preview")
	}
}
