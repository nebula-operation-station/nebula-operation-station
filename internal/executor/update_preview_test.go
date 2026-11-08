// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// The pin is the digest of the docker.update_preview 1.0.0 script the
// server ships (the bytes embedded in the actions catalog). Changing the
// script without a reviewed pin update fails here.
func TestShippedUpdatePreviewPinMatchesEmbeddedScript(t *testing.T) {
	a, ok := actions.Lookup(updatePreviewAction)
	if !ok {
		t.Fatal("docker.update_preview is not in the catalog")
	}
	if a.Version != updatePreviewVersion || !a.Durable || !a.ReadOnly || a.Risk != pb.RiskClass_RISK_CLASS_LOW || a.Timeout != updatePreviewTimeout {
		t.Fatalf("catalog has %s %s (durable %v, read-only %v, %v, %s), the executor pins %s for %s",
			a.ID, a.Version, a.Durable, a.ReadOnly, a.Risk, a.Timeout, updatePreviewVersion, updatePreviewTimeout)
	}
	if got := sha256Hex(a.Script); got != updatePreviewArtifactSHA256 || a.SHA256() != updatePreviewArtifactSHA256 {
		t.Fatalf("the embedded docker.update_preview %s script has digest %s, the executor pins %q: update updatePreviewArtifactSHA256 after review",
			a.Version, got, updatePreviewArtifactSHA256)
	}
	if s := string(a.Script); !strings.Contains(s, "docker.update_preview 1.0.0") || !strings.Contains(s, "docker-update-preview-v1") {
		t.Fatal("the pinned script is not the preview 1.0.0")
	}
	// The pin admits exactly that artifact at exactly that version.
	if err := checkPreviewArtifact(updatePreviewVersion, a.Script); err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), a.Script...)
	tampered[len(tampered)-2] ^= 1
	for name, err := range map[string]error{
		"tampered":      checkPreviewArtifact(updatePreviewVersion, tampered),
		"other version": checkPreviewArtifact("1.0.1", a.Script),
		"no artifact":   checkPreviewArtifact(updatePreviewVersion, nil),
		"declared":      checkPreviewPin(updatePreviewVersion, strings.Repeat("0", 64)),
		"empty":         checkPreviewPin("", ""),
	} {
		if !errors.Is(err, errPreviewArtifact) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := checkPreviewPin(updatePreviewVersion, a.SHA256()); err != nil {
		t.Fatal(err)
	}
}

func requirePreviewRefused(t *testing.T, err error) {
	t.Helper()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "update_preview_refused") {
		t.Fatalf("want update_preview_refused, got %v", err)
	}
}

// The preview never runs attached: an attached run has no runs row whose
// result Resolve could read, so the request is refused before anything
// is authorized.
func TestUpdatePreviewNeverRunsAttached(t *testing.T) {
	e := newReconcileEnv(t)
	a, _ := actions.Lookup(updatePreviewAction)
	_, err := e.svc.RunAttached(context.Background(), &pb.RunAttachedRequest{
		Run: &pb.AuthorizeRunRequest{HostId: e.host, ActionId: updatePreviewAction, ModuleVersion: updatePreviewVersion,
			Artifact: a.Script, ParametersJson: []byte(`{"target_tags":""}`)},
		TimeoutSeconds: 60,
	})
	requirePreviewRefused(t, err)
	if !strings.Contains(err.Error(), errPreviewTransport.Error()) {
		t.Fatal(err)
	}
}

// A durable preview run with an artifact other than the pinned one, or
// another module version, is refused before a run is recorded.
func TestUpdatePreviewDurableNeedsPinnedArtifact(t *testing.T) {
	e := newReconcileEnv(t)
	a, _ := actions.Lookup(updatePreviewAction)
	other := append([]byte("# other\n"), a.Script...)
	for name, run := range map[string]*pb.AuthorizeRunRequest{
		"artifact": {HostId: e.host, ActionId: updatePreviewAction, ModuleVersion: updatePreviewVersion, Artifact: other},
		"version":  {HostId: e.host, ActionId: updatePreviewAction, ModuleVersion: "0.9.0", Artifact: a.Script},
	} {
		run.ExecutionDigest = strings.Repeat("a", 64)
		_, err := e.svc.StartDurable(context.Background(), &pb.StartDurableRequest{Run: run, TimeoutSeconds: 3600})
		requirePreviewRefused(t, err)
		if !strings.Contains(err.Error(), errPreviewArtifact.Error()) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	runs, err := e.db.OpenRuns()
	if err != nil || len(runs) != 0 {
		t.Fatalf("a run was recorded: %v %v", runs, err)
	}
}

// A preview is approved only for its pinned artifact: a proposal naming
// another version or digest is refused, the pinned one is accepted.
func TestUpdatePreviewProposalNeedsPin(t *testing.T) {
	e := newReconcileEnv(t)
	a, _ := actions.Lookup(updatePreviewAction)
	bad := listPendingRequest(t, 1, []byte("echo not the preview\n"))
	bad.Request.ActionId = updatePreviewAction
	_, err := e.svc.ProposeExecution(context.Background(), bad)
	requirePreviewRefused(t, err)

	wrongVersion := listPendingRequest(t, 2, a.Script)
	wrongVersion.Request.ActionId, wrongVersion.Request.ModuleVersion = updatePreviewAction, "2.0.0"
	_, err = e.svc.ProposeExecution(context.Background(), wrongVersion)
	requirePreviewRefused(t, err)

	good := listPendingRequest(t, 3, a.Script)
	good.Request.ActionId = updatePreviewAction
	if _, err := e.svc.ProposeExecution(context.Background(), good); err != nil {
		t.Fatalf("pinned preview refused: %v", err)
	}
}

// The preview never runs as a batch member, which would run attached and
// leave no row for Resolve: the member is refused before the claim and
// nothing reaches the host.
func TestUpdatePreviewNeverRunsAsBatchMember(t *testing.T) {
	e := newDispatchEnv(t, "web-1")
	d, members, n := e.propose(t, canonical.BatchGateAutomatic, true, dispatchMember{host: "web-1", action: updatePreviewAction})
	_, err := e.server.RunBatchMember(context.Background(), e.runReq(d, n, 0, "web-1"))
	e.requireRefused(t, err, codes.FailedPrecondition, members[0], 0)
	if !strings.Contains(err.Error(), "update_preview_refused") {
		t.Fatal(err)
	}
}

// finishedRun stores a finished durable run of e.host with a result.
func (e *reconcileEnv) finishedRun(actionID, memberID string) string {
	e.t.Helper()
	id := newTestUUID()
	if err := e.db.CreateRun(executordb.Run{ExecutionID: id, HostID: e.host, Digest: strings.Repeat("b", 64),
		Endpoints: []string{"127.0.0.1:22"}, Fingerprint: e.fp, Timeout: updatePreviewTimeout, ActionID: actionID, MemberID: memberID}); err != nil {
		e.t.Fatal(err)
	}
	if err := e.db.FinishRun(executordb.Run{ExecutionID: id, HostID: e.host, Class: "success", Result: []byte(`{"format":"x"}`),
		Log: []byte("nos: phase: list\n")}); err != nil {
		e.t.Fatal(err)
	}
	return id
}

// uncertainRow gives e.host an uncertain container recreation row.
func (e *reconcileEnv) uncertainRow() {
	e.t.Helper()
	run := testDispatchRun(e.t, testComposeUpdate())
	run.ExecutionID = newTestUUID()
	row, err := recreationIntent(run, e.host, "SHA256:k")
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.db.CreateContainerRecreation(row); err != nil {
		e.t.Fatal(err)
	}
	if err := e.db.CompleteContainerRecreation(run.ExecutionID, executordb.RecreationCompletion{State: executordb.RecreationUncertain},
		time.Now(), 7*24*time.Hour); err != nil {
		e.t.Fatal(err)
	}
	if ok, err := e.db.HostHasUncertainRecreation(e.host); err != nil || !ok {
		e.t.Fatalf("no uncertain row: %v", err)
	}
}

func (e *reconcileEnv) release(id string) *pb.RunStatus {
	e.t.Helper()
	resp, err := e.svc.GetRun(context.Background(), &pb.GetRunRequest{ExecutionId: id, HostId: e.host, Release: true})
	if err != nil {
		e.t.Fatal(err)
	}
	return resp.GetRun()
}

// ReleaseRun keeps a preview's result while its host has an uncertain
// recreation row (the evidence Resolve reads, Q19); every other run, a
// preview of a host without such a row, and a batch member's run are
// released as before.
func TestReleaseRunKeepsPreviewWhileHostUncertain(t *testing.T) {
	e := newReconcileEnv(t)
	plain := e.finishedRun("", "")
	early := e.finishedRun(updatePreviewAction, "")
	// Without an uncertain row, a preview is released like any run.
	if st := e.release(early); len(st.GetResult()) == 0 {
		t.Fatal("first status lacks the result")
	}
	if r := e.getRun(early); !r.Released || r.Result != nil {
		t.Fatal("preview of a host without an uncertain row was kept")
	}

	e.uncertainRow()
	preview := e.finishedRun(updatePreviewAction, "")
	member := e.finishedRun(updatePreviewAction, "member-0")
	for range 2 {
		if st := e.release(preview); len(st.GetResult()) == 0 || st.GetReleased() {
			t.Fatalf("retained preview status %+v", st)
		}
	}
	if r := e.getRun(preview); r.Released || len(r.Result) == 0 {
		t.Fatal("the preview's result was released while the host is uncertain")
	}
	for _, id := range []string{plain, member} {
		e.release(id)
		if r := e.getRun(id); !r.Released || r.Result != nil {
			t.Fatalf("run %s was kept", id)
		}
	}
	if len(e.logs.find("preview_result_retained", preview)) == 0 {
		t.Fatal("retention not audited")
	}
}
