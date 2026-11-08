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

// An accepted durable preview start records its runs row through
// StartDurable itself: action_id is docker.update_preview (the evidence
// Resolve checks) and the timeout is the fixed 5 minutes, whatever the
// request asked for. The host is unreachable, so the run closes as not
// dispatched, after the row was written.
func TestUpdatePreviewDurableStartRecordsActionAndTimeout(t *testing.T) {
	e := newReconcileEnv(t)
	e.pin(mustReadSigner(t))
	a, _ := actions.Lookup(updatePreviewAction)
	params := []byte(`{"target_tags":""}`)
	prop := listPendingRequest(t, 7, a.Script)
	prop.Request.ActionId, prop.Request.ModuleVersion = updatePreviewAction, updatePreviewVersion
	prop.Request.CredentialRefs = []string{"cred"}
	prop.Request.ResolvedTargets = []*pb.Target{{HostId: e.host, HostKeyFingerprint: e.fp}}
	ph, err := canonical.HashParameters(params)
	if err != nil {
		t.Fatal(err)
	}
	prop.Request.ParametersHash, prop.ParametersJson = ph, params
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
			ActionId: updatePreviewAction, ModuleVersion: updatePreviewVersion, Artifact: a.Script, ParametersJson: params,
			CredentialRef: "cred"},
		Endpoints: []string{"127.0.0.1:1"}, TimeoutSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	r := e.getRun(st.GetRun().GetExecutionId())
	if r.ActionID != updatePreviewAction || r.MemberID != "" || r.Timeout != updatePreviewTimeout {
		t.Fatalf("runs row action %q member %q timeout %s, want %s and %s", r.ActionID, r.MemberID, r.Timeout,
			updatePreviewAction, updatePreviewTimeout)
	}
}

// finishedRun stores a finished durable run of e.host with a result.
func (e *reconcileEnv) finishedRun(actionID, memberID string) string {
	e.t.Helper()
	return e.finishedRunID(newTestUUID(), actionID, memberID)
}

// finishedRunID is finishedRun with a given execution ID.
func (e *reconcileEnv) finishedRunID(id, actionID, memberID string) string {
	e.t.Helper()
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

// Only the newest preview of an uncertain host keeps its result (Q19):
// keeping a newer preview releases the one kept before, an older preview
// asked for release afterwards is released.
func TestReleaseRunKeepsOnlyNewestPreview(t *testing.T) {
	e := newReconcileEnv(t)
	e.uncertainRow()
	// Created in this order (same second or later), so the IDs and the
	// start times order the runs alike.
	first := e.finishedRunID("00000000-0000-4000-8000-000000000001", updatePreviewAction, "")
	second := e.finishedRunID("00000000-0000-4000-8000-000000000002", updatePreviewAction, "")
	third := e.finishedRunID("00000000-0000-4000-8000-000000000003", updatePreviewAction, "")

	if st := e.release(second); len(st.GetResult()) == 0 || st.GetReleased() {
		t.Fatalf("second preview %+v", st)
	}
	if r := e.getRun(second); r.Released || len(r.Result) == 0 {
		t.Fatal("the newest preview so far was released")
	}
	// An older preview is released: a newer one is kept.
	e.release(first)
	if r := e.getRun(first); !r.Released || r.Result != nil {
		t.Fatal("an older preview was kept beside the newest")
	}
	// A newer preview supersedes the kept one.
	e.release(third)
	if r := e.getRun(third); r.Released || len(r.Result) == 0 {
		t.Fatal("the newest preview was released")
	}
	if r := e.getRun(second); !r.Released || r.Result != nil {
		t.Fatal("the superseded preview is still kept")
	}
	if len(e.logs.find("preview_result_released", second)) == 0 {
		t.Fatal("supersession not audited")
	}
	// Asking again keeps the newest.
	if st := e.release(third); len(st.GetResult()) == 0 || st.GetReleased() {
		t.Fatalf("newest preview asked again %+v", st)
	}
}
