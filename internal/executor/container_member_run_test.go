// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions/actions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// containerEnv is a dispatch environment whose durable jobs run for real
// on the loopback test host, without sudo or systemd.
type containerEnv struct {
	*dispatchEnv
	dir string
}

func newContainerEnv(t *testing.T, hosts ...string) *containerEnv {
	t.Helper()
	e := newDispatchEnv(t, hosts...)
	dir := t.TempDir()
	e.svc.SetJobConfig(hostrun.JobConfig{JobRoot: filepath.Join(dir, "jobs"), RunRoot: filepath.Join(dir, "run"),
		BootIDFile: filepath.Join(dir, "bootid")})
	e.svc.batchRun.durablePoll = 20 * time.Millisecond
	return &containerEnv{dispatchEnv: e, dir: dir}
}

// script is a stand-in recreate job: it copies the parameters it got to
// <dir>/params-<tag>.json, waits while <dir>/block exists and exits with
// code. It is trusted as MEDIUM, so the plan stays on an automatic gate, and
// the executor pins it as a binding-consuming 2.0.0 artifact (the shipped
// executor pins none yet).
func (e *containerEnv) script(t *testing.T, tag string, code int) []byte {
	t.Helper()
	s := e.trustedScript(t, tag, code, composeUpdateVersion)
	e.svc.batchRun.composePins = append(e.svc.batchRun.composePins, containerArtifact{ActionID: composeUpdateAction,
		ModuleVersion: composeUpdateVersion, SHA256: sha256Hex(s)})
	return s
}

// trustedScript is script without the pin: trusted for docker.compose_update
// at version, but not an artifact the executor runs for a container member.
func (e *containerEnv) trustedScript(t *testing.T, tag string, code int, version string) []byte {
	t.Helper()
	s := e.stubScript(tag, code)
	e.trust(t, s, version)
	return s
}

// stubScript is the stand-in job's bytes: it prints <dir>/result.json when
// the test wrote one (a compose-update-v2 or compose-rollback-v1 result),
// otherwise a result no judge accepts.
func (e *containerEnv) stubScript(tag string, code int) []byte {
	return fmt.Appendf(nil, "#!/bin/sh\ncp \"$NEBULA_PARAMS\" %q\nwhile [ -e %q ]; do sleep 0.05; done\n"+
		"if [ -f %q ]; then cat %q; else printf '{\"format\":\"test\"}\\n'; fi\nexit %d\n",
		filepath.Join(e.dir, "params-"+tag+".json"), filepath.Join(e.dir, "block"),
		filepath.Join(e.dir, "result.json"), filepath.Join(e.dir, "result.json"), code)
}

// trust trusts art for docker.compose_update at version as MEDIUM.
func (e *containerEnv) trust(t *testing.T, art []byte, version string) {
	t.Helper()
	e.trustFor(t, art, composeUpdateAction, version)
}

// trustFor trusts art for action at version as MEDIUM.
func (e *containerEnv) trustFor(t *testing.T, art []byte, action, version string) {
	t.Helper()
	h := sha256.Sum256(art)
	if err := e.db.TrustArtifact(executordb.TrustedArtifact{SHA256: canonical.Digest(h).String(), ActionID: action,
		ModuleVersion: version, Risk: canonical.RiskMedium, TrustedBy: "test"}); err != nil {
		t.Fatal(err)
	}
}

// nextExecution is the execution ID the next proposeContainer gives member
// i, so a test can write the result of that run (with its retained tags)
// before proposing.
func (e *containerEnv) nextExecution(i int) string {
	return fmt.Sprintf("00000000-0000-4000-8%03d-%012d", e.next+1, i+100)
}

// proposeContainer proposes and approves a one-stage plan of compose update
// members, one per artifact, each on host with binding u, at the pinned
// module version.
func (e *containerEnv) proposeContainer(t *testing.T, host string, u canonical.BatchContainerUpdate, arts ...[]byte) (string, []canonical.BatchMember) {
	t.Helper()
	return e.proposeContainerVersion(t, host, composeUpdateVersion, u, arts...)
}

// proposeContainerVersion is proposeContainer with the members' module
// version.
func (e *containerEnv) proposeContainerVersion(t *testing.T, host, version string, u canonical.BatchContainerUpdate, arts ...[]byte) (string, []canonical.BatchMember) {
	t.Helper()
	return e.proposeContainerAction(t, host, composeUpdateAction, version, u, arts...)
}

// proposeContainerAction is proposeContainerVersion for the members'
// action ID.
func (e *containerEnv) proposeContainerAction(t *testing.T, host, action, version string, u canonical.BatchContainerUpdate, arts ...[]byte) (string, []canonical.BatchMember) {
	t.Helper()
	e.next++
	n := e.next
	expiry := e.clock.Now().Unix() + 3600
	b := canonical.Batch{BatchVersion: canonical.BatchVersion, BatchID: fmt.Sprintf("00000000-0000-4000-8000-%012d", n), ExpiryUnix: expiry,
		StagePlan: canonical.BatchStagePlan{Dependencies: []canonical.BatchDependency{}, Stages: []canonical.BatchStage{{StageID: "stage-1",
			Gate: canonical.BatchGateAutomatic, MemberIDs: []string{}, RequiredPostchecks: []string{}}}}}
	hk, ok, err := e.db.HostKey(host)
	if err != nil || !ok {
		t.Fatalf("host %s not pinned: %v", host, err)
	}
	req := &pb.ProposeBatchRequest{}
	for i, art := range arts {
		id := fmt.Sprintf("member-%d", i)
		h := sha256.Sum256(art)
		// Member i > 0 updates another project, so no tuple repeats.
		bu := u.Clone()
		if i > 0 {
			bu.Project = fmt.Sprintf("%s%d", u.Project, i)
		}
		params, ph, err := canonical.ContainerUpdateParameters(bu)
		if err != nil {
			t.Fatal(err)
		}
		b.Members = append(b.Members, canonical.BatchMember{MemberID: id, ContainerUpdate: &bu, Request: canonical.Request{
			RequestVersion: canonical.RequestVersion, ExecutionID: fmt.Sprintf("00000000-0000-4000-8%03d-%012d", n, i+100), ActionID: action,
			ModuleVersion: version, ArtifactSHA256: canonical.Digest(h).String(), ParametersHash: ph, CredentialRefs: []string{"cred"},
			RiskClass: canonical.RiskMedium, ExpiryUnix: expiry,
			ResolvedTargets: []canonical.Target{{HostID: host, HostKeyFingerprint: hk.Fingerprint}}},
			CredentialVersions: []canonical.CredentialVersion{{Reference: "cred", Version: CredentialVersionOf(e.userPub)}}, PreconditionHashes: []string{}})
		b.StagePlan.Stages[0].MemberIDs = append(b.StagePlan.Stages[0].MemberIDs, id)
		req.Members = append(req.Members, &pb.BatchMemberInput{MemberId: id, Artifact: art, ParametersJson: params})
	}
	sh, err := canonical.BatchStagePlanHash(b.StagePlan)
	if err != nil {
		t.Fatal(err)
	}
	b.StagePlanHash = sh.String()
	for i := range b.Members {
		b.Members[i].Request.StagePlanHash = sh.String()
	}
	if req.BatchJson, err = json.Marshal(b); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	prop, err := e.server.ProposeBatch(ctx, req)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if _, err := e.admin.ApproveBatchCLI(ctx, &pb.ApproveBatchCLIRequest{BatchDigest: prop.GetBatchDigest()}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	plan, _, _, err := canonical.ParseBatch(prop.GetCanonicalBatch(), e.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	return prop.GetBatchDigest(), plan.Members
}

func (e *containerEnv) req(digest string, i int, host string, art []byte) *pb.RunBatchMemberRequest {
	return &pb.RunBatchMemberRequest{BatchDigest: digest, MemberId: fmt.Sprintf("member-%d", i), Endpoints: []string{e.ssh[host].addr},
		Artifact: art, TimeoutSeconds: 60}
}

// A compose update member runs as a durable job, whatever the request
// says: with the fixed mutation timeout, never through the attached runner,
// and with exactly the parameters rendered from its frozen binding. Its run
// keeps member and action ID, and the target is free again afterwards.
func TestContainerMemberRunsDurableWithFrozenBindingOnly(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	art := e.script(t, "ok", 0)
	u := testComposeUpdate()
	exec := e.nextExecution(0)
	e.writeResult(t, passingComposeResultFor(u, exec))
	d, members := e.proposeContainer(t, "web-1", u, art)
	if members[0].Request.ExecutionID != exec {
		t.Fatalf("execution %s, the result was written for %s", members[0].Request.ExecutionID, exec)
	}

	resp, err := e.server.RunBatchMember(context.Background(), e.req(d, 0, "web-1", art))
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS || resp.GetClass() != hostrun.ClassSuccess ||
		!strings.Contains(string(resp.GetResult()), `"format":"compose-update-v2"`) {
		t.Fatalf("response %+v", resp)
	}
	if row, err := e.db.GetContainerRecreation(members[0].Request.ExecutionID); err != nil || row.State != executordb.RecreationRecreated ||
		!row.Verdict.Passed || len(row.Baseline) == 0 || row.WindowExpiresAt.IsZero() {
		t.Fatalf("recreation row %+v %v", row, err)
	}
	if e.attached.count() != 0 {
		t.Fatal("a container member ran attached")
	}
	want, _, err := canonical.ContainerUpdateParameters(u)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(e.dir, "params-ok.json"))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("the job got %q (%v), want the binding's rendering %q", got, err, want)
	}
	run, err := e.db.GetRun(members[0].Request.ExecutionID, "web-1")
	if err != nil || run.State != executordb.RunFinished || run.Class != hostrun.ClassSuccess || run.MemberID != "member-0" ||
		run.ActionID != composeUpdateAction || run.Timeout != containerMutationTimeout || run.Digest != d {
		t.Fatalf("run %+v %v", run, err)
	}
	if byMember, err := e.db.RunByMember(d, "member-0"); err != nil || byMember.ExecutionID != run.ExecutionID {
		t.Fatalf("run by member %+v %v", byMember, err)
	}
	if held := e.svc.HeldBatchTargets(); len(held) != 0 {
		t.Fatalf("target still held: %+v", held)
	}
	// Spent: never run again.
	if _, err := e.server.RunBatchMember(context.Background(), e.req(d, 0, "web-1", art)); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("replay: %v", err)
	}
}

// A job that fails on the host is a failed member: the rollout stops (zero
// threshold) and the next member is not claimed.
func TestContainerMemberFailedJobStopsRollout(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	bad, next := e.script(t, "bad", 10), e.script(t, "next", 0)
	d, members := e.proposeContainer(t, "web-1", testComposeUpdate(), bad, next)
	resp, err := e.server.RunBatchMember(context.Background(), e.req(d, 0, "web-1", bad))
	if err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_FAILURE || resp.GetExitCode() != 10 {
		t.Fatalf("failed job: %+v %v", resp, err)
	}
	if _, err := e.server.RunBatchMember(context.Background(), e.req(d, 1, "web-1", next)); err == nil {
		t.Fatal("the next member ran after a failed container update")
	}
	if _, err := e.db.GetRun(members[1].Request.ExecutionID, "web-1"); err == nil {
		t.Fatal("the next member left a run")
	}
	if _, err := os.Stat(filepath.Join(e.dir, "params-next.json")); err == nil {
		t.Fatal("the next member's job ran")
	}
}

// When the server stops waiting, the job keeps running: the member answers
// unknown, the target stays held (RunVisible is never asked: the job runs
// as root), and the reconciled outcome later frees the target.
func TestDurableOutcomeReconciledAfterRequestEnds(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	art := e.script(t, "slow", 0)
	d, members := e.proposeContainer(t, "web-1", testComposeUpdate(), art)
	block := filepath.Join(e.dir, "block")
	if err := os.WriteFile(block, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// Code that asked RunVisible would free the target.
	e.visible.set(false)
	// The server hangs up once the job runs on the host.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer cancel()
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(filepath.Join(e.dir, "params-slow.json")); err == nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	resp, err := e.server.RunBatchMember(ctx, e.req(d, 0, "web-1", art))
	cancel()
	if err != nil {
		// The RPC itself may end with the context; the run must be open.
		if status.Code(err) != codes.Canceled {
			t.Fatal(err)
		}
	} else if resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_UNKNOWN {
		t.Fatalf("response %+v", resp)
	}
	execID := members[0].Request.ExecutionID
	waitFor(t, func() bool {
		h := e.svc.HeldBatchTargets()
		return len(h) == 1 && h[0].Durable && !h[0].Running
	})
	if run, err := e.db.GetRun(execID, "web-1"); err != nil || run.State == executordb.RunFinished {
		t.Fatalf("an unfinished job's run was closed: %+v %v", run, err)
	}
	// Another member on the target is refused while the job runs.
	art2 := e.script(t, "other", 0)
	d2, _ := e.proposeContainer(t, "web-1", testComposeUpdate(), art2)
	if _, err := e.server.RunBatchMember(context.Background(), e.req(d2, 0, "web-1", art2)); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "batch_host_busy") {
		t.Fatalf("second member: %v", err)
	}
	if e.visible.count() != 0 {
		t.Fatal("a durable hold was rechecked with RunVisible")
	}
	// The server hanging up is not a host failure: no attempt was counted,
	// so the run is not backed off.
	if f := e.logs.find("reconcile_unreachable", execID); len(f) != 0 {
		t.Fatalf("the hang-up counted as an unreachable host: %v", f[0].attrs)
	}
	if err := os.Remove(block); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		e.svc.ReconcileOnce(context.Background())
		run, err := e.db.GetRun(execID, "web-1")
		return err == nil && run.State == executordb.RunFinished
	})
	run, _ := e.db.GetRun(execID, "web-1")
	if run.Class != hostrun.ClassSuccess {
		t.Fatalf("reconciled run %+v", run)
	}
	if held := e.svc.HeldBatchTargets(); len(held) != 0 {
		t.Fatalf("target still held after the job was reconciled: %+v", held)
	}
}

// A run that closes without a result (here: the job directory is gone, so
// unknown) keeps its target held, across a restart, and neither a recheck
// nor RunVisible frees it.
func TestUnknownDurableRunKeepsTargetHeld(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	art := e.script(t, "lost", 0)
	d, members := e.proposeContainer(t, "web-1", testComposeUpdate(), art)
	// The job reaches the host and vanishes (a host reset, a wiped job root).
	e.svc.batchRun.durable = func(context.Context, *ssh.Client, hostrun.JobConfig, string, []byte, []byte, time.Duration, ...hostrun.Secret) (hostrun.DispatchOutcome, string, error) {
		return hostrun.Dispatched, "", nil
	}
	e.visible.set(false)
	resp, err := e.server.RunBatchMember(context.Background(), e.req(d, 0, "web-1", art))
	if err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_UNKNOWN || resp.GetClass() != classUnknown {
		t.Fatalf("response %+v %v", resp, err)
	}
	if run, err := e.db.GetRun(members[0].Request.ExecutionID, "web-1"); err != nil || run.Class != classUnknown {
		t.Fatalf("run %+v %v", run, err)
	}
	for range 2 {
		if e.svc.recheckHeld(context.Background(), e.svc.batchRun, "web-1") {
			t.Fatal("a recheck freed the target of an unknown durable run")
		}
	}
	if err := e.svc.ReleaseHeldBatchTarget(context.Background(), "web-1", members[0].Request.ExecutionID, "op", "test"); err == nil {
		t.Fatal("an operator release freed the target of an unknown durable run")
	}
	if e.visible.count() != 0 {
		t.Fatal("a durable hold was rechecked with RunVisible")
	}
	// Restart: the hold comes back as durable.
	if err := e.svc.EnableBatchExecution(); err != nil {
		t.Fatal(err)
	}
	e.svc.batchRun.visible = e.visible.run
	h := e.svc.HeldBatchTargets()
	if len(h) != 1 || !h[0].Durable {
		t.Fatalf("restored holds %+v", h)
	}
	if e.svc.recheckHeld(context.Background(), e.svc.batchRun, "web-1") || e.visible.count() != 0 {
		t.Fatal("a restored durable hold was freed or asked RunVisible")
	}
}

// A container member whose job the host refuses to start ends as a
// failure with nothing run, and its target is free.
func TestContainerMemberNotStartedReleasesTarget(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	art := e.script(t, "refused", 0)
	d, _ := e.proposeContainer(t, "web-1", testComposeUpdate(), art)
	e.svc.batchRun.durable = func(context.Context, *ssh.Client, hostrun.JobConfig, string, []byte, []byte, time.Duration, ...hostrun.Secret) (hostrun.DispatchOutcome, string, error) {
		return hostrun.NotStarted, "nebula-bootstrap: job exists", nil
	}
	resp, err := e.server.RunBatchMember(context.Background(), e.req(d, 0, "web-1", art))
	if err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_FAILURE || resp.GetClass() != hostrun.ClassPrecheckFailed {
		t.Fatalf("response %+v %v", resp, err)
	}
	if held := e.svc.HeldBatchTargets(); len(held) != 0 {
		t.Fatalf("target held after a refused start: %+v", held)
	}
}

// A container member runs only with the pinned module version and the
// pinned, binding-consuming artifact. Trust alone is not enough: a member
// whose artifact the executor trusts for docker.compose_update but has not
// pinned (another script, the inspect-based 1.0.0 script, under 1.0.0 or
// labelled 2.0.0), or the pinned artifact under another module version, is
// refused before the claim. Nothing runs, no run is recorded, the target
// stays free, and the member is not spent.
func TestContainerMemberRefusedWithUnpinnedArtifactOrVersion(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	pinned := e.script(t, "pinned", 0)
	other := e.trustedScript(t, "other", 0, composeUpdateVersion)
	v1 := composeUpdateV1(t)
	e.trust(t, v1, "1.0.0")
	e.trust(t, v1, composeUpdateVersion)
	e.trust(t, pinned, "2.0.1")
	cases := []struct {
		name, version string
		art           []byte
	}{
		{"another trusted artifact at 2.0.0", composeUpdateVersion, other},
		{"inspect-based 1.0.0 artifact at 1.0.0", "1.0.0", v1},
		{"inspect-based 1.0.0 artifact trusted as 2.0.0", composeUpdateVersion, v1},
		{"pinned artifact at another version", "2.0.1", pinned},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, members := e.proposeContainerVersion(t, "web-1", c.version, testComposeUpdate(), c.art)
			_, err := e.server.RunBatchMember(context.Background(), e.req(d, 0, "web-1", c.art))
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "container_member_refused") ||
				!strings.Contains(err.Error(), errContainerArtifact.Error()) {
				t.Fatalf("err = %v, want the container member refused for its artifact", err)
			}
			if _, err := e.db.GetRun(members[0].Request.ExecutionID, "web-1"); err == nil {
				t.Fatal("a refused member left a run")
			}
			if held := e.svc.HeldBatchTargets(); len(held) != 0 {
				t.Fatalf("target held after a refusal: %+v", held)
			}
			if e.attached.count() != 0 {
				t.Fatal("a refused container member ran attached")
			}
			// Refused before the claim: the same request is refused again
			// for the same reason, not as spent.
			if _, err := e.server.RunBatchMember(context.Background(), e.req(d, 0, "web-1", c.art)); status.Code(err) != codes.FailedPrecondition ||
				!strings.Contains(err.Error(), "container_member_refused") {
				t.Fatalf("second attempt: %v", err)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(e.dir, "params-other.json")); err == nil {
		t.Fatal("the unpinned artifact ran")
	}
	// The pinned artifact at the pinned version runs (control).
	e.writeResult(t, passingComposeResultFor(testComposeUpdate(), e.nextExecution(0)))
	d, _ := e.proposeContainer(t, "web-1", testComposeUpdate(), pinned)
	resp, err := e.server.RunBatchMember(context.Background(), e.req(d, 0, "web-1", pinned))
	if err != nil || resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_SUCCESS {
		t.Fatalf("pinned member: %+v %v", resp, err)
	}
}

// The executor as shipped pins only the shipped 2.0.0 update script, the
// shipped 1.0.0 rollback script and the shipped standalone 1.0.0 update and
// rollback scripts, so another trusted 2.0.0 artifact is refused and never
// runs.
func TestShippedExecutorRefusesContainerMembers(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	if !slices.Equal(e.svc.batchRun.composePins, []containerArtifact{shippedComposeUpdatePin(), shippedComposeRollbackPin(),
		shippedStandaloneUpdatePin(), shippedStandaloneRollbackPin()}) {
		t.Fatalf("pins %+v", e.svc.batchRun.composePins)
	}
	art := e.trustedScript(t, "shipped", 0, composeUpdateVersion)
	d, _ := e.proposeContainer(t, "web-1", testComposeUpdate(), art)
	if _, err := e.server.RunBatchMember(context.Background(), e.req(d, 0, "web-1", art)); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), errContainerArtifact.Error()) {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "params-shipped.json")); err == nil {
		t.Fatal("an unpinned artifact ran")
	}
}

// The shipped docker.compose_update 2.0.0 artifact, with nothing but the
// shipped pin, runs end-to-end over RunBatchMember: claimed, dispatched as a
// durable job with the rendered binding, executed on the host and
// reconciled. The test host is no prepared Docker host (no root, no salt,
// none of the bound containers), so the script stops in its precheck with
// its typed v2 result and changes nothing. The same artifact under 1.0.0 or
// another version, and the inspect-based 1.0.0 script, are refused before
// the claim.
func TestShippedComposeUpdateArtifactRunsOverRunBatchMember(t *testing.T) {
	e := newContainerEnv(t, "web-1")
	if !slices.Equal(e.svc.batchRun.composePins, shippedContainerPins()) {
		t.Fatalf("pins %+v", e.svc.batchRun.composePins)
	}
	a, ok := actions.Lookup(composeUpdateAction)
	if !ok {
		t.Fatal("docker.compose_update missing")
	}
	art := a.Script
	v1 := composeUpdateV1(t)
	for _, v := range []string{composeUpdateVersion, "1.0.0", "2.0.1"} {
		e.trust(t, art, v)
	}
	e.trust(t, v1, "1.0.0")
	for _, c := range []struct {
		version string
		art     []byte
	}{{"1.0.0", art}, {"2.0.1", art}, {"1.0.0", v1}} {
		d, members := e.proposeContainerVersion(t, "web-1", c.version, testComposeUpdate(), c.art)
		_, err := e.server.RunBatchMember(context.Background(), e.req(d, 0, "web-1", c.art))
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), errContainerArtifact.Error()) {
			t.Fatalf("%s: err = %v, want refused for its artifact", c.version, err)
		}
		if _, err := e.db.GetRun(members[0].Request.ExecutionID, "web-1"); err == nil {
			t.Fatalf("%s: a refused member left a run", c.version)
		}
	}

	d, members := e.proposeContainer(t, "web-1", testComposeUpdate(), art)
	resp, err := e.server.RunBatchMember(context.Background(), e.req(d, 0, "web-1", art))
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(resp.GetResult(), &result); err != nil {
		t.Fatalf("result %q: %v (%+v)", resp.GetResult(), err, resp)
	}
	if resp.GetOutcome() != pb.BatchMemberOutcome_BATCH_MEMBER_OUTCOME_FAILURE || resp.GetClass() != hostrun.ClassPrecheckFailed ||
		result["format"] != "compose-update-v2" || result["phase"] != "precheck" || result["reason"] == "" || result["reason"] == "binding_invalid" {
		t.Fatalf("response %+v result %v", resp, result)
	}
	t.Logf("the shipped artifact stopped in its precheck: %v", result["reason"])
	if e.attached.count() != 0 {
		t.Fatal("the member ran attached")
	}
	run, err := e.db.GetRun(members[0].Request.ExecutionID, "web-1")
	if err != nil || run.State != executordb.RunFinished || run.Class != hostrun.ClassPrecheckFailed || run.MemberID != "member-0" ||
		run.ActionID != composeUpdateAction || run.Timeout != containerMutationTimeout {
		t.Fatalf("run %+v %v", run, err)
	}
	if held := e.svc.HeldBatchTargets(); len(held) != 0 {
		t.Fatalf("target still held: %+v", held)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
