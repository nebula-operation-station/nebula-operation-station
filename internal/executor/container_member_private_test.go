// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/dispatch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/sshtransport"
)

// durableStub is a durableRunner that records what the target had seen
// when the job was handed over, and never starts one.
type durableStub struct {
	target *fakeTarget
	mu     sync.Mutex
	calls  [][]string // the target's commands at each hand-over
}

func (d *durableStub) run(_ context.Context, _ *ssh.Client, _ hostrun.JobConfig, _ string, _, _ []byte, _ time.Duration,
	_ ...hostrun.Secret) (hostrun.DispatchOutcome, string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, d.target.cmds())
	return hostrun.NotStarted, "stub: no job", nil
}

func (d *durableStub) handovers() [][]string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([][]string(nil), d.calls...)
}

// privateMemberEnv runs durableMemberTransport for a private compose update
// member against the fake target, connected the production way (pinned
// host key, executor credential).
type privateMemberEnv struct {
	*transferEnv
	durable *durableStub
	x       *batchExec
	eps     []sshtransport.Endpoint
}

func newPrivateMemberEnv(t *testing.T, store string) *privateMemberEnv {
	t.Helper()
	e := newTransferEnv(t, store)
	addr, hostKey := e.target.listen(t, e.userPub)
	e.pin(hostKey)
	ep, err := sshtransport.ParseEndpoint(addr)
	if err != nil {
		t.Fatal(err)
	}
	d := &durableStub{target: e.target}
	x := &batchExec{durable: d.run, composePins: []containerArtifact{testComposePin()}}
	return &privateMemberEnv{transferEnv: e, durable: d, x: x, eps: []sshtransport.Endpoint{ep}}
}

// member is a private compose update member over the transfer image.
func (e *privateMemberEnv) member(t *testing.T) dispatch.Run {
	t.Helper()
	u := testComposeUpdate()
	tb := e.binding()
	img := tb.Images[0]
	img.Service = u.Images[0].Service
	u.Images, u.Registry = []canonical.ContainerUpdateImage{img}, tb.Registry
	m, params := testContainerMember(t, u)
	m.Request.ExecutionID = "00000000-0000-4000-8000-000000000777"
	m.Request.ResolvedTargets = []canonical.Target{{HostID: e.host, HostKeyFingerprint: e.fp}}
	return dispatch.Run{ParentDigest: hexOf("9"), MemberID: m.MemberID, ExecutionID: m.Request.ExecutionID, ActionID: m.Request.ActionID,
		Member: m, Parameters: params}
}

func (e *privateMemberEnv) transport(t *testing.T, run dispatch.Run) (dispatch.Outcome, *batchMemberCall) {
	t.Helper()
	call := &batchMemberCall{hostID: e.host, fingerprint: e.fp, eps: e.eps, artifact: testComposeArtifact, timeout: time.Minute,
		durable: true, resp: &pb.RunBatchMemberResponse{}}
	c, err := e.svc.Connect(context.Background(), e.host, e.fp, e.eps)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	out, err := e.svc.durableMemberTransport(context.Background(), e.x, call, run, c)
	if err != nil {
		t.Fatalf("durable transport: %v", err)
	}
	return out, call
}

// The durable path transfers a private member's images over the member's
// own session before the job is handed over: the target has run docker
// load and the evidence inspect when the job arrives.
func TestPrivateMemberTransfersBeforeTheJob(t *testing.T) {
	e := newPrivateMemberEnv(t, imageStoreContainerd)
	run := e.member(t)
	e.transport(t, run)
	h := e.durable.handovers()
	if len(h) != 1 {
		t.Fatalf("%d job hand-overs, want 1", len(h))
	}
	want := []string{"docker info --format '{{json .DriverStatus}}'", "docker load -q",
		wantInspectPrefix + e.repository() + "@" + e.pull.img.manifestDigest + "'"}
	if got := h[0]; strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("target commands before the job:\n got %q\nwant %q", got, want)
	}
	e.assertNoCredentialOnTarget(t, nil)
}

// A failed transfer is the member's "not started": no recreation intent,
// no job, nothing for the reconciler, whatever stopped the transfer.
func TestPrivateMemberTransferFailureIsNotStarted(t *testing.T) {
	cases := []struct {
		name  string
		store string
		mut   func(*privateMemberEnv)
		want  error
	}{
		{"classic image store", imageStoreClassic, nil, errTransferStore},
		{"docker load fails", imageStoreContainerd, func(e *privateMemberEnv) { e.target.loadFails = true }, errTransferLoad},
		{"registry binding differs", imageStoreContainerd, func(e *privateMemberEnv) {
			if _, err := e.svc.RemovePrivateRegistry(context.Background(), &pb.RemovePrivateRegistryRequest{RegistryId: "corp"}); err != nil {
				e.t.Fatal(err)
			}
		}, errTransferBinding},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newPrivateMemberEnv(t, c.store)
			run := e.member(t)
			if c.mut != nil {
				c.mut(e)
			}
			out, call := e.transport(t, run)
			if out != dispatch.OutcomeFailure || call.resp.GetClass() != classBatchNotExecuted ||
				!strings.HasPrefix(call.resp.GetDetail(), "not started: "+c.want.Error()) {
				t.Fatalf("outcome %v, response %+v; want not started: %v", out, call.resp, c.want)
			}
			if call.dispatched {
				t.Fatal("a failed transfer handed the run to the reconciler")
			}
			if n := len(e.durable.handovers()); n != 0 {
				t.Fatalf("the job was handed over %d times after a failed transfer", n)
			}
			if _, err := e.db.GetContainerRecreation(run.ExecutionID); err == nil {
				t.Fatal("a recreation intent was recorded after a failed transfer")
			}
		})
	}
}
