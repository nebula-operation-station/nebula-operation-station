// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/hostrun"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// SSH failover through the durable dispatch path (ep02): the endpoint a
// run was dispatched on — an alternate after failover — is what the run
// record, the response and the audit name, and it is stored before the
// dispatch starts, so a dispatch that breaks mid-way names it too.

// failoverScript is the job the dispatch tests start: it ends at once.
var failoverScript = []byte("#!/bin/sh\nexit 0\n")

// startDurableOn proposes, approves and starts one durable run of
// failoverScript on e.host over endpoints.
func (e *reconcileEnv) startDurableOn(seq int, endpoints ...string) *pb.RunStatus {
	e.t.Helper()
	prop := listPendingRequest(e.t, seq, failoverScript)
	prop.Request.CredentialRefs = []string{"cred"}
	prop.Request.ResolvedTargets = []*pb.Target{{HostId: e.host, HostKeyFingerprint: e.fp}}
	resp, err := e.svc.ProposeExecution(context.Background(), prop)
	if err != nil {
		e.t.Fatalf("propose: %v", err)
	}
	d, err := canonical.ParseDigest(resp.GetExecutionDigest())
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.svc.auth.ApproveCLI(d, 0, "admin"); err != nil {
		e.t.Fatalf("approve: %v", err)
	}
	st, err := e.svc.StartDurable(context.Background(), &pb.StartDurableRequest{
		Run: &pb.AuthorizeRunRequest{ExecutionDigest: resp.GetExecutionDigest(), HostId: e.host, HostKeyFingerprint: e.fp,
			ActionId: prop.Request.ActionId, ModuleVersion: prop.Request.ModuleVersion, Artifact: failoverScript,
			ParametersJson: prop.ParametersJson, CredentialRef: "cred"},
		Endpoints: endpoints, TimeoutSeconds: 600,
	})
	if err != nil {
		e.t.Fatalf("start durable: %v", err)
	}
	return st.GetRun()
}

// TestStartDurableFailsOverAndNamesAlternate: the primary is down, the run
// is dispatched on the alternate, and the response, the run record and
// run_dispatched all name the alternate — never the first configured
// endpoint.
func TestStartDurableFailsOverAndNamesAlternate(t *testing.T) {
	t.Parallel()
	e := newReconcileEnv(t)
	hk := newHostKey(t)
	e.pin(hk)
	alt := startTestSSHWithKey(t, e.userPub, sshModeNormal, hk)
	primary := closedAddr(t)

	st := e.startDurableOn(101, primary, alt.addr)
	if st.GetEndpoint() != alt.addr {
		t.Fatalf("response endpoint = %q, want the alternate %q", st.GetEndpoint(), alt.addr)
	}
	r := e.getRun(st.GetExecutionId())
	if r.State != executordb.RunRunning || r.Endpoint != alt.addr {
		t.Fatalf("run state/endpoint = %s/%q, want running/%q", r.State, r.Endpoint, alt.addr)
	}
	recs := e.logs.find("run_dispatched", st.GetExecutionId())
	if len(recs) != 1 || recs[0].attrs["endpoint"] != alt.addr {
		t.Fatalf("run_dispatched audit = %+v, want one naming %s", recs, alt.addr)
	}
	if n := len(e.logs.find("ssh_failover", "")); n != 1 {
		t.Fatalf("ssh_failover audit records = %d, want 1", n)
	}
}

// TestBrokenDispatchNamesAttemptedEndpoint: the dispatch on the alternate
// breaks after the connection stood. The run stays dispatching with the
// alternate stored as its dispatch endpoint; run_dispatch_uncertain names
// it, and the reconcile that closes the run keeps it.
func TestBrokenDispatchNamesAttemptedEndpoint(t *testing.T) {
	t.Parallel()
	e := newReconcileEnv(t)
	hk := newHostKey(t)
	e.pin(hk)
	alt := startTestSSHWithKey(t, e.userPub, sshModeReject, hk) // sessions fail: the dispatch breaks
	primary := closedAddr(t)

	st := e.startDurableOn(102, primary, alt.addr)
	id := st.GetExecutionId()
	if st.GetState() != executordb.RunDispatching || st.GetEndpoint() != alt.addr {
		t.Fatalf("response state/endpoint = %s/%q, want dispatching/%q", st.GetState(), st.GetEndpoint(), alt.addr)
	}
	recs := e.logs.find("run_dispatch_uncertain", id)
	if len(recs) != 1 || recs[0].attrs["endpoint"] != alt.addr {
		t.Fatalf("run_dispatch_uncertain audit = %+v, want one naming %s", recs, alt.addr)
	}

	alt.setMode(sshModeNormal)
	e.reconcile(context.Background())
	r := e.requireFinished(id, classNotExecuted)
	if r.Endpoint != alt.addr {
		t.Fatalf("run endpoint = %q, want the attempted dispatch endpoint %q", r.Endpoint, alt.addr)
	}
	fin := e.logs.find("run_finished", id)
	if len(fin) != 1 || fin[0].attrs["endpoint"] != alt.addr {
		t.Fatalf("run_finished audit = %+v, want endpoint %s", fin, alt.addr)
	}
}

// TestReconcileRunningJobKeepsDispatchEndpoint: a dispatching run whose
// job is found running over another endpoint is marked running with its
// stored dispatch endpoint; the check endpoint never replaces it.
func TestReconcileRunningJobKeepsDispatchEndpoint(t *testing.T) {
	t.Parallel()
	for _, stored := range []string{"192.0.2.10:22", ""} {
		name := stored
		if name == "" {
			name = "no stored endpoint"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newReconcileEnv(t)
			hk := newHostKey(t)
			e.pin(hk)
			alt := startTestSSHWithKey(t, e.userPub, sshModeNormal, hk)
			id := newTestUUID()
			if err := e.db.CreateRun(executordb.Run{ExecutionID: id, HostID: e.host, Digest: "failover-test-digest",
				Endpoints: []string{closedAddr(t), alt.addr}, Fingerprint: e.fp, Timeout: 10 * time.Minute}); err != nil {
				t.Fatal(err)
			}
			if stored != "" {
				if err := e.db.SetRunDispatchEndpoint(id, e.host, stored); err != nil {
					t.Fatal(err)
				}
			}
			// The job is on the host and running (started over the alternate).
			c, err := e.svc.Connect(context.Background(), e.host, e.fp, mustEndpoints(t, alt.addr))
			if err != nil {
				t.Fatal(err)
			}
			out, _, err := hostrun.Dispatch(context.Background(), c.Client, e.jobs, id, []byte("{}"), []byte("#!/bin/sh\nsleep 3\n"), time.Minute)
			c.Close()
			if err != nil || out != hostrun.Dispatched {
				t.Fatalf("dispatch: %v %v", out, err)
			}

			e.reconcile(context.Background())

			r := e.getRun(id)
			if r.State != executordb.RunRunning {
				t.Fatalf("run state = %s, want running", r.State)
			}
			if r.Endpoint != stored {
				t.Fatalf("run endpoint = %q, want the stored dispatch endpoint %q (not the check endpoint %s)", r.Endpoint, stored, alt.addr)
			}
		})
	}
}
