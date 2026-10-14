// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// durableScript counts its runs in a file outside the job directory.
func durableScript(counter string, extra string) []byte {
	return []byte("#!/bin/sh\necho run >> " + counter + "\n" + extra + "cat \"$NEBULA_PARAMS\"\n")
}

func durableReq(digest string, host runHost, script []byte) *pb.StartDurableRequest {
	r := runReq(digest, host, script, credRef)
	return &pb.StartDurableRequest{Run: r.GetRun(), Endpoints: r.GetEndpoints(), TimeoutSeconds: 120}
}

func (h *harness) getRun(execID, host string, release bool) *pb.RunStatus {
	h.t.Helper()
	r, err := h.client.GetRun(h.ctx(), &pb.GetRunRequest{ExecutionId: execID, HostId: host, Release: release})
	if err != nil {
		h.t.Fatal(err)
	}
	return r.GetRun()
}

// reconcileUntil runs reconciliation passes until the run is finished.
func (h *harness) reconcileUntil(execID, host string) *pb.RunStatus {
	h.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		h.svc.ReconcileOnce(context.Background())
		st := h.getRun(execID, host, false)
		if st.GetState() == "finished" {
			return st
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("run still %s", st.GetState())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func runCount(t *testing.T, counter string) int {
	t.Helper()
	b, _ := os.ReadFile(counter)
	return strings.Count(string(b), "run")
}

// M4 acceptance: killing Nebula during a durable job and restarting it
// reconciles the result without re-running the job.
func TestM4_DurableJobSurvivesAnExecutorRestart(t *testing.T) {
	dir := privateDir(t)
	counter := filepath.Join(t.TempDir(), "count")
	script := durableScript(counter, "sleep 1\n")
	h := newHarness(t, harnessOptions{dataDir: dir})
	h.unlock()
	host := h.pinnedRunHost("runhost")
	d := h.approvedScript(host, script)
	r, err := h.client.StartDurable(h.ctx(), durableReq(d, host, script))
	if err != nil {
		t.Fatal(err)
	}
	execID := r.GetRun().GetExecutionId()
	if r.GetRun().GetState() != "running" {
		t.Fatalf("started: %+v", r.GetRun())
	}
	h.requireAudit("run_dispatched", "runhost")
	h.stop() // the executor dies while the job runs

	h = newHarness(t, harnessOptions{dataDir: dir})
	h.svc.ReconcileOnce(context.Background()) // locked: nothing happens
	if st := h.getRun(execID, "runhost", false); st.GetState() != "running" {
		t.Fatalf("reconciled while locked: %+v", st)
	}
	h.unlock()
	st := h.reconcileUntil(execID, "runhost")
	if st.GetClass() != "success" || string(st.GetResult()) != `{"a":"x","b":[1,2]}` {
		t.Fatalf("reconciled: %+v", st)
	}
	if n := runCount(t, counter); n != 1 {
		t.Fatalf("the job ran %d times", n)
	}
	// Collected: the job directory is gone from the host.
	if _, err := os.Stat(filepath.Join(dir, "remote", "jobs", execID)); !os.IsNotExist(err) {
		t.Fatalf("job directory left: %v", err)
	}
	// The server takes the result once; afterwards only the metadata stays.
	if st := h.getRun(execID, "runhost", true); len(st.GetResult()) == 0 {
		t.Fatal("release returned no result")
	}
	if st := h.getRun(execID, "runhost", false); !st.GetReleased() || len(st.GetResult()) != 0 || st.GetClass() != "success" {
		t.Fatalf("after release: %+v", st)
	}
	// Reconciliation never dispatches again.
	h.svc.ReconcileOnce(context.Background())
	if n := runCount(t, counter); n != 1 {
		t.Fatalf("the job ran %d times", n)
	}
}

func TestM4_DurableJobStartsOncePerHost(t *testing.T) {
	counter := filepath.Join(t.TempDir(), "count")
	script := durableScript(counter, "")
	h := newHarness(t, harnessOptions{})
	h.unlock()
	host := h.pinnedRunHost("runhost")
	d := h.approvedScript(host, script)
	if _, err := h.client.StartDurable(h.ctx(), durableReq(d, host, script)); err != nil {
		t.Fatal(err)
	}
	_, err := h.client.StartDurable(h.ctx(), durableReq(d, host, script))
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = h.client.RunAttached(h.ctx(), runReq(d, host, script, credRef))
	wantCode(t, err, codes.PermissionDenied, "")
	h.reconcileUntil(hostExecID(t, h, d), "runhost")
	if n := runCount(t, counter); n != 1 {
		t.Fatalf("ran %d times", n)
	}
}

// hostExecID returns the execution ID of the only run recorded so far.
func hostExecID(t *testing.T, h *harness, _ string) string {
	t.Helper()
	runs, err := h.db.OpenRuns()
	if err != nil || len(runs) == 0 {
		t.Fatalf("open runs: %v %v", runs, err)
	}
	return runs[0].ExecutionID
}

func TestM4_DurableJobThatDiesIsInterruptedNotRerun(t *testing.T) {
	dir := privateDir(t)
	counter := filepath.Join(t.TempDir(), "count")
	script := durableScript(counter, "sleep 60\n")
	h := newHarness(t, harnessOptions{dataDir: dir})
	h.unlock()
	host := h.pinnedRunHost("runhost")
	d := h.approvedScript(host, script)
	r, err := h.client.StartDurable(h.ctx(), durableReq(d, host, script))
	if err != nil {
		t.Fatal(err)
	}
	execID := r.GetRun().GetExecutionId()
	state := filepath.Join(dir, "remote", "jobs", execID, "state.json")
	var pid int
	deadline := time.Now().Add(10 * time.Second)
	for pid == 0 && time.Now().Before(deadline) {
		b, _ := os.ReadFile(state)
		if parts := strings.SplitN(string(b), `"pid":`, 2); len(parts) == 2 {
			pid, _ = strconv.Atoi(strings.SplitN(parts[1], ",", 2)[0])
		}
		time.Sleep(50 * time.Millisecond)
	}
	if p, err := os.FindProcess(pid); err != nil || p.Kill() != nil {
		t.Fatalf("kill %d: %v", pid, err)
	}
	st := h.reconcileUntil(execID, "runhost")
	if st.GetClass() != "script_interrupted" {
		t.Fatalf("%+v", st)
	}
	if n := runCount(t, counter); n != 1 {
		t.Fatalf("ran %d times", n)
	}
}

func TestM4_DurableJobOnAnUnreachableHostIsNotExecuted(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.unlock()
	host := h.pinnedRunHost("runhost")
	d := h.approvedScript(host, runScript)
	down := host
	down.endpoint = closedPort(t)
	r, err := h.client.StartDurable(h.ctx(), durableReq(d, down, runScript))
	if err != nil {
		t.Fatal(err)
	}
	if st := r.GetRun(); st.GetState() != "finished" || st.GetClass() != "network_unreachable" || !strings.HasPrefix(st.GetDetail(), "not dispatched") {
		t.Fatalf("%+v", st)
	}
	if len(host.srv.Commands()) != 0 {
		t.Fatal("host contacted")
	}
}

func TestM4_DurableIsServerOnly(t *testing.T) {
	uid := uint32(os.Getuid())
	h := newHarness(t, harnessOptions{uidRoles: map[uint32][]peercred.Role{uid: {peercred.RoleAdmin}}})
	_, err := h.client.StartDurable(h.ctx(), &pb.StartDurableRequest{})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = h.client.GetRun(h.ctx(), &pb.GetRunRequest{})
	wantCode(t, err, codes.PermissionDenied, "")
}
