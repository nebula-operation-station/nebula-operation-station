// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// H02 acceptance: executor state in executor.db. Each test runs one
// executor, stops it, and starts a second one on the same data directory.

func TestH02_RestartRevokesPermitsAndStartsLocked(t *testing.T) {
	dir, id := privateDir(t), newIdentity()
	h1 := newHarness(t, harnessOptions{dataDir: dir, identity: id})
	h1.unlock()
	h1.openSession()
	approved := h1.approvedMedium()
	h1.propose(h1.request(pb.RiskClass_RISK_CLASS_MEDIUM)) // stays pending
	if _, err := h1.client.AuthorizeRun(h1.ctx(), run(approved.GetExecutionDigest(), "dockerflux", fpA)); err != nil {
		t.Fatalf("authorize before restart: %v", err)
	}
	h1.stop()

	h2 := newHarness(t, harnessOptions{dataDir: dir, identity: id})
	st, err := h2.client.GetStatus(h2.ctx(), &pb.GetStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if st.GetUnlocked() || st.GetPrivilegedSessionActive() || st.GetPendingPermits() != 0 || st.GetApprovedPermits() != 0 {
		t.Fatalf("after restart: unlocked=%v session=%v pending=%d approved=%d; want locked, no session, no permits",
			st.GetUnlocked(), st.GetPrivilegedSessionActive(), st.GetPendingPermits(), st.GetApprovedPermits())
	}
	pend, err := h2.client.ListPending(h2.ctx(), &pb.ListPendingRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(pend.GetPermits()); n != 0 {
		t.Fatalf("%d pending permits survived the restart", n)
	}
	// The approved permit is gone: even unlocked, the remaining host cannot run.
	h2.unlock()
	_, err = h2.client.AuthorizeRun(h2.ctx(), run(approved.GetExecutionDigest(), "strompi", fpB))
	wantCode(t, err, codes.NotFound, string(permit.CodeNotFound))
}

func TestH02_SpentExecutionIDsSurviveRestart(t *testing.T) {
	dir, id := privateDir(t), newIdentity()
	h1 := newHarness(t, harnessOptions{dataDir: dir, identity: id})
	r := h1.request(pb.RiskClass_RISK_CLASS_MEDIUM)
	h1.propose(r)
	h1.stop()

	h2 := newHarness(t, harnessOptions{dataDir: dir, identity: id})
	// The same request cannot be revived ...
	_, err := h2.client.ProposeExecution(h2.ctx(), &pb.ProposeExecutionRequest{Request: r, ParametersJson: params})
	wantCode(t, err, codes.AlreadyExists, string(permit.CodeExecutionIDReused))
	// ... and the ID cannot be re-bound to other content.
	r.ResolvedTargets = r.ResolvedTargets[:1]
	_, err = h2.client.ProposeExecution(h2.ctx(), &pb.ProposeExecutionRequest{Request: r, ParametersJson: params})
	wantCode(t, err, codes.AlreadyExists, string(permit.CodeExecutionIDReused))
}

func TestH02_SignCountersSurviveRestart(t *testing.T) {
	dir, id := privateDir(t), newIdentity()
	id.cred.Counter = 10
	h1 := newHarness(t, harnessOptions{dataDir: dir, identity: id})
	h1.openSession()
	h1.stop()

	h2 := newHarness(t, harnessOptions{dataDir: dir, identity: id})
	// An authenticator (or a cloned one) presenting counter 10 again is
	// rejected although the credential file still says 0.
	b, err := h2.client.BeginPrivilegedSession(h2.ctx(), &pb.BeginPrivilegedSessionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = h2.client.CompletePrivilegedSession(h2.ctx(), &pb.CompletePrivilegedSessionRequest{AssertionJson: h2.sign(b.GetChallenge())})
	wantCode(t, err, codes.PermissionDenied, string(permit.CodeAssertionRejected))

	id.cred.Counter = 11
	h2.openSession()
}

func TestH02_DatabaseFileIsPrivate(t *testing.T) {
	dir := privateDir(t)
	newHarness(t, harnessOptions{dataDir: dir})
	fi, err := os.Lstat(filepath.Join(dir, executordb.FileName))
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%s: mode %v, want a regular 0600 file", executordb.FileName, fi.Mode())
	}
}
