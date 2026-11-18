// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/events"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// memEventStore keeps signed event records in memory.
type memEventStore struct{ recs []events.Record }

func (m *memEventStore) LastEvent() (int64, []byte, error) {
	if len(m.recs) == 0 {
		return 0, nil, nil
	}
	r := m.recs[len(m.recs)-1]
	return r.Seq, r.Hash, nil
}

func (m *memEventStore) InsertEvent(r events.Record) error { m.recs = append(m.recs, r); return nil }

// chainRejections is a RejectionStore whose commit checks the bindings in
// executor.db, appends the signed event to a real event chain and stores
// the row, all under one mutex (the test's stand-in for the executordb
// transaction).
type chainRejections struct {
	mu    sync.Mutex
	ids   permit.Store
	chain *events.Chain
	evs   *memEventStore
	pub   ed25519.PublicKey
	rows  map[canonical.Digest]permit.Rejection
}

func newChainRejections(t *testing.T, ids permit.Store) *chainRejections {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	evs := &memEventStore{}
	return &chainRejections{ids: ids, chain: events.NewChain(evs, key), evs: evs, pub: pub, rows: map[canonical.Digest]permit.Rejection{}}
}

func (c *chainRejections) RejectedProposal(d canonical.Digest) (permit.Rejection, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.rows[d]
	return r, ok, nil
}

func (c *chainRejections) RejectedBatchID(id string) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range c.rows {
		if r.Kind == permit.ProposalBatch && r.ID == id {
			return true, nil
		}
	}
	return false, nil
}

func (c *chainRejections) CommitRejection(r permit.Rejection, bindings []permit.ExecutionBinding) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, b := range bindings {
		d, ok, err := c.ids.LookupExecution(b.ExecutionID)
		if err != nil {
			return err
		}
		if !ok || d != b.Digest {
			return permit.ErrBindingMismatch
		}
	}
	if _, err := c.chain.Append(permit.RejectedEventKind, r.EventAttrs()); err != nil {
		return err
	}
	c.rows[r.Digest] = r
	return nil
}

// newRejectRPCEnv is newReconcileEnv with a permit authority that has a
// rejected-marker store.
func newRejectRPCEnv(t *testing.T) (*reconcileEnv, *chainRejections) {
	t.Helper()
	e := newReconcileEnv(t)
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "reconcile.test", Origins: []string{"https://reconcile.test"}, Counters: e.db}, nil)
	if err != nil {
		t.Fatal(err)
	}
	risk, err := riskpolicy.New(e.db)
	if err != nil {
		t.Fatal(err)
	}
	rej := newChainRejections(t, e.db)
	auth, err := permit.New(permit.Options{Verifier: v, Store: e.db, RiskPolicy: risk, Now: e.clock.Now, Rejections: rej})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.auth = auth
	return e, rej
}

func proposePending(t *testing.T, e *reconcileEnv, seq int) string {
	t.Helper()
	resp, err := e.svc.ProposeExecution(context.Background(), listPendingRequest(t, seq, []byte("#!/bin/sh\necho hi\n")))
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetState() != pb.PermitState_PERMIT_STATE_PENDING {
		t.Fatalf("state = %v", resp.GetState())
	}
	return resp.GetExecutionDigest()
}

func wantStatus(t *testing.T, err error, c codes.Code, code permit.Code) {
	t.Helper()
	if status.Code(err) != c || (code != "" && !strings.Contains(status.Convert(err).Message(), string(code))) {
		t.Fatalf("got %v, want %v %s", err, c, code)
	}
}

func TestRejectPendingRPCRoles(t *testing.T) {
	e, _ := newRejectRPCEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d := proposePending(t, e, 1)
	for _, role := range []peercred.Role{peercred.RolePVECollector, peercred.RoleNetDevCollector} {
		_, err := readRPCClient(t, e.svc, role).RejectPending(ctx, &pb.RejectPendingRequest{Digest: d})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s: %v, want PermissionDenied", role, err)
		}
	}
	server := readRPCClient(t, e.svc, peercred.RoleServer)
	_, err := server.RejectPending(ctx, &pb.RejectPendingRequest{Digest: d, RelayedUser: "alice"})
	wantStatus(t, err, codes.FailedPrecondition, permit.CodeSessionRequired)
	admin := readRPCClient(t, e.svc, peercred.RoleAdmin)
	_, err = admin.RejectPending(ctx, &pb.RejectPendingRequest{Digest: d, RelayedUser: "alice"})
	wantStatus(t, err, codes.InvalidArgument, permit.CodeInvalidRequest)
	_, err = admin.RejectPending(ctx, &pb.RejectPendingRequest{Digest: "not-a-digest"})
	wantStatus(t, err, codes.InvalidArgument, permit.CodeInvalidRequest)

	resp, err := admin.RejectPending(ctx, &pb.RejectPendingRequest{Digest: d, Reason: "not today"})
	if err != nil {
		t.Fatalf("admin reject: %v", err)
	}
	if resp.GetState() != pb.PermitState_PERMIT_STATE_REJECTED || resp.GetKind() != pb.ProposalKind_PROPOSAL_KIND_EXECUTION {
		t.Fatalf("response = %v", resp)
	}
	_, err = admin.RejectPending(ctx, &pb.RejectPendingRequest{Digest: d})
	wantStatus(t, err, codes.FailedPrecondition, permit.CodeAlreadyRejected)

	st, err := server.GetPermitState(ctx, &pb.GetPermitStateRequest{ExecutionDigest: d})
	if err != nil {
		t.Fatal(err)
	}
	if st.GetState() != pb.PermitState_PERMIT_STATE_REJECTED || st.GetRejectedBy() != pb.RejectingRole_REJECTING_ROLE_ADMIN {
		t.Fatalf("GetPermitState = %v", st)
	}
}

func TestRejectPendingRPCWritesOneSignedEventWithoutReasonText(t *testing.T) {
	e, rej := newRejectRPCEnv(t)
	ctx := context.Background()
	d := proposePending(t, e, 2)
	admin := readRPCClient(t, e.svc, peercred.RoleAdmin)
	reason := "Falscher Host, bitte neu planen"
	if _, err := admin.RejectPending(ctx, &pb.RejectPendingRequest{Digest: d, Reason: reason}); err != nil {
		t.Fatal(err)
	}
	if len(rej.evs.recs) != 1 {
		t.Fatalf("events = %d, want 1", len(rej.evs.recs))
	}
	if err := events.Verify(rej.pub, rej.evs.recs, nil); err != nil {
		t.Fatalf("chain does not verify: %v", err)
	}
	var body events.Body
	if err := json.Unmarshal(rej.evs.recs[0].Body, &body); err != nil {
		t.Fatal(err)
	}
	if body.Kind != permit.RejectedEventKind || body.Attrs["digest"] != d || body.Attrs["role"] != "admin" ||
		body.Attrs["reason_len"] != "31" || body.Attrs["proposal_kind"] != "execution" {
		t.Fatalf("event body = %+v", body)
	}
	if strings.Contains(string(rej.evs.recs[0].Body), "Falscher") {
		t.Fatal("signed event carries the reason text")
	}
}

func TestRejectedPermitCanNeverRun(t *testing.T) {
	e, _ := newRejectRPCEnv(t)
	ctx := context.Background()
	d := proposePending(t, e, 3)
	admin := readRPCClient(t, e.svc, peercred.RoleAdmin)
	if _, err := admin.RejectPending(ctx, &pb.RejectPendingRequest{Digest: d}); err != nil {
		t.Fatal(err)
	}
	_, err := admin.ApproveCLI(ctx, &pb.ApproveCLIRequest{ExecutionDigest: d})
	wantStatus(t, err, codes.FailedPrecondition, permit.CodeRejected)
	dg, err := canonical.ParseDigest(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.auth.Authorize(dg, permit.Run{HostID: "dockerflux", HostKeyFingerprint: testFingerprint}); err == nil {
		t.Fatal("rejected permit authorized a run")
	}
	// After a lock (permit authority only; the keyring is shared between
	// tests) the persisted marker still refuses approval.
	e.svc.auth.Lock("test")
	_, err = admin.ApproveCLI(ctx, &pb.ApproveCLIRequest{ExecutionDigest: d})
	wantStatus(t, err, codes.FailedPrecondition, permit.CodeRejected)
	// Re-proposal under the same execution ID is refused.
	_, err = e.svc.ProposeExecution(ctx, listPendingRequest(t, 3, []byte("#!/bin/sh\necho hi\n")))
	if status.Code(err) == codes.OK {
		t.Fatal("rejected execution re-proposed")
	}
}

func TestRejectApprovedPermitRPC(t *testing.T) {
	e, _ := newRejectRPCEnv(t)
	ctx := context.Background()
	d := proposePending(t, e, 4)
	admin := readRPCClient(t, e.svc, peercred.RoleAdmin)
	if _, err := admin.ApproveCLI(ctx, &pb.ApproveCLIRequest{ExecutionDigest: d}); err != nil {
		t.Fatal(err)
	}
	_, err := admin.RejectPending(ctx, &pb.RejectPendingRequest{Digest: d})
	wantStatus(t, err, codes.FailedPrecondition, permit.CodeAlreadyApproved)
	_, err = admin.RejectPending(ctx, &pb.RejectPendingRequest{Digest: strings.Repeat("ab", 32)})
	wantStatus(t, err, codes.NotFound, permit.CodeNotFound)
}
