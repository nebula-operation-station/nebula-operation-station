// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executor/dispatch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/keyring"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit/batch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// randomSSHKey returns a fresh ed25519 SSH public key and its private key.
func randomSSHKey(t *testing.T) (ssh.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k, priv
}

// rotatedTestKeyring is an unlocked keyring whose "cred" reference holds a
// new key: the credential was rotated.
func rotatedTestKeyring(t *testing.T) (*keyring.Keyring, ssh.PublicKey) {
	t.Helper()
	pub, priv := randomSSHKey(t)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "rotated", []byte(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	kr, err := unlockTestKeyring(t.TempDir(), pem.EncodeToMemory(block))
	if err != nil {
		t.Fatal(err)
	}
	return kr, pub
}

// rebindCredentialVersion rewrites the version every member of the proposal
// binds for "cred".
func rebindCredentialVersion(t *testing.T, req *pb.ProposeBatchRequest, version uint64) {
	t.Helper()
	var b canonical.Batch
	if err := json.Unmarshal(req.GetBatchJson(), &b); err != nil {
		t.Fatal(err)
	}
	for i := range b.Members {
		b.Members[i].CredentialVersions = []canonical.CredentialVersion{{Reference: "cred", Version: version}}
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	req.BatchJson = raw
}

// Real keys: every CredentialVersionOf value is a valid canonical batch
// integer and survives canonicalization and parsing exactly. The unmasked
// 64-bit prefix the first version used is rejected by the canonical batch
// for most keys, which is what this test guards against.
func TestCredentialVersionOfFitsCanonicalBatches(t *testing.T) {
	env := newBatchRPCEnv(t, uint32(os.Getuid()))
	var base canonical.Batch
	if err := json.Unmarshal(env.plan(t, canonical.RiskLow).GetBatchJson(), &base); err != nil {
		t.Fatal(err)
	}
	now := env.clock.Now()
	wide := 0
	for range 64 {
		k, _ := randomSSHKey(t)
		v := CredentialVersionOf(k)
		sum := sha256.Sum256(k.Marshal())
		prefix := binary.BigEndian.Uint64(sum[:8])
		if v == 0 || v > canonical.MaxCredentialVersion || (prefix&canonical.MaxCredentialVersion != 0 && v != prefix&canonical.MaxCredentialVersion) {
			t.Fatalf("version %d of prefix %#x", v, prefix)
		}
		b := base
		b.Members = append([]canonical.BatchMember(nil), base.Members...)
		b.Members[0].CredentialVersions = []canonical.CredentialVersion{{Reference: "cred", Version: v}}
		_, canon, _, err := canonical.CanonicalizeBatch(b, now)
		if err != nil {
			t.Fatalf("canonicalize version %d: %v", v, err)
		}
		parsed, _, _, err := canonical.ParseBatch(canon, now)
		if err != nil || parsed.Members[0].CredentialVersions[0].Version != v {
			t.Fatalf("parse version %d: %v", v, err)
		}
		if prefix > canonical.MaxCredentialVersion {
			wide++
			b.Members[0].CredentialVersions[0].Version = prefix
			if _, _, _, err := canonical.CanonicalizeBatch(b, now); err == nil {
				t.Fatalf("canonical batch took the unmasked version %#x", prefix)
			}
		}
	}
	if wide == 0 {
		t.Fatal("no key had a prefix above 2^53-1; the test proves nothing")
	}
}

// The version read through the RPC is the one the executor accepts in a
// proposal; a version of another key is refused before the authority and
// audited with versions only.
func TestProposeBatchRefusesRotatedCredential(t *testing.T) {
	env := newBatchRPCEnv(t, uint32(os.Getuid()))
	ctx := context.Background()
	resp, err := env.svc.GetBatchCredentialVersions(ctx, &pb.GetBatchCredentialVersionsRequest{CredentialRefs: []string{"cred"}})
	if err != nil {
		t.Fatal(err)
	}
	read := resp.GetVersions()[0].GetVersion()

	stale := env.plan(t, canonical.RiskLow)
	rebindCredentialVersion(t, stale, read^1)
	if _, err := env.svc.ProposeBatch(ctx, stale); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("rotated propose: %v", err)
	}
	if recs := env.logs.find("batch_credential_rotated", ""); len(recs) != 1 || recs[0].attrs["at"] != "propose" ||
		recs[0].attrs["credential_ref"] != "cred" {
		t.Fatalf("audit = %+v", recs)
	}

	fresh := env.plan(t, canonical.RiskLow)
	rebindCredentialVersion(t, fresh, read)
	if _, err := env.svc.ProposeBatch(ctx, fresh); err != nil {
		t.Fatalf("propose with the read version: %v", err)
	}
}

// productionBatchAuthority replaces env's fake policy with the executor's
// production BatchPolicy over the real risk policy and executor.db.
func (e *batchRPCEnv) productionBatchAuthority(t *testing.T) *batch.Authority {
	t.Helper()
	risk, err := riskpolicy.New(e.db)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := NewBatchPolicy(e.svc, risk, e.db)
	if err != nil {
		t.Fatal(err)
	}
	a, err := batch.New(batch.Options{
		Mode: permit.ModeStandard, Verifier: e.verifier, Policy: pol, AdminUIDs: e.adminUIDs, Now: e.clock.Now, Store: e.db,
		Session: func() (bool, time.Time) { return true, e.clock.Now().Add(time.Hour) },
	})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.SetBatchAuthority(a)
	return a
}

// memRecorder is an in-memory dispatch.Recorder.
type memRecorder struct {
	mu       sync.Mutex
	outcomes map[string]dispatch.Outcome
}

func (r *memRecorder) RecordIntent(_ context.Context, run dispatch.Run) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.outcomes[run.ExecutionID]; ok {
		return dispatch.ErrIntentRecorded
	}
	r.outcomes[run.ExecutionID] = ""
	return nil
}

func (r *memRecorder) RecordOutcome(_ context.Context, run dispatch.Run, o dispatch.Outcome) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.outcomes[run.ExecutionID] = o
	return nil
}

// approvedClaimedMember proposes a one-member HIGH plan through the
// production authority, approves it locally as the admin and claims the
// member.
func approvedClaimedMember(t *testing.T, env *batchRPCEnv, a *batch.Authority) (canonical.Digest, canonical.BatchMember) {
	t.Helper()
	ctx := context.Background()
	prop, err := env.svc.ProposeBatch(ctx, env.plan(t, canonical.RiskHigh))
	if err != nil {
		t.Fatal(err)
	}
	admin := readRPCClient(t, env.svc, peercred.RoleAdmin)
	if _, err := admin.ApproveBatchCLI(ctx, &pb.ApproveBatchCLIRequest{BatchDigest: prop.GetBatchDigest()}); err != nil {
		t.Fatal(err)
	}
	plan, _, d, err := canonical.ParseBatch(prop.GetCanonicalBatch(), env.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.ClaimMember(ctx, d, 0, plan.Members[0]); err != nil {
		t.Fatal(err)
	}
	return d, plan.Members[0]
}

// The production policy and dispatcher: an unchanged key dispatches; a key
// rotated between approval and dispatch stops the member before the
// transport (fail closed), audited without key material.
func TestBatchCredentialRotationBetweenApproveAndDispatch(t *testing.T) {
	for _, rotate := range []bool{false, true} {
		name := map[bool]string{false: "unchanged", true: "rotated"}[rotate]
		t.Run(name, func(t *testing.T) {
			env := newBatchRPCEnv(t, uint32(os.Getuid()))
			env.usePrivateKeyring()
			a := env.productionBatchAuthority(t)
			d, member := approvedClaimedMember(t, env, a)
			if member.CredentialVersions[0].Version != CredentialVersionOf(env.userPub) {
				t.Fatalf("bound version %d", member.CredentialVersions[0].Version)
			}
			var calls atomic.Int32
			rec := &memRecorder{outcomes: map[string]dispatch.Outcome{}}
			disp, err := dispatch.New(dispatch.Options{Permits: a, Recorder: rec, Credentials: env.svc.CredentialVersion,
				Transport: func(context.Context, dispatch.Run) (dispatch.Outcome, error) {
					calls.Add(1)
					return dispatch.OutcomeSuccess, nil
				}})
			if err != nil {
				t.Fatal(err)
			}
			if rotate {
				kr, pub := rotatedTestKeyring(t)
				if CredentialVersionOf(pub) == member.CredentialVersions[0].Version {
					t.Fatal("rotated key has the same version")
				}
				env.svc.keys = kr
			}
			out, err := disp.Dispatch(context.Background(), d, member.MemberID)
			if !rotate {
				if err != nil || out != dispatch.OutcomeSuccess || calls.Load() != 1 {
					t.Fatalf("dispatch = %v %v, %d calls", out, err, calls.Load())
				}
				return
			}
			if err == nil || out != dispatch.OutcomeNotExecuted || calls.Load() != 0 {
				t.Fatalf("rotated dispatch = %v %v, %d calls", out, err, calls.Load())
			}
			if rec.outcomes[member.Request.ExecutionID] != dispatch.OutcomeNotExecuted {
				t.Errorf("recorded outcome = %q", rec.outcomes[member.Request.ExecutionID])
			}
			recs := env.logs.find("batch_credential_rotated", member.Request.ExecutionID)
			if len(recs) == 0 {
				t.Fatal("rotation not audited")
			}
			for _, r := range recs {
				for k, v := range r.attrs {
					if s, ok := v.(string); ok && (len(s) > 200 || k == "key") {
						t.Errorf("audit attr %s=%q", k, s)
					}
				}
			}
		})
	}
}

// The production policy refuses provider members (no provider trust yet),
// a locked keyring and a rotated key, and derives the risk floor itself.
func TestBatchPolicyEvaluate(t *testing.T) {
	env := newBatchRPCEnv(t, uint32(os.Getuid()))
	env.usePrivateKeyring()
	risk, err := riskpolicy.New(env.db)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewBatchPolicy(nil, risk, env.db); err == nil {
		t.Error("policy without a service")
	}
	pol, err := NewBatchPolicy(env.svc, risk, env.db)
	if err != nil {
		t.Fatal(err)
	}
	var b canonical.Batch
	if err := json.Unmarshal(env.plan(t, canonical.RiskLow).GetBatchJson(), &b); err != nil {
		t.Fatal(err)
	}
	m := b.Members[0]
	ctx := context.Background()
	snap, err := pol.Evaluate(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	// An untrusted artifact on an unrecorded host is HIGH, whatever the
	// proposal says.
	if snap.Risk != canonical.RiskHigh || snap.Trust == (canonical.Digest{}) {
		t.Errorf("snapshot = %+v", snap)
	}
	again, err := pol.Evaluate(ctx, m)
	if err != nil || again != snap {
		t.Errorf("snapshot not stable: %+v %v", again, err)
	}
	provider := m
	provider.ProviderTarget = &canonical.BatchProviderTarget{}
	if _, err := pol.Evaluate(ctx, provider); err == nil {
		t.Error("provider member evaluated")
	}
	env.svc.keys, _ = rotatedTestKeyring(t)
	if _, err := pol.Evaluate(ctx, m); !errors.Is(err, ErrCredentialRotated) {
		t.Errorf("rotated key: %v", err)
	}
	env.svc.keys.Lock()
	if _, err := pol.Evaluate(ctx, m); !errors.Is(err, keyring.ErrLocked) {
		t.Errorf("locked keyring: %v", err)
	}
}

// Locking the executor revokes batch approvals and claimed member permits
// together with the keyring (spec 05).
func TestServiceLockRevokesBatchAuthority(t *testing.T) {
	env := newBatchRPCEnv(t, uint32(os.Getuid()))
	env.usePrivateKeyring()
	a := env.productionBatchAuthority(t)
	d, member := approvedClaimedMember(t, env, a)
	if _, ok := a.Member(d, member.MemberID); !ok {
		t.Fatal("member not claimed")
	}
	if _, err := env.svc.Lock(context.Background(), &pb.LockRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Member(d, member.MemberID); ok {
		t.Error("claimed member permit survived Lock")
	}
}
