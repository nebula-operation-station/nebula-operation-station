// SPDX-License-Identifier: AGPL-3.0-or-later

package batch

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
)

// fakeStore is an in-memory permit.Store double whose bindings survive
// authority restarts, like the durable executor store.
type fakeStore struct {
	mu    sync.Mutex
	bound map[string]canonical.Digest
	fail  error
}

func newFakeStore() *fakeStore { return &fakeStore{bound: map[string]canonical.Digest{}} }

func (s *fakeStore) setFail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = err
}

func (s *fakeStore) BindExecution(executionID string, d canonical.Digest, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	if _, ok := s.bound[executionID]; ok {
		return permit.ErrExecutionBound
	}
	s.bound[executionID] = d
	return nil
}

func (s *fakeStore) LookupExecution(executionID string) (canonical.Digest, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return canonical.Digest{}, false, s.fail
	}
	d, ok := s.bound[executionID]
	return d, ok, nil
}

func (s *fakeStore) boundCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.bound)
}

// forceBind overwrites a binding; tests use it to simulate a store where an
// execution ID is bound to a foreign digest.
func (s *fakeStore) forceBind(executionID string, d canonical.Digest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bound[executionID] = d
}

// variantPlan rewrites the batch ID, host and execution ID of a proposed
// plan so it is a different batch with a different spent execution ID.
func variantPlan(t *testing.T, raw []byte, batchID, host, execID string) canonical.Batch {
	t.Helper()
	var b canonical.Batch
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	b.BatchID = batchID
	b.Members[0].Request.ResolvedTargets[0].HostID = host
	b.Members[0].Request.ExecutionID = execID
	return b
}

// A proposed batch durably spends every member execution ID, so an
// unapproved, expired or abandoned proposal can never reissue them.
func TestProposedBatchSpendsExecutionIDs(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	propose(t, e, canonical.RiskMedium) // pending, never approved
	if e.store.boundCount() != 1 {
		t.Fatalf("proposed batch bound %d execution IDs, want 1", e.store.boundCount())
	}
	raw, in := e.plan(t, canonical.RiskLow)
	b := variantPlan(t, raw, "00000000-0000-4000-8000-000000000002", "host-9", "00000000-0000-4000-8000-000000000010")
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.a.Propose(ctx, raw, in)
	wantCode(t, err, permit.CodeExecutionIDReused)
}

// Without a durable store the authority cannot guarantee single-use
// execution IDs, so proposing and claiming both fail closed.
func TestStoreRequiredFailsClosed(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	o := e.options
	o.Store = nil
	a, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	e.a = a
	raw, in := e.plan(t, canonical.RiskLow)
	_, err = e.a.Propose(ctx, raw, in)
	wantCode(t, err, permit.CodeStorage)
}

// Two concurrent claims of the same member: exactly one succeeds, the
// permit is retrievable, and a sequential re-claim is refused.
func TestClaimMemberSingleUseConcurrent(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	p := propose(t, e, canonical.RiskLow, canonical.RiskLow) // auto-approved
	member := p.Plan.Members[0]
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.a.ClaimMember(ctx, p.Digest, 0, member)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	succeeded, failed := 0, 0
	for err := range results {
		if err == nil {
			succeeded++
			continue
		}
		failed++
		wantCode(t, err, permit.CodeWrongState)
	}
	if succeeded != 1 || failed != 1 {
		t.Fatalf("claims succeeded=%d failed=%d, want 1/1", succeeded, failed)
	}
	mp, ok := e.a.Member(p.Digest, "member-0")
	if !ok {
		t.Fatal("claimed member permit not retrievable")
	}
	if mp.ParentDigest != p.Digest || mp.Index != 0 || mp.Member.MemberID != "member-0" {
		t.Fatalf("permit bindings wrong: %+v", mp)
	}
	_, err := e.a.ClaimMember(ctx, p.Digest, 0, member)
	wantCode(t, err, permit.CodeWrongState)
}

// Any candidate member that differs in any field from the frozen plan
// member is a substitution and is refused without claiming.
func TestClaimMemberSubstitutionRejected(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	p := propose(t, e, canonical.RiskLow)
	original := p.Plan.Members[0]
	mutate := func(f func(m *canonical.BatchMember)) canonical.BatchMember {
		m := cloneMember(original)
		f(&m)
		return m
	}
	cases := map[string]func(*canonical.BatchMember){
		"action": func(m *canonical.BatchMember) { m.Request.ActionID = "attacker.action" },
		"parameters": func(m *canonical.BatchMember) {
			m.Request.ParametersHash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		},
		"execution": func(m *canonical.BatchMember) { m.Request.ExecutionID = "00000000-0000-4000-8000-0000000000ff" },
		"target":    func(m *canonical.BatchMember) { m.Request.ResolvedTargets[0].HostID = "other-host" },
		"artifact": func(m *canonical.BatchMember) {
			m.Request.ArtifactSHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		},
		"risk":       func(m *canonical.BatchMember) { m.Request.RiskClass = canonical.RiskHigh },
		"credential": func(m *canonical.BatchMember) { m.CredentialVersions[0].Version = 99 },
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := e.a.ClaimMember(ctx, p.Digest, 0, mutate(f))
			wantCode(t, err, permit.CodeInvalidRequest)
			if _, ok := e.a.Member(p.Digest, "member-0"); ok {
				t.Fatal("substituted member was claimed")
			}
		})
	}
	// A member belonging to a different batch is a substitution as well.
	raw, _ := e.plan(t, canonical.RiskLow)
	other := variantPlan(t, raw, "00000000-0000-4000-8000-000000000002", "host-9", "00000000-0000-4000-8000-000000000020")
	_, err := e.a.ClaimMember(ctx, p.Digest, 0, other.Members[0])
	wantCode(t, err, permit.CodeInvalidRequest)
	// An index outside the plan and an unknown parent are refused too.
	_, err = e.a.ClaimMember(ctx, p.Digest, 5, original)
	wantCode(t, err, permit.CodeInvalidRequest)
	_, err = e.a.ClaimMember(ctx, canonical.Digest{}, 0, original)
	wantCode(t, err, permit.CodeNotFound)
}

// A member can only be claimed once its parent is approved.
func TestClaimMemberRequiresApprovedParent(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	p := propose(t, e, canonical.RiskMedium) // pending until asserted
	_, err := e.a.ClaimMember(ctx, p.Digest, 0, p.Plan.Members[0])
	wantCode(t, err, permit.CodeWrongState)
	if _, err := e.a.SubmitAssertion(ctx, p.Digest, e.sign(p.Challenge)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.ClaimMember(ctx, p.Digest, 0, p.Plan.Members[0]); err != nil {
		t.Fatal(err)
	}
}

// A crash (or Lock) revokes every member permit in the process, and the
// spent execution ID is never reissued, not even by a re-proposal of the
// identical batch.
func TestClaimMemberCrashRevocation(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	p := propose(t, e, canonical.RiskLow)
	member := p.Plan.Members[0]
	if _, err := e.a.ClaimMember(ctx, p.Digest, 0, member); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.a.Member(p.Digest, "member-0"); !ok {
		t.Fatal("claimed permit not visible before crash")
	}
	// Crash: the in-memory authority is gone; the durable store survives.
	restarted, err := New(e.options)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := restarted.Member(p.Digest, "member-0"); ok {
		t.Fatal("crashed member permit survived restart")
	}
	_, err = restarted.ClaimMember(ctx, p.Digest, 0, member)
	wantCode(t, err, permit.CodeNotFound)
	// The spent execution ID is never reissued.
	raw, in := e.plan(t, canonical.RiskLow)
	_, err = restarted.Propose(ctx, raw, in)
	wantCode(t, err, permit.CodeExecutionIDReused)
}

// Lock revokes claimed permits within the process; the spent execution ID
// survives the lock.
func TestClaimMemberLockRevokes(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	p := propose(t, e, canonical.RiskLow)
	if _, err := e.a.ClaimMember(ctx, p.Digest, 0, p.Plan.Members[0]); err != nil {
		t.Fatal(err)
	}
	e.a.Lock()
	if _, ok := e.a.Member(p.Digest, "member-0"); ok {
		t.Fatal("lock did not revoke the member permit")
	}
	raw, in := e.plan(t, canonical.RiskLow)
	b := variantPlan(t, raw, "00000000-0000-4000-8000-000000000002", "host-9", "00000000-0000-4000-8000-000000000010")
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.a.Propose(ctx, raw, in)
	wantCode(t, err, permit.CodeExecutionIDReused)
}

// The member permit inherits the parent plan expiry: after it, no permit
// remains and no further member can be claimed.
func TestClaimMemberExpiry(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	p := propose(t, e, canonical.RiskLow, canonical.RiskLow)
	mp, err := e.a.ClaimMember(ctx, p.Digest, 0, p.Plan.Members[0])
	if err != nil {
		t.Fatal(err)
	}
	if !mp.Expiry.Equal(time.Unix(p.Plan.ExpiryUnix, 0)) {
		t.Fatalf("member permit expiry %v differs from plan expiry", mp.Expiry)
	}
	e.unix.Store(p.Plan.ExpiryUnix + 1)
	_, err = e.a.ClaimMember(ctx, p.Digest, 1, p.Plan.Members[1])
	wantCode(t, err, permit.CodeExpired)
	if _, ok := e.a.Member(p.Digest, "member-0"); ok {
		t.Fatal("expired member permit still visible")
	}
}

// A trust or risk change after approval invalidates the whole batch before
// any member can be claimed.
func TestClaimMemberTrustChangeInvalidates(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	p := propose(t, e, canonical.RiskLow, canonical.RiskLow)
	e.policy.set("member-0", Snapshot{Risk: canonical.RiskHigh, Trust: sha256.Sum256([]byte("member-0"))})
	_, err := e.a.ClaimMember(ctx, p.Digest, 0, p.Plan.Members[0])
	if !errors.Is(err, ErrInvalidated) {
		t.Fatalf("claim after trust change: %v", err)
	}
	if _, ok := e.a.Member(p.Digest, "member-0"); ok {
		t.Fatal("invalidated member permit still visible")
	}
	// The batch was revoked permanently: Check now fails, not with a new
	// invalidation but because the entry is gone.
	if _, err := e.a.Check(ctx, p.Digest); err == nil {
		t.Fatal("check after trust change succeeded")
	}
}

// Store failures fail closed without claiming; recovery makes the same
// claim succeed. A binding to a different digest is a reused execution ID.
func TestClaimMemberStoreFailures(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	p := propose(t, e, canonical.RiskLow, canonical.RiskLow)
	member := p.Plan.Members[0]
	e.store.setFail(errors.New("store down"))
	_, err := e.a.ClaimMember(ctx, p.Digest, 0, member)
	wantCode(t, err, permit.CodeStorage)
	if _, ok := e.a.Member(p.Digest, "member-0"); ok {
		t.Fatal("failed claim marked as claimed")
	}
	e.store.setFail(nil)
	if _, err := e.a.ClaimMember(ctx, p.Digest, 0, member); err != nil {
		t.Fatal(err)
	}
	// Member 1's execution ID is bound to a foreign digest.
	foreign := canonical.Digest{1}
	e.store.forceBind(p.Plan.Members[1].Request.ExecutionID, foreign)
	_, err = e.a.ClaimMember(ctx, p.Digest, 1, p.Plan.Members[1])
	wantCode(t, err, permit.CodeExecutionIDReused)
}

// The returned permit is a detached copy bound to the exact approved
// member and parameters.
func TestClaimedMemberPermitBindings(t *testing.T) {
	e := setup(t, permit.ModeStandard)
	p := propose(t, e, canonical.RiskLow)
	mp, err := e.a.ClaimMember(ctx, p.Digest, 0, p.Plan.Members[0])
	if err != nil {
		t.Fatal(err)
	}
	if mp.ParentDigest != p.Digest || mp.Index != 0 || mp.Member.MemberID != "member-0" {
		t.Fatalf("permit bindings wrong: %+v", mp)
	}
	if !bytes.Equal(mp.Parameters, p.Parameters[0]) {
		t.Fatal("permit parameters differ from approved parameters")
	}
	if !reflect.DeepEqual(mp.Member, p.Plan.Members[0]) {
		t.Fatal("permit member differs from approved member")
	}
	mp.Parameters[0] = 'x'
	mp.Member.Request.ActionID = "mutated"
	got, ok := e.a.Member(p.Digest, "member-0")
	if !ok {
		t.Fatal("permit gone after mutation")
	}
	if !bytes.Equal(got.Parameters, p.Parameters[0]) || got.Member.Request.ActionID != "package.upgrade" {
		t.Fatal("mutating a returned permit changed the authority state")
	}
}
