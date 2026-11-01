// SPDX-License-Identifier: AGPL-3.0-or-later

package batch

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
)

// MemberPermit is the single-use dispatch authorization for exactly one
// approved batch member. It is bound to the parent digest, the member's plan
// index and the exact frozen member request, and it carries no credentials.
// It exists only in the claiming process: Lock, expiry, invalidation and a
// restart revoke it, while the durable execution ID binding outlives it, so
// the member can never be re-dispatched. Returned permits are detached
// copies; mutating them cannot change authority state.
type MemberPermit struct {
	ParentDigest canonical.Digest
	Index        int
	Member       canonical.BatchMember
	Parameters   []byte
	Expiry       time.Time
}

// ExecutionID returns the member's single-use execution ID.
func (m MemberPermit) ExecutionID() string { return m.Member.Request.ExecutionID }

func (m *MemberPermit) clone() MemberPermit {
	c := *m
	c.Member = cloneMember(m.Member)
	c.Parameters = slices.Clone(m.Parameters)
	return c
}

// memberKey namespaces a claimed member by its approved parent and member ID.
func memberKey(parent canonical.Digest, memberID string) string {
	return parent.String() + "\x00" + memberID
}

// ClaimMember authorizes exactly one member of an approved batch for
// dispatch. The candidate must byte-match the frozen member at index, the
// parent must be approved, unexpired and still matching its trust snapshot,
// and the member's execution ID must be durably bound to the parent digest.
// The permit is single-use: a second claim of the same member fails, and the
// spent execution ID is never reissued, even after a restart or re-proposal.
func (a *Authority) ClaimMember(ctx context.Context, parent canonical.Digest, index int, member canonical.BatchMember) (MemberPermit, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, err := a.getLocked(parent, permit.StateApproved)
	if err != nil {
		return MemberPermit{}, err
	}
	if err := a.freshLocked(ctx, parent, e, permit.StateApproved); err != nil {
		return MemberPermit{}, err
	}
	plan := e.approval.Plan
	if index < 0 || index >= len(plan.Members) {
		return MemberPermit{}, failure(permit.CodeInvalidRequest, "member index outside the approved plan")
	}
	if err := canonical.VerifyBatchMember(plan, parent, index, member, a.options.Now()); err != nil {
		return MemberPermit{}, failure(permit.CodeInvalidRequest, "member differs from the approved plan")
	}
	frozen := plan.Members[index]
	key := memberKey(parent, frozen.MemberID)
	if _, ok := a.members[key]; ok {
		return MemberPermit{}, failure(permit.CodeWrongState, "member already claimed")
	}
	if a.options.Store == nil {
		return MemberPermit{}, failure(permit.CodeStorage, "execution ID store unavailable")
	}
	bound, ok, err := a.options.Store.LookupExecution(frozen.Request.ExecutionID)
	if err != nil {
		return MemberPermit{}, failure(permit.CodeStorage, "execution ID store unavailable")
	}
	if !ok || bound != parent {
		return MemberPermit{}, failure(permit.CodeExecutionIDReused, "member execution ID is not bound to this batch")
	}
	mp := &MemberPermit{
		ParentDigest: parent,
		Index:        index,
		Member:       cloneMember(frozen),
		Parameters:   slices.Clone(e.approval.Parameters[index]),
		Expiry:       time.Unix(plan.ExpiryUnix, 0),
	}
	a.members[key] = mp
	a.emit("member_claimed", parent, "", frozen.MemberID)
	return mp.clone(), nil
}

// Member returns the claimed permit for one member, or ok=false when the
// member was never claimed, or the claim was revoked by Lock, expiry,
// invalidation or a restart.
func (a *Authority) Member(parent canonical.Digest, memberID string) (MemberPermit, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.gcLocked()
	key := memberKey(parent, memberID)
	mp, ok := a.members[key]
	if !ok || !a.options.Now().Before(mp.Expiry) {
		delete(a.members, key)
		return MemberPermit{}, false
	}
	return mp.clone(), true
}

// bindExecutionIDs durably spends every member execution ID of the plan,
// bound to the parent digest. The caller holds a.mu, so no other proposal
// of this authority interleaves; a store failure part-way leaves the
// earlier IDs spent, which only ever fails closed.
func (a *Authority) bindExecutionIDs(plan canonical.Batch, digest canonical.Digest, expiry time.Time) error {
	if a.options.Store == nil {
		return failure(permit.CodeStorage, "execution ID store unavailable")
	}
	// Check every ID first, so a plan that reuses one ID spends none.
	for _, m := range plan.Members {
		if _, ok, err := a.options.Store.LookupExecution(m.Request.ExecutionID); err != nil {
			return failure(permit.CodeStorage, "execution ID store unavailable")
		} else if ok {
			return failure(permit.CodeExecutionIDReused, "execution ID already spent")
		}
	}
	for _, m := range plan.Members {
		if err := a.options.Store.BindExecution(m.Request.ExecutionID, digest, expiry); err != nil {
			if errors.Is(err, permit.ErrExecutionBound) {
				return failure(permit.CodeExecutionIDReused, "execution ID already spent")
			}
			return failure(permit.CodeStorage, "execution ID store unavailable")
		}
	}
	return nil
}
