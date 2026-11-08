// SPDX-License-Identifier: AGPL-3.0-or-later

package batch

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
)

var (
	// ErrContainerCritical refuses a container update or rollback whose risk
	// reaches CRITICAL. ADR 0006 has no CRITICAL container variant: there is
	// no separate approval path and the floor is never lowered.
	ErrContainerCritical = errors.New("CRITICAL container update or rollback is refused")
	// ErrContainerRiskBelowFloor refuses a container member whose proposed
	// risk class is below the floor its binding implies (a tag change
	// labelled MEDIUM).
	ErrContainerRiskBelowFloor = errors.New("container member risk class is below its binding's floor")
	// ErrContainerPolicy refuses a tag change that the executor's tag policy
	// does not confirm: another policy version or digest, a wrong
	// major_change, a variant change or tags that cannot be compared.
	ErrContainerPolicy = errors.New("container tag change does not match the executor's tag policy")
	// ErrContainerUnsupported refuses a binding whose executor-side checks
	// do not exist yet: standalone definitions (cu05) and private registry
	// transfer (cu06). A public compose rollback (cu03) is admitted: the
	// executor checks it against its recreation row before anything runs.
	ErrContainerUnsupported = errors.New("container update form is not supported yet")
)

// ContainerRefusal names the member a container rule refused. It unwraps to
// one of the ErrContainer* sentinels.
type ContainerRefusal struct {
	MemberID string
	Err      error
}

func (e *ContainerRefusal) Error() string {
	return fmt.Sprintf("batch member %s: %v", e.MemberID, e.Err)
}

// Unwrap permits errors.Is with the ErrContainer* sentinels.
func (e *ContainerRefusal) Unwrap() error { return e.Err }

// TagComparison is the executor's verdict for one tag change under its own
// policy for the repository.
type TagComparison struct {
	PolicyVersion string
	PolicyDigest  string
	MajorChange   bool
}

// TagPolicy compares tags under the executor's own tag policy (registrymeta
// in production, Q13). CompareTags must return an error for tags that cannot
// be compared and for a variant change; both are refusals (R8).
type TagPolicy interface {
	CompareTags(repository, oldTag, newTag string) (TagComparison, error)
}

func refuse(m canonical.BatchMember, err error) error {
	return &ContainerRefusal{MemberID: m.MemberID, Err: err}
}

// containerSnapshot applies the container rules to a policy snapshot: the
// risk is at least the binding's floor, CRITICAL is refused, every tag change
// of an update must match the executor's tag policy, and the policy verdicts
// go into the trust digest so a policy changed after approval fails
// revalidation. A rollback selects no new version: its tag policy is the
// recorded update's, which the executor compares together with the rest of
// the binding against its recreation row (window, baseline, recovery plan)
// before the rollback is dispatched, instead of running CompareTags.
func (a *Authority) containerSnapshot(m canonical.BatchMember, s Snapshot) (Snapshot, error) {
	u := m.ContainerUpdate
	rollback := u.Kind == canonical.ContainerUpdateKindRollback
	switch {
	case u.Kind != canonical.ContainerUpdateKindUpdate && !rollback:
		return Snapshot{}, refuse(m, fmt.Errorf("%w: kind %q", ErrContainerUnsupported, u.Kind))
	case u.Form != canonical.ContainerUpdateFormCompose:
		return Snapshot{}, refuse(m, fmt.Errorf("%w: standalone definitions arrive with cu05", ErrContainerUnsupported))
	case u.Registry != nil:
		return Snapshot{}, refuse(m, fmt.Errorf("%w: private registry transfer arrives with cu06", ErrContainerUnsupported))
	}
	risk := canonical.MaxRisk(s.Risk, canonical.ContainerUpdateFloor(*u))
	if risk == canonical.RiskCritical {
		return Snapshot{}, refuse(m, ErrContainerCritical)
	}
	h := sha256.New()
	field(h, "nebula-batch-container-trust-v1")
	h.Write(s.Trust[:])
	for _, img := range u.Images {
		if img.OldTag == img.NewTag || rollback {
			continue
		}
		if a.options.TagPolicy == nil {
			return Snapshot{}, refuse(m, fmt.Errorf("%w: no executor tag policy", ErrContainerPolicy))
		}
		c, err := a.options.TagPolicy.CompareTags(img.Repository, img.OldTag, img.NewTag)
		if err != nil {
			return Snapshot{}, refuse(m, fmt.Errorf("%w: service %q: %w", ErrContainerPolicy, img.Service, err))
		}
		if c.PolicyVersion != img.PolicyVersion || c.PolicyDigest != img.PolicyDigest {
			return Snapshot{}, refuse(m, fmt.Errorf("%w: service %q: policy differs", ErrContainerPolicy, img.Service))
		}
		if c.MajorChange != img.MajorChange {
			return Snapshot{}, refuse(m, fmt.Errorf("%w: service %q: major_change differs", ErrContainerPolicy, img.Service))
		}
		field(h, img.Service)
		field(h, c.PolicyVersion)
		field(h, c.PolicyDigest)
		field(h, fmt.Sprint(c.MajorChange))
	}
	var d canonical.Digest
	copy(d[:], h.Sum(nil))
	return Snapshot{Risk: risk, Trust: d}, nil
}

// field writes one length-prefixed field, so field boundaries are unambiguous.
func field(h hash.Hash, s string) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(s)))
	h.Write(n[:])
	h.Write([]byte(s))
}
