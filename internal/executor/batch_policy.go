// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit/batch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
)

// errBatchProviderMember refuses provider members: the production batch
// policy has no provider trust to evaluate yet, so it fails closed.
var errBatchProviderMember = errors.New("batch: provider members are not supported by the executor batch policy")

// BatchPolicy is the executor's production batch.Policy (ADR 0007 E19b):
// the member's risk floor is the authority's own risk policy over executor
// data (never the proposed RiskClass), and its trust digest covers the
// artifact trust entry, the criticality records of the exact target and the
// credential versions the member binds. Every credential version is
// compared with the key the executor holds now, so a key rotated after
// planning fails the proposal, the approval and every member revalidation
// (ErrCredentialRotated). Unavailable state is an error (fail closed).
type BatchPolicy struct {
	svc  *Service
	risk permit.RiskPolicy
	src  riskpolicy.Source
}

var _ batch.Policy = (*BatchPolicy)(nil)

// NewBatchPolicy returns the batch policy over the service's keyring, the
// authority's risk policy (NewExecutorRiskPolicy in production) and its
// source (the executor database).
func NewBatchPolicy(svc *Service, risk permit.RiskPolicy, src riskpolicy.Source) (*BatchPolicy, error) {
	if svc == nil || risk == nil || src == nil {
		return nil, errors.New("executor: batch policy needs the service, a risk policy and a risk source")
	}
	return &BatchPolicy{svc: svc, risk: risk, src: src}, nil
}

// Evaluate implements batch.Policy.
func (p *BatchPolicy) Evaluate(ctx context.Context, m canonical.BatchMember) (batch.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return batch.Snapshot{}, err
	}
	if m.ProviderTarget != nil {
		return batch.Snapshot{}, errBatchProviderMember
	}
	if len(m.Request.ResolvedTargets) != 1 {
		return batch.Snapshot{}, errors.New("batch: member must have exactly one target")
	}
	if err := p.svc.checkMemberCredentials("policy", m); err != nil {
		return batch.Snapshot{}, err
	}
	floor, _, err := p.risk.MinimumRisk(m.Request, m.Request.ResolvedTargets)
	if err != nil {
		return batch.Snapshot{}, fmt.Errorf("batch: risk floor: %w", err)
	}
	declared, trusted, err := p.src.ArtifactRisk(m.Request.ArtifactSHA256, m.Request.ActionID, m.Request.ModuleVersion)
	if err != nil {
		return batch.Snapshot{}, fmt.Errorf("batch: artifact trust: %w", err)
	}
	h := sha256.New()
	writeField(h, "nebula-batch-trust-v1")
	writeField(h, m.Request.ArtifactSHA256)
	writeField(h, m.Request.ActionID)
	writeField(h, m.Request.ModuleVersion)
	writeField(h, fmt.Sprint(trusted))
	writeField(h, string(declared))
	writeField(h, string(floor))
	for _, t := range m.Request.ResolvedTargets {
		c, exact, err := p.src.HostCriticality(t.HostID, t.HostKeyFingerprint)
		if err != nil {
			return batch.Snapshot{}, fmt.Errorf("batch: host criticality: %w", err)
		}
		writeField(h, t.HostID)
		writeField(h, t.HostKeyFingerprint)
		writeField(h, string(c))
		writeField(h, fmt.Sprint(exact))
	}
	for _, v := range m.CredentialVersions {
		writeField(h, v.Reference)
		writeField(h, fmt.Sprint(v.Version))
	}
	var d canonical.Digest
	copy(d[:], h.Sum(nil))
	return batch.Snapshot{Risk: floor, Trust: d}, nil
}

// writeField writes one length-prefixed field, so field boundaries are
// unambiguous.
func writeField(h hash.Hash, s string) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(s)))
	h.Write(n[:])
	h.Write([]byte(s))
}
