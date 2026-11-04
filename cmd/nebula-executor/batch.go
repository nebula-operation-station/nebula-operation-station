// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"slices"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit/batch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// batchConfig is what the executor's batch authority is built from; every
// field comes from the executor's own configuration and state.
type batchConfig struct {
	Mode     permit.Mode
	Verifier *webauthnverify.Verifier
	// Risk is the authority's risk policy (NewExecutorRiskPolicy) and
	// Source its executor-held data; the batch policy reuses both.
	Risk   permit.RiskPolicy
	Source riskpolicy.Source
	Store  permit.Store
	// Session is the privileged session of the single-action authority.
	Session func() (bool, time.Time)
	// AdminUIDs are the local admins who may review and approve batches
	// with `nebula approve` (batchAdminUIDs).
	AdminUIDs []uint32
	Audit     func(permit.Event)
}

// setupBatchAuthority builds the batch approval authority (ADR 0007 E19b)
// with the executor's production batch policy, wires it into svc, so the
// batch RPCs, including GetBatchCredentialVersions, are served, and wires
// the production batch dispatcher (EnableBatchExecution, E11), so approved
// members run through RunBatchMember and batch execution is advertised.
// The caller locks the returned authority on shutdown; Service.Lock locks
// it with the keyring.
func setupBatchAuthority(svc *executor.Service, c batchConfig) (*batch.Authority, error) {
	pol, err := executor.NewBatchPolicy(svc, c.Risk, c.Source)
	if err != nil {
		return nil, err
	}
	a, err := batch.New(batch.Options{
		Mode: c.Mode, Verifier: c.Verifier, Policy: pol, Session: c.Session,
		AdminUIDs: c.AdminUIDs, Audit: c.Audit, Store: c.Store,
	})
	if err != nil {
		return nil, fmt.Errorf("batch authority: %w", err)
	}
	svc.SetBatchAuthority(a)
	if err := svc.EnableBatchExecution(); err != nil {
		return nil, fmt.Errorf("batch execution: %w", err)
	}
	return a, nil
}

// batchAdminUIDs are the local admin UIDs that may review and approve
// batches with `nebula approve`: every UID the role table (resolveRoles)
// gives the admin role, the same peers the role check admits to
// ReviewBatch and ApproveBatchCLI. Without one, no peer can approve
// locally (browser approval still works). Sorted for a stable order.
func batchAdminUIDs(roles map[uint32][]peercred.Role) []uint32 {
	var out []uint32
	for uid, rs := range roles {
		if slices.Contains(rs, peercred.RoleAdmin) {
			out = append(out, uid)
		}
	}
	slices.Sort(out)
	return out
}
