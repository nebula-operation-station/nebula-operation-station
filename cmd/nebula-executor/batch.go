// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit/batch"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// noBatchAdminUID is the batch admin UID when no admin user is configured:
// (uid_t)-1 is never a real peer, so no local CLI approval matches it.
const noBatchAdminUID = math.MaxUint32

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
	Session  func() (bool, time.Time)
	AdminUID uint32
	Audit    func(permit.Event)
}

// setupBatchAuthority builds the batch approval authority (ADR 0007 E19b)
// with the executor's production batch policy and wires it into svc, so the
// batch RPCs, including GetBatchCredentialVersions, are served. The caller
// locks the returned authority on shutdown; Service.Lock locks it with the
// keyring.
func setupBatchAuthority(svc *executor.Service, c batchConfig) (*batch.Authority, error) {
	pol, err := executor.NewBatchPolicy(svc, c.Risk, c.Source)
	if err != nil {
		return nil, err
	}
	a, err := batch.New(batch.Options{
		Mode: c.Mode, Verifier: c.Verifier, Policy: pol, Session: c.Session,
		AdminUID: c.AdminUID, Audit: c.Audit, Store: c.Store,
	})
	if err != nil {
		return nil, fmt.Errorf("batch authority: %w", err)
	}
	svc.SetBatchAuthority(a)
	return a, nil
}

// batchAdminUID is the local admin UID that may review and approve batches
// with `nebula approve`: the first configured admin user. Without one, no
// peer can approve locally (browser approval still works).
func batchAdminUID(adminUsers string) (uint32, error) {
	for _, name := range strings.Split(adminUsers, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		uid, err := peercred.LookupUID(name)
		if err != nil {
			return 0, fmt.Errorf("admin user %q: %w", name, err)
		}
		return uid, nil
	}
	return noBatchAdminUID, nil
}
