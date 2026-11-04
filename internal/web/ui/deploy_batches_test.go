// SPDX-License-Identifier: AGPL-3.0-or-later

package ui_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// probedBatches is a DeployBatches with the optional DeployBatchProbe and a
// switchable proposal error.
type probedBatches struct {
	*fakeDeployBatches
	mu         sync.Mutex
	available  bool
	probeErr   error
	probes     int
	proposeErr error
}

func (p *probedBatches) BatchesAvailable(context.Context) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.probes++
	return p.available, p.probeErr
}

func (p *probedBatches) ProposeBatch(ctx context.Context, user string, req executions.BatchRequest) (executions.BatchCreated, error) {
	p.mu.Lock()
	err := p.proposeErr
	p.mu.Unlock()
	if err != nil {
		return executions.BatchCreated{}, err
	}
	return p.fakeDeployBatches.ProposeBatch(ctx, user, req)
}

func newProbedDPEnv(t *testing.T, available bool, probeErr error) (*dpEnv, *probedBatches) {
	t.Helper()
	p := &probedBatches{available: available, probeErr: probeErr}
	e := newDPEnvWith(t, func(o *ui.Options) {
		p.fakeDeployBatches = o.DeployBatches.(*fakeDeployBatches)
		o.DeployBatches = p
	})
	return e, p
}

// With batches available on the executor, a run with bootstrap modules and
// runbooks goes to bootstrapping and its staged plan is proposed and run
// instead of ending at "joined".
func TestDeployWithBatchesRunsTheStagedPlan(t *testing.T) {
	e, p := newProbedDPEnv(t, true, nil)
	id, run := e.toBootstrapping(t)
	body := e.waitState(t, run, "bootstrapping")
	if !strings.Contains(body, `action="/deployments/plan"`) || strings.Contains(body, "bootstrap steps not available") {
		t.Fatalf("bootstrapping page does not offer the plan: %s", body)
	}
	if p.probes != 1 {
		t.Errorf("probes = %d, want 1", p.probes)
	}
	e.proposePlan(t, id, "batch-1")
	if len(e.batches.requests) != 1 || len(e.batches.requests[0].Stages) == 0 {
		t.Fatalf("staged plan = %+v", e.batches.requests)
	}
	e.batches.set("approved", executions.BatchCounts{Total: len(e.batches.requests[0].Stages), Success: len(e.batches.requests[0].Stages)})
	e.waitState(t, run, "done")
}

// An executor without the capability (no batch execution, no batch
// authority, or no credential-version read) keeps "joined" as the fallback, with a reason.
func TestDeployExecutorWithoutBatchesEndsAtJoined(t *testing.T) {
	e, _ := newProbedDPEnv(t, false, nil)
	_, run := e.toBootstrapping(t)
	body := e.waitState(t, run, "joined")
	for _, want := range []string{"the executor does not run batches", `id="deploy-no-batches"`, "Bootstrapping (not available)"} {
		if !strings.Contains(body, want) {
			t.Errorf("joined page lacks %q", want)
		}
	}
	if strings.Contains(body, `action="/deployments/plan"`) {
		t.Error("a joined run offers a plan proposal")
	}
	if len(e.batches.requests) != 0 {
		t.Error("a plan was proposed")
	}
}

// A failed probe is transient: the run waits in bootstrapping. Proposing
// the plan probes again: while the probe fails nothing is proposed, and
// once the executor reports batch execution the plan is proposed.
func TestDeployBatchProbeErrorKeepsBootstrapping(t *testing.T) {
	e, p := newProbedDPEnv(t, false, errors.New("probe batch support: unavailable"))
	id, run := e.toBootstrapping(t)
	e.waitState(t, run, "bootstrapping")
	code, body, _ := e.do(t, http.MethodPost, "/deployments/plan", gpFormCT, url.Values{"id": {id}}.Encode())
	if code != http.StatusConflict || !strings.Contains(body, "whether it runs batches") {
		t.Fatalf("plan while the probe fails = %d %q", code, body)
	}
	if len(e.batches.requests) != 0 {
		t.Fatal("a plan was proposed while the probe failed")
	}
	e.waitState(t, run, "bootstrapping")
	p.mu.Lock()
	p.available, p.probeErr = true, nil
	p.mu.Unlock()
	e.proposePlan(t, id, "batch-1")
}

// A run left in bootstrapping by a failed probe ends at "joined" when the
// executor then answers that it does not run batches: no plan is proposed,
// so no batch is approved that would never run.
func TestDeployPlanProbeWithoutExecutionEndsAtJoined(t *testing.T) {
	e, p := newProbedDPEnv(t, false, errors.New("probe batch support: unavailable"))
	id, run := e.toBootstrapping(t)
	e.waitState(t, run, "bootstrapping")
	p.mu.Lock()
	p.probeErr = nil
	p.mu.Unlock()
	code, body, _ := e.do(t, http.MethodPost, "/deployments/plan", gpFormCT, url.Values{"id": {id}}.Encode())
	if code != http.StatusConflict || !strings.Contains(body, "bootstrap steps not available") {
		t.Fatalf("plan = %d %q", code, body)
	}
	if len(e.batches.requests) != 0 {
		t.Fatal("a plan was proposed to an executor that does not run batches")
	}
	page := e.waitState(t, run, "joined")
	if !strings.Contains(page, "the executor does not run batches") || strings.Contains(page, `action="/deployments/plan"`) {
		t.Errorf("joined page = %s", page)
	}
}

// A proposal without credential versions (locked keyring) proposes
// nothing, says why and can be proposed again.
func TestDeployPlanCredentialErrorCanBeRetried(t *testing.T) {
	e, p := newProbedDPEnv(t, true, nil)
	id, run := e.toBootstrapping(t)
	p.mu.Lock()
	p.proposeErr = fmt.Errorf("member m-001: %w", executions.ErrBatchCredentials)
	p.mu.Unlock()
	code, body, _ := e.do(t, http.MethodPost, "/deployments/plan", gpFormCT, url.Values{"id": {id}}.Encode())
	if code != http.StatusConflict || !strings.Contains(body, "credential versions could not be read") {
		t.Fatalf("plan = %d %q", code, body)
	}
	if page := e.waitState(t, run, "bootstrapping"); !strings.Contains(page, "is the executor unlocked?") {
		t.Error("the run page does not explain the credential failure")
	}
	p.mu.Lock()
	p.proposeErr = nil
	p.mu.Unlock()
	e.proposePlan(t, id, "batch-1")
}
