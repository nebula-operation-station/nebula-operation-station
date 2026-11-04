// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/ui"
)

// Run deadlines, address release and batch outcomes of deployment runs
// (PV-08 review fixes). Every test drives the handler's clock.

const dpAddr = "192.168.10.50"

// addressFree reports whether the run's address can be reserved again
// (and gives it back at once).
func (e *dpEnv) addressFree(t *testing.T) bool {
	t.Helper()
	ad := netip.MustParseAddr(dpAddr)
	if _, err := e.ipam.Reserve(context.Background(), "probe", "lan", "servers", ad, "probe"); err != nil {
		return false
	}
	if err := e.ipam.ClearEntry(context.Background(), ad); err != nil {
		t.Fatal(err)
	}
	return true
}

func dhcpForm(name string) url.Values {
	f := dpForm()
	f.Set("name", name)
	f.Set("ip_mode", "dhcp")
	f.Del("network")
	f.Del("pool")
	f.Del("address")
	return f
}

func TestDeployExpiredProposalStopsCountingAndReleasesItsAddress(t *testing.T) {
	e := newDPEnv(t)
	run := e.propose(t, dpForm())
	if e.addressFree(t) {
		t.Fatal("the proposal holds no reservation")
	}
	// The executor's bound request expires after five minutes.
	e.advance(6 * time.Minute)
	body := e.waitState(t, run, "failed")
	for _, want := range []string{"Proposed (failed)", "expired unapproved", "nothing was created"} {
		if !strings.Contains(body, want) {
			t.Errorf("expired proposal page lacks %q", want)
		}
	}
	if !e.addressFree(t) {
		t.Error("the reservation of an expired proposal is kept")
	}
	id := strings.TrimPrefix(run, "/deployments/")
	if code, _, _ := e.do(t, http.MethodPost, "/deployments/approve", "application/json", approveJSON(id)); code != http.StatusNotFound {
		t.Errorf("approval of an expired proposal = %d", code)
	}
	// After the TTL the settled run is pruned.
	e.advance(25 * time.Hour)
	if code, _, _ := e.do(t, http.MethodGet, run, "", ""); code != http.StatusNotFound {
		t.Errorf("expired run still shown after its TTL: %d", code)
	}
}

func TestDeployUserCapCountsOnlyLiveRuns(t *testing.T) {
	e := newDPEnv(t)
	for i := range 16 {
		e.propose(t, dhcpForm("web"+string(rune('a'+i))))
		e.advance(3 * time.Second) // past the propose throttle
	}
	code, body, _ := e.do(t, http.MethodPost, "/deployments/propose", gpFormCT, dhcpForm("webz").Encode())
	if code != http.StatusTooManyRequests || !strings.Contains(body, "too many unfinished") {
		t.Fatalf("17th proposal = %d %q", code, body)
	}
	// Once the abandoned proposals have expired they no longer count.
	e.advance(6 * time.Minute)
	e.propose(t, dhcpForm("webz"))
}

func TestDeployRefusedCommitReleasesTheAddress(t *testing.T) {
	e := newDPEnv(t)
	e.prov.commitErr = status.Error(codes.InvalidArgument, "pve guest provision: invalid or unsupported spec")
	run := e.propose(t, dpForm())
	id := strings.TrimPrefix(run, "/deployments/")
	if code, body, _ := e.do(t, http.MethodPost, "/deployments/approve", "application/json", approveJSON(id)); code != http.StatusOK {
		t.Fatalf("approve = %d %q", code, body)
	}
	e.waitState(t, run, "failed")
	deadline := time.Now().Add(3 * time.Second)
	for !e.addressFree(t) {
		if time.Now().After(deadline) {
			t.Fatal("the reservation of a refused commit is kept")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestDeployAmbiguousRefusalKeepsTheAddress: PermissionDenied (also the
// permit already used by an earlier run, or final) and FailedPrecondition
// (also the VMID now existing) do not prove that no run of the execution
// created the guest, so the address stays reserved, in key mode and in CLI
// mode, also after the proposal of a CLI run expires.
func TestDeployAmbiguousRefusalKeepsTheAddress(t *testing.T) {
	for _, tc := range []struct {
		name string
		cli  bool
		err  error
	}{
		{"key already run", false, status.Error(codes.PermissionDenied, "pve guest provision: no approved permit covers this provisioning")},
		{"key vmid exists", false, status.Error(codes.FailedPrecondition, "pve guest provision: the vmid is in use or not reserved for this execution")},
		{"cli already run", true, status.Error(codes.PermissionDenied, "pve guest provision: no approved permit covers this provisioning")},
		{"cli vmid exists", true, status.Error(codes.FailedPrecondition, "pve guest provision: the vmid is in use or not reserved for this execution")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newDPEnv(t)
			if tc.cli {
				e.prov.requirement = pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY
			}
			e.prov.commitErr = tc.err
			run := e.propose(t, dpForm())
			id := strings.TrimPrefix(run, "/deployments/")
			var body string
			if tc.cli {
				if code, _, _ := e.do(t, http.MethodPost, "/deployments/run", gpFormCT, url.Values{"id": {id}}.Encode()); code != http.StatusSeeOther {
					t.Fatalf("run = %d", code)
				}
				body = e.waitState(t, run, "proposed")
			} else {
				if code, b, _ := e.do(t, http.MethodPost, "/deployments/approve", "application/json", approveJSON(id)); code != http.StatusOK {
					t.Fatalf("approve = %d %q", code, b)
				}
				body = e.waitState(t, run, "failed")
			}
			if !strings.Contains(body, "stays reserved because an earlier run of this execution may have created the guest") {
				t.Errorf("refused run does not say the address is kept: %s", body)
			}
			if e.addressFree(t) {
				t.Fatal("the address was released after an ambiguous refusal")
			}
			if tc.cli {
				// The proposal of the reset run expires: still kept.
				e.advance(6 * time.Minute)
				body = e.waitState(t, run, "failed")
				if !strings.Contains(body, "the address stays reserved") || strings.Contains(body, "nothing was created") {
					t.Errorf("expired CLI run after a refusal: %s", body)
				}
				if e.addressFree(t) {
					t.Fatal("the expiry released the address of a refused CLI run")
				}
			}
			e.advance(25 * time.Hour)
			e.do(t, http.MethodGet, "/deployments", "", "")
			if e.addressFree(t) {
				t.Error("the address was released after the TTL")
			}
		})
	}
}

// flakyIPAM fails ClearEntry while fail is set.
type flakyIPAM struct {
	*ipam.Store
	mu    sync.Mutex
	fail  bool
	calls int
}

func (f *flakyIPAM) ClearEntry(ctx context.Context, ad netip.Addr) error {
	f.mu.Lock()
	f.calls++
	fail := f.fail
	f.mu.Unlock()
	if fail {
		return errors.New("database is locked")
	}
	return f.Store.ClearEntry(ctx, ad)
}

func (f *flakyIPAM) set(fail bool) (calls int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = fail
	return f.calls
}

// TestDeployFailedReleaseIsRetried: a ClearEntry that fails leaves the
// release pending; the run is not pruned past its TTL, and the next
// settle (any deployment page) clears the reservation.
func TestDeployFailedReleaseIsRetried(t *testing.T) {
	var fl *flakyIPAM
	e := newDPEnvWith(t, func(o *ui.Options) {
		fl = &flakyIPAM{Store: o.DeployIPAM.(*ipam.Store), fail: true}
		o.DeployIPAM = fl
	})
	e.prov.commitErr = status.Error(codes.InvalidArgument, "pve guest provision: invalid or unsupported spec")
	run := e.propose(t, dpForm())
	id := strings.TrimPrefix(run, "/deployments/")
	if code, body, _ := e.do(t, http.MethodPost, "/deployments/approve", "application/json", approveJSON(id)); code != http.StatusOK {
		t.Fatalf("approve = %d %q", code, body)
	}
	e.waitState(t, run, "failed")
	deadline := time.Now().Add(3 * time.Second)
	for fl.set(true) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no release was attempted")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e.addressFree(t) {
		t.Fatal("the address is free although ClearEntry failed")
	}
	// Past the TTL the run waits for its release instead of being pruned.
	e.advance(25 * time.Hour)
	before := fl.set(true)
	if code, _, _ := e.do(t, http.MethodGet, run, "", ""); code != http.StatusOK {
		t.Fatalf("run with a pending release pruned: %d", code)
	}
	if fl.set(true) <= before {
		t.Error("the failed release was not retried")
	}
	if e.addressFree(t) {
		t.Fatal("the address is free although ClearEntry failed again")
	}
	// Once ClearEntry works the retry clears it, and the run is pruned.
	fl.set(false)
	e.do(t, http.MethodGet, "/deployments", "", "")
	if !e.addressFree(t) {
		t.Fatal("the retried release did not clear the reservation")
	}
	if code, _, _ := e.do(t, http.MethodGet, run, "", ""); code != http.StatusNotFound {
		t.Errorf("released run still shown after its TTL: %d", code)
	}
}

func TestDeployUnknownCommitOutcomeKeepsTheAddress(t *testing.T) {
	e := newDPEnv(t)
	e.prov.commitErr = status.Error(codes.Unavailable, "connection reset")
	run := e.propose(t, dpForm())
	id := strings.TrimPrefix(run, "/deployments/")
	if code, body, _ := e.do(t, http.MethodPost, "/deployments/approve", "application/json", approveJSON(id)); code != http.StatusOK {
		t.Fatalf("approve = %d %q", code, body)
	}
	body := e.waitState(t, run, "failed")
	if !strings.Contains(body, "stays reserved because the guest may exist") {
		t.Errorf("unknown outcome does not say the address is kept: %s", body)
	}
	e.advance(25 * time.Hour)
	e.do(t, http.MethodGet, "/deployments", "", "")
	if e.addressFree(t) {
		t.Error("the address of a guest that may exist was released")
	}
}

func TestDeployFailedProvisioningKeepsTheAddress(t *testing.T) {
	e := newDPEnv(t)
	e.prov.failStep = true
	run := e.propose(t, dpForm())
	id := strings.TrimPrefix(run, "/deployments/")
	if code, _, _ := e.do(t, http.MethodPost, "/deployments/approve", "application/json", approveJSON(id)); code != http.StatusOK {
		t.Fatal("approve")
	}
	if body := e.waitState(t, run, "failed"); !strings.Contains(body, "stays reserved") {
		t.Errorf("failed provisioning does not say the address is kept")
	}
	if e.addressFree(t) {
		t.Error("the address of a created guest was released")
	}
}

func TestDeployIdleRunsFailAtTheirDeadline(t *testing.T) {
	t.Run("booting", func(t *testing.T) {
		e := newDPEnv(t)
		run := e.propose(t, dpForm())
		id := strings.TrimPrefix(run, "/deployments/")
		if code, _, _ := e.do(t, http.MethodPost, "/deployments/approve", "application/json", approveJSON(id)); code != http.StatusOK {
			t.Fatal("approve")
		}
		e.waitState(t, run, "booting")
		e.advance(5 * time.Hour)
		e.waitState(t, run, "booting")
		e.advance(2 * time.Hour)
		body := e.waitState(t, run, "failed")
		if !strings.Contains(body, "Booting (failed)") || !strings.Contains(body, "not enrolled within") {
			t.Errorf("expired booting run lacks its reason: %s", body)
		}
		if e.addressFree(t) {
			t.Error("the address of a created guest was released")
		}
		if code, _, _ := e.do(t, http.MethodPost, "/deployments/join", gpFormCT, url.Values{"id": {id}}.Encode()); code != http.StatusNotFound {
			t.Errorf("enrollment of an expired run = %d", code)
		}
	})
	t.Run("enrolling", func(t *testing.T) {
		e := newDPEnv(t)
		id, run := e.toEnrolling(t)
		e.advance(7 * time.Hour)
		if body := e.waitState(t, run, "failed"); !strings.Contains(body, "Enrolling (failed)") {
			t.Errorf("expired enrolling run: %s", body)
		}
		if code, _, _ := e.do(t, http.MethodPost, "/deployments/join/approve", "application/json", approveJSON(id)); code != http.StatusNotFound {
			t.Errorf("approval of an expired enrollment = %d", code)
		}
	})
	t.Run("bootstrapping", func(t *testing.T) {
		e := newDPEnv(t)
		_, run := e.toBootstrapping(t)
		e.advance(25 * time.Hour)
		if body := e.waitState(t, run, "failed"); !strings.Contains(body, "Bootstrapping (failed)") || !strings.Contains(body, "did not finish within") {
			t.Errorf("expired bootstrapping run: %s", body)
		}
	})
}

// toBootstrapping runs a deployment up to the committed enrollment.
func (e *dpEnv) toBootstrapping(t *testing.T) (string, string) {
	t.Helper()
	id, run := e.toEnrolling(t)
	if code, body, _ := e.do(t, http.MethodPost, "/deployments/join/approve", "application/json", approveJSON(id)); code != http.StatusOK {
		t.Fatalf("join approve = %d %q", code, body)
	}
	return id, run
}

func (e *dpEnv) proposePlan(t *testing.T, id, want string) {
	t.Helper()
	if code, body, loc := e.do(t, http.MethodPost, "/deployments/plan", gpFormCT, url.Values{"id": {id}}.Encode()); code != http.StatusSeeOther || loc != "/batches/"+want {
		t.Fatalf("plan = %d %q -> %q", code, body, loc)
	}
}

func TestDeployRefusedOrExpiredBatchCanBeProposedAgain(t *testing.T) {
	for _, tc := range []struct {
		name   string
		state  string
		counts executions.BatchCounts
		expiry time.Duration
	}{
		{"refused", "refused", executions.BatchCounts{Total: 3, Planned: 3}, 0},
		{"expired and swept", "expired", executions.BatchCounts{Total: 3, NotExecuted: 3}, 0},
		{"pending past its expiry", "pending", executions.BatchCounts{Total: 3, Planned: 3}, time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newDPEnv(t)
			id, run := e.toBootstrapping(t)
			e.proposePlan(t, id, "batch-1")
			if tc.expiry > 0 {
				e.batches.mu.Lock()
				e.batches.expiry = e.now().Add(tc.expiry)
				e.batches.mu.Unlock()
				e.batches.set(tc.state, tc.counts)
				// Within the expiry and its grace nothing changes.
				if body := e.waitState(t, run, "bootstrapping"); !strings.Contains(body, "/batches/batch-1") {
					t.Fatal("a pending batch was detached early")
				}
				e.advance(tc.expiry + 6*time.Minute)
			} else {
				e.batches.set(tc.state, tc.counts)
			}
			body := e.waitState(t, run, "bootstrapping")
			if !strings.Contains(body, "before any step ran: nothing was executed") || !strings.Contains(body, `action="/deployments/plan"`) {
				t.Fatalf("an ended batch does not offer the plan again: %s", body)
			}
			e.batches.set("pending", executions.BatchCounts{Total: 3, Planned: 3})
			e.proposePlan(t, id, "batch-2")
			e.batches.set("approved", executions.BatchCounts{Total: 3, Success: 3})
			e.waitState(t, run, "done")
		})
	}
}

func TestDeployBatchFailureEndsTheRun(t *testing.T) {
	for _, tc := range []struct {
		name, state, want string
		counts            executions.BatchCounts
	}{
		{"member failed", "approved", "Bootstrapping (failed)", executions.BatchCounts{Total: 3, Success: 1, Failed: 1, NotExecuted: 1}},
		{"ended after a step ran", "expired", "after some steps ran", executions.BatchCounts{Total: 3, Success: 1, Planned: 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newDPEnv(t)
			id, run := e.toBootstrapping(t)
			e.proposePlan(t, id, "batch-1")
			e.batches.set(tc.state, tc.counts)
			if body := e.waitState(t, run, "failed"); !strings.Contains(body, tc.want) {
				t.Errorf("failed run lacks %q: %s", tc.want, body)
			}
			if code, _, _ := e.do(t, http.MethodPost, "/deployments/plan", gpFormCT, url.Values{"id": {id}}.Encode()); code != http.StatusNotFound {
				t.Errorf("plan of a failed run = %d", code)
			}
		})
	}
	t.Run("dispatched member keeps the run open", func(t *testing.T) {
		e := newDPEnv(t)
		id, run := e.toBootstrapping(t)
		e.proposePlan(t, id, "batch-1")
		e.batches.set("expired", executions.BatchCounts{Total: 3, Dispatched: 1, Planned: 2})
		if body := e.waitState(t, run, "bootstrapping"); !strings.Contains(body, "/batches/batch-1") {
			t.Error("a batch with a dispatched member was decided")
		}
	})
}

func TestDeployWithoutBatchPlannerEndsAtJoined(t *testing.T) {
	e := newDPEnvWith(t, func(o *ui.Options) { o.DeployBatches = nil })
	_, run := e.toBootstrapping(t)
	body := e.waitState(t, run, "joined")
	for _, want := range []string{"bootstrap steps not available", `id="deploy-no-batches"`, "Bootstrapping (not available)", `id="deploy-pinned">` + dpFingerprint} {
		if !strings.Contains(body, want) {
			t.Errorf("joined page lacks %q", want)
		}
	}
	if strings.Contains(body, `action="/deployments/plan"`) {
		t.Error("a joined run offers a plan proposal")
	}
}

func TestDeploySaveAsProfileOnlyAfterTheProposal(t *testing.T) {
	e := newDPEnv(t)
	e.prov.proposeErr = status.Error(codes.FailedPrecondition, "pve guest provision: the template is not prepared or changed; prepare it again")
	f := dpForm()
	f.Del("profile")
	f.Del("profile_version")
	f.Set("save_as", "adhoc_web")
	if code, body, _ := e.do(t, http.MethodPost, "/deployments/propose", gpFormCT, f.Encode()); code != http.StatusConflict {
		t.Fatalf("propose = %d %q", code, body)
	}
	if code, _, _ := e.do(t, http.MethodGet, "/deploy/adhoc_web", "", ""); code != http.StatusNotFound {
		t.Errorf("a refused deployment saved its profile: %d", code)
	}
	e.prov.proposeErr = nil
	e.advance(3 * time.Second)
	run := e.propose(t, f)
	if _, body, _ := e.do(t, http.MethodGet, run, "", ""); !strings.Contains(body, `href="/deploy/adhoc_web?version=1"`) {
		t.Error("the proposed deployment does not show its saved profile")
	}
}

func TestDeployDHCPEndpointMustBeUnicast(t *testing.T) {
	e := newDPEnv(t)
	run := e.propose(t, dhcpForm("web1"))
	id := strings.TrimPrefix(run, "/deployments/")
	if code, _, _ := e.do(t, http.MethodPost, "/deployments/approve", "application/json", approveJSON(id)); code != http.StatusOK {
		t.Fatal("approve")
	}
	e.waitState(t, run, "booting")
	e.observe(t, dpGuest(dpVMID, "web1", pvecontract.GuestRunning))
	for _, ep := range []string{"127.0.0.1", "0.0.0.0", "::", "224.0.0.1", "169.254.1.2", "fe80::1", "255.255.255.255", "::ffff:127.0.0.1"} {
		code, body, _ := e.do(t, http.MethodPost, "/deployments/join", gpFormCT, url.Values{"id": {id}, "endpoint": {ep}}.Encode())
		if code != http.StatusBadRequest || !strings.Contains(body, "unicast") {
			t.Errorf("endpoint %s = %d %q", ep, code, body)
		}
	}
	if len(e.join.proposed) != 0 {
		t.Error("an unusable endpoint reached the executor")
	}
	if code, body, _ := e.do(t, http.MethodPost, "/deployments/join", gpFormCT, url.Values{"id": {id}, "endpoint": {"192.168.10.77"}}.Encode()); code != http.StatusSeeOther {
		t.Errorf("unicast endpoint = %d %q", code, body)
	}
}
