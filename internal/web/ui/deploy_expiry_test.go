// SPDX-License-Identifier: AGPL-3.0-or-later
package ui_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/canonical"
	"github.com/nebula-operation-station/nebula-operation-station/internal/deployprofile"
	"github.com/nebula-operation-station/nebula-operation-station/internal/executions"
	"github.com/nebula-operation-station/nebula-operation-station/internal/ipam"
	"github.com/nebula-operation-station/nebula-operation-station/internal/pvecontract"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/middleware"
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

// TestDeployExpiredProposalStopsCountingAndKeepsItsAddress: the executor
// cannot tell whether an execution was committed out of band before its
// permit expired (GetPermitState answers "no live permit" for consumed and
// expired alike), so the expiry never releases the address: it stays
// reserved and the page says it may be in use.
func TestDeployExpiredProposalStopsCountingAndKeepsItsAddress(t *testing.T) {
	e := newDPEnv(t)
	run := e.propose(t, dpForm())
	if e.addressFree(t) {
		t.Fatal("the proposal holds no reservation")
	}
	// The executor's bound request expires after five minutes.
	e.advance(6 * time.Minute)
	body := e.waitState(t, run, "failed")
	for _, want := range []string{"Proposed (failed)", "expired without a run from this page", "may be in use", dpAddr,
		"VMID " + strconv.Itoa(dpVMID)} {
		if !strings.Contains(body, want) {
			t.Errorf("expired proposal page lacks %q", want)
		}
	}
	if strings.Contains(body, "nothing was created") {
		t.Error("the expired proposal claims nothing was created")
	}
	if e.addressFree(t) {
		t.Error("the expiry released the address of a proposal that may have been committed out of band")
	}
	id := strings.TrimPrefix(run, "/deployments/")
	if code, _, _ := e.do(t, http.MethodPost, "/deployments/approve", "application/json", approveJSON(id)); code != http.StatusNotFound {
		t.Errorf("approval of an expired proposal = %d", code)
	}
	// After the TTL the settled run is pruned; the reservation stays.
	e.advance(25 * time.Hour)
	if code, _, _ := e.do(t, http.MethodGet, run, "", ""); code != http.StatusNotFound {
		t.Errorf("expired run still shown after its TTL: %d", code)
	}
	if e.addressFree(t) {
		t.Error("pruning the expired run released its address")
	}
}

// TestDeployOutOfBandCommitKeepsTheAddressOnExpiry: a CLI-mode proposal is
// approved and committed outside the web UI (the admin role may call
// CommitPVEGuestProvision) and never run from the page. When its proposal
// expires on the page, the guest exists and uses the address: it must stay
// reserved.
func TestDeployOutOfBandCommitKeepsTheAddressOnExpiry(t *testing.T) {
	e := newDPEnv(t)
	e.prov.requirement = pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY
	run := e.propose(t, dpForm())
	spec := e.prov.proposed[0]
	// `nebula approve` and a commit by the admin, out of band.
	resp, err := e.prov.CommitPVEGuestProvision(context.Background(), &pb.CommitPVEGuestProvisionRequest{Spec: spec, ExecutionId: dpExec})
	if err != nil || len(resp.GetSteps()) == 0 {
		t.Fatalf("out-of-band commit = %v, %v", resp, err)
	}
	e.advance(6 * time.Minute)
	body := e.waitState(t, run, "failed")
	if !strings.Contains(body, "may be in use") {
		t.Errorf("expired CLI proposal does not say the address may be in use: %s", body)
	}
	for range 3 {
		e.do(t, http.MethodGet, "/deployments", "", "")
		e.do(t, http.MethodGet, "/deployments/new", "", "")
	}
	if e.addressFree(t) {
		t.Fatal("the expiry released the address of a guest committed out of band")
	}
	e.advance(25 * time.Hour)
	e.do(t, http.MethodGet, "/deployments", "", "")
	if e.addressFree(t) {
		t.Error("the address of a guest committed out of band was released after the TTL")
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

// TestDeployAmbiguousRefusalKeepsTheAddress: no refusal of the commit
// proves that no run of the execution (another commit, for example with the
// CLI) created the guest. InvalidArgument is not only request validation
// (the executor also wraps automation key lookup errors in it and sends one
// fixed text for every cause), PermissionDenied also means the permit was
// already used or is final, FailedPrecondition also means the VMID now
// exists, NotFound a remote or key removed after a run, Aborted a
// concurrent change. The address stays reserved, in key mode and in CLI
// mode, also after the proposal of a reset CLI run expires.
func TestDeployAmbiguousRefusalKeepsTheAddress(t *testing.T) {
	invalid := status.Error(codes.InvalidArgument, "pve guest provision: invalid or unsupported spec, template, network, key or password id")
	used := status.Error(codes.PermissionDenied, "pve guest provision: no approved permit covers this provisioning")
	vmid := status.Error(codes.FailedPrecondition, "pve guest provision: the vmid is in use or not reserved for this execution")
	gone := status.Error(codes.NotFound, "pve guest provision: the NOS automation credential is not in the keyring")
	aborted := status.Error(codes.Aborted, "pve guest provision: concurrent change")
	for _, tc := range []struct {
		name string
		cli  bool
		err  error
		// reset: the CLI run goes back to proposed (approve, run again).
		reset bool
	}{
		{"key invalid", false, invalid, false},
		{"key already run", false, used, false},
		{"key vmid exists", false, vmid, false},
		{"key not found", false, gone, false},
		{"key aborted", false, aborted, false},
		{"cli invalid", true, invalid, false},
		{"cli already run", true, used, true},
		{"cli vmid exists", true, vmid, true},
		{"cli not found", true, gone, false},
		{"cli aborted", true, aborted, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newDPEnv(t)
			if tc.cli {
				e.prov.requirement = pb.ApprovalRequirement_APPROVAL_REQUIREMENT_CLI_ONLY
			}
			e.prov.commitErr = tc.err
			run := e.propose(t, dpForm())
			id := strings.TrimPrefix(run, "/deployments/")
			want := "failed"
			if tc.reset {
				want = "proposed"
			}
			if tc.cli {
				if code, _, _ := e.do(t, http.MethodPost, "/deployments/run", gpFormCT, url.Values{"id": {id}}.Encode()); code != http.StatusSeeOther {
					t.Fatalf("run = %d", code)
				}
			} else if code, b, _ := e.do(t, http.MethodPost, "/deployments/approve", "application/json", approveJSON(id)); code != http.StatusOK {
				t.Fatalf("approve = %d %q", code, b)
			}
			body := e.waitState(t, run, want)
			if !strings.Contains(body, "stays reserved because an earlier run of this execution may have created the guest") {
				t.Errorf("refused run does not say the address is kept: %s", body)
			}
			if e.addressFree(t) {
				t.Fatal("the address was released after a refused commit")
			}
			if tc.reset {
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

// TestDeploySettleNeverClearsAnAddress: settling (every deployment page and
// form) never calls ClearEntry, so no page request waits on the IPAM store
// and a failing store is never retried per request. Refused, expired and
// pruned runs leave their reservation for the operator to clear on the
// network page once no guest uses it.
func TestDeploySettleNeverClearsAnAddress(t *testing.T) {
	var fl *flakyIPAM
	e := newDPEnvWith(t, func(o *ui.Options) {
		fl = &flakyIPAM{Store: o.DeployIPAM.(*ipam.Store), fail: true}
		o.DeployIPAM = fl
	})
	e.prov.commitErr = status.Error(codes.InvalidArgument, "pve guest provision: invalid or unsupported spec, template, network, key or password id")
	refused := e.propose(t, dpForm())
	id := strings.TrimPrefix(refused, "/deployments/")
	if code, body, _ := e.do(t, http.MethodPost, "/deployments/approve", "application/json", approveJSON(id)); code != http.StatusOK {
		t.Fatalf("approve = %d %q", code, body)
	}
	e.waitState(t, refused, "failed")
	e.advance(3 * time.Second) // past the propose throttle
	f := dhcpForm("web2")
	expired := e.propose(t, f)
	e.advance(6 * time.Minute)
	e.waitState(t, expired, "failed")
	for range 5 {
		e.do(t, http.MethodGet, "/deployments", "", "")
		e.do(t, http.MethodGet, "/deployments/new", "", "")
		e.do(t, http.MethodGet, refused, "", "")
	}
	e.advance(25 * time.Hour)
	e.do(t, http.MethodGet, "/deployments", "", "")
	if n := fl.set(false); n != 0 {
		t.Errorf("settling called ClearEntry %d times", n)
	}
	if e.addressFree(t) {
		t.Error("an address was released by settling")
	}
}

// brokenDigestProvision answers with a permit whose digest does not match
// its bound request: the executor holds a live permit, the page refuses it.
type brokenDigestProvision struct{ *fakeProvision }

func (b brokenDigestProvision) ProposePVEGuestProvision(ctx context.Context, in *pb.ProposePVEGuestProvisionRequest, opts ...grpc.CallOption) (*pb.ProposePVEGuestProvisionResponse, error) {
	resp, err := b.fakeProvision.ProposePVEGuestProvision(ctx, in, opts...)
	if err == nil {
		resp.GetPermit().ExecutionDigest = strings.Repeat("0", 64)
	}
	return resp, err
}

// TestDeployProposeKeepsTheAddressWhenAPermitMayExist: the wizard releases
// the address only when the executor refused the proposal (it then holds no
// permit). When the outcome of the call is unknown, or the executor
// answered with a permit the page cannot use, an admin may still approve
// and commit that execution out of band, so the address stays reserved.
func TestDeployProposeKeepsTheAddressWhenAPermitMayExist(t *testing.T) {
	t.Run("unknown outcome", func(t *testing.T) {
		e := newDPEnv(t)
		e.prov.proposeErr = status.Error(codes.Unavailable, "connection reset")
		code, body, _ := e.do(t, http.MethodPost, "/deployments/propose", gpFormCT, dpForm().Encode())
		if code < 400 || !strings.Contains(body, "stays reserved") {
			t.Errorf("propose = %d %q", code, body)
		}
		if e.addressFree(t) {
			t.Error("the address was released although the executor may hold a permit")
		}
	})
	t.Run("unusable permit", func(t *testing.T) {
		prov := &fakeProvision{risk: canonical.RiskHigh, requirement: pb.ApprovalRequirement_APPROVAL_REQUIREMENT_ASSERTION_VERIFIED}
		e := newDPEnvWith(t, func(o *ui.Options) { o.Deploy = brokenDigestProvision{prov} })
		code, body, _ := e.do(t, http.MethodPost, "/deployments/propose", gpFormCT, dpForm().Encode())
		if code != http.StatusBadGateway || !strings.Contains(body, "stays reserved") {
			t.Errorf("propose = %d %q", code, body)
		}
		if e.addressFree(t) {
			t.Error("the address was released although the executor holds a permit")
		}
	})
	t.Run("other refusal", func(t *testing.T) {
		// Shown as the executor's refusal, but only the spec refusal
		// proves that no permit exists.
		e := newDPEnv(t)
		e.prov.proposeErr = status.Error(codes.FailedPrecondition, "pve guest provision: the template is not prepared or changed; prepare it again")
		code, body, _ := e.do(t, http.MethodPost, "/deployments/propose", gpFormCT, dpForm().Encode())
		if code != http.StatusConflict || !strings.Contains(body, "the executor refused: pve guest provision: the template is not prepared") || !strings.Contains(body, "stays reserved") {
			t.Errorf("propose = %d %q", code, body)
		}
		if e.addressFree(t) {
			t.Error("the address was released after a refusal that does not prove the absence of a permit")
		}
	})
	t.Run("spec refusal", func(t *testing.T) {
		e := newDPEnv(t)
		e.prov.proposeErr = status.Error(codes.InvalidArgument, "pve guest provision: invalid or unsupported spec, template, network, key or password id")
		if code, body, _ := e.do(t, http.MethodPost, "/deployments/propose", gpFormCT, dpForm().Encode()); code != http.StatusConflict {
			t.Errorf("propose = %d %q", code, body)
		}
		if !e.addressFree(t) {
			t.Error("the reservation of a refused proposal is kept")
		}
	})
}

// TestDeployProposeKeptAuditRecordsReasonRemoteAndVmid: the propose-time
// deployment_address_kept audit entry records the path that kept the
// reservation (reason), the remote, the VMID (0 before the executor
// answered with one) and the user, so the owner of a left-behind
// reservation can be found in the log.
func TestDeployProposeKeptAuditRecordsReasonRemoteAndVmid(t *testing.T) {
	e := newDPEnv(t)
	e.prov.proposeErr = status.Error(codes.Unavailable, "connection reset")
	code, body, _ := e.do(t, http.MethodPost, "/deployments/propose", gpFormCT, dpForm().Encode())
	if code != http.StatusBadGateway || !strings.Contains(body, "stays reserved") {
		t.Fatalf("propose = %d %q", code, body)
	}
	audit := e.logBuf.String()
	for _, want := range []string{"kind=deployment_address_kept", "reason=unknown_outcome", "address=" + dpAddr,
		"remote=" + dpRemote, "vmid=0", "user=unknown", "execution="} {
		if !strings.Contains(audit, want) {
			t.Errorf("audit log lacks %q: %s", want, audit)
		}
	}
}

// TestDeployProposeWithoutChallengeKeepsTheAddress: a key requirement
// without request options gives the page nothing to approve, so it
// refuses the proposal; the executor still holds a permit for the
// execution, so the reserved address stays.
func TestDeployProposeWithoutChallengeKeepsTheAddress(t *testing.T) {
	e := newDPEnv(t)
	e.prov.noOptions = true
	code, body, _ := e.do(t, http.MethodPost, "/deployments/propose", gpFormCT, dpForm().Encode())
	if code != http.StatusBadGateway || !strings.Contains(body, "no approval challenge") || !strings.Contains(body, "stays reserved") {
		t.Fatalf("propose = %d %q", code, body)
	}
	if e.addressFree(t) {
		t.Error("the address was released although the executor holds a permit")
	}
}

// TestDeployProposeProfileSaveFailureKeepsTheAddress: saving the ad-hoc
// profile after a usable proposal can fail (invalid profile, store
// error); the proposal is refused, but the executor holds a permit for
// the execution, so the reserved address stays.
func TestDeployProposeProfileSaveFailureKeepsTheAddress(t *testing.T) {
	t.Run("invalid profile", func(t *testing.T) {
		e := newDPEnvWith(t, func(o *ui.Options) {
			o.DeployProfiles = failingDeployProfiles{DeployProfiles: o.DeployProfiles, saveErr: &deployprofile.InvalidError{Err: errors.New("bogus")}}
		})
		f := dpForm()
		f.Del("profile")
		f.Del("profile_version")
		f.Set("save_as", "adhoc_web")
		code, body, _ := e.do(t, http.MethodPost, "/deployments/propose", gpFormCT, f.Encode())
		if code != http.StatusBadRequest || !strings.Contains(body, "the profile could not be saved") || !strings.Contains(body, "stays reserved") {
			t.Fatalf("propose = %d %q", code, body)
		}
		if e.addressFree(t) {
			t.Error("the address was released although the executor holds a permit")
		}
	})
	t.Run("store error", func(t *testing.T) {
		e := newDPEnvWith(t, func(o *ui.Options) {
			o.DeployProfiles = failingDeployProfiles{DeployProfiles: o.DeployProfiles, saveErr: errors.New("database is locked")}
		})
		f := dpForm()
		f.Del("profile")
		f.Del("profile_version")
		f.Set("save_as", "adhoc_web")
		code, body, _ := e.do(t, http.MethodPost, "/deployments/propose", gpFormCT, f.Encode())
		if code != http.StatusInternalServerError || !strings.Contains(body, "the profile could not be saved") || !strings.Contains(body, "stays reserved") {
			t.Fatalf("propose = %d %q", code, body)
		}
		if e.addressFree(t) {
			t.Error("the address was released although the executor holds a permit")
		}
	})
}

// TestDeployProposeRunStoreFullKeepsTheAddress: the run store is full of
// live runs while a proposal is in flight, so the proposal cannot be
// stored; the executor still holds a permit for the execution, so the
// reserved address stays.
func TestDeployProposeRunStoreFullKeepsTheAddress(t *testing.T) {
	e := newDPEnv(t)
	sessions := auth.NewStore(e.db, time.Now)
	a, err := auth.New(auth.Options{Executor: pveFakeExec{}, Sessions: sessions, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(middleware.Handler(middleware.Options{PublicOrigin: gpOrigin}, a.Wrap(e.h)))
	t.Cleanup(srv.Close)
	cookie := make(map[string]*http.Cookie)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for u := range 11 {
		name := fmt.Sprintf("user%d", u+1)
		token, _, err := sessions.Create(context.Background(), "cred-"+name, name)
		if err != nil {
			t.Fatal(err)
		}
		cookie[name] = &http.Cookie{Name: auth.CookieName, Value: token}
	}
	do := func(name, ct, body string) (int, string, error) {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/deployments/propose", strings.NewReader(body))
		if err != nil {
			return 0, "", err
		}
		req.AddCookie(cookie[name])
		req.Header.Set("Origin", gpOrigin)
		req.Header.Set("Content-Type", ct)
		resp, err := client.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		b := new(bytes.Buffer)
		if _, err := b.ReadFrom(resp.Body); err != nil {
			return 0, "", err
		}
		return resp.StatusCode, b.String(), nil
	}
	must := func(name, ct, body string) (int, string) {
		t.Helper()
		code, body, err := do(name, ct, body)
		if err != nil {
			t.Fatalf("%s propose: %v", name, err)
		}
		return code, body
	}
	// 127 live runs: user1..user8 with 15 each, user9 with 7.
	for round := range 15 {
		if round > 0 {
			e.advance(3 * time.Second) // past the propose throttle
		}
		for u := range 8 {
			name := fmt.Sprintf("user%d", u+1)
			if code, body := must(name, gpFormCT, dhcpForm(fmt.Sprintf("fill%d-%d", u+1, round)).Encode()); code != http.StatusSeeOther {
				t.Fatalf("%s fill propose = %d %q", name, code, body)
			}
		}
		if round < 7 {
			if code, body := must("user9", gpFormCT, dhcpForm(fmt.Sprintf("fill9-%d", round)).Encode()); code != http.StatusSeeOther {
				t.Fatalf("user9 fill propose = %d %q", code, body)
			}
		}
	}
	e.prov.holdIPAM = make(chan struct{})
	e.prov.holdIPAMStarted = make(chan struct{})
	xres := make(chan struct {
		code int
		body string
	})
	go func() {
		code, body, err := do("user10", gpFormCT, dpForm().Encode())
		if err != nil {
			xres <- struct {
				code int
				body string
			}{0, err.Error()}
			return
		}
		xres <- struct {
			code int
			body string
		}{code, body}
	}()
	<-e.prov.holdIPAMStarted
	// A second proposal fills the store while the first is in flight.
	if code, body := must("user11", gpFormCT, dhcpForm("web16").Encode()); code != http.StatusSeeOther {
		t.Fatalf("second propose = %d %q", code, body)
	}
	close(e.prov.holdIPAM)
	res := <-xres
	if res.code != http.StatusServiceUnavailable || !strings.Contains(res.body, "too many deployments in progress") || !strings.Contains(res.body, "stays reserved") {
		t.Fatalf("full store propose = %d %q", res.code, res.body)
	}
	if e.addressFree(t) {
		t.Error("the address was released although the executor holds a permit")
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
	// The spec refusal releases the address, so the second proposal can
	// reserve it again.
	e.prov.proposeErr = status.Error(codes.InvalidArgument, "pve guest provision: invalid or unsupported spec, template, network, key or password id")
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
