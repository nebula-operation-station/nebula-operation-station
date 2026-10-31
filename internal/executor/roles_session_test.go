// SPDX-License-Identifier: AGPL-3.0-or-later

package executor

import (
	"context"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	"github.com/nebula-operation-station/nebula-operation-station/internal/permit"
	"github.com/nebula-operation-station/nebula-operation-station/internal/riskpolicy"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnreg"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// The session-state surface is server and admin only (ADR 0007 E19d, spec
// 05): the server displays the executor-reported expiry and remaining time
// and the admin CLI can read it; the pve-collector and unknown UIDs cannot.
func TestSessionMethodRoles(t *testing.T) {
	methods := map[string][]peercred.Role{
		pb.ExecutorService_GetSessionState_FullMethodName: {peercred.RoleServer, peercred.RoleAdmin},
	}
	roles := []peercred.Role{peercred.RoleServer, peercred.RoleAdmin, peercred.RolePVECollector, peercred.Role("discovery")}
	uids := map[uint32][]peercred.Role{}
	for i, r := range roles {
		uids[uint32(i+1)] = []peercred.Role{r}
	}
	policy := peercred.NewPolicy(uids, MethodRoles())
	for method, want := range methods {
		t.Run(method, func(t *testing.T) {
			got := MethodRoles()[method]
			if len(got) != len(want) {
				t.Errorf("roles = %v, want %v", got, want)
			}
			for i, role := range roles {
				allowed := false
				for _, r := range want {
					allowed = allowed || r == role
				}
				if _, ok := policy.Allowed(uint32(i+1), method); ok != allowed {
					t.Errorf("role %s allowed=%v, want %v", role, ok, allowed)
				}
			}
		})
	}
}

// sessionRPCEnv builds a reconcile env whose authority carries one virtual
// WebAuthn credential and the given executor-configured session length.
func sessionRPCEnv(t *testing.T, length time.Duration) (*reconcileEnv, func([]byte) []byte) {
	t.Helper()
	e := newReconcileEnv(t)
	cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	dev := virtualwebauthn.NewAuthenticator()
	dev.AddCredential(cred)
	v, err := webauthnverify.New(webauthnverify.Config{RPID: "reconcile.test", Origins: []string{"https://reconcile.test"}, Counters: e.db},
		[]webauthnverify.Credential{{ID: cred.ID, PublicKey: cred.Key.AttestationData()}})
	if err != nil {
		t.Fatal(err)
	}
	risk, err := riskpolicy.New(e.db)
	if err != nil {
		t.Fatal(err)
	}
	e.svc.auth, err = permit.New(permit.Options{
		Mode:          permit.ModeStandard,
		Verifier:      v,
		Store:         e.db,
		RiskPolicy:    risk,
		Now:           e.clock.Now,
		SessionLength: length,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.reg, err = webauthnreg.New(webauthnreg.Config{RPID: "reconcile.test", Origins: []string{"https://reconcile.test"}}, v, e.db)
	if err != nil {
		t.Fatal(err)
	}
	// The virtual authenticator always performs user verification, which is
	// what the session flow requires.
	sign := func(challenge []byte) []byte {
		return []byte(virtualwebauthn.CreateAssertionResponse(virtualwebauthn.RelyingParty{Name: "Reconcile", ID: "reconcile.test", Origin: "https://reconcile.test"}, dev, cred,
			virtualwebauthn.AssertionOptions{Challenge: challenge, RelyingPartyID: "reconcile.test"}))
	}
	return e, sign
}

// The executor is authoritative for the session duration and expiry (spec
// 05, ADR 0007 E19d): the state RPC reports the configured duration and the
// executor-computed expiry/remaining time, the Begin response names the
// operation bound into the challenge and the configured duration, and a
// re-approval sets the expiry to approval time plus duration (no
// accumulation). The requests carry no duration field, so the server cannot
// choose it.
func TestGetSessionStateExecutorAuthority(t *testing.T) {
	const length = 30 * time.Minute
	e, sign := sessionRPCEnv(t, length)
	ctx := context.Background()

	st, err := e.svc.GetSessionState(ctx, &pb.GetSessionStateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if st.GetActive() || st.GetExpiryUnix() != 0 || st.GetRemainingSeconds() != 0 || st.GetDurationSeconds() != int64(length/time.Second) {
		t.Fatalf("inactive state = %+v, want inactive with duration %d", st, int64(length/time.Second))
	}

	b, err := e.svc.BeginPrivilegedSession(ctx, &pb.BeginPrivilegedSessionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if b.GetOperation() != permit.SessionExtensionOperation {
		t.Fatalf("operation = %q, want %q", b.GetOperation(), permit.SessionExtensionOperation)
	}
	if b.GetDurationSeconds() != int64(length/time.Second) {
		t.Fatalf("begin duration = %d, want %d", b.GetDurationSeconds(), int64(length/time.Second))
	}
	if len(b.GetChallenge()) == 0 {
		t.Fatal("empty challenge")
	}
	if want := e.clock.Now().Add(permit.SessionChallengeTTL).Unix(); b.GetChallengeExpiryUnix() != want {
		t.Fatalf("challenge expiry = %d, want %d", b.GetChallengeExpiryUnix(), want)
	}

	comp, err := e.svc.CompletePrivilegedSession(ctx, &pb.CompletePrivilegedSessionRequest{AssertionJson: sign(b.GetChallenge())})
	if err != nil {
		t.Fatal(err)
	}
	want := e.clock.Now().Add(length).Unix()
	if comp.GetSessionExpiryUnix() != want {
		t.Fatalf("expiry = %d, want approval time + duration = %d", comp.GetSessionExpiryUnix(), want)
	}

	st, err = e.svc.GetSessionState(ctx, &pb.GetSessionStateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !st.GetActive() || st.GetExpiryUnix() != want || st.GetRemainingSeconds() != int64(length/time.Second) {
		t.Fatalf("active state = %+v, want active until %d with %ds left", st, want, int64(length/time.Second))
	}

	// Ten minutes later the remaining time is executor-computed, not
	// client-supplied.
	e.clock.Set(e.clock.Now().Add(10 * time.Minute))
	st, err = e.svc.GetSessionState(ctx, &pb.GetSessionStateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !st.GetActive() || st.GetExpiryUnix() != want || st.GetRemainingSeconds() != int64((length-10*time.Minute)/time.Second) {
		t.Fatalf("state after 10m = %+v, want active until %d with %ds left", st, want, int64((length-10*time.Minute)/time.Second))
	}

	// Re-approval (extension) sets the expiry to the new approval time plus
	// the configured duration; it never accumulates.
	b2, err := e.svc.BeginPrivilegedSession(ctx, &pb.BeginPrivilegedSessionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	comp2, err := e.svc.CompletePrivilegedSession(ctx, &pb.CompletePrivilegedSessionRequest{AssertionJson: sign(b2.GetChallenge())})
	if err != nil {
		t.Fatal(err)
	}
	if want2 := e.clock.Now().Add(length).Unix(); comp2.GetSessionExpiryUnix() != want2 {
		t.Fatalf("extension expiry = %d, want %d (no accumulation)", comp2.GetSessionExpiryUnix(), want2)
	}
}

// The extension challenge is bound to the session-extension operation
// (ADR 0007 E19d): an assertion made for an execution approval cannot open
// or extend the session, and an assertion made for the session cannot
// approve an execution.
func TestSessionExtensionChallengeIsOperationBound(t *testing.T) {
	e, sign := sessionRPCEnv(t, 0)
	ctx := context.Background()

	// Execution challenge -> session completion must fail.
	artifact := []byte("#!/bin/sh\nset -eu\necho precheck\nsystemctl reboot\n")
	prop, err := e.svc.ProposeExecution(ctx, listPendingRequest(t, 1, artifact))
	if err != nil {
		t.Fatal(err)
	}
	if len(prop.GetChallenge()) == 0 {
		t.Fatal("execution proposal returned no challenge")
	}
	if _, err := e.svc.CompletePrivilegedSession(ctx, &pb.CompletePrivilegedSessionRequest{AssertionJson: sign(prop.GetChallenge())}); err == nil {
		t.Fatal("execution challenge opened the privileged session")
	}
	st, err := e.svc.GetSessionState(ctx, &pb.GetSessionStateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if st.GetActive() {
		t.Fatal("session is active after a cross-operation assertion")
	}

	// Session challenge -> execution approval must fail.
	b, err := e.svc.BeginPrivilegedSession(ctx, &pb.BeginPrivilegedSessionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SubmitAssertion(ctx, &pb.SubmitAssertionRequest{
		ExecutionDigest: prop.GetExecutionDigest(),
		AssertionJson:   sign(b.GetChallenge()),
	}); err == nil {
		t.Fatal("session challenge approved an execution")
	}
}

// While a recovery is pending the session-state RPC is refused like other
// privileged work (fail closed).
func TestGetSessionStateRecoveryPending(t *testing.T) {
	e, _ := sessionRPCEnv(t, 0)
	if err := e.db.SetRecoveryPending(); err != nil {
		t.Fatal(err)
	}
	_, err := e.svc.GetSessionState(context.Background(), &pb.GetSessionStateRequest{})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition: %v", status.Code(err), err)
	}
}
