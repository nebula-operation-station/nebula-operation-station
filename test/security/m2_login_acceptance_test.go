// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
	"google.golang.org/grpc/codes"

	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// M2 acceptance: web login is verified by the executor against the
// registered credentials; the server only relays.

func (h *harness) loginAssertion(b *pb.BeginLoginResponse, key *identity) []byte {
	h.t.Helper()
	opts, err := virtualwebauthn.ParseAssertionOptions(string(b.GetRequestOptionsJson()))
	if err != nil {
		h.t.Fatal(err)
	}
	return []byte(virtualwebauthn.CreateAssertionResponse(h.rp, key.dev, key.cred, *opts))
}

func (h *harness) beginLogin() *pb.BeginLoginResponse {
	h.t.Helper()
	b, err := h.client.BeginLogin(h.ctx(), &pb.BeginLoginRequest{})
	if err != nil {
		h.t.Fatalf("begin login: %v", err)
	}
	return b
}

func TestM2_LoginWithRegisteredKey(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	b := h.beginLogin()
	r, err := h.client.FinishLogin(h.ctx(), &pb.FinishLoginRequest{LoginId: b.GetLoginId(), AssertionJson: h.loginAssertion(b, h.id)})
	if err != nil {
		t.Fatal(err)
	}
	if r.GetCredentialId() != base64.RawURLEncoding.EncodeToString(h.id.cred.ID) || r.GetUserName() != "admin" {
		t.Fatalf("login result %+v", r)
	}
	// Single use.
	_, err = h.client.FinishLogin(h.ctx(), &pb.FinishLoginRequest{LoginId: b.GetLoginId(), AssertionJson: h.loginAssertion(b, h.id)})
	wantCode(t, err, codes.NotFound, "login_not_found")
}

func TestM2_LoginRejectsUnknownKeyAndMissingUV(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	b := h.beginLogin()
	_, err := h.client.FinishLogin(h.ctx(), &pb.FinishLoginRequest{LoginId: b.GetLoginId(), AssertionJson: h.loginAssertion(b, newIdentity())})
	wantCode(t, err, codes.Unauthenticated, "")

	b = h.beginLogin()
	noUV := *h.id
	noUV.dev.Options.UserNotVerified = true
	_, err = h.client.FinishLogin(h.ctx(), &pb.FinishLoginRequest{LoginId: b.GetLoginId(), AssertionJson: h.loginAssertion(b, &noUV)})
	wantCode(t, err, codes.Unauthenticated, "")
	if !strings.Contains(h.logs.String(), `"kind":"login_failed"`) {
		t.Fatal("failed login not audited")
	}
}

func TestM2_NoLoginBeforeSetup(t *testing.T) {
	h := newHarness(t, harnessOptions{noCredential: true})
	_, err := h.client.BeginLogin(h.ctx(), &pb.BeginLoginRequest{})
	wantCode(t, err, codes.FailedPrecondition, "nebula webauthn code")
}

func TestM2_RemovedKeyCannotLogIn(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	b := h.beginLogin()
	as := h.loginAssertion(b, h.id)
	if _, err := h.client.RemoveWebAuthnCredential(h.ctx(), &pb.RemoveWebAuthnCredentialRequest{
		CredentialId: base64.RawURLEncoding.EncodeToString(h.id.cred.ID)}); err != nil {
		t.Fatal(err)
	}
	_, err := h.client.FinishLogin(h.ctx(), &pb.FinishLoginRequest{LoginId: b.GetLoginId(), AssertionJson: as})
	wantCode(t, err, codes.NotFound, "")
}

func TestM2_OnlyTheServerRoleLogsIn(t *testing.T) {
	h := newHarness(t, harnessOptions{uidRoles: map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleAdmin}}})
	_, err := h.client.BeginLogin(h.ctx(), &pb.BeginLoginRequest{})
	wantCode(t, err, codes.PermissionDenied, "")
}

// The privileged session challenge comes with request options for the
// browser; the session still opens only with a user-verified assertion.
func TestM2_PrivilegedSessionFromTheBrowser(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	b, err := h.client.BeginPrivilegedSession(h.ctx(), &pb.BeginPrivilegedSessionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	opts, err := virtualwebauthn.ParseAssertionOptions(string(b.GetRequestOptionsJson()))
	if err != nil {
		t.Fatal(err)
	}
	if string(opts.Challenge) != string(b.GetChallenge()) || len(opts.AllowCredentials) != 1 {
		t.Fatalf("options %+v", opts)
	}
	noUV := *h.id
	noUV.dev.Options.UserNotVerified = true
	as := virtualwebauthn.CreateAssertionResponse(h.rp, noUV.dev, noUV.cred, *opts)
	if _, err := h.client.CompletePrivilegedSession(h.ctx(), &pb.CompletePrivilegedSessionRequest{AssertionJson: []byte(as)}); err == nil {
		t.Fatal("privileged session opened without user verification")
	}
	b, _ = h.client.BeginPrivilegedSession(h.ctx(), &pb.BeginPrivilegedSessionRequest{})
	opts, _ = virtualwebauthn.ParseAssertionOptions(string(b.GetRequestOptionsJson()))
	as = virtualwebauthn.CreateAssertionResponse(h.rp, h.id.dev, h.id.cred, *opts)
	if _, err := h.client.CompletePrivilegedSession(h.ctx(), &pb.CompletePrivilegedSessionRequest{AssertionJson: []byte(as)}); err != nil {
		t.Fatal(err)
	}
}

// The server asks whether a session's credential is still registered; a
// removed credential reports false (M2-6).
func TestM2_CheckCredentialFollowsRemoval(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	id := base64.RawURLEncoding.EncodeToString(h.id.cred.ID)
	r, err := h.client.CheckCredential(h.ctx(), &pb.CheckCredentialRequest{CredentialId: id})
	if err != nil || !r.GetRegistered() {
		t.Fatalf("registered credential: %v %v", r, err)
	}
	r, err = h.client.CheckCredential(h.ctx(), &pb.CheckCredentialRequest{CredentialId: base64.RawURLEncoding.EncodeToString([]byte("other"))})
	if err != nil || r.GetRegistered() {
		t.Fatalf("unknown credential: %v %v", r, err)
	}
	_, err = h.client.CheckCredential(h.ctx(), &pb.CheckCredentialRequest{CredentialId: "not base64!"})
	wantCode(t, err, codes.InvalidArgument, "")
	if _, err := h.client.RemoveWebAuthnCredential(h.ctx(), &pb.RemoveWebAuthnCredentialRequest{CredentialId: id}); err != nil {
		t.Fatal(err)
	}
	r, err = h.client.CheckCredential(h.ctx(), &pb.CheckCredentialRequest{CredentialId: id})
	if err != nil || r.GetRegistered() {
		t.Fatalf("removed credential still registered: %v %v", r, err)
	}
	admin := newHarness(t, harnessOptions{uidRoles: map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleAdmin}}})
	_, err = admin.client.CheckCredential(admin.ctx(), &pb.CheckCredentialRequest{CredentialId: id})
	wantCode(t, err, codes.PermissionDenied, "")
}
