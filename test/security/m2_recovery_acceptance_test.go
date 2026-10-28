// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"encoding/base32"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"google.golang.org/grpc/codes"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/totp"
	"github.com/nebula-operation-station/nebula-operation-station/internal/web/auth"
)

// M2 acceptance: TOTP recovery (spec 05). Recovery forces a new WebAuthn
// registration before any privileged action.

func (h *harness) setupTOTP() []byte {
	h.t.Helper()
	b, err := h.client.BeginTOTPSetup(h.ctx(), &pb.BeginTOTPSetupRequest{Account: "admin@nebula.example.org"})
	if err != nil {
		h.t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(b.GetSecretBase32())
	if err != nil || !strings.HasPrefix(b.GetUri(), "otpauth://totp/") {
		h.t.Fatalf("setup: %v %q", err, b.GetUri())
	}
	if _, err := h.client.ConfirmTOTPSetup(h.ctx(), &pb.ConfirmTOTPSetupRequest{Code: totp.Code(secret, time.Now())}); err != nil {
		h.t.Fatal(err)
	}
	return secret
}

// nextCode is a code for the next step: the current one was used by the
// confirmation, and one step of clock skew is accepted.
func nextCode(secret []byte) string { return totp.Code(secret, time.Now().Add(totp.Step)) }

func TestM2Recovery_ForcesNewRegistration(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	_, err := h.client.RecoveryLogin(h.ctx(), &pb.RecoveryLoginRequest{Code: "123456"})
	wantCode(t, err, codes.FailedPrecondition, "recovery_not_set_up")

	secret := h.setupTOTP()
	st, err := h.client.GetTOTPStatus(h.ctx(), &pb.GetTOTPStatusRequest{})
	if err != nil || !st.GetConfigured() || !st.GetActivated() || st.GetRecoveryPending() {
		t.Fatalf("status %v %v", st, err)
	}
	// A privileged session that is open before the recovery ends with it.
	h.openSession()

	code := nextCode(secret)
	if _, err := h.client.RecoveryLogin(h.ctx(), &pb.RecoveryLoginRequest{Code: code}); err != nil {
		t.Fatal(err)
	}
	// Single use.
	_, err = h.client.RecoveryLogin(h.ctx(), &pb.RecoveryLoginRequest{Code: code})
	wantCode(t, err, codes.Unauthenticated, "")

	s, _ := h.client.GetStatus(h.ctx(), &pb.GetStatusRequest{})
	if !s.GetRecoveryPending() || s.GetPrivilegedSessionActive() {
		t.Fatalf("after recovery: %v", s)
	}
	_, err = h.client.BeginPrivilegedSession(h.ctx(), &pb.BeginPrivilegedSessionRequest{})
	wantCode(t, err, codes.FailedPrecondition, "recovery_pending")
	_, err = h.client.CompletePrivilegedSession(h.ctx(), &pb.CompletePrivilegedSessionRequest{AssertionJson: []byte(`{}`)})
	wantCode(t, err, codes.FailedPrecondition, "recovery_pending")
	_, err = h.client.SubmitAssertion(h.ctx(), &pb.SubmitAssertionRequest{
		ExecutionDigest: strings.Repeat("a", 64), AssertionJson: []byte(`{}`)})
	wantCode(t, err, codes.FailedPrecondition, "recovery_pending")

	// The state survives a restart of the executor.
	h.stop()
	h2 := newHarness(t, harnessOptions{dataDir: h.dataDir, identity: h.id})
	_, err = h2.client.BeginPrivilegedSession(h2.ctx(), &pb.BeginPrivilegedSessionRequest{})
	wantCode(t, err, codes.FailedPrecondition, "recovery_pending")

	// Registering a new key (one-time code from the executor host,
	// confirmed by a registered key) ends the recovery state.
	h2.register(newKey(virtualwebauthn.AuthenticatorOptions{}), h2.id)
	if s, _ := h2.client.GetStatus(h2.ctx(), &pb.GetStatusRequest{}); s.GetRecoveryPending() {
		t.Fatal("recovery still pending after a new registration")
	}
	h2.openSession()
}

func TestM2Recovery_WrongCodesAreLimited(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	secret := h.setupTOTP()
	for i := 0; i < 5; i++ {
		_, err := h.client.RecoveryLogin(h.ctx(), &pb.RecoveryLoginRequest{Code: "000000"})
		if err == nil {
			t.Fatal("wrong code accepted")
		}
	}
	_, err := h.client.RecoveryLogin(h.ctx(), &pb.RecoveryLoginRequest{Code: nextCode(secret)})
	wantCode(t, err, codes.ResourceExhausted, "")
	if !strings.Contains(h.logs.String(), `"kind":"recovery_login_limited"`) {
		t.Fatal("limit not audited")
	}
}

func TestM2Recovery_RolesAndSessionCheck(t *testing.T) {
	uid := uint32(os.Getuid())
	server := newHarness(t, harnessOptions{uidRoles: map[uint32][]peercred.Role{uid: {peercred.RoleServer}}})
	for name, call := range map[string]func() error{
		"BeginTOTPSetup": func() error {
			_, err := server.client.BeginTOTPSetup(server.ctx(), &pb.BeginTOTPSetupRequest{})
			return err
		},
		"ConfirmTOTPSetup": func() error {
			_, err := server.client.ConfirmTOTPSetup(server.ctx(), &pb.ConfirmTOTPSetupRequest{})
			return err
		},
		"RemoveTOTP": func() error { _, err := server.client.RemoveTOTP(server.ctx(), &pb.RemoveTOTPRequest{}); return err },
	} {
		if err := call(); err == nil {
			t.Errorf("server role may call %s", name)
		}
	}
	// Reading the status is allowed for the server role (issue #72).
	if _, err := server.client.GetTOTPStatus(server.ctx(), &pb.GetTOTPStatusRequest{}); err != nil {
		t.Fatalf("server role may not read the TOTP status: %v", err)
	}
	admin := newHarness(t, harnessOptions{uidRoles: map[uint32][]peercred.Role{uid: {peercred.RoleAdmin}}})
	_, err := admin.client.RecoveryLogin(admin.ctx(), &pb.RecoveryLoginRequest{Code: "123456"})
	wantCode(t, err, codes.PermissionDenied, "")

	// The web session of a recovery login stays valid only while TOTP is set up.
	if auth.RecoveryCredentialID != executor.RecoveryCredentialID {
		t.Fatal("server and executor disagree on the recovery credential ID")
	}
	h := newHarness(t, harnessOptions{})
	h.setupTOTP()
	r, err := h.client.CheckCredential(h.ctx(), &pb.CheckCredentialRequest{CredentialId: executor.RecoveryCredentialID})
	if err != nil || !r.GetRegistered() {
		t.Fatalf("recovery credential: %v %v", r, err)
	}
	if _, err := h.client.RemoveTOTP(h.ctx(), &pb.RemoveTOTPRequest{}); err != nil {
		t.Fatal(err)
	}
	r, _ = h.client.CheckCredential(h.ctx(), &pb.CheckCredentialRequest{CredentialId: executor.RecoveryCredentialID})
	if r.GetRegistered() {
		t.Fatal("recovery session survives TOTP removal")
	}
}

// All keys lost (Hermes review of M2-5, finding 1): the only credential is
// removed, and the new key can only be registered with the one-time code.
// A compromised server sees that code, so such a key ends the recovery
// only after the admin confirms it on the executor host.
func TestM2Recovery_CodeOnlyKeyNeedsConfirmationOnTheExecutorHost(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	secret := h.setupTOTP()
	if _, err := h.client.RecoveryLogin(h.ctx(), &pb.RecoveryLoginRequest{Code: nextCode(secret)}); err != nil {
		t.Fatal(err)
	}
	oldID := base64.RawURLEncoding.EncodeToString(h.id.cred.ID)
	if _, err := h.client.RemoveWebAuthnCredential(h.ctx(), &pb.RemoveWebAuthnCredentialRequest{CredentialId: oldID}); err != nil {
		t.Fatal(err)
	}
	_, err := h.client.FinishRecovery(h.ctx(), &pb.FinishRecoveryRequest{CredentialId: oldID})
	wantCode(t, err, codes.NotFound, "")

	key := newKey(virtualwebauthn.AuthenticatorOptions{})
	b := h.begin(h.code())
	resp, err := h.finish(b, attest(t, b, h.rp, key), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.GetRecoveryConfirmationRequired() {
		t.Fatal("code-only registration ended the recovery")
	}
	h.id = key
	_, err = h.client.BeginPrivilegedSession(h.ctx(), &pb.BeginPrivilegedSessionRequest{})
	wantCode(t, err, codes.FailedPrecondition, "recovery_pending")

	// Only the admin role confirms, and only a key from after the recovery.
	uid := uint32(os.Getuid())
	server := newHarness(t, harnessOptions{uidRoles: map[uint32][]peercred.Role{uid: {peercred.RoleServer}}})
	_, err = server.client.FinishRecovery(server.ctx(), &pb.FinishRecoveryRequest{CredentialId: resp.GetCredentialId()})
	wantCode(t, err, codes.PermissionDenied, "")
	if _, err := h.client.FinishRecovery(h.ctx(), &pb.FinishRecoveryRequest{CredentialId: resp.GetCredentialId()}); err != nil {
		t.Fatal(err)
	}
	h.requireAudit("recovery_completed")
	h.openSession()
	_, err = h.client.FinishRecovery(h.ctx(), &pb.FinishRecoveryRequest{CredentialId: resp.GetCredentialId()})
	wantCode(t, err, codes.FailedPrecondition, "no recovery")
}

// A recovery login cancels registrations in progress, like Lock (Hermes
// review of M2-5, finding 3).
func TestM2Recovery_LoginCancelsPendingRegistrations(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	secret := h.setupTOTP()
	code := h.code()
	if _, err := h.client.RecoveryLogin(h.ctx(), &pb.RecoveryLoginRequest{Code: nextCode(secret)}); err != nil {
		t.Fatal(err)
	}
	_, err := h.client.BeginRegistration(h.ctx(), &pb.BeginRegistrationRequest{Code: code})
	if err == nil {
		t.Fatal("a code from before the recovery login still works")
	}
}
