// SPDX-License-Identifier: AGPL-3.0-or-later

package security

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
	"google.golang.org/grpc/codes"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executor"
	"github.com/nebula-operation-station/nebula-operation-station/internal/peercred"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// H03 acceptance: WebAuthn registration in the executor.

// newKey is a fresh virtual authenticator with one credential.
func newKey(opts virtualwebauthn.AuthenticatorOptions) *identity {
	id := &identity{dev: virtualwebauthn.NewAuthenticatorWithOptions(opts), cred: virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)}
	id.dev.AddCredential(id.cred)
	return id
}

func (h *harness) code() string {
	h.t.Helper()
	resp, err := h.client.CreateRegistrationCode(h.ctx(), &pb.CreateRegistrationCodeRequest{UserName: "axel", Label: "test key"})
	if err != nil {
		h.t.Fatalf("create code: %v", err)
	}
	return resp.GetCode()
}

func (h *harness) begin(code string) *pb.BeginRegistrationResponse {
	h.t.Helper()
	b, err := h.client.BeginRegistration(h.ctx(), &pb.BeginRegistrationRequest{Code: code})
	if err != nil {
		h.t.Fatalf("begin registration: %v", err)
	}
	return b
}

// attest answers the creation options with key from rp.
func attest(t *testing.T, b *pb.BeginRegistrationResponse, rp virtualwebauthn.RelyingParty, key *identity) []byte {
	t.Helper()
	opts, err := virtualwebauthn.ParseAttestationOptions(string(b.GetCreationOptionsJson()))
	if err != nil {
		t.Fatal(err)
	}
	return []byte(virtualwebauthn.CreateAttestationResponse(rp, key.dev, key.cred, *opts))
}

// authorize answers the authorization options with key.
func (h *harness) authorize(b *pb.BeginRegistrationResponse, key *identity) []byte {
	h.t.Helper()
	opts, err := virtualwebauthn.ParseAssertionOptions(string(b.GetAuthorizationOptionsJson()))
	if err != nil {
		h.t.Fatal(err)
	}
	return []byte(virtualwebauthn.CreateAssertionResponse(h.rp, key.dev, key.cred, *opts))
}

func (h *harness) finish(b *pb.BeginRegistrationResponse, att, assertion []byte) (*pb.FinishRegistrationResponse, error) {
	return h.client.FinishRegistration(h.ctx(), &pb.FinishRegistrationRequest{
		RegistrationId: b.GetRegistrationId(), AttestationJson: att, AssertionJson: assertion,
	})
}

// register runs a registration for key with a fresh code. confirm is the
// registered key that confirms it, or nil for the first credential. It
// returns the base64url credential ID.
func (h *harness) register(key, confirm *identity) string {
	h.t.Helper()
	b := h.begin(h.code())
	var assertion []byte
	if confirm != nil {
		assertion = h.authorize(b, confirm)
	}
	resp, err := h.finish(b, attest(h.t, b, h.rp, key), assertion)
	if err != nil {
		h.t.Fatalf("finish registration: %v", err)
	}
	return resp.GetCredentialId()
}

func (h *harness) listCreds() []*pb.WebAuthnCredential {
	h.t.Helper()
	resp, err := h.client.ListWebAuthnCredentials(h.ctx(), &pb.ListWebAuthnCredentialsRequest{})
	if err != nil {
		h.t.Fatal(err)
	}
	return resp.GetCredentials()
}

func TestH03_FirstCredentialOnlyWithOneTimeCode(t *testing.T) {
	key := newKey(virtualwebauthn.AuthenticatorOptions{})
	h := newHarness(t, harnessOptions{noCredential: true, identity: key})

	// No unauthenticated registration: no code, or a wrong one.
	_, err := h.client.BeginRegistration(h.ctx(), &pb.BeginRegistrationRequest{})
	wantCode(t, err, codes.FailedPrecondition, "registration_not_allowed")
	_, err = h.client.BeginRegistration(h.ctx(), &pb.BeginRegistrationRequest{Code: "AAAA-BBBB-CCCC-DDDD-EEEE"})
	wantCode(t, err, codes.Unauthenticated, "registration_code_invalid")

	id := h.register(key, nil)
	creds := h.listCreds()
	if len(creds) != 1 || creds[0].GetCredentialId() != id || creds[0].GetLabel() != "test key" ||
		creds[0].GetUserName() != "axel" || !strings.HasPrefix(creds[0].GetCreatedBy(), "code:admin:uid") {
		t.Fatalf("credentials: %v", creds)
	}
	h.requireAudit(`"kind":"credential_registered"`)

	// The new credential is live: it opens the privileged session and
	// approves a permit.
	h.openSession()
	h.approvedMedium()
}

func TestH03_CodeIsSingleUseAndGuessingInvalidatesIt(t *testing.T) {
	h := newHarness(t, harnessOptions{noCredential: true})
	code := h.code()
	h.begin(code)
	_, err := h.client.BeginRegistration(h.ctx(), &pb.BeginRegistrationRequest{Code: code})
	wantCode(t, err, codes.Unauthenticated, "registration_code_invalid")

	code = h.code()
	for i := 0; i < 5; i++ {
		_, err = h.client.BeginRegistration(h.ctx(), &pb.BeginRegistrationRequest{Code: "0000-0000-0000-0000-0000"})
		wantCode(t, err, codes.Unauthenticated, "")
	}
	_, err = h.client.BeginRegistration(h.ctx(), &pb.BeginRegistrationRequest{Code: code})
	wantCode(t, err, codes.Unauthenticated, "registration_code_invalid")
	h.requireAudit("code invalidated")
}

func TestH03_OnlyTheAdminCreatesCodes(t *testing.T) {
	h := newHarness(t, harnessOptions{noCredential: true, uidRoles: map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleServer}}})
	_, err := h.client.CreateRegistrationCode(h.ctx(), &pb.CreateRegistrationCodeRequest{})
	wantCode(t, err, codes.PermissionDenied, "")
	// Listing is read-only and allowed for the server role (issue #72).
	if _, err = h.client.ListWebAuthnCredentials(h.ctx(), &pb.ListWebAuthnCredentialsRequest{}); err != nil {
		t.Fatalf("server role may not list credentials: %v", err)
	}
	_, err = h.client.RemoveWebAuthnCredential(h.ctx(), &pb.RemoveWebAuthnCredentialRequest{CredentialId: "AA"})
	wantCode(t, err, codes.PermissionDenied, "")

	admin := newHarness(t, harnessOptions{noCredential: true, uidRoles: map[uint32][]peercred.Role{uint32(os.Getuid()): {peercred.RoleAdmin}}})
	_, err = admin.client.BeginRegistration(admin.ctx(), &pb.BeginRegistrationRequest{})
	wantCode(t, err, codes.PermissionDenied, "")
	_, err = admin.client.FinishRegistration(admin.ctx(), &pb.FinishRegistrationRequest{})
	wantCode(t, err, codes.PermissionDenied, "")
}

func TestH03_ReplayedRegistrationIsRejected(t *testing.T) {
	h := newHarness(t, harnessOptions{noCredential: true})
	key := newKey(virtualwebauthn.AuthenticatorOptions{})
	b := h.begin(h.code())
	att := attest(t, b, h.rp, key)
	if _, err := h.finish(b, att, nil); err != nil {
		t.Fatal(err)
	}
	_, err := h.finish(b, att, nil)
	wantCode(t, err, codes.NotFound, "registration_not_found")

	// The recorded response against a fresh registration (confirmed by the
	// registered key, so the attestation is checked): wrong challenge.
	b2 := h.begin(h.code())
	_, err = h.finish(b2, att, h.authorize(b2, key))
	wantCode(t, err, codes.PermissionDenied, "attestation_rejected")
	if n := len(h.listCreds()); n != 1 {
		t.Fatalf("%d credentials after replay, want 1", n)
	}
}

// Two registrations begun before any credential exists: once the first is
// finished, the second is no longer a "first credential" and is rejected
// without a confirmation.
func TestH03_ConcurrentFirstRegistrationsNeedConfirmation(t *testing.T) {
	h := newHarness(t, harnessOptions{noCredential: true})
	b1 := h.begin(h.code())
	b2 := h.begin(h.code())
	if _, err := h.finish(b1, attest(t, b1, h.rp, newKey(virtualwebauthn.AuthenticatorOptions{})), nil); err != nil {
		t.Fatal(err)
	}
	_, err := h.finish(b2, attest(t, b2, h.rp, newKey(virtualwebauthn.AuthenticatorOptions{})), nil)
	wantCode(t, err, codes.PermissionDenied, "assertion_rejected")
	if n := len(h.listCreds()); n != 1 {
		t.Fatalf("%d credentials, want 1", n)
	}
}

func TestH03_CrossOriginRegistrationIsRejected(t *testing.T) {
	for name, rp := range map[string]virtualwebauthn.RelyingParty{
		"foreign origin": {Name: "Evil", ID: rpID, Origin: "https://evil.example"},
		"foreign RP ID":  {Name: "Evil", ID: "evil.example", Origin: origin},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, harnessOptions{noCredential: true})
			key := newKey(virtualwebauthn.AuthenticatorOptions{})
			b := h.begin(h.code())
			_, err := h.finish(b, attest(t, b, rp, key), nil)
			wantCode(t, err, codes.PermissionDenied, "attestation_rejected")
			if n := len(h.listCreds()); n != 0 {
				t.Fatalf("%d credentials registered from a foreign origin", n)
			}
		})
	}
}

// Further credentials need a one-time code from the executor host AND a
// user-verified assertion of a registered credential over this
// registration's challenge. The browser alone cannot add a credential, not
// even with a hijacked authenticator gesture.
func TestH03_FurtherCredentialNeedsCodeAndUserVerifiedAssertion(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	phone := newKey(virtualwebauthn.AuthenticatorOptions{})

	// Without a code: no registration at all, even for a registered admin.
	_, err := h.client.BeginRegistration(h.ctx(), &pb.BeginRegistrationRequest{})
	wantCode(t, err, codes.FailedPrecondition, "registration_not_allowed")

	b := h.begin(h.code())
	if len(b.GetAuthorizationOptionsJson()) == 0 {
		t.Fatal("no authorization options although a credential is registered")
	}
	_, err = h.finish(b, attest(t, b, h.rp, phone), nil)
	wantCode(t, err, codes.PermissionDenied, "assertion_rejected")

	b = h.begin(h.code())
	noUV := &identity{dev: h.id.dev, cred: h.id.cred}
	noUV.dev.Options.UserNotVerified = true
	_, err = h.finish(b, attest(t, b, h.rp, phone), h.authorize(b, noUV))
	wantCode(t, err, codes.PermissionDenied, "assertion_rejected")

	// An assertion from the privileged-session ceremony does not confirm a
	// registration.
	b = h.begin(h.code())
	sess, err := h.client.BeginPrivilegedSession(h.ctx(), &pb.BeginPrivilegedSessionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.finish(b, attest(t, b, h.rp, phone), h.sign(sess.GetChallenge()))
	wantCode(t, err, codes.PermissionDenied, "assertion_rejected")

	h.register(phone, h.id)
	creds := h.listCreds()
	confirmed := 0
	for _, c := range creds {
		if strings.HasPrefix(c.GetCreatedBy(), "code:admin:uid") && strings.Contains(c.GetCreatedBy(), "+webauthn:") {
			confirmed++
		}
	}
	if len(creds) != 2 || confirmed != 1 {
		t.Fatalf("credentials: %v", creds)
	}
	h.requireAudit(`"kind":"credential_registered"`, `+webauthn:`)
}

// Removing a credential deactivates it at once and locks the executor.
func TestH03_RemovedCredentialIsDeadAndLocks(t *testing.T) {
	h := newHarness(t, harnessOptions{})
	h.openSession()
	pending := h.propose(h.request(riskMedium))
	id := base64.RawURLEncoding.EncodeToString(h.id.cred.ID)

	reg := h.begin(h.code())
	resp, err := h.client.RemoveWebAuthnCredential(h.ctx(), &pb.RemoveWebAuthnCredentialRequest{CredentialId: id})
	if err != nil || !resp.GetRemoved() {
		t.Fatalf("remove: %v %v", resp, err)
	}
	st, err := h.client.GetStatus(h.ctx(), &pb.GetStatusRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if st.GetPrivilegedSessionActive() || st.GetPendingPermits() != 0 {
		t.Fatalf("after removal: session=%v pending=%d", st.GetPrivilegedSessionActive(), st.GetPendingPermits())
	}
	if h.verifier.Has(h.id.cred.ID) {
		t.Fatal("removed credential is still active")
	}
	_, err = h.client.SubmitAssertion(h.ctx(), &pb.SubmitAssertionRequest{ExecutionDigest: pending.GetExecutionDigest(), AssertionJson: h.sign(pending.GetChallenge())})
	wantCode(t, err, codes.NotFound, "")
	b, err := h.client.BeginPrivilegedSession(h.ctx(), &pb.BeginPrivilegedSessionRequest{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.client.CompletePrivilegedSession(h.ctx(), &pb.CompletePrivilegedSessionRequest{AssertionJson: h.sign(b.GetChallenge())})
	wantCode(t, err, codes.PermissionDenied, "assertion_rejected")
	// The registration that was pending is cancelled.
	_, err = h.finish(reg, attest(t, reg, h.rp, newKey(virtualwebauthn.AuthenticatorOptions{})), nil)
	wantCode(t, err, codes.NotFound, "registration_not_found")
}

func TestH03_LockCancelsRegistrations(t *testing.T) {
	h := newHarness(t, harnessOptions{noCredential: true})
	code := h.code()
	b := h.begin(h.code())
	if _, err := h.client.Lock(h.ctx(), &pb.LockRequest{}); err != nil {
		t.Fatal(err)
	}
	_, err := h.finish(b, attest(t, b, h.rp, newKey(virtualwebauthn.AuthenticatorOptions{})), nil)
	wantCode(t, err, codes.NotFound, "")
	_, err = h.client.BeginRegistration(h.ctx(), &pb.BeginRegistrationRequest{Code: code})
	wantCode(t, err, codes.Unauthenticated, "")
}

func TestH03_CredentialsSurviveRestartAndLegacyFileIsImportedOnce(t *testing.T) {
	dir := privateDir(t)
	legacy := newKey(virtualwebauthn.AuthenticatorOptions{})
	b, err := json.Marshal([]webauthnverify.Credential{{ID: legacy.cred.ID, PublicKey: legacy.cred.Key.AttestationData(), Label: "M0 key"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, executor.LegacyCredentialsFile), b, 0o600); err != nil {
		t.Fatal(err)
	}

	h1 := newHarness(t, harnessOptions{dataDir: dir, identity: legacy, noCredential: true})
	creds := h1.listCreds()
	if len(creds) != 1 || creds[0].GetLabel() != "M0 key" || creds[0].GetCreatedBy() != "import:"+executor.LegacyCredentialsFile {
		t.Fatalf("after import: %v", creds)
	}
	if _, err := os.Stat(filepath.Join(dir, executor.LegacyCredentialsFile)); !os.IsNotExist(err) {
		t.Fatal("legacy file not renamed after import")
	}
	h1.openSession() // the imported credential works
	extra := newKey(virtualwebauthn.AuthenticatorOptions{})
	h1.register(extra, legacy)
	_, err = h1.client.RemoveWebAuthnCredential(h1.ctx(), &pb.RemoveWebAuthnCredentialRequest{
		CredentialId: base64.RawURLEncoding.EncodeToString(legacy.cred.ID)})
	if err != nil {
		t.Fatal(err)
	}
	h1.stop()

	// After a restart: the registered key is there, the removed legacy key
	// does not come back from the renamed file.
	h2 := newHarness(t, harnessOptions{dataDir: dir, identity: extra, noCredential: true})
	creds = h2.listCreds()
	if len(creds) != 1 || creds[0].GetCredentialId() != base64.RawURLEncoding.EncodeToString(extra.cred.ID) {
		t.Fatalf("after restart: %v", creds)
	}
	h2.openSession()
}
