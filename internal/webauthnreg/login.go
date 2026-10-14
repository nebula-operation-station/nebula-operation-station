// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthnreg

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// Web login (M2). The server starts a login and relays the browser's
// assertion; the executor verifies it against the registered credentials,
// so the server never holds a credential store of its own. A login proves
// who is at the browser for the web session (reading); it grants nothing
// on the executor; approvals still need their own assertions.

// Login limits.
const (
	LoginTTL        = 2 * time.Minute
	MaxPendingLogin = 32
)

// Login failure codes.
const (
	CodeNoCredentials Code = "no_credentials"       // nothing registered yet: run the setup
	CodeLoginNotFound Code = "login_not_found"      // unknown, used or expired login ID
	CodeLoginRejected Code = "login_rejected"       // assertion invalid
	CodeLoginLimit    Code = "login_limit_exceeded" // too many pending logins
)

type pendingLogin struct {
	challenge []byte
	expiry    time.Time
}

// LoginStart is what the browser needs for navigator.credentials.get().
type LoginStart struct {
	ID          string
	OptionsJSON []byte
	Expiry      time.Time
}

// BeginLogin starts a login with a fresh single-use challenge. User
// verification is required.
func (r *Registrar) BeginLogin() (LoginStart, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.cfg.Now()
	if r.verifier.Count() == 0 {
		return LoginStart{}, fail(CodeNoCredentials, "no credential is registered; create a code with `nebula webauthn code` and register one")
	}
	for id, l := range r.logins {
		if !now.Before(l.expiry) {
			delete(r.logins, id)
		}
	}
	if len(r.logins) >= MaxPendingLogin {
		return LoginStart{}, fail(CodeLoginLimit, "too many logins in progress")
	}
	challenge, idb := random(32), random(16)
	if challenge == nil || idb == nil {
		return LoginStart{}, errNoRandom
	}
	var allow []protocol.CredentialDescriptor
	for _, c := range r.verifier.Credentials() {
		allow = append(allow, protocol.CredentialDescriptor{Type: protocol.PublicKeyCredentialType, CredentialID: c.ID})
	}
	opts, err := json.Marshal(protocol.CredentialAssertion{Response: protocol.PublicKeyCredentialRequestOptions{
		Challenge:          challenge,
		Timeout:            int(LoginTTL / time.Millisecond),
		RelyingPartyID:     r.cfg.RPID,
		AllowedCredentials: allow,
		UserVerification:   protocol.VerificationRequired,
	}})
	if err != nil {
		return LoginStart{}, err
	}
	id := hex.EncodeToString(idb)
	exp := now.Add(LoginTTL)
	r.logins[id] = &pendingLogin{challenge: challenge, expiry: exp}
	return LoginStart{ID: id, OptionsJSON: opts, Expiry: exp}, nil
}

// FinishLogin verifies the assertion for a pending login and returns the
// credential that made it. The login is consumed first, so a failed or
// replayed attempt needs a new BeginLogin.
func (r *Registrar) FinishLogin(id string, assertionJSON []byte) ([]byte, error) {
	if len(assertionJSON) == 0 || len(assertionJSON) > MaxResponseSize {
		return nil, fail(CodeInvalidRequest, "assertion size out of range")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	l, ok := r.logins[id]
	if !ok {
		return nil, fail(CodeLoginNotFound, "no such login (it may have been used already)")
	}
	delete(r.logins, id)
	if !r.cfg.Now().Before(l.expiry) {
		return nil, fail(CodeLoginNotFound, "login expired")
	}
	credID, err := r.verifier.Verify(assertionJSON, l.challenge, webauthnverify.Requirement{UserVerification: true})
	if errors.Is(err, webauthnverify.ErrCounterStore) {
		r.cfg.Audit(Event{Kind: "login_rejected", Detail: err.Error()})
		return nil, fail(CodeStorage, "executor state store unavailable")
	}
	if err != nil {
		r.cfg.Audit(Event{Kind: "login_rejected", Detail: err.Error()})
		return nil, fail(CodeLoginRejected, "%v", err)
	}
	r.cfg.Audit(Event{Kind: "login_verified", Credential: hex.EncodeToString(credID)})
	return credID, nil
}
