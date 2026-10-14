// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthnreg

import (
	"bytes"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
)

func (e *env) loginAssertion(l LoginStart, a virtualwebauthn.Authenticator, c virtualwebauthn.Credential) []byte {
	e.t.Helper()
	opts, err := virtualwebauthn.ParseAssertionOptions(string(l.OptionsJSON))
	if err != nil {
		e.t.Fatal(err)
	}
	return []byte(virtualwebauthn.CreateAssertionResponse(e.rp, a, c, *opts))
}

func TestLoginWithRegisteredCredential(t *testing.T) {
	e := newEnv(t, true)
	l, err := e.reg.BeginLogin()
	if err != nil {
		t.Fatal(err)
	}
	id, err := e.reg.FinishLogin(l.ID, e.loginAssertion(l, *e.existing, e.existingCred))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(id, e.existingCred.ID) {
		t.Fatalf("credential %x", id)
	}
}

func TestLoginNeedsARegisteredCredential(t *testing.T) {
	e := newEnv(t, false)
	_, err := e.reg.BeginLogin()
	wantCode(t, err, CodeNoCredentials)
}

func TestLoginIsSingleUse(t *testing.T) {
	e := newEnv(t, true)
	l, _ := e.reg.BeginLogin()
	as := e.loginAssertion(l, *e.existing, e.existingCred)
	if _, err := e.reg.FinishLogin(l.ID, as); err != nil {
		t.Fatal(err)
	}
	_, err := e.reg.FinishLogin(l.ID, as)
	wantCode(t, err, CodeLoginNotFound)

	// A failed attempt consumes the login too.
	l, _ = e.reg.BeginLogin()
	_, err = e.reg.FinishLogin(l.ID, []byte(`{"id":"x"}`))
	wantCode(t, err, CodeLoginRejected)
	_, err = e.reg.FinishLogin(l.ID, e.loginAssertion(l, *e.existing, e.existingCred))
	wantCode(t, err, CodeLoginNotFound)
}

func TestLoginRejectsForeignChallengeNoUVAndUnknownKeys(t *testing.T) {
	e := newEnv(t, true)
	l1, _ := e.reg.BeginLogin()
	l2, _ := e.reg.BeginLogin()
	_, err := e.reg.FinishLogin(l2.ID, e.loginAssertion(l1, *e.existing, e.existingCred))
	wantCode(t, err, CodeLoginRejected)

	l, _ := e.reg.BeginLogin()
	noUV := *e.existing
	noUV.Options.UserNotVerified = true
	_, err = e.reg.FinishLogin(l.ID, e.loginAssertion(l, noUV, e.existingCred))
	wantCode(t, err, CodeLoginRejected)

	l, _ = e.reg.BeginLogin()
	a, c := newKey(virtualwebauthn.AuthenticatorOptions{})
	_, err = e.reg.FinishLogin(l.ID, e.loginAssertion(l, a, c))
	wantCode(t, err, CodeLoginRejected)
}

func TestLoginExpiresAndIsLimited(t *testing.T) {
	e := newEnv(t, true)
	l, _ := e.reg.BeginLogin()
	e.clk.t = e.clk.t.Add(LoginTTL + time.Second)
	_, err := e.reg.FinishLogin(l.ID, e.loginAssertion(l, *e.existing, e.existingCred))
	wantCode(t, err, CodeLoginNotFound)

	for i := 0; i < MaxPendingLogin; i++ {
		if _, err := e.reg.BeginLogin(); err != nil {
			t.Fatal(err)
		}
	}
	_, err = e.reg.BeginLogin()
	wantCode(t, err, CodeLoginLimit)
	// Expired ones are collected.
	e.clk.t = e.clk.t.Add(LoginTTL + time.Second)
	if _, err := e.reg.BeginLogin(); err != nil {
		t.Fatal(err)
	}
}

func TestRemovedCredentialCannotLogIn(t *testing.T) {
	e := newEnv(t, true)
	l, _ := e.reg.BeginLogin()
	as := e.loginAssertion(l, *e.existing, e.existingCred)
	if _, err := e.reg.Remove(e.existingCred.ID); err != nil {
		t.Fatal(err)
	}
	_, err := e.reg.FinishLogin(l.ID, as)
	wantCode(t, err, CodeLoginNotFound) // Remove cancels pending logins
	_, err = e.reg.BeginLogin()
	wantCode(t, err, CodeNoCredentials)
}
