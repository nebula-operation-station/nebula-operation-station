// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthnverify

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/descope/virtualwebauthn"
)

const (
	rpID   = "nebula.example.org"
	origin = "https://nebula.example.org"
)

type fixture struct {
	rp   virtualwebauthn.RelyingParty
	auth virtualwebauthn.Authenticator
	cred virtualwebauthn.Credential
	v    *Verifier
}

func newFixture(t *testing.T, opts virtualwebauthn.AuthenticatorOptions) *fixture {
	t.Helper()
	return newFixtureWith(t, opts, newMemCounters(), 0)
}

// newFixtureWith builds a verifier on the given counter store; fileCount is
// the sign counter recorded in the credential file.
func newFixtureWith(t *testing.T, opts virtualwebauthn.AuthenticatorOptions, counters CounterStore, fileCount uint32) *fixture {
	t.Helper()
	f := &fixture{
		rp:   virtualwebauthn.RelyingParty{Name: "Nebula", ID: rpID, Origin: origin},
		auth: virtualwebauthn.NewAuthenticatorWithOptions(opts),
		cred: virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2),
	}
	f.auth.AddCredential(f.cred)
	v, err := New(Config{RPID: rpID, Origins: []string{origin}, Counters: counters}, []Credential{{
		ID:        f.cred.ID,
		PublicKey: f.cred.Key.AttestationData(),
		SignCount: fileCount,
	}})
	if err != nil {
		t.Fatal(err)
	}
	f.v = v
	return f
}

func challenge(t *testing.T) []byte {
	t.Helper()
	c := make([]byte, 32)
	if _, err := rand.Read(c); err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fixture) sign(rp virtualwebauthn.RelyingParty, c []byte) []byte {
	return []byte(virtualwebauthn.CreateAssertionResponse(rp, f.auth, f.cred, virtualwebauthn.AssertionOptions{
		Challenge:      c,
		RelyingPartyID: rp.ID,
	}))
}

func TestValidAssertion(t *testing.T) {
	f := newFixture(t, virtualwebauthn.AuthenticatorOptions{})
	c := challenge(t)
	id, err := f.v.Verify(f.sign(f.rp, c), c, Requirement{UserVerification: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(id, f.cred.ID) {
		t.Fatal("wrong credential id returned")
	}
}

func TestWrongChallengeRejected(t *testing.T) {
	f := newFixture(t, virtualwebauthn.AuthenticatorOptions{})
	signed := f.sign(f.rp, challenge(t))
	if _, err := f.v.Verify(signed, challenge(t), Requirement{}); !errors.Is(err, ErrInvalidAssertion) {
		t.Fatalf("expected invalid assertion, got %v", err)
	}
}

func TestWrongOriginRejected(t *testing.T) {
	f := newFixture(t, virtualwebauthn.AuthenticatorOptions{})
	c := challenge(t)
	evil := virtualwebauthn.RelyingParty{Name: "x", ID: rpID, Origin: "https://evil.example.org"}
	if _, err := f.v.Verify(f.sign(evil, c), c, Requirement{}); !errors.Is(err, ErrInvalidAssertion) {
		t.Fatalf("expected invalid assertion, got %v", err)
	}
}

func TestWrongRPIDRejected(t *testing.T) {
	f := newFixture(t, virtualwebauthn.AuthenticatorOptions{})
	c := challenge(t)
	other := virtualwebauthn.RelyingParty{Name: "x", ID: "other.example.org", Origin: origin}
	if _, err := f.v.Verify(f.sign(other, c), c, Requirement{}); !errors.Is(err, ErrInvalidAssertion) {
		t.Fatalf("expected invalid assertion, got %v", err)
	}
}

func TestUserVerificationEnforced(t *testing.T) {
	f := newFixture(t, virtualwebauthn.AuthenticatorOptions{UserNotVerified: true})
	c := challenge(t)
	signed := f.sign(f.rp, c)
	if _, err := f.v.Verify(signed, c, Requirement{UserVerification: true}); !errors.Is(err, ErrInvalidAssertion) {
		t.Fatalf("UV required but accepted: %v", err)
	}
	// The same assertion is acceptable when only presence is required.
	if _, err := f.v.Verify(signed, c, Requirement{}); err != nil {
		t.Fatalf("presence-only should pass: %v", err)
	}
}

func TestUserPresenceAlwaysRequired(t *testing.T) {
	f := newFixture(t, virtualwebauthn.AuthenticatorOptions{UserNotPresent: true})
	c := challenge(t)
	if _, err := f.v.Verify(f.sign(f.rp, c), c, Requirement{}); !errors.Is(err, ErrInvalidAssertion) {
		t.Fatalf("missing UP accepted: %v", err)
	}
}

func TestUnknownCredentialRejected(t *testing.T) {
	f := newFixture(t, virtualwebauthn.AuthenticatorOptions{})
	stranger := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	c := challenge(t)
	signed := []byte(virtualwebauthn.CreateAssertionResponse(f.rp, f.auth, stranger, virtualwebauthn.AssertionOptions{Challenge: c, RelyingPartyID: rpID}))
	if _, err := f.v.Verify(signed, c, Requirement{}); !errors.Is(err, ErrUnknownCredential) {
		t.Fatalf("expected unknown credential, got %v", err)
	}
}

func TestSignatureFromOtherKeyRejected(t *testing.T) {
	f := newFixture(t, virtualwebauthn.AuthenticatorOptions{})
	// Same credential ID, different private key: the stored public key must win.
	forged := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	forged.ID = f.cred.ID
	c := challenge(t)
	signed := []byte(virtualwebauthn.CreateAssertionResponse(f.rp, f.auth, forged, virtualwebauthn.AssertionOptions{Challenge: c, RelyingPartyID: rpID}))
	if _, err := f.v.Verify(signed, c, Requirement{}); !errors.Is(err, ErrInvalidAssertion) {
		t.Fatalf("forged signature accepted: %v", err)
	}
}

func TestCounterMustIncrease(t *testing.T) {
	f := newFixture(t, virtualwebauthn.AuthenticatorOptions{})
	f.cred.Counter = 5
	c1 := challenge(t)
	if _, err := f.v.Verify(f.sign(f.rp, c1), c1, Requirement{}); err != nil {
		t.Fatal(err)
	}
	// Same counter again (cloned authenticator or replayed authenticator data).
	c2 := challenge(t)
	if _, err := f.v.Verify(f.sign(f.rp, c2), c2, Requirement{}); !errors.Is(err, ErrCounterRegression) {
		t.Fatalf("expected counter regression, got %v", err)
	}
	f.cred.Counter = 6
	c3 := challenge(t)
	if _, err := f.v.Verify(f.sign(f.rp, c3), c3, Requirement{}); err != nil {
		t.Fatalf("increased counter rejected: %v", err)
	}
}

func TestGarbageInputRejected(t *testing.T) {
	f := newFixture(t, virtualwebauthn.AuthenticatorOptions{})
	c := challenge(t)
	for _, in := range [][]byte{nil, []byte("{}"), []byte("not json"), bytes.Repeat([]byte("a"), MaxAssertionSize+1)} {
		if _, err := f.v.Verify(in, c, Requirement{}); err == nil {
			t.Fatalf("garbage accepted: %q", in)
		}
	}
	if _, err := f.v.Verify(f.sign(f.rp, c[:16]), c[:16], Requirement{}); err == nil {
		t.Fatal("short challenge accepted")
	}
}

func TestConfigValidation(t *testing.T) {
	m := newMemCounters()
	if _, err := New(Config{Origins: []string{origin}, Counters: m}, nil); err == nil {
		t.Fatal("missing RP ID accepted")
	}
	if _, err := New(Config{RPID: rpID, Counters: m}, nil); err == nil {
		t.Fatal("missing origins accepted")
	}
	c := Credential{ID: []byte{1}, PublicKey: []byte{2}}
	if _, err := New(Config{RPID: rpID, Origins: []string{origin}, Counters: m}, []Credential{c, c}); err == nil {
		t.Fatal("duplicate credential accepted")
	}
}

func FuzzVerifyNeverPanics(f *testing.F) {
	f.Add([]byte(`{"id":"AA","rawId":"AA","type":"public-key","response":{}}`))
	v, err := New(Config{RPID: rpID, Origins: []string{origin}, Counters: newMemCounters()}, nil)
	if err != nil {
		f.Fatal(err)
	}
	c := make([]byte, 32)
	f.Fuzz(func(t *testing.T, in []byte) {
		_, _ = v.Verify(in, c, Requirement{UserVerification: true})
	})
}
