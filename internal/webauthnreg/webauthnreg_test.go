// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthnreg

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

const (
	rpID   = "nebula.example.org"
	origin = "https://nebula.example.org"
)

// memStore implements Store and webauthnverify.CounterStore.
type memStore struct {
	mu       sync.Mutex
	creds    []executordb.WebAuthnCredential
	counters map[string]uint32
	failAdd  error
	failRm   error
}

func newMemStore() *memStore { return &memStore{counters: map[string]uint32{}} }

func (m *memStore) AddWebAuthnCredential(c executordb.WebAuthnCredential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failAdd != nil {
		return m.failAdd
	}
	for _, e := range m.creds {
		if bytes.Equal(e.ID, c.ID) {
			return executordb.ErrCredentialExists
		}
	}
	m.creds = append(m.creds, c)
	if c.SignCount > m.counters[string(c.ID)] {
		m.counters[string(c.ID)] = c.SignCount
	}
	return nil
}

func (m *memStore) RemoveWebAuthnCredential(id []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failRm != nil {
		return false, m.failRm
	}
	for i, e := range m.creds {
		if bytes.Equal(e.ID, id) {
			m.creds = append(m.creds[:i], m.creds[i+1:]...)
			return true, nil
		}
	}
	return false, nil
}

// SaveCounter makes memStore a webauthnverify.CounterStore.
func (m *memStore) SaveCounter(id []byte, n uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n > m.counters[string(id)] {
		m.counters[string(id)] = n
	}
	return nil
}

func (m *memStore) LoadCounters() (map[string]uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]uint32{}
	for k, v := range m.counters {
		out[k] = v
	}
	return out, nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

type env struct {
	t      *testing.T
	clk    *clock
	store  *memStore
	v      *webauthnverify.Verifier
	reg    *Registrar
	rp     virtualwebauthn.RelyingParty
	events []Event
	// existing is a pre-registered authenticator, if any.
	existing     *virtualwebauthn.Authenticator
	existingCred virtualwebauthn.Credential
}

func newEnv(t *testing.T, withExisting bool) *env {
	t.Helper()
	e := &env{t: t, clk: &clock{t: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}, store: newMemStore(),
		rp: virtualwebauthn.RelyingParty{Name: "Nebula", ID: rpID, Origin: origin}}
	var creds []webauthnverify.Credential
	if withExisting {
		a := virtualwebauthn.NewAuthenticator()
		e.existing = &a
		e.existingCred = virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
		e.existing.AddCredential(e.existingCred)
		creds = append(creds, webauthnverify.Credential{ID: e.existingCred.ID, PublicKey: e.existingCred.Key.AttestationData()})
	}
	v, err := webauthnverify.New(webauthnverify.Config{RPID: rpID, Origins: []string{origin}, Counters: e.store}, creds)
	if err != nil {
		t.Fatal(err)
	}
	e.v = v
	e.reg, err = New(Config{RPID: rpID, Origins: []string{origin}, Now: e.clk.now,
		Audit: func(ev Event) { e.events = append(e.events, ev) }}, v, e.store)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func wantCode(t *testing.T, err error, code Code) {
	t.Helper()
	if got := CodeOf(err); got != code {
		t.Fatalf("want %q, got %v", code, err)
	}
}

// newKey is a fresh authenticator with one new credential.
func newKey(opts virtualwebauthn.AuthenticatorOptions) (virtualwebauthn.Authenticator, virtualwebauthn.Credential) {
	a := virtualwebauthn.NewAuthenticatorWithOptions(opts)
	c := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
	a.AddCredential(c)
	return a, c
}

// attest answers the creation options of b with key (a, c) from rp.
func attest(t *testing.T, b Begin, rp virtualwebauthn.RelyingParty, a virtualwebauthn.Authenticator, c virtualwebauthn.Credential) []byte {
	t.Helper()
	opts, err := virtualwebauthn.ParseAttestationOptions(string(b.CreationOptions))
	if err != nil {
		t.Fatal(err)
	}
	if opts.RelyingPartyID != rpID {
		t.Fatalf("options name RP %q", opts.RelyingPartyID)
	}
	return []byte(virtualwebauthn.CreateAttestationResponse(rp, a, c, *opts))
}

func (e *env) authorize(b Begin, a virtualwebauthn.Authenticator, c virtualwebauthn.Credential) []byte {
	e.t.Helper()
	opts, err := virtualwebauthn.ParseAssertionOptions(string(b.AuthorizationOptions))
	if err != nil {
		e.t.Fatal(err)
	}
	return []byte(virtualwebauthn.CreateAssertionResponse(e.rp, a, c, *opts))
}

func (e *env) codeBegin() Begin {
	e.t.Helper()
	code, _, err := e.reg.CreateCode("axel", "YubiKey 5", "admin:uid1000")
	if err != nil {
		e.t.Fatal(err)
	}
	b, err := e.reg.Begin(code)
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

func TestFirstCredentialWithOneTimeCode(t *testing.T) {
	e := newEnv(t, false)
	code, exp, err := e.reg.CreateCode("axel", "YubiKey 5", "admin:uid1000")
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 24 || strings.Count(code, "-") != 4 || !exp.Equal(e.clk.t.Add(CodeTTL)) {
		t.Fatalf("code %q, expiry %v", code, exp)
	}
	b, err := e.reg.Begin(code)
	if err != nil {
		t.Fatal(err)
	}
	if b.AuthorizationOptions != nil {
		t.Fatal("code path asks for an assertion")
	}
	a, c := newKey(virtualwebauthn.AuthenticatorOptions{})
	res, err := e.reg.Finish(b.ID, attest(t, b, e.rp, a, c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.CredentialID, c.ID) || res.Label != "YubiKey 5" || res.UserName != "axel" || res.By != "code:admin:uid1000" {
		t.Fatalf("result %+v", res)
	}
	if len(e.store.creds) != 1 || !bytes.Equal(e.store.creds[0].PublicKey, c.Key.AttestationData()) || e.store.creds[0].CreatedBy != "code:admin:uid1000" {
		t.Fatalf("stored %+v", e.store.creds)
	}
	// The new credential works for approvals right away.
	ch := bytes.Repeat([]byte{7}, 32)
	as := virtualwebauthn.CreateAssertionResponse(e.rp, a, c, virtualwebauthn.AssertionOptions{Challenge: ch, RelyingPartyID: rpID})
	if _, err := e.v.Verify([]byte(as), ch, webauthnverify.Requirement{UserVerification: true}); err != nil {
		t.Fatalf("registered credential cannot sign: %v", err)
	}
}

func TestNoRegistrationWithoutCode(t *testing.T) {
	for _, existing := range []bool{false, true} {
		e := newEnv(t, existing)
		_, err := e.reg.Begin("")
		wantCode(t, err, CodeNotAllowed)
		// No code outstanding: any code is rejected.
		_, err = e.reg.Begin("ABCD-EFGH-JKMN-PQRS-TVWX")
		wantCode(t, err, CodeCodeInvalid)
	}
}

func TestCodeIsSingleUseAndExpires(t *testing.T) {
	e := newEnv(t, false)
	code, _, _ := e.reg.CreateCode("", "", "admin:uid1000")
	if _, err := e.reg.Begin(code); err != nil {
		t.Fatal(err)
	}
	_, err := e.reg.Begin(code)
	wantCode(t, err, CodeCodeInvalid)

	code, _, _ = e.reg.CreateCode("", "", "admin:uid1000")
	e.clk.t = e.clk.t.Add(CodeTTL)
	_, err = e.reg.Begin(code)
	wantCode(t, err, CodeCodeInvalid)
}

func TestCodeNormalization(t *testing.T) {
	e := newEnv(t, false)
	code, _, _ := e.reg.CreateCode("", "", "admin:uid1000")
	sloppy := strings.ToLower(strings.ReplaceAll(code, "-", " "))
	if _, err := e.reg.Begin(sloppy); err != nil {
		t.Fatalf("lower case with spaces rejected: %v", err)
	}
}

func TestWrongCodesInvalidateTheCode(t *testing.T) {
	e := newEnv(t, false)
	code, _, _ := e.reg.CreateCode("", "", "admin:uid1000")
	for i := 0; i < MaxCodeFailures; i++ {
		_, err := e.reg.Begin("0000-0000-0000-0000-0000")
		wantCode(t, err, CodeCodeInvalid)
	}
	_, err := e.reg.Begin(code)
	wantCode(t, err, CodeCodeInvalid)
	found := false
	for _, ev := range e.events {
		found = found || strings.Contains(ev.Detail, "code invalidated")
	}
	if !found {
		t.Fatal("invalidation not audited")
	}
}

func TestReplayedRegistrationIsRejected(t *testing.T) {
	e := newEnv(t, false)
	b := e.codeBegin()
	a, c := newKey(virtualwebauthn.AuthenticatorOptions{})
	att := attest(t, b, e.rp, a, c)
	if _, err := e.reg.Finish(b.ID, att, nil); err != nil {
		t.Fatal(err)
	}
	_, err := e.reg.Finish(b.ID, att, nil)
	wantCode(t, err, CodeNotFound)
	// The same attestation against a new registration (confirmed by the now
	// registered key, so the attestation check is reached): wrong challenge.
	b2 := e.codeBegin()
	_, err = e.reg.Finish(b2.ID, att, e.authorize(b2, a, c))
	wantCode(t, err, CodeAttestation)
}

func TestCrossOriginRegistrationIsRejected(t *testing.T) {
	for name, rp := range map[string]virtualwebauthn.RelyingParty{
		"foreign origin": {Name: "Evil", ID: rpID, Origin: "https://evil.example"},
		"foreign RP ID":  {Name: "Evil", ID: "evil.example", Origin: origin},
		"http origin":    {Name: "Nebula", ID: rpID, Origin: "http://nebula.example.org"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, false)
			b := e.codeBegin()
			a, c := newKey(virtualwebauthn.AuthenticatorOptions{})
			_, err := e.reg.Finish(b.ID, attest(t, b, rp, a, c), nil)
			wantCode(t, err, CodeAttestation)
			if len(e.store.creds) != 0 || e.v.Has(c.ID) {
				t.Fatal("credential registered")
			}
			// The registration is consumed by the failed attempt.
			_, err = e.reg.Finish(b.ID, attest(t, b, e.rp, a, c), nil)
			wantCode(t, err, CodeNotFound)
		})
	}
}

func TestUserVerificationIsRequired(t *testing.T) {
	e := newEnv(t, false)
	b := e.codeBegin()
	a, c := newKey(virtualwebauthn.AuthenticatorOptions{UserNotVerified: true})
	_, err := e.reg.Finish(b.ID, attest(t, b, e.rp, a, c), nil)
	wantCode(t, err, CodeAttestation)
}

// Further credentials need the code AND a user-verified assertion by a
// registered credential over this registration's challenge.
func TestFurtherCredentialNeedsCodeAndUserVerifiedAssertion(t *testing.T) {
	e := newEnv(t, true)
	a, c := newKey(virtualwebauthn.AuthenticatorOptions{})

	b := e.codeBegin()
	if b.AuthorizationOptions == nil {
		t.Fatal("no authorization options although a credential is registered")
	}
	_, err := e.reg.Finish(b.ID, attest(t, b, e.rp, a, c), nil)
	wantCode(t, err, CodeAssertion)

	// Assertion without user verification.
	b = e.codeBegin()
	noUV := *e.existing
	noUV.Options.UserNotVerified = true
	_, err = e.reg.Finish(b.ID, attest(t, b, e.rp, a, c), e.authorize(b, noUV, e.existingCred))
	wantCode(t, err, CodeAssertion)

	// Assertion over another registration's challenge.
	b1 := e.codeBegin()
	b2 := e.codeBegin()
	_, err = e.reg.Finish(b2.ID, attest(t, b2, e.rp, a, c), e.authorize(b1, *e.existing, e.existingCred))
	wantCode(t, err, CodeAssertion)

	// Assertion by a credential that is not registered (the new key
	// confirming itself).
	b = e.codeBegin()
	_, err = e.reg.Finish(b.ID, attest(t, b, e.rp, a, c), e.authorize(b, a, c))
	wantCode(t, err, CodeAssertion)
	if e.v.Has(c.ID) {
		t.Fatal("credential registered without a valid confirmation")
	}

	b = e.codeBegin()
	res, err := e.reg.Finish(b.ID, attest(t, b, e.rp, a, c), e.authorize(b, *e.existing, e.existingCred))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.By, "code:admin:uid1000+webauthn:") || res.Label != "YubiKey 5" || !e.v.Has(c.ID) {
		t.Fatalf("result %+v", res)
	}
}

// An assertion made for another ceremony (privileged session, permit) has a
// different challenge and cannot confirm a registration.
func TestForeignCeremonyAssertionCannotConfirm(t *testing.T) {
	e := newEnv(t, true)
	a, c := newKey(virtualwebauthn.AuthenticatorOptions{})
	b := e.codeBegin()
	sessionChallenge := bytes.Repeat([]byte{9}, 32)
	foreign := virtualwebauthn.CreateAssertionResponse(e.rp, *e.existing, e.existingCred,
		virtualwebauthn.AssertionOptions{Challenge: sessionChallenge, RelyingPartyID: rpID})
	_, err := e.reg.Finish(b.ID, attest(t, b, e.rp, a, c), []byte(foreign))
	wantCode(t, err, CodeAssertion)
}

func TestDuplicateCredentialIsRejected(t *testing.T) {
	e := newEnv(t, true)
	b := e.codeBegin()
	_, err := e.reg.Finish(b.ID, attest(t, b, e.rp, *e.existing, e.existingCred), e.authorize(b, *e.existing, e.existingCred))
	wantCode(t, err, CodeExists)
}

func TestPendingRegistrationsAreBounded(t *testing.T) {
	e := newEnv(t, true)
	for i := 0; i < MaxPending; i++ {
		e.codeBegin()
	}
	code, _, _ := e.reg.CreateCode("", "", "admin:uid1000")
	_, err := e.reg.Begin(code)
	wantCode(t, err, CodeLimit)
	// The limit check comes before the code is consumed.
	e.clk.t = e.clk.t.Add(RegistrationTTL)
	if _, err := e.reg.Begin(code); err != nil {
		t.Fatalf("expired registrations not collected, or code consumed by the rejected attempt: %v", err)
	}
}

func TestExpiredRegistrationIsRejected(t *testing.T) {
	e := newEnv(t, false)
	b := e.codeBegin()
	a, c := newKey(virtualwebauthn.AuthenticatorOptions{})
	att := attest(t, b, e.rp, a, c)
	e.clk.t = e.clk.t.Add(RegistrationTTL)
	_, err := e.reg.Finish(b.ID, att, nil)
	if c := CodeOf(err); c != CodeExpired && c != CodeNotFound {
		t.Fatalf("expired registration: %v", err)
	}
}

func TestStoreFailureDoesNotActivate(t *testing.T) {
	e := newEnv(t, false)
	b := e.codeBegin()
	e.store.failAdd = errors.New("disk full at /var/lib/nebula/executor/executor.db")
	a, c := newKey(virtualwebauthn.AuthenticatorOptions{})
	_, err := e.reg.Finish(b.ID, attest(t, b, e.rp, a, c), nil)
	wantCode(t, err, CodeStorage)
	if strings.Contains(err.Error(), "executor.db") {
		t.Fatalf("store detail leaked: %v", err)
	}
	if e.v.Has(c.ID) {
		t.Fatal("credential active although it was not stored")
	}
}

func TestFirstCredentialTakesNoAssertion(t *testing.T) {
	e := newEnv(t, false)
	b := e.codeBegin()
	a, c := newKey(virtualwebauthn.AuthenticatorOptions{})
	_, err := e.reg.Finish(b.ID, attest(t, b, e.rp, a, c), []byte(`{"id":"x"}`))
	wantCode(t, err, CodeInvalidRequest)
}

func TestUserPresenceIsRequired(t *testing.T) {
	e := newEnv(t, false)
	b := e.codeBegin()
	a, c := newKey(virtualwebauthn.AuthenticatorOptions{UserNotPresent: true})
	_, err := e.reg.Finish(b.ID, attest(t, b, e.rp, a, c), nil)
	wantCode(t, err, CodeAttestation)
}

// Removing a credential cancels the outstanding code and every pending
// registration, and the removed credential can no longer confirm anything.
func TestRemoveCancelsRegistrations(t *testing.T) {
	e := newEnv(t, true)
	b := e.codeBegin()
	code, _, _ := e.reg.CreateCode("", "", "admin:uid1000")
	removed, err := e.reg.Remove(e.existingCred.ID)
	if err != nil || !removed {
		t.Fatalf("remove: %v %v", removed, err)
	}
	if e.v.Has(e.existingCred.ID) {
		t.Fatal("removed credential still active")
	}
	a, c := newKey(virtualwebauthn.AuthenticatorOptions{})
	_, err = e.reg.Finish(b.ID, attest(t, b, e.rp, a, c), e.authorize(b, *e.existing, e.existingCred))
	wantCode(t, err, CodeNotFound)
	_, err = e.reg.Begin(code)
	wantCode(t, err, CodeCodeInvalid)
	// Lock (Reset) does the same.
	code, _, _ = e.reg.CreateCode("", "", "admin:uid1000")
	e.reg.Reset("test")
	_, err = e.reg.Begin(code)
	wantCode(t, err, CodeCodeInvalid)
}

func TestCounterIsStoredWithTheCredential(t *testing.T) {
	e := newEnv(t, false)
	b := e.codeBegin()
	a, c := newKey(virtualwebauthn.AuthenticatorOptions{})
	c.Counter = 42
	if _, err := e.reg.Finish(b.ID, attest(t, b, e.rp, a, c), nil); err != nil {
		t.Fatal(err)
	}
	if e.store.creds[0].SignCount != 42 || e.store.counters[string(c.ID)] != 42 {
		t.Fatalf("counter not stored with the credential: %+v", e.store.creds[0])
	}
}

func TestWeakOrUnusableKeysAreRejected(t *testing.T) {
	ec := func(crv int64, n int) []byte {
		b, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
			PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.EllipticKey), Algorithm: int64(webauthncose.AlgES256)},
			Curve:         crv, XCoord: bytes.Repeat([]byte{1}, n), YCoord: bytes.Repeat([]byte{2}, n),
		})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	rsa := func(bits int) []byte {
		b, err := webauthncbor.Marshal(webauthncose.RSAPublicKeyData{
			PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.RSAKey), Algorithm: int64(webauthncose.AlgRS256)},
			Modulus:       append([]byte{0x80}, make([]byte, bits/8-1)...), Exponent: []byte{1, 0, 1},
		})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for name, key := range map[string][]byte{
		"P-384 curve": ec(2, 48),
		"short coord": ec(1, 16),
		"RSA 1024":    rsa(1024),
		"garbage":     {0xff, 0x00},
	} {
		if err := checkPublicKey(key); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := checkPublicKey(rsa(2048)); err != nil {
		t.Errorf("RSA 2048 rejected: %v", err)
	}
	_, c := newKey(virtualwebauthn.AuthenticatorOptions{})
	if err := checkPublicKey(c.Key.AttestationData()); err != nil {
		t.Errorf("P-256 key rejected: %v", err)
	}
}

func TestCodeNormalizationAcceptsUnicodeSeparators(t *testing.T) {
	e := newEnv(t, false)
	code, _, _ := e.reg.CreateCode("", "", "admin:uid1000")
	fancy := strings.ReplaceAll(code, "-", "–") // en dash, as some keyboards produce
	if _, err := e.reg.Begin(fancy); err != nil {
		t.Fatalf("code with en dashes rejected: %v", err)
	}
}

func TestCreateCodeValidatesText(t *testing.T) {
	e := newEnv(t, false)
	if _, _, err := e.reg.CreateCode("axel", "a\x1b[2J", "admin"); CodeOf(err) != CodeInvalidRequest {
		t.Fatalf("escape in label: %v", err)
	}
	if _, _, err := e.reg.CreateCode(strings.Repeat("x", 65), "", "admin"); CodeOf(err) != CodeInvalidRequest {
		t.Fatalf("long user name: %v", err)
	}
}

// Two registrations begun while no credential exists: the first to finish
// becomes the first credential, the second must not register without a
// confirmation.
func TestFirstCredentialRaceNeedsConfirmation(t *testing.T) {
	e := newEnv(t, false)
	b1 := e.codeBegin()
	b2 := e.codeBegin()
	if b1.AuthorizationOptions != nil || b2.AuthorizationOptions != nil {
		t.Fatal("authorization options without a registered credential")
	}
	a1, c1 := newKey(virtualwebauthn.AuthenticatorOptions{})
	if _, err := e.reg.Finish(b1.ID, attest(t, b1, e.rp, a1, c1), nil); err != nil {
		t.Fatal(err)
	}
	a2, c2 := newKey(virtualwebauthn.AuthenticatorOptions{})
	_, err := e.reg.Finish(b2.ID, attest(t, b2, e.rp, a2, c2), nil)
	wantCode(t, err, CodeAssertion)
	if e.v.Has(c2.ID) || len(e.store.creds) != 1 {
		t.Fatal("second credential registered without a confirmation")
	}
}

// A store failure on removal still deactivates the credential, and says
// plainly that the removal was not stored.
func TestRemoveStoreFailureIsExplicit(t *testing.T) {
	e := newEnv(t, false)
	b := e.codeBegin()
	a, c := newKey(virtualwebauthn.AuthenticatorOptions{})
	if _, err := e.reg.Finish(b.ID, attest(t, b, e.rp, a, c), nil); err != nil {
		t.Fatal(err)
	}
	e.store.failRm = errors.New("disk full")
	removed, err := e.reg.Remove(c.ID)
	if !errors.Is(err, ErrRemovalNotStored) || !removed {
		t.Fatalf("remove: %v %v", removed, err)
	}
	if e.v.Has(c.ID) {
		t.Fatal("credential still active after a failed store removal")
	}
	if len(e.store.creds) != 1 {
		t.Fatal("store row gone although the store failed")
	}
	// Retry succeeds.
	e.store.failRm = nil
	if removed, err = e.reg.Remove(c.ID); err != nil || !removed {
		t.Fatalf("retry: %v %v", removed, err)
	}
	if len(e.store.creds) != 0 {
		t.Fatal("store row left after retry")
	}
}
