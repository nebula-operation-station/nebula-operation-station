// SPDX-License-Identifier: AGPL-3.0-or-later

// Package webauthnverify verifies WebAuthn assertions inside the executor.
//
// The executor never trusts the web server's opinion of an assertion. It
// holds the credential public keys itself and checks challenge, RP ID hash,
// origin, user presence/verification flags, signature and signature counter.
// Challenge single-use is enforced by the caller (internal/permit), because
// only the caller knows which challenge was issued for which purpose.
package webauthnverify

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
)

// MaxAssertionSize bounds the JSON accepted from the browser.
const MaxAssertionSize = 16 << 10

// Credential is a registered authenticator credential.
type Credential struct {
	ID         []byte `json:"id"`
	PublicKey  []byte `json:"public_key"` // COSE_Key
	SignCount  uint32 `json:"sign_count"`
	UserHandle []byte `json:"user_handle,omitempty"`
	Label      string `json:"label,omitempty"`
}

// CounterStore persists signature counters so that a restart cannot reset
// them (internal/executordb implements it).
type CounterStore interface {
	// LoadCounters returns the stored counter of every credential, keyed by
	// the raw credential ID.
	LoadCounters() (map[string]uint32, error)
	// SaveCounter durably stores a new counter value. It must never lower a
	// stored value. Verify calls it before it reports success.
	SaveCounter(credentialID []byte, count uint32) error
}

// Config describes the relying party as the executor knows it.
type Config struct {
	// RPID is the fixed hostname Nebula is served under (never an IP).
	RPID string
	// Origins are the exact allowed origins, e.g. "https://nebula.example.org".
	Origins []string
	// Counters persists signature counters. Required.
	Counters CounterStore
}

// Requirement selects the flags an assertion must carry.
type Requirement struct {
	UserVerification bool
}

// Errors returned by Verify. They are deliberately coarse: details go to the
// executor log, not to the caller.
var (
	ErrUnknownCredential = errors.New("webauthn: unknown credential")
	ErrInvalidAssertion  = errors.New("webauthn: assertion invalid")
	ErrCounterRegression = errors.New("webauthn: signature counter did not increase (possible cloned authenticator or replay)")
	ErrCounterStore      = errors.New("webauthn: signature counter could not be stored")
)

// Verifier holds the credentials and verifies assertions. It is safe for
// concurrent use; verification of the same credential is serialized so that
// counter checks cannot race.
type Verifier struct {
	cfg    Config
	mu     sync.Mutex
	creds  map[string]*Credential
	stored map[string]uint32 // counters loaded from the store at startup
}

// New returns a verifier. RPID, at least one origin and a counter store are
// required. Each credential starts at the higher of the counter in creds and
// the stored counter, so neither a stale credential file nor a lost store
// can lower it.
func New(cfg Config, creds []Credential) (*Verifier, error) {
	if cfg.RPID == "" {
		return nil, errors.New("webauthn: RP ID is required")
	}
	if len(cfg.Origins) == 0 {
		return nil, errors.New("webauthn: at least one origin is required")
	}
	if cfg.Counters == nil {
		return nil, errors.New("webauthn: a counter store is required")
	}
	stored, err := cfg.Counters.LoadCounters()
	if err != nil {
		return nil, fmt.Errorf("webauthn: load signature counters: %w", err)
	}
	if stored == nil {
		stored = map[string]uint32{}
	}
	v := &Verifier{cfg: cfg, creds: make(map[string]*Credential, len(creds)), stored: stored}
	for i := range creds {
		if err := v.add(creds[i]); err != nil {
			return nil, err
		}
	}
	return v, nil
}

// Add registers a credential. Registration ceremonies (Milestone 2) call it
// after verifying an attestation; until then credentials are loaded from the
// executor's private store.
func (v *Verifier) Add(c Credential) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.add(c)
}

func (v *Verifier) add(c Credential) error {
	if len(c.ID) == 0 || len(c.PublicKey) == 0 {
		return errors.New("webauthn: credential needs id and public key")
	}
	k := string(c.ID)
	if _, dup := v.creds[k]; dup {
		return errors.New("webauthn: duplicate credential id")
	}
	cp := c
	cp.ID = bytes.Clone(c.ID)
	cp.PublicKey = bytes.Clone(c.PublicKey)
	cp.UserHandle = bytes.Clone(c.UserHandle)
	if n := v.stored[k]; n > cp.SignCount {
		cp.SignCount = n
	}
	v.creds[k] = &cp
	return nil
}

// Remove unregisters a credential and reports whether it was registered.
// Its stored counter is kept, so a re-registered credential cannot start
// below it.
func (v *Verifier) Remove(id []byte) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	k := string(id)
	c, ok := v.creds[k]
	if !ok {
		return false
	}
	if c.SignCount > v.stored[k] {
		v.stored[k] = c.SignCount
	}
	delete(v.creds, k)
	return true
}

// Has reports whether a credential is registered.
func (v *Verifier) Has(id []byte) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, ok := v.creds[string(id)]
	return ok
}

// Credentials returns copies of all registered credentials.
func (v *Verifier) Credentials() []Credential {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]Credential, 0, len(v.creds))
	for _, c := range v.creds {
		cp := *c
		cp.ID = bytes.Clone(c.ID)
		cp.PublicKey = bytes.Clone(c.PublicKey)
		cp.UserHandle = bytes.Clone(c.UserHandle)
		out = append(out, cp)
	}
	return out
}

// Count returns the number of registered credentials.
func (v *Verifier) Count() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.creds)
}

// RPID returns the configured relying party ID.
func (v *Verifier) RPID() string { return v.cfg.RPID }

// Verify checks assertionJSON against the expected challenge bytes and
// returns the ID of the credential that signed it. On success the stored
// signature counter is advanced.
func (v *Verifier) Verify(assertionJSON, challenge []byte, req Requirement) ([]byte, error) {
	if len(assertionJSON) == 0 || len(assertionJSON) > MaxAssertionSize {
		return nil, ErrInvalidAssertion
	}
	if len(challenge) < 32 {
		return nil, fmt.Errorf("%w: challenge too short", ErrInvalidAssertion)
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(assertionJSON)
	if err != nil {
		return nil, fmt.Errorf("%w: parse: %v", ErrInvalidAssertion, err)
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	cred, ok := v.creds[string(parsed.RawID)]
	if !ok {
		return nil, ErrUnknownCredential
	}
	if uh := parsed.Response.UserHandle; len(uh) > 0 && len(cred.UserHandle) > 0 && !bytes.Equal(uh, cred.UserHandle) {
		return nil, fmt.Errorf("%w: user handle mismatch", ErrInvalidAssertion)
	}

	err = parsed.Verify(
		base64.RawURLEncoding.EncodeToString(challenge),
		v.cfg.RPID,
		"", // no FIDO AppID extension
		v.cfg.Origins,
		nil, // no opaque origins
		nil, // no top origins: cross-origin use is not allowed
		protocol.TopOriginExplicitVerificationMode,
		false, // allowCrossOrigin
		req.UserVerification,
		true, // user presence always required
		cred.PublicKey,
		protocol.SignaturePolicy{},
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAssertion, err)
	}

	// Signature counter (WebAuthn §6.1.1): if either value is non-zero the new
	// counter must be strictly greater. Many passkeys always report zero,
	// which is why challenge single-use in internal/permit is the primary
	// replay defence.
	newCount := parsed.Response.AuthenticatorData.Counter
	if newCount != 0 || cred.SignCount != 0 {
		if newCount <= cred.SignCount {
			return nil, ErrCounterRegression
		}
	}
	// Persist before reporting success, and advance the in-memory value only
	// after the store accepted it: an assertion whose counter cannot be
	// recorded is rejected, so a restart can never re-accept it.
	if newCount != cred.SignCount {
		if err := v.cfg.Counters.SaveCounter(cred.ID, newCount); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCounterStore, err)
		}
		cred.SignCount = newCount
		if newCount > v.stored[string(cred.ID)] {
			v.stored[string(cred.ID)] = newCount // a later Remove and Add must not start lower
		}
	}
	return bytes.Clone(cred.ID), nil
}
