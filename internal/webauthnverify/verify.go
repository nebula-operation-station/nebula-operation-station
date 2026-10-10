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

// Config describes the relying party as the executor knows it.
type Config struct {
	// RPID is the fixed hostname Nebula is served under (never an IP).
	RPID string
	// Origins are the exact allowed origins, e.g. "https://nebula.example.org".
	Origins []string
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
)

// Verifier holds the credentials and verifies assertions. It is safe for
// concurrent use; verification of the same credential is serialized so that
// counter checks cannot race.
type Verifier struct {
	cfg   Config
	mu    sync.Mutex
	creds map[string]*Credential
}

// New returns a verifier. RPID and at least one origin are required.
func New(cfg Config, creds []Credential) (*Verifier, error) {
	if cfg.RPID == "" {
		return nil, errors.New("webauthn: RP ID is required")
	}
	if len(cfg.Origins) == 0 {
		return nil, errors.New("webauthn: at least one origin is required")
	}
	v := &Verifier{cfg: cfg, creds: make(map[string]*Credential, len(creds))}
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
	v.creds[k] = &cp
	return nil
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
	cred.SignCount = newCount
	return bytes.Clone(cred.ID), nil
}
