// SPDX-License-Identifier: AGPL-3.0-or-later

// Package webauthnreg implements the WebAuthn registration ceremony inside
// the executor (H03, docs/spec/05-authentication.md), and the web login
// ceremony (M2, login.go) over the same credentials.
//
// There is no unauthenticated registration, and the browser alone can never
// add a credential. Every registration starts with a one-time code that an
// admin creates on the executor host (`nebula webauthn code`: 100 bits,
// 15 minutes, single use, five wrong attempts invalidate it). The code is
// typed into the browser; BeginRegistration consumes it.
//
//   - First credential: the code is enough.
//   - Further credentials: FinishRegistration must also carry a
//     user-verified assertion by an already registered credential over a
//     challenge that belongs to this registration (spec 05).
//
// Requiring the code for further credentials too means a compromised
// server cannot turn one hijacked authenticator gesture into a permanent
// credential of its own. Recovery after losing every key: remove the lost
// credentials with `nebula webauthn remove`, then the code alone suffices.
//
// The attestation is verified with go-webauthn (challenge, origin, RP ID,
// user presence and verification, algorithm, attestation statement). Each
// registration challenge is single-use: FinishRegistration deletes the
// pending registration before it verifies anything. Credential public keys
// are stored only in the executor's database.
package webauthnreg

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"

	"github.com/nebula-operation-station/nebula-operation-station/internal/executordb"
	"github.com/nebula-operation-station/nebula-operation-station/internal/webauthnverify"
)

// Limits and timings.
const (
	CodeTTL          = 15 * time.Minute
	RegistrationTTL  = 5 * time.Minute
	MaxPending       = 4
	MaxCodeFailures  = 5
	MaxResponseSize  = webauthnverify.MaxAssertionSize
	codeChars        = 20 // 100 bits in Crockford base32
	maxUserNameBytes = 64
	maxLabelBytes    = 200
	defaultUserName  = "admin"
)

// Code classifies registration failures; the string form is stable.
type Code string

// Failure codes.
const (
	CodeInvalidRequest Code = "invalid_request"
	CodeCodeInvalid    Code = "registration_code_invalid"
	CodeNotAllowed     Code = "registration_not_allowed"
	CodeNotFound       Code = "registration_not_found"
	CodeExpired        Code = "registration_expired"
	CodeAttestation    Code = "attestation_rejected"
	CodeAssertion      Code = "assertion_rejected"
	CodeExists         Code = "credential_exists"
	CodeLimit          Code = "limit_exceeded"
	CodeStorage        Code = "storage_error"
)

// Error is a registration failure.
type Error struct {
	Code   Code
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Detail
}

func fail(code Code, format string, args ...any) error {
	return &Error{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// CodeOf returns the failure code of err, or "".
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Store persists credentials and counters (internal/executordb).
type Store interface {
	// AddWebAuthnCredential stores a credential and its initial signature
	// counter atomically; ErrCredentialExists for a stored ID.
	AddWebAuthnCredential(executordb.WebAuthnCredential) error
	// RemoveWebAuthnCredential deletes a credential (counter kept).
	RemoveWebAuthnCredential(id []byte) (bool, error)
}

// Event is an audit record.
type Event struct {
	Kind       string // registration_code_created, registration_code_rejected, registration_started, credential_registered, registration_rejected
	Credential string // hex credential ID, when known
	By         string
	Detail     string
}

// Config configures a Registrar.
type Config struct {
	RPID    string
	RPName  string
	Origins []string
	Now     func() time.Time
	Audit   func(Event)
}

// Registrar runs registration ceremonies. It is safe for concurrent use.
type Registrar struct {
	cfg      Config
	verifier *webauthnverify.Verifier
	store    Store

	mu       sync.Mutex
	code     *oneTimeCode
	failures int
	pending  map[string]*registration
	logins   map[string]*pendingLogin
}

type oneTimeCode struct {
	hash     [sha256.Size]byte
	userName string
	label    string
	by       string
	expiry   time.Time
}

type registration struct {
	challenge     []byte
	authChallenge []byte // nil for the one-time-code path
	userHandle    []byte
	userName      string
	label         string // from the code (set by the admin on the executor host)
	via           string
	expiry        time.Time
}

// errNoRandom is returned when the system random source fails.
var errNoRandom = errors.New("webauthnreg: no randomness")

// New returns a Registrar.
func New(cfg Config, v *webauthnverify.Verifier, store Store) (*Registrar, error) {
	switch {
	case cfg.RPID == "" || len(cfg.Origins) == 0:
		return nil, errors.New("webauthnreg: RP ID and origins are required")
	case v == nil || store == nil:
		return nil, errors.New("webauthnreg: verifier and store are required")
	}
	if cfg.RPName == "" {
		cfg.RPName = "Nebula Operation Station"
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Audit == nil {
		cfg.Audit = func(Event) {}
	}
	return &Registrar{cfg: cfg, verifier: v, store: store, pending: map[string]*registration{}, logins: map[string]*pendingLogin{}}, nil
}

var codeEncoding = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// CreateCode issues a new one-time code for the next registration and
// replaces any earlier unused one. by names the admin (UID) asking for it.
func (r *Registrar) CreateCode(userName, label, by string) (string, time.Time, error) {
	if userName == "" {
		userName = defaultUserName
	}
	if err := checkText("user name", userName, maxUserNameBytes, false); err != nil {
		return "", time.Time{}, err
	}
	if err := checkText("label", label, maxLabelBytes, true); err != nil {
		return "", time.Time{}, err
	}
	raw := make([]byte, 13)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	plain := codeEncoding.EncodeToString(raw)[:codeChars]

	r.mu.Lock()
	defer r.mu.Unlock()
	exp := r.cfg.Now().Add(CodeTTL)
	replaced := r.code != nil
	r.code = &oneTimeCode{hash: sha256.Sum256([]byte(plain)), userName: userName, label: label, by: by, expiry: exp}
	r.failures = 0
	detail := "user " + userName
	if replaced {
		detail += "; replaces an unused code"
	}
	r.cfg.Audit(Event{Kind: "registration_code_created", By: by, Detail: detail})
	var groups []string
	for i := 0; i < codeChars; i += 4 {
		groups = append(groups, plain[i:i+4])
	}
	return strings.Join(groups, "-"), exp, nil
}

// normalizeCode accepts lower case, spaces and dashes and the usual
// Crockford confusions (O for 0, I and L for 1).
func normalizeCode(s string) (string, bool) {
	s = strings.Map(func(c rune) rune {
		if unicode.IsSpace(c) || unicode.Is(unicode.Pd, c) {
			return -1 // any space or dash is a separator
		}
		return unicode.ToUpper(c)
	}, s)
	s = strings.NewReplacer("O", "0", "I", "1", "L", "1").Replace(s)
	if len(s) != codeChars {
		return "", false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789ABCDEFGHJKMNPQRSTVWXYZ", c) {
			return "", false
		}
	}
	return s, true
}

// Begin is the result of BeginRegistration.
type Begin struct {
	ID string
	// CreationOptions is a CredentialCreationOptions JSON document
	// ({"publicKey": ...}) for navigator.credentials.create().
	CreationOptions []byte
	// AuthorizationOptions is a CredentialRequestOptions JSON document for
	// navigator.credentials.get(), or nil on the one-time-code path. The
	// assertion must be user-verified and come from a registered credential.
	AuthorizationOptions []byte
	Expiry               time.Time
}

// Begin starts a registration with a one-time code. If credentials are
// already registered, the result also carries authorization options: the
// registration must then be confirmed by one of them (user-verified).
func (r *Registrar) Begin(code string) (Begin, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.cfg.Now()
	r.gcLocked(now)
	if code == "" {
		return Begin{}, fail(CodeNotAllowed, "a one-time code is required: run `nebula webauthn code` on the executor host")
	}
	if len(r.pending) >= MaxPending {
		return Begin{}, fail(CodeLimit, "too many registrations in progress")
	}
	if err := r.consumeCodeLocked(code, now); err != nil {
		return Begin{}, err
	}
	c := r.code
	r.code, r.failures = nil, 0

	reg := &registration{
		expiry: now.Add(RegistrationTTL), userName: c.userName, label: c.label, via: "code:" + c.by,
		challenge: random(32), userHandle: random(16),
	}
	if r.verifier.Count() > 0 {
		reg.authChallenge = random(32)
		if reg.authChallenge == nil {
			return Begin{}, errNoRandom
		}
	}
	idb := random(16)
	if reg.challenge == nil || reg.userHandle == nil || idb == nil {
		return Begin{}, errNoRandom
	}
	id := hex.EncodeToString(idb)
	out := Begin{ID: id, Expiry: reg.expiry}
	var err error
	if out.CreationOptions, err = r.creationOptions(reg); err != nil {
		return Begin{}, err
	}
	if reg.authChallenge != nil {
		if out.AuthorizationOptions, err = r.requestOptions(reg.authChallenge); err != nil {
			return Begin{}, err
		}
	}
	r.pending[id] = reg
	path := "first credential"
	if reg.authChallenge != nil {
		path = "further credential, needs confirmation by a registered one"
	}
	r.cfg.Audit(Event{Kind: "registration_started", By: reg.via, Detail: path + ", user " + reg.userName})
	return out, nil
}

func (r *Registrar) consumeCodeLocked(code string, now time.Time) error {
	norm, ok := normalizeCode(code)
	if r.code == nil || !now.Before(r.code.expiry) {
		r.code = nil
		r.cfg.Audit(Event{Kind: "registration_code_rejected", Detail: "no valid code is outstanding"})
		return fail(CodeCodeInvalid, "registration code is invalid or expired")
	}
	h := sha256.Sum256([]byte(norm))
	if !ok || subtle.ConstantTimeCompare(h[:], r.code.hash[:]) != 1 {
		r.failures++
		detail := fmt.Sprintf("wrong code (%d of %d)", r.failures, MaxCodeFailures)
		if r.failures >= MaxCodeFailures {
			r.code, r.failures = nil, 0
			detail += "; code invalidated"
		}
		r.cfg.Audit(Event{Kind: "registration_code_rejected", Detail: detail})
		return fail(CodeCodeInvalid, "registration code is invalid or expired")
	}
	return nil
}

var credParams = []protocol.CredentialParameter{
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgEdDSA},
	{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgRS256},
}

func (r *Registrar) creationOptions(reg *registration) ([]byte, error) {
	var exclude []protocol.CredentialDescriptor
	for _, c := range r.verifier.Credentials() {
		exclude = append(exclude, protocol.CredentialDescriptor{Type: protocol.PublicKeyCredentialType, CredentialID: c.ID})
	}
	return json.Marshal(protocol.CredentialCreation{Response: protocol.PublicKeyCredentialCreationOptions{
		RelyingParty: protocol.RelyingPartyEntity{CredentialEntity: protocol.CredentialEntity{Name: r.cfg.RPName}, ID: r.cfg.RPID},
		User: protocol.UserEntity{
			CredentialEntity: protocol.CredentialEntity{Name: reg.userName},
			DisplayName:      reg.userName,
			ID:               protocol.URLEncodedBase64(reg.userHandle),
		},
		Challenge:             reg.challenge,
		Parameters:            credParams,
		Timeout:               int(RegistrationTTL / time.Millisecond),
		CredentialExcludeList: exclude,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationRequired,
		},
		Attestation: protocol.PreferNoAttestation,
	}})
}

func (r *Registrar) requestOptions(challenge []byte) ([]byte, error) {
	return r.RequestOptions(challenge, RegistrationTTL)
}

// RequestOptions returns CredentialRequestOptions JSON for
// navigator.credentials.get(): the challenge, every registered credential,
// and user verification required. The privileged session (permit) uses it
// for its own challenge.
func (r *Registrar) RequestOptions(challenge []byte, timeout time.Duration) ([]byte, error) {
	var allow []protocol.CredentialDescriptor
	for _, c := range r.verifier.Credentials() {
		allow = append(allow, protocol.CredentialDescriptor{Type: protocol.PublicKeyCredentialType, CredentialID: c.ID})
	}
	return json.Marshal(protocol.CredentialAssertion{Response: protocol.PublicKeyCredentialRequestOptions{
		Challenge:          challenge,
		Timeout:            int(timeout / time.Millisecond),
		RelyingPartyID:     r.cfg.RPID,
		AllowedCredentials: allow,
		UserVerification:   protocol.VerificationRequired,
	}})
}

// Result describes a newly registered credential.
type Result struct {
	CredentialID []byte
	UserName     string
	Label        string
	AAGUID       []byte
	Format       string
	By           string
}

// Finish completes a registration. The pending registration is consumed
// first, so a failed or replayed attempt cannot be retried with the same
// challenge.
func (r *Registrar) Finish(id string, attestationJSON, assertionJSON []byte) (Result, error) {
	if len(attestationJSON) == 0 || len(attestationJSON) > MaxResponseSize || len(assertionJSON) > MaxResponseSize {
		return Result{}, fail(CodeInvalidRequest, "attestation or assertion size out of range")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.cfg.Now()
	reg, ok := r.pending[id]
	if !ok {
		return Result{}, fail(CodeNotFound, "no such registration (it may have been used already)")
	}
	delete(r.pending, id)
	if !now.Before(reg.expiry) {
		return Result{}, fail(CodeExpired, "registration expired")
	}

	by := reg.via
	if reg.authChallenge != nil {
		if len(assertionJSON) == 0 {
			return Result{}, r.reject(reg, CodeAssertion, "a user-verified assertion by a registered credential is required")
		}
		authID, err := r.verifier.Verify(assertionJSON, reg.authChallenge, webauthnverify.Requirement{UserVerification: true})
		if errors.Is(err, webauthnverify.ErrCounterStore) {
			r.cfg.Audit(Event{Kind: "registration_rejected", Detail: err.Error()})
			return Result{}, fail(CodeStorage, "executor state store unavailable")
		}
		if err != nil {
			return Result{}, r.reject(reg, CodeAssertion, "%v", err)
		}
		by += "+webauthn:" + hex.EncodeToString(authID)
	} else {
		// Whether a confirmation is needed was decided at Begin. If another
		// registration added the first credential in between, this one was
		// begun as "first" but no longer is: it must start again and be
		// confirmed like every further credential.
		if r.verifier.Count() > 0 {
			return Result{}, r.reject(reg, CodeAssertion, "a credential was registered since this registration began; start again")
		}
		if len(assertionJSON) != 0 {
			return Result{}, r.reject(reg, CodeInvalidRequest, "no assertion is expected for the first credential")
		}
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(attestationJSON)
	if err != nil {
		return Result{}, r.reject(reg, CodeAttestation, "parse: %v", err)
	}
	if _, err := parsed.Verify(
		base64.RawURLEncoding.EncodeToString(reg.challenge),
		r.cfg.RPID,
		r.cfg.Origins,
		nil, // no opaque origins
		nil, // no top origins: cross-origin use is not allowed
		protocol.TopOriginExplicitVerificationMode,
		false, // allowCrossOrigin
		true,  // user verification required
		true,  // user presence required
		nil,   // no metadata service: authenticator models are not restricted
		credParams,
		protocol.AttestationPolicy{},
		protocol.SignaturePolicy{},
	); err != nil {
		return Result{}, r.reject(reg, CodeAttestation, "%v", err)
	}
	ad := parsed.Response.AttestationObject.AuthData
	credID, pub := ad.AttData.CredentialID, ad.AttData.CredentialPublicKey
	if err := checkPublicKey(pub); err != nil {
		return Result{}, r.reject(reg, CodeAttestation, "%v", err)
	}
	if r.verifier.Has(credID) {
		return Result{}, r.reject(reg, CodeExists, "credential is already registered")
	}
	aaguid := ad.AttData.AAGUID
	if len(aaguid) != 16 {
		aaguid = nil
	}
	format := parsed.Response.AttestationObject.Format

	// Credential and initial counter are stored in one transaction, and only
	// for an ID that is not stored yet.
	rec := executordb.WebAuthnCredential{
		ID: credID, PublicKey: pub, UserHandle: reg.userHandle, UserName: reg.userName, Label: reg.label,
		AAGUID: aaguid, AttestationFormat: format, CreatedBy: by, SignCount: ad.Counter,
	}
	switch err := r.store.AddWebAuthnCredential(rec); {
	case errors.Is(err, executordb.ErrCredentialExists):
		return Result{}, r.reject(reg, CodeExists, "credential is already registered")
	case errors.Is(err, executordb.ErrInvalid):
		return Result{}, r.reject(reg, CodeInvalidRequest, "%v", err)
	case err != nil:
		r.cfg.Audit(Event{Kind: "registration_rejected", Detail: err.Error()})
		return Result{}, fail(CodeStorage, "executor state store unavailable")
	}
	if err := r.verifier.Add(webauthnverify.Credential{
		ID: credID, PublicKey: pub, SignCount: ad.Counter, UserHandle: reg.userHandle, Label: reg.label,
	}); err != nil {
		// Stored but not active until the next start; report it.
		r.cfg.Audit(Event{Kind: "registration_rejected", Credential: hex.EncodeToString(credID), Detail: "stored but not activated: " + err.Error()})
		return Result{}, fail(CodeStorage, "credential stored but not activated; restart the executor")
	}
	r.cfg.Audit(Event{Kind: "credential_registered", Credential: hex.EncodeToString(credID), By: by,
		Detail: fmt.Sprintf("user %s, label %q, format %s, aaguid %x", reg.userName, reg.label, format, aaguid)})
	return Result{CredentialID: credID, UserName: reg.userName, Label: reg.label, AAGUID: aaguid, Format: format, By: by}, nil
}

// Remove deactivates a credential and deletes it from the store. It is
// serialized with Finish, and it drops the outstanding code and every
// pending registration, because a credential is removed when it may be lost
// or compromised. It reports whether the credential was stored or active.
func (r *Registrar) Remove(id []byte) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resetLocked("credential removed")
	// The store is the durable record; delete there first. The credential is
	// deactivated in memory in any case (fail closed), but if the store
	// failed, the row is still there and the credential would be active
	// again after a restart: the caller gets ErrRemovalNotStored and must
	// retry.
	stored, err := r.store.RemoveWebAuthnCredential(id)
	active := r.verifier.Remove(id)
	if err != nil {
		r.cfg.Audit(Event{Kind: "credential_removal_not_stored", Detail: err.Error()})
		return active, fmt.Errorf("%w: %w", ErrRemovalNotStored, err)
	}
	return active || stored, nil
}

// ErrRemovalNotStored is returned by Remove when the credential was
// deactivated in memory but could not be deleted from the store. It is active
// again after a restart unless Remove is retried successfully.
var ErrRemovalNotStored = errors.New("credential deactivated until the executor restarts, but its removal was not stored; retry the removal")

// Reset drops the outstanding code and every pending registration (Lock).
func (r *Registrar) Reset(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resetLocked(reason)
}

func (r *Registrar) resetLocked(reason string) {
	if r.code != nil || len(r.pending) > 0 {
		r.cfg.Audit(Event{Kind: "registrations_cancelled", Detail: fmt.Sprintf("%s: %d pending, code outstanding: %v", reason, len(r.pending), r.code != nil)})
	}
	r.code, r.failures = nil, 0
	clear(r.pending)
	clear(r.logins)
}

func (r *Registrar) reject(reg *registration, code Code, format string, args ...any) error {
	err := fail(code, format, args...)
	r.cfg.Audit(Event{Kind: "registration_rejected", By: reg.via, Detail: err.Error()})
	return err
}

func (r *Registrar) gcLocked(now time.Time) {
	for id, reg := range r.pending {
		if !now.Before(reg.expiry) {
			delete(r.pending, id)
		}
	}
	if r.code != nil && !now.Before(r.code.expiry) {
		r.code, r.failures = nil, 0
	}
}

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil
	}
	return b
}

func checkText(field, s string, max int, allowEmpty bool) error {
	switch {
	case s == "" && !allowEmpty:
		return fail(CodeInvalidRequest, "%s is required", field)
	case len(s) > max:
		return fail(CodeInvalidRequest, "%s longer than %d bytes", field, max)
	case !utf8.ValidString(s):
		return fail(CodeInvalidRequest, "%s is not valid UTF-8", field)
	}
	for _, c := range s {
		if !unicode.IsPrint(c) {
			return fail(CodeInvalidRequest, "%s contains a non-printable character %U", field, c)
		}
	}
	return nil
}

// checkPublicKey rejects credential keys the verifier could not use or that
// are too weak: EC2 must be P-256, OKP must be Ed25519, RSA at least 2048
// bits with a public exponent other than 1.
func checkPublicKey(cose []byte) error {
	k, err := webauthncose.ParsePublicKey(cose)
	if err != nil {
		return fmt.Errorf("credential public key: %w", err)
	}
	switch key := k.(type) {
	case webauthncose.EC2PublicKeyData:
		if key.Curve != 1 || len(key.XCoord) != 32 || len(key.YCoord) != 32 { // 1 = P-256
			return errors.New("credential public key: EC2 key must be P-256")
		}
	case webauthncose.OKPPublicKeyData:
		if key.Curve != 6 || len(key.XCoord) != 32 { // 6 = Ed25519
			return errors.New("credential public key: OKP key must be Ed25519")
		}
	case webauthncose.RSAPublicKeyData:
		n := new(big.Int).SetBytes(key.Modulus)
		e := new(big.Int).SetBytes(key.Exponent)
		if n.BitLen() < 2048 || e.Cmp(big.NewInt(1)) <= 0 {
			return errors.New("credential public key: RSA key must have at least 2048 bits")
		}
	default:
		return fmt.Errorf("credential public key: unsupported key type %T", k)
	}
	return nil
}
